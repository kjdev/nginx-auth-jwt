/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * JWT decode layer (malloc-based, replaces libjwt jwt_parse)
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "ngx_auth_jwt_decode.h"
#include "jwt/jwt.h"
#include "jwt/jwt-private.h"


static char *
ngx_auth_jwt_b64url_decode(const char *src, size_t src_len, int *out_len)
{
    char *padded, *buf;
    size_t padded_len, i, pad;
    int len;
    BIO *b64, *bmem;

    if (src == NULL || src_len == 0) {
        return NULL;
    }

    /* convert base64url to base64 and add padding */
    pad = (4 - (src_len % 4)) % 4;
    padded_len = src_len + pad;
    padded = malloc(padded_len + 1);
    if (padded == NULL) {
        return NULL;
    }

    for (i = 0; i < src_len; i++) {
        switch (src[i]) {
        case '-':
            padded[i] = '+';
            break;
        case '_':
            padded[i] = '/';
            break;
        default:
            padded[i] = src[i];
        }
    }
    for (i = 0; i < pad; i++) {
        padded[src_len + i] = '=';
    }
    padded[padded_len] = '\0';

    /* allocate output buffer */
    buf = malloc(padded_len + 1);
    if (buf == NULL) {
        free(padded);
        return NULL;
    }

    /* decode using OpenSSL BIO */
    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
        free(padded);
        free(buf);
        return NULL;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_new_mem_buf(padded, (int) padded_len);
    if (bmem == NULL) {
        BIO_free(b64);
        free(padded);
        free(buf);
        return NULL;
    }
    bmem = BIO_push(b64, bmem);

    len = BIO_read(bmem, buf, (int) padded_len);
    BIO_free_all(bmem);
    free(padded);

    if (len <= 0) {
        free(buf);
        return NULL;
    }

    buf[len] = '\0';
    *out_len = len;

    return buf;
}


static json_t *
ngx_auth_jwt_b64url_decode_json(const char *src, size_t src_len)
{
    json_t *js;
    char *buf;
    int len;

    buf = ngx_auth_jwt_b64url_decode(src, src_len, &len);
    if (buf == NULL) {
        return NULL;
    }

    js = json_loadb(buf, (size_t) len, JSON_REJECT_DUPLICATES, NULL);

    OPENSSL_cleanse(buf, (size_t) len);
    free(buf);

    return js;
}


int
ngx_auth_jwt_decode(ngx_auth_jwt_t **jwt, const char *token,
    unsigned int *payload_len)
{
    ngx_auth_jwt_t *new_jwt;
    const char *head_start, *body_start, *sig_start, *end;
    size_t token_len, head_len, body_len;
    const char *alg;

    if (jwt == NULL || token == NULL || payload_len == NULL) {
        return EINVAL;
    }

    *jwt = NULL;

    token_len = strlen(token);
    if (token_len == 0 || token_len > NGX_AUTH_JWT_MAX_TOKEN_LENGTH) {
        return EINVAL;
    }

    /* find segments: header.payload.signature */
    head_start = token;
    end = token + token_len;

    body_start = memchr(head_start, '.', (size_t)(end - head_start));
    if (body_start == NULL || body_start == head_start) {
        return EINVAL;
    }
    head_len = (size_t)(body_start - head_start);
    body_start++;

    sig_start = memchr(body_start, '.', (size_t)(end - body_start));
    if (sig_start == NULL) {
        return EINVAL;
    }
    body_len = (size_t)(sig_start - body_start);

    /* reject extra segments (JWE) */
    if (memchr(sig_start + 1, '.', (size_t)(end - sig_start - 1)) != NULL) {
        return EINVAL;
    }

    /* reject empty payload */
    if (body_len == 0) {
        return EINVAL;
    }

    /* reject oversized header */
    if (head_len > NGX_AUTH_JWT_MAX_HEADER_LENGTH) {
        return EINVAL;
    }

    /* allocate jwt struct */
    new_jwt = calloc(1, sizeof(ngx_auth_jwt_t));
    if (new_jwt == NULL) {
        return ENOMEM;
    }

    /* decode header */
    new_jwt->headers = ngx_auth_jwt_b64url_decode_json(head_start, head_len);
    if (new_jwt->headers == NULL) {
        ngx_auth_jwt_free(new_jwt);
        return EINVAL;
    }

    /* validate alg field exists */
    alg = json_string_value(json_object_get(new_jwt->headers, "alg"));
    if (alg == NULL) {
        ngx_auth_jwt_free(new_jwt);
        return EINVAL;
    }

    /* decode payload */
    new_jwt->payload = ngx_auth_jwt_b64url_decode_json(body_start, body_len);
    if (new_jwt->payload == NULL) {
        ngx_auth_jwt_free(new_jwt);
        return EINVAL;
    }
    if (!json_is_object(new_jwt->payload)) {
        ngx_auth_jwt_free(new_jwt);
        return EINVAL;
    }

    /* store token copy for signature verification */
    new_jwt->token_copy = strdup(token);
    if (new_jwt->token_copy == NULL) {
        ngx_auth_jwt_free(new_jwt);
        return ENOMEM;
    }

    new_jwt->payload_len = (unsigned int)(sig_start - token);
    *payload_len = new_jwt->payload_len;
    *jwt = new_jwt;

    return 0;
}


void
ngx_auth_jwt_free(ngx_auth_jwt_t *jwt)
{
    if (jwt == NULL) {
        return;
    }

    if (jwt->headers) {
        json_decref(jwt->headers);
    }
    if (jwt->payload) {
        json_decref(jwt->payload);
    }
    if (jwt->token_copy) {
        OPENSSL_cleanse(jwt->token_copy, strlen(jwt->token_copy));
        free(jwt->token_copy);
    }

    free(jwt);
}


int
ngx_auth_jwt_verify_sig(ngx_auth_jwt_t *jwt, const char *token,
    unsigned int payload_len, const unsigned char *key, int key_len)
{
    struct jwt tmp;
    const char *alg_str;
    int ret;

    if (jwt == NULL || token == NULL || key == NULL || key_len <= 0) {
        return EINVAL;
    }

    alg_str = json_string_value(json_object_get(jwt->headers, "alg"));
    if (alg_str == NULL) {
        return EINVAL;
    }

    memset(&tmp, 0, sizeof(tmp));
    tmp.alg = jwt_str_alg(alg_str);
    if (tmp.alg == JWT_ALG_INVAL || tmp.alg == JWT_ALG_NONE) {
        return EINVAL;
    }

    tmp.key = malloc((size_t) key_len);
    if (tmp.key == NULL) {
        return ENOMEM;
    }
    memcpy(tmp.key, key, (size_t) key_len);
    tmp.key_len = key_len;

    tmp.headers = jwt->headers;
    tmp.grants = jwt->payload;

    ret = jwt_verify_sig(&tmp, token, payload_len, key, key_len);

    memset(tmp.key, 0, (size_t) key_len);
    free(tmp.key);

    /* do not free headers/grants as they belong to jwt */
    tmp.headers = NULL;
    tmp.grants = NULL;

    return ret;
}
