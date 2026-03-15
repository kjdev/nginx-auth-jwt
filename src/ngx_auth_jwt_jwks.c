/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * JWKS (JSON Web Key Set) parser for nginx-auth-jwt module
 *
 * Converts JWK entries to OpenSSL EVP_PKEY objects (RSA/EC/OKP)
 * or raw key bytes (HMAC). Uses ngx_pool_t for allocation.
 *
 * Supports OpenSSL 1.1.1+ and 3.0+.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include "ngx_auth_jwt_jwks.h"


/* ================================================================
 * Base64url decode (OpenSSL BIO-based, same approach as decode.c)
 * ================================================================ */

static unsigned char *
jwks_base64url_decode(const char *src, size_t src_len, size_t *out_len)
{
    char *padded;
    unsigned char *buf;
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
    for (i = src_len; i < padded_len; i++) {
        padded[i] = '=';
    }
    padded[padded_len] = '\0';

    buf = malloc(padded_len);
    if (buf == NULL) {
        free(padded);
        return NULL;
    }

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(padded, (int) padded_len);
    if (b64 == NULL || bmem == NULL) {
        free(padded);
        free(buf);
        if (b64 != NULL) {
            BIO_free(b64);
        }
        if (bmem != NULL) {
            BIO_free(bmem);
        }
        return NULL;
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_push(b64, bmem);

    len = BIO_read(bmem, buf, (int) padded_len);
    BIO_free_all(bmem);
    free(padded);

    if (len <= 0) {
        free(buf);
        return NULL;
    }

    *out_len = (size_t) len;
    return buf;
}


/* ================================================================
 * Pool cleanup handler for keyset resources
 * ================================================================ */

static void
jwks_keyset_cleanup(void *data)
{
    ngx_auth_jwt_jwks_keyset_t *keyset = data;
    size_t i;
    ngx_auth_jwt_jwks_key_t *key;

    if (keyset == NULL || keyset->keys == NULL) {
        return;
    }

    for (i = 0; i < keyset->nkeys; i++) {
        key = &keyset->keys[i];

        if (key->pkey != NULL) {
            EVP_PKEY_free(key->pkey);
            key->pkey = NULL;
        }
        if (key->hmac_key != NULL) {
            OPENSSL_cleanse(key->hmac_key, key->hmac_key_len);
            key->hmac_key = NULL;
        }
    }

    keyset->keys = NULL;
    keyset->nkeys = 0;
}


/* ================================================================
 * Keyset allocation helpers
 * ================================================================ */

static ngx_auth_jwt_jwks_keyset_t *
jwks_keyset_create(ngx_pool_t *pool, size_t initial_capacity)
{
    ngx_auth_jwt_jwks_keyset_t *keyset;
    ngx_pool_cleanup_t *cln;

    keyset = ngx_pcalloc(pool, sizeof(ngx_auth_jwt_jwks_keyset_t));
    if (keyset == NULL) {
        return NULL;
    }

    if (initial_capacity == 0) {
        initial_capacity = 4;
    }

    keyset->keys = ngx_pcalloc(pool,
                               initial_capacity
                               * sizeof(ngx_auth_jwt_jwks_key_t));
    if (keyset->keys == NULL) {
        return NULL;
    }

    keyset->nkeys = 0;
    keyset->capacity = initial_capacity;
    keyset->pool = pool;

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }
    cln->handler = jwks_keyset_cleanup;
    cln->data = keyset;

    return keyset;
}


static ngx_auth_jwt_jwks_key_t *
jwks_keyset_push(ngx_auth_jwt_jwks_keyset_t *keyset)
{
    ngx_auth_jwt_jwks_key_t *key;

    if (keyset->nkeys >= NGX_AUTH_JWT_MAX_JWKS_KEYS) {
        return NULL;
    }

    if (keyset->nkeys >= keyset->capacity) {
        size_t new_cap;
        ngx_auth_jwt_jwks_key_t *new_keys;

        new_cap = keyset->capacity * 2;
        if (new_cap > NGX_AUTH_JWT_MAX_JWKS_KEYS) {
            new_cap = NGX_AUTH_JWT_MAX_JWKS_KEYS;
        }
        new_keys = ngx_pcalloc(keyset->pool,
                               new_cap * sizeof(ngx_auth_jwt_jwks_key_t));
        if (new_keys == NULL) {
            return NULL;
        }
        ngx_memcpy(new_keys, keyset->keys,
                   keyset->nkeys * sizeof(ngx_auth_jwt_jwks_key_t));
        keyset->keys = new_keys;
        keyset->capacity = new_cap;
    }

    key = &keyset->keys[keyset->nkeys];
    ngx_memzero(key, sizeof(ngx_auth_jwt_jwks_key_t));
    keyset->nkeys++;

    return key;
}


static char *
jwks_strdup(ngx_pool_t *pool, const char *s)
{
    size_t len;
    char *dup;

    if (s == NULL) {
        return NULL;
    }

    len = strlen(s);
    dup = ngx_pnalloc(pool, len + 1);
    if (dup == NULL) {
        return NULL;
    }
    ngx_memcpy(dup, s, len + 1);

    return dup;
}


/* ================================================================
 * RSA key creation
 * ================================================================ */

static EVP_PKEY *
jwks_create_rsa_key(json_t *jwk)
{
    const char *n_b64, *e_b64;
    unsigned char *n_bin = NULL, *e_bin = NULL;
    size_t n_len, e_len;
    BIGNUM *n_bn = NULL, *e_bn = NULL;
    EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
#else
    RSA *rsa = NULL;
#endif

    n_b64 = json_string_value(json_object_get(jwk, "n"));
    e_b64 = json_string_value(json_object_get(jwk, "e"));
    if (n_b64 == NULL || e_b64 == NULL) {
        return NULL;
    }

    n_bin = jwks_base64url_decode(n_b64, strlen(n_b64), &n_len);
    if (n_bin == NULL) {
        goto cleanup;
    }

    e_bin = jwks_base64url_decode(e_b64, strlen(e_b64), &e_len);
    if (e_bin == NULL) {
        goto cleanup;
    }

    if (e_len == 0) {
        goto cleanup;
    }

    n_bn = BN_bin2bn(n_bin, (int) n_len, NULL);
    if (n_bn == NULL) {
        goto cleanup;
    }

    e_bn = BN_bin2bn(e_bin, (int) e_len, NULL);
    if (e_bn == NULL) {
        goto cleanup;
    }

    /* Validate minimum RSA key length (2048 bits) after normalization */
    if (BN_num_bits(n_bn) < 2048) {
        goto cleanup;
    }

    /* Validate RSA public exponent: must be odd and >= 3 */
    if (!BN_is_odd(e_bn) || BN_is_zero(e_bn) || BN_is_one(e_bn)) {
        goto cleanup;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n_bn)
        || !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e_bn))
    {
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        goto cleanup;
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pctx == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        pkey = NULL;
    }
#else
    rsa = RSA_new();
    if (rsa == NULL) {
        goto cleanup;
    }

    if (!RSA_set0_key(rsa, n_bn, e_bn, NULL)) {
        goto cleanup;
    }

    /* ownership transferred to RSA object */
    n_bn = NULL;
    e_bn = NULL;

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto cleanup;
    }

    /* ownership transferred to EVP_PKEY */
    rsa = NULL;
#endif

cleanup:
    free(n_bin);
    free(e_bin);
    if (n_bn != NULL) {
        BN_free(n_bn);
    }
    if (e_bn != NULL) {
        BN_free(e_bn);
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
#else
    if (rsa != NULL) {
        RSA_free(rsa);
    }
#endif

    return pkey;
}


/* ================================================================
 * EC key creation
 * ================================================================ */

typedef struct {
    const char *jwk_crv;
    const char *ossl_name;
    size_t      coord_len;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    int         nid;
#endif
} jwks_ec_curve_t;

static const jwks_ec_curve_t jwks_ec_curves[] = {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    { "P-256",     "prime256v1", 32 },
    { "P-384",     "secp384r1",  48 },
    { "P-521",     "secp521r1",  66 },
    { "secp256k1", "secp256k1",  32 },
#else
    { "P-256",     "prime256v1", 32, NID_X9_62_prime256v1 },
    { "P-384",     "secp384r1",  48, NID_secp384r1 },
    { "P-521",     "secp521r1",  66, NID_secp521r1 },
    { "secp256k1", "secp256k1",  32, NID_secp256k1 },
#endif
    { NULL, NULL, 0 }
};


static EVP_PKEY *
jwks_create_ec_key(json_t *jwk)
{
    const char *crv_str, *x_b64, *y_b64;
    unsigned char *x_bin = NULL, *y_bin = NULL, *pub = NULL;
    size_t x_len, y_len, pub_len;
    const jwks_ec_curve_t *curve;
    EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
#else
    EC_KEY *ec = NULL;
    const unsigned char *pub_in;
#endif

    crv_str = json_string_value(json_object_get(jwk, "crv"));
    x_b64 = json_string_value(json_object_get(jwk, "x"));
    y_b64 = json_string_value(json_object_get(jwk, "y"));
    if (crv_str == NULL || x_b64 == NULL || y_b64 == NULL) {
        return NULL;
    }

    /* Find matching curve */
    for (curve = jwks_ec_curves; curve->jwk_crv != NULL; curve++) {
        if (strcmp(crv_str, curve->jwk_crv) == 0) {
            break;
        }
    }
    if (curve->jwk_crv == NULL) {
        return NULL;
    }

    x_bin = jwks_base64url_decode(x_b64, strlen(x_b64), &x_len);
    if (x_bin == NULL) {
        goto cleanup;
    }

    y_bin = jwks_base64url_decode(y_b64, strlen(y_b64), &y_len);
    if (y_bin == NULL) {
        goto cleanup;
    }

    /* Validate coordinate lengths for the curve */
    if (x_len != curve->coord_len || y_len != curve->coord_len) {
        goto cleanup;
    }

    /* Create uncompressed EC point: 0x04 || X || Y */
    pub_len = 1 + x_len + y_len;
    pub = malloc(pub_len);
    if (pub == NULL) {
        goto cleanup;
    }
    pub[0] = 0x04;
    memcpy(pub + 1, x_bin, x_len);
    memcpy(pub + 1 + x_len, y_bin, y_len);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld,
                                         OSSL_PKEY_PARAM_GROUP_NAME,
                                         curve->ossl_name, 0))
    {
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_octet_string(param_bld,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          pub, pub_len))
    {
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        goto cleanup;
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (pctx == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        pkey = NULL;
    }
#else
    ec = EC_KEY_new_by_curve_name(curve->nid);
    if (ec == NULL) {
        goto cleanup;
    }

    pub_in = (const unsigned char *) pub;
    if (!o2i_ECPublicKey(&ec, &pub_in, (long) pub_len)) {
        goto cleanup;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto cleanup;
    }

    /* ownership transferred to EVP_PKEY */
    ec = NULL;
#endif

cleanup:
    free(x_bin);
    free(y_bin);
    free(pub);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
#else
    if (ec != NULL) {
        EC_KEY_free(ec);
    }
#endif

    return pkey;
}


/* ================================================================
 * OKP (Ed25519/Ed448) key creation
 * ================================================================ */

static EVP_PKEY *
jwks_create_okp_key(json_t *jwk)
{
    const char *crv_str, *x_b64;
    unsigned char *x_bin = NULL;
    size_t x_len, expected_len;
    EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    const char *algorithm;
#else
    int nid;
#endif

    crv_str = json_string_value(json_object_get(jwk, "crv"));
    x_b64 = json_string_value(json_object_get(jwk, "x"));
    if (crv_str == NULL || x_b64 == NULL) {
        return NULL;
    }

    if (strcmp(crv_str, "Ed25519") == 0) {
        expected_len = 32;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        algorithm = "ED25519";
#else
        nid = EVP_PKEY_ED25519;
#endif
    } else if (strcmp(crv_str, "Ed448") == 0) {
        expected_len = 57;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        algorithm = "ED448";
#else
        nid = EVP_PKEY_ED448;
#endif
    } else {
        return NULL;
    }

    x_bin = jwks_base64url_decode(x_b64, strlen(x_b64), &x_len);
    if (x_bin == NULL) {
        return NULL;
    }

    if (x_len != expected_len) {
        free(x_bin);
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_octet_string(param_bld,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          x_bin, x_len))
    {
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        goto cleanup;
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    if (pctx == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        pkey = NULL;
    }
#else
    pkey = EVP_PKEY_new_raw_public_key(nid, NULL, x_bin, x_len);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
cleanup:
    if (param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
#endif

    free(x_bin);
    return pkey;
}


/* ================================================================
 * HMAC (oct) key extraction
 * ================================================================ */

static int
jwks_extract_hmac_key(json_t *jwk, unsigned char **key_out, size_t *key_len)
{
    const char *k_b64;

    k_b64 = json_string_value(json_object_get(jwk, "k"));
    if (k_b64 == NULL) {
        return -1;
    }

    *key_out = jwks_base64url_decode(k_b64, strlen(k_b64), key_len);
    if (*key_out == NULL) {
        return -1;
    }

    return 0;
}


/* ================================================================
 * Helper: copy HMAC key from malloc buffer to pool
 * ================================================================ */

static unsigned char *
jwks_hmac_key_to_pool(ngx_pool_t *pool, unsigned char *src, size_t len)
{
    unsigned char *dst;

    dst = ngx_pnalloc(pool, len);
    if (dst == NULL) {
        OPENSSL_cleanse(src, len);
        free(src);
        return NULL;
    }
    ngx_memcpy(dst, src, len);

    /* cleanse and free the original malloc buffer */
    OPENSSL_cleanse(src, len);
    free(src);

    return dst;
}


/* ================================================================
 * Helper: check if "use" is "enc" (encryption key)
 * ================================================================ */

static int
jwks_is_enc_key(json_t *jwk)
{
    const char *use;

    use = json_string_value(json_object_get(jwk, "use"));
    if (use != NULL && strcmp(use, "enc") == 0) {
        return 1;
    }

    return 0;
}


/* ================================================================
 * Copy optional string fields from JWK
 * ================================================================ */

static void
jwks_clear_metadata(ngx_auth_jwt_jwks_key_t *key)
{
    key->kid = NULL;
    key->alg = NULL;
    key->crv = NULL;
}


static int
jwks_copy_metadata(ngx_pool_t *pool, json_t *jwk, ngx_auth_jwt_jwks_key_t *key)
{
    const char *val;

    val = json_string_value(json_object_get(jwk, "kid"));
    if (val != NULL) {
        key->kid = jwks_strdup(pool, val);
        if (key->kid == NULL) {
            goto fail;
        }
    }

    val = json_string_value(json_object_get(jwk, "alg"));
    if (val != NULL) {
        key->alg = jwks_strdup(pool, val);
        if (key->alg == NULL) {
            goto fail;
        }
    }

    val = json_string_value(json_object_get(jwk, "crv"));
    if (val != NULL) {
        key->crv = jwks_strdup(pool, val);
        if (key->crv == NULL) {
            goto fail;
        }
    }

    return 0;

fail:
    jwks_clear_metadata(key);
    return -1;
}


/* ================================================================
 * Public API: parse JWKS format {"keys": [...]}
 * ================================================================ */

ngx_auth_jwt_jwks_keyset_t *
ngx_auth_jwt_jwks_parse(ngx_pool_t *pool, const char *json_str, size_t len)
{
    json_t *root = NULL, *keys_array, *jwk;
    json_error_t err;
    ngx_auth_jwt_jwks_keyset_t *keyset = NULL;
    ngx_auth_jwt_jwks_key_t *key;
    const char *kty_str;
    size_t i, array_size;

    if (json_str == NULL || len == 0) {
        return NULL;
    }

    if (len > NGX_AUTH_JWT_MAX_JWKS_SIZE) {
        return NULL;
    }

    root = json_loadb(json_str, len, 0, &err);
    if (root == NULL) {
        return NULL;
    }

    keys_array = json_object_get(root, "keys");
    if (!json_is_array(keys_array)) {
        json_decref(root);
        return NULL;
    }

    array_size = json_array_size(keys_array);
    if (array_size > NGX_AUTH_JWT_MAX_JWKS_KEYS) {
        json_decref(root);
        return NULL;
    }

    keyset = jwks_keyset_create(pool, array_size > 0 ? array_size : 1);
    if (keyset == NULL) {
        json_decref(root);
        return NULL;
    }

    for (i = 0; i < array_size; i++) {
        jwk = json_array_get(keys_array, i);
        if (!json_is_object(jwk)) {
            continue;
        }

        /* Skip encryption keys */
        if (jwks_is_enc_key(jwk)) {
            continue;
        }

        kty_str = json_string_value(json_object_get(jwk, "kty"));
        if (kty_str == NULL) {
            continue;
        }

        key = jwks_keyset_push(keyset);
        if (key == NULL) {
            ngx_auth_jwt_jwks_free(keyset);
            json_decref(root);
            return NULL;
        }

        if (jwks_copy_metadata(pool, jwk, key) != 0) {
            keyset->nkeys--;
            ngx_auth_jwt_jwks_free(keyset);
            json_decref(root);
            return NULL;
        }

        if (strcmp(kty_str, "RSA") == 0) {
            key->kty = NGX_AUTH_JWT_JWK_RSA;
            key->pkey = jwks_create_rsa_key(jwk);
            if (key->pkey == NULL) {
                jwks_clear_metadata(key);
                keyset->nkeys--;
                continue;
            }
        } else if (strcmp(kty_str, "EC") == 0) {
            key->kty = NGX_AUTH_JWT_JWK_EC;
            key->pkey = jwks_create_ec_key(jwk);
            if (key->pkey == NULL) {
                jwks_clear_metadata(key);
                keyset->nkeys--;
                continue;
            }
        } else if (strcmp(kty_str, "OKP") == 0) {
            key->kty = NGX_AUTH_JWT_JWK_OKP;
            key->pkey = jwks_create_okp_key(jwk);
            if (key->pkey == NULL) {
                jwks_clear_metadata(key);
                keyset->nkeys--;
                continue;
            }
        } else if (strcmp(kty_str, "oct") == 0) {
            unsigned char *hmac_buf;
            size_t hmac_len;

            key->kty = NGX_AUTH_JWT_JWK_HMAC;
            if (jwks_extract_hmac_key(jwk, &hmac_buf, &hmac_len) != 0) {
                jwks_clear_metadata(key);
                keyset->nkeys--;
                continue;
            }
            key->hmac_key = jwks_hmac_key_to_pool(pool, hmac_buf, hmac_len);
            if (key->hmac_key == NULL) {
                jwks_clear_metadata(key);
                keyset->nkeys--;
                continue;
            }
            key->hmac_key_len = hmac_len;
        } else {
            jwks_clear_metadata(key);
            keyset->nkeys--;
            continue;
        }
    }

    json_decref(root);
    return keyset;
}


/* ================================================================
 * Helpers: PEM key metadata
 * ================================================================ */

static const char *
jwks_get_ec_crv(EVP_PKEY *pkey)
{
    const jwks_ec_curve_t *c;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    char group_name[64];

    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                        group_name, sizeof(group_name), NULL))
    {
        return NULL;
    }

    for (c = jwks_ec_curves; c->jwk_crv != NULL; c++) {
        if (strcmp(group_name, c->ossl_name) == 0) {
            return c->jwk_crv;
        }
    }
#else
    const EC_KEY *ec_key;
    const EC_GROUP *group;
    int nid;

    ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    if (ec_key == NULL) {
        return NULL;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        return NULL;
    }

    nid = EC_GROUP_get_curve_name(group);

    for (c = jwks_ec_curves; c->jwk_crv != NULL; c++) {
        if (c->nid == nid) {
            return c->jwk_crv;
        }
    }
#endif

    return NULL;
}


/* ================================================================
 * Public API: parse keyval format {"kid": "PEM or HMAC key"}
 * ================================================================ */

static int
jwks_is_pem_string(const char *value)
{
    return (strncmp(value, "-----BEGIN ", 11) == 0);
}


ngx_auth_jwt_jwks_keyset_t *
ngx_auth_jwt_jwks_parse_keyval(ngx_pool_t *pool,
    const char *json_str, size_t len)
{
    json_t *root = NULL;
    json_error_t err;
    ngx_auth_jwt_jwks_keyset_t *keyset = NULL;
    ngx_auth_jwt_jwks_key_t *key;
    const char *kid;
    json_t *value;
    void *iter;

    if (json_str == NULL || len == 0) {
        return NULL;
    }

    if (len > NGX_AUTH_JWT_MAX_JWKS_SIZE) {
        return NULL;
    }

    root = json_loadb(json_str, len, 0, &err);
    if (root == NULL || !json_is_object(root)) {
        if (root != NULL) {
            json_decref(root);
        }
        return NULL;
    }

    if (json_object_size(root) > NGX_AUTH_JWT_MAX_JWKS_KEYS) {
        json_decref(root);
        return NULL;
    }

    keyset = jwks_keyset_create(pool, json_object_size(root));
    if (keyset == NULL) {
        json_decref(root);
        return NULL;
    }

    iter = json_object_iter(root);
    while (iter != NULL) {
        kid = json_object_iter_key(iter);
        value = json_object_iter_value(iter);

        if (!json_is_string(value) || kid == NULL) {
            iter = json_object_iter_next(root, iter);
            continue;
        }

        key = jwks_keyset_push(keyset);
        if (key == NULL) {
            ngx_auth_jwt_jwks_free(keyset);
            json_decref(root);
            return NULL;
        }

        key->kid = jwks_strdup(pool, kid);
        if (key->kid == NULL) {
            keyset->nkeys--;
            iter = json_object_iter_next(root, iter);
            continue;
        }

        if (jwks_is_pem_string(json_string_value(value))) {
            /* PEM public key -> EVP_PKEY */
            BIO *bio;
            const char *pem_str;
            EVP_PKEY *pkey;

            pem_str = json_string_value(value);
            bio = BIO_new_mem_buf(pem_str, (int) strlen(pem_str));
            if (bio == NULL) {
                ngx_auth_jwt_jwks_free(keyset);
                json_decref(root);
                return NULL;
            }

            pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
            BIO_free(bio);

            if (pkey == NULL) {
                ngx_auth_jwt_jwks_free(keyset);
                json_decref(root);
                return NULL;
            }

            key->pkey = pkey;

            /* Determine type from EVP_PKEY */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            if (EVP_PKEY_is_a(pkey, "RSA")) {
                key->kty = NGX_AUTH_JWT_JWK_RSA;
            } else if (EVP_PKEY_is_a(pkey, "EC")) {
                const char *crv_name;

                key->kty = NGX_AUTH_JWT_JWK_EC;
                crv_name = jwks_get_ec_crv(pkey);
                if (crv_name != NULL) {
                    key->crv = jwks_strdup(pool, crv_name);
                }
            } else if (EVP_PKEY_is_a(pkey, "ED25519")
                       || EVP_PKEY_is_a(pkey, "ED448"))
            {
                key->kty = NGX_AUTH_JWT_JWK_OKP;
            } else {
                key->kty = NGX_AUTH_JWT_JWK_UNKNOWN;
            }
#else
            {
                int pkey_id = EVP_PKEY_base_id(pkey);
                if (pkey_id == EVP_PKEY_RSA) {
                    key->kty = NGX_AUTH_JWT_JWK_RSA;
                } else if (pkey_id == EVP_PKEY_EC) {
                    const char *crv_name;

                    key->kty = NGX_AUTH_JWT_JWK_EC;
                    crv_name = jwks_get_ec_crv(pkey);
                    if (crv_name != NULL) {
                        key->crv = jwks_strdup(pool, crv_name);
                    }
                } else if (pkey_id == EVP_PKEY_ED25519
                           || pkey_id == EVP_PKEY_ED448)
                {
                    key->kty = NGX_AUTH_JWT_JWK_OKP;
                } else {
                    key->kty = NGX_AUTH_JWT_JWK_UNKNOWN;
                }
            }
#endif
        } else {
            /* Raw string -> HMAC key */
            const char *raw;
            size_t raw_len;

            raw = json_string_value(value);
            raw_len = json_string_length(value);

            if (raw_len == 0) {
                ngx_auth_jwt_jwks_free(keyset);
                json_decref(root);
                return NULL;
            }

            key->kty = NGX_AUTH_JWT_JWK_HMAC;
            key->hmac_key = ngx_pnalloc(pool, raw_len);
            if (key->hmac_key == NULL) {
                key->kid = NULL;
                keyset->nkeys--;
                iter = json_object_iter_next(root, iter);
                continue;
            }
            ngx_memcpy(key->hmac_key, raw, raw_len);
            key->hmac_key_len = raw_len;
        }

        iter = json_object_iter_next(root, iter);
    }

    json_decref(root);
    return keyset;
}


/* ================================================================
 * Public API: load from file
 * ================================================================ */

ngx_auth_jwt_jwks_keyset_t *
ngx_auth_jwt_jwks_load_file(ngx_pool_t *pool, const char *path, int is_jwks)
{
    FILE *fp;
    char *buf;
    long file_size;
    size_t nread;
    ngx_auth_jwt_jwks_keyset_t *keyset;

    if (path == NULL) {
        return NULL;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }

    file_size = ftell(fp);
    if (file_size <= 0 || (size_t) file_size > NGX_AUTH_JWT_MAX_JWKS_SIZE) {
        fclose(fp);
        return NULL;
    }

    rewind(fp);

    buf = malloc((size_t) file_size + 1);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }

    nread = fread(buf, 1, (size_t) file_size, fp);
    if (nread != (size_t) file_size || ferror(fp)) {
        fclose(fp);
        free(buf);
        return NULL;
    }
    fclose(fp);
    buf[nread] = '\0';

    if (is_jwks) {
        keyset = ngx_auth_jwt_jwks_parse(pool, buf, nread);
    } else {
        keyset = ngx_auth_jwt_jwks_parse_keyval(pool, buf, nread);
    }

    free(buf);
    return keyset;
}


/* ================================================================
 * Public API: create empty keyset
 * ================================================================ */

ngx_auth_jwt_jwks_keyset_t *
ngx_auth_jwt_jwks_create(ngx_pool_t *pool)
{
    return jwks_keyset_create(pool, 4);
}


/* ================================================================
 * Public API: append keys from src to dst
 * ================================================================ */

int
ngx_auth_jwt_jwks_append(ngx_auth_jwt_jwks_keyset_t *dst,
    ngx_auth_jwt_jwks_keyset_t *src)
{
    size_t i, orig_nkeys;
    ngx_auth_jwt_jwks_key_t *sk, *dk;

    if (dst == NULL || src == NULL) {
        return -1;
    }

    orig_nkeys = dst->nkeys;

    for (i = 0; i < src->nkeys; i++) {
        sk = &src->keys[i];

        dk = jwks_keyset_push(dst);
        if (dk == NULL) {
            goto rollback;
        }

        dk->kty = sk->kty;
        dk->kid = jwks_strdup(dst->pool, sk->kid);
        dk->alg = jwks_strdup(dst->pool, sk->alg);
        dk->crv = jwks_strdup(dst->pool, sk->crv);

        if ((sk->kid != NULL && dk->kid == NULL)
            || (sk->alg != NULL && dk->alg == NULL)
            || (sk->crv != NULL && dk->crv == NULL))
        {
            goto rollback;
        }

        if (sk->pkey != NULL) {
            if (EVP_PKEY_up_ref(sk->pkey) != 1) {
                goto rollback;
            }
            dk->pkey = sk->pkey;
        }

        if (sk->hmac_key != NULL && sk->hmac_key_len > 0) {
            dk->hmac_key = ngx_pnalloc(dst->pool, sk->hmac_key_len);
            if (dk->hmac_key == NULL) {
                goto rollback;
            }
            ngx_memcpy(dk->hmac_key, sk->hmac_key, sk->hmac_key_len);
            dk->hmac_key_len = sk->hmac_key_len;
        }
    }

    return 0;

rollback:
    for (i = orig_nkeys; i < dst->nkeys; i++) {
        dk = &dst->keys[i];

        if (dk->pkey != NULL) {
            EVP_PKEY_free(dk->pkey);
            dk->pkey = NULL;
        }
        if (dk->hmac_key != NULL) {
            OPENSSL_cleanse(dk->hmac_key, dk->hmac_key_len);
            dk->hmac_key = NULL;
        }
        jwks_clear_metadata(dk);
    }
    dst->nkeys = orig_nkeys;

    return -1;
}


/* ================================================================
 * Public API: free keyset resources (EVP_PKEY + HMAC cleanse)
 * Memory is managed by pool; this only releases non-pool resources.
 * ================================================================ */

void
ngx_auth_jwt_jwks_free(ngx_auth_jwt_jwks_keyset_t *keyset)
{
    size_t i;
    ngx_auth_jwt_jwks_key_t *key;

    if (keyset == NULL) {
        return;
    }

    if (keyset->keys != NULL) {
        for (i = 0; i < keyset->nkeys; i++) {
            key = &keyset->keys[i];

            if (key->pkey != NULL) {
                EVP_PKEY_free(key->pkey);
                key->pkey = NULL;
            }
            if (key->hmac_key != NULL) {
                OPENSSL_cleanse(key->hmac_key, key->hmac_key_len);
                key->hmac_key = NULL;
            }
        }

        keyset->keys = NULL;
    }

    keyset->nkeys = 0;
}
