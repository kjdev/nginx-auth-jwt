/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * JWT signature verification (JWS) for nginx-auth-jwt module
 *
 * Supports RSA (RS256/384/512, PS256/384/512), ECDSA (ES256/384/512, ES256K),
 * EdDSA (Ed25519, Ed448), and HMAC (HS256/384/512).
 *
 * Uses malloc for allocation (Phase 1).
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>

#include "ngx_auth_jwt_jws.h"


/* ================================================================
 * Base64url decode (same approach as decode.c / jwks.c)
 * ================================================================ */

static unsigned char *
jws_base64url_decode(const char *src, size_t src_len, size_t *out_len)
{
    char *padded;
    unsigned char *buf;
    size_t padded_len, i, pad;
    int len;
    BIO *b64, *bmem;

    if (src == NULL || src_len == 0 || out_len == NULL) {
        return NULL;
    }

    if (src_len > (size_t) INT_MAX - 4) {
        return NULL;
    }

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
 * Algorithm helpers
 * ================================================================ */

static const EVP_MD *
jws_get_md(const char *alg)
{
    size_t len;
    const char *suffix;

    if (alg == NULL) {
        return NULL;
    }

    len = strlen(alg);
    if (len < 4) {
        return NULL;
    }

    /* EdDSA: no separate digest */
    if (strcmp(alg, "EdDSA") == 0) {
        return NULL;
    }

    /* ES256K: suffix is "56K" */
    if (strcmp(alg, "ES256K") == 0) {
        return EVP_sha256();
    }

    /* Standard RS/PS/ES/HS algorithms: hash size from last 3 characters */
    suffix = alg + len - 3;

    if (strcmp(suffix, "256") == 0) {
        return EVP_sha256();
    }

    if (strcmp(suffix, "384") == 0) {
        return EVP_sha384();
    }

    if (strcmp(suffix, "512") == 0) {
        return EVP_sha512();
    }

    return NULL;
}


static int
jws_is_rsa_alg(const char *alg)
{
    if (alg == NULL || alg[0] == '\0' || alg[1] == '\0') {
        return 0;
    }
    return (alg[0] == 'R' && alg[1] == 'S')
        || (alg[0] == 'P' && alg[1] == 'S');
}


static int
jws_is_pss_alg(const char *alg)
{
    if (alg == NULL || alg[0] == '\0' || alg[1] == '\0') {
        return 0;
    }
    return (alg[0] == 'P' && alg[1] == 'S');
}


static int
jws_is_ec_alg(const char *alg)
{
    if (alg == NULL || alg[0] == '\0' || alg[1] == '\0') {
        return 0;
    }
    return (alg[0] == 'E' && alg[1] == 'S');
}


static int
jws_is_hmac_alg(const char *alg)
{
    if (alg == NULL || alg[0] == '\0' || alg[1] == '\0') {
        return 0;
    }
    return (alg[0] == 'H' && alg[1] == 'S');
}


/* ================================================================
 * RSA verification (RS256/384/512, PS256/384/512)
 * ================================================================ */

static int
jws_verify_rsa(const unsigned char *hp_data, size_t hp_len,
    const unsigned char *sig_data, size_t sig_len,
    EVP_PKEY *pkey, const char *alg)
{
    const EVP_MD *md;
    EVP_MD_CTX *mdctx;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int rc;

    md = jws_get_md(alg);
    if (md == NULL) {
        return EINVAL;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        ERR_clear_error();
        return ENOMEM;
    }

    if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, md, NULL, pkey) != 1) {
        ERR_clear_error();
        EVP_MD_CTX_free(mdctx);
        return EINVAL;
    }

    if (jws_is_pss_alg(alg)) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING)
            != 1)
        {
            ERR_clear_error();
            EVP_MD_CTX_free(mdctx);
            return EINVAL;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST)
            != 1)
        {
            ERR_clear_error();
            EVP_MD_CTX_free(mdctx);
            return EINVAL;
        }
    }

    rc = EVP_DigestVerify(mdctx, sig_data, sig_len, hp_data, hp_len);
    EVP_MD_CTX_free(mdctx);
    ERR_clear_error();

    return (rc == 1) ? 0 : EACCES;
}


/* ================================================================
 * ECDSA verification (ES256/384/512, ES256K)
 * ================================================================ */

static int
jws_verify_ec(const unsigned char *hp_data, size_t hp_len,
    const unsigned char *sig_data, size_t sig_len,
    EVP_PKEY *pkey, const char *alg)
{
    const EVP_MD *md;
    EVP_MD_CTX *mdctx;
    ECDSA_SIG *ec_sig = NULL;
    unsigned char *der_sig = NULL;
    BIGNUM *bn_r = NULL, *bn_s = NULL;
    int key_bits, coord_size, der_len, rc;
    int result = EINVAL;

    md = jws_get_md(alg);
    if (md == NULL) {
        return EINVAL;
    }

    key_bits = EVP_PKEY_bits(pkey);
    if (key_bits <= 0) {
        return EINVAL;
    }
    coord_size = (key_bits + 7) / 8;

    if (sig_len != (size_t) (coord_size * 2)) {
        return EINVAL;
    }

    /* Convert R||S to DER format */
    bn_r = BN_bin2bn(sig_data, coord_size, NULL);
    if (bn_r == NULL) {
        result = ENOMEM;
        goto cleanup;
    }

    bn_s = BN_bin2bn(sig_data + coord_size, coord_size, NULL);
    if (bn_s == NULL) {
        result = ENOMEM;
        goto cleanup;
    }

    ec_sig = ECDSA_SIG_new();
    if (ec_sig == NULL) {
        result = ENOMEM;
        goto cleanup;
    }

    /* ECDSA_SIG_set0 takes ownership of bn_r and bn_s on success */
    if (!ECDSA_SIG_set0(ec_sig, bn_r, bn_s)) {
        goto cleanup;
    }
    bn_r = NULL;
    bn_s = NULL;

    der_len = i2d_ECDSA_SIG(ec_sig, &der_sig);
    if (der_len <= 0 || der_sig == NULL) {
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        result = ENOMEM;
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) != 1) {
        EVP_MD_CTX_free(mdctx);
        goto cleanup;
    }

    rc = EVP_DigestVerify(mdctx, der_sig, (size_t) der_len, hp_data, hp_len);
    EVP_MD_CTX_free(mdctx);

    result = (rc == 1) ? 0 : EACCES;

cleanup:
    ERR_clear_error();

    if (der_sig != NULL) {
        OPENSSL_free(der_sig);
    }
    if (ec_sig != NULL) {
        ECDSA_SIG_free(ec_sig);
    }
    if (bn_r != NULL) {
        BN_free(bn_r);
    }
    if (bn_s != NULL) {
        BN_free(bn_s);
    }

    return result;
}


/* ================================================================
 * EdDSA verification (Ed25519, Ed448)
 * ================================================================ */

static int
jws_verify_eddsa(const unsigned char *hp_data, size_t hp_len,
    const unsigned char *sig_data, size_t sig_len,
    EVP_PKEY *pkey)
{
    EVP_MD_CTX *mdctx;
    int rc;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        ERR_clear_error();
        return ENOMEM;
    }

    /* EdDSA uses NULL as the digest */
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) != 1) {
        ERR_clear_error();
        EVP_MD_CTX_free(mdctx);
        return EINVAL;
    }

    rc = EVP_DigestVerify(mdctx, sig_data, sig_len, hp_data, hp_len);
    EVP_MD_CTX_free(mdctx);
    ERR_clear_error();

    return (rc == 1) ? 0 : EACCES;
}


/* ================================================================
 * HMAC verification (HS256/384/512)
 * ================================================================ */

static int
jws_verify_hmac(const unsigned char *hp_data, size_t hp_len,
    const unsigned char *sig_data, size_t sig_len,
    const unsigned char *key, size_t key_len, const char *alg)
{
    const EVP_MD *md;
    unsigned char computed[EVP_MAX_MD_SIZE];
    unsigned int computed_len;

    md = jws_get_md(alg);
    if (md == NULL) {
        return EINVAL;
    }

    if (key_len > INT_MAX) {
        return EINVAL;
    }

    if (HMAC(md, key, (int) key_len, hp_data, hp_len,
             computed, &computed_len) == NULL)
    {
        ERR_clear_error();
        return EINVAL;
    }

    if (computed_len != sig_len) {
        OPENSSL_cleanse(computed, sizeof(computed));
        return EACCES;
    }

    /* constant-time comparison */
    if (CRYPTO_memcmp(computed, sig_data, sig_len) != 0) {
        OPENSSL_cleanse(computed, sizeof(computed));
        return EACCES;
    }

    OPENSSL_cleanse(computed, sizeof(computed));
    return 0;
}


/* ================================================================
 * Key matching helpers
 * ================================================================ */

static int
jws_key_matches_alg(const ngx_auth_jwt_jwks_key_t *key, const char *alg)
{
    /* If key has explicit alg, it must match (but still check kty below) */
    if (key->alg != NULL && strcmp(key->alg, alg) != 0) {
        return 0;
    }

    switch (key->kty) {
    case NGX_AUTH_JWT_JWK_RSA:
        return jws_is_rsa_alg(alg);

    case NGX_AUTH_JWT_JWK_EC:
        return jws_is_ec_alg(alg);

    case NGX_AUTH_JWT_JWK_OKP:
        return (strcmp(alg, "EdDSA") == 0);

    case NGX_AUTH_JWT_JWK_HMAC:
        return jws_is_hmac_alg(alg);

    default:
        return 0;
    }
}


static int
jws_ec_curve_matches_alg(const ngx_auth_jwt_jwks_key_t *key, const char *alg)
{
    if (key->crv == NULL) {
        return 1;
    }

    if (strcmp(alg, "ES256") == 0) {
        return (strcmp(key->crv, "P-256") == 0);
    }
    if (strcmp(alg, "ES384") == 0) {
        return (strcmp(key->crv, "P-384") == 0);
    }
    if (strcmp(alg, "ES512") == 0) {
        return (strcmp(key->crv, "P-521") == 0);
    }
    if (strcmp(alg, "ES256K") == 0) {
        return (strcmp(key->crv, "secp256k1") == 0);
    }

    return 0;
}


/* ================================================================
 * Public API
 * ================================================================ */

int
ngx_auth_jwt_jws_verify(const char *token, unsigned int payload_len,
    ngx_auth_jwt_jwks_keyset_t *keyset, const char *alg, const char *kid)
{
    const char *sig_start;
    size_t token_len, sig_b64_len, sig_len;
    unsigned char *sig = NULL;
    size_t i, tried;
    int rc;

    if (token == NULL || keyset == NULL || alg == NULL) {
        return EINVAL;
    }

    if (keyset->nkeys == 0) {
        return EINVAL;
    }

    token_len = strlen(token);
    if (payload_len == 0 || payload_len >= token_len) {
        return EINVAL;
    }

    /* Reject "none" algorithm */
    if (strcmp(alg, "none") == 0) {
        return EINVAL;
    }

    ERR_clear_error();

    /* Signature starts after the second dot */
    if (token[payload_len] != '.') {
        return EINVAL;
    }
    sig_start = token + payload_len + 1;
    sig_b64_len = token_len - payload_len - 1;

    if (sig_b64_len == 0) {
        return EINVAL;
    }

    /* Decode signature */
    sig = jws_base64url_decode(sig_start, sig_b64_len, &sig_len);
    if (sig == NULL) {
        return EINVAL;
    }

    /* Try each key from the keyset */
    tried = 0;

    /*
     * Two-pass verification:
     * Pass 1: try keys matching by kid (if kid is provided)
     * Pass 2: try all remaining keys as fallback
     *
     * This matches the old behavior where kid-matched keys were tried
     * first, then all keys were tried regardless of kid.
     */

    /* Pass 1: kid-matched keys */
    if (has_kid) {
        for (i = 0; i < keyset->nkeys; i++) {
            ngx_auth_jwt_jwks_key_t *key = &keyset->keys[i];

            if (key->kid == NULL || strcmp(kid, key->kid) != 0) {
                continue;
            }

            rc = jws_try_key((const unsigned char *) token,
                             (size_t) payload_len, sig, sig_len, key, alg);
            if (rc == -1) {
                continue;
            }

            tried++;

            if (rc == 0) {
                free(sig);
                return 0;
            }
            if (rc == ENOMEM) {
                free(sig);
                return ENOMEM;
            }

            /* kid-matched key was tried but signature failed */
            if (kid_tried != NULL) {
                *kid_tried = 1;
            }
        }
    }

    /* Pass 2: try all keys (skip kid-matched keys already tried) */
    for (i = 0; i < keyset->nkeys; i++) {
        ngx_auth_jwt_jwks_key_t *key = &keyset->keys[i];

        /* Skip keys already tried in pass 1 */
        if (has_kid && key->kid != NULL && strcmp(kid, key->kid) == 0) {
            continue;
        }

        rc = jws_try_key((const unsigned char *) token,
                         (size_t) payload_len, sig, sig_len, key, alg);
        if (rc == -1) {
            continue;
        }

        tried++;

        if (rc == 0) {
            free(sig);
            return 0;
        }
        if (rc == ENOMEM) {
            free(sig);
            return ENOMEM;
        }
    }

    free(sig);

    if (tried == 0) {
        return ENOENT;
    }

    return EACCES;
}
