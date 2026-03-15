/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */
#ifndef NGX_AUTH_JWT_JWKS_H
#define NGX_AUTH_JWT_JWKS_H

#include <ngx_core.h>
#include <openssl/evp.h>
#include <stddef.h>

#define NGX_AUTH_JWT_MAX_JWKS_SIZE  262144
#define NGX_AUTH_JWT_MAX_JWKS_KEYS  64

typedef enum {
    NGX_AUTH_JWT_JWK_UNKNOWN = 0,
    NGX_AUTH_JWT_JWK_RSA,
    NGX_AUTH_JWT_JWK_EC,
    NGX_AUTH_JWT_JWK_OKP,
    NGX_AUTH_JWT_JWK_HMAC
} ngx_auth_jwt_jwk_type_t;

typedef struct {
    char                    *kid;
    char                    *alg;
    char                    *crv;
    ngx_auth_jwt_jwk_type_t  kty;
    EVP_PKEY                *pkey;         /* for RSA/EC/OKP */
    unsigned char           *hmac_key;     /* for HMAC (raw key bytes) */
    size_t                   hmac_key_len;
} ngx_auth_jwt_jwks_key_t;

typedef struct {
    ngx_auth_jwt_jwks_key_t *keys;
    size_t                   nkeys;
    size_t                   capacity;
    ngx_pool_t              *pool;
} ngx_auth_jwt_jwks_keyset_t;

/* Parse JWKS JSON format: {"keys": [...]} */
ngx_auth_jwt_jwks_keyset_t *ngx_auth_jwt_jwks_parse(
    ngx_pool_t *pool, const char *json, size_t len);

/* Parse keyval format: {"kid": "PEM string or HMAC key"} */
ngx_auth_jwt_jwks_keyset_t *ngx_auth_jwt_jwks_parse_keyval(
    ngx_pool_t *pool, const char *json, size_t len);

/* Load from file (is_jwks selects JWKS or keyval parser) */
ngx_auth_jwt_jwks_keyset_t *ngx_auth_jwt_jwks_load_file(
    ngx_pool_t *pool, const char *path, int is_jwks);

/* Create an empty keyset */
ngx_auth_jwt_jwks_keyset_t *ngx_auth_jwt_jwks_create(ngx_pool_t *pool);

/* Append all keys from src into dst (EVP_PKEY_up_ref / memcpy) */
int ngx_auth_jwt_jwks_append(ngx_auth_jwt_jwks_keyset_t *dst,
    ngx_auth_jwt_jwks_keyset_t *src);

void ngx_auth_jwt_jwks_free(ngx_auth_jwt_jwks_keyset_t *keyset);

#endif
