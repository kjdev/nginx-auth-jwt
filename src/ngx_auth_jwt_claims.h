/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */
#ifndef NGX_AUTH_JWT_CLAIMS_H
#define NGX_AUTH_JWT_CLAIMS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <nxe_json.h>


/*
 * View of a parsed JWT exposed to the validation layer (claims, field,
 * operator, http module).  Token decoding itself is delegated to
 * nxe_jwx; this struct holds borrowed references into the
 * nxe_jwx_token_t header / payload trees so the validation layer can
 * traverse them without re-parsing.
 *
 * `headers` and `payload` are owned by the nxe_jwx_token attached to
 * the request pool; this struct does not free them.
 */
typedef struct {
    nxe_json_t *headers;
    nxe_json_t *payload;
} ngx_auth_jwt_t;


const char *ngx_auth_jwt_claims_get_header(ngx_auth_jwt_t *jwt,
    const char *header, const char *delim, const char *quote);
long ngx_auth_jwt_claims_get_header_int(ngx_auth_jwt_t *jwt, const char *header,
    const char *delim, const char *quote);
int ngx_auth_jwt_claims_get_header_bool(ngx_auth_jwt_t *jwt, const char *header,
    const char *delim, const char *quote);
char *ngx_auth_jwt_claims_get_headers_json(ngx_auth_jwt_t *jwt,
    const char *header, const char *delim, const char *quote);

const char *ngx_auth_jwt_claims_get_grant(ngx_auth_jwt_t *jwt,
    const char *grant, const char *delim, const char *quote);
long ngx_auth_jwt_claims_get_grant_int(ngx_auth_jwt_t *jwt, const char *grant,
    const char *delim, const char *quote);
int ngx_auth_jwt_claims_get_grant_bool(ngx_auth_jwt_t *jwt, const char *grant,
    const char *delim, const char *quote);
char *ngx_auth_jwt_claims_get_grants_json(ngx_auth_jwt_t *jwt,
    const char *grant, const char *delim, const char *quote);

#endif /* NGX_AUTH_JWT_CLAIMS_H */
