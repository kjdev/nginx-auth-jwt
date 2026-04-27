/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */
#ifndef NGX_AUTH_JWT_CLAIMS_H
#define NGX_AUTH_JWT_CLAIMS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <jansson.h>


/*
 * View of a parsed JWT exposed to the validation layer (claims, field,
 * operator, http module).  Token decoding itself is delegated to
 * nxe_jwx; the http module copies the parsed header / payload trees
 * into this opaque-ish struct so the existing claims API stays stable.
 *
 * `headers` and `payload` are jansson values that the http module
 * loads independently of nxe_jwx (so we never assume the nxe_json
 * opaque is implemented on top of jansson).  Memory is owned by the
 * request pool via a cleanup handler that calls json_decref.
 */
typedef struct {
    json_t *headers;
    json_t *payload;
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
