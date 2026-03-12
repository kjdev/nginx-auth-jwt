#ifndef NGX_AUTH_JWT_CLAIMS_H
#define NGX_AUTH_JWT_CLAIMS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ngx_auth_jwt_decode.h"

const char *ngx_auth_jwt_claims_get_header(ngx_auth_jwt_t *jwt, const char *header, const char *delim, const char *quote);
long ngx_auth_jwt_claims_get_header_int(ngx_auth_jwt_t *jwt, const char *header, const char *delim, const char *quote);
int ngx_auth_jwt_claims_get_header_bool(ngx_auth_jwt_t *jwt, const char *header, const char *delim, const char *quote);
char *ngx_auth_jwt_claims_get_headers_json(ngx_auth_jwt_t *jwt, const char *header, const char *delim, const char *quote);

const char *ngx_auth_jwt_claims_get_grant(ngx_auth_jwt_t *jwt, const char *grant, const char *delim, const char *quote);
long ngx_auth_jwt_claims_get_grant_int(ngx_auth_jwt_t *jwt, const char *grant, const char *delim, const char *quote);
int ngx_auth_jwt_claims_get_grant_bool(ngx_auth_jwt_t *jwt, const char *grant, const char *delim, const char *quote);
char *ngx_auth_jwt_claims_get_grants_json(ngx_auth_jwt_t *jwt, const char *grant, const char *delim, const char *quote);

#ifdef __cplusplus
}
#endif

#endif /* NGX_AUTH_JWT_CLAIMS_H */
