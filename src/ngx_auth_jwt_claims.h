#ifndef NGX_AUTH_JWT_CLAIMS_H
#define NGX_AUTH_JWT_CLAIMS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "jwt/jwt.h"

const char *ngx_auth_jwt_claims_get_header(jwt_t *jwt, const char *header, const char *delim, const char *quote);
long ngx_auth_jwt_claims_get_header_int(jwt_t *jwt, const char *header, const char *delim, const char *quote);
int ngx_auth_jwt_claims_get_header_bool(jwt_t *jwt, const char *header, const char *delim, const char *quote);
char *ngx_auth_jwt_claims_get_headers_json(jwt_t *jwt, const char *header, const char *delim, const char *quote);

const char *ngx_auth_jwt_claims_get_grant(jwt_t *jwt, const char *grant, const char *delim, const char *quote);
long ngx_auth_jwt_claims_get_grant_int(jwt_t *jwt, const char *grant, const char *delim, const char *quote);
int ngx_auth_jwt_claims_get_grant_bool(jwt_t *jwt, const char *grant, const char *delim, const char *quote);
char *ngx_auth_jwt_claims_get_grants_json(jwt_t *jwt, const char *grant, const char *delim, const char *quote);

#ifdef __cplusplus
}
#endif

#endif /* NGX_AUTH_JWT_CLAIMS_H */
