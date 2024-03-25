#ifndef JWK_GET_CLAIMS_H
#define JWK_GET_CLAIMS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "jwt/jwt.h"

const char *ngx_http_auth_jwt_get_header(jwt_t *jwt, const char *header, const char *delim, const char *quote);
long ngx_http_auth_jwt_get_header_int(jwt_t *jwt, const char *header, const char *delim, const char *quote);
int ngx_http_auth_jwt_get_header_bool(jwt_t *jwt, const char *header, const char *delim, const char *quote);
char *ngx_http_auth_jwt_get_headers_json(jwt_t *jwt, const char *header, const char *delim, const char *quote);

const char *ngx_http_auth_jwt_get_grant(jwt_t *jwt, const char *grant, const char *delim, const char *quote);
long ngx_http_auth_jwt_get_grant_int(jwt_t *jwt, const char *grant, const char *delim, const char *quote);
int ngx_http_auth_jwt_get_grant_bool(jwt_t *jwt, const char *grant, const char *delim, const char *quote);
char *ngx_http_auth_jwt_get_grants_json(jwt_t *jwt, const char *grant, const char *delim, const char *quote);

#ifdef __cplusplus
}
#endif

#endif /* JWK_GET_CLAIMS_H */
