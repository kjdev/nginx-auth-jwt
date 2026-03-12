/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_JWT_DECODE_H
#define NGX_AUTH_JWT_DECODE_H

#include <jansson.h>

#define NGX_AUTH_JWT_MAX_TOKEN_LENGTH   16384
#define NGX_AUTH_JWT_MAX_HEADER_LENGTH  8192

typedef struct {
    json_t         *headers;
    json_t         *payload;
    char           *token_copy;
    unsigned int    payload_len;
} ngx_auth_jwt_t;

int ngx_auth_jwt_decode(ngx_auth_jwt_t **jwt, const char *token,
    unsigned int *payload_len);
void ngx_auth_jwt_free(ngx_auth_jwt_t *jwt);

#endif /* NGX_AUTH_JWT_DECODE_H */
