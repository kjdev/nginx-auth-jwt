/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_JWT_FIELD_H
#define NGX_AUTH_JWT_FIELD_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <jansson.h>

typedef enum {
    NGX_AUTH_JWT_FIELD_KEY,      /* .key or ."quoted.key" */
    NGX_AUTH_JWT_FIELD_INDEX     /* [N] */
} ngx_auth_jwt_field_type_t;

typedef struct {
    ngx_auth_jwt_field_type_t  type;
    union {
        struct {
            char   *name;
            size_t  len;
        } key;
        size_t  index;
    } u;
} ngx_auth_jwt_field_segment_t;

int ngx_auth_jwt_field_is_jq_path(const char *path, size_t len);

ngx_int_t ngx_auth_jwt_field_parse(ngx_pool_t *pool,
    const char *path, size_t len,
    ngx_auth_jwt_field_segment_t **segments, size_t *nsegments);

json_t *ngx_auth_jwt_field_resolve(json_t *root,
    ngx_auth_jwt_field_segment_t *segments, size_t nsegments);

#endif /* NGX_AUTH_JWT_FIELD_H */
