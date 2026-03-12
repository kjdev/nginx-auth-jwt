/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_JWT_JSON_H
#define NGX_AUTH_JWT_JSON_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef void ngx_auth_jwt_json_t;

typedef enum {
    NGX_AUTH_JWT_JSON_INVALID = -1,
    NGX_AUTH_JWT_JSON_NULL,
    NGX_AUTH_JWT_JSON_BOOLEAN,
    NGX_AUTH_JWT_JSON_INTEGER,
    NGX_AUTH_JWT_JSON_REAL,
    NGX_AUTH_JWT_JSON_STRING,
    NGX_AUTH_JWT_JSON_ARRAY,
    NGX_AUTH_JWT_JSON_OBJECT
} ngx_auth_jwt_json_type_t;

#define NGX_AUTH_JWT_MAX_JSON_SIZE  1048576

ngx_auth_jwt_json_t *ngx_auth_jwt_json_parse(const char *data, size_t len);
void ngx_auth_jwt_json_free(ngx_auth_jwt_json_t *json);

ngx_auth_jwt_json_type_t ngx_auth_jwt_json_type(
    ngx_auth_jwt_json_t *json);

ngx_auth_jwt_json_t *ngx_auth_jwt_json_object_get(
    ngx_auth_jwt_json_t *json, const char *key);

size_t ngx_auth_jwt_json_array_size(ngx_auth_jwt_json_t *json);
ngx_auth_jwt_json_t *ngx_auth_jwt_json_array_get(
    ngx_auth_jwt_json_t *json, size_t index);

ngx_int_t ngx_auth_jwt_json_string(ngx_auth_jwt_json_t *json,
    const char **value, size_t *len);
ngx_int_t ngx_auth_jwt_json_integer(ngx_auth_jwt_json_t *json,
    int64_t *value);
ngx_int_t ngx_auth_jwt_json_real(ngx_auth_jwt_json_t *json,
    double *value);
ngx_int_t ngx_auth_jwt_json_boolean(ngx_auth_jwt_json_t *json,
    int *value);

ngx_auth_jwt_json_t *ngx_auth_jwt_json_from_string(const char *data,
    size_t len);

int ngx_auth_jwt_json_equal(ngx_auth_jwt_json_t *a,
    ngx_auth_jwt_json_t *b);

ngx_int_t ngx_auth_jwt_json_number(ngx_auth_jwt_json_t *json,
    double *value);
ngx_int_t ngx_auth_jwt_json_compare(ngx_auth_jwt_json_t *a,
    ngx_auth_jwt_json_t *b, double *diff, ngx_log_t *log);

#define ngx_auth_jwt_json_is_string(json)                                \
        (ngx_auth_jwt_json_type(json) == NGX_AUTH_JWT_JSON_STRING)

#define ngx_auth_jwt_json_is_integer(json)                               \
        (ngx_auth_jwt_json_type(json) == NGX_AUTH_JWT_JSON_INTEGER)

#define ngx_auth_jwt_json_is_real(json)                                  \
        (ngx_auth_jwt_json_type(json) == NGX_AUTH_JWT_JSON_REAL)

#define ngx_auth_jwt_json_is_boolean(json)                               \
        (ngx_auth_jwt_json_type(json) == NGX_AUTH_JWT_JSON_BOOLEAN)

#define ngx_auth_jwt_json_is_array(json)                                 \
        (ngx_auth_jwt_json_type(json) == NGX_AUTH_JWT_JSON_ARRAY)

#define ngx_auth_jwt_json_is_object(json)                                \
        (ngx_auth_jwt_json_type(json) == NGX_AUTH_JWT_JSON_OBJECT)

#define ngx_auth_jwt_json_is_null(json)                                  \
        (ngx_auth_jwt_json_type(json) == NGX_AUTH_JWT_JSON_NULL)

#endif /* NGX_AUTH_JWT_JSON_H */
