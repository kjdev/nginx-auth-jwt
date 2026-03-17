/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "ngx_auth_jwt_field.h"


int
ngx_auth_jwt_field_is_jq_path(const char *path, size_t len)
{
    if (path == NULL || len == 0) {
        return 0;
    }

    return (path[0] == '.' || path[0] == '[');
}


/*
 * Count or parse segments from a JQ-like path.
 *
 * Grammar:
 *   path    = segment+
 *   segment = "." key | "." quoted | index
 *   key     = [a-zA-Z_][a-zA-Z0-9_-]*
 *   quoted  = '"' (non-'"')+ '"'
 *   index   = "[" digits "]"
 *
 * When segments == NULL, only counts. Otherwise fills the array.
 */
static ngx_int_t
ngx_auth_jwt_field_scan(ngx_pool_t *pool, const char *path, size_t len,
    ngx_auth_jwt_field_segment_t *segments, size_t *nsegments)
{
    const char *p, *end;
    size_t count = 0;

    p = path;
    end = path + len;

    while (p < end) {
        if (*p == '.') {
            p++;
            if (p >= end) {
                return NGX_ERROR;
            }

            if (*p == '"') {
                /* quoted key: ."some.key" */
                const char *start;

                p++;
                start = p;

                while (p < end && *p != '"') {
                    p++;
                }

                if (p >= end) {
                    return NGX_ERROR;
                }

                if (p == start) {
                    return NGX_ERROR;
                }

                if (segments != NULL) {
                    size_t key_len = p - start;

                    segments[count].type = NGX_AUTH_JWT_FIELD_KEY;
                    segments[count].u.key.name = ngx_pnalloc(pool, key_len + 1);
                    if (segments[count].u.key.name == NULL) {
                        return NGX_ERROR;
                    }
                    ngx_memcpy(segments[count].u.key.name, start, key_len);
                    segments[count].u.key.name[key_len] = '\0';
                    segments[count].u.key.len = key_len;
                }

                count++;
                p++; /* skip closing quote */
            } else if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
                       || *p == '_')
            {
                /* unquoted key */
                const char *start = p;

                p++;
                while (p < end && ((*p >= 'a' && *p <= 'z')
                                   || (*p >= 'A' && *p <= 'Z')
                                   || (*p >= '0' && *p <= '9')
                                   || *p == '_' || *p == '-'))
                {
                    p++;
                }

                if (segments != NULL) {
                    size_t key_len = p - start;

                    segments[count].type = NGX_AUTH_JWT_FIELD_KEY;
                    segments[count].u.key.name = ngx_pnalloc(pool, key_len + 1);
                    if (segments[count].u.key.name == NULL) {
                        return NGX_ERROR;
                    }
                    ngx_memcpy(segments[count].u.key.name, start, key_len);
                    segments[count].u.key.name[key_len] = '\0';
                    segments[count].u.key.len = key_len;
                }

                count++;
            } else {
                return NGX_ERROR;
            }
        } else if (*p == '[') {
            p++;

            if (p >= end) {
                return NGX_ERROR;
            }

            if (*p == '*') {
                /* wildcard [*] is not supported in Part 1 */
                return NGX_ERROR;
            }

            if (*p < '0' || *p > '9') {
                return NGX_ERROR;
            }

            {
                size_t idx = 0;
                const char *start = p;

                while (p < end && *p >= '0' && *p <= '9') {
                    size_t digit = *p - '0';

                    if (idx > SIZE_MAX / 10
                        || (idx == SIZE_MAX / 10 && digit > SIZE_MAX % 10))
                    {
                        return NGX_ERROR;
                    }
                    idx = idx * 10 + digit;
                    p++;
                }

                if (p >= end || *p != ']') {
                    return NGX_ERROR;
                }

                /* reject leading zeros (except "0" itself) */
                if (p - start > 1 && *start == '0') {
                    return NGX_ERROR;
                }

                if (segments != NULL) {
                    segments[count].type = NGX_AUTH_JWT_FIELD_INDEX;
                    segments[count].u.index = idx;
                }

                count++;
                p++; /* skip ']' */
            }
        } else {
            return NGX_ERROR;
        }
    }

    if (count == 0) {
        return NGX_ERROR;
    }

    *nsegments = count;

    return NGX_OK;
}


ngx_int_t
ngx_auth_jwt_field_parse(ngx_pool_t *pool, const char *path, size_t len,
    ngx_auth_jwt_field_segment_t **segments, size_t *nsegments)
{
    size_t count;

    if (pool == NULL || path == NULL || len == 0 || segments == NULL
        || nsegments == NULL)
    {
        return NGX_ERROR;
    }

    /* pass 1: count segments */
    if (ngx_auth_jwt_field_scan(pool, path, len, NULL, &count) != NGX_OK) {
        return NGX_ERROR;
    }

    /* overflow guard */
    if (count > SIZE_MAX / sizeof(ngx_auth_jwt_field_segment_t)) {
        return NGX_ERROR;
    }

    /* allocate segment array */
    *segments = ngx_palloc(pool, count * sizeof(ngx_auth_jwt_field_segment_t));
    if (*segments == NULL) {
        return NGX_ERROR;
    }

    /* pass 2: fill segments */
    if (ngx_auth_jwt_field_scan(pool, path, len, *segments, nsegments)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


json_t *
ngx_auth_jwt_field_resolve(json_t *root,
    ngx_auth_jwt_field_segment_t *segments, size_t nsegments)
{
    json_t *current;
    size_t i;

    if (root == NULL || segments == NULL || nsegments == 0) {
        return NULL;
    }

    current = root;

    for (i = 0; i < nsegments; i++) {
        if (current == NULL) {
            return NULL;
        }

        switch (segments[i].type) {
        case NGX_AUTH_JWT_FIELD_KEY:
            if (!json_is_object(current)) {
                return NULL;
            }
            current = json_object_get(current,
                                      segments[i].u.key.name);
            break;

        case NGX_AUTH_JWT_FIELD_INDEX:
            if (!json_is_array(current)) {
                return NULL;
            }
            current = json_array_get(current, segments[i].u.index);
            break;
        }
    }

    return current;
}
