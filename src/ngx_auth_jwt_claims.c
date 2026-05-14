#include <errno.h>
#include <jansson.h>
#include <string.h>
#include "ngx_auth_jwt_claims.h"

/*
 * Layer 2 consumes the JWT view as opaque nxe_json_t handles.  For the
 * key-path traversal and scalar extraction below we use the nxe_json
 * API.  json_dumps() is still used for the *_json accessors because
 * nxe-json does not yet expose JSON_SORT_KEYS, and deterministic
 * ordering is a user-visible contract of $jwt_claim_* / $jwt_header_*
 * variables (asserted by t/auth_jwt_claims.t).  When nxe-json gains a
 * sorted stringify, drop the jansson include entirely.
 */
static nxe_json_t *
get_js_json(nxe_json_t *js, const char *key,
    const char *delim, const char *quote)
{
    nxe_json_t *js_val = NULL;

    if (!js) {
        return NULL;
    }

    js_val = js;

    if (key && strlen(key) && js_val != NULL) {
        nxe_json_t *js_obj = NULL;

        if (delim && delim[0] != '\0') {
            char *s = NULL, *var = NULL, *seg = NULL;
            size_t delim_len = strlen(delim), quote_len = 0;

            var = strdup(key);
            if (!var) {
                return NULL;
            }

            s = var;

            if (quote) {
                quote_len = strlen(quote);
            }

            while (s != NULL && *s != '\0') {
                if (quote_len > 0 && strncmp(s, quote, quote_len) == 0) {
                    /* Quoted segment: find closing quote */
                    char *end;

                    s += quote_len;
                    end = strstr(s, quote);
                    if (end == NULL) {
                        js_val = NULL;
                        break;
                    }
                    *end = '\0';
                    seg = s;
                    s = end + quote_len;

                    /* Skip delimiter after closing quote */
                    if (strncmp(s, delim, delim_len) == 0) {
                        s += delim_len;
                    } else if (*s != '\0') {
                        js_val = NULL;
                        break;
                    }
                } else {
                    /* Unquoted segment: find next delimiter */
                    char *end = strstr(s, delim);

                    if (end != NULL) {
                        *end = '\0';
                        seg = s;
                        s = end + delim_len;
                    } else {
                        seg = s;
                        s = NULL;
                    }
                }

                if (seg[0] != '\0') {
                    js_obj = nxe_json_object_get(js_val, seg);
                    if (js_obj == NULL) {
                        js_val = NULL;
                        break;
                    }
                    js_val = js_obj;
                }
            }

            free(var);
        } else {
            js_obj = nxe_json_object_get(js_val, key);
            if (js_obj == NULL) {
                js_val = NULL;
            } else {
                js_val = js_obj;
            }
        }
    }

    if (js_val == NULL) {
        return NULL;
    }

    return js_val;
}

static const char *
get_js_string(nxe_json_t *js, const char *key,
    const char *delim, const char *quote)
{
    nxe_json_t *js_val = NULL;
    ngx_str_t value;

    if (!key || !strlen(key)) {
        errno = EINVAL;
        return NULL;
    }

    js_val = get_js_json(js, key, delim, quote);
    if (js_val == NULL) {
        errno = ENOENT;
        return NULL;
    }

    if (nxe_json_string(js_val, &value) != NGX_OK) {
        errno = EINVAL;
        return NULL;
    }

    /* nxe_json_string returns data backed by jansson storage which is
     * NUL-terminated at value.len; safe to expose as const char *. */
    return (const char *) value.data;
}

static long
get_js_int(nxe_json_t *js, const char *key,
    const char *delim, const char *quote)
{
    nxe_json_t *js_val = NULL;
    int64_t value;

    if (!key || !strlen(key)) {
        errno = EINVAL;
        return 0;
    }

    js_val = get_js_json(js, key, delim, quote);
    if (js_val == NULL) {
        errno = ENOENT;
        return 0;
    }

    if (nxe_json_integer(js_val, &value) != NGX_OK) {
        errno = EINVAL;
        return -1;
    }

    return (long) value;
}

static int
get_js_bool(nxe_json_t *js, const char *key,
    const char *delim, const char *quote)
{
    nxe_json_t *js_val = NULL;
    ngx_flag_t value;

    if (!key || !strlen(key)) {
        errno = EINVAL;
        return 0;
    }

    js_val = get_js_json(js, key, delim, quote);
    if (js_val == NULL) {
        errno = ENOENT;
        return 0;
    }

    if (nxe_json_boolean(js_val, &value) != NGX_OK) {
        errno = EINVAL;
        return 0;
    }

    return value ? 1 : 0;
}

static char *
dump_js_sorted_compact(nxe_json_t *js)
{
    /* nxe-json lacks a JSON_SORT_KEYS option; reach down to the
     * underlying jansson handle to keep $jwt_*_set output deterministic.
     * Drop this once nxe-json exposes a sorted stringify. */
    return json_dumps((const json_t *) js,
                      JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
}

const char *
ngx_auth_jwt_claims_get_header(ngx_auth_jwt_t *jwt, const char *header,
    const char *delim, const char *quote)
{
    if (!jwt) {
        errno = EINVAL;
        return NULL;
    }

    errno = 0;

    return get_js_string(jwt->headers, header, delim, quote);
}

long
ngx_auth_jwt_claims_get_header_int(ngx_auth_jwt_t *jwt, const char *header,
    const char *delim, const char *quote)
{
    if (!jwt) {
        errno = EINVAL;
        return 0;
    }

    errno = 0;

    return get_js_int(jwt->headers, header, delim, quote);
}

int
ngx_auth_jwt_claims_get_header_bool(ngx_auth_jwt_t *jwt, const char *header,
    const char *delim, const char *quote)
{
    if (!jwt) {
        errno = EINVAL;
        return 0;
    }

    errno = 0;

    return get_js_bool(jwt->headers, header, delim, quote);
}

char *
ngx_auth_jwt_claims_get_headers_json(ngx_auth_jwt_t *jwt, const char *header,
    const char *delim, const char *quote)
{
    nxe_json_t *js_val = NULL;

    if (!jwt) {
        errno = EINVAL;
        return NULL;
    }

    js_val = get_js_json(jwt->headers, header, delim, quote);
    if (js_val == NULL) {
        errno = ENOENT;
        return NULL;
    }

    errno = 0;

    return dump_js_sorted_compact(js_val);
}

const char *
ngx_auth_jwt_claims_get_grant(ngx_auth_jwt_t *jwt, const char *grant,
    const char *delim, const char *quote)
{
    if (!jwt) {
        errno = EINVAL;
        return NULL;
    }

    errno = 0;

    return get_js_string(jwt->payload, grant, delim, quote);
}

long
ngx_auth_jwt_claims_get_grant_int(ngx_auth_jwt_t *jwt, const char *grant,
    const char *delim, const char *quote)
{
    if (!jwt) {
        errno = EINVAL;
        return 0;
    }

    errno = 0;

    return get_js_int(jwt->payload, grant, delim, quote);
}

int
ngx_auth_jwt_claims_get_grant_bool(ngx_auth_jwt_t *jwt, const char *grant,
    const char *delim, const char *quote)
{
    if (!jwt) {
        errno = EINVAL;
        return 0;
    }

    errno = 0;

    return get_js_bool(jwt->payload, grant, delim, quote);
}

char *
ngx_auth_jwt_claims_get_grants_json(ngx_auth_jwt_t *jwt, const char *grant,
    const char *delim, const char *quote)
{
    nxe_json_t *js_val = NULL;

    if (!jwt) {
        errno = EINVAL;
        return NULL;
    }

    js_val = get_js_json(jwt->payload, grant, delim, quote);
    if (js_val == NULL) {
        errno = ENOENT;
        return NULL;
    }

    errno = 0;

    return dump_js_sorted_compact(js_val);
}
