#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_jwt_decode.h"
#include "ngx_auth_jwt_jwks.h"
#include "ngx_auth_jwt_jws.h"
#include "ngx_auth_jwt_claims.h"
#include "ngx_auth_jwt_field.h"
#include "ngx_auth_jwt_operator.h"

#define NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX "jwt_claim_"
#define NGX_HTTP_AUTH_JWT_HEADER_VAR_PREFIX "jwt_header_"

static ngx_int_t ngx_http_auth_jwt_variable_claim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_jwt_variable_header(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_jwt_variable_claims(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_jwt_variable_nowtime(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static char *ngx_http_auth_jwt_conf_set_token_variable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_claim(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_header(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_key_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_key_request(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_revocation(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char * ngx_http_auth_jwt_conf_set_requirement(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_require_variable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_allow_nested(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_auth_jwt_pre_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_jwt_post_conf(ngx_conf_t *cf);
static void *ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static void ngx_http_auth_jwt_exit_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_auth_jwt_preaccess_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_jwt_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r,
    ngx_int_t phase);

static void ngx_http_auth_jwt_cleanup(void *data);

typedef struct {
    ngx_int_t    token_variable;
    ngx_array_t *set_vars;
    time_t       leeway;
    ngx_int_t    phase;
    ngx_flag_t   enabled;
    ngx_str_t    realm;
    struct {
        json_t *subs;
        json_t *kids;
    } revocation;
    struct {
        ngx_array_t                *files;
        ngx_array_t                *requests;
        ngx_auth_jwt_jwks_keyset_t *vars;
    } key;
    struct {
        ngx_flag_t  exp;
        ngx_flag_t  sig;
        struct {
            ngx_array_t *claims;
            ngx_array_t *headers;
        } requirement;
        struct {
            ngx_int_t    error;
            ngx_array_t *values;
        } variable;
    } validate;
    struct {
        char *delimiter;
        char *quote;
    } nested;
} ngx_http_auth_jwt_loc_conf_t;

typedef struct {
    ngx_int_t   index;
    ngx_flag_t  jwks;
} ngx_http_auth_jwt_key_file_t;

typedef struct {
    ngx_flag_t                  use_bearer;
    ngx_uint_t                  done;
    ngx_uint_t                  subrequest;
    ngx_flag_t                  verified;
    u_char                     *token;
    unsigned int                payload_len;
    ngx_auth_jwt_t             *jwt;
    ngx_auth_jwt_jwks_keyset_t *keys;
    ngx_int_t                   status;
    ngx_flag_t                  reject_request;
} ngx_http_auth_jwt_ctx_t;

typedef struct {
    ngx_http_complex_value_t     *value;
    char                         *name;
    char                         *operator;
    ngx_auth_jwt_field_segment_t *segments;
    size_t                        nsegments;
#if (NGX_PCRE)
    ngx_regex_t                  *regex;
#endif
} ngx_http_auth_jwt_requirement_t;

typedef struct {
    ngx_int_t                index;
    ngx_str_t                url;
    ngx_flag_t               jwks;
    ngx_http_auth_jwt_ctx_t *ctx;
} ngx_http_auth_jwt_key_request_t;

typedef const char *(*auth_jwt_get)(ngx_auth_jwt_t *jwt, const char *key,
    const char *delim, const char *quote);
typedef char *(*auth_jwt_get_json)(ngx_auth_jwt_t *jwt, const char *key,
    const char *delim, const char *quote);

static ngx_conf_enum_t ngx_http_auth_jwt_phases[] = {
    { ngx_string("PREACCESS"), NGX_HTTP_PREACCESS_PHASE },
    { ngx_string("ACCESS"), NGX_HTTP_ACCESS_PHASE },
    { ngx_null_string, 0 }
};

static char *ngx_http_auth_jwt_require_operators[] = {
    NGX_AUTH_JWT_OPERATOR_EQ,
    NGX_AUTH_JWT_OPERATOR_NE,
    NGX_AUTH_JWT_OPERATOR_GT,
    NGX_AUTH_JWT_OPERATOR_GE,
    NGX_AUTH_JWT_OPERATOR_LT,
    NGX_AUTH_JWT_OPERATOR_LE,
    NGX_AUTH_JWT_OPERATOR_ANY,
    NGX_AUTH_JWT_OPERATOR_INTERSECT,
    NGX_AUTH_JWT_OPERATOR_NINTERSECT,
    NGX_AUTH_JWT_OPERATOR_IN,
    NGX_AUTH_JWT_OPERATOR_NIN,
#if (NGX_PCRE)
    NGX_AUTH_JWT_OPERATOR_MATCH,
#endif
    NULL,
};

static ngx_http_variable_t ngx_http_auth_jwt_vars[] = {
    { ngx_string(NGX_HTTP_AUTH_JWT_HEADER_VAR_PREFIX),
      NULL,
      ngx_http_auth_jwt_variable_header,
      0,
      NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_PREFIX,
      0 },
    { ngx_string(NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX),
      NULL,
      ngx_http_auth_jwt_variable_claim,
      0,
      NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_PREFIX,
      0 },
    { ngx_string("jwt_claims"),
      NULL,
      ngx_http_auth_jwt_variable_claims,
      0,
      NGX_HTTP_VAR_NOCACHEABLE,
      0 },
    { ngx_string("jwt_nowtime"),
      NULL,
      ngx_http_auth_jwt_variable_nowtime,
      0,
      NGX_HTTP_VAR_NOCACHEABLE,
      0 },
    ngx_http_null_variable
};

static ngx_command_t ngx_http_auth_jwt_commands[] = {
    { ngx_string("auth_jwt"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF
      | NGX_CONF_TAKE12,
      ngx_http_auth_jwt_conf_set_token_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("auth_jwt_revocation_list_sub"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF
      | NGX_CONF_TAKE1,
      ngx_http_auth_jwt_conf_set_revocation,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_jwt_loc_conf_t, revocation.subs),
      NULL },
    { ngx_string("auth_jwt_revocation_list_kid"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF
      | NGX_CONF_TAKE1,
      ngx_http_auth_jwt_conf_set_revocation,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_jwt_loc_conf_t, revocation.kids),
      NULL },
    { ngx_string("auth_jwt_require_claim"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF
      | NGX_CONF_TAKE3,
      ngx_http_auth_jwt_conf_set_requirement,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_jwt_loc_conf_t, validate.requirement.claims),
      NULL },
    { ngx_string("auth_jwt_require_header"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF
      | NGX_CONF_TAKE3,
      ngx_http_auth_jwt_conf_set_requirement,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_jwt_loc_conf_t, validate.requirement.headers),
      NULL },
    { ngx_string("auth_jwt_require"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF
      | NGX_CONF_1MORE,
      ngx_http_auth_jwt_conf_set_require_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("auth_jwt_claim_set"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2,
      ngx_http_auth_jwt_conf_set_claim,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("auth_jwt_header_set"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2,
      ngx_http_auth_jwt_conf_set_header,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("auth_jwt_key_file"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF
      | NGX_CONF_TAKE12,
      ngx_http_auth_jwt_conf_set_key_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("auth_jwt_key_request"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF
      | NGX_CONF_TAKE12,
      ngx_http_auth_jwt_conf_set_key_request,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("auth_jwt_leeway"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_jwt_loc_conf_t, leeway),
      NULL },
    { ngx_string("auth_jwt_phase"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_jwt_loc_conf_t, phase),
      &ngx_http_auth_jwt_phases },
    { ngx_string("auth_jwt_validate_exp"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF
      | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_jwt_loc_conf_t, validate.exp),
      NULL },
    { ngx_string("auth_jwt_validate_sig"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF
      | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_jwt_loc_conf_t, validate.sig),
      NULL },
    { ngx_string("auth_jwt_allow_nested"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_NOARGS | NGX_CONF_TAKE1 | NGX_CONF_TAKE2,
      ngx_http_auth_jwt_conf_set_allow_nested,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_auth_jwt_module_ctx = {
    ngx_http_auth_jwt_pre_conf,      /* preconfiguration */
    ngx_http_auth_jwt_post_conf,     /* postconfiguration */
    NULL,                            /* create main configuration */
    NULL,                            /* init main configuration */
    NULL,                            /* create server configuration */
    NULL,                            /* merge server configuration */
    ngx_http_auth_jwt_create_loc_conf, /* create location configuration */
    ngx_http_auth_jwt_merge_loc_conf /* merge location configuration */
};

ngx_module_t ngx_http_auth_jwt_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_jwt_module_ctx, /* module context */
    ngx_http_auth_jwt_commands,   /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    ngx_http_auth_jwt_exit_process, /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING
};

static u_char *
ngx_http_auth_jwt_strdup(ngx_pool_t *pool, u_char *data, size_t len)
{
    u_char *dst;

    dst = ngx_pnalloc(pool, len + 1);
    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, data, len);
    dst[len] = '\0';

    return dst;
}

static int
ngx_http_auth_jwt_key_import_file(ngx_pool_t *pool,
    ngx_auth_jwt_jwks_keyset_t **keyset,
    const char *path, const int is_jwks)
{
    ngx_auth_jwt_jwks_keyset_t *loaded;

    if (path == NULL) {
        return 1;
    }

    loaded = ngx_auth_jwt_jwks_load_file(pool, path, is_jwks);
    if (loaded == NULL) {
        return 1;
    }

    if (*keyset == NULL) {
        *keyset = loaded;
    }else {
        if (ngx_auth_jwt_jwks_append(*keyset, loaded) != 0) {
            ngx_auth_jwt_jwks_free(loaded);
            return 1;
        }
        ngx_auth_jwt_jwks_free(loaded);
    }

    return 0;
}

static int
ngx_http_auth_jwt_fill_list_object_by_file(json_t **object, const char *path)
{
    json_t *keyval = NULL;
    const char *key = NULL;
    json_t *value = NULL;

    if (path == NULL) {
        return 1;
    }

    keyval = json_load_file(path, 0, NULL);
    if (keyval == NULL) {
        return 1;
    }

    if (!json_is_object(keyval)) {
        json_delete(keyval);
        return 1;
    }

    if (*object == NULL) {
        *object = json_object();
    }

    json_object_foreach((json_t *) keyval, key, value) {
        if (!key) {
            continue;
        }

        json_object_set_new(*object, key, json_copy(value));
    }

    json_delete(keyval);

    return 0;
}

static int
ngx_http_auth_jwt_key_import_string(ngx_pool_t *pool,
    ngx_auth_jwt_jwks_keyset_t **keyset,
    const char *input, const size_t len,
    const int is_jwks)
{
    ngx_auth_jwt_jwks_keyset_t *loaded;
    size_t actual_len;

    if (input == NULL) {
        return 1;
    }

    actual_len = (len > 0) ? len : strlen(input);

    if (is_jwks) {
        loaded = ngx_auth_jwt_jwks_parse(pool, input, actual_len);
    }else {
        loaded = ngx_auth_jwt_jwks_parse_keyval(pool, input, actual_len);
    }

    if (loaded == NULL) {
        return 1;
    }

    if (*keyset == NULL) {
        *keyset = loaded;
    }else {
        if (ngx_auth_jwt_jwks_append(*keyset, loaded) != 0) {
            ngx_auth_jwt_jwks_free(loaded);
            return 1;
        }
        ngx_auth_jwt_jwks_free(loaded);
    }

    return 0;
}

static ngx_http_auth_jwt_ctx_t *
ngx_http_auth_jwt_get_module_ctx(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t *cln;
    ngx_http_auth_jwt_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);

    if (ctx == NULL && (r->internal || r->filter_finalize)) {
        /*
         * if module context was reset, the original address
         * can still be found in the cleanup handler
         */
        for (cln = r->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == ngx_http_auth_jwt_cleanup) {
                ctx = cln->data;
                break;
            }
        }
    }

    return ctx;
}

typedef enum {
    NGX_HTTP_AUTH_JWT_VARIABLE_HEADER = 0,
    NGX_HTTP_AUTH_JWT_VARIABLE_CLAIM,
    NGX_HTTP_AUTH_JWT_VARIABLE_CLAIMS
} ngx_http_auth_jwt_variable_find_t;

static ngx_int_t
ngx_http_auth_jwt_variable_find(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,
    const ngx_str_t *name,
    const ngx_http_auth_jwt_variable_find_t use)
{
    char *str = NULL, *prefix = NULL;
    const char *value;
    size_t len, prefix_len;
    u_char *data, *key = NULL, *var;
    ngx_http_auth_jwt_ctx_t *ctx;
    ngx_http_auth_jwt_loc_conf_t *cf;
    auth_jwt_get jwt_get;
    auth_jwt_get_json jwt_get_json;

    ctx = ngx_http_auth_jwt_get_module_ctx(r);
    if (!ctx || !ctx->jwt) {
        v->not_found = 1;
        return NGX_OK;
    }

    cf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);
    if (!cf) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (use == NGX_HTTP_AUTH_JWT_VARIABLE_HEADER) {
        prefix = NGX_HTTP_AUTH_JWT_HEADER_VAR_PREFIX;
        jwt_get = ngx_auth_jwt_claims_get_header;
        jwt_get_json = ngx_auth_jwt_claims_get_headers_json;
    }else {
        if (!ctx->verified) {
            v->not_found = 1;
            return NGX_OK;
        }

        if (use == NGX_HTTP_AUTH_JWT_VARIABLE_CLAIM) {
            prefix = NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX;
        }
        jwt_get = ngx_auth_jwt_claims_get_grant;
        jwt_get_json = ngx_auth_jwt_claims_get_grants_json;
    }

    if (prefix) {
        prefix_len = strlen(prefix);
        len = name->len - prefix_len;
        var = name->data + prefix_len;

        if (len == 0) {
            v->not_found = 1;
            return NGX_OK;
        }

        key = ngx_pcalloc(r->pool, len + 1);
        if (key == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(key, var, len);
    }

    value = (*jwt_get)(ctx->jwt, (char *) key,
                       cf->nested.delimiter, cf->nested.quote);
    if (value == NULL) {
        size_t i, t;

        str = (*jwt_get_json)(ctx->jwt, (char *) key,
                              cf->nested.delimiter, cf->nested.quote);
        if (str == NULL) {
            v->not_found = 1;
            return NGX_OK;
        }

        if (use == NGX_HTTP_AUTH_JWT_VARIABLE_CLAIM) {
            len = strlen(str);

            for (i = t = 0; i < len; i++) {
                switch (str[i]) {
                case '[':
                case ']':
                case '"':
                    break;
                default:
                    str[t++] = str[i];
                }
            }
            str[t] = '\0';
        }

        value = str;
    }

    len = strlen(value);
    data = ngx_pcalloc(r->pool, len + 1);
    if (data == NULL) {
        if (str) {
            free(str);
        }
        return NGX_ERROR;
    }
    ngx_memcpy(data, value, len);

    if (str) {
        free(str);
    }

    v->data = data;
    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_jwt_variable_header(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return ngx_http_auth_jwt_variable_find(r, v, (ngx_str_t *) data,
                                           NGX_HTTP_AUTH_JWT_VARIABLE_HEADER);
}

static ngx_int_t
ngx_http_auth_jwt_variable_claim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return ngx_http_auth_jwt_variable_find(r, v, (ngx_str_t *) data,
                                           NGX_HTTP_AUTH_JWT_VARIABLE_CLAIM);
}

static ngx_int_t
ngx_http_auth_jwt_variable_claims(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return ngx_http_auth_jwt_variable_find(r, v, (ngx_str_t *) data,
                                           NGX_HTTP_AUTH_JWT_VARIABLE_CLAIMS);
}

static ngx_int_t
ngx_http_auth_jwt_variable_nowtime(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,
    uintptr_t data)
{
    time_t now;

    v->data = ngx_pnalloc(r->pool, sizeof("4294967295") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    now = ngx_time();

    v->len = ngx_sprintf(v->data, "%ui", now) - v->data;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static char *
ngx_http_auth_jwt_conf_set_token_variable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_jwt_loc_conf_t *lcf;
    ngx_str_t *value;

    lcf = conf;
    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        lcf->enabled = 0;
        return NGX_CONF_OK;
    }

    lcf->enabled = 1;

    lcf->realm.data = value[1].data;
    lcf->realm.len = value[1].len;

    if (cf->args->nelts > 2) {
        /* check argument starts with "token=" */
        const char *starts_with = "token=";
        const size_t starts_with_len = sizeof("token=") - 1;
        if (value[2].len <= starts_with_len
            || ngx_strncmp(value[2].data, starts_with, starts_with_len) != 0)
        {
            return "no token specified";
        }

        value[2].data = value[2].data + starts_with_len;
        value[2].len = value[2].len - starts_with_len;

        if (value[2].data[0] != '$') {
            return "token is not a variable specified";
        }

        value[2].data++;
        value[2].len--;

        lcf->token_variable = ngx_http_get_variable_index(cf, &value[2]);
        if (lcf->token_variable == NGX_ERROR) {
            return "no token variables";
        }
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_jwt_conf_set_variable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf,
    const char *prefix,
    ngx_http_get_variable_pt get_handler)
{
    ngx_http_auth_jwt_loc_conf_t *lcf;
    ngx_str_t *str, *value;
    ngx_http_variable_t *var;
    size_t prefix_len = strlen(prefix);

    lcf = conf;
    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        return "not a variable specified";
    }

    value[1].data++;
    value[1].len--;

    if (lcf->set_vars == NGX_CONF_UNSET_PTR) {
        lcf->set_vars = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (lcf->set_vars == NULL) {
            return "failed to allocate";
        }
    }

    str = ngx_array_push(lcf->set_vars);
    if (str == NULL) {
        return "failed to allocate iteam";
    }

    str->len = value[2].len + prefix_len;
    str->data = ngx_pnalloc(cf->pool, str->len);
    if (str->data == NULL) {
        return "failed to allocate variable";
    }

    ngx_memcpy(str->data, prefix, prefix_len);
    ngx_memcpy(str->data + prefix_len, value[2].data, value[2].len);

    var = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return "failed to add variable";
    }

    var->get_handler = get_handler;
    var->data = (uintptr_t) str;

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_jwt_conf_set_claim(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    return
        ngx_http_auth_jwt_conf_set_variable(cf, cmd, conf,
                                            NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX,
                                            ngx_http_auth_jwt_variable_claim);
}

static char *
ngx_http_auth_jwt_conf_set_header(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    return
        ngx_http_auth_jwt_conf_set_variable(cf, cmd, conf,
                                            NGX_HTTP_AUTH_JWT_HEADER_VAR_PREFIX,
                                            ngx_http_auth_jwt_variable_header);
}

static char *
ngx_http_auth_jwt_conf_set_revocation(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    char *file;
    ngx_str_t *value;
    json_t **revocation;
    char *p = conf;

    revocation = (json_t **) (p + cmd->offset);

    value = cf->args->elts;

    if (value[1].len == 0) {
        return "is empty";
    }

    if (ngx_conf_full_name(cf->cycle, &value[1], 1) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" directive failed to get full name: \"%V\"",
                           &cmd->name, &value[1]);
        return NGX_CONF_ERROR;
    }

    file = (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                             value[1].data, value[1].len);
    if (file == NULL) {
        return "failed to allocate file";
    }

    if (ngx_http_auth_jwt_fill_list_object_by_file(revocation, file) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" directive failed to load file: \"%s\"",
                           &cmd->name,file);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_jwt_conf_set_key_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    char *file;
    ngx_flag_t jwks = 1;
    ngx_http_auth_jwt_loc_conf_t *lcf;
    ngx_str_t *value;

    lcf = conf;
    value = cf->args->elts;

    if (value[1].len == 0) {
        return "is empty";
    }

    if (cf->args->nelts > 2 && value[2].len > 0) {
        if (ngx_strncmp("keyval", value[2].data, value[2].len) == 0) {
            jwks = 0;
        }else if (ngx_strncmp("jwks", value[2].data, value[2].len) != 0) {
            return "format is incorrect";
        }
    }

    if (value[1].data[0] == '$') {
        ngx_str_t var;
        ngx_http_auth_jwt_key_file_t *key_file;

        if (lcf->key.files == NULL) {
            lcf->key.files = ngx_array_create(cf->pool, 1, sizeof(*key_file));
            if (lcf->key.files == NULL) {
                return "failed to allocate";
            }
        }

        key_file = ngx_array_push(lcf->key.files);
        if (key_file == NULL) {
            return "failed to allocate item";
        }

        var.len = value[1].len - 1;
        var.data = value[1].data + 1;

        key_file->index = ngx_http_get_variable_index(cf, &var);
        if (key_file->index == NGX_ERROR) {
            return "no variables";
        }

        key_file->jwks = jwks;

        return NGX_CONF_OK;
    }

    if (ngx_conf_full_name(cf->cycle, &value[1], 1) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" directive failed to get full name: \"%V\"",
                           &cmd->name, &value[1]);
        return NGX_CONF_ERROR;
    }

    file = (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                             value[1].data, value[1].len);
    if (file == NULL) {
        return "failed to allocate file";
    }

    if (ngx_http_auth_jwt_key_import_file(cf->pool, &lcf->key.vars, file,
                                          jwks) != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" directive failed to load %s file: \"%s\"",
                           &cmd->name, (jwks ? "jwks" : "key"), file);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_jwt_conf_set_requirement(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_array_t **requirements;
    ngx_http_auth_jwt_requirement_t *requirement;
    char *p = conf;

    requirements = (ngx_array_t **) (p + cmd->offset);

    value = cf->args->elts;

    if (cf->args->nelts != 4) {
        return "invalid params count in require";
    }

    if (*requirements == NULL) {
        *requirements = ngx_array_create(cf->pool, 4, sizeof(*requirement));
        if (*requirements == NULL) {
            return "failed to allocate memory for require";
        }
    }

    requirement = ngx_array_push(*requirements);
    if (requirement == NULL) {
        return "failed to allocate item for require";
    }

    if (value[1].len != 0) {
        requirement->name = (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                                              value[1].data,
                                                              value[1].len);
        if (requirement->name == NULL) {
            return "failed to allocate item for require name";
        }
        requirement->segments = NULL;
        requirement->nsegments = 0;

        if (ngx_auth_jwt_field_is_jq_path((char *) value[1].data,
                                          value[1].len))
        {
            if (ngx_auth_jwt_field_parse(cf->pool,
                                         (char *) value[1].data, value[1].len,
                                         &requirement->segments,
                                         &requirement->nsegments) != NGX_OK)
            {
                return "invalid JQ-like field path syntax";
            }

            if (requirement->nsegments == 1
                && requirement->segments[0].type == NGX_AUTH_JWT_FIELD_KEY)
            {
                requirement->name = requirement->segments[0].u.key.name;
            }
        }
    }else {
        return "first argument should not be empty";
    }
    if (value[2].len != 0) {
        ngx_flag_t invalid_operator = 1;
        u_char *op_name = value[2].data;
        size_t op_len = value[2].len;

        /* skip '!' negate prefix for validation */
        if (op_len > 1 && op_name[0] == '!') {
            op_name++;
            op_len--;
        }

        for (int i = 0; ngx_http_auth_jwt_require_operators[i] != NULL; i++) {
            if (ngx_strlen(ngx_http_auth_jwt_require_operators[i]) == op_len
                && ngx_strncmp(ngx_http_auth_jwt_require_operators[i],
                               (char *) op_name, op_len) == 0)
            {
                invalid_operator = 0;
                break;
            }
        }
        if (invalid_operator == 1) {
            return
                "second argument should be one of available require operators";
        }
        requirement->operator = (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                                                  value[2].data,
                                                                  value[2].len);
    }else {
        return "second argument should not be empty";
    }

    if (value[3].len != 0) {
        ngx_http_compile_complex_value_t ccv;

        requirement->value = ngx_palloc(cf->pool,
                                        sizeof(ngx_http_complex_value_t));
        if (requirement->value == NULL) {
            return "failed to allocate value variables";
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[3];
        ccv.complex_value = requirement->value;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return "no value variables";
        }
    }else {
        return "third argument should be variable";
    }

#if (NGX_PCRE)
    requirement->regex = NULL;

    /* precompile regex for match operator with static value */
    if (ngx_strcmp(requirement->operator,
                   NGX_AUTH_JWT_OPERATOR_MATCH) == 0
        || ngx_strcmp(requirement->operator, "!" NGX_AUTH_JWT_OPERATOR_MATCH)
        == 0)
    {
        if (requirement->value->lengths == NULL) {
            u_char *pattern_data;
            size_t pattern_len;
            ngx_auth_jwt_json_t *pattern_json = NULL;
            ngx_regex_compile_t rgc;
            u_char errstr[NGX_MAX_CONF_ERRSTR];

            /* static value: decode JSON exactly like the request-time path */
            pattern_data = value[3].data;
            pattern_len = value[3].len;

            if (pattern_len > 5
                && ngx_strncmp(pattern_data, "json=", 5) == 0)
            {
                const char *pattern_str;
                size_t decoded_len;

                pattern_json = ngx_auth_jwt_json_parse(
                    (const char *) (pattern_data + 5), pattern_len - 5);

                if (pattern_json == NULL
                    || ngx_auth_jwt_json_string(pattern_json, &pattern_str,
                                                &decoded_len) != NGX_OK)
                {
                    ngx_auth_jwt_json_free(pattern_json);
                    return "match operator requires a JSON string pattern";
                }

                pattern_data = (u_char *) pattern_str;
                pattern_len = decoded_len;
            }

            if (pattern_len > NGX_AUTH_JWT_MAX_REGEX_SIZE) {
                ngx_auth_jwt_json_free(pattern_json);
                return "regex pattern too large";
            }

            ngx_memzero(&rgc, sizeof(ngx_regex_compile_t));
            rgc.pattern.data = pattern_data;
            rgc.pattern.len = pattern_len;
            rgc.pool = cf->pool;
            rgc.err.data = errstr;
            rgc.err.len = NGX_MAX_CONF_ERRSTR;

            if (ngx_regex_compile(&rgc) != NGX_OK) {
                ngx_auth_jwt_json_free(pattern_json);
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "regex compile failed: %V", &rgc.err);
                return NGX_CONF_ERROR;
            }

            ngx_auth_jwt_json_free(pattern_json);
            requirement->regex = rgc.regex;
        }
    }
#endif

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_jwt_conf_set_require_variable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_jwt_loc_conf_t *lcf;
    ngx_str_t *value;
    ngx_uint_t i, n;
    const char *error_with = "error=";
    const size_t error_with_len = sizeof("error=") - 1;

    lcf = conf;
    value = cf->args->elts;
    n = cf->args->nelts - 1;

    if (lcf->validate.variable.values == NULL) {
        lcf->validate.variable.values =
            ngx_array_create(cf->pool, 4, sizeof(ngx_http_complex_value_t));
        if (lcf->validate.variable.values == NULL) {
            return "failed to allocate memory for require";
        }
    }

    if (value[n].len >= error_with_len
        && ngx_strncmp(value[n].data, error_with, error_with_len) == 0)
    {
        value[n].data += error_with_len;
        value[n].len -= error_with_len;

        lcf->validate.variable.error = ngx_atoi(value[n].data, value[n].len);
        if (lcf->validate.variable.error < 400
            || lcf->validate.variable.error > 599
            || lcf->validate.variable.error == 444
            || lcf->validate.variable.error == 499)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" directive error code must be 400-599 "
                               "(excluding 444 and 499): \"%V\"",
                               &cmd->name, &value[n]);
            return NGX_CONF_ERROR;
        }

        --n;
        if (n == 0) {
            return "at least one variable must be specified";
        }
    }

    for (i = 1; i <= n; i++) {
        ngx_http_complex_value_t *var;
        ngx_http_compile_complex_value_t ccv;

        if (value[i].data[0] != '$') {
            return "not a variable specified";
        }

        var = ngx_array_push(lcf->validate.variable.values);
        if (var == NULL) {
            return "failed to allocate item for require";
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = var;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return "no value variables";
        }
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_jwt_conf_set_key_request(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_flag_t jwks = 1;
    ngx_http_auth_jwt_loc_conf_t *lcf;
    ngx_str_t *value;
    ngx_http_auth_jwt_key_request_t *key_request;

    lcf = conf;
    value = cf->args->elts;

    if (value[1].len == 0) {
        return "is empty";
    }

    if (cf->args->nelts > 2 && value[2].len > 0) {
        if (ngx_strncmp("keyval", value[2].data, value[2].len) == 0) {
            jwks = 0;
        }else if (ngx_strncmp("jwks", value[2].data, value[2].len) != 0) {
            return "format is incorrect";
        }
    }

    if (lcf->key.requests == NULL) {
        lcf->key.requests = ngx_array_create(cf->pool, 1, sizeof(*key_request));
        if (lcf->key.requests == NULL) {
            return "failed to allocate";
        }
    }

    key_request = ngx_array_push(lcf->key.requests);
    if (key_request == NULL) {
        return "failed to allocate item";
    }

    if (value[1].data[0] == '$') {
        ngx_str_t var;

        var.len = value[1].len - 1;
        var.data = value[1].data + 1;

        key_request->index = ngx_http_get_variable_index(cf, &var);
        if (key_request->index == NGX_ERROR) {
            return "no variables";
        }

        ngx_str_null(&key_request->url);
    }else {
        key_request->index = -1;
        key_request->url = value[1];
    }

    key_request->jwks = jwks;

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_jwt_conf_set_allow_nested(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_uint_t i;
    ngx_http_auth_jwt_loc_conf_t *lcf;
    ngx_str_t *value;

    lcf = conf;
    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "delimiter=", 10) == 0
            && value[i].len > 10)
        {
            value[i].data += 10;
            value[i].len -= 10;
            lcf->nested.delimiter = (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                                                      value[i].
                                                                      data,
                                                                      value[i].
                                                                      len);
            continue;
        }

        if (ngx_strncmp(value[i].data, "quote=", 6) == 0 && value[i].len > 6) {
            value[i].data += 6;
            value[i].len -= 6;
            lcf->nested.quote = (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                                                  value[i].data,
                                                                  value[i].len);
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" invalid parameter \"%V\"",
                           &cmd->name, &value[i]);
        return NGX_CONF_ERROR;
    }

    if (lcf->nested.delimiter == NULL) {
        lcf->nested.delimiter = (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                                                  (u_char *) ".",
                                                                  1);
    }

    if (lcf->nested.quote == NULL) {
        lcf->nested.quote = (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                                              (u_char *) "\"",
                                                              1);
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_jwt_pre_conf(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_auth_jwt_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_jwt_post_conf(ngx_conf_t *cf)
{
    ngx_http_handler_pt *handler;
    ngx_http_core_main_conf_t *conf;

    conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    handler = ngx_array_push(&conf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (handler == NULL) {
        return NGX_ERROR;
    }
    *handler = ngx_http_auth_jwt_preaccess_handler;

    handler = ngx_array_push(&conf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (handler == NULL) {
        return NGX_ERROR;
    }
    *handler = ngx_http_auth_jwt_access_handler;

    return NGX_OK;
}

static void *
ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_jwt_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_jwt_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->token_variable = NGX_CONF_UNSET;
    conf->set_vars = NGX_CONF_UNSET_PTR;
    conf->leeway = NGX_CONF_UNSET;
    conf->phase = NGX_CONF_UNSET;
    conf->key.files = NULL;
    conf->key.requests = NULL;
    conf->key.vars = NULL;
    conf->revocation.subs = NULL;
    conf->revocation.kids = NULL;
    conf->validate.requirement.claims = NULL;
    conf->validate.requirement.headers = NULL;
    conf->validate.variable.error = NGX_CONF_UNSET;
    conf->validate.variable.values = NULL;
    conf->validate.exp = NGX_CONF_UNSET;
    conf->validate.sig = NGX_CONF_UNSET;
    conf->nested.delimiter = NULL;
    conf->nested.quote = NULL;

    conf->enabled = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_jwt_loc_conf_t *prev = parent;
    ngx_http_auth_jwt_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->token_variable,
                         prev->token_variable, NGX_CONF_UNSET);
    ngx_conf_merge_ptr_value(conf->set_vars, prev->set_vars, NULL);

    if (conf->key.files == NULL || conf->key.files->nelts == 0) {
        conf->key.files = prev->key.files;
    }else if (prev->key.files && prev->key.files->nelts) {
        ngx_uint_t i, len, n;
        ngx_http_auth_jwt_key_file_t *key_file, *var;

        len = conf->key.files->nelts;
        n = prev->key.files->nelts;

        ngx_array_push_n(conf->key.files, n);

        key_file = conf->key.files->elts;
        var = prev->key.files->elts;

        for (i = 0; i < len; i++) {
            key_file[n + i] = key_file[i];
        }
        for (i = 0; i < n; i++) {
            key_file[i] = var[i];
        }
    }

    if (conf->validate.requirement.claims == NULL
        || conf->validate.requirement.claims->nelts == 0)
    {
        conf->validate.requirement.claims = prev->validate.requirement.claims;
    }else if (prev->validate.requirement.claims
              && prev->validate.requirement.claims->nelts)
    {
        ngx_uint_t i, len, n;
        ngx_http_auth_jwt_requirement_t *requirement, *var;

        len = conf->validate.requirement.claims->nelts;
        n = prev->validate.requirement.claims->nelts;

        ngx_array_push_n(conf->validate.requirement.claims, n);

        requirement = conf->validate.requirement.claims->elts;
        var = prev->validate.requirement.claims->elts;

        for (i = 0; i < len; i++) {
            requirement[n + i] = requirement[i];
        }
        for (i = 0; i < n; i++) {
            requirement[i] = var[i];
        }
    }

    if (conf->validate.requirement.headers == NULL
        || conf->validate.requirement.headers->nelts == 0)
    {
        conf->validate.requirement.headers = prev->validate.requirement.headers;
    }else if (prev->validate.requirement.headers
              && prev->validate.requirement.headers->nelts)
    {
        ngx_uint_t i, len, n;
        ngx_http_auth_jwt_requirement_t *requirement, *var;

        len = conf->validate.requirement.headers->nelts;
        n = prev->validate.requirement.headers->nelts;

        ngx_array_push_n(conf->validate.requirement.headers, n);

        requirement = conf->validate.requirement.headers->elts;
        var = prev->validate.requirement.headers->elts;

        for (i = 0; i < len; i++) {
            requirement[n + i] = requirement[i];
        }
        for (i = 0; i < n; i++) {
            requirement[i] = var[i];
        }
    }

    ngx_conf_merge_value(conf->validate.variable.error,
                         prev->validate.variable.error, NGX_HTTP_UNAUTHORIZED);
    if (conf->validate.variable.values == NULL
        || conf->validate.variable.values->nelts == 0)
    {
        conf->validate.variable.values = prev->validate.variable.values;
    }else if (prev->validate.variable.values
              && prev->validate.variable.values->nelts)
    {
        ngx_uint_t i, len, n;
        ngx_http_complex_value_t *value, *var;

        len = conf->validate.variable.values->nelts;
        n = prev->validate.variable.values->nelts;

        ngx_array_push_n(conf->validate.variable.values, n);

        value = conf->validate.variable.values->elts;
        var = prev->validate.variable.values->elts;

        for (i = 0; i < len; i++) {
            value[n + i] = value[i];
        }
        for (i = 0; i < n; i++) {
            value[i] = var[i];
        }
    }

    if (conf->key.requests == NULL || conf->key.requests->nelts == 0) {
        conf->key.requests = prev->key.requests;
    }else if (prev->key.requests && prev->key.requests->nelts) {
        ngx_uint_t i, len, n;
        ngx_http_auth_jwt_key_request_t *key_request, *var;

        len = conf->key.requests->nelts;
        n = prev->key.requests->nelts;

        ngx_array_push_n(conf->key.requests, n);

        key_request = conf->key.requests->elts;
        var = prev->key.requests->elts;

        for (i = 0; i < len; i++) {
            key_request[n + i] = key_request[i];
        }
        for (i = 0; i < n; i++) {
            key_request[i] = var[i];
        }
    }

    ngx_conf_merge_sec_value(conf->leeway, prev->leeway, 0);

    ngx_conf_merge_value(conf->phase, prev->phase, NGX_HTTP_ACCESS_PHASE);

    ngx_conf_merge_value(conf->validate.exp, prev->validate.exp, 1);
    ngx_conf_merge_value(conf->validate.sig, prev->validate.sig, 1);

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_str_value(conf->realm, prev->realm, "");

    if (prev->revocation.subs) {
        if (conf->revocation.subs) {
            json_object_update_missing(conf->revocation.subs,
                                       prev->revocation.subs);
        }else {
            conf->revocation.subs = json_copy(prev->revocation.subs);
        }
    }

    if (prev->revocation.kids) {
        if (conf->revocation.kids) {
            json_object_update_missing(conf->revocation.kids,
                                       prev->revocation.kids);
        }else {
            conf->revocation.kids = json_copy(prev->revocation.kids);
        }
    }

    if (prev->key.vars) {
        if (conf->key.vars) {
            ngx_auth_jwt_jwks_append(conf->key.vars, prev->key.vars);
        }else {
            conf->key.vars = ngx_auth_jwt_jwks_create(cf->pool);
            if (conf->key.vars != NULL) {
                ngx_auth_jwt_jwks_append(conf->key.vars, prev->key.vars);
            }
        }
    }

    if (conf->nested.delimiter == NULL) {
        if (prev->nested.delimiter) {
            conf->nested.delimiter =
                (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                                  (u_char *) prev->nested.
                                                  delimiter,
                                                  strlen(
                                                      prev->nested.delimiter));
        }
    }
    if (conf->nested.quote == NULL) {
        if (prev->nested.quote) {
            conf->nested.quote =
                (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                                  (u_char *) prev->nested.quote,
                                                  strlen(prev->nested.quote));
        }
    }

    return NGX_CONF_OK;
}

static void
ngx_http_auth_jwt_exit_process(ngx_cycle_t *cycle)
{
    ngx_http_auth_jwt_loc_conf_t *conf;
    ngx_http_conf_ctx_t *ctx;
    ngx_uint_t index = ngx_http_auth_jwt_module.ctx_index;

    if (!cycle->conf_ctx[ngx_http_module.index]) {
        return;
    }

    ctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];
    index = ngx_http_auth_jwt_module.ctx_index;

    if (!ctx->loc_conf[index]) {
        return;
    }

    conf = (ngx_http_auth_jwt_loc_conf_t *) ctx->loc_conf[index];

    if (conf && conf->key.vars) {
        ngx_auth_jwt_jwks_free(conf->key.vars);
    }

    if (conf && conf->revocation.subs) {
        json_delete(conf->revocation.subs);
    }

    if (conf && conf->revocation.kids) {
        json_delete(conf->revocation.kids);
    }
}

/*
 * Explicit cleanup for ctx resources. Pool cleanup handlers also
 * release these, but explicit free ensures deterministic ordering.
 * All free functions are idempotent (NULL-check + NULL-set).
 */
static void
ngx_http_auth_jwt_cleanup(void *data)
{
    ngx_http_auth_jwt_ctx_t *ctx = data;

    if (!ctx) {
        return;
    }

    if (ctx->jwt) {
        ngx_auth_jwt_free(ctx->jwt);
    }

    if (ctx->keys) {
        ngx_auth_jwt_jwks_free(ctx->keys);
    }
}

static ngx_int_t
ngx_http_auth_jwt_set_bearer_header(ngx_http_request_t *r,
    ngx_str_t *realm, ngx_int_t error)
{
    size_t len;
    u_char *bearer, *p;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_ERROR;
    }

    len = sizeof("Bearer realm=\"\"") - 1 + realm->len;
    if (error) {
        len += sizeof(", error=\"invalid_token\"") - 1;
    }

    bearer = ngx_pnalloc(r->pool, len);
    if (bearer == NULL) {
        r->headers_out.www_authenticate->hash = 0;
        r->headers_out.www_authenticate = NULL;
        return NGX_ERROR;
    }

    p = ngx_cpymem(bearer, "Bearer realm=\"", sizeof("Bearer realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    if (error) {
        p = ngx_cpymem(p, "\", error=\"invalid_token\"",
                       sizeof("\", error=\"invalid_token\"") - 1);
    }else {
        *p = '"';
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->next = NULL;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = bearer;
    r->headers_out.www_authenticate->value.len = len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_jwt_response(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *cf,
    ngx_http_auth_jwt_ctx_t *ctx,
    ngx_int_t use_error, ngx_int_t code)
{
    if (ctx->use_bearer) {
        if (ngx_http_auth_jwt_set_bearer_header(r, &cf->realm,
                                                use_error) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_jwt: failed to set Bearer header");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    return code;
}

#define ngx_http_auth_jwt_http_ok() ngx_http_auth_jwt_response(r, cf, ctx, 0, \
                                                               NGX_OK)
#define ngx_http_auth_jwt_http_error_without_token() ngx_http_auth_jwt_response( \
            r, cf, ctx, 0, \
            ctx->status != 0 ? ctx->status : NGX_HTTP_UNAUTHORIZED)
#define ngx_http_auth_jwt_http_error() ngx_http_auth_jwt_response(r, cf, ctx, 1, \
                                                                  ctx->status != \
                                                                  0 ? \
                                                                  ctx->status : \
                                                                  NGX_HTTP_UNAUTHORIZED)

static ngx_int_t
ngx_http_auth_jwt_key_request_handler(ngx_http_request_t *r,
    void *data, ngx_int_t rc)
{
    ngx_http_auth_jwt_key_request_t *key_request = data;
    ngx_buf_t *b = NULL;

    if (r->out) {
        b = r->out->buf;
    }

    if (r->headers_out.content_encoding
        && r->headers_out.content_encoding->value.len > 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: %s subrequest returned compressed response"
                      " (Content-Encoding: %V), rejecting",
                      (key_request->jwks ? "JWKS" : "key"),
                      &r->headers_out.content_encoding->value);
        key_request->ctx->reject_request = 1;
        key_request->ctx->status = NGX_HTTP_UNAUTHORIZED;
        key_request->ctx->done++;
        return rc;
    }

    if (b != NULL) {
        size_t len;

        len = b->last - b->pos;

        if (ngx_http_auth_jwt_key_import_string(r->pool,
                                                &key_request->ctx->keys,
                                                (char *) b->pos, len,
                                                key_request->jwks) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_jwt: failed to load %s: \"%V\"",
                          (key_request->jwks ? "jwks" : "key"), &r->uri);
        }
    }

    key_request->ctx->done++;

    return rc;
}

static ngx_int_t
ngx_http_auth_jwt_load_keys(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *cf,
    ngx_http_auth_jwt_ctx_t *ctx)
{
    if (!cf || !ctx) {
        return NGX_DECLINED;
    }
    /* do not run if not validating JWT signature */
    if (!cf->validate.sig) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "auth_jwt: ignore load keys");
        return NGX_DECLINED;
    }

    if (cf->key.vars) {
        ctx->keys = ngx_auth_jwt_jwks_create(r->pool);
        if (ctx->keys != NULL) {
            ngx_auth_jwt_jwks_append(ctx->keys, cf->key.vars);
        }
    }

    if (cf->key.files != NULL) {
        ngx_uint_t i;
        ngx_http_auth_jwt_key_file_t *key_file;

        key_file = cf->key.files->elts;

        for (i = 0; i < cf->key.files->nelts; i++) {
            char *file;
            ngx_http_variable_value_t *v;

            v = ngx_http_get_indexed_variable(r, key_file[i].index);
            if (v == NULL || v->not_found) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_jwt: key_file variable specified was not provided");
                continue;
            }

            file = (char *) ngx_http_auth_jwt_strdup(r->pool, v->data, v->len);
            if (file == NULL) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                              "auth_jwt: failed to allocate key file");
                continue;
            }

            if (ngx_http_auth_jwt_key_import_file(r->pool, &ctx->keys, file,
                                                  key_file[i].jwks) != 0)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_jwt: failed to load %s file: \"%s\"",
                              (key_file[i].jwks ? "jwks" : "key"), file);
            }
        }
    }

    if (cf->key.requests != NULL) {
        ngx_int_t flags = 0;
        ngx_http_post_subrequest_t *ps;
        ngx_http_request_t *sr;
        ngx_uint_t i;
        ngx_http_auth_jwt_key_request_t *key_request;

        flags = NGX_HTTP_SUBREQUEST_WAITED | NGX_HTTP_SUBREQUEST_IN_MEMORY;

        key_request = cf->key.requests->elts;

        for (i = 0; i < cf->key.requests->nelts; i++) {
            ngx_str_t url;

            key_request[i].ctx = ctx;

            ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
            if (ps == NULL) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                              "auth_jwt: failed to allocate subrequest");
                continue;
            }

            ps->handler = ngx_http_auth_jwt_key_request_handler;
            ps->data = &key_request[i];

            if (key_request[i].index > 0) {
                ngx_http_variable_value_t *v;

                v = ngx_http_get_indexed_variable(r, key_request[i].index);
                if (v == NULL || v->not_found) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "auth_jwt: key_request variable specified "
                                  "was not provided");
                    continue;
                }

                url.len = v->len;
                url.data = v->data;
            }else {
                url = key_request[i].url;
            }

            if (ngx_http_subrequest(r, &url, NULL, &sr, ps, flags) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_jwt: failed to subrequest: \"%V\"", &url);
                continue;
            }
            ctx->subrequest++;
        }

        if (ctx->subrequest > 0) {
            return NGX_AGAIN;
        }
    }

    return NGX_OK;
}

static time_t
ngx_http_auth_jwt_get_grant_time(ngx_http_request_t *r, ngx_auth_jwt_t *jwt,
    char *claim, char *delimiter, char *quote)
{
    time_t val;

    val = (time_t) ngx_auth_jwt_claims_get_grant_int(jwt, claim, delimiter,
                                                     quote);
    if (val == -1) {
        char *var;

        var = ngx_auth_jwt_claims_get_grants_json(jwt, claim, delimiter, quote);
        if (var) {
            size_t n;
            u_char *p;

            p = (u_char *) ngx_strchr(var, '.');
            if (p) {
                n = p - (u_char *) var;
            }else {
                n = strlen(var);
            }

            val = ngx_atotm((u_char *) var, n);

            free(var);
        }
    }

    if (val == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: rejected due to %s claim could not be obtained",
                      claim);
    }

    return val;
}

static ngx_int_t
ngx_http_auth_jwt_validate_variable(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *cf,
    ngx_http_auth_jwt_ctx_t *ctx)
{
    ngx_uint_t i;
    ngx_http_complex_value_t *var;

    if (!cf->validate.variable.values) {
        return NGX_OK;
    }

    var = cf->validate.variable.values->elts;

    for (i = 0; i < cf->validate.variable.values->nelts; i++) {
        ngx_str_t value = ngx_null_string;

        if (ngx_http_complex_value(r, &var[i], &value) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_jwt: variable specified was not provided: %V",
                          &(var[i].value));
            return NGX_ERROR;
        }

        if (!value.data || value.len == 0
            || ngx_strncmp("0", value.data, value.len) == 0)
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "auth_jwt: rejected due to %V variable invalid",
                          &(var[i].value));
            ctx->status = cf->validate.variable.error;
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_jwt_validate_requirement(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *cf,
    ngx_http_auth_jwt_ctx_t *ctx,
    ngx_array_t *requirements,
    const char **algorithm,
    const auth_jwt_get_json jwt_get_json)
{
    ngx_uint_t i;
    ngx_http_auth_jwt_requirement_t *requirement;
    const char *requirement_type;

    if (requirements == NULL) {
        return NGX_OK;
    }

    if (jwt_get_json == ngx_auth_jwt_claims_get_grants_json) {
        requirement_type = "claim";
    }else {
        requirement_type = "header";
    }

    requirement = requirements->elts;

    for (i = 0; i < requirements->nelts; i++) {
        char *jwt_value = NULL;
        json_t *jwt_value_json = NULL, *expected_json = NULL;
        ngx_str_t value = ngx_null_string;
        ngx_flag_t json = 0;

        if (ngx_http_complex_value(r, requirement[i].value, &value) != NGX_OK
            || !value.data || value.len == 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_jwt: require variable specified was not provided"
                          ": %V", &(requirement[i].value->value));
            return NGX_ERROR;
        }
        if (requirement[i].value->value.len != 0
            && requirement[i].value->value.data[0] == '$')
        {
            json = 1;
        }else if (value.len > 5 && ngx_strncmp(value.data, "json=", 5) == 0) {
            json = 1;
            value.data += 5;
            value.len -= 5;
        }

        if (value.len > NGX_AUTH_JWT_MAX_EXPECTED_SIZE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_jwt: %s requirement value too large"
                          ": %s (%uz bytes)",
                          requirement_type, requirement[i].name, value.len);
            return NGX_ERROR;
        }

        if (requirement[i].segments != NULL) {
            json_t *root, *resolved;

            root = (jwt_get_json == ngx_auth_jwt_claims_get_grants_json)
                   ? ctx->jwt->payload : ctx->jwt->headers;
            resolved = ngx_auth_jwt_field_resolve(root,
                                                  requirement[i].segments,
                                                  requirement[i].nsegments);
            if (resolved == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_jwt: rejected due to missing %s: %s",
                              requirement_type, requirement[i].name);
                return NGX_ERROR;
            }

            jwt_value_json = json_deep_copy(resolved);
            if (jwt_value_json == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_jwt: failed to copy jwt %s: %s",
                              requirement_type, requirement[i].name);
                return NGX_ERROR;
            }
            jwt_value = json_dumps(jwt_value_json,
                                   JSON_SORT_KEYS | JSON_COMPACT
                                   | JSON_ENCODE_ANY);
            if (jwt_value == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_jwt: failed to dump jwt %s: %s",
                              requirement_type, requirement[i].name);
                json_delete(jwt_value_json);
                return NGX_ERROR;
            }
        } else {
            jwt_value = jwt_get_json(ctx->jwt, requirement[i].name,
                                     cf->nested.delimiter, cf->nested.quote);
            if (jwt_value == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_jwt: rejected due to missing %s: %s",
                              requirement_type, requirement[i].name);
                return NGX_ERROR;
            }
            jwt_value_json = json_loads(jwt_value, JSON_DECODE_ANY, NULL);
            if (jwt_value_json == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_jwt: failed to json load jwt %s: %s",
                              requirement_type, requirement[i].name);
                free(jwt_value);
                return NGX_ERROR;
            }
        }

        if (!json) {
            expected_json = json_stringn((char *) value.data, value.len);
        }else {
            expected_json = json_loadb((char *) value.data, value.len,
                                       JSON_DECODE_ANY, NULL);
        }
        if (expected_json == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_jwt: failed to json load %s requirement: %s",
                          requirement_type, requirement[i].name);
            free(jwt_value);
            json_delete(jwt_value_json);
            return NGX_ERROR;
        }

        if (jwt_get_json == ngx_auth_jwt_claims_get_grants_json) {
            // NOTE: only claim requirement
            if (ngx_strcmp("nbf", requirement[i].name) == 0) {
                if (json_is_number(expected_json)) {
                    time_t val = ngx_atotm(value.data, value.len);
                    json_delete(expected_json);
                    expected_json = json_integer(val + cf->leeway);
                    if (expected_json == NULL) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "auth_jwt: failed to json reload"
                                      " jwt %s requirement: %s",
                                      requirement_type, requirement[i].name);
                        free(jwt_value);
                        json_delete(jwt_value_json);
                        return NGX_ERROR;
                    }
                }
            }else if (ngx_strcmp("exp", requirement[i].name) == 0) {
                if (json_is_number(expected_json)) {
                    time_t val = ngx_atotm(value.data, value.len);
                    json_delete(expected_json);
                    expected_json = json_integer(val - cf->leeway);
                    if (expected_json == NULL) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "auth_jwt: failed to json reload"
                                      " jwt %s requirement: %s",
                                      requirement_type, requirement[i].name);
                        free(jwt_value);
                        json_delete(jwt_value_json);
                        return NGX_ERROR;
                    }

                    // NOTE: do not verify exp if exp requirements are met
                    cf->validate.exp = 0;
                }
            }
        }

        {
            void *regex = NULL;
#if (NGX_PCRE)
            regex = requirement[i].regex;
#endif
            if (ngx_auth_jwt_operator_validate(
                    requirement[i].operator, jwt_value_json,
                    expected_json, regex,
                    r->pool, r->connection->log) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "auth_jwt: rejected due to %s %s requirement"
                              ": \"%s\" is not \"%s\" \"%V\"",
                              requirement[i].name, requirement_type, jwt_value,
                              requirement[i].operator, &value);
                free(jwt_value);
                json_delete(jwt_value_json);
                json_delete(expected_json);
                return NGX_ERROR;
            }
        }

        free(jwt_value);
        json_delete(jwt_value_json);
        json_delete(expected_json);

        if (jwt_get_json == ngx_auth_jwt_claims_get_headers_json) {
            // NOTE: only header requirement
            if (ngx_strcmp("alg", requirement[i].name) == 0) {
                // NOTE: allow NONE algorithm when passing alg requirements
                if (*algorithm != NULL && ngx_strcmp(*algorithm, "none") == 0) {
                    cf->validate.sig = 0;
                }
                // NOTE: do not verify algorithm if alg requirements are met
                *algorithm = NULL;
            }
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_jwt_validate(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *cf,
    ngx_http_auth_jwt_ctx_t *ctx)
{
    const char *algorithm;
    const char *kid = NULL;

    if (!cf || !ctx) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "auth_jwt: rejected due to missing required arguments");
        return NGX_ERROR;
    }

    algorithm = json_string_value(json_object_get(ctx->jwt->headers, "alg"));

    if (cf->revocation.subs != NULL) {
        json_t *value = NULL;
        const char *revocation_sub;
        const char *jwt_sub =
            json_string_value(json_object_get(ctx->jwt->payload, "sub"));

        if (jwt_sub == NULL) {
            return NGX_ERROR;
        }

        json_object_foreach(cf->revocation.subs, revocation_sub, value) {
            if (ngx_strcmp(jwt_sub, revocation_sub) == 0) {
                char *msg = json_dumps(value, JSON_COMPACT);
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "auth_jwt: rejected due to sub in revocation list"
                              ": sub=\"%s\" %s", jwt_sub, msg ? msg : "");
                if (msg) {
                    free(msg);
                }
                return NGX_ERROR;
            }
        }
    }

    kid = json_string_value(json_object_get(ctx->jwt->headers, "kid"));

    if (cf->revocation.kids != NULL) {
        json_t *value = NULL;
        const char *revocation_kid;

        // note that revocation_kids turn on kid to required header
        if (kid == NULL || ngx_strcmp(kid, "") == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "auth_jwt: rejected due to kid cannot be empty"
                          " when revocation_kids set", kid);
            return NGX_ERROR;
        }

        json_object_foreach(cf->revocation.kids, revocation_kid, value) {
            if (ngx_strcmp(kid, revocation_kid) == 0) {
                char *msg = json_dumps(value, JSON_COMPACT);
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "auth_jwt: rejected due to kid in revocation list"
                              ": kid=\"%s\" %s", revocation_kid,
                              msg ? msg : "");
                if (msg) {
                    free(msg);
                }
                return NGX_ERROR;
            }
        }
    }

    /* validate requirement claim */
    if (ngx_http_auth_jwt_validate_requirement(r, cf, ctx,
                                               cf->validate.requirement.claims,
                                               &algorithm,
                                               ngx_auth_jwt_claims_get_grants_json)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* validate exp claim */
    if (cf->validate.exp) {
        time_t exp, now;

        exp = ngx_http_auth_jwt_get_grant_time(r, ctx->jwt, "exp", NULL, NULL);
        if (exp == -1) {
            return NGX_ERROR;
        }

        now = ngx_time();

        if (now >= exp + cf->leeway) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "auth_jwt: rejected due to token expired"
                          ": exp=%l: greater than expected=%l actual=%l",
                          exp, now, exp + cf->leeway);
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "auth_jwt: token: \"%s\"", (char *) ctx->token);
            return NGX_ERROR;
        }
    }

    /* validate requirement header */
    if (ngx_http_auth_jwt_validate_requirement(r, cf, ctx,
                                               cf->validate.requirement.headers,
                                               &algorithm,
                                               ngx_auth_jwt_claims_get_headers_json)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* rejected none algorithm */
    if (algorithm != NULL && ngx_strcmp(algorithm, "none") == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "auth_jwt: rejected due to none algorithm");
        return NGX_ERROR;
    }

    /* validate signature */
    if (!cf->validate.sig) {
        ctx->verified = 1;
        return ngx_http_auth_jwt_validate_variable(r, cf, ctx);
    }

    if (!ctx->keys || ctx->keys->nkeys == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "auth_jwt: rejected due to without signature key");
        return NGX_ERROR;
    }

    /* re-read algorithm if it was cleared by alg requirement validation */
    if (algorithm == NULL) {
        algorithm = json_string_value(json_object_get(ctx->jwt->headers,
                                                      "alg"));
    }

    if (algorithm == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "auth_jwt: rejected due to missing algorithm");
        return NGX_ERROR;
    }

    {
        int jws_rc;
        int kid_tried = 0;

        jws_rc = ngx_auth_jwt_jws_verify((const char *) ctx->token,
                                         ctx->payload_len,
                                         ctx->keys, algorithm, kid,
                                         &kid_tried);

        if (kid_tried && kid) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "auth_jwt: rejected due to signature validate failure"
                          ": kid=\"%s\"", kid);
        }

        if (jws_rc == 0) {
            ctx->verified = 1;
            return ngx_http_auth_jwt_validate_variable(r, cf, ctx);
        }
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "auth_jwt: rejected due to missing signature key "
                  "or signature validate failure");

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "auth_jwt: token: \"%s\"", (char *) ctx->token);

    return NGX_ERROR;
}

static ngx_int_t
ngx_http_auth_jwt_preaccess_handler(ngx_http_request_t *r)
{
    return ngx_http_auth_jwt_handler(r, NGX_HTTP_PREACCESS_PHASE);
}

static ngx_int_t
ngx_http_auth_jwt_access_handler(ngx_http_request_t *r)
{
    return ngx_http_auth_jwt_handler(r, NGX_HTTP_ACCESS_PHASE);
}

static ngx_int_t
ngx_http_auth_jwt_handler(ngx_http_request_t *r, ngx_int_t phase)
{
    ngx_http_auth_jwt_loc_conf_t *cf;
    ngx_http_variable_value_t *variable;
    ngx_http_auth_jwt_ctx_t *ctx;
    ngx_pool_cleanup_t *cleanup;
    ngx_str_t var = ngx_string("");

    cf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

    if (cf->enabled != 1) {
        return NGX_DECLINED;
    }
    if (cf->phase != phase) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "auth_jwt: ignore phase: %s",
                      phase ==
                      NGX_HTTP_PREACCESS_PHASE ? "PREACCESS" : "ACCESS");
        return NGX_DECLINED;
    }

    ctx = ngx_http_auth_jwt_get_module_ctx(r);
    if (ctx != NULL) {
        if (ctx->done < ctx->subrequest) {
            return NGX_AGAIN;
        }

        if (ctx->reject_request) {
            return ngx_http_auth_jwt_http_error();
        }

        if (ngx_http_auth_jwt_validate(r, cf, ctx) == NGX_ERROR) {
            return ngx_http_auth_jwt_http_error();
        }

        return ngx_http_auth_jwt_http_ok();
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_jwt_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "auth_jwt: failed to allocate context");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cleanup = ngx_pool_cleanup_add(r->pool, 0);
    if (cleanup == NULL) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "auth_jwt: failed to allocate cleanup");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cleanup->handler = ngx_http_auth_jwt_cleanup;
    cleanup->data = ctx;

    ngx_http_set_ctx(r, ctx, ngx_http_auth_jwt_module);

    /* read token */
    if (cf->token_variable != NGX_CONF_UNSET) {
        /* token from variable */
        variable = ngx_http_get_indexed_variable(r, cf->token_variable);
        if (variable->not_found) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_jwt: token variable specified was not provided");
            return ngx_http_auth_jwt_http_error();
        }
        var.data = variable->data;
        var.len = variable->len;
    }else if (r->headers_in.authorization
              && ngx_strncmp(r->headers_in.authorization->value.data,
                             "Bearer ", sizeof("Bearer ") - 1) == 0)
    {
        /* token from authorization header */
        var.data = r->headers_in.authorization->value.data + 7;
        var.len = r->headers_in.authorization->value.len - 7;

        ctx->use_bearer = 1;
    }

    if (var.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "auth_jwt: token was not provided");
        return ngx_http_auth_jwt_http_error_without_token();
    }

    ctx->token = ngx_http_auth_jwt_strdup(r->pool, var.data, var.len);
    if (ctx->token == NULL) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "auth_jwt: failed to allocate token");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* parse jwt token */
    if (ngx_auth_jwt_decode(r->pool, &ctx->jwt, (char *) ctx->token,
                            &ctx->payload_len) != 0
        || ctx->jwt == NULL)
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "auth_jwt: failed to parse jwt token");
        return ngx_http_auth_jwt_http_error();
    }

    /* load keys */
    if (ngx_http_auth_jwt_load_keys(r, cf, ctx) == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    /* validate */
    if (ngx_http_auth_jwt_validate(r, cf, ctx) == NGX_ERROR) {
        return ngx_http_auth_jwt_http_error();
    }

    return ngx_http_auth_jwt_http_ok();
}
