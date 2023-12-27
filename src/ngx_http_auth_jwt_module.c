
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "jwt/jwt.h"
#include "jwt/jwt-private.h"
#include "jwk.h"
#include "jwt_requirement_operators.h"

#define NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX "jwt_claim_"
#define NGX_HTTP_AUTH_JWT_HEADER_VAR_PREFIX "jwt_header_"

static ngx_int_t ngx_http_auth_jwt_variable_claim(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_jwt_variable_header(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_jwt_variable_claims(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_jwt_variable_nowtime(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static char *ngx_http_auth_jwt_conf_set_token_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_claim(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_key_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_key_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_auth_jwt_conf_set_revocation_subs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_revocation_kids(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_auth_jwt_conf_set_require_claim(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_require_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_auth_jwt_pre_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_jwt_post_conf(ngx_conf_t *cf);
static void *ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static void ngx_http_auth_jwt_exit_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_auth_jwt_preaccess_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_jwt_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r, ngx_int_t phase);

typedef struct {
  ngx_int_t token_variable;
  ngx_array_t *set_vars;
  time_t leeway;
  ngx_int_t phase;
  ngx_flag_t enabled;
  ngx_str_t realm;
  json_t *revocation_subs;
  json_t *revocation_kids;
  struct {
    ngx_array_t *files;
    ngx_array_t *requests;
    json_t *vars;
  } key;
  struct {
    ngx_flag_t exp;
    ngx_flag_t sig;
    ngx_array_t *claim_requirements;
    ngx_array_t *header_requirements;
  } validate;
} ngx_http_auth_jwt_loc_conf_t;

typedef struct {
  ngx_int_t index;
  ngx_flag_t jwks;
} ngx_http_auth_jwt_key_file_t;

typedef struct {
  ngx_flag_t use_bearer;
  ngx_uint_t done;
  ngx_uint_t subrequest;
  ngx_flag_t verified;
  u_char *token;
  unsigned int payload_len;
  jwt_t *jwt;
  json_t *keys;
  json_t *revocation_subs;
  json_t *revocation_kids;
  ngx_array_t *claim_requirements;
  ngx_array_t *header_requirements;
} ngx_http_auth_jwt_ctx_t;

typedef struct  {
  ngx_flag_t json;
  ngx_str_t value;
  char *name;
  char *operator;
} ngx_http_auth_jwt_ctx_require_t;

typedef struct {
  ngx_http_complex_value_t *value;
  char *name;
  char *operator;
} ngx_http_auth_jwt_require_t;


typedef struct {
  ngx_int_t index;
  ngx_str_t url;
  ngx_flag_t jwks;
  ngx_http_auth_jwt_ctx_t *ctx;
} ngx_http_auth_jwt_key_request_t;

typedef const char *(*auth_jwt_get)(jwt_t *jwt, const char *key);
typedef char *(*auth_jwt_get_json)(jwt_t *jwt, const char *key);

static ngx_conf_enum_t ngx_http_auth_jwt_phases[] = {
  { ngx_string("PREACCESS"), NGX_HTTP_PREACCESS_PHASE },
  { ngx_string("ACCESS"), NGX_HTTP_ACCESS_PHASE },
  { ngx_null_string, 0 }
};

static char *ngx_http_auth_jwt_require_operators[] = {
  NGX_HTTP_AUTH_JWT_REQUIRE_EQUAL_OPERATOR,
  NGX_HTTP_AUTH_JWT_REQUIRE_NOT_EQUAL_OPERATOR,
  NGX_HTTP_AUTH_JWT_REQUIRE_GREATER_THAN_OPERATOR,
  NGX_HTTP_AUTH_JWT_REQUIRE_GREATER_OR_EQUAL_OPERATOR,
  NGX_HTTP_AUTH_JWT_REQUIRE_LESS_THAN_OPERATOR,
  NGX_HTTP_AUTH_JWT_REQUIRE_LESS_OR_EQUAL_OPERATOR,
  NGX_HTTP_AUTH_JWT_REQUIRE_INTERSECTION_OPERATOR,
  NGX_HTTP_AUTH_JWT_REQUIRE_NOT_INTERSECTION_OPERATOR,
  NGX_HTTP_AUTH_JWT_REQUIRE_IN_OPERATOR,
  NGX_HTTP_AUTH_JWT_REQUIRE_NOT_IN_OPERATOR,
  NULL,
};

static ngx_http_variable_t ngx_http_auth_jwt_vars[] = {
  { ngx_string(NGX_HTTP_AUTH_JWT_HEADER_VAR_PREFIX),
    NULL,
    ngx_http_auth_jwt_variable_header,
    0,
    NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_PREFIX,
    0 },
  { ngx_string(NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX),
    NULL,
    ngx_http_auth_jwt_variable_claim,
    0,
    NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_PREFIX,
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
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
    ngx_http_auth_jwt_conf_set_token_variable,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("auth_jwt_revocation_list_sub"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_auth_jwt_conf_set_revocation_subs,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("auth_jwt_revocation_list_kid"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_auth_jwt_conf_set_revocation_kids,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("auth_jwt_require_claim"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
    ngx_http_auth_jwt_conf_set_require_claim,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("auth_jwt_require_header"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
    ngx_http_auth_jwt_conf_set_require_header,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("auth_jwt_claim_set"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
    ngx_http_auth_jwt_conf_set_claim,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("auth_jwt_header_set"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
    ngx_http_auth_jwt_conf_set_header,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("auth_jwt_key_file"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
    ngx_http_auth_jwt_conf_set_key_file,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("auth_jwt_key_request"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
    ngx_http_auth_jwt_conf_set_key_request,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("auth_jwt_leeway"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_sec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, leeway),
    NULL },
  { ngx_string("auth_jwt_phase"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_enum_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, phase),
    &ngx_http_auth_jwt_phases },
  { ngx_string("auth_jwt_validate_exp"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, validate.exp),
    NULL },
  { ngx_string("auth_jwt_validate_sig"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, validate.sig),
    NULL },
  ngx_null_command
};

static ngx_http_module_t ngx_http_auth_jwt_module_ctx = {
  ngx_http_auth_jwt_pre_conf,        /* preconfiguration */
  ngx_http_auth_jwt_post_conf,       /* postconfiguration */
  NULL,                              /* create main configuration */
  NULL,                              /* init main configuration */
  NULL,                              /* create server configuration */
  NULL,                              /* merge server configuration */
  ngx_http_auth_jwt_create_loc_conf, /* create location configuration */
  ngx_http_auth_jwt_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_auth_jwt_module = {
  NGX_MODULE_V1,
  &ngx_http_auth_jwt_module_ctx,  /* module context */
  ngx_http_auth_jwt_commands,     /* module directives */
  NGX_HTTP_MODULE,                /* module type */
  NULL,                           /* init master */
  NULL,                           /* init module */
  NULL,                           /* init process */
  NULL,                           /* init thread */
  NULL,                           /* exit thread */
  ngx_http_auth_jwt_exit_process, /* exit process */
  NULL,                           /* exit master */
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
ngx_http_auth_jwt_key_import(json_t **object,
                             const jwks_t *jwks, const json_t *keyval)
{
  if (!jwks && !json_is_object(keyval)) {
    return 1;
  }

  if (*object == NULL) {
    *object = json_object();
  }

  if (jwks) {
    const char *id, *key = NULL;
    size_t key_len;

    jwks_foreach_by(jwks, id) {
      key = jwks_key_by(jwks, id, &key_len);
      if (key == NULL || key_len == 0) {
        continue;
      }
      json_object_set_new(*object, id, json_string_nocheck(key));
    }
  }

  if (keyval) {
    const char *key = NULL;
    json_t *value = NULL;

    json_object_foreach((json_t *) keyval, key, value) {
      if (!key || !json_is_string(value)) {
        continue;
      }

      json_object_set_new(*object, key, json_copy(value));
    }
  }

  return 0;
}

static int
ngx_http_auth_jwt_key_import_file(json_t **object, const char *path,
                                  const int is_jwks)
{
  int rc;
  json_t *keyval = NULL;
  jwks_t *jwks = NULL;

  if (path == NULL) {
    return 1;
  }

  if (is_jwks) {
    jwks = jwks_import_file(path);
    if (jwks == NULL) {
      return 1;
    }
  }
  else {
    keyval = json_load_file(path, 0, NULL);
    if (keyval == NULL) {
      return 1;
    }
  }

  rc = ngx_http_auth_jwt_key_import(object, jwks, keyval);

  if (jwks) {
    jwks_free(jwks);
  }
  if (keyval) {
    json_delete(keyval);
  }

  return rc;
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
ngx_http_auth_jwt_key_import_string(json_t **object,
                                    const char *input, const size_t len,
                                    const int is_jwks)
{
  int rc;
  json_t *keyval = NULL;
  jwks_t *jwks = NULL;

  if (input == NULL) {
    return 1;
  }

  if (is_jwks) {
    jwks = jwks_import_string(input, len);
    if (jwks == NULL) {
      return 1;
    }
  }
  else {
    if (len == 0) {
      keyval = json_loads(input, 0, NULL);
    }
    else {
      keyval = json_loadb(input, len, 0, NULL);
    }
    if (keyval == NULL) {
      return 1;
    }
  }

  rc = ngx_http_auth_jwt_key_import(object, jwks, keyval);

  if (jwks) {
    jwks_free(jwks);
  }
  if (keyval) {
    json_delete(keyval);
  }

  return rc;
}

static const char *
ngx_http_auth_jwt_key_get(const json_t *object, const char *kid)
{
  json_t *var = NULL;

  if (!json_is_object(object) || kid == NULL) {
    return NULL;
  }

  var = json_object_get(object, kid);
  if (!json_is_string(var)) {
    return NULL;
  }

  return json_string_value(var);
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
  auth_jwt_get jwt_get;
  auth_jwt_get_json jwt_get_json;

  ctx = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);
  if (!ctx || !ctx->jwt) {
    v->not_found = 1;
    return NGX_OK;
  }

  if (use == NGX_HTTP_AUTH_JWT_VARIABLE_HEADER) {
    prefix = NGX_HTTP_AUTH_JWT_HEADER_VAR_PREFIX;
    jwt_get = jwt_get_header;
    jwt_get_json = jwt_get_headers_json;
  }
  else {
    if (!ctx->verified) {
      v->not_found = 1;
      return NGX_OK;
    }

    if (use == NGX_HTTP_AUTH_JWT_VARIABLE_CLAIM) {
      prefix = NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX;
    }
    jwt_get = jwt_get_grant;
    jwt_get_json = jwt_get_grants_json;
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

  value = (*jwt_get)(ctx->jwt, (char *) key);
  if (value == NULL) {
    size_t i, t;

    str = (*jwt_get_json)(ctx->jwt, (char *) key);
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
        || ngx_strncmp(value[2].data, starts_with, starts_with_len) != 0) {
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
ngx_http_auth_jwt_conf_set_valiable(ngx_conf_t *cf,
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
    ngx_http_auth_jwt_conf_set_valiable(cf, cmd, conf,
                                        NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX,
                                        ngx_http_auth_jwt_variable_claim);
}

static char *
ngx_http_auth_jwt_conf_set_header(ngx_conf_t *cf,
                                  ngx_command_t *cmd, void *conf)
{
  return
    ngx_http_auth_jwt_conf_set_valiable(cf, cmd, conf,
                                        NGX_HTTP_AUTH_JWT_HEADER_VAR_PREFIX,
                                        ngx_http_auth_jwt_variable_header);
}

static char *
ngx_http_auth_jwt_conf_set_revocation_subs(ngx_conf_t *cf,
                                           ngx_command_t *cmd, void *conf)
{
  char *file;
  ngx_http_auth_jwt_loc_conf_t *lcf;
  ngx_str_t *value;

  lcf = conf;
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

  if (ngx_http_auth_jwt_fill_list_object_by_file(&lcf->revocation_subs, file)
      != 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" directive failed to load file: \"%s\"",
                       &cmd->name ,file);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *
ngx_http_auth_jwt_conf_set_revocation_kids(ngx_conf_t *cf,
                                           ngx_command_t *cmd, void *conf)
{
  char *file;
  ngx_http_auth_jwt_loc_conf_t *lcf;
  ngx_str_t *value;

  lcf = conf;
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

  if (ngx_http_auth_jwt_fill_list_object_by_file(&lcf->revocation_kids, file)
      != 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" directive failed to load file: \"%s\"",
                       &cmd->name ,file);
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
    }
    else if (ngx_strncmp("jwks", value[2].data, value[2].len) != 0) {
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

  if (ngx_http_auth_jwt_key_import_file(&lcf->key.vars, file, jwks) != 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" directive failed to load %s file: \"%s\"",
                       &cmd->name, (jwks ? "jwks" : "key"), file);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *
ngx_http_auth_jwt_conf_set_require(ngx_conf_t *cf, ngx_command_t *cmd,
                                   ngx_array_t ** requirements)
{
  ngx_str_t *value;
  ngx_http_auth_jwt_require_t *require;

  value = cf->args->elts;

  if (cf->args->nelts != 4) {
    return "invalid params count in require";
  }

  if (*requirements == NULL) {
    *requirements = ngx_array_create(cf->pool, 1, sizeof(*require));
    if (requirements == NULL) {
      return "failed to allocate memory for require";
    }
  }

  require = ngx_array_push(*requirements);
  if (require == NULL) {
    return "failed to allocate item for require";
  }

  if (value[1].len != 0) {
    require->name = (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                                      value[1].data,
                                                      value[1].len);
  }
  else {
    return "first argument should not be empty";
  }
  if (value[2].len != 0 /* && value[2].data not in ... */) {
    ngx_flag_t invalid_operator = 1;
    for (int i = 0; ngx_http_auth_jwt_require_operators[i] != NULL; i++) {
      if (strcmp(ngx_http_auth_jwt_require_operators[i], (char *)value[2].data)
          == 0){
        invalid_operator = 0;
        break;
      }
    }
    if (invalid_operator == 1) {
      return "second argument should be one of available require operators";
    }
    require->operator = (char *) ngx_http_auth_jwt_strdup(cf->pool,
                                                          value[2].data,
                                                          value[2].len);
  }
  else {
    return "second argument should not be empty";
  }

  if (value[3].len != 0) {
    ngx_http_compile_complex_value_t ccv;

    require->value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (require->value == NULL) {
      return "failed to allocate value variables";
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[3];
    ccv.complex_value = require->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
      return "no value variables";
    }
  }
  else {
    return "third argument should be variable";
  }

  return NGX_CONF_OK;
}

static char *
ngx_http_auth_jwt_conf_set_require_claim(ngx_conf_t *cf,
                                         ngx_command_t *cmd, void *conf)
{
  ngx_http_auth_jwt_loc_conf_t *lcf;

  lcf = conf;
  char *x
    = ngx_http_auth_jwt_conf_set_require(cf, cmd,
                                         &(lcf->validate.claim_requirements));

  return x;
}

static char *
ngx_http_auth_jwt_conf_set_require_header(ngx_conf_t *cf,
                                          ngx_command_t *cmd, void *conf)
{
  ngx_http_auth_jwt_loc_conf_t *lcf;

  lcf = conf;
  return ngx_http_auth_jwt_conf_set_require(cf, cmd,
                                            &lcf->validate.header_requirements);
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
    }
    else if (ngx_strncmp("jwks", value[2].data, value[2].len) != 0) {
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
  }
  else {
    key_request->index = -1;
    key_request->url = value[1];
  }

  key_request->jwks = jwks;

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
  conf->revocation_subs = NULL;
  conf->revocation_kids = NULL;
  conf->validate.claim_requirements = NULL;
  conf->validate.header_requirements = NULL;
  conf->validate.exp = NGX_CONF_UNSET;
  conf->validate.sig = NGX_CONF_UNSET;

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
  }
  else if (prev->key.files && prev->key.files->nelts) {
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

  if (conf->validate.claim_requirements == NULL
      || conf->validate.claim_requirements->nelts == 0) {
    conf->validate.claim_requirements = prev->validate.claim_requirements;
  }
  else if (prev->validate.claim_requirements
           && prev->validate.claim_requirements->nelts) {
    ngx_uint_t i, len, n;
    ngx_http_auth_jwt_require_t *require, *var;

    len = conf->validate.claim_requirements->nelts;
    n = prev->validate.claim_requirements->nelts;

    ngx_array_push_n(conf->validate.claim_requirements, n);

    require = conf->validate.claim_requirements->elts;
    var = prev->validate.claim_requirements->elts;

    for (i = 0; i < len; i++) {
      require[n + i] = require[i];
    }
    for (i = 0; i < n; i++) {
      require[i] = var[i];
    }
  }

  if (conf->validate.header_requirements == NULL
      || conf->validate.header_requirements->nelts == 0) {
    conf->validate.header_requirements = prev->validate.header_requirements;
  }
  else if (prev->validate.header_requirements
           && prev->validate.header_requirements->nelts) {
    ngx_uint_t i, len, n;
    ngx_http_auth_jwt_require_t *require, *var;

    len = conf->validate.header_requirements->nelts;
    n = prev->validate.header_requirements->nelts;

    ngx_array_push_n(conf->validate.header_requirements, n);

    require = conf->validate.header_requirements->elts;
    var = prev->validate.header_requirements->elts;

    for (i = 0; i < len; i++) {
      require[n + i] = require[i];
    }
    for (i = 0; i < n; i++) {
      require[i] = var[i];
    }
  }

  if (conf->key.requests == NULL || conf->key.requests->nelts == 0) {
    conf->key.requests = prev->key.requests;
  }
  else if (prev->key.requests && prev->key.requests->nelts) {
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

  if (prev->revocation_subs) {
    if (conf->revocation_subs) {
      json_object_update_missing(conf->revocation_subs, prev->revocation_subs);
    }
    else {
      conf->revocation_subs = json_copy(prev->revocation_subs);
    }
  }

  if (prev->revocation_kids) {
    if (conf->revocation_kids) {
      json_object_update_missing(conf->revocation_kids, prev->revocation_kids);
    }
    else {
      conf->revocation_kids = json_copy(prev->revocation_kids);
    }
  }

  if (prev->key.vars) {
    if (conf->key.vars) {
      json_object_update_missing(conf->key.vars, prev->key.vars);
    }
    else {
      conf->key.vars = json_copy(prev->key.vars);
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
    json_delete(conf->key.vars);
  }

  if (conf && conf->revocation_subs) {
    json_delete(conf->revocation_subs);
  }

  if (conf && conf->revocation_kids) {
    json_delete(conf->revocation_kids);
  }
}

static void
ngx_http_auth_jwt_cleanup(void *data)
{
  ngx_http_auth_jwt_ctx_t *ctx = data;

  if (!ctx) {
    return;
  }

  if (ctx->jwt) {
    jwt_free(ctx->jwt);
  }

  if (ctx->keys) {
    json_delete(ctx->keys);
  }

  if (ctx->revocation_subs) {
    json_delete(ctx->revocation_subs);
  }

  if (ctx->revocation_kids) {
    json_delete(ctx->revocation_kids);
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
  }
  else {
    *p = '"';
  }

  r->headers_out.www_authenticate->hash = 1;
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
                                            use_error) != NGX_OK) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "auth_jwt: failed to set Bearer header");
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
  }
  return code;
}

#define ngx_http_auth_jwt_http_ok() ngx_http_auth_jwt_response(r, cf, ctx, 0, NGX_OK)
#define ngx_http_auth_jwt_http_unauthorized_error() ngx_http_auth_jwt_response(r, cf, ctx, 0, NGX_HTTP_UNAUTHORIZED)
#define ngx_http_auth_jwt_http_unauthorized() ngx_http_auth_jwt_response(r, cf, ctx, 1, NGX_HTTP_UNAUTHORIZED)

static ngx_int_t
ngx_http_auth_jwt_key_request_handler(ngx_http_request_t *r,
                                      void *data, ngx_int_t rc)
{
  ngx_http_auth_jwt_key_request_t *key_request = data;
  ngx_buf_t *b = NULL;

  if (r->out) {
    b = r->out->buf;
  }

  if (b != NULL) {
    size_t len;

    len = b->last - b->pos;

    if (ngx_http_auth_jwt_key_import_string(&key_request->ctx->keys,
                                            (char *) b->pos, len,
                                            key_request->jwks) != 0) {
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
    ctx->keys = json_copy(cf->key.vars);
  }

  if (cf->key.files != NULL) {
    ngx_uint_t i;
    ngx_http_auth_jwt_key_file_t *key_file;

    key_file = cf->key.files->elts;

    for (i = 0; i < cf->key.files->nelts; i++) {
      char *file;
      ngx_http_variable_value_t  *v;

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

      if (ngx_http_auth_jwt_key_import_file(&ctx->keys, file,
                                            key_file[i].jwks) != 0) {
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
        ngx_http_variable_value_t  *v;

        v = ngx_http_get_indexed_variable(r, key_request[i].index);
        if (v == NULL || v->not_found) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "auth_jwt: key_request variable specified "
                        "was not provided");
          continue;
        }

        url.len = v->len;
        url.data = v->data;
      }
      else {
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

static ngx_int_t
ngx_http_auth_jwt_load_requirements(ngx_http_request_t *r,
                                    ngx_array_t **requirements,
                                    ngx_array_t **ctx_requirements)
{
  if (*requirements != NULL) {
    ngx_uint_t i;
    ngx_http_auth_jwt_require_t *require;
    ngx_http_auth_jwt_ctx_require_t *ctx_require;

    require = (*requirements)->elts;

    for (i = 0; i < (*requirements)->nelts; i++) {
      ngx_str_t value = ngx_null_string;

      if (ngx_http_complex_value(r, require[i].value, &value) != NGX_OK
          || !value.data || value.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: require variable specified was not provided");
        return NGX_ERROR;
      }

      if (*ctx_requirements == NULL) {
        *ctx_requirements = ngx_array_create(r->pool, 1, sizeof(*ctx_require));
        if (*ctx_requirements == NULL) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "auth_jwt: failed to allocate requirements");
          return NGX_ERROR;
        }
      }
      ctx_require = ngx_array_push(*ctx_requirements);
      if (ctx_require == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: failed to push context require");
        return NGX_ERROR;
      }

      if (require[i].value->value.len != 0
          && require[i].value->value.data[0] == '$') {
        ctx_require->json = 1;
        ctx_require->value.data = value.data;
        ctx_require->value.len = value.len;
      }
      else if (value.len > 5 && ngx_strncmp(value.data, "json=", 5) == 0) {
        ctx_require->json = 1;
        ctx_require->value.data = value.data + 5;
        ctx_require->value.len = value.len - 5;
      }
      else {
        ctx_require->json = 0;
        ctx_require->value.data = value.data;
        ctx_require->value.len = value.len;
      }
      ctx_require->operator = require[i].operator;
      ctx_require->name = require[i].name;
    }
  }

  return NGX_OK;
}

static time_t
ngx_http_auth_jwt_get_grant_time(ngx_http_request_t *r, jwt_t *jwt, char *claim)
{
  time_t val;

  val = (time_t) jwt_get_grant_int(jwt, claim);
  if (val == -1) {
    char *var;

    var = jwt_get_grants_json(jwt, claim);
    if (var) {
      size_t n;
      u_char *p;

      p = (u_char *) ngx_strchr(var, '.');
      if (p) {
        n = p - (u_char *) var;
      }
      else {
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
ngx_http_auth_jwt_validate(ngx_http_request_t *r,
                           ngx_http_auth_jwt_loc_conf_t *cf,
                           ngx_http_auth_jwt_ctx_t *ctx)
{
  jwt_alg_t algorithm;
  const char *kid = NULL, *key = NULL;
  json_t *var = NULL;

  if (!cf || !ctx) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "auth_jwt: rejected due to missing required arguments");
    return NGX_ERROR;
  }

  algorithm = jwt_get_alg(ctx->jwt);

  if (ctx->revocation_subs != NULL) {
    json_t *value = NULL;
    const char * revocation_sub;
    const char *jwt_sub = jwt_get_grant(ctx->jwt, "sub");
    if (jwt_sub == NULL){
      return NGX_ERROR;
    }

    json_object_foreach(ctx->revocation_subs, revocation_sub, value) {
      if (strcmp(jwt_sub, revocation_sub) == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "auth_jwt: rejected due to sub in revocation list"
                      ": sub=\"%s\"", jwt_sub);
        // todo: it seems to be good,
        // if we add DEBUG log with short dump of value,
        // where we could find a reason of locking.
        return NGX_ERROR;
      }
    }
  }

  kid = jwt_get_header(ctx->jwt, "kid");

  if (ctx->revocation_kids != NULL) {
    json_t *value = NULL;
    const char * revocation_kid;

    // note that revocation_kids turn on kid to required header
    if (kid == NULL || strcmp(kid, "") == 0) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "auth_jwt: rejected due to kid cannot be empty"
                    " when revocation_kids set", kid);
      return NGX_ERROR;
    }

    json_object_foreach(ctx->revocation_kids, revocation_kid, value) {
      if (strcmp(kid, revocation_kid) == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "auth_jwt: rejected due to kid in revocation list"
                      ": kid=\"%s\"", revocation_kid);
        // todo: it seems to be good,
        // if we add DEBUG log with short dump of value,
        // where we could find a reason of revocation.
        return NGX_ERROR;
      }
    }
  }

  if (ctx->claim_requirements != NULL) {
    ngx_uint_t i;
    ngx_http_auth_jwt_ctx_require_t *ctx_require;
    ctx_require = ctx->claim_requirements->elts;
    for (i = 0; i < ctx->claim_requirements->nelts; i++) {
      char *jwt_claim = NULL;
      json_t *jwt_claim_json = NULL, *expected_json = NULL;
      ngx_int_t is_valid;

      jwt_claim = jwt_get_grants_json(ctx->jwt, ctx_require[i].name);
      if (jwt_claim == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: rejected due to missing claim: %s",
                      ctx_require[i].name);
        return NGX_ERROR;
      }
      jwt_claim_json = json_loads(jwt_claim, JSON_DECODE_ANY, NULL);
      if (jwt_claim_json == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: failed to json load jwt claim: %s",
                      ctx_require[i].name);
        free(jwt_claim);
        return NGX_ERROR;
      }

      if (!ctx_require->json) {
        expected_json = json_stringn((char *) ctx_require[i].value.data,
                                     ctx_require[i].value.len);
      }
      else {
        expected_json = json_loadb((char *) ctx_require[i].value.data,
                                   ctx_require[i].value.len,
                                   JSON_DECODE_ANY, NULL);
      }
      if (expected_json == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: failed to json load claim requirement: %s",
                      ctx_require[i].name);
        free(jwt_claim);
        json_delete(jwt_claim_json);
        return NGX_ERROR;
      }

      if (ngx_strcmp("nbf", ctx_require[i].name) == 0) {
        if (json_is_number(expected_json)) {
          time_t val = ngx_atotm(ctx_require[i].value.data,
                                 ctx_require[i].value.len);
          json_delete(expected_json);
          expected_json = json_integer(val + cf->leeway);
          if (expected_json == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_jwt: failed to json reload"
                          " jwt claim requirement: %s",
                          ctx_require[i].name);
            free(jwt_claim);
            json_delete(jwt_claim_json);
            return NGX_ERROR;
          }
        }
      }
      else if (ngx_strcmp("exp", ctx_require[i].name) == 0) {
        if (json_is_number(expected_json)) {
          time_t val = ngx_atotm(ctx_require[i].value.data,
                                 ctx_require[i].value.len);
          json_delete(expected_json);
          expected_json = json_integer(val - cf->leeway);
          if (expected_json == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_jwt: failed to json reload"
                          " jwt claim requirement: %s",
                          ctx_require[i].name);
            free(jwt_claim);
            json_delete(jwt_claim_json);
            return NGX_ERROR;
          }

          // NOTE: do not verify exp if exp requirements are met
          cf->validate.exp = 0;
        }
      }

      is_valid = ngx_http_auth_jwt_validate_requirement_by_operator(
        ctx_require[i].operator, jwt_claim_json, expected_json);
      if (is_valid != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "auth_jwt: rejected due to %s claim requirement"
                      ": \"%s\" is not \"%s\" \"%V\"",
                      ctx_require[i].name, jwt_claim,
                      ctx_require[i].operator, &ctx_require[i].value);
        free(jwt_claim);
        json_delete(jwt_claim_json);
        json_delete(expected_json);
        return NGX_ERROR;
      }

      free(jwt_claim);
      json_delete(jwt_claim_json);
      json_delete(expected_json);
    }
  }

  /* validate exp claim */
  if (cf->validate.exp) {
    time_t exp, now;

    exp = ngx_http_auth_jwt_get_grant_time(r, ctx->jwt, "exp");
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

  if (ctx->header_requirements != NULL) {
    ngx_uint_t i;
    ngx_http_auth_jwt_ctx_require_t *ctx_require;
    ctx_require = ctx->header_requirements->elts;
    for (i = 0; i < ctx->header_requirements->nelts; i++) {
      json_t *jwt_header_json = NULL, *expected_json = NULL;
      char *jwt_header = NULL;
      ngx_int_t is_valid;

      jwt_header = jwt_get_headers_json(ctx->jwt, ctx_require[i].name);
      if (jwt_header == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: rejected due to missing header: %s",
                      ctx_require[i].name);
        return NGX_ERROR;
      }
      jwt_header_json = json_loads(jwt_header, JSON_DECODE_ANY, NULL);
      if (jwt_header_json == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: failed to json load jwt header: %s",
                      ctx_require[i].name);
        free(jwt_header);
        return NGX_ERROR;
      }

      if (!ctx_require->json) {
        expected_json = json_stringn((char *) ctx_require[i].value.data,
                                     ctx_require[i].value.len);
      }
      else {
        expected_json = json_loadb((char *) ctx_require[i].value.data,
                                   ctx_require[i].value.len,
                                   JSON_DECODE_ANY, NULL);
      }
      if (expected_json == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: failed to json load header requirement: %s",
                      ctx_require[i].name);
        free(jwt_header);
        json_delete(jwt_header_json);
        return NGX_ERROR;
      }

      is_valid = ngx_http_auth_jwt_validate_requirement_by_operator(
        ctx_require[i].operator, jwt_header_json, expected_json);
      if (is_valid != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "auth_jwt: rejected due to %s header requirement"
                      ": \"%s\" is not \"%s\" \"%V\"",
                      ctx_require[i].name, jwt_header,
                      ctx_require[i].operator, &ctx_require[i].value);
        free(jwt_header);
        json_delete(jwt_header_json);
        json_delete(expected_json);
        return NGX_ERROR;
      }

      free(jwt_header);
      json_delete(jwt_header_json);
      json_delete(expected_json);

      if (ngx_strcmp("alg", ctx_require[i].name) == 0) {
        // NOTE: allow NONE algorithm when passing alg requirements
        if (algorithm == JWT_ALG_NONE) {
          cf->validate.sig = 0;
        }
        // NOTE: do not verify algorithm if alg requirements are met
        algorithm = JWT_ALG_TERM;
      }
    }
  }

  /* rejected JWT_ALG_NONE as algorithm */
  if (algorithm == JWT_ALG_NONE) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "auth_jwt: rejected due to none algorithm");
    return NGX_ERROR;
  }

  /* validate signature */
  if (!cf->validate.sig) {
    ctx->verified = 1;
    return NGX_OK;
  }

  if (!ctx->keys) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "auth_jwt: rejected due to without signature key");
    return NGX_ERROR;
  }

  if (kid) {
    key = ngx_http_auth_jwt_key_get(ctx->keys, kid);
  }

  if (key) {
    if (jwt_verify_sig(ctx->jwt, (char *) ctx->token, ctx->payload_len,
                       (unsigned char *) key, strlen(key)) == 0) {
      ctx->verified = 1;
      return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "auth_jwt: rejected due to signature validate failure"
                  ": kid=\"%s\"", kid);
  }

  json_object_foreach(ctx->keys, kid, var) {
    if (!kid || !json_is_string(var)) {
      continue;
    }

    key = json_string_value(var);

    if (jwt_verify_sig(ctx->jwt, (char *) ctx->token, ctx->payload_len,
                       (unsigned char *) key, strlen(key)) == 0) {
      ctx->verified = 1;
      return NGX_OK;
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
                  phase == NGX_HTTP_PREACCESS_PHASE ? "PREACCESS" : "ACCESS");
    return NGX_DECLINED;
  }

  ctx = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);
  if (ctx != NULL) {
    if (ctx->done < ctx->subrequest) {
      return NGX_AGAIN;
    }

    if (ngx_http_auth_jwt_validate(r, cf, ctx) == NGX_ERROR) {
      return ngx_http_auth_jwt_http_unauthorized();
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
  if(cleanup == NULL) {
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
      return ngx_http_auth_jwt_http_unauthorized();
    }
    var.data = variable->data;
    var.len = variable->len;
  }
  else if (r->headers_in.authorization
           && ngx_strncmp(r->headers_in.authorization->value.data,
                          "Bearer ", sizeof("Bearer ") - 1) == 0) {
    /* token from authorization header */
    var.data = r->headers_in.authorization->value.data + 7;
    var.len = r->headers_in.authorization->value.len - 7;

    ctx->use_bearer = 1;
  }

  if (var.len == 0) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "auth_jwt: token was not provided");
    return ngx_http_auth_jwt_http_unauthorized_error();
  }

  ctx->token = ngx_http_auth_jwt_strdup(r->pool, var.data, var.len);
  if (ctx->token == NULL) {
    ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                  "auth_jwt: failed to allocate token");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  if (cf->revocation_subs) {
    ctx->revocation_subs = json_copy(cf->revocation_subs);
  }

  if (cf->revocation_kids) {
    ctx->revocation_kids = json_copy(cf->revocation_kids);
  }

  if (ngx_http_auth_jwt_load_requirements(r, &cf->validate.claim_requirements,
                                          &ctx->claim_requirements)
      == NGX_ERROR) {
    return ngx_http_auth_jwt_http_unauthorized_error();
  }

  if (ngx_http_auth_jwt_load_requirements(r, &cf->validate.header_requirements,
                                          &ctx->header_requirements)
      == NGX_ERROR) {
    return ngx_http_auth_jwt_http_unauthorized_error();
  }

  /* parse jwt token */
  if (jwt_parse(&ctx->jwt, (char *) ctx->token, &ctx->payload_len) != 0
      || ctx->jwt == NULL) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "auth_jwt: failed to parse jwt token");
    return ngx_http_auth_jwt_http_unauthorized();
  }

  /* load keys */
  if (ngx_http_auth_jwt_load_keys(r, cf, ctx) == NGX_AGAIN) {
    return NGX_AGAIN;
  }

  /* validate */
  if (ngx_http_auth_jwt_validate(r, cf, ctx) == NGX_ERROR) {
    return ngx_http_auth_jwt_http_unauthorized();
  }

  return ngx_http_auth_jwt_http_ok();
}
