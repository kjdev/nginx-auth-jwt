
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "jwt/jwt.h"
#include "jwt/jwt-private.h"
#include "key.h"

#define NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX "jwt_claim_"
#define NGX_HTTP_AUTH_JWT_HEADER_VAR_PREFIX "jwt_header_"

static ngx_int_t ngx_http_auth_jwt_variable_claim(ngx_http_request_t *r,  ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_jwt_variable_header(ngx_http_request_t *r,  ngx_http_variable_value_t *v, uintptr_t data);

static char *ngx_http_auth_jwt_conf_set_token_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_claim(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_key_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_conf_set_key_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

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
  ngx_array_t *claim_vars;
  ngx_array_t *key_files;
  ngx_array_t *key_requests;
  time_t leeway;
  ngx_int_t phase;
  ngx_uint_t validate_alg;
  ngx_flag_t validate_exp;
  ngx_flag_t validate_sig;
  ngx_flag_t enabled;
  ngx_str_t realm;
  json_t *keys;
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
} ngx_http_auth_jwt_ctx_t;

typedef struct {
  ngx_int_t index;
  ngx_str_t url;
  ngx_flag_t jwks;
  ngx_http_auth_jwt_ctx_t *ctx;
} ngx_http_auth_jwt_key_request_t;

typedef const char *(*auth_jwt_get)(jwt_t *jwt, const char *key);
typedef char *(*auth_jwt_get_json)(jwt_t *jwt, const char *key);

static ngx_conf_enum_t ngx_http_auth_jwt_algs[] = {
  { ngx_string("none"),  JWT_ALG_NONE  },
  { ngx_string("HS256"), JWT_ALG_HS256 },
  { ngx_string("HS384"), JWT_ALG_HS384 },
  { ngx_string("HS512"), JWT_ALG_HS512 },
  { ngx_string("RS256"), JWT_ALG_RS256 },
  { ngx_string("RS384"), JWT_ALG_RS384 },
  { ngx_string("RS512"), JWT_ALG_RS512 },
  { ngx_string("ES256"), JWT_ALG_ES256 },
  { ngx_string("ES384"), JWT_ALG_ES384 },
  { ngx_string("ES512"), JWT_ALG_ES512 },
  { ngx_null_string, 0 }
};

static ngx_conf_enum_t ngx_http_auth_jwt_phases[] = {
  { ngx_string("PREACCESS"), NGX_HTTP_PREACCESS_PHASE },
  { ngx_string("ACCESS"), NGX_HTTP_ACCESS_PHASE },
  { ngx_null_string, 0 }
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
  ngx_http_null_variable
};

static ngx_command_t ngx_http_auth_jwt_commands[] = {
  { ngx_string("auth_jwt"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
    ngx_http_auth_jwt_conf_set_token_variable,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("auth_jwt_claim_set"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
    ngx_http_auth_jwt_conf_set_claim,
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
  { ngx_string("auth_jwt_validate_alg"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_enum_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, validate_alg),
    &ngx_http_auth_jwt_algs },
  { ngx_string("auth_jwt_validate_exp"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, validate_exp),
    NULL },
  { ngx_string("auth_jwt_validate_sig"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, validate_sig),
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

static ngx_int_t
ngx_http_auth_jwt_variable_find(ngx_http_request_t *r,
                                ngx_http_variable_value_t *v,
                                const ngx_str_t *name,
                                const ngx_flag_t use_claim)
{
  char *str = NULL, *prefix = NULL;
  const char *value;
  size_t len, prefix_len;
  u_char *data, *key, *var;
  ngx_http_auth_jwt_ctx_t *ctx;
  auth_jwt_get jwt_get;
  auth_jwt_get_json jwt_get_json;

  ctx = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);
  if (!ctx || !ctx->jwt) {
    v->not_found = 1;
    return NGX_OK;
  }

  if (use_claim != 1) {
    prefix = NGX_HTTP_AUTH_JWT_HEADER_VAR_PREFIX;
    jwt_get = jwt_get_header;
    jwt_get_json = jwt_get_headers_json;
  } else {
    if (!ctx->verified) {
      v->not_found = 1;
      return NGX_OK;
    }

    prefix = NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX;
    jwt_get = jwt_get_grant;
    jwt_get_json = jwt_get_grants_json;
  }

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

  value = (*jwt_get)(ctx->jwt, (char *)key);
  if (value == NULL) {
    size_t i, t;

    str = (*jwt_get_json)(ctx->jwt, (char *)key);
    if (str == NULL) {
      v->not_found = 1;
      return NGX_OK;
    }

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
  return ngx_http_auth_jwt_variable_find(r, v, (ngx_str_t *)data, 0);
}

static ngx_int_t
ngx_http_auth_jwt_variable_claim(ngx_http_request_t *r,
                                 ngx_http_variable_value_t *v, uintptr_t data)
{
  return ngx_http_auth_jwt_variable_find(r, v, (ngx_str_t *)data, 1);
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
ngx_http_auth_jwt_conf_set_claim(ngx_conf_t *cf,
                                 ngx_command_t *cmd, void *conf)
{
  ngx_http_auth_jwt_loc_conf_t *lcf;
  ngx_str_t *str, *value;
  ngx_http_variable_t *var;
  size_t prefix;

  lcf = conf;
  value = cf->args->elts;

  if (value[1].data[0] != '$') {
    return "not a variable specified";
  }

  value[1].data++;
  value[1].len--;

  if (lcf->claim_vars == NGX_CONF_UNSET_PTR) {
    lcf->claim_vars = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
    if (lcf->claim_vars == NULL) {
      return "failed to allocate";
    }
  }

  str = ngx_array_push(lcf->claim_vars);
  if (str == NULL) {
    return "failed to allocate iteam";
  }

  prefix = sizeof(NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX);
  str->len = value[2].len + prefix - 1;
  str->data = ngx_pnalloc(cf->pool, str->len);
  if (str->data == NULL) {
    return "failed to allocate variable";
  }

  ngx_memcpy(str->data, NGX_HTTP_AUTH_JWT_CLAIM_VAR_PREFIX, prefix);
  ngx_memcpy(str->data + prefix - 1, value[2].data, value[2].len);

  var = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
  if (var == NULL) {
    return "failed to add variable";
  }

  var->get_handler = ngx_http_auth_jwt_variable_claim;
  var->data = (uintptr_t)str;

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
    } else if (ngx_strncmp("jwks", value[2].data, value[2].len) != 0) {
      return "format is incorrect";
    }
  }

  if (value[1].data[0] == '$') {
    ngx_str_t var;
    ngx_http_auth_jwt_key_file_t *key_file;

    if (lcf->key_files == NULL) {
      lcf->key_files = ngx_array_create(cf->pool, 1, sizeof(*key_file));
      if (lcf->key_files == NULL) {
        return "failed to allocate";
      }
    }

    key_file = ngx_array_push(lcf->key_files);
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

  file = (char *)ngx_http_auth_jwt_strdup(cf->pool,
                                          value[1].data, value[1].len);
  if (file == NULL) {
    return "failed to allocate file";
  }

  if (jwks) {
    if (key_jwks_load_file(&lcf->keys, file) != 0) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "\"%V\" directive failed to load jwks file: \"%s\"",
                         &cmd->name, file);
      return NGX_CONF_ERROR;
    }
  } else {
    if (key_load_file(&lcf->keys, file) != 0) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "\"%V\" directive failed to load key file: \"%s\"",
                         &cmd->name, file);
      return NGX_CONF_ERROR;
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
    } else if (ngx_strncmp("jwks", value[2].data, value[2].len) != 0) {
      return "format is incorrect";
    }
  }

  if (lcf->key_requests == NULL) {
    lcf->key_requests = ngx_array_create(cf->pool, 1, sizeof(*key_request));
    if (lcf->key_requests == NULL) {
      return "failed to allocate";
    }
  }

  key_request = ngx_array_push(lcf->key_requests);
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
  } else {
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
  conf->claim_vars = NGX_CONF_UNSET_PTR;
  conf->key_files = NULL;
  conf->key_requests = NULL;
  conf->leeway = NGX_CONF_UNSET;
  conf->phase = NGX_CONF_UNSET;
  conf->validate_alg = NGX_CONF_UNSET_UINT;
  conf->validate_exp = NGX_CONF_UNSET;
  conf->validate_sig = NGX_CONF_UNSET;

  conf->enabled = NGX_CONF_UNSET;
  conf->keys = NULL;

  return conf;
}

static char *
ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_auth_jwt_loc_conf_t *prev = parent;
  ngx_http_auth_jwt_loc_conf_t *conf = child;

  ngx_conf_merge_value(conf->token_variable,
                       prev->token_variable, NGX_CONF_UNSET);
  ngx_conf_merge_ptr_value(conf->claim_vars, prev->claim_vars, NULL);

  if (conf->key_files == NULL || conf->key_files->nelts == 0) {
    conf->key_files = prev->key_files;
  } else if (prev->key_files && prev->key_files->nelts) {
    ngx_uint_t i, len, n;
    ngx_http_auth_jwt_key_file_t *key_file, *var;

    len = conf->key_files->nelts;
    n = prev->key_files->nelts;

    ngx_array_push_n(conf->key_files, n);

    key_file = conf->key_files->elts;
    var = prev->key_files->elts;

    for (i = 0; i < len; i++) {
      key_file[n + i] = key_file[i];
    }
    for (i = 0; i < n; i++) {
      key_file[i] = var[i];
    }
  }

  if (conf->key_requests == NULL || conf->key_requests->nelts == 0) {
    conf->key_requests = prev->key_requests;
  } else if (prev->key_requests && prev->key_requests->nelts) {
    ngx_uint_t i, len, n;
    ngx_http_auth_jwt_key_request_t *key_request, *var;

    len = conf->key_requests->nelts;
    n = prev->key_requests->nelts;

    ngx_array_push_n(conf->key_requests, n);

    key_request = conf->key_requests->elts;
    var = prev->key_requests->elts;

    for (i = 0; i < len; i++) {
      key_request[n + i] = key_request[i];
    }
    for (i = 0; i < n; i++) {
      key_request[i] = var[i];
    }
  }

  ngx_conf_merge_sec_value(conf->leeway, prev->leeway, 0);

  ngx_conf_merge_value(conf->phase, prev->phase, NGX_HTTP_ACCESS_PHASE);

  ngx_conf_merge_uint_value(conf->validate_alg,
                            prev->validate_alg, NGX_CONF_UNSET_UINT);
  ngx_conf_merge_value(conf->validate_exp, prev->validate_exp, 1);
  ngx_conf_merge_value(conf->validate_sig, prev->validate_sig, 1);

  ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
  ngx_conf_merge_str_value(conf->realm, prev->realm, "");

  if (prev->keys) {
    if (conf->keys) {
      json_object_update_missing(conf->keys, prev->keys);
    } else {
      conf->keys = json_copy(prev->keys);
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

  ctx = (ngx_http_conf_ctx_t *)cycle->conf_ctx[ngx_http_module.index];
  index = ngx_http_auth_jwt_module.ctx_index;

  if (!ctx->loc_conf[index]) {
    return;
  }

  conf = (ngx_http_auth_jwt_loc_conf_t *)ctx->loc_conf[index];

  if (conf && conf->keys) {
    json_delete(conf->keys);
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
  } else {
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
    json_t *json = NULL;

    len = b->last - b->pos;

    json = json_loadb((char *)b->pos, len, 0, NULL);
    if (json) {
      if (key_request->jwks) {
        if (key_jwks_load(&key_request->ctx->keys, json) != 0) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "auth_jwt: failed to load jwks: \"%V\"",
                        &r->uri);
        }
      } else {
        if (key_load(&key_request->ctx->keys, json) != 0) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "auth_jwt: failed to load key: \"%V\"",
                        &r->uri);
        }
      }
      json_delete(json);
    } else {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "auth_jwt: failed to load json: \"%V\"",
                    &r->uri);
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
  if (!cf->validate_sig) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "auth_jwt: ignore load keys");
    return NGX_DECLINED;
  }

  if (cf->keys) {
    ctx->keys = json_copy(cf->keys);
  }

  if (cf->key_files != NULL) {
    ngx_uint_t i;
    ngx_http_auth_jwt_key_file_t *key_file;

    key_file = cf->key_files->elts;

    for (i = 0; i < cf->key_files->nelts; i++) {
      char *file;
      ngx_http_variable_value_t  *v;

      v = ngx_http_get_indexed_variable(r, key_file[i].index);
      if (v == NULL || v->not_found) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: key_file variable specified was not provided");
        continue;
      }

      file = (char *)ngx_http_auth_jwt_strdup(r->pool, v->data, v->len);
      if (file == NULL) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "auth_jwt: failed to allocate key file");
        continue;
      }

      if (key_file[i].jwks) {
        if (key_jwks_load_file(&ctx->keys, file) != 0) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "auth_jwt: failed to load jwks file: \"%s\"", file);
        }
      } else {
        if (key_load_file(&ctx->keys, file) != 0) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "auth_jwt: failed to load key file: \"%s\"", file);
        }
      }
    }
  }

  if (cf->key_requests != NULL) {
    ngx_int_t flags = 0;
    ngx_http_post_subrequest_t *ps;
    ngx_http_request_t *sr;
    ngx_uint_t i;
    ngx_http_auth_jwt_key_request_t *key_request;

    flags = NGX_HTTP_SUBREQUEST_WAITED | NGX_HTTP_SUBREQUEST_IN_MEMORY;

    key_request = cf->key_requests->elts;

    for (i = 0; i < cf->key_requests->nelts; i++) {
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
      } else {
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
ngx_http_auth_jwt_validate(ngx_http_request_t *r,
                           ngx_http_auth_jwt_loc_conf_t *cf,
                           ngx_http_auth_jwt_ctx_t *ctx)
{
  jwt_alg_t algorithm;

  if (!cf || !ctx) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "auth_jwt: rejected due to missing required arguments");
    return NGX_ERROR;
  }

  /* validate algorithm */
  algorithm = jwt_get_alg(ctx->jwt);

  if (cf->validate_alg != NGX_CONF_UNSET_UINT) {
    if (cf->validate_alg != algorithm) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "auth_jwt: rejected due to unacceptable algorithm"
                    ": equals expected=%s actual=%s",
                    jwt_alg_str(cf->validate_alg), jwt_alg_str(algorithm));
      return NGX_ERROR;
    }
    if (algorithm == JWT_ALG_NONE) {
      cf->validate_sig = 0;
    }
  } else if (algorithm == JWT_ALG_NONE) {
    /* rejected JWT_ALG_NONE as algorithm */
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "auth_jwt: rejected due to none algorithm");
    return NGX_ERROR;
  }

  /* validate exp claim */
  if (cf->validate_exp) {
    time_t exp, now;

    exp = (time_t)jwt_get_grant_int(ctx->jwt, "exp");
    if (exp == -1) {
      const char *var;

      var = jwt_get_grants_json(ctx->jwt, "exp");
      if (var) {
        size_t n;
        u_char *p;

        p = (u_char *)ngx_strchr(var, '.');
        if (p) {
          n = p - (u_char *)var;
        } else {
          n = strlen(var);
        }

        exp = ngx_atotm((u_char *)var, n);
      } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_jwt: failed to get exp claim: \"%s\"", var);
      }
    }

    now = ngx_time();

    if (now > exp + cf->leeway) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "auth_jwt: rejected due to token expired"
                    ": exp=%l: greater than expected=%l actual=%l",
                    exp, now, exp + cf->leeway);
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "auth_jwt: token: \"%s\"", (char *)ctx->token);
      return NGX_ERROR;
    }
  }

  /* validate signature */
  if (cf->validate_sig) {
    const char *kid = NULL, *key = NULL;

    if (!ctx->keys) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "auth_jwt: rejected due to without signature key");
      return NGX_ERROR;
    }

    kid = jwt_get_header(ctx->jwt, "kid");
    if (kid == NULL) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "auth_jwt: rejected due to missing JWT header kid");
      return NGX_ERROR;
    }

    key = key_get(ctx->keys, kid);
    if (key == NULL) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "auth_jwt: rejected due to missing signature key"
                    ": kid=\"%s\"", kid);
      return NGX_ERROR;
    }

    if (jwt_verify_sig(ctx->jwt, (char *)ctx->token, ctx->payload_len,
                       (unsigned char *)key, strlen(key)) != 0) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "auth_jwt: rejected due to signature validate failure"
                    ": kid=\"%s\"",
                    jwt_get_header(ctx->jwt, "kid"));
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "auth_jwt: token: \"%s\"", (char *)ctx->token);
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "auth_jwt: signature key: \"%s\"", key);
      return NGX_ERROR;
    }
  }

  ctx->verified = 1;

  return NGX_OK;
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
  } else if (r->headers_in.authorization
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

  /* parse jwt token */
  if (jwt_parse(&ctx->jwt, (char *)ctx->token, &ctx->payload_len) != 0
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
