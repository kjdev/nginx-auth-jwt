#include <errno.h>
#include <jansson.h>
#include <string.h>
#include "jwt_get_claims.h"
#include "jwt/jwt-private.h"

static json_t *
get_js_json(const json_t *js, const char *key,
            const char *delim, const char *quote)
{
  json_t *js_val = NULL;

  if (!js) {
    return NULL;
  }

  js_val = (json_t *) js;

  if (key && strlen(key) && js_val != NULL) {
    json_t *js_obj = NULL;

    if (delim) {
      char *p = NULL, *s = NULL, *var = NULL;
      size_t delim_len = strlen(delim), quote_len = 0;

      var = strdup(key);
      if (!var) {
        return NULL;
      }

      s = var;

      if (quote) {
        quote_len = strlen(quote);
      }

      do {
        if (s && quote && strncmp(s, quote, quote_len) == 0) {
          s += quote_len;
          p = strsep(&s, quote);
          if (p && strlen(p)) {
            if (s) {
              s += quote_len - 1;
            }
            js_obj = json_object_get(js_val, p);
            if (js_obj == NULL) {
              js_val = NULL;
              break;
            }
            js_val = js_obj;
          }
        }

        p = strsep(&s, delim);
        if (p && strlen(p)) {
          if (s) {
            s += delim_len - 1;
          }
          js_obj = json_object_get(js_val, p);
          if (js_obj == NULL) {
            js_val = NULL;
            break;
          }
          js_val = js_obj;
        }
      } while (p);

      free(var);
    }
    else {
      js_obj = json_object_get(js_val, key);
      if (js_obj == NULL) {
        js_val = NULL;
      }
      else {
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
get_js_string(const json_t *js, const char *key,
              const char *delim, const char *quote)
{
  const char *val = NULL;
  json_t *js_val = NULL;

  if (!key || !strlen(key)) {
    errno = EINVAL;
    return NULL;
  }

  js_val = get_js_json(js, key, delim, quote);
  if (js_val == NULL) {
    errno = ENOENT;
    return NULL;
  }

  if (json_typeof(js_val) == JSON_STRING) {
    val = json_string_value(js_val);
  }
  else {
    errno = EINVAL;
  }

  return val;
}

static long
get_js_int(const json_t *js, const char *key,
           const char *delim, const char *quote)
{
  long val = -1;
  json_t *js_val = NULL;

  if (!key || !strlen(key)) {
    errno = EINVAL;
    return 0;
  }

  js_val = get_js_json(js, key, delim, quote);
  if (js_val == NULL) {
    errno = ENOENT;
    return 0;
  }

  if (json_typeof(js_val) == JSON_INTEGER) {
    val = (long) json_integer_value(js_val);
  }
  else {
    errno = EINVAL;
  }

  return val;
}

static int
get_js_bool(const json_t *js, const char *key,
            const char *delim, const char *quote)
{
  int val = -1;
  json_t *js_val = NULL;

  if (!key || !strlen(key)) {
    errno = EINVAL;
    return 0;
  }

  js_val = get_js_json(js, key, delim, quote);
  if (js_val == NULL) {
    errno = ENOENT;
    return 0;
  }

  switch (json_typeof(js_val)) {
    case JSON_TRUE:
      val = 1;
      break;
    case JSON_FALSE:
      val = 0;
      break;
    default:
      errno = EINVAL;
  }

  return val;
}

const char *
ngx_http_auth_jwt_get_header(jwt_t *jwt, const char *header,
                             const char *delim, const char *quote)
{
  if (delim == NULL) {
    return jwt_get_header(jwt, header);
  }

  if (!jwt) {
    errno = EINVAL;
    return NULL;
  }

  errno = 0;

  return get_js_string(jwt->headers, header, delim, quote);
}

long
ngx_http_auth_jwt_get_header_int(jwt_t *jwt, const char *header,
                                 const char *delim, const char *quote)
{
  if (delim == NULL) {
    return jwt_get_header_int(jwt, header);
  }

  if (!jwt) {
    errno = EINVAL;
    return 0;
  }

  errno = 0;

  return get_js_int(jwt->headers, header, delim, quote);
}

int
ngx_http_auth_jwt_get_header_bool(jwt_t *jwt, const char *header,
                                  const char *delim, const char *quote)
{
  if (delim == NULL) {
    return jwt_get_header_bool(jwt, header);
  }

  if (!jwt) {
    errno = EINVAL;
    return 0;
  }

  errno = 0;

  return get_js_bool(jwt->headers, header, delim, quote);
}

char *
ngx_http_auth_jwt_get_headers_json(jwt_t *jwt, const char *header,
                                   const char *delim, const char *quote)
{
  json_t *js_val = NULL;

  if (delim == NULL) {
    return jwt_get_headers_json(jwt, header);
  }

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

  return json_dumps(js_val, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
}

const char *
ngx_http_auth_jwt_get_grant(jwt_t *jwt, const char *grant,
                            const char *delim, const char *quote)
{
  if (delim == NULL) {
    return jwt_get_grant(jwt, grant);
  }

  if (!jwt) {
    errno = EINVAL;
    return NULL;
  }

  errno = 0;

  return get_js_string(jwt->grants, grant, delim, quote);
}

long
ngx_http_auth_jwt_get_grant_int(jwt_t *jwt, const char *grant,
                                const char *delim, const char *quote)
{
  if (delim == NULL) {
    return jwt_get_grant_int(jwt, grant);
  }

  if (!jwt) {
    errno = EINVAL;
    return 0;
  }

  errno = 0;

  return get_js_int(jwt->grants, grant, delim, quote);
}

int
ngx_http_auth_jwt_get_grant_bool(jwt_t *jwt, const char *grant,
                                 const char *delim, const char *quote)
{
  if (delim == NULL) {
    return jwt_get_grant_bool(jwt, grant);
  }

  if (!jwt) {
    errno = EINVAL;
    return 0;
  }

  errno = 0;

  return get_js_bool(jwt->grants, grant, delim, quote);
}

char *
ngx_http_auth_jwt_get_grants_json(jwt_t *jwt, const char *grant,
                                  const char *delim, const char *quote)
{
  json_t *js_val = NULL;

  if (delim == NULL) {
    return jwt_get_grants_json(jwt, grant);
  }

  if (!jwt) {
    errno = EINVAL;
    return NULL;
  }

  js_val = get_js_json(jwt->grants, grant, delim, quote);
  if (js_val == NULL) {
    errno = ENOENT;
    return NULL;
  }

  errno = 0;

  return json_dumps(js_val, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
}
