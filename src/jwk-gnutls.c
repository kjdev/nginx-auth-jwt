#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include "jwk.h"

#define SHA256_DIGEST_LENGTH 32

/*
  jwk rsa and ecdsa key parameters
*/

typedef struct
{
  gnutls_datum_t *n;
  gnutls_datum_t *e;
} jwk_key_rsa_t;

typedef struct
{
  gnutls_datum_t *curve;
  gnutls_datum_t *x;
  gnutls_datum_t *y;
} jwk_key_ec_t;

/* jwk key type */

typedef enum
{
  JWK_KTY_NONE = 0,
  JWK_KTY_OCT,
  JWK_KTY_RSA,
  JWK_KTY_EC,
  JWK_KTY_OKP
} jwk_kty_t;

static const char *jwk_kty_to(jwk_kty_t kty)
{
  switch (kty)
  {
  case JWK_KTY_OCT:
    return "oct";
  case JWK_KTY_RSA:
    return "RSA";
  case JWK_KTY_EC:
    return "EC";
  case JWK_KTY_OKP:
    return "OKP";
  default:
    return "";
  }
}

static jwk_kty_t jwk_kty_from(const char *kty)
{
  if (strcmp("oct", kty) == 0)
  {
    return JWK_KTY_OCT;
  }
  else if (strcmp("RSA", kty) == 0)
  {
    return JWK_KTY_RSA;
  }
  else if (strcmp("EC", kty) == 0)
  {
    return JWK_KTY_EC;
  }
  else if (strcmp("OKP", kty) == 0)
  {
    return JWK_KTY_OKP;
  }
  return JWK_KTY_NONE;
}

/* base64 encode/decode */

static char *jwk_base64_urlencode(const char *input, size_t length)
{
  gnutls_datum_t input_data = {(unsigned char *)input, length};
  gnutls_datum_t output_data = {NULL, 0};
  char *base64_encoded = NULL;

  if (gnutls_base64_encode2(&input_data, &output_data) == GNUTLS_E_SUCCESS &&
      output_data.data != NULL)
  {
    // Create a URL-safe Base64 encoded string
    base64_encoded = (char *)malloc(output_data.size + 1);
    if (base64_encoded)
    {
      memcpy(base64_encoded, output_data.data, output_data.size);
      base64_encoded[output_data.size] = '\0';

      // Replace '+' with '-' and '/' with '_'
      size_t i;
      for (i = 0; i < output_data.size; i++)
      {
        if (base64_encoded[i] == '+')
        {
          base64_encoded[i] = '-';
        }
        else if (base64_encoded[i] == '/')
        {
          base64_encoded[i] = '_';
        }
      }

      gnutls_free(output_data.data);
    }
  }

  return base64_encoded;
}

static char *jwk_base64_urldecode(const char *input)
{
  // Create a URL-safe copy of the input string
  char *url_safe_copy = strdup(input);
  if (url_safe_copy == NULL)
  {
    return NULL;
  }

  // Replace '-' with '+' and '_' with '/' in the URL-safe copy
  size_t i;
  for (i = 0; i < strlen(input); i++)
  {
    if (url_safe_copy[i] == '-')
    {
      url_safe_copy[i] = '+';
    }
    else if (url_safe_copy[i] == '_')
    {
      url_safe_copy[i] = '/';
    }
  }

  gnutls_datum_t input_data = {(unsigned char *)url_safe_copy, strlen(url_safe_copy)};
  gnutls_datum_t output_data = {NULL, 0};
  char *base64_decoded = NULL;

  if (gnutls_base64_decode2(&input_data, &output_data) == GNUTLS_E_SUCCESS &&
      output_data.data != NULL)
  {
    base64_decoded = (char *)malloc(output_data.size + 1);
    if (base64_decoded)
    {
      memcpy(base64_decoded, output_data.data, output_data.size);
      base64_decoded[output_data.size] = '\0';
    }

    gnutls_free(output_data.data);
  }

  free(url_safe_copy);
  return base64_decoded;
}

/* jwk */

struct jwk
{
  char *key;
  size_t key_len;
  jwk_kty_t kty;
  json_t *params;
  char *thumbprint;
};

static int jwk_calc_thumbprint(jwk_t *jwk)
{
  const char *var;
  char *str;
  json_t *members = NULL;
  size_t count = 0;
  unsigned char digest[SHA256_DIGEST_LENGTH];
  gnutls_hash_hd_t sha256_ctx;

  if (!jwk)
  {
    return EINVAL;
  }

  gnutls_hash_init(&sha256_ctx, GNUTLS_DIG_SHA256);

  members = json_object();

  if (jwk->kty == JWK_KTY_OCT)
  {
    count = 2;
    var = jwk_parameter(jwk, "k");
    if (var)
    {
      json_object_set_new(members, "k", json_string(var));
    }
    json_object_set_new(members, "kty", json_string(jwk_kty_to(jwk->kty)));
  }
  else if (jwk->kty == JWK_KTY_RSA)
  {
    count = 3;
    var = jwk_parameter(jwk, "e");
    if (var)
    {
      json_object_set_new(members, "e", json_string(var));
    }
    json_object_set_new(members, "kty", json_string(jwk_kty_to(jwk->kty)));
    var = jwk_parameter(jwk, "n");
    if (var)
    {
      json_object_set_new(members, "n", json_string(var));
    }
  }
  else if (jwk->kty == JWK_KTY_EC)
  {
    count = 4;
    var = jwk_parameter(jwk, "crv");
    if (var)
    {
      json_object_set_new(members, "crv", json_string(var));
    }
    json_object_set_new(members, "kty", json_string(jwk_kty_to(jwk->kty)));
    var = jwk_parameter(jwk, "x");
    if (var)
    {
      json_object_set_new(members, "x", json_string(var));
    }
    var = jwk_parameter(jwk, "y");
    if (var)
    {
      json_object_set_new(members, "y", json_string(var));
    }
  }
  else if (jwk->kty == JWK_KTY_OKP)
  {
    count = 3;
    var = jwk_parameter(jwk, "crv");
    if (var)
    {
      json_object_set_new(members, "crv", json_string(var));
    }
    json_object_set_new(members, "kty", json_string(jwk_kty_to(jwk->kty)));
    var = jwk_parameter(jwk, "x");
    if (var)
    {
      json_object_set_new(members, "x", json_string(var));
    }
  }
  else
  {
    count = 0;
  }

  if (count == 0 || json_object_size(members) != count)
  {
    gnutls_hash_deinit(sha256_ctx, NULL);
    json_delete(members);
    return EPERM;
  }

  str = json_dumps(members, JSON_COMPACT);
  gnutls_hash(sha256_ctx, (const unsigned char *)str, strlen(str));
  gnutls_hash_output(sha256_ctx, digest);

  gnutls_hash_deinit(sha256_ctx, NULL);
  free(str);
  json_delete(members);

  jwk->thumbprint = jwk_base64_urlencode((char *)digest, SHA256_DIGEST_LENGTH);

  return 0;
}

// replaces: static BIGNUM *jwk_key_base64_to_bn(const char *data)
static gnutls_datum_t *jwk_key_base64_to_datum(const char *data)
{
  gnutls_datum_t *datum = NULL;
  char *decoded_data;

  if (!data)
  {
    return NULL;
  }

  decoded_data = jwk_base64_urldecode(data);
  if (!decoded_data)
  {
    return NULL;
  }

  // Allocate memory for the gnutls_datum_t and copy the decoded data
  datum = (gnutls_datum_t *)gnutls_malloc(sizeof(gnutls_datum_t));
  if (!datum)
  {
    free(decoded_data);
    return NULL;
  }

  datum->data = (unsigned char *)decoded_data;
  datum->size = strlen(decoded_data);

  return datum;
}

// replaces: static BIO *jwk_key_pem_pubkey_new(EVP_PKEY_CTX *context, OSSL_PARAM *param)
gnutls_pubkey_t jwk_key_pem_pubkey_new(jwk_kty_t class, void *params)
{
  gnutls_pubkey_t pubkey = NULL; // Initialize to NULL

  if (params == NULL)
  {
    return NULL;
  }

  if (gnutls_pubkey_init(&pubkey) != GNUTLS_E_SUCCESS)
  {
    return NULL;
  }

  switch (class)
  {
  case JWK_KTY_RSA:
  {
    jwk_key_rsa_t *p = (jwk_key_rsa_t *)params;
    if (gnutls_pubkey_import_rsa_raw(pubkey, p->n, p->e) != GNUTLS_E_SUCCESS)
    {
      return NULL;
    }

    break;
  }

  case JWK_KTY_EC:
  {
    jwk_key_ec_t *p = (jwk_key_ec_t *)params;
    gnutls_ecc_curve_t curve = gnutls_ecc_curve_get_id((const char *)p->curve->data);

    if (gnutls_pubkey_import_ecc_raw(pubkey, curve, p->x, p->y) != GNUTLS_E_SUCCESS)
    {
      return NULL;
    }

    break;
  }

  default:
    return NULL;
  }

  return pubkey;
}

// replaces: void jwk_key_pem_pubkey_free(BIO *bio)
static void jwk_key_pem_pubkey_free(gnutls_pubkey_t key)
{
  if (key)
  {
    gnutls_pubkey_deinit(key);
  }
}

// replaces: static char *jwk_key_pem_pubkey_get(BIO *bio)
static char *jwk_key_pem_pubkey_get(gnutls_pubkey_t key)
{
  size_t data_sz;
  char *data = NULL;
  char *pem = NULL;

  if (key == NULL)
  {
    return NULL;
  }

  if (gnutls_pubkey_export(key, GNUTLS_X509_FMT_PEM, NULL,
                           &data_sz) == GNUTLS_E_SUCCESS)
  {
    data = gnutls_malloc(data_sz + 1);
    if (data)
    {
      if (gnutls_pubkey_export(key, GNUTLS_X509_FMT_PEM, data,
                               &data_sz) == GNUTLS_E_SUCCESS)
      {
        data[data_sz] = '\0';
        pem = strdup(data);
      }

      gnutls_free(data);
    }
  }

  return pem;
}

static void jwk_key_rsa_init(jwk_key_rsa_t *rsa)
{
  rsa->n = NULL;
  rsa->e = NULL;
}

static void jwk_key_rsa_deinit(jwk_key_rsa_t *rsa)
{
  if (rsa->e)
  {
    if (rsa->e->data)
    {
      gnutls_free(rsa->e->data);
    }
    gnutls_free(rsa->e);
  }

  if (rsa->n)
  {
    if (rsa->n->data)
    {
      gnutls_free(rsa->n->data);
    }
    gnutls_free(rsa->n);
  }
}

static int jwk_key_rsa_import(jwk_key_rsa_t *rsa, jwk_t *jwk)
{
  const char *var = NULL;

  if (!rsa || !jwk)
  {
    return EINVAL;
  }

  if (jwk->kty != JWK_KTY_RSA)
  {
    return EPERM;
  }

  var = jwk_parameter(jwk, "n");
  if (!var)
  {
    return EPERM;
  }
  rsa->n = jwk_key_base64_to_datum(var);

  var = jwk_parameter(jwk, "e");
  if (!var)
  {
    return EPERM;
  }

  rsa->e = jwk_key_base64_to_datum(var);
  return 0;
}

static char *jwk_key_rsa_get(jwk_key_rsa_t *rsa)
{
  char *out = NULL;

  gnutls_pubkey_t pubkey = jwk_key_pem_pubkey_new(JWK_KTY_RSA, rsa);
  if (!pubkey)
  {
    return NULL;
  }

  out = jwk_key_pem_pubkey_get(pubkey);
  jwk_key_pem_pubkey_free(pubkey);

  return out;
}

static void jwk_key_ec_init(jwk_key_ec_t *ec)
{
  ec->curve = NULL;
  ec->x = NULL;
  ec->y = NULL;
}

static void jwk_key_ec_deinit(jwk_key_ec_t *ec)
{
  if (ec->curve)
  {
    if (ec->curve->data)
    {
      gnutls_free(ec->curve->data);
    }
    gnutls_free(ec->curve);
  }

  if (ec->x)
  {
    if (ec->x->data)
    {
      gnutls_free(ec->x->data);
    }
    gnutls_free(ec->x);
  }

  if (ec->y)
  {
    if (ec->y->data)
    {
      gnutls_free(ec->y->data);
    }
    gnutls_free(ec->y);
  }
}

static int jwk_key_ec_import(jwk_key_ec_t *ec, jwk_t *jwk)
{
  const char *var;

  if (!ec || !jwk)
  {
    return EINVAL;
  }

  if (jwk->kty != JWK_KTY_EC)
  {
    return EPERM;
  }

  var = jwk_parameter(jwk, "crv");
  if (!var)
  {
    return EPERM;
  }
  ec->curve = jwk_key_base64_to_datum(var); // TODO:: this is not base64 encoded!

  var = jwk_parameter(jwk, "x");
  if (!var)
  {
    return EPERM;
  }
  ec->x = jwk_key_base64_to_datum(var);

  var = jwk_parameter(jwk, "x");
  if (!var)
  {
    return EPERM;
  }
  ec->y = jwk_key_base64_to_datum(var);

  return 0;
}

static char *jwk_key_ec_get(jwk_key_ec_t *ec)
{
  char *out = NULL;

  gnutls_pubkey_t pubkey = jwk_key_pem_pubkey_new(JWK_KTY_EC, ec);
  if (!pubkey)
  {
    return NULL;
  }

  out = jwk_key_pem_pubkey_get(pubkey);
  jwk_key_pem_pubkey_free(pubkey);

  return out;
}

static int jwk_export_key(jwk_t *jwk)
{
  if (!jwk)
  {
    return EINVAL;
  }

  if (jwk->kty == JWK_KTY_OCT)
  {
    const char *var;

    var = jwk_parameter(jwk, "k");
    if (!var)
    {
      return EPERM;
    }

    jwk->key = jwk_base64_urldecode(var);
    if (jwk->key != NULL)
    {
      jwk->key_len = strlen(jwk->key);
    }
  }
  else if (jwk->kty == JWK_KTY_RSA)
  {
    jwk_key_rsa_t rsa;

    jwk_key_rsa_init(&rsa);

    if (jwk_key_rsa_import(&rsa, jwk) == 0)
    {
      jwk->key = jwk_key_rsa_get(&rsa);
      jwk->key_len = strlen(jwk->key);
    }

    jwk_key_rsa_deinit(&rsa);
  }
  else if (jwk->kty == JWK_KTY_EC)
  {
    jwk_key_ec_t ec;

    jwk_key_ec_init(&ec);

    if (jwk_key_ec_import(&ec, jwk) == 0)
    {
      jwk->key = jwk_key_ec_get(&ec);
      jwk->key_len = strlen(jwk->key);
    }

    jwk_key_ec_deinit(&ec);
  }
  else if (jwk->kty == JWK_KTY_OKP)
  {
    // TODO
    return EPERM;
  }
  else
  {
    return EPERM;
  }

  return 0;
}

static jwk_t *jwk_import_json(json_t *json)
{
  const char *kty = NULL;
  jwk_t *jwk = NULL;

  if (!json_is_object(json))
  {
    return NULL;
  }

  jwk = malloc(sizeof(jwk_t));
  if (!jwk)
  {
    return NULL;
  }
  memset(jwk, 0, sizeof(jwk_t));

  jwk->params = json_copy(json);

  /* MUST: kty parameter */
  kty = jwk_parameter(jwk, "kty");
  if (!kty)
  {
    jwk_free(jwk);
    return NULL;
  }
  jwk->kty = jwk_kty_from(kty);

  jwk_calc_thumbprint(jwk);

  jwk_export_key(jwk);

  return jwk;
}

jwk_t *jwk_import_string(const char *input, const size_t len)
{
  json_t *json = NULL;
  jwk_t *jwk = NULL;

  if (!input)
  {
    return NULL;
  }

  if (len == 0)
  {
    json = json_loads(input, 0, NULL);
  }
  else
  {
    json = json_loadb(input, len, 0, NULL);
  }
  if (!json)
  {
    return NULL;
  }

  jwk = jwk_import_json(json);

  json_delete(json);

  return jwk;
}

jwk_t *jwk_import_file(const char *file)
{
  json_t *json = NULL;
  jwk_t *jwk = NULL;

  if (!file)
  {
    return NULL;
  }

  json = json_load_file(file, 0, NULL);
  if (!json)
  {
    return NULL;
  }

  jwk = jwk_import_json(json);

  json_delete(json);

  return jwk;
}

void jwk_free(jwk_t *jwk)
{
  if (!jwk)
  {
    return;
  }

  if (jwk->key)
  {
    free(jwk->key);
  }

  if (jwk->params)
  {
    json_delete(jwk->params);
  }

  if (jwk->thumbprint)
  {
    free(jwk->thumbprint);
  }

  free(jwk);
}

char *jwk_dump(const jwk_t *jwk)
{
  if (!jwk)
  {
    return NULL;
  }
  return json_dumps(jwk->params, JSON_COMPACT);
}

const char *jwk_parameter(const jwk_t *jwk, const char *key)
{
  if (!jwk || !jwk->params || !key)
  {
    return NULL;
  }
  return json_string_value(json_object_get(jwk->params, key));
}

const char *jwk_thumbprint(const jwk_t *jwk)
{
  if (!jwk || !jwk->thumbprint)
  {
    return NULL;
  }
  return jwk->thumbprint;
}

const char *jwk_key(const jwk_t *jwk, size_t *length)
{
  if (!jwk || !jwk->key)
  {
    if (length)
    {
      *length = 0;
    }
    return NULL;
  }

  if (length)
  {
    *length = jwk->key_len;
  }

  return jwk->key;
}

/* jwk set */

struct jwks
{
  json_t *indexes;
  json_t *keys;
  json_t *params;
  json_t *thumbprints;
};

static json_int_t jwks_get_index_by(const jwks_t *jwks, const char *id)
{
  json_t *value = NULL;

  if (!jwks || !id)
  {
    return -1;
  }

  value = json_object_get(jwks->indexes, id);
  if (!json_is_integer(value))
  {
    return -1;
  }

  return json_integer_value(value);
}

static jwks_t *jwks_import_json(const json_t *json)
{
  json_t *keys = NULL, *value = NULL;
  jwks_t *jwks = NULL;
  size_t index;

  if (!json)
  {
    return NULL;
  }

  jwks = jwks_new();
  if (!jwks)
  {
    return NULL;
  }

  keys = json_object_get(json, "keys");
  if (!json_is_array(keys))
  {
    return NULL;
  }

  json_array_foreach(keys, index, value)
  {
    json_t *kty = NULL;
    jwk_t jwk = {0};

    if (!json_is_object(value))
    {
      continue;
    }

    /* MUST: kty parameter */
    kty = json_object_get(value, "kty");
    if (!json_is_string(kty))
    {
      continue;
    }

    jwk.kty = jwk_kty_from(json_string_value(kty));
    jwk.params = value;
    jwk_calc_thumbprint(&jwk);
    jwk_export_key(&jwk);

    jwks_append(jwks, &jwk);

    if (jwk.key)
    {
      free(jwk.key);
    }
    if (jwk.thumbprint)
    {
      free(jwk.thumbprint);
    }
  }

  return jwks;
}

jwks_t *jwks_import_string(const char *input, const size_t len)
{
  json_t *json = NULL;
  jwks_t *jwks = NULL;

  if (!input)
  {
    return NULL;
  }

  if (len == 0)
  {
    json = json_loads(input, 0, NULL);
  }
  else
  {
    json = json_loadb(input, len, 0, NULL);
  }
  if (!json)
  {
    return NULL;
  }

  jwks = jwks_import_json(json);

  json_delete(json);

  return jwks;
}

jwks_t *jwks_import_file(const char *file)
{
  json_t *json = NULL;
  jwks_t *jwks = NULL;

  if (!file)
  {
    return NULL;
  }

  json = json_load_file(file, 0, NULL);
  if (!json)
  {
    return NULL;
  }

  jwks = jwks_import_json(json);

  json_delete(json);

  return jwks;
}

jwks_t *jwks_new(void)
{
  jwks_t *jwks = NULL;

  jwks = malloc(sizeof(jwks_t));
  if (!jwks)
  {
    return NULL;
  }
  memset(jwks, 0, sizeof(jwks_t));

  jwks->indexes = json_object();
  jwks->params = json_array();
  jwks->keys = json_array();
  jwks->thumbprints = json_array();

  return jwks;
}

void jwks_free(jwks_t *jwks)
{
  if (jwks->indexes)
  {
    json_delete(jwks->indexes);
  }
  if (jwks->params)
  {
    json_delete(jwks->params);
  }
  if (jwks->keys)
  {
    json_delete(jwks->keys);
  }
  if (jwks->thumbprints)
  {
    json_delete(jwks->thumbprints);
  }

  free(jwks);
}

int jwks_append(jwks_t *jwks, const jwk_t *jwk)
{
  json_t *kid = NULL;
  size_t index;

  if (!jwks || !jwk || !json_is_object(jwk->params))
  {
    return EINVAL;
  }

  index = json_array_size(jwks->params);

  json_array_insert_new(jwks->params, index, json_copy(jwk->params));

  kid = json_object_get(jwk->params, "kid");
  if (json_is_string(kid))
  {
    json_object_set_new(jwks->indexes,
                        json_string_value(kid), json_integer(index));
  }

  if (jwk->thumbprint)
  {
    json_object_set_new(jwks->indexes, jwk->thumbprint, json_integer(index));

    json_array_insert_new(jwks->thumbprints,
                          index, json_string(jwk->thumbprint));
  }
  else
  {
    json_array_insert_new(jwks->thumbprints, index, json_null());
  }

  if (jwk->key)
  {
    json_array_insert_new(jwks->keys,
                          index, json_stringn_nocheck(jwk->key, jwk->key_len));
  }
  else
  {
    json_array_insert_new(jwks->keys, index, json_null());
  }

  return 0;
}

size_t jwks_size(const jwks_t *jwks)
{
  if (!jwks)
  {
    return 0;
  }
  return json_array_size(jwks->params);
}

char *jwks_dump(const jwks_t *jwks)
{
  char *str;
  json_t *keys = NULL, *value = NULL, *var = NULL;
  size_t index;

  keys = json_array();

  json_array_foreach(jwks->params, index, value)
  {
    json_array_append_new(keys, json_copy(value));
  }

  var = json_object();
  json_object_set_new(var, "keys", keys);

  str = json_dumps(var, JSON_COMPACT);

  json_delete(var);

  return str;
}

jwk_t *jwks_fetch(const jwks_t *jwks, const size_t index)
{
  if (!jwks || !jwks->params)
  {
    return NULL;
  }
  return jwk_import_json(json_array_get(jwks->params, index));
}

jwk_t *jwks_fetch_by(const jwks_t *jwks, const char *id)
{
  if (!id)
  {
    return NULL;
  }
  return jwks_fetch(jwks, jwks_get_index_by(jwks, id));
}

const char *jwks_parameter(const jwks_t *jwks,
                           const size_t index, const char *key)
{
  if (!jwks || !jwks->params || !key)
  {
    return NULL;
  }
  return json_string_value(
      json_object_get(json_array_get(jwks->params, index), key));
}

const char *jwks_parameter_by(const jwks_t *jwks,
                              const char *id, const char *key)
{
  if (!id)
  {
    return NULL;
  }
  return jwks_parameter(jwks, jwks_get_index_by(jwks, id), key);
}

const char *jwks_thumbprint(const jwks_t *jwks, const size_t index)
{
  if (!jwks || !jwks->thumbprints)
  {
    return NULL;
  }
  return json_string_value(json_array_get(jwks->thumbprints, index));
}

const char *jwks_thumbprint_by(const jwks_t *jwks, const char *id)
{
  if (!id)
  {
    return NULL;
  }
  return jwks_thumbprint(jwks, jwks_get_index_by(jwks, id));
}

const char *jwks_key(const jwks_t *jwks, const size_t index, size_t *key_len)
{
  json_t *var;

  if (!jwks || !jwks->keys)
  {
    return NULL;
  }

  var = json_array_get(jwks->keys, index);
  if (key_len)
  {
    *key_len = json_string_length(var);
  }

  return json_string_value(var);
}

const char *jwks_key_by(const jwks_t *jwks, const char *id, size_t *key_len)
{
  if (!id)
  {
    return NULL;
  }
  return jwks_key(jwks, jwks_get_index_by(jwks, id), key_len);
}

void *jwks_iter(const jwks_t *jwks)
{
  if (!jwks)
  {
    return NULL;
  }
  return json_object_iter(jwks->indexes);
}

void *jwks_iter_next(const jwks_t *jwks, void *iter)
{
  if (!jwks || !iter)
  {
    return NULL;
  }
  return json_object_iter_next(jwks->indexes, iter);
}

const char *jwks_iter_id(void *iter)
{
  if (!iter)
  {
    return NULL;
  }
  return json_object_iter_key(iter);
}

void *jwks_iter_by(const char *id)
{
  if (!id)
  {
    return NULL;
  }
  return json_object_key_to_iter(id);
}

int ssl_global_init()
{
  return gnutls_global_init();
}

void ssl_global_deinit()
{
  return gnutls_global_deinit();
}