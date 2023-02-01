
#include <jansson.h>
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif
#include <string.h>

#include "key.h"

#include "jwt/jwt.h"
#include "jwt/jwt-private.h"

int
key_load(json_t **object, const json_t *json)
{
  const char *key = NULL;
  json_t *value = NULL;

  if (!json_is_object(json)) {
    return 1;
  }

  if (*object == NULL) {
    *object = json_object();
  }

  json_object_foreach((json_t *)json, key, value) {
    if (!key || !json_is_string(value)) {
      continue;
    }

    json_object_set_new(*object, key, json_copy(value));
  }

  return 0;
}

int
key_load_file(json_t **object, const char *path)
{
  json_t *json = NULL;
  int rc;

  if (path == NULL) {
    return 1;
  }

  json = json_load_file(path, 0, NULL);
  if (json == NULL) {
    return 1;
  }

  rc = key_load(object, json);

  json_delete(json);

  return rc;
}

int
key_load_string(json_t **object, const char *input)
{
  json_t *json = NULL;
  int rc;

  if (input == NULL) {
    return 1;
  }

  json = json_loads(input, 0, NULL);
  if (json == NULL) {
    return 1;
  }

  rc = key_load(object, json);

  json_delete(json);

  return rc;
}

static unsigned char *
key_base64_decode(const char *encoded, int *len)
{
  BIO *b64, *bio;
  size_t i, n;
  char *data;
  unsigned char *decoded = NULL;

  *len = 0;

  /* Decode based on RFC-4648 URI safe encoding */
  n = strlen(encoded);
  data = alloca(n + 4);
  if (!data) {
    return NULL;
  }
  for (i = 0; i < n; i++) {
    switch (encoded[i]) {
      case '-':
        data[i] = '+';
        break;
      case '_':
        data[i] = '/';
        break;
      default:
        data[i] = encoded[i];
    }
  }
  n = 4 - (i % 4);
  if (n < 4) {
    while (n--)
      data[i++] = '=';
  }
  data[i] = '\0';

  b64 = BIO_new(BIO_f_base64());
  if (b64 == NULL) {
    return NULL;
  }
  bio = BIO_new_mem_buf(data, -1);
  if (bio == NULL) {
    BIO_free(b64);
    return NULL;
  }

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bio);

  n = (i / 4 * 3) + 1;

  decoded = calloc(n, sizeof(unsigned char));
  if (!decoded) {
    BIO_free(bio);
    BIO_free(b64);
    return NULL;
  }

  *len = BIO_read(b64, decoded, n);

  BIO_free(bio);
  BIO_free(b64);

  return decoded;
}

static BIGNUM *
key_base64_to_bn(const char *data)
{
  BIGNUM *bn = NULL;
  unsigned char *decode;
  int len;

  if (data == NULL) {
    return NULL;
  }

  decode = key_base64_decode(data, &len);
  if (decode == NULL) {
    return NULL;
  }

  bn = BN_bin2bn(decode, len, NULL);
  if (bn == NULL) {
    free(decode);
    return NULL;
  }

  free(decode);

  return bn;
}

typedef struct {
  BIGNUM *n;
  BIGNUM *e;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_PKEY_CTX *context;
  OSSL_PARAM_BLD *param_build;
  OSSL_PARAM *param;
#else
  RSA *context;
#endif
} key_rsa_t;

static void
key_rsa_free(key_rsa_t *rsa)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if (rsa->param) {
    OSSL_PARAM_free(rsa->param);
  }
  if (rsa->param_build) {
    OSSL_PARAM_BLD_free(rsa->param_build);
  }
  if (rsa->context) {
    EVP_PKEY_CTX_free(rsa->context);
  }
#else
  if (rsa->context) {
    RSA_free(rsa->context);
  }
#endif
  if (rsa->n) {
    BN_free(rsa->n);
  }
  if (rsa->e) {
    BN_free(rsa->e);
  }
}

static int
key_rsa_set_data(key_rsa_t *rsa, const json_t *key)
{
  json_t *var = NULL;

  if (rsa == NULL || !json_is_object(key)) {
    return 1;
  }

  var = json_object_get(key, "kty");
  if (!json_is_string(var) || strcmp("RSA", json_string_value(var)) != 0) {
    return 1;
  }

  var = json_object_get(key, "n");
  if (!json_is_string(var)) {
    return 1;
  }

  rsa->n = key_base64_to_bn(json_string_value(var));

  var = json_object_get(key, "e");
  if (!json_is_string(var)) {
    return 1;
  }

  rsa->e = key_base64_to_bn(json_string_value(var));

  return 0;
}

static int
key_rsa_set_ctx(key_rsa_t *rsa)
{
  if (rsa == NULL) {
    return 1;
  }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  rsa->context = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
  if (rsa->context == NULL) {
    return 1;
  }
  if (EVP_PKEY_fromdata_init(rsa->context) <= 0) {
    return 1;
  }
#else
  rsa->context = RSA_new();
  if (rsa->context == NULL) {
    return 1;
  }
#endif

  return 0;
}

static int
key_rsa_set_param(key_rsa_t *rsa)
{
  if (rsa == NULL) {
    return 1;
  }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  {
    OSSL_PARAM_BLD *param_bld = NULL;

    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
      return 1;
    }

    if (OSSL_PARAM_BLD_push_BN(param_bld,
                               OSSL_PKEY_PARAM_RSA_N, rsa->n) == 0) {
      OSSL_PARAM_BLD_free(param_bld);
      return 1;
    }
    if (OSSL_PARAM_BLD_push_BN(param_bld,
                               OSSL_PKEY_PARAM_RSA_E, rsa->e) == 0) {
      OSSL_PARAM_BLD_free(param_bld);
      return 1;
    }

    rsa->param = OSSL_PARAM_BLD_to_param(param_bld);
    if (rsa->param == NULL) {
      OSSL_PARAM_BLD_free(param_bld);
      return 1;
    }

    OSSL_PARAM_BLD_free(param_bld);
  }
#else
  if (RSA_set0_key(rsa->context, rsa->n, rsa->e, NULL) == 0) {
    return 1;
  }

  rsa->n = NULL;
  rsa->e = NULL;
#endif

  return 0;
}

static char *
key_rsa_get_pem(key_rsa_t *rsa)
{
  BIO *bio = NULL;
  BUF_MEM *mem = NULL;
  char *pem = NULL;

  bio = BIO_new(BIO_s_mem());
  if (bio == NULL) {
    return NULL;
  }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  {
    EVP_PKEY *pkey = NULL;

    if (EVP_PKEY_fromdata(rsa->context, &pkey,
                          EVP_PKEY_KEYPAIR, rsa->param) <= 0
        || pkey == NULL) {
      if (pkey) {
        EVP_PKEY_free(pkey);
      }
      return NULL;
    }

    PEM_write_bio_PUBKEY(bio, pkey);

    EVP_PKEY_free(pkey);
  }
#else
  PEM_write_bio_RSA_PUBKEY(bio, rsa->context);
#endif

  BIO_get_mem_ptr(bio, &mem);
  if (mem == NULL) {
    BIO_free(bio);
    return NULL;
  }

  pem = calloc(mem->length + 1, sizeof(char));
  if (!pem) {
    BIO_free(bio);
    return NULL;
  }
  BIO_read(bio, pem, mem->length);
  BIO_free(bio);

  return pem;
}

static char *
key_jwks_data_rsa(const json_t *key)
{
  char *pem = NULL;
  key_rsa_t rsa = {NULL};

  if (key_rsa_set_data(&rsa, key) != 0
      || key_rsa_set_ctx(&rsa) != 0
      || key_rsa_set_param(&rsa) != 0) {
    key_rsa_free(&rsa);
    return NULL;
  }

  pem = key_rsa_get_pem(&rsa);

  key_rsa_free(&rsa);

  return pem;
}

static char *
key_jwks_data_oct(const json_t *key)
{
  json_t *k = NULL;
  char *decode;
  int len;

  if (!json_is_object(key)) {
    return NULL;
  }

  k = json_object_get(key, "k");
  if (!json_is_string(k)) {
    return NULL;
  }

  decode = (char *)key_base64_decode(json_string_value(k), &len);
  if (decode == NULL) {
    return NULL;
  }

  decode[len] = '\0';

  return decode;
}

static char *
key_jwks_thumbprint(const char *kty, const json_t *json)
{
  char *var, *thumbprint = NULL;
  unsigned char digest[SHA256_DIGEST_LENGTH + 1];
  int len;

  if (!kty || !json_is_object(json)) {
    return NULL;
  }

  json_t *members;
  members = json_object();

  if (strcmp("RSA", kty) == 0) {
    json_object_set_new(members, "e", json_copy(json_object_get(json, "e")));
    json_object_set_new(members, "kty", json_string(kty));
    json_object_set_new(members, "n", json_copy(json_object_get(json, "n")));
  } else if (strcmp("oct", kty) == 0) {
    json_object_set_new(members, "k", json_copy(json_object_get(json, "k")));
    json_object_set_new(members, "kty", json_string(kty));
  } else if (strcmp("EC", kty) == 0) {
    json_object_set_new(members, "crv",
                        json_copy(json_object_get(json, "crv")));
    json_object_set_new(members, "kty", json_string(kty));
    json_object_set_new(members, "x", json_copy(json_object_get(json, "x")));
    json_object_set_new(members, "y", json_copy(json_object_get(json, "y")));
  } else {
    return NULL;
  }

  var = json_dumps(members, JSON_COMPACT);

  SHA256((unsigned char *)var, strlen(var), digest);

  free(var);

  json_delete(members);

  digest[SHA256_DIGEST_LENGTH] = '\0';

  thumbprint = (char *)jwt_b64_encode((char *)digest, &len);

  return thumbprint;
}

int
key_jwks_load(json_t **object, const json_t *json)
{
  json_t  *keys = NULL, *key = NULL, *kid = NULL, *kty = NULL;
  size_t index;

  if (!json_is_object(json)) {
    return 1;
  }

  keys = json_object_get(json, "keys");
  if (!json_is_array(keys)) {
    return 1;
  }

  if (*object == NULL) {
    *object = json_object();
  }

  json_array_foreach(keys, index, key) {
    const char *type;
    char *data = NULL, *thumbprint = NULL;

    if (!json_is_object(key)) {
      continue;
    }

    kty = json_object_get(key, "kty");
    if (!json_is_string(kty)) {
      continue;
    }
    type = json_string_value(kty);

    if (strcmp("RSA", type) == 0) {
      data = key_jwks_data_rsa(key);
    } else if (strcmp("oct", type) == 0) {
      data = key_jwks_data_oct(key);
    } else {
      continue;
    }

    if (data == NULL) {
      continue;
    }

    kid = json_object_get(key, "kid");
    if (json_is_string(kid)) {
      json_object_set_new(*object, json_string_value(kid), json_string(data));
    }

    thumbprint = key_jwks_thumbprint(type, key);

    if (thumbprint) {
      json_object_set_new(*object, thumbprint, json_string(data));
      free(thumbprint);
    }

    free(data);
 }

  return 0;
}

int
key_jwks_load_file(json_t **object, const char *path)
{
  json_t *json = NULL;
  int rc;

  if (path == NULL) {
    return 1;
  }

  json = json_load_file(path, 0, NULL);
  if (json == NULL) {
    return 1;
  }

  rc = key_jwks_load(object, json);

  json_delete(json);

  return rc;
}

int
key_jwks_load_string(json_t **object, const char *input)
{
  json_t *json = NULL;
  int rc;

  if (input == NULL) {
    return 1;
  }

  json = json_loads(input, 0, NULL);
  if (json == NULL) {
    return 1;
  }

  rc = key_jwks_load(object, json);

  json_delete(json);

  return rc;
}

const char *
key_get(const json_t *object, const char *kid)
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
