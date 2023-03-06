#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include "jwk.h"

/* jwk key type */

typedef enum {
  JWK_KTY_NONE = 0,
  JWK_KTY_OCT,
  JWK_KTY_RSA,
  JWK_KTY_EC,
  JWK_KTY_OKP
} jwk_kty_t;

static const char *jwk_kty_to(jwk_kty_t kty)
{
  switch (kty) {
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
  if (strcmp("oct", kty) == 0) {
    return JWK_KTY_OCT;
  } else if (strcmp("RSA", kty) == 0) {
    return JWK_KTY_RSA;
  } else if (strcmp("EC", kty) == 0) {
    return JWK_KTY_EC;
  } else if (strcmp("OKP", kty) == 0) {
    return JWK_KTY_OKP;
  }
  return JWK_KTY_NONE;
}

/* base64 encode/decode */

static char *jwk_base64_urlencode(const char *input, size_t length)
{
  BIO *b64, *bio;
  BUF_MEM *mem;
  char *data;
  int i, n, t;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bio);
  BIO_write(b64, input, length);
  BIO_flush(b64);

  BIO_get_mem_ptr(b64, &mem);
  data = strndup(mem->data, mem->length);
  if (!data) {
    return NULL;
  }

  BIO_free_all(b64);

  // urlencode
  n = strlen(data);

  for (i = t = 0; i < n; i++) {
    switch (data[i]) {
      case '+':
        data[t++] = '-';
        break;
      case '/':
        data[t++] = '_';
        break;
      case '=':
        break;
      default:
        data[t++] = data[i];
    }
  }

  data[t] = '\0';

  return data;
}

static char *jwk_base64_urldecode(const char *input, size_t *length)
{
  BIO *b64, *bio;
  char *data, *out;
  int i, n;

  // urlencode
  n = strlen(input);
  data = alloca(n + 4);
  if (!data) {
    return NULL;
  }
  for (i = 0; i < n; i++) {
    switch (input[i]) {
      case '-':
        data[i] = '+';
        break;
      case '_':
        data[i] = '/';
        break;
      default:
        data[i] = input[i];
    }
  }
  n = 4 - (i % 4);
  if (n < 4) {
    while (n--) {
      data[i++] = '=';
    }
  }
  data[i] = '\0';

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(data, -1);

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bio);
  BIO_flush(b64);

  n = (i / 4 * 3) + 1;

  out = calloc(n, sizeof(char));
  if (!out) {
    BIO_free_all(b64);
    return NULL;
  }

  *length = BIO_read(b64, out, n);

  BIO_free_all(b64);

  return out;
}

/* jwk */

struct jwk {
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

  if (!jwk) {
    return EINVAL;
  }

  members = json_object();

  if (jwk->kty == JWK_KTY_OCT) {
    count = 2;
    var = jwk_parameter(jwk, "k");
    if (var) {
      json_object_set_new(members, "k", json_string(var));
    }
    json_object_set_new(members, "kty", json_string(jwk_kty_to(jwk->kty)));
  } else if (jwk->kty == JWK_KTY_RSA) {
    count = 3;
    var = jwk_parameter(jwk, "e");
    if (var) {
      json_object_set_new(members, "e", json_string(var));
    }
    json_object_set_new(members, "kty", json_string(jwk_kty_to(jwk->kty)));
    var = jwk_parameter(jwk, "n");
    if (var) {
      json_object_set_new(members, "n", json_string(var));
    }
  } else if (jwk->kty == JWK_KTY_EC) {
    count = 4;
    var = jwk_parameter(jwk, "crv");
    if (var) {
      json_object_set_new(members, "crv", json_string(var));
    }
    json_object_set_new(members, "kty", json_string(jwk_kty_to(jwk->kty)));
    var = jwk_parameter(jwk, "x");
    if (var) {
      json_object_set_new(members, "x", json_string(var));
    }
    var = jwk_parameter(jwk, "y");
    if (var) {
      json_object_set_new(members, "y", json_string(var));
    }
  } else if (jwk->kty == JWK_KTY_OKP) {
    count = 3;
    var = jwk_parameter(jwk, "crv");
    if (var) {
      json_object_set_new(members, "crv", json_string(var));
    }
    json_object_set_new(members, "kty", json_string(jwk_kty_to(jwk->kty)));
    var = jwk_parameter(jwk, "x");
    if (var) {
      json_object_set_new(members, "x", json_string(var));
    }
  } else {
    count = 0;
  }

  if (count == 0 || json_object_size(members) != count) {
    json_delete(members);
    return EPERM;
  }

  str = json_dumps(members, JSON_COMPACT);

  SHA256((unsigned char *)str, strlen(str), digest);

  free(str);

  json_delete(members);

  jwk->thumbprint = jwk_base64_urlencode((char *)digest, SHA256_DIGEST_LENGTH);

  return 0;
}

static BIGNUM *jwk_key_base64_to_bn(const char *data)
{
  BIGNUM *bn = NULL;
  char *str;
  size_t n;

  if (!data) {
    return NULL;
  }

  str = jwk_base64_urldecode(data, &n);
  if (!str) {
    return NULL;
  }

  bn = BN_bin2bn((unsigned char *) str, n, NULL);
  free(str);

  return bn;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static BIO *jwk_key_pem_pubkey_new(EVP_PKEY_CTX *context, OSSL_PARAM *param)
{
  BIO *bio = NULL;
  EVP_PKEY *pkey = NULL;

  if (EVP_PKEY_fromdata(context, &pkey, EVP_PKEY_PUBLIC_KEY, param) <= 0
      || !pkey) {
    if (pkey) {
      EVP_PKEY_free(pkey);
    }
    return NULL;
  }

  bio = BIO_new(BIO_s_mem());
  if (!bio) {
    EVP_PKEY_free(pkey);
    return NULL;
  }

  PEM_write_bio_PUBKEY(bio, pkey);

  EVP_PKEY_free(pkey);

  return bio;
}
#endif

static void jwk_key_pem_pubkey_free(BIO *bio)
{
  if (bio) {
    BIO_free(bio);
  }
}

static char *jwk_key_pem_pubkey_get(BIO *bio)
{
  BUF_MEM *mem = NULL;
  char *pem = NULL;

  BIO_get_mem_ptr(bio, &mem);
  if (!mem) {
    return NULL;
  }

  pem = strndup(mem->data, mem->length);

  return pem;
}

typedef struct {
  BIGNUM *n;
  BIGNUM *e;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_PKEY_CTX *context;
  OSSL_PARAM *param;
#else
  RSA *context;
#endif
} jwk_key_rsa_t;

static void jwk_key_rsa_init(jwk_key_rsa_t *rsa)
{
  rsa->n = NULL;
  rsa->e = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  rsa->context = NULL;
  rsa->param = NULL;
#else
  rsa->context =NULL;
#endif
}

static void jwk_key_rsa_deinit(jwk_key_rsa_t *rsa)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if (rsa->param) {
    OSSL_PARAM_free(rsa->param);
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

static int jwk_key_rsa_import(jwk_key_rsa_t *rsa, jwk_t *jwk)
{
  const char *var = NULL;

  if (!rsa || !jwk) {
    return EINVAL;
  }

  if (jwk->kty != JWK_KTY_RSA) {
    return EPERM;
  }

  var = jwk_parameter(jwk, "n");
  if (!var) {
    return EPERM;
  }
  rsa->n = jwk_key_base64_to_bn(var);

  var = jwk_parameter(jwk, "e");
  if (!var) {
    return EPERM;
  }
  rsa->e = jwk_key_base64_to_bn(var);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  rsa->context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!rsa->context) {
    return ENOMEM;
  }
  if (EVP_PKEY_fromdata_init(rsa->context) <= 0) {
    return EPERM;
  }
#else
  rsa->context = RSA_new();
  if (!rsa->context) {
    return ENOMEM;
  }
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  {
    OSSL_PARAM_BLD *param_bld = NULL;

    param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
      return ENOMEM;
    }

    if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, rsa->n)) {
      OSSL_PARAM_BLD_free(param_bld);
      return EPERM;
    }
    if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, rsa->e)) {
      OSSL_PARAM_BLD_free(param_bld);
      return EPERM;
    }

    rsa->param = OSSL_PARAM_BLD_to_param(param_bld);
    if (!rsa->param) {
      OSSL_PARAM_BLD_free(param_bld);
      return ENOMEM;
    }

    OSSL_PARAM_BLD_free(param_bld);
  }
#else
  if (!RSA_set0_key(rsa->context, rsa->n, rsa->e, NULL)) {
    return EPERM;
  }

  rsa->n = NULL;
  rsa->e = NULL;
#endif

  return 0;
}

static char *jwk_key_rsa_get(jwk_key_rsa_t *rsa)
{
  BIO *bio = NULL;
  char *out = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  bio = jwk_key_pem_pubkey_new(rsa->context, rsa->param);
  if (!bio) {
    return NULL;
  }
#else
  bio = BIO_new(BIO_s_mem());
  if (!bio) {
    return NULL;
  }

  PEM_write_bio_RSA_PUBKEY(bio, rsa->context);
#endif

  out = jwk_key_pem_pubkey_get(bio);

  jwk_key_pem_pubkey_free(bio);

  return out;
}

typedef struct {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_PKEY_CTX *context;
  OSSL_PARAM *param;
#else
  EC_KEY *context;
#endif
} jwk_key_ec_t;

static void jwk_key_ec_init(jwk_key_ec_t *ec)
{
  ec->context = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  ec->param = NULL;
#endif
}

static void jwk_key_ec_deinit(jwk_key_ec_t *ec)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if (ec->param) {
    OSSL_PARAM_free(ec->param);
  }
  if (ec->context) {
    EVP_PKEY_CTX_free(ec->context);
  }
#else
  if (ec->context) {
    EC_KEY_free(ec->context);
  }
#endif
}

static int jwk_key_ec_import(jwk_key_ec_t *ec, jwk_t *jwk)
{
  const char *crv, *var;
  char *x = NULL, *y = NULL, *pub = NULL;
  size_t x_size, y_size, pub_size;

  if (!ec || !jwk) {
    return EINVAL;
  }

  if (jwk->kty != JWK_KTY_EC) {
    return EPERM;
  }

  crv = jwk_parameter(jwk, "crv");
  if (!crv) {
    return EPERM;
  }

  var = jwk_parameter(jwk, "x");
  if (!var) {
    return EPERM;
  }
  x = jwk_base64_urldecode(var, &x_size);
  if (!x) {
    return ENOMEM;
  }

  var = jwk_parameter(jwk, "y");
  if (!var) {
    free(x);
    return EPERM;
  }
  y = jwk_base64_urldecode(var, &y_size);
  if (!y) {
    free(x);
    return ENOMEM;
  }

  pub_size = 1 + x_size + y_size;
  pub = calloc(pub_size, sizeof(char));
  if (!pub) {
    return ENOMEM;
  }

  pub[0] = POINT_CONVERSION_UNCOMPRESSED;
  memcpy(pub + 1, x, x_size);
  memcpy(pub + 1 + x_size, y ,y_size);

  free(x);
  free(y);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  ec->context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (!ec->context) {
    free(pub);
    return ENOMEM;
  }

  if (EVP_PKEY_fromdata_init(ec->context) <= 0) {
    free(pub);
    return EPERM;
  }

  {
    OSSL_PARAM_BLD *param_bld = NULL;

    param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
      free(pub);
      return ENOMEM;
    }

    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                         crv, 0)) {
      free(pub);
      OSSL_PARAM_BLD_free(param_bld);
      return EPERM;
    }

    if (!OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                          pub, pub_size)) {
      free(pub);
      OSSL_PARAM_BLD_free(param_bld);
      return EPERM;
    }

    ec->param = OSSL_PARAM_BLD_to_param(param_bld);
    if (!ec->param) {
      free(pub);
      OSSL_PARAM_BLD_free(param_bld);
      return ENOMEM;
    }

    OSSL_PARAM_BLD_free(param_bld);
  }
#else
  {
    int nid;
    const unsigned char *pub_in = (unsigned char *)pub;

    if (strcmp("P-256", crv) == 0) {
      nid = NID_X9_62_prime256v1;
    } else if (strcmp("P-384", crv) == 0) {
      nid = NID_secp384r1;
    } else if (strcmp("P-521", crv) == 0) {
      nid = NID_secp521r1;
    } else {
      free(pub);
      return EPERM;
    }

    ec->context = EC_KEY_new_by_curve_name(nid);
    if (!ec->context) {
      free(pub);
      return ENOMEM;
    }

    if (!o2i_ECPublicKey(&ec->context, &pub_in, pub_size)) {
      free(pub);
      return EPERM;
    }
  }
#endif

  free(pub);

  return 0;
}

static char *jwk_key_ec_get(jwk_key_ec_t *ec)
{
  BIO *bio = NULL;
  char *out = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  bio = jwk_key_pem_pubkey_new(ec->context, ec->param);
  if (!bio) {
    return NULL;
  }
#else
  bio = BIO_new(BIO_s_mem());
  if (!bio) {
    return NULL;
  }
  PEM_write_bio_EC_PUBKEY(bio, ec->context);
#endif

  out = jwk_key_pem_pubkey_get(bio);

  jwk_key_pem_pubkey_free(bio);

  return out;
}

static int jwk_export_key(jwk_t *jwk)
{
  if (!jwk) {
    return EINVAL;
  }

  if (jwk->kty == JWK_KTY_OCT) {
    const char *var;

    var = jwk_parameter(jwk, "k");
    if (!var) {
      return EPERM;
    }

    jwk->key = jwk_base64_urldecode(var, &jwk->key_len);
  } else if (jwk->kty == JWK_KTY_RSA) {
    jwk_key_rsa_t rsa;

    jwk_key_rsa_init(&rsa);

    if (jwk_key_rsa_import(&rsa, jwk) == 0) {
      jwk->key = jwk_key_rsa_get(&rsa);
      jwk->key_len = strlen(jwk->key);
    }

    jwk_key_rsa_deinit(&rsa);
  } else if (jwk->kty == JWK_KTY_EC) {
    jwk_key_ec_t ec;

    jwk_key_ec_init(&ec);

    if (jwk_key_ec_import(&ec, jwk) == 0) {
      jwk->key = jwk_key_ec_get(&ec);
      jwk->key_len = strlen(jwk->key);
    }

    jwk_key_ec_deinit(&ec);
  } else if (jwk->kty == JWK_KTY_OKP) {
    // TODO
    return EPERM;
  } else {
    return EPERM;
  }

  return 0;
}

static jwk_t *jwk_import_json(json_t *json)
{
  const char *kty = NULL;
  jwk_t *jwk = NULL;

  if (!json_is_object(json)) {
    return NULL;
  }

  jwk = malloc(sizeof(jwk_t));
  if (!jwk) {
    return NULL;
  }
  memset(jwk, 0, sizeof(jwk_t));

  jwk->params = json_copy(json);

  /* MUST: kty parameter */
  kty = jwk_parameter(jwk, "kty");
  if (!kty) {
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

  if (!input) {
    return NULL;
  }

  if (len == 0) {
    json = json_loads(input, 0, NULL);
  } else {
    json = json_loadb(input, len, 0, NULL);
  }
  if (!json) {
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

  if (!file) {
    return NULL;
  }

  json = json_load_file(file, 0, NULL);
  if (!json) {
    return NULL;
  }

  jwk = jwk_import_json(json);

  json_delete(json);

  return jwk;
}

void jwk_free(jwk_t *jwk)
{
  if (!jwk) {
    return;
  }

  if (jwk->key) {
    free(jwk->key);
  }

  if (jwk->params) {
    json_delete(jwk->params);
  }

  if (jwk->thumbprint) {
    free(jwk->thumbprint);
  }

  free(jwk);
}

char *jwk_dump(const jwk_t *jwk)
{
  if (!jwk) {
    return NULL;
  }
  return json_dumps(jwk->params, JSON_COMPACT);
}

const char *jwk_parameter(const jwk_t *jwk, const char *key)
{
  if (!jwk || !jwk->params || !key) {
    return NULL;
  }
  return json_string_value(json_object_get(jwk->params, key));
}

const char *jwk_thumbprint(const jwk_t *jwk)
{
  if (!jwk || !jwk->thumbprint) {
    return NULL;
  }
  return jwk->thumbprint;
}

const char *jwk_key(const jwk_t *jwk, size_t *length)
{
  if (!jwk || !jwk->key) {
    if (length) {
      *length = 0;
    }
    return NULL;
  }

  if (length) {
    *length = jwk->key_len;
  }

  return jwk->key;
}

/* jwk set */

struct jwks {
  json_t *indexes;
  json_t *keys;
  json_t *params;
  json_t *thumbprints;
};

static json_int_t jwks_get_index_by(const jwks_t *jwks, const char *id)
{
  json_t *value = NULL;

  if (!jwks || !id) {
    return -1;
  }

  value = json_object_get(jwks->indexes, id);
  if (!json_is_integer(value)) {
    return -1;
  }

  return json_integer_value(value);
}

static jwks_t *jwks_import_json(const json_t *json)
{
  json_t *keys = NULL, *value = NULL;
  jwks_t *jwks = NULL;
  size_t index;

  if (!json) {
    return NULL;
  }

  jwks = jwks_new();
  if (!jwks) {
    return NULL;
  }

  keys = json_object_get(json, "keys");
  if (!json_is_array(keys)) {
    return NULL;
  }

  json_array_foreach(keys, index, value) {
    json_t *kty = NULL;
    jwk_t jwk = {0};

    if (!json_is_object(value)) {
      continue;
    }

    /* MUST: kty parameter */
    kty = json_object_get(value, "kty");
    if (!json_is_string(kty)) {
      continue;
    }

    jwk.kty = jwk_kty_from(json_string_value(kty));
    jwk.params = value;
    jwk_calc_thumbprint(&jwk);
    jwk_export_key(&jwk);

    jwks_append(jwks, &jwk);

    if (jwk.key) {
      free(jwk.key);
    }
    if (jwk.thumbprint) {
      free(jwk.thumbprint);
    }
  }

  return jwks;
}

jwks_t *jwks_import_string(const char *input, const size_t len)
{
  json_t *json = NULL;
  jwks_t *jwks = NULL;

  if (!input) {
    return NULL;
  }

  if (len == 0) {
    json = json_loads(input, 0, NULL);
  } else {
    json = json_loadb(input, len, 0, NULL);
  }
  if (!json) {
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

  if (!file) {
    return NULL;
  }

  json = json_load_file(file, 0, NULL);
  if (!json) {
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
  if (!jwks) {
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
  if (jwks->indexes) {
    json_delete(jwks->indexes);
  }
  if (jwks->params) {
    json_delete(jwks->params);
  }
  if (jwks->keys) {
    json_delete(jwks->keys);
  }
  if (jwks->thumbprints) {
    json_delete(jwks->thumbprints);
  }

  free(jwks);
}

int jwks_append(jwks_t *jwks, const jwk_t *jwk)
{
  json_t *kid = NULL;
  size_t index;

  if (!jwks || !jwk || !json_is_object(jwk->params)) {
    return EINVAL;
  }

  index = json_array_size(jwks->params);

  json_array_insert_new(jwks->params, index, json_copy(jwk->params));

  kid = json_object_get(jwk->params, "kid");
  if (json_is_string(kid)) {
    json_object_set_new(jwks->indexes,
                        json_string_value(kid), json_integer(index));
  }

  if (jwk->thumbprint) {
    json_object_set_new(jwks->indexes, jwk->thumbprint, json_integer(index));

    json_array_insert_new(jwks->thumbprints,
                          index, json_string(jwk->thumbprint));
  } else {
    json_array_insert_new(jwks->thumbprints, index, json_null());
  }

  if (jwk->key) {
    json_array_insert_new(jwks->keys,
                          index, json_stringn_nocheck(jwk->key, jwk->key_len));
  } else {
    json_array_insert_new(jwks->keys, index, json_null());
  }

  return 0;
}

size_t jwks_size(const jwks_t *jwks)
{
  if (!jwks) {
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

  json_array_foreach(jwks->params, index, value) {
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
  if (!jwks || !jwks->params) {
    return NULL;
  }
  return jwk_import_json(json_array_get(jwks->params, index));
}

jwk_t *jwks_fetch_by(const jwks_t *jwks, const char *id)
{
  if (!id) {
    return NULL;
  }
  return jwks_fetch(jwks, jwks_get_index_by(jwks, id));
}

const char *jwks_parameter(const jwks_t *jwks,
                           const size_t index, const char *key)
{
  if (!jwks || !jwks->params || !key) {
    return NULL;
  }
  return json_string_value(
    json_object_get(json_array_get(jwks->params, index), key));
}

const char *jwks_parameter_by(const jwks_t *jwks,
                              const char *id, const char *key)
{
  if (!id) {
    return NULL;
  }
  return jwks_parameter(jwks, jwks_get_index_by(jwks, id), key);
}

const char *jwks_thumbprint(const jwks_t *jwks, const size_t index)
{
  if (!jwks || !jwks->thumbprints) {
    return NULL;
  }
  return json_string_value(json_array_get(jwks->thumbprints, index));
}

const char *jwks_thumbprint_by(const jwks_t *jwks, const char *id)
{
  if (!id) {
    return NULL;
  }
  return jwks_thumbprint(jwks, jwks_get_index_by(jwks, id));
}

const char *jwks_key(const jwks_t *jwks, const size_t index, size_t *key_len)
{
  json_t *var;

  if (!jwks || !jwks->keys) {
    return NULL;
  }

  var = json_array_get(jwks->keys, index);
  if (key_len) {
    *key_len = json_string_length(var);
  }

  return json_string_value(var);
}

const char *jwks_key_by(const jwks_t *jwks, const char *id, size_t *key_len)
{
  if (!id) {
    return NULL;
  }
  return jwks_key(jwks, jwks_get_index_by(jwks, id), key_len);
}

void *jwks_iter(const jwks_t *jwks)
{
  if (!jwks) {
    return NULL;
  }
  return json_object_iter(jwks->indexes);
}

void *jwks_iter_next(const jwks_t *jwks, void *iter)
{
  if (!jwks || !iter) {
    return NULL;
  }
  return json_object_iter_next(jwks->indexes, iter);
}

const char *jwks_iter_id(void *iter)
{
  if (!iter) {
    return NULL;
  }
  return json_object_iter_key(iter);
}

void *jwks_iter_by(const char *id)
{
  if (!id) {
    return NULL;
  }
  return json_object_key_to_iter(id);
}
