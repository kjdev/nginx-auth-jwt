#ifndef JWK_H
#define JWK_H

#ifdef __cplusplus
extern "C" {
#endif

/* jwk */

typedef struct jwk jwk_t;

jwk_t *jwk_import_string(const char *input, const size_t len);
#define jwk_import(input) jwk_import_string(input, 0)
jwk_t *jwk_import_file(const char *file);
void jwk_free(jwk_t *jwk);
char *jwk_dump(const jwk_t *jwk);

const char *jwk_parameter(const jwk_t *jwk, const char *key);
const char *jwk_thumbprint(const jwk_t *jwk);
const char *jwk_key(const jwk_t *jwk, size_t *length);

/* jwk set */

typedef struct jwks jwks_t;

jwks_t *jwks_import_string(const char *input, const size_t len);
#define jwks_import(input) jwks_import_string(input, 0)
jwks_t *jwks_import_file(const char *file);
jwks_t *jwks_new(void);
void jwks_free(jwks_t *jwks);
int jwks_append(jwks_t *jwks, const jwk_t *jwk);
size_t jwks_size(const jwks_t *jwks);
char *jwks_dump(const jwks_t *jwks);

jwk_t *jwks_fetch(const jwks_t *jwks, const size_t index);
const char *jwks_parameter(const jwks_t *jwks, const size_t index, const char *key);
const char *jwks_thumbprint(const jwks_t *jwks, const size_t index);
const char *jwks_key(const jwks_t *jwks, const size_t index, size_t *key_len);

#define jwks_foreach(jwks, index) \
  for (index = 0; index < jwks_size(jwks);  index++)

/* @id is kid or thumbprint */
jwk_t *jwks_fetch_by(const jwks_t *jwks, const char *id);
const char *jwks_parameter_by(const jwks_t *jwks, const char *id, const char *key);
const char *jwks_thumbprint_by(const jwks_t *jwks, const char *id);
const char *jwks_key_by(const jwks_t *jwks, const char *id, size_t *key_len);
char *jwks_dump_by(const jwks_t *jwks, const char *id);

void *jwks_iter(const jwks_t *jwks);
void *jwks_iter_next(const jwks_t *jwks, void *iter);
const char *jwks_iter_id(void *iter);
void *jwks_iter_by(const char *id);

#define jwks_foreach_by(jwks, id)                                 \
  for (id = jwks_iter_id(jwks_iter(jwks));                        \
       id;                                                        \
       id = jwks_iter_id(jwks_iter_next(jwks, jwks_iter_by(id))))

#ifdef __cplusplus
}
#endif

#endif /* JWK_H */
