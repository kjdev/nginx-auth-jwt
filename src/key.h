#ifndef _KEY_H_
#define _KEY_H_

#include <jansson.h>

int key_load(json_t **object, const json_t *json);
int key_load_file(json_t **object, const char *path);
int key_load_string(json_t **object, const char *input);

int key_jwks_load(json_t **object, const json_t *json);
int key_jwks_load_file(json_t **object, const char *path);
int key_jwks_load_string(json_t **object, const char *input);

const char *key_get(const json_t *object, const char *kid);

#endif /* _KEY_H_ */
