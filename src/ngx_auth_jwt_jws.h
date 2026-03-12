/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */
#ifndef NGX_AUTH_JWT_JWS_H
#define NGX_AUTH_JWT_JWS_H

#include "ngx_auth_jwt_jwks.h"

/*
 * Verify JWT signature against a JWKS keyset
 *
 * Decodes the base64url-encoded signature from the token, finds a matching
 * key in the keyset (by kid and alg/kty compatibility), and verifies the
 * signature using OpenSSL EVP API (RSA/EC/OKP) or HMAC.
 *
 * @param[in] token        JWT token string (header.payload.signature)
 * @param[in] payload_len  Offset of the second dot (end of header.payload)
 * @param[in] keyset       Parsed JWKS keyset
 * @param[in] alg          Algorithm from JWT header ("alg" field)
 * @param[in] kid          Key ID from JWT header ("kid" field, may be NULL)
 *
 * @return 0 if signature is valid, non-zero on failure
 */
int ngx_auth_jwt_jws_verify(const char *token, unsigned int payload_len,
    ngx_auth_jwt_jwks_keyset_t *keyset, const char *alg, const char *kid);

#endif /* NGX_AUTH_JWT_JWS_H */
