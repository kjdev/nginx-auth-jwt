#ifndef NGX_AUTH_JWT_OPERATOR_H
#define NGX_AUTH_JWT_OPERATOR_H

#include <ngx_core.h>
#include "ngx_auth_jwt_json.h"

#define NGX_AUTH_JWT_OPERATOR_EQ "eq"
#define NGX_AUTH_JWT_OPERATOR_NE "ne"
#define NGX_AUTH_JWT_OPERATOR_GT "gt"
#define NGX_AUTH_JWT_OPERATOR_GE "ge"
#define NGX_AUTH_JWT_OPERATOR_LT "lt"
#define NGX_AUTH_JWT_OPERATOR_LE "le"
#define NGX_AUTH_JWT_OPERATOR_ANY "any"
#define NGX_AUTH_JWT_OPERATOR_INTERSECT "intersect"
#define NGX_AUTH_JWT_OPERATOR_NINTERSECT "nintersect"
#define NGX_AUTH_JWT_OPERATOR_IN "in"
#define NGX_AUTH_JWT_OPERATOR_NIN "nin"
#define NGX_AUTH_JWT_OPERATOR_MATCH "match"

#define NGX_AUTH_JWT_OPERATOR_NEGATE_PREFIX "!"

#define NGX_AUTH_JWT_MAX_EXPECTED_SIZE  4096
#define NGX_AUTH_JWT_MAX_REGEX_SIZE     1024

#define NGX_AUTH_JWT_REGEX_MATCH_LIMIT        10000
#define NGX_AUTH_JWT_REGEX_MATCH_LIMIT_DEPTH   5000

/*
 * Returns:
 *   NGX_OK       condition met
 *   NGX_DECLINED condition not met (valid comparison)
 *   NGX_ERROR    internal error (type mismatch, etc.)
 */
ngx_int_t ngx_auth_jwt_operator_validate(char *op,
    ngx_auth_jwt_json_t *input, ngx_auth_jwt_json_t *requirement,
    void *regex, ngx_pool_t *pool, ngx_log_t *log);

#endif /* NGX_AUTH_JWT_OPERATOR_H */
