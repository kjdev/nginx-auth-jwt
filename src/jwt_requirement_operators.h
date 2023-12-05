#ifndef JWK_REQUIREMENT_OPERATORS_H
#define JWK_REQUIREMENT_OPERATORS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ngx_core.h>
#include "jwt/jwt.h"
#include "jwt/jwt-private.h"

#define NGX_HTTP_AUTH_JWT_REQUIRE_EQUAL_OPERATOR "eq"
#define NGX_HTTP_AUTH_JWT_REQUIRE_NOT_EQUAL_OPERATOR "ne"
#define NGX_HTTP_AUTH_JWT_REQUIRE_GREATER_THAN_OPERATOR "gt"
#define NGX_HTTP_AUTH_JWT_REQUIRE_GREATER_OR_EQUAL_OPERATOR "ge"
#define NGX_HTTP_AUTH_JWT_REQUIRE_LESS_THAN_OPERATOR "lt"
#define NGX_HTTP_AUTH_JWT_REQUIRE_LESS_OR_EQUAL_OPERATOR "le"
#define NGX_HTTP_AUTH_JWT_REQUIRE_INTERSECTION_OPERATOR "intersect"
#define NGX_HTTP_AUTH_JWT_REQUIRE_NOT_INTERSECTION_OPERATOR "nintersect"
#define NGX_HTTP_AUTH_JWT_REQUIRE_IN_OPERATOR "in"
#define NGX_HTTP_AUTH_JWT_REQUIRE_NOT_IN_OPERATOR "nin"

ngx_int_t ngx_http_auth_jwt_validate_requirement_by_operator(char *op, json_t *input, json_t *requirement);

#ifdef __cplusplus
}
#endif

#endif /* JWK_REQUIREMENT_OPERATORS_H */
