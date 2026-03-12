#ifndef NGX_AUTH_JWT_OPERATOR_H
#define NGX_AUTH_JWT_OPERATOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include <ngx_core.h>

#define NGX_AUTH_JWT_OPERATOR_EQ "eq"
#define NGX_AUTH_JWT_OPERATOR_NE "ne"
#define NGX_AUTH_JWT_OPERATOR_GT "gt"
#define NGX_AUTH_JWT_OPERATOR_GE "ge"
#define NGX_AUTH_JWT_OPERATOR_LT "lt"
#define NGX_AUTH_JWT_OPERATOR_LE "le"
#define NGX_AUTH_JWT_OPERATOR_INTERSECT "intersect"
#define NGX_AUTH_JWT_OPERATOR_NINTERSECT "nintersect"
#define NGX_AUTH_JWT_OPERATOR_IN "in"
#define NGX_AUTH_JWT_OPERATOR_NIN "nin"

ngx_int_t ngx_auth_jwt_operator_validate(char *op, json_t *input, json_t *requirement);

#ifdef __cplusplus
}
#endif

#endif /* NGX_AUTH_JWT_OPERATOR_H */
