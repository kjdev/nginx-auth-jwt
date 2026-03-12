#include "ngx_auth_jwt_operator.h"

static ngx_int_t
ngx_auth_jwt_op_eq(json_t *input, json_t *requirement)
{
  return json_equal(input, requirement) == 1 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
ngx_auth_jwt_op_ne(json_t *input, json_t *requirement)
{
  return json_equal(input, requirement) != 1 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
ngx_auth_jwt_op_gt(json_t *input, json_t *requirement)
{
  if (!json_is_integer(requirement)) {
    return NGX_ERROR;
  }

  if (json_is_integer(input)) {
    return json_integer_value(input) > json_integer_value(requirement)
      ? NGX_OK : NGX_ERROR;
  }
  else if (json_is_number(input)) {
    return json_number_value(input) > json_number_value(requirement)
      ? NGX_OK : NGX_ERROR;
  }

  return NGX_ERROR;
}

static ngx_int_t
ngx_auth_jwt_op_ge(json_t *input, json_t *requirement)
{
  if (!json_is_integer(requirement)) {
    return NGX_ERROR;
  }

  if (json_is_integer(input)) {
    return json_integer_value(input) >= json_integer_value(requirement)
      ? NGX_OK : NGX_ERROR;
  }
  else if (json_is_number(input)) {
    return json_number_value(input) >= json_number_value(requirement)
      ? NGX_OK : NGX_ERROR;
  }

  return NGX_ERROR;
}

static ngx_int_t
ngx_auth_jwt_op_lt(json_t *input, json_t *requirement)
{
  if (!json_is_integer(requirement)) {
    return NGX_ERROR;
  }

  if (json_is_integer(input)) {
    return json_integer_value(input) < json_integer_value(requirement)
      ? NGX_OK : NGX_ERROR;
  }
  else if (json_is_number(input)) {
    return json_number_value(input) < json_number_value(requirement)
      ? NGX_OK : NGX_ERROR;
  }

  return NGX_ERROR;
}

static ngx_int_t
ngx_auth_jwt_op_le(json_t *input, json_t *requirement)
{
  if (!json_is_integer(requirement)) {
    return NGX_ERROR;
  }

  if (json_is_integer(input)) {
    return json_integer_value(input) <= json_integer_value(requirement)
      ? NGX_OK : NGX_ERROR;
  }
  else if (json_is_number(input)) {
    return json_number_value(input) <= json_number_value(requirement)
      ? NGX_OK : NGX_ERROR;
  }

  return NGX_ERROR;
}

static ngx_int_t
ngx_auth_jwt_op_intersect(json_t *input, json_t *requirement)
{
  ngx_flag_t invalid = 1;
  json_t *input_val = NULL, *requirement_val = NULL;
  size_t input_index, requirement_index;

  if (!json_is_array(requirement)) {
    return NGX_ERROR;
  }

  if (json_is_array(input)) {
    json_array_foreach(input, input_index, input_val) {
      if (invalid == 0) {
        break;
      }
      json_array_foreach(requirement, requirement_index, requirement_val) {
        if (json_equal(input_val, requirement_val) == 1) {
          invalid = 0;
          break;
        }
      }
    }
  }
  else {
    json_array_foreach(requirement, requirement_index, requirement_val) {
      if (json_equal(input, requirement_val) == 1) {
        invalid = 0;
        break;
      }
    }
  }

  return invalid == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
ngx_auth_jwt_op_nintersect(json_t *input, json_t *requirement)
{
  ngx_flag_t invalid = 0;
  json_t *input_val = NULL, *requirement_val = NULL;
  size_t input_index, requirement_index;

  if (!json_is_array(requirement)) {
    return NGX_ERROR;
  }

  if (json_is_array(input)) {
    json_array_foreach(input, input_index, input_val) {
      if (invalid == 1) {
        break;
      }
      json_array_foreach(requirement, requirement_index, requirement_val) {
        if (json_equal(input_val, requirement_val) == 1) {
          invalid = 1;
          break;
        }
      }
    }
  }
  else {
    json_array_foreach(requirement, requirement_index, requirement_val) {
      if (json_equal(input, requirement_val) == 1) {
        invalid = 1;
        break;
      }
    }
  }

  return invalid == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
ngx_auth_jwt_op_in(json_t *input, json_t *requirement)
{
  ngx_flag_t invalid = 1;

  if (json_is_array(requirement)) {
    json_t *val = NULL;
    size_t index;

    json_array_foreach(requirement, index, val) {
      if (json_equal(input, val) == 1) {
        invalid = 0;
        break;
      }
    }
  }
  else if (json_is_object(requirement)) {
    json_t *val = NULL;
    const char *key;

    json_object_foreach(requirement, key, val) {
      if (json_equal(input, val) == 1) {
        invalid = 0;
        break;
      }
    }
  }
  else {
    return NGX_ERROR;
  }

  return invalid == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
ngx_auth_jwt_op_nin(json_t *input, json_t *requirement)
{
  ngx_flag_t invalid = 0;

  if (json_is_array(requirement)) {
    json_t *val = NULL;
    size_t index;

    json_array_foreach(requirement, index, val) {
      if (json_equal(input, val) == 1) {
        invalid = 1;
        break;
      }
    }
  }
  else if (json_is_object(requirement)) {
    json_t *val = NULL;
    const char *key;

    json_object_foreach(requirement, key, val) {
      if (json_equal(input, val) == 1) {
        invalid = 1;
        break;
      }
    }
  }
  else {
    return NGX_ERROR;
  }

  return invalid == 0 ? NGX_OK : NGX_ERROR;
}

#define OPERATOR_IS(op, data) ngx_strcmp(data, NGX_AUTH_JWT_OPERATOR_ ## op) == 0

ngx_int_t
ngx_auth_jwt_operator_validate(char *op, json_t *input, json_t *requirement)
{
  if (OPERATOR_IS(EQ, op)) {
    return ngx_auth_jwt_op_eq(input, requirement);
  }
  else if (OPERATOR_IS(NE, op)) {
    return ngx_auth_jwt_op_ne(input, requirement);
  }
  else if (OPERATOR_IS(GT, op)) {
    return ngx_auth_jwt_op_gt(input, requirement);
  }
  else if (OPERATOR_IS(GE, op)) {
    return ngx_auth_jwt_op_ge(input, requirement);
  }
  else if (OPERATOR_IS(LT, op)) {
    return ngx_auth_jwt_op_lt(input, requirement);
  }
  else if (OPERATOR_IS(LE, op)) {
    return ngx_auth_jwt_op_le(input, requirement);
  }
  else if (OPERATOR_IS(INTERSECT, op)) {
    return ngx_auth_jwt_op_intersect(input, requirement);
  }
  else if (OPERATOR_IS(NINTERSECT, op)) {
    return ngx_auth_jwt_op_nintersect(input, requirement);
  }
  else if (OPERATOR_IS(IN, op)) {
    return ngx_auth_jwt_op_in(input, requirement);
  }
  else if (OPERATOR_IS(NIN, op)) {
    return ngx_auth_jwt_op_nin(input, requirement);
  }

  return NGX_ERROR;
}
