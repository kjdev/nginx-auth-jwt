#include "jwt_requirement_operators.h"

static ngx_int_t
jwt_requirement_eq(json_t *input, json_t *requirement)
{
  return json_equal(input, requirement) == 1 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
jwt_requirement_not_eq(json_t *input, json_t *requirement)
{
  return json_equal(input, requirement) != 1 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
jwt_requirement_greater_than(json_t *input, json_t *requirement)
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
jwt_requirement_greater_or_equal(json_t *input, json_t *requirement)
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
jwt_requirement_less_than(json_t *input, json_t *requirement)
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
jwt_requirement_less_or_equal(json_t *input, json_t *requirement)
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
jwt_requirement_intersection(json_t *input, json_t *requirement)
{
  ngx_flag_t invalid = 1;
  json_t *input_val = NULL, *requirement_val = NULL;
  size_t input_index, requirement_index;

  if (!json_is_array(input) || !json_is_array(requirement)) {
    return NGX_ERROR;
  }

  json_array_foreach(input, input_index, input_val) {
    if (invalid == 0) {
      break;
    }
    if (!json_is_string(input_val)) {
      continue;
    }
    json_array_foreach(requirement, requirement_index, requirement_val) {
      if (json_equal(input_val, requirement_val) == 1) {
        invalid = 0;
        break;
      }
    }
  }

  return invalid == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
jwt_requirement_not_intersection(json_t *input, json_t *requirement)
{
  ngx_flag_t invalid = 0;
  json_t *input_val = NULL, *requirement_val = NULL;
  size_t input_index, requirement_index;

  if (!json_is_array(input) || !json_is_array(requirement)) {
    return NGX_ERROR;
  }

  json_array_foreach(input, input_index, input_val) {
    if (invalid == 1) {
      break;
    }
    if (!json_is_string(input_val)) {
      continue;
    }
    json_array_foreach(requirement, requirement_index, requirement_val) {
      if (json_equal(input_val, requirement_val) == 1) {
        invalid = 1;
        break;
      }
    }
  }

  return invalid == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
jwt_requirement_in(json_t *input, json_t *requirement)
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
jwt_requirement_not_in(json_t *input, json_t *requirement)
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

#define OPERATOR_IS(op, data) ngx_strcmp(data, NGX_HTTP_AUTH_JWT_REQUIRE_ ## op ## _OPERATOR) == 0

ngx_int_t
ngx_http_auth_jwt_validate_requirement_by_operator(char *op,
                                                   json_t *input,
                                                   json_t *requirement)
{
  if (OPERATOR_IS(EQUAL, op)) {
    return jwt_requirement_eq(input, requirement);
  }
  else if (OPERATOR_IS(NOT_EQUAL, op)) {
    return jwt_requirement_not_eq(input, requirement);
  }
  else if (OPERATOR_IS(GREATER_THAN, op)) {
    return jwt_requirement_greater_than(input, requirement);
  }
  else if (OPERATOR_IS(GREATER_OR_EQUAL, op)) {
    return jwt_requirement_greater_or_equal(input, requirement);
  }
  else if (OPERATOR_IS(LESS_THAN, op)) {
    return jwt_requirement_less_than(input, requirement);
  }
  else if (OPERATOR_IS(LESS_OR_EQUAL, op)) {
    return jwt_requirement_less_or_equal(input, requirement);
  }
  else if (OPERATOR_IS(INTERSECTION, op)) {
    return jwt_requirement_intersection(input, requirement);
  }
  else if (OPERATOR_IS(NOT_INTERSECTION, op)) {
    return jwt_requirement_not_intersection(input, requirement);
  }
  else if (OPERATOR_IS(IN, op)) {
    return jwt_requirement_in(input, requirement);
  }
  else if (OPERATOR_IS(NOT_IN, op)) {
    return jwt_requirement_not_in(input, requirement);
  }

  return NGX_ERROR;
}
