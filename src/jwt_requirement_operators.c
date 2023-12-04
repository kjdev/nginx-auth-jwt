#include "jwt_requirement_operators.h"
#include <string.h>

ngx_int_t
ngx_http_auth_jwt_validate_requirement_by_operator(char *op,
                                                   json_t *input,
                                                   json_t *requirement)
{
  if (strcmp(op, NGX_HTTP_AUTH_JWT_REQUIRE_EQUAL_OPERATOR) == 0) {
    int eq = json_equal(input, requirement);
    if (eq != 1) {
      return NGX_ERROR;
    }
  }
  else if (strcmp(op, NGX_HTTP_AUTH_JWT_REQUIRE_NOT_EQUAL_OPERATOR) == 0) {
    int eq = json_equal(input, requirement);
    if (eq == 1) {
      return NGX_ERROR;
    }
  }
  else if (strcmp(op, NGX_HTTP_AUTH_JWT_REQUIRE_GREATER_THAN_OPERATOR) == 0) {
    long long jwt_claim_json_data_value, expected_json_value;
    if (!json_is_integer(input) || !json_is_integer(requirement)) {
      return NGX_ERROR;
    }
    jwt_claim_json_data_value = json_integer_value(input);
    expected_json_value = json_integer_value(requirement);

    if (jwt_claim_json_data_value <= expected_json_value) {
      return NGX_ERROR;
    }
  }
  else if (strcmp(op,
                  NGX_HTTP_AUTH_JWT_REQUIRE_GREATER_OR_EQUAL_OPERATOR) == 0) {
    long long jwt_claim_json_data_value, expected_json_value;
    if (!json_is_integer(input) || !json_is_integer(requirement)) {
      return NGX_ERROR;
    }
    jwt_claim_json_data_value = json_integer_value(input);
    expected_json_value = json_integer_value(requirement);

    if (jwt_claim_json_data_value < expected_json_value) {
      return NGX_ERROR;
    }
  }
  else if (strcmp(op, NGX_HTTP_AUTH_JWT_REQUIRE_LESS_THAN_OPERATOR) == 0) {
    long long jwt_claim_json_data_value, expected_json_value;
    if (!json_is_integer(input) || !json_is_integer(requirement)) {
      return NGX_ERROR;
    }
    jwt_claim_json_data_value = json_integer_value(input);
    expected_json_value = json_integer_value(requirement);

    if (jwt_claim_json_data_value >= expected_json_value) {
      return NGX_ERROR;
    }
  }
  else if (strcmp(op, NGX_HTTP_AUTH_JWT_REQUIRE_LESS_OR_EQUAL_OPERATOR) == 0) {
    long long jwt_claim_json_data_value, expected_json_value;
    if (!json_is_integer(input) || !json_is_integer(requirement)) {
      return NGX_ERROR;
    }
    jwt_claim_json_data_value = json_integer_value(input);
    expected_json_value = json_integer_value(requirement);

    if (jwt_claim_json_data_value > expected_json_value) {
      return NGX_ERROR;
    }
  }
  else if (strcmp(op, NGX_HTTP_AUTH_JWT_REQUIRE_INTERSECTION_OPERATOR) == 0) {
    ngx_flag_t invalidFlag = 1;
    json_t *input_val = NULL, *requirement_val = NULL;
    size_t input_index, requirement_index;

    if (!json_is_array(input) || !json_is_array(requirement)) {
      return NGX_ERROR;
    }

    json_array_foreach(input, input_index, input_val) {
      if (invalidFlag == 0) {
        break;
      }
      if (!json_is_string(input_val)) {
        continue;
      }
      json_array_foreach(requirement, requirement_index, requirement_val) {
        if (json_equal(input_val, requirement_val) == 1) {
          invalidFlag = 0;
          break;
        }
      }
    }

    if (invalidFlag == 1) {
      return NGX_ERROR;
    }
  }
  else if (strcmp(op,
                  NGX_HTTP_AUTH_JWT_REQUIRE_NOT_INTERSECTION_OPERATOR) == 0) {
    ngx_flag_t invalidFlag = 0;
    json_t *input_val = NULL, *requirement_val = NULL;
    size_t input_index, requirement_index;

    if (!json_is_array(input) || !json_is_array(requirement)) {
      return NGX_ERROR;
    }

    json_array_foreach(input, input_index, input_val) {
      if (invalidFlag == 1) {
        break;
      }
      if (!json_is_string(input_val)) {
        continue;
      }
      json_array_foreach(requirement, requirement_index, requirement_val) {
        if (json_equal(input_val, requirement_val) == 1) {
          invalidFlag = 1;
          break;
        }
      }
    }

    if (invalidFlag == 1) {
      return NGX_ERROR;
    }
  }
  else if (strcmp(op, NGX_HTTP_AUTH_JWT_REQUIRE_IN_OPERATOR) == 0) {
    ngx_flag_t invalidFlag = 1;

    if (json_is_array(requirement)) {
      json_t *val = NULL;
      size_t index;

      json_array_foreach(requirement, index, val) {
        if (json_equal(input, val) == 1) {
          invalidFlag = 0;
          break;
        }
      }
    }
    else if (json_is_object(requirement)) {
      json_t *val = NULL;
      const char *key;

      json_object_foreach(requirement, key, val) {
        if (json_equal(input, val) == 1) {
          invalidFlag = 0;
          break;
        }
      }
    }
    else {
      return NGX_ERROR;
    }


    if (invalidFlag == 1) {
      return NGX_ERROR;
    }
  }
  else if (strcmp(op, NGX_HTTP_AUTH_JWT_REQUIRE_NOT_IN_OPERATOR) == 0) {
    ngx_flag_t invalidFlag = 0;

    if (json_is_array(requirement)) {
      json_t *val = NULL;
      size_t index;

      json_array_foreach(requirement, index, val) {
        if (json_equal(input, val) == 1) {
          invalidFlag = 1;
          break;
        }
      }
    }
    else if (json_is_object(requirement)) {
      json_t *val = NULL;
      const char *key;

      json_object_foreach(requirement, key, val) {
        if (json_equal(input, val) == 1) {
          invalidFlag = 1;
          break;
        }
      }
    }
    else {
      return NGX_ERROR;
    }

    if (invalidFlag == 1) {
      return NGX_ERROR;
    }
  }
  else {
    return NGX_ERROR;
  }

  return NGX_OK;
}
