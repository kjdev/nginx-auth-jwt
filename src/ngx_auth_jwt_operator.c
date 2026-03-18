/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * Operator comparison logic for nginx-auth-jwt module
 *
 * Returns:
 *   NGX_OK       condition met
 *   NGX_DECLINED condition not met (valid comparison)
 *   NGX_ERROR    internal error (type mismatch, etc.)
 *
 * Negation is implemented via '!' prefix (e.g. !eq, !any, !in).
 * Legacy aliases (ne, nin, nintersect) are mapped to negated forms.
 * NGX_ERROR is never flipped (authorization bypass prevention).
 */

#include "ngx_auth_jwt_operator.h"

#if (NGX_PCRE)
#include <ngx_regex.h>
#endif

#define NGX_AUTH_JWT_MAX_ARRAY_SIZE  1024


static ngx_int_t
ngx_auth_jwt_op_eq(ngx_auth_jwt_json_t *input,
    ngx_auth_jwt_json_t *requirement)
{
    return ngx_auth_jwt_json_equal(input, requirement)
         ? NGX_OK : NGX_DECLINED;
}


static ngx_int_t
ngx_auth_jwt_op_gt(ngx_auth_jwt_json_t *input,
    ngx_auth_jwt_json_t *requirement)
{
    double diff;

    if (ngx_auth_jwt_json_compare(input, requirement, &diff, NULL) == NGX_OK) {
        return (diff > 0) ? NGX_OK : NGX_DECLINED;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_auth_jwt_op_ge(ngx_auth_jwt_json_t *input,
    ngx_auth_jwt_json_t *requirement)
{
    double diff;

    if (ngx_auth_jwt_json_compare(input, requirement, &diff, NULL) == NGX_OK) {
        return (diff >= 0) ? NGX_OK : NGX_DECLINED;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_auth_jwt_op_lt(ngx_auth_jwt_json_t *input,
    ngx_auth_jwt_json_t *requirement)
{
    double diff;

    if (ngx_auth_jwt_json_compare(input, requirement, &diff, NULL) == NGX_OK) {
        return (diff < 0) ? NGX_OK : NGX_DECLINED;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_auth_jwt_op_le(ngx_auth_jwt_json_t *input,
    ngx_auth_jwt_json_t *requirement)
{
    double diff;

    if (ngx_auth_jwt_json_compare(input, requirement, &diff, NULL) == NGX_OK) {
        return (diff <= 0) ? NGX_OK : NGX_DECLINED;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_auth_jwt_op_any(ngx_auth_jwt_json_t *input,
    ngx_auth_jwt_json_t *requirement)
{
    size_t i, j, input_size, req_size;
    ngx_auth_jwt_json_t *input_val, *req_val;

    if (!ngx_auth_jwt_json_is_array(requirement)) {
        return NGX_ERROR;
    }

    req_size = ngx_auth_jwt_json_array_size(requirement);
    if (req_size > NGX_AUTH_JWT_MAX_ARRAY_SIZE) {
        return NGX_ERROR;
    }

    if (ngx_auth_jwt_json_is_array(input)) {
        input_size = ngx_auth_jwt_json_array_size(input);
        if (input_size > NGX_AUTH_JWT_MAX_ARRAY_SIZE) {
            return NGX_ERROR;
        }

        for (i = 0; i < input_size; i++) {
            input_val = ngx_auth_jwt_json_array_get(input, i);
            for (j = 0; j < req_size; j++) {
                req_val = ngx_auth_jwt_json_array_get(requirement, j);
                if (ngx_auth_jwt_json_equal(input_val, req_val)) {
                    return NGX_OK;
                }
            }
        }
    }else {
        for (j = 0; j < req_size; j++) {
            req_val = ngx_auth_jwt_json_array_get(requirement, j);
            if (ngx_auth_jwt_json_equal(input, req_val)) {
                return NGX_OK;
            }
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_auth_jwt_op_in(ngx_auth_jwt_json_t *input,
    ngx_auth_jwt_json_t *requirement)
{
    size_t i, size;
    ngx_auth_jwt_json_t *val;

    if (ngx_auth_jwt_json_is_array(requirement)) {
        size = ngx_auth_jwt_json_array_size(requirement);
        if (size > NGX_AUTH_JWT_MAX_ARRAY_SIZE) {
            return NGX_ERROR;
        }

        for (i = 0; i < size; i++) {
            val = ngx_auth_jwt_json_array_get(requirement, i);
            if (ngx_auth_jwt_json_equal(input, val)) {
                return NGX_OK;
            }
        }

        return NGX_DECLINED;
    }

    if (ngx_auth_jwt_json_is_object(requirement)) {
        const char *key_str;
        size_t key_len;

        if (ngx_auth_jwt_json_string(input, &key_str, &key_len) != NGX_OK) {
            return NGX_ERROR;
        }
        if (strlen(key_str) != key_len) {
            return NGX_ERROR;
        }

        val = ngx_auth_jwt_json_object_get(requirement, key_str);
        return (val != NULL) ? NGX_OK : NGX_DECLINED;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_auth_jwt_op_negate(ngx_int_t rc)
{
    switch (rc) {
    case NGX_OK:
        return NGX_DECLINED;
    case NGX_DECLINED:
        return NGX_OK;
    default:
        /* NGX_ERROR is never flipped */
        return rc;
    }
}


#if (NGX_PCRE)
static ngx_int_t
ngx_auth_jwt_op_match(ngx_auth_jwt_json_t *input,
    ngx_auth_jwt_json_t *requirement, ngx_regex_t *regex,
    ngx_pool_t *pool, ngx_log_t *log)
{
    const char *input_str;
    size_t input_len;
    ngx_str_t subject;
    ngx_int_t rc;

    if (ngx_auth_jwt_json_string(input, &input_str, &input_len) != NGX_OK) {
        return NGX_ERROR;
    }

    subject.data = (u_char *) input_str;
    subject.len = input_len;

    if (regex != NULL) {
#if (NGX_PCRE2)
        pcre2_match_data *match_data;
        pcre2_match_context *mctx;

        match_data = pcre2_match_data_create(1, NULL);
        if (match_data == NULL) {
            return NGX_ERROR;
        }

        mctx = pcre2_match_context_create(NULL);
        if (mctx == NULL) {
            pcre2_match_data_free(match_data);
            return NGX_ERROR;
        }

        pcre2_set_match_limit(mctx, NGX_AUTH_JWT_REGEX_MATCH_LIMIT);
        pcre2_set_depth_limit(mctx, NGX_AUTH_JWT_REGEX_MATCH_LIMIT_DEPTH);

        rc = pcre2_match(regex, subject.data, subject.len, 0, 0,
                         match_data, mctx);

        pcre2_match_context_free(mctx);
        pcre2_match_data_free(match_data);

        if (rc == PCRE2_ERROR_MATCHLIMIT
            || rc == PCRE2_ERROR_DEPTHLIMIT)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auth_jwt: regex match limit exceeded");
            return NGX_ERROR;
        }
#else
        pcre_extra extra;

        ngx_memzero(&extra, sizeof(pcre_extra));
        extra.flags = PCRE_EXTRA_MATCH_LIMIT
                      | PCRE_EXTRA_MATCH_LIMIT_RECURSION;
        extra.match_limit = NGX_AUTH_JWT_REGEX_MATCH_LIMIT;
        extra.match_limit_recursion = NGX_AUTH_JWT_REGEX_MATCH_LIMIT_DEPTH;

        rc = pcre_exec(regex->code, &extra,
                       (const char *) subject.data, subject.len,
                       0, 0, NULL, 0);

        if (rc == PCRE_ERROR_MATCHLIMIT
            || rc == PCRE_ERROR_RECURSIONLIMIT)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auth_jwt: regex match limit exceeded");
            return NGX_ERROR;
        }
#endif
    } else {
        const char *pattern_str;
        size_t pattern_len;
        ngx_regex_compile_t rgc;
        u_char errstr[NGX_MAX_CONF_ERRSTR];

        if (ngx_auth_jwt_json_string(requirement, &pattern_str,
                                     &pattern_len) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (pattern_len > NGX_AUTH_JWT_MAX_REGEX_SIZE) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auth_jwt: regex pattern too large: %uz bytes",
                          pattern_len);
            return NGX_ERROR;
        }

        ngx_memzero(&rgc, sizeof(ngx_regex_compile_t));
        rgc.pattern.data = (u_char *) pattern_str;
        rgc.pattern.len = pattern_len;
        rgc.pool = pool;
        rgc.err.data = errstr;
        rgc.err.len = NGX_MAX_CONF_ERRSTR;

        if (ngx_regex_compile(&rgc) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auth_jwt: regex compile failed: %V", &rgc.err);
            return NGX_ERROR;
        }

#if (NGX_PCRE2)
        {
            pcre2_match_data *match_data;
            pcre2_match_context *mctx;

            match_data = pcre2_match_data_create(1, NULL);
            if (match_data == NULL) {
                return NGX_ERROR;
            }

            mctx = pcre2_match_context_create(NULL);
            if (mctx == NULL) {
                pcre2_match_data_free(match_data);
                return NGX_ERROR;
            }

            pcre2_set_match_limit(mctx,
                                  NGX_AUTH_JWT_REGEX_MATCH_LIMIT);
            pcre2_set_depth_limit(mctx,
                                  NGX_AUTH_JWT_REGEX_MATCH_LIMIT_DEPTH);

            rc = pcre2_match(rgc.regex, subject.data, subject.len,
                             0, 0, match_data, mctx);

            pcre2_match_context_free(mctx);
            pcre2_match_data_free(match_data);

            if (rc == PCRE2_ERROR_MATCHLIMIT
                || rc == PCRE2_ERROR_DEPTHLIMIT)
            {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "auth_jwt: regex match limit exceeded");
                return NGX_ERROR;
            }
        }
#else
        {
            pcre_extra extra;

            ngx_memzero(&extra, sizeof(pcre_extra));
            extra.flags = PCRE_EXTRA_MATCH_LIMIT
                          | PCRE_EXTRA_MATCH_LIMIT_RECURSION;
            extra.match_limit = NGX_AUTH_JWT_REGEX_MATCH_LIMIT;
            extra.match_limit_recursion = NGX_AUTH_JWT_REGEX_MATCH_LIMIT_DEPTH;

            rc = pcre_exec(rgc.regex->code, &extra,
                           (const char *) subject.data, subject.len,
                           0, 0, NULL, 0);

            if (rc == PCRE_ERROR_MATCHLIMIT
                || rc == PCRE_ERROR_RECURSIONLIMIT)
            {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "auth_jwt: regex match limit exceeded");
                return NGX_ERROR;
            }
        }
#endif
    }

    if (rc >= 0) {
        return NGX_OK;
    }else if (rc == NGX_REGEX_NO_MATCHED) {
        return NGX_DECLINED;
    }

    return NGX_ERROR;
}
#endif


ngx_int_t
ngx_auth_jwt_operator_validate(char *op,
    ngx_auth_jwt_json_t *input, ngx_auth_jwt_json_t *requirement,
    void *regex, ngx_pool_t *pool, ngx_log_t *log)
{
    ngx_flag_t negate = 0;
    char *name;
    ngx_int_t rc;

    if (op == NULL || input == NULL || requirement == NULL) {
        return NGX_ERROR;
    }

    name = op;

    /* '!' prefix → negate mode */
    if (name[0] == '!') {
        negate = 1;
        name++;
    }

    /* legacy alias mapping */
    if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_NE) == 0) {
        negate = !negate;
        name = NGX_AUTH_JWT_OPERATOR_EQ;
    }else if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_NIN) == 0) {
        negate = !negate;
        name = NGX_AUTH_JWT_OPERATOR_IN;
    }else if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_NINTERSECT) == 0) {
        negate = !negate;
        name = NGX_AUTH_JWT_OPERATOR_ANY;
    }else if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_INTERSECT) == 0) {
        name = NGX_AUTH_JWT_OPERATOR_ANY;
    }

    /* dispatch */
    if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_EQ) == 0) {
        rc = ngx_auth_jwt_op_eq(input, requirement);
    }else if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_GT) == 0) {
        rc = ngx_auth_jwt_op_gt(input, requirement);
    }else if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_GE) == 0) {
        rc = ngx_auth_jwt_op_ge(input, requirement);
    }else if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_LT) == 0) {
        rc = ngx_auth_jwt_op_lt(input, requirement);
    }else if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_LE) == 0) {
        rc = ngx_auth_jwt_op_le(input, requirement);
    }else if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_ANY) == 0) {
        rc = ngx_auth_jwt_op_any(input, requirement);
    }else if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_IN) == 0) {
        rc = ngx_auth_jwt_op_in(input, requirement);
#if (NGX_PCRE)
    }else if (ngx_strcmp(name, NGX_AUTH_JWT_OPERATOR_MATCH) == 0) {
        rc = ngx_auth_jwt_op_match(input, requirement, (ngx_regex_t *) regex,
                                   pool, log);
#endif
    }else {
        return NGX_ERROR;
    }

    return negate ? ngx_auth_jwt_op_negate(rc) : rc;
}
