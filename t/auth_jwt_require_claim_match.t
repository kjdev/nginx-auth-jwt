use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: operator match returns 200 with matching string
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $pattern '"^John"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name match $pattern;
}
--- request
    GET /
--- error_code: 200

=== test: operator match returns 401 with non-matching string
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $pattern '"^Alice"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name match $pattern;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to name claim requirement: ""John Doe"" is not "match" ""^Alice""

=== test: operator !match returns 200 when not matching
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $pattern '"^Alice"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name !match $pattern;
}
--- request
    GET /
--- error_code: 200

=== test: operator !match returns 401 when matching
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $pattern '"^John"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name !match $pattern;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to name claim requirement: ""John Doe"" is not "!match" ""^John""

=== test: operator match returns 401 with non-string claim
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $pattern '"^[0-9]+"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat match $pattern;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to iat claim requirement

=== test: operator match returns 200 with complex pattern
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $pattern '"John .+"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name match $pattern;
}
--- request
    GET /
--- error_code: 200

=== test: operator match returns 200 with partial match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $pattern '"Doe"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name match $pattern;
}
--- request
    GET /
--- error_code: 200

=== test: operator match returns 200 with \z end anchor
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name match 'Doe\z';
}
--- request
    GET /
--- error_code: 200

=== test: operator match returns 401 with \z end anchor mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name match 'John\z';
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to name claim requirement

=== test: operator match returns 200 with full \A \z anchored pattern
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name match '\AJohn Doe\z';
}
--- request
    GET /
--- error_code: 200

=== test: operator match returns 401 with backtracking pattern (ReDoS protection)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $pattern '"^(a+)+\\\\z"';
  auth_jwt "" token=$redos_jwt;
  auth_jwt_require_claim sub match $pattern;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: regex match limit exceeded

=== test: operator match rejects non-string json= value at config time
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name match json=123;
}
--- must_die

=== test: operator match rejects invalid json= value at config time
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name match json={};
}
--- must_die

=== test: operator match returns 200 with static json= string pattern
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name match 'json="^John"';
}
--- request
    GET /
--- error_code: 200

=== test: operator match returns 200 with normal dynamic pattern
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $pattern '"^John"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name match $pattern;
}
--- request
    GET /
--- error_code: 200
