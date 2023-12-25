use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: operator equal returns 200 with different values
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_name '"John Doe"';
  set $expected_sub '"1234567890"';
  set $expected_iat "1516239022";
  set $expected_roles '  ["admin",   "service"]  '; # note: with additional spaces
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name eq   $expected_name;
  auth_jwt_require_claim sub eq    $expected_sub;
  auth_jwt_require_claim iat eq    $expected_iat;
  auth_jwt_require_claim roles eq  $expected_roles;
}
--- request
    GET /
--- error_code: 200


=== test: operator equal returns 401 with incorrect string
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_name '"Not John Doe"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name eq   $expected_name;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to name claim requirement: ""John Doe"" is not "eq" ""Not John Doe""

=== test: operator equal returns 401 with incorrect number
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat "111";
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat eq $expected_iat;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to iat claim requirement: "1516239022" is not "eq" "111"

=== test: operator equal returns 401 with incorrect json array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles '["user"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim roles eq   $expected_roles;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to roles claim requirement: "["admin","service"]" is not "eq" "["user"]"
