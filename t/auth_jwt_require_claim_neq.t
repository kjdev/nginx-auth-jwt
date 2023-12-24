use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: operator not-equal returns 200 with different values
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_name '"Not John Doe"';
  set $expected_sub '"111"';
  set $expected_iat "111";
  set $expected_roles '  ["user"]  '; # note: with additional spaces
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name ne   $expected_name;
  auth_jwt_require_claim sub ne    $expected_sub;
  auth_jwt_require_claim iat ne    $expected_iat;
  auth_jwt_require_claim roles ne  $expected_roles;
}
--- request
    GET /
--- error_code: 200


=== test: operator not-equal returns 401 with not not-equal string
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_name '"John Doe"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name ne   $expected_name;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed requirement for "name":  ""John Doe"" is not "ne" ""John Doe""

=== test: operator not-equal returns 401 with not not-equal number
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat "1516239022";
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat ne $expected_iat;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed requirement for "iat":  "1516239022" is not "ne" "1516239022"

=== test: operator not-equal returns 401 with not not-equal json array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles '["admin", "service"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim roles ne   $expected_roles;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed requirement for "roles":  "["admin","service"]" is not "ne" "["admin", "service"]"
