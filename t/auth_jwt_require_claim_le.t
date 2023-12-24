use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: operator le returns 200 with number
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat "9516239022";
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat le $expected_iat;
}
--- request
    GET /
--- error_code: 200

=== test: operator le returns 401 with string
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat '"1"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat le $expected_iat;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed requirement for "iat":  "1516239022" is not "le" ""1""

=== test: operator le returns 401 with not le number
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat "1";
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat le $expected_iat;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed requirement for "iat":  "1516239022" is not "le" "1"

=== test: operator le returns 200 with equal number
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat "1516239022";
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat le $expected_iat;
}
--- request
    GET /
--- error_code: 200
