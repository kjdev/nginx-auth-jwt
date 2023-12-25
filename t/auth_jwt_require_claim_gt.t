use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: operator gt returns 200 with number
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat "1";
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat gt $expected_iat;
}
--- request
    GET /
--- error_code: 200

=== test: operator gt returns 401 with string
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat '"1"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat gt $expected_iat;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to iat claim requirement: "1516239022" is not "gt" ""1""

=== test: operator gt returns 401 with not gt number
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat "9516239022";
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat gt $expected_iat;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to iat claim requirement: "1516239022" is not "gt" "9516239022"

=== test: operator gt returns 401 with equal number
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat "1516239022";
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat gt $expected_iat;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to iat claim requirement: "1516239022" is not "gt" "1516239022"

=== test: operator gt returns 200 with number (real)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_real_jwt;
  auth_jwt_require_claim iat gt json=1;
}
--- request
    GET /
--- error_code: 200

=== test: operator gt returns 401 with string (real)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_real_jwt;
  auth_jwt_require_claim iat gt 1;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to iat claim requirement: "1516239022.1234" is not "gt" "1"

=== test: operator gt returns 401 with not gt number (real)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_real_jwt;
  auth_jwt_require_claim iat gt json=9516239022;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to iat claim requirement: "1516239022.1234" is not "gt" "9516239022"

=== test: operator gt returns 200 with equal number (real)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_real_jwt;
  auth_jwt_require_claim iat gt json=1516239022;
}
--- request
    GET /
--- error_code: 200

=== test: operator gt returns 401 with gt number (real)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_real_jwt;
  auth_jwt_require_claim iat gt json=1516239023;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to iat claim requirement: "1516239022.1234" is not "gt" "1516239023"
