use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: operator !eq returns 200 when not equal
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_name '"Not John Doe"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name !eq $expected_name;
}
--- request
    GET /
--- error_code: 200

=== test: operator !eq returns 401 when equal
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_name '"John Doe"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name !eq $expected_name;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to name claim requirement: ""John Doe"" is not "!eq" ""John Doe""

=== test: operator !in returns 200 when not in array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_names '["Alice", "Bob"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name !in $expected_names;
}
--- request
    GET /
--- error_code: 200

=== test: operator !in returns 401 when in array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_names '["John Doe", "Alice"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name !in $expected_names;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to name claim requirement: ""John Doe"" is not "!in" "["John Doe", "Alice"]"

=== test: operator !gt returns 200 when not greater
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat '9999999999';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat !gt $expected_iat;
}
--- request
    GET /
--- error_code: 200

=== test: operator !gt returns 401 when greater
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat '100';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat !gt $expected_iat;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to iat claim requirement: "1516239022" is not "!gt" "100"

=== test: operator !ge returns 200 when less than
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat '9999999999';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat !ge $expected_iat;
}
--- request
    GET /
--- error_code: 200

=== test: operator !lt returns 200 when not less than
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat '100';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat !lt $expected_iat;
}
--- request
    GET /
--- error_code: 200

=== test: operator !le returns 200 when greater
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_iat '100';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim iat !le $expected_iat;
}
--- request
    GET /
--- error_code: 200

=== test: invalid operator returns error
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name !invalid '"test"';
}
--- must_die
