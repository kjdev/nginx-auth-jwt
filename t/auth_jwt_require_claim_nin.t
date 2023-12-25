use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: operator nin returns 200 with array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_name '["John Doe5", "John Doe2" , "John Doe3"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name nin $expected_name;
}
--- request
    GET /
--- error_code: 200

=== test: operator nin returns 401 with not nin array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_name '["John Doe", "John Doe2" , "John Doe3"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name nin $expected_name;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to name claim requirement: ""John Doe"" is not "nin" "["John Doe", "John Doe2" , "John Doe3"]"


=== test: operator nin returns 200 with not array expected value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_name '"just string"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name nin $expected_name;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to name claim requirement: ""John Doe"" is not "nin" ""just string""
