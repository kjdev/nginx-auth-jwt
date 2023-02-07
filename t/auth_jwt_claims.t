use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== claims
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  add_header 'X-Jwt-Claims' $jwt_claims;
}
--- request
GET /
--- response_headers
X-Jwt-Claims: {"aud":"test1.audience.example.com","email":"test1@example.com","exp":4133862000,"iat":1662512286,"iss":"https://test1.issuer.example.com","sub":"test1.identifier"}
--- error_code: 200
