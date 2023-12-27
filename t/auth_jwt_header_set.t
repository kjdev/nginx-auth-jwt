use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== set claim
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_header_set $jwt_alg alg;
auth_jwt_header_set $jwt_type typ;
auth_jwt_header_set $jwt_kid kid;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  add_header 'X-Jwt-ALG' $jwt_alg;
  add_header 'X-Jwt-TYPE' $jwt_type;
  add_header 'X-Jwt-KID' $jwt_kid;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
X-Jwt-ALG: HS256
X-Jwt-TYPE: JWT
X-Jwt-KID: test1
--- error_code: 200

=== set claim on server
--- http_config
--- config
auth_jwt_header_set $jwt_alg alg;
--- must_die

=== set claim on location
--- http_config
--- config
location / {
  auth_jwt_header_set $jwt_alg alg;
}
--- must_die
