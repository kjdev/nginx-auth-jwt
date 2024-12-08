use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== valid claim value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== valid header value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_header_kid $valid_jwt_kid {
  "test1" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_kid;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== invalid value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "issuer" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss;
}
--- request
GET /
--- error_code: 401
--- error_log: auth_jwt: rejected due to $valid_jwt_iss variable invalid

=== valid with default
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "fail" 0;
  default 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== invalid with default
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 0;
  default 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss;
}
--- request
GET /
--- error_code: 401
--- error_log: auth_jwt: rejected due to $valid_jwt_iss variable invalid

=== valid multiple value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
}
map $jwt_claim_sub $valid_jwt_sub {
  "test1.identifier" 1;
}
map $jwt_header_kid $valid_jwt_kid {
  "test1" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss $valid_jwt_sub $valid_jwt_kid;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== invalid multiple value case1
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "fail" 1;
}
map $jwt_claim_sub $valid_jwt_sub {
  "test1.identifier" 1;
}
map $jwt_header_kid $valid_jwt_kid {
  "test1" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss $valid_jwt_sub $valid_jwt_kid;
}
--- request
GET /
--- error_code: 401
--- error_log: auth_jwt: rejected due to $valid_jwt_iss variable invalid

=== invalid multiple value case2
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
}
map $jwt_claim_sub $valid_jwt_sub {
  "fail" 1;
}
map $jwt_header_kid $valid_jwt_kid {
  "test1" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss $valid_jwt_sub $valid_jwt_kid;
}
--- request
GET /
--- error_code: 401
--- error_log: auth_jwt: rejected due to $valid_jwt_sub variable invalid

=== invalid multiple value case3
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
}
map $jwt_claim_sub $valid_jwt_sub {
  "test1.identifier" 1;
}
map $jwt_header_kid $valid_jwt_kid {
  "fail" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss $valid_jwt_sub $valid_jwt_kid;
}
--- request
GET /
--- error_code: 401
--- error_log: auth_jwt: rejected due to $valid_jwt_kid variable invalid

=== valid multiple line
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
}
map $jwt_claim_sub $valid_jwt_sub {
  "test1.identifier" 1;
}
map $jwt_header_kid $valid_jwt_kid {
  "test1" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss;
  auth_jwt_require $valid_jwt_sub;
  auth_jwt_require $valid_jwt_kid;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== invalid multiple line case1
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "fail" 1;
}
map $jwt_claim_sub $valid_jwt_sub {
  "test1.identifier" 1;
}
map $jwt_header_kid $valid_jwt_kid {
  "test1" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss;
  auth_jwt_require $valid_jwt_sub;
  auth_jwt_require $valid_jwt_kid;
}
--- request
GET /
--- error_code: 401
--- error_log: auth_jwt: rejected due to $valid_jwt_iss variable invalid

=== invalid multiple line case2
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
}
map $jwt_claim_sub $valid_jwt_sub {
  "fail" 1;
}
map $jwt_header_kid $valid_jwt_kid {
  "test1" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss;
  auth_jwt_require $valid_jwt_sub;
  auth_jwt_require $valid_jwt_kid;
}
--- request
GET /
--- error_code: 401
--- error_log: auth_jwt: rejected due to $valid_jwt_sub variable invalid

=== invalid multiple line case3
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
}
map $jwt_claim_sub $valid_jwt_sub {
  "test1.identifier" 1;
}
map $jwt_header_kid $valid_jwt_kid {
  "fail" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss;
  auth_jwt_require $valid_jwt_sub;
  auth_jwt_require $valid_jwt_kid;
}
--- request
GET /
--- error_code: 401
--- error_log: auth_jwt: rejected due to $valid_jwt_kid variable invalid

=== valid error=403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss error=403;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== invalid error=403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "issuer" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss error=403;
}
--- request
GET /
--- error_code: 403
--- error_log: auth_jwt: rejected due to $valid_jwt_iss variable invalid

=== valid multiple variable error=403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
}
map $jwt_claim_sub $valid_jwt_sub {
  "test1.identifier" 1;
}
map $jwt_claim_email $valid_jwt_email {
  "test1@example.com" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss $valid_jwt_sub $valid_jwt_email error=403;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== invalid multiple variable error=403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
}
map $jwt_claim_sub $valid_jwt_sub {
  "identifier" 1;
}
map $jwt_claim_email $valid_jwt_email {
  "test1@example.com" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss $valid_jwt_sub $valid_jwt_email error=403;
}
--- request
GET /
--- error_code: 403
--- error_log: auth_jwt: rejected due to $valid_jwt_sub variable invalid

=== invalid error=xxx
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require $valid_jwt_iss error=500;
}
--- must_die

=== invalid config
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  auth_jwt_require "iss";
}
--- must_die

=== limit_except
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $http_x_id $jwt {
  "test1" $test1_jwt;
  "test2" $test2_jwt;
}
map $jwt_claim_iss $valid_jwt_iss {
  "https://test1.issuer.example.com" 1;
  "https://test2.issuer.example.com" 1;
}
map $jwt_claim_sub $valid_jwt_sub {
  "test2.identifier" 1;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_require $valid_jwt_iss;
  limit_except GET {
    auth_jwt_require $valid_jwt_sub;
  }
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request eval
[
  "GET /",
  "GET /",
  "POST /",
  "POST /"
]
--- more_headers eval
[
  "X-Id: test1",
  "X-Id: test2",
  "X-Id: test1",
  "X-Id: test2"
]
--- error_code eval
[
  200,
  200,
  401,
  200
]
