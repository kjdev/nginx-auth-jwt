use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== valid
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_aud "test1.audience.example.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== valid of set variable
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
set $aud "test1.audience.example.com";
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_aud $aud;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== invalid value to short length
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_aud "audience.example.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log: auth_jwt: rejected due to not include: aud='"test1.audience.example.com"': expected='audience.example.com'
--- log_level: info

=== invalid value to long length
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_aud "app.test1.audience.example.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log: auth_jwt: rejected due to not include: aud='"test1.audience.example.com"': expected='app.test1.audience.example.com'
--- log_level: info

=== invalid value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_aud "test.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log: auth_jwt: rejected due to not include: aud='"test1.audience.example.com"': expected='test.com'
--- log_level: info

=== missing expected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_aud "";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log: auth_jwt: rejected due to missing expected aud
--- log_level: info

=== valid array 1
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test10_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_aud "test10.audience.example.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test10.issuer.example.com
X-Jwt-Claim-Sub: test10.identifier
X-Jwt-Claim-Aud: test10.audience.example.com,test10.audience.test.com
X-Jwt-Claim-Email: test10@example.com
--- error_code: 200

=== valid array 2
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test10_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_aud "test10.audience.test.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test10.issuer.example.com
X-Jwt-Claim-Sub: test10.identifier
X-Jwt-Claim-Aud: test10.audience.example.com,test10.audience.test.com
X-Jwt-Claim-Email: test10@example.com
--- error_code: 200

=== invalid array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test10_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_aud "audience.example.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log: auth_jwt: rejected due to not include: aud='["test10.audience.example.com","test10.audience.test.com"]': expected='audience.example.com'
--- log_level: info
