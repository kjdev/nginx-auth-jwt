use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== valid HS256 in jwks
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg HS256;
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

=== valid HS256 in key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/keys.json keyval;
  auth_jwt_validate_alg HS256;
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

=== invalid HS256
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test4_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg HS256;
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
--- error_log: auth_jwt: rejected due to unacceptable algorithm: equals expected=HS256 actual=RS256
--- log_level: info

=== valid HS384 in jwks
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test2_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg HS384;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test2.issuer.example.com
X-Jwt-Claim-Sub: test2.identifier
X-Jwt-Claim-Aud: test2.audience.example.com
X-Jwt-Claim-Email: test2@example.com
--- error_code: 200

=== valid HS384 in key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test2_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/keys.json keyval;
  auth_jwt_validate_alg HS384;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test2.issuer.example.com
X-Jwt-Claim-Sub: test2.identifier
X-Jwt-Claim-Aud: test2.audience.example.com
X-Jwt-Claim-Email: test2@example.com
--- error_code: 200

=== invalid HS384
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test5_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg HS384;
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
--- error_log: auth_jwt: rejected due to unacceptable algorithm: equals expected=HS384 actual=RS384
--- log_level: info

=== valid HS512 in jwks
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test3_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg HS512;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test3.issuer.example.com
X-Jwt-Claim-Sub: test3.identifier
X-Jwt-Claim-Aud: test3.audience.example.com
X-Jwt-Claim-Email: test3@example.com
--- error_code: 200

=== valid HS512 in key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test3_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/keys.json keyval;
  auth_jwt_validate_alg HS512;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test3.issuer.example.com
X-Jwt-Claim-Sub: test3.identifier
X-Jwt-Claim-Aud: test3.audience.example.com
X-Jwt-Claim-Email: test3@example.com
--- error_code: 200

=== invalid HS512
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test6_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg HS512;
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
--- error_log: auth_jwt: rejected due to unacceptable algorithm: equals expected=HS512 actual=RS512
--- log_level: info

=== valid RS256 in jwks
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test4_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg RS256;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test4.issuer.example.com
X-Jwt-Claim-Sub: test4.identifier
X-Jwt-Claim-Aud: test4.audience.example.com
X-Jwt-Claim-Email: test4@example.com
--- error_code: 200

=== valid RS256 in key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test4_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/keys.json keyval;
  auth_jwt_validate_alg RS256;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test4.issuer.example.com
X-Jwt-Claim-Sub: test4.identifier
X-Jwt-Claim-Aud: test4.audience.example.com
X-Jwt-Claim-Email: test4@example.com
--- error_code: 200

=== invalid RS256
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg RS256;
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
--- error_log: auth_jwt: rejected due to unacceptable algorithm: equals expected=RS256 actual=HS256
--- log_level: info

=== valid RS384 in jwks
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test5_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg RS384;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test5.issuer.example.com
X-Jwt-Claim-Sub: test5.identifier
X-Jwt-Claim-Aud: test5.audience.example.com
X-Jwt-Claim-Email: test5@example.com
--- error_code: 200

=== valid RS384 in key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test5_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/keys.json keyval;
  auth_jwt_validate_alg RS384;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test5.issuer.example.com
X-Jwt-Claim-Sub: test5.identifier
X-Jwt-Claim-Aud: test5.audience.example.com
X-Jwt-Claim-Email: test5@example.com
--- error_code: 200

=== invalid RS384
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test2_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg RS384;
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
--- error_log: auth_jwt: rejected due to unacceptable algorithm: equals expected=RS384 actual=HS384
--- log_level: info

=== valid RS512 in jwks
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test6_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg RS512;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test6.issuer.example.com
X-Jwt-Claim-Sub: test6.identifier
X-Jwt-Claim-Aud: test6.audience.example.com
X-Jwt-Claim-Email: test6@example.com
--- error_code: 200

=== valid RS512 in key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test6_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/keys.json keyval;
  auth_jwt_validate_alg RS512;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test6.issuer.example.com
X-Jwt-Claim-Sub: test6.identifier
X-Jwt-Claim-Aud: test6.audience.example.com
X-Jwt-Claim-Email: test6@example.com
--- error_code: 200

=== invalid RS512
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test3_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg RS512;
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
--- error_log: auth_jwt: rejected due to unacceptable algorithm: equals expected=RS512 actual=HS512
--- log_level: info

=== ES256 in jwks
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test7_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg ES256;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test7.issuer.example.com
X-Jwt-Claim-Sub: test7.identifier
X-Jwt-Claim-Aud: test7.audience.example.com
X-Jwt-Claim-Email: test7@example.com
--- error_code: 200

=== ES256 in key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test7_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/keys.json keyval;
  auth_jwt_validate_alg ES256;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test7.issuer.example.com
X-Jwt-Claim-Sub: test7.identifier
X-Jwt-Claim-Aud: test7.audience.example.com
X-Jwt-Claim-Email: test7@example.com
--- error_code: 200

=== ES256 (signature off)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test7_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg ES256;
  auth_jwt_validate_sig off;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test7.issuer.example.com
X-Jwt-Claim-Sub: test7.identifier
X-Jwt-Claim-Aud: test7.audience.example.com
X-Jwt-Claim-Email: test7@example.com
--- error_code: 200

=== invalid ES256 (signature off)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test7_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg RS256;
  auth_jwt_validate_sig off;
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
--- error_log: auth_jwt: rejected due to unacceptable algorithm: equals expected=RS256 actual=ES256
--- log_level: info

=== ES384 in jwks
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test8_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg ES384;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test8.issuer.example.com
X-Jwt-Claim-Sub: test8.identifier
X-Jwt-Claim-Aud: test8.audience.example.com
X-Jwt-Claim-Email: test8@example.com
--- error_code: 200

=== ES384 in key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test8_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/keys.json keyval;
  auth_jwt_validate_alg ES384;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test8.issuer.example.com
X-Jwt-Claim-Sub: test8.identifier
X-Jwt-Claim-Aud: test8.audience.example.com
X-Jwt-Claim-Email: test8@example.com
--- error_code: 200

=== ES384 (signature off)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test8_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg ES384;
  auth_jwt_validate_sig off;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test8.issuer.example.com
X-Jwt-Claim-Sub: test8.identifier
X-Jwt-Claim-Aud: test8.audience.example.com
X-Jwt-Claim-Email: test8@example.com
--- error_code: 200

=== invalid ES384 (signature off)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test8_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg RS384;
  auth_jwt_validate_sig off;
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
--- error_log: auth_jwt: rejected due to unacceptable algorithm: equals expected=RS384 actual=ES384
--- log_level: info

=== ES512 in jwks
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test9_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg ES512;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test9.issuer.example.com
X-Jwt-Claim-Sub: test9.identifier
X-Jwt-Claim-Aud: test9.audience.example.com
X-Jwt-Claim-Email: test9@example.com
--- error_code: 200

=== ES512 in key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test9_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/keys.json keyval;
  auth_jwt_validate_alg ES512;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test9.issuer.example.com
X-Jwt-Claim-Sub: test9.identifier
X-Jwt-Claim-Aud: test9.audience.example.com
X-Jwt-Claim-Email: test9@example.com
--- error_code: 200

=== ES512 (signature off)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test9_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg ES512;
  auth_jwt_validate_sig off;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test9.issuer.example.com
X-Jwt-Claim-Sub: test9.identifier
X-Jwt-Claim-Aud: test9.audience.example.com
X-Jwt-Claim-Email: test9@example.com
--- error_code: 200

=== invalid ES512 (signature off)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test9_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg RS512;
  auth_jwt_validate_sig off;
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
--- error_log: auth_jwt: rejected due to unacceptable algorithm: equals expected=RS512 actual=ES512
--- log_level: info

=== valid none
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test0_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg none;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test0.issuer.example.com
X-Jwt-Claim-Sub: test0.identifier
X-Jwt-Claim-Aud: test0.audience.example.com
X-Jwt-Claim-Email: test0@example.com
--- error_code: 200

=== invalid none
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test0_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_validate_alg HS256;
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
--- error_log: auth_jwt: rejected due to unacceptable algorithm: equals expected=HS256 actual=none
--- log_level: info

=== default none invalid
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test0_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
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
--- error_log: auth_jwt: rejected due to none algorithm
--- log_level: info
