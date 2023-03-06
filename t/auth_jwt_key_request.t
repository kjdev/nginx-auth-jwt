use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test1 set valid
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
set $key_request3 /test3.jwks;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test1.jwks;
  auth_jwt_key_request /test2.jwks;
  auth_jwt_key_request $key_request3;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== test2 set valid
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
set $key_request3 /test3.jwks;
location / {
  auth_jwt "" token=$test2_jwt;
  auth_jwt_key_request /test1.jwks;
  auth_jwt_key_request /test2.jwks;
  auth_jwt_key_request $key_request3;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test2.issuer.example.com
X-Jwt-Claim-Sub: test2.identifier
X-Jwt-Claim-Aud: test2.audience.example.com
X-Jwt-Claim-Email: test2@example.com
--- error_code: 200

=== test3 set valid
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
set $key_request3 /test3.jwks;
location / {
  auth_jwt "" token=$test3_jwt;
  auth_jwt_key_request /test1.jwks;
  auth_jwt_key_request /test2.jwks;
  auth_jwt_key_request $key_request3;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test3.issuer.example.com
X-Jwt-Claim-Sub: test3.identifier
X-Jwt-Claim-Aud: test3.audience.example.com
X-Jwt-Claim-Email: test3@example.com
--- error_code: 200

=== invalid token
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
set $key_request3 /test3.jwks;
location / {
  auth_jwt "" token=$test4_jwt;
  auth_jwt_key_request /test1.jwks;
  auth_jwt_key_request /test2.jwks;
  auth_jwt_key_request $key_request3;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log: auth_jwt: rejected due to missing signature key or signature validate failure
--- log_level: info

=== set variable valid
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
set $key_request3 /test1.jwks;
location / {
  set $key_request3 /test3.jwks;
  auth_jwt "" token=$test3_jwt;
  auth_jwt_key_request /test1.jwks;
  auth_jwt_key_request /test2.jwks;
  auth_jwt_key_request $key_request3;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /t {
  set $key_request3 /test2.jwks;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test3.issuer.example.com
X-Jwt-Claim-Sub: test3.identifier
X-Jwt-Claim-Aud: test3.audience.example.com
X-Jwt-Claim-Email: test3@example.com
--- error_code: 200

=== set variable invalid
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
set $key_request3 /test3.jwks;
location / {
  set $key_request3 /test1.jwks;
  auth_jwt "" token=$test3_jwt;
  auth_jwt_key_request /test1.jwks;
  auth_jwt_key_request /test2.jwks;
  auth_jwt_key_request $key_request3;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /t {
  set $key_request3 /test2.jwks;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log: auth_jwt: rejected due to missing signature key or signature validate failure
--- log_level: info

=== valid location with set multiple on http, server and location
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_key_request /test3.jwks;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_request /test2.jwks;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test1.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /t {
  auth_jwt "";
  auth_jwt_key_request /test4.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== valid server with set multiple on http, server and location
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_key_request /test3.jwks;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_request /test1.jwks;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test2.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /t {
  auth_jwt "";
  auth_jwt_key_request /test4.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== valid http with set multiple on http, server and location
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_key_request /test1.jwks;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_request /test2.jwks;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test3.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /t {
  auth_jwt "";
  auth_jwt_key_request /test4.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== invalid location with set multiple on http, server and location
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_key_request /test1.jwks;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_request /test2.jwks;
location / {
  auth_jwt "" token=$test4_jwt;
  auth_jwt_key_request /test3.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /t {
  auth_jwt "";
  auth_jwt_key_request /test4.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log: auth_jwt: rejected due to missing signature key or signature validate failure
--- log_level: info

=== valid overwrite with same kid on same directives
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test1.invalid.jwks;
  auth_jwt_key_request /test1.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== invalid overwrite with same kid on same directives
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test1.jwks;
  auth_jwt_key_request /test1.invalid.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== same kid on same directives
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test1.invalid.jwks;
  auth_jwt_key_request /test1.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== valid overwrite with same kid on other directives
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_request /test1.invalid.jwks;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test1.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== invalid overwrite with same kid on other directives
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_request /test1.jwks;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test1.invalid.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== same kid on other directives
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_request /test1.invalid.jwks;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test1.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== invalid data
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /invalid.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log: auth_jwt: rejected due to missing signature key or signature validate failure
--- log_level: info

=== invalid request
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /invalid;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log eval
[
  "auth_jwt: failed to load jwks: \"/invalid\"",
  "auth_jwt: rejected due to without signature key"
]
--- log_level: info

=== invalid jwks request
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test1.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log eval
[
  "auth_jwt: failed to load jwks: \"/test1.json\"",
  "auth_jwt: rejected due to without signature key"
]
--- log_level: info

=== invalid key request
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /empty keyval;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log eval
[
  "auth_jwt: failed to load key: \"/empty\"",
  "auth_jwt: rejected due to without signature key"
]
--- log_level: info

=== test1 with format jwks
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /jwks.json jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== test4 with format jwks
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test4_jwt;
  auth_jwt_key_request /jwks.json jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test4.issuer.example.com
X-Jwt-Claim-Sub: test4.identifier
X-Jwt-Claim-Aud: test4.audience.example.com
X-Jwt-Claim-Email: test4@example.com
--- error_code: 200

=== test1 with format keyval
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /keys.json keyval;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== test4 with format keyval
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test4_jwt;
  auth_jwt_key_request /keys.json keyval;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test4.issuer.example.com
X-Jwt-Claim-Sub: test4.identifier
X-Jwt-Claim-Aud: test4.audience.example.com
X-Jwt-Claim-Email: test4@example.com
--- error_code: 200

=== test1 with format jwks and keyval
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /test1.jwks jwks;
  auth_jwt_key_request /test4.json keyval;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== test4 with format jwks and keyval
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test4_jwt;
  auth_jwt_key_request /test1.jwks jwks;
  auth_jwt_key_request /test4.json keyval;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test4.issuer.example.com
X-Jwt-Claim-Sub: test4.identifier
X-Jwt-Claim-Aud: test4.audience.example.com
X-Jwt-Claim-Email: test4@example.com
--- error_code: 200

=== invalid variable
--- http_config
--- config
location / {
  auth_jwt_key_request $key_file;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- must_die

=== invalid format
--- http_config
--- config
location / {
  auth_jwt_key_request /test1.jwks invalid;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- must_die

=== test1 with format jwks (no kid)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /jwks.no_kid.json jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200

=== test4 with format jwks (no kid)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test4_jwt;
  auth_jwt_key_request /jwks.no_kid.json jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test4.issuer.example.com
X-Jwt-Claim-Sub: test4.identifier
X-Jwt-Claim-Aud: test4.audience.example.com
X-Jwt-Claim-Email: test4@example.com
--- error_code: 200

=== invalid key for kid, refer elsewhere
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_request /jwks.no_kid.json;
  auth_jwt_key_request /test1.invalid.jwks;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
--- error_code: 200
--- error_log: auth_jwt: rejected due to signature validate failure: kid="test1"
