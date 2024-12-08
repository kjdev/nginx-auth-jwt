use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: set valid auth_jwt_revocation_list_sub in location part
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/revocation_list_sub/revocation_list_sub.json;
}
--- request
    GET /
--- error_code: 200

=== test: set invalid auth_jwt_revocation_list_sub in location part
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/revocation_list_sub/invalid_revocation_list_sub.json;
}
--- must_die

=== test: set valid auth_jwt_revocation_list_sub in http_config part
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/revocation_list_sub/revocation_list_sub.json;
--- config
location / {}
--- request
    GET /
--- error_code: 200

=== test: set invalid auth_jwt_revocation_list_sub in http_config part
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/revocation_list_sub/invalid_revocation_list_sub.json;
--- config
location / {}
--- must_die

=== test: set invalid json data auth_jwt_revocation_list_sub failed
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/revocation_list_sub/invalid_json_revocation_list_sub.json;
--- config
location / {}
--- must_die

=== test: multiple auth_jwt_revocation_list_sub directives success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/revocation_list_sub/revocation_list_sub.json;
auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/revocation_list_sub/revocation_list_sub.json;
--- config
location / {}
--- request
    GET /
--- error_code: 200

=== test: invalid file path, "auth_jwt_revocation_list_sub" directive failed to load file by non-existing file
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/xxx.json;
--- config
location / {}
--- request
    GET /
--- must_die

=== test: invalid file path, "auth_jwt_revocation_list_sub" directive failed to load file by trying variable in path
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
set $path "xxx.json";
auth_jwt_revocation_list_sub $path;
location / {}
--- request
    GET /
--- must_die

=== test: check non-revocation user test1
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/test1.jwks;
  auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/revocation_list_sub/revocation_list_sub.json;
}
--- request
    GET /
--- error_code: 200

=== test: check revocation user "sub": "test2.identifier"
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test2_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/test1.jwks;
  auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/revocation_list_sub/revocation_list_sub.json;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to sub in revocation list: sub="test2.identifier"

=== limit_except
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $http_x_id $jwt {
  "test1" $test1_jwt;
  "test2" $test2_jwt;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/revocation_list_sub/empty_revocation_list_sub.json;
  limit_except GET {
    auth_jwt_revocation_list_sub $TEST_NGINX_DATA_DIR/revocation_list_sub/revocation_list_sub.json;
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
  200,
  401
]
