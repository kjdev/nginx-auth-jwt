use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: set valid auth_jwt_revocation_list_kid in location part
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/revocation_kid_list/revocation_kid_list.json;
}
--- request
    GET /
--- error_code: 200

=== test: set invalid auth_jwt_revocation_list_kid in location part
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/revocation_kid_list/invalid_revocation_kid_list.json;
}
--- must_die

=== test: set valid auth_jwt_revocation_list_kid in http_config part
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/revocation_kid_list/revocation_kid_list.json;
--- config
location / {}
--- request
    GET /
--- error_code: 200

=== test: set invalid auth_jwt_revocation_list_kid in http_config part
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/revocation_kid_list/invalid_revocation_kid_list.json;
--- config
location / {}
--- must_die

=== test: set invalid json data auth_jwt_revocation_list_kid failed
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/revocation_kid_list/invalid_json_revocation_kid_list.json;
--- config
location / {}
--- must_die

=== test: multiple auth_jwt_revocation_list_kid directives success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/revocation_kid_list/revocation_kid_list.json;
auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/revocation_kid_list/revocation_kid_list.json;
--- config
location / {}
--- request
    GET /
--- error_code: 200

=== test: invalid file path, "auth_jwt_revocation_list_kid" directive failed to load file by non-existing file
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/xxx.json;
--- config
location / {}
--- request
    GET /
--- must_die

=== test: invalid file path, "auth_jwt_revocation_list_kid" directive failed to load file by trying variable in path
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
set $path "xxx.json";
auth_jwt_revocation_list_kid $path;
location / {}
--- request
    GET /
--- must_die

=== test: check non-revocation kid test1
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/revocation_kid_list/revocation_kid_list.json;
}
--- request
    GET /
--- error_code: 200

=== test: check revocation kid "kid": "test2"
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test2_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/revocation_kid_list/revocation_kid_list.json;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to kid in revocation list: kid="test2"

=== test: check 401 with empty "kid" and empty auth_jwt_revocation_list_kid directive
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt_empty_kid;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/revocation_kid_list/revocation_kid_list.json;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to kid cannot be empty when revocation_kids set

=== test: check 401 with unrepresented "kid" and empty auth_jwt_revocation_list_kid directive
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt_unrepresented_kid;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_revocation_list_kid $TEST_NGINX_DATA_DIR/revocation_kid_list/revocation_kid_list.json;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to kid cannot be empty when revocation_kids set