use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: valid operators
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  set $variable "1";
  auth_jwt "" token=$test1_jwt;
  auth_jwt_require_header kid eq $variable;
  auth_jwt_require_header kid ne $variable;
  auth_jwt_require_header kid gt $variable;
  auth_jwt_require_header kid ge $variable;
  auth_jwt_require_header kid lt $variable;
  auth_jwt_require_header kid le $variable;
  auth_jwt_require_header kid intersect $variable;
  auth_jwt_require_header kid nintersect $variable;
  auth_jwt_require_header kid in $variable;
  auth_jwt_require_header kid nin $variable;
}
--- request
    GET /
--- error_code: 401


=== test: check header requirements returns 200 for simple operator eq (others operators are the same like for jwt-claims)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  set $expected_kid '"test1"';
  auth_jwt "" token=$test1_jwt;
  auth_jwt_require_header kid eq $expected_kid;
}
--- request
    GET /
--- error_code: 200

=== test: check 401 with incorrect string
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  set $variable '"test2"';
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_require_header kid eq $variable;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed requirement for "kid":  ""test1"" is not "eq" ""test2""

=== test: check 401 with invalid operators
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  set $variable "1";
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_require_header kid invalidname $variable;
}
--- must_die

=== test: check 401 with invalid json expected variable
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  set $variable "'1'"; # it is not a json string
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_require_header kid eq $variable;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed to json_load jwt header requirement
--- log_level
error
