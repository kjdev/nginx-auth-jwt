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
  auth_jwt_require_claim exp eq $variable;
  auth_jwt_require_claim exp ne $variable;
  auth_jwt_require_claim exp gt $variable;
  auth_jwt_require_claim exp ge $variable;
  auth_jwt_require_claim exp lt $variable;
  auth_jwt_require_claim exp le $variable;
  auth_jwt_require_claim exp intersect $variable;
  auth_jwt_require_claim exp nintersect $variable;
  auth_jwt_require_claim exp in $variable;
  auth_jwt_require_claim exp nin $variable;
}
--- request
    GET /
--- error_code: 401

=== test: check 401 with invalid operators
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  set $variable "1";
  auth_jwt "" token=$test1_jwt;
  auth_jwt_require_claim exp invalidname $variable;
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
  auth_jwt_require_claim exp eq $variable;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed to json_load jwt claim requirement
--- log_level
error
