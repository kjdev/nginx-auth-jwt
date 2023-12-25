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

=== test: valid operators string
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_require_claim exp eq 1;
  auth_jwt_require_claim exp ne 1;
  auth_jwt_require_claim exp gt 1;
  auth_jwt_require_claim exp ge 1;
  auth_jwt_require_claim exp lt 1;
  auth_jwt_require_claim exp le 1;
  auth_jwt_require_claim exp intersect 1;
  auth_jwt_require_claim exp nintersect 1;
  auth_jwt_require_claim exp in 1;
  auth_jwt_require_claim exp nin 1;
}
--- request
    GET /
--- error_code: 401

=== test: valid operators string (json=)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_require_claim exp eq json=1;
  auth_jwt_require_claim exp ne json=1;
  auth_jwt_require_claim exp gt json=1;
  auth_jwt_require_claim exp ge json=1;
  auth_jwt_require_claim exp lt json=1;
  auth_jwt_require_claim exp le json=1;
  auth_jwt_require_claim exp intersect json=1;
  auth_jwt_require_claim exp nintersect json=1;
  auth_jwt_require_claim exp in json=1;
  auth_jwt_require_claim exp nin json=1;
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
auth_jwt: failed to json load claim requirement: exp
--- log_level
error

=== test: check 401 with invalid json expected string (json=) variable
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_require_claim exp eq json='1';
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed to json load claim requirement: exp
--- log_level
error
