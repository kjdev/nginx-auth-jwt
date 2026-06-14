use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: alg none requirement does not permanently disable signature validation
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $http_x_token $jwt {
  default  $test1_invalid_sig_jwt;
  "none"   $test0_jwt;
  "forged" $test1_invalid_sig_jwt;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_require_header alg in json=["HS256","none"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request eval
[
  "GET /",
  "GET /"
]
--- more_headers eval
[
  "X-Token: none",
  "X-Token: forged"
]
--- error_code eval
[
  200,
  401
]

=== test: builtin exp validation is applied on every request
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $http_x_token $jwt {
  "future"  $test1_jwt;
  "expired" $test1_invalid_exp_jwt;
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request eval
[
  "GET /",
  "GET /"
]
--- more_headers eval
[
  "X-Token: future",
  "X-Token: expired"
]
--- error_code eval
[
  200,
  401
]
