use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== preaccess phase populates $jwt_claim_sub before limit_req in the same PREACCESS phase
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
limit_req_zone $jwt_claim_sub zone=auth_jwt_phase_sub:1m rate=1r/s;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_phase preaccess;
  limit_req zone=auth_jwt_phase_sub;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- pipelined_requests eval
["GET /", "GET /"]
--- error_code eval
[200, 503]
