use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: operator intersect returns 200 with array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles1 '["admin", "user_role1" , "user_role2"]';
  set $expected_roles2 '["admin", "service", "user_role1" , "user_role2"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim roles intersect $expected_roles1;
  auth_jwt_require_claim roles intersect $expected_roles2;
}
--- request
    GET /
--- error_code: 200

=== test: operator intersect returns 401 with not intersect array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles '["user_role1" , "user_role2", "user_role3"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim roles intersect $expected_roles;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to roles claim requirement: "["admin","service"]" is not "intersect" "["user_role1" , "user_role2", "user_role3"]"

=== test: operator intersect returns 401 with not array expected value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles '"just string"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim roles intersect $expected_roles;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to roles claim requirement: "["admin","service"]" is not "intersect" ""just string""

=== test: operator intersect returns 401 with not array jwt claim value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles '["user_role1" , "user_role2", "user_role3"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name intersect $expected_roles;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to name claim requirement: ""John Doe"" is not "intersect" "["user_role1" , "user_role2", "user_role3"]"
