use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: operator any returns 200 with array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles1 '["admin", "user_role1" , "user_role2"]';
  set $expected_roles2 '["admin", "service", "user_role1" , "user_role2"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim roles any $expected_roles1;
  auth_jwt_require_claim roles any $expected_roles2;
}
--- request
    GET /
--- error_code: 200

=== test: operator any returns 401 with not intersect array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles '["user_role1" , "user_role2", "user_role3"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim roles any $expected_roles;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to roles claim requirement: "["admin","service"]" is not "any" "["user_role1" , "user_role2", "user_role3"]"

=== test: operator any returns 401 with not array expected value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles '"just string"';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim roles any $expected_roles;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to roles claim requirement: "["admin","service"]" is not "any" ""just string""

=== test: operator any returns 200 with scalar input matching array element
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles '["John Doe", "Role"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim name any $expected_roles;
}
--- request
    GET /
--- error_code: 200

=== test: operator !any returns 200 when no intersection
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles '["user_role1" , "user_role2", "user_role3"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim roles !any $expected_roles;
}
--- request
    GET /
--- error_code: 200

=== test: operator !any returns 401 when intersection exists
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  set $expected_roles '["admin", "user_role1"]';
  auth_jwt "" token=$require_claim_jwt;
  auth_jwt_require_claim roles !any $expected_roles;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: rejected due to roles claim requirement: "["admin","service"]" is not "!any" "["admin", "user_role1"]"
