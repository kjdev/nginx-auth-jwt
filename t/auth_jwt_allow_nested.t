use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== require nested claim
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  set $expected_access '["grants_access_admin"]';
  auth_jwt_require_claim grants.access intersect $expected_access;
}
--- request
GET /
--- error_code: 200

=== require nested claim with multiple
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  set $expected_access '["grants_access_admin"]';
  auth_jwt_require_claim grants.access intersect $expected_access;
  set $expected_roles '["grants_roles_admin"]';
  auth_jwt_require_claim grants.roles intersect $expected_roles;
}
--- request
GET /
--- error_code: 200

=== require nested claim with multiple stage
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  set $expected_roles '["grants_service_roles_admin"]';
  auth_jwt_require_claim grants.service.roles intersect $expected_roles;
}
--- request
GET /
--- error_code: 200

=== require nested claim with invalid key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  set $expected_roles '["access_roles_admin"]';
  auth_jwt_require_claim access.roles intersect $expected_roles;
}
--- request
GET /
--- error_code: 401

=== require nested claim with quote key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  set $expected_roles '["access_roles_admin"]';
  auth_jwt_require_claim '"access.roles"' intersect $expected_roles;
}
--- request
GET /
--- error_code: 200

=== require nested claim with quote key and multiple stage
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  set $expected_roles '["access_roles_admin"]';
  auth_jwt_require_claim '"access.roles"' intersect $expected_roles;
  set $expected_access_roles '["grants_access_roles_admin"]';
  auth_jwt_require_claim 'grants."access.roles"' intersect $expected_access_roles;
  set $expected_service_roles '["grants_access_service_roles_admin"]';
  auth_jwt_require_claim 'grants."access.service".roles' intersect $expected_service_roles;
}
--- request
GET /
--- error_code: 200

=== require nested claim with specify delimiter
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested delimiter=<>;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  set $expected_roles '["grants_service_roles_admin"]';
  auth_jwt_require_claim grants<>service<>roles intersect $expected_roles;
}
--- request
GET /
--- error_code: 200

=== require nested claim with specify quote
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested delimiter=. quote=';
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  set $expected_roles '["access_roles_admin"]';
  auth_jwt_require_claim '"access.roles"' intersect $expected_roles;
}
--- request
GET /
--- error_code: 401

=== require nested header
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  set $expected_access '["roles_access_admin"]';
  auth_jwt_require_header roles.access intersect $expected_access;
  set $expected_services '["roles_services_admin"]';
  auth_jwt_require_header roles.services intersect $expected_services;
}
--- request
GET /
--- error_code: 200

=== variable nested claim
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested delimiter=_;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  add_header 'X-Jwt-Claim-Sub' $jwt_claim_sub;
  add_header 'X-Jwt-Claim-Roles' $jwt_claim_roles;
  # variable name can only contain A-z, 0-9, and _
  add_header 'X-Jwt-Claim-Grants-Access' $jwt_claim_grants_access;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Sub: 1234567890
X-Jwt-Claim-Roles: admin,user
X-Jwt-Claim-Grants-Access: grants_access_admin,grants_access_user
--- error_code: 200

=== variable nested header
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested delimiter=_;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  add_header 'X-Jwt-Claim-Alg' $jwt_header_alg;
  # variable name can only contain A-z, 0-9, and _
  add_header 'X-Jwt-Claim-Roles-Access' $jwt_header_roles_access;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Alg: HS256
X-Jwt-Claim-Roles-Access: ["roles_access_admin","roles_access_user"]
--- error_code: 200

=== set variable nested claim
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested;
auth_jwt_claim_set $jwt_access grants.access;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  add_header 'X-Jwt-Claim-Sub' $jwt_claim_sub;
  add_header 'X-Jwt-Claim-Roles' $jwt_claim_roles;
  add_header 'X-Jwt-Claim-Grants-Access' $jwt_access;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Sub: 1234567890
X-Jwt-Claim-Roles: admin,user
X-Jwt-Claim-Grants-Access: grants_access_admin,grants_access_user
--- error_code: 200

=== set variable nested header
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested;
auth_jwt_header_set $jwt_access roles.access;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$nested_jwt;
  add_header 'X-Jwt-Claim-Alg' $jwt_header_alg;
  add_header 'X-Jwt-Claim-Roles-Access' $jwt_access;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Alg: HS256
X-Jwt-Claim-Roles-Access: ["roles_access_admin","roles_access_user"]
--- error_code: 200

=== set allow nested on server
--- http_config
--- config
auth_jwt_allow_nested;
--- must_die

=== set allow nested on location
--- http_config
--- config
location / {
  auth_jwt_allow_nested;
}
--- must_die
