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
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
auth_jwt "" token=$nested_jwt;
location / {
  # variable name can only contain A-z, 0-9, and _
  auth_jwt_allow_nested delimiter=_;
  add_header 'X-Jwt-Claim-Grants-Access' $jwt_claim_grants_access;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /no_nested {
  add_header 'X-Jwt-Claim-Grants-Access' $jwt_claim_grants_access;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request eval
[
  "GET /",
  "GET /no_nested"
]
--- response_headers eval
[
  "X-Jwt-Claim-Grants-Access: grants_access_admin,grants_access_user",
  "X-Jwt-Claim-Grants-Access:"
]

=== variable nested header
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
auth_jwt "" token=$nested_jwt;
location / {
  # variable name can only contain A-z, 0-9, and _
  auth_jwt_allow_nested delimiter=_;
  add_header 'X-Jwt-Header-Roles-Access' $jwt_header_roles_access;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /no_nested {
  add_header 'X-Jwt-Header-Roles-Access' $jwt_header_roles_access;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request eval
[
  "GET /",
  "GET /no_nested"
]
--- response_headers eval
[
  "X-Jwt-Header-Roles-Access: \[\"roles_access_admin\",\"roles_access_user\"\]",
  "X-Jwt-Header-Roles-Access:"
]

=== set variable nested claim
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_claim_set $jwt_access_dot grants.access;
auth_jwt_claim_set $jwt_access_colon grants:access;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
auth_jwt "" token=$nested_jwt;
location / {
  auth_jwt_allow_nested;
  add_header 'X-Jwt-Claim-Grants-Access-Dot' $jwt_access_dot;
  add_header 'X-Jwt-Claim-Grants-Access-Colon' $jwt_access_colon;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /colon {
  auth_jwt_allow_nested delimiter=:;
  add_header 'X-Jwt-Claim-Grants-Access-Dot' $jwt_access_dot;
  add_header 'X-Jwt-Claim-Grants-Access-Colon' $jwt_access_colon;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /no_nested {
  add_header 'X-Jwt-Claim-Grants-Access-Dot' $jwt_access_dot;
  add_header 'X-Jwt-Claim-Grants-Access-Colon' $jwt_access_colon;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request eval
[
  "GET /",
  "GET /colon",
  "GET /no_nested"
]
--- response_headers eval
[
  "X-Jwt-Claim-Grants-Access-Dot: grants_access_admin,grants_access_user\nX-Jwt-Claim-Grants-Access-Colon:",
  "X-Jwt-Claim-Grants-Access-Dot:\nX-Jwt-Claim-Grants-Access-Colon: grants_access_admin,grants_access_user",
  "X-Jwt-Claim-Grants-Access-Dot:\nX-Jwt-Claim-Grants-Access-Colon:"
]

=== set variable nested header
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_header_set $jwt_access_dot roles.access;
auth_jwt_header_set $jwt_access_colon roles:access;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
auth_jwt "" token=$nested_jwt;
location / {
  auth_jwt_allow_nested;
  add_header 'X-Jwt-Header-Role-Access-Dot' $jwt_access_dot;
  add_header 'X-Jwt-Header-Role-Access-Colon' $jwt_access_colon;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /colon {
  auth_jwt_allow_nested delimiter=:;
  add_header 'X-Jwt-Header-Role-Access-Dot' $jwt_access_dot;
  add_header 'X-Jwt-Header-Role-Access-Colon' $jwt_access_colon;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /no_nested {
  add_header 'X-Jwt-Header-Role-Access-Dot' $jwt_access_dot;
  add_header 'X-Jwt-Header-Role-Access-Colon' $jwt_access_colon;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request eval
[
  "GET /",
  "GET /colon",
  "GET /no_nested"
]
--- response_headers eval
[
  "X-Jwt-Header-Role-Access-Dot: \[\"roles_access_admin\",\"roles_access_user\"\]\nX-Jwt-Header-Role-Access-Colon:",
  "X-Jwt-Header-Role-Access-Dot:\nX-Jwt-Header-Role-Access-Colon: \[\"roles_access_admin\",\"roles_access_user\"\]",
  "X-Jwt-Header-Role-Access-Dot:\nX-Jwt-Header-Role-Access-Colon:"
]

=== set allow nested on server
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
auth_jwt "" token=$nested_jwt;
auth_jwt_allow_nested;
location / {
  auth_jwt_require_claim grants.access intersect json=["grants_access_admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /user {
  auth_jwt_require_claim grants.access intersect json=["grants_access_user"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request eval
[
  "GET /",
  "GET /user",
]
--- error_code eval
[
  200,
  200
]

=== set allow nested on location
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
auth_jwt "" token=$nested_jwt;
location / {
  auth_jwt_allow_nested;
  auth_jwt_require_claim grants.access intersect json=["grants_access_admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /no_nested {
  auth_jwt_require_claim grants.access intersect json=["grants_access_admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request eval
[
  "GET /",
  "GET /no_nested",
]
--- error_code eval
[
  200,
  401
]
