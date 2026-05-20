use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== default (on) emits Bearer realm with error
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "test-realm";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- more_headers
Authorization: Bearer TOKEN
--- response_headers
WWW-Authenticate: Bearer realm="test-realm", error="invalid_token"
--- error_code: 401

=== explicit on emits Bearer realm with error
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "test-realm";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_www_authenticate on;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- more_headers
Authorization: Bearer TOKEN
--- response_headers
WWW-Authenticate: Bearer realm="test-realm", error="invalid_token"
--- error_code: 401

=== off suppresses header on invalid token
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "test-realm";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_www_authenticate off;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- more_headers
Authorization: Bearer TOKEN
--- response_headers
WWW-Authenticate:
--- error_code: 401

=== off suppresses header when token missing
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "test-realm";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_www_authenticate off;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
WWW-Authenticate:
--- error_code: 401

=== custom value not emitted when token missing
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "test-realm";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_www_authenticate 'Bearer error="missing"';
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
WWW-Authenticate:
--- error_code: 401

=== custom static value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "test-realm";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_www_authenticate 'Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", scope="mcp:read"';
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- more_headers
Authorization: Bearer TOKEN
--- response_headers
WWW-Authenticate: Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", scope="mcp:read"
--- error_code: 401

=== custom value with variable
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
set $mcp_scope "mcp:read";
set $mcp_metadata "https://rs.example.com/.well-known/oauth-protected-resource";
location / {
  auth_jwt "test-realm";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_www_authenticate 'Bearer resource_metadata="$mcp_metadata", scope="$mcp_scope"';
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- more_headers
Authorization: Bearer TOKEN
--- response_headers
WWW-Authenticate: Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", scope="mcp:read"
--- error_code: 401

=== off suppresses header through error_page named location
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location /mcp {
  auth_jwt "test-realm";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_www_authenticate off;
  error_page 401 = @mcp_unauthorized;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location @mcp_unauthorized {
  internal;
  add_header WWW-Authenticate 'Bearer resource_metadata="https://rs.example.com/meta", scope="mcp:read"' always;
  return 401;
}
--- request
GET /mcp
--- more_headers
Authorization: Bearer TOKEN
--- response_headers
WWW-Authenticate: Bearer resource_metadata="https://rs.example.com/meta", scope="mcp:read"
--- error_code: 401

=== inherit from server with location override
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
auth_jwt_www_authenticate off;
location / {
  auth_jwt "test-realm";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
location /strict {
  auth_jwt "strict-realm";
  auth_jwt_www_authenticate on;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request eval
[
  "GET /",
  "GET /strict"
]
--- more_headers eval
[
  "Authorization: Bearer TOKEN",
  "Authorization: Bearer TOKEN"
]
--- response_headers eval
[
  "WWW-Authenticate:",
  "WWW-Authenticate: Bearer realm=\"strict-realm\", error=\"invalid_token\""
]
--- error_code eval
[
  401,
  401
]

=== off on successful auth still suppresses header
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  auth_jwt_www_authenticate off;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
WWW-Authenticate:
--- error_code: 200
