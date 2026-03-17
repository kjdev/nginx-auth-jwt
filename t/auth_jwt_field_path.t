use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== JQ path: basic key access (.sub)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .sub eq 1234567890;
}
--- request
GET /
--- error_code: 200

=== JQ path: nested object (.address.city)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .address.city eq Tokyo;
}
--- request
GET /
--- error_code: 200

=== JQ path: array index 0 (.roles[0])
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .roles[0] eq admin;
}
--- request
GET /
--- error_code: 200

=== JQ path: array index 1 (.roles[1])
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .roles[1] eq user;
}
--- request
GET /
--- error_code: 200

=== JQ path: nested object + array (.groups[0].name)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .groups[0].name eq engineering;
}
--- request
GET /
--- error_code: 200

=== JQ path: quoted key (."dotted.key")
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim ."dotted.key" eq dotted_value;
}
--- request
GET /
--- error_code: 200

=== JQ path: nested + quoted key (.nested."dotted.child")
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .nested."dotted.child" eq nested_dotted_value;
}
--- request
GET /
--- error_code: 200

=== JQ path: missing path returns 401
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .nonexistent.path eq something;
}
--- request
GET /
--- error_code: 401

=== JQ path: array out of bounds returns 401
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .roles[99] eq admin;
}
--- request
GET /
--- error_code: 401

=== JQ path: type mismatch - index on object returns 401
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .address[0] eq something;
}
--- request
GET /
--- error_code: 401

=== JQ path: type mismatch - key on array returns 401
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .roles.name eq something;
}
--- request
GET /
--- error_code: 401

=== JQ path: works without auth_jwt_allow_nested
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .address.city eq Tokyo;
  auth_jwt_require_claim .roles[0] eq admin;
}
--- request
GET /
--- error_code: 200

=== JQ path: coexist with delimiter path
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_allow_nested;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .address.city eq Tokyo;
  auth_jwt_require_claim address.city eq Tokyo;
}
--- request
GET /
--- error_code: 200

=== JQ path: header access (.meta.version)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_header .meta.version eq 2.0;
}
--- request
GET /
--- error_code: 200

=== JQ path: header array access (.meta.flags[0])
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_header .meta.flags[0] eq experimental;
}
--- request
GET /
--- error_code: 200

=== JQ path: nested array access (.matrix[0][1])
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .matrix[0][1] eq json=2;
}
--- request
GET /
--- error_code: 200

=== JQ path: integer comparison with json= prefix
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .groups[0].level eq json=1;
}
--- request
GET /
--- error_code: 200

=== JQ path: invalid syntax triggers config error
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$field_path_jwt;
  auth_jwt_require_claim .[invalid eq something;
}
--- must_die
