use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: operator nintersect returns 200 with array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
set $token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlcyI6WyJhZG1pbiIsInNlcnZpY2UiXX0.48TJcIdYaNyWlFhwGIR8ZPgn2-Chy-rpk3592OVL9A0";
#HEADER:ALGORITHM & TOKEN TYPE
#{
#  "alg": "HS256",
#  "typ": "JWT"
#}
#PAYLOAD:DATA
#{
#  "sub": "1234567890",
#  "name": "John Doe",
#  "iat": 1516239022,
#  "roles": ["admin", "service"]
#}
auth_jwt_validate_sig off; # to check only auth_jwt_require_claim we turn off default auth_jwt_validate_sig
auth_jwt_validate_exp off; # to check only auth_jwt_require_claim we turn off default auth_jwt_validate_exp

location / {
  set $expected_roles '["user_role1" , "user_role2", "user_role3"]';
  auth_jwt "" token=$token;
  auth_jwt_require_claim roles nintersect $expected_roles;
}
--- request
    GET /
--- error_code: 200

=== test: operator nintersect returns 401 with not nintersect array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
set $token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlcyI6WyJhZG1pbiIsInNlcnZpY2UiXX0.48TJcIdYaNyWlFhwGIR8ZPgn2-Chy-rpk3592OVL9A0";
#HEADER:ALGORITHM & TOKEN TYPE
#{
#  "alg": "HS256",
#  "typ": "JWT"
#}
#PAYLOAD:DATA
#{
#  "sub": "1234567890",
#  "name": "John Doe",
#  "iat": 1516239022,
#  "roles": ["admin", "service"]
#}
auth_jwt_validate_sig off; # to check only auth_jwt_require_claim we turn off default auth_jwt_validate_sig
auth_jwt_validate_exp off; # to check only auth_jwt_require_claim we turn off default auth_jwt_validate_exp

location / {
  set $expected_roles1 '["admin", "user_role1" , "user_role2"]';
  set $expected_roles2 '["admin", "service", "user_role1" , "user_role2"]';
  auth_jwt "" token=$token;
  auth_jwt_require_claim roles nintersect $expected_roles1;
  auth_jwt_require_claim roles nintersect $expected_roles2;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed requirement for "roles":  "["admin","service"]" is not "nintersect" "["admin", "user_role1" , "user_role2"]"

=== test: operator nintersect returns 401 with not array expected value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
set $token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlcyI6WyJhZG1pbiIsInNlcnZpY2UiXX0.48TJcIdYaNyWlFhwGIR8ZPgn2-Chy-rpk3592OVL9A0";
#HEADER:ALGORITHM & TOKEN TYPE
#{
#  "alg": "HS256",
#  "typ": "JWT"
#}
#PAYLOAD:DATA
#{
#  "sub": "1234567890",
#  "name": "John Doe",
#  "iat": 1516239022,
#  "roles": ["admin", "service"]
#}
auth_jwt_validate_sig off; # to check only auth_jwt_require_claim we turn off default auth_jwt_validate_sig
auth_jwt_validate_exp off; # to check only auth_jwt_require_claim we turn off default auth_jwt_validate_exp

location / {
  set $expected_roles '"just string"';
  auth_jwt "" token=$token;
  auth_jwt_require_claim roles nintersect $expected_roles;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed requirement for "roles":  "["admin","service"]" is not "nintersect" ""just string""

=== test: operator nintersect returns 401 with not array jwt claim value
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
set $token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlcyI6WyJhZG1pbiIsInNlcnZpY2UiXX0.48TJcIdYaNyWlFhwGIR8ZPgn2-Chy-rpk3592OVL9A0";
#HEADER:ALGORITHM & TOKEN TYPE
#{
#  "alg": "HS256",
#  "typ": "JWT"
#}
#PAYLOAD:DATA
#{
#  "sub": "1234567890",
#  "name": "John Doe",
#  "iat": 1516239022,
#  "roles": ["admin", "service"]
#}
auth_jwt_validate_sig off; # to check only auth_jwt_require_claim we turn off default auth_jwt_validate_sig
auth_jwt_validate_exp off; # to check only auth_jwt_require_claim we turn off default auth_jwt_validate_exp

location / {
  set $expected_roles '["user_role1" , "user_role2", "user_role3"]';
  auth_jwt "" token=$token;
  auth_jwt_require_claim name nintersect $expected_roles;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed requirement for "name":  ""John Doe"" is not "nintersect" "["user_role1" , "user_role2", "user_role3"]"