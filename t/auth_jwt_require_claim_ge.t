use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test: operator ge returns 200 with number
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
  set $expected_iat "1";
  auth_jwt "" token=$token;
  auth_jwt_require_claim iat ge $expected_iat;
}
--- request
    GET /
--- error_code: 200

=== test: operator ge returns 401 with string
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
  set $expected_iat '"1"';
  auth_jwt "" token=$token;
  auth_jwt_require_claim iat ge $expected_iat;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed requirement for "iat":  "1516239022" is not "ge" ""1""

=== test: operator ge returns 401 with not ge number
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
  set $expected_iat "9516239022";
  auth_jwt "" token=$token;
  auth_jwt_require_claim iat ge $expected_iat;
}
--- request
    GET /
--- error_code: 401
--- error_log
auth_jwt: failed requirement for "iat":  "1516239022" is not "ge" "9516239022"

=== test: operator ge returns 200 with equal number
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
  set $expected_iat "1516239022";
  auth_jwt "" token=$token;
  auth_jwt_require_claim iat ge $expected_iat;
}
--- request
    GET /
--- error_code: 200
