use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== authorization header
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3QxIn0.eyJpc3MiOiJodHRwczovL3Rlc3QxLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QxLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0MS5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyODYsImVtYWlsIjoidGVzdDFAZXhhbXBsZS5jb20ifQ.2b2m62IaWeY971ofeZuk7CsaG1RhM3Vukp5xSYGt3ak
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
WWW-Authenticate: Bearer realm=""
--- error_code: 200

=== no authorization header
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
--- error_code: 401
--- error_log: auth_jwt: token was not provided
--- log_level: info

=== variable token
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
set $jwt_token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCIsImtpZCI6InRlc3QyIn0.eyJpc3MiOiJodHRwczovL3Rlc3QyLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QyLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0Mi5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyOTIsImVtYWlsIjoidGVzdDJAZXhhbXBsZS5jb20ifQ.qnGFuYHDjWLPc_NxNl_e9iSVUrRf1RES_4au-kFlW3zszm1fYP07r2tY1v_g9HCp";
location / {
  auth_jwt "" token=$jwt_token;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test2.issuer.example.com
X-Jwt-Claim-Sub: test2.identifier
X-Jwt-Claim-Aud: test2.audience.example.com
X-Jwt-Claim-Email: test2@example.com
WWW-Authenticate:
--- error_code: 200

=== query token
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "" token=$arg_token;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6InRlc3QzIn0.eyJpc3MiOiJodHRwczovL3Rlc3QzLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QzLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0My5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyOTYsImVtYWlsIjoidGVzdDNAZXhhbXBsZS5jb20ifQ.DEMEn8uyNGKNGFSSOBs3WyyoYUioR4tTwmijqmpcFCWIsV9Zomv9FVqtnTAODWNL0XYilGwOHvZC6yWqiA-UGg
--- response_headers
X-Jwt-Claim-Iss: https://test3.issuer.example.com
X-Jwt-Claim-Sub: test3.identifier
X-Jwt-Claim-Aud: test3.audience.example.com
X-Jwt-Claim-Email: test3@example.com
WWW-Authenticate:
--- error_code: 200

=== no query token
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "" token=$arg_token;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
WWW-Authenticate:
--- error_code: 401
--- error_log: auth_jwt: token variable specified was not provided
--- log_level: error

=== cookie token
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "" token=$cookie_token;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- more_headers
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Q0In0.eyJpc3MiOiJodHRwczovL3Rlc3Q0Lmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3Q0LmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0NC5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTA3OTAsImVtYWlsIjoidGVzdDRAZXhhbXBsZS5jb20ifQ.hsM8VP1zyrUeZnszfKyqsbBZMSBPxJGTLMbjPrp1RfAJiMbIXvBxR_JUV0sEypgUI-pK08ff3VC9vVLBhOJcyHFrbbyRPRwfVZ3RjLqXMzXP98QjxaV42Qi_9QJUc66xfFfs87m_QVFHAwGWQfMNdm1LL3YJdY26kb5e0egD_b8g3MwL2wuxTVoIB0Fs6Mxc_URVXhmwLXyTiGba3mqhERGUlnY4xptSEgHO-kiHhB12t4rUfSoalUXjy_G3SKeZwW2raVd1FWeTGdNRgfBtSNOsHZBPqGqYuKNi_GGjUJ6F5E81kTlvtCYc0ujRUIWCGcZYiCs1VKgr8j80oWQhtg
--- response_headers
X-Jwt-Claim-Iss: https://test4.issuer.example.com
X-Jwt-Claim-Sub: test4.identifier
X-Jwt-Claim-Aud: test4.audience.example.com
X-Jwt-Claim-Email: test4@example.com
WWW-Authenticate:
--- error_code: 200

=== no cookie token
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "" token=$cookie_token;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
WWW-Authenticate:
--- error_code: 401
--- error_log: auth_jwt: token variable specified was not provided
--- log_level: error

=== invalid token
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "invalid token";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- more_headers
Authorization: Bearer TOKEN
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
WWW-Authenticate: Bearer realm="invalid token", error="invalid_token"
--- error_code: 401
--- error_log: auth_jwt: failed to parse jwt token
--- log_level: info

=== empty token
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- more_headers
Authorization: Bearer
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
WWW-Authenticate:
--- error_code: 401
--- error_log: auth_jwt: token was not provided
--- log_level: info

=== valid location with set multiple on server and location
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
auth_jwt "";
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$arg_token;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6InRlc3QzIn0.eyJpc3MiOiJodHRwczovL3Rlc3QzLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QzLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0My5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyOTYsImVtYWlsIjoidGVzdDNAZXhhbXBsZS5jb20ifQ.DEMEn8uyNGKNGFSSOBs3WyyoYUioR4tTwmijqmpcFCWIsV9Zomv9FVqtnTAODWNL0XYilGwOHvZC6yWqiA-UGg
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3QxIn0.eyJpc3MiOiJodHRwczovL3Rlc3QxLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QxLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0MS5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyODYsImVtYWlsIjoidGVzdDFAZXhhbXBsZS5jb20ifQ.2b2m62IaWeY971ofeZuk7CsaG1RhM3Vukp5xSYGt3ak
--- response_headers
X-Jwt-Claim-Iss: https://test3.issuer.example.com
X-Jwt-Claim-Sub: test3.identifier
X-Jwt-Claim-Aud: test3.audience.example.com
X-Jwt-Claim-Email: test3@example.com
WWW-Authenticate:
--- error_code: 200

=== invalid location with set multiple on server and location
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
auth_jwt "";
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt "" token=$arg_token;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /?token=
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3QxIn0.eyJpc3MiOiJodHRwczovL3Rlc3QxLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QxLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0MS5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyODYsImVtYWlsIjoidGVzdDFAZXhhbXBsZS5jb20ifQ.2b2m62IaWeY971ofeZuk7CsaG1RhM3Vukp5xSYGt3ak
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
WWW-Authenticate:
--- error_code: 401
--- error_log: auth_jwt: token was not provided
--- log_level: info

=== valid server with set multiple on http and server
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt "";
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
--- config
auth_jwt "" token=$arg_token;
location / {
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6InRlc3QzIn0.eyJpc3MiOiJodHRwczovL3Rlc3QzLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QzLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0My5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyOTYsImVtYWlsIjoidGVzdDNAZXhhbXBsZS5jb20ifQ.DEMEn8uyNGKNGFSSOBs3WyyoYUioR4tTwmijqmpcFCWIsV9Zomv9FVqtnTAODWNL0XYilGwOHvZC6yWqiA-UGg
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3QxIn0.eyJpc3MiOiJodHRwczovL3Rlc3QxLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QxLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0MS5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyODYsImVtYWlsIjoidGVzdDFAZXhhbXBsZS5jb20ifQ.2b2m62IaWeY971ofeZuk7CsaG1RhM3Vukp5xSYGt3ak
--- response_headers
X-Jwt-Claim-Iss: https://test3.issuer.example.com
X-Jwt-Claim-Sub: test3.identifier
X-Jwt-Claim-Aud: test3.audience.example.com
X-Jwt-Claim-Email: test3@example.com
WWW-Authenticate:
--- error_code: 200

=== invalid server with set multiple on http and server
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt "";
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
--- config
auth_jwt "" token=$arg_token;
location / {
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /?token=
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3QxIn0.eyJpc3MiOiJodHRwczovL3Rlc3QxLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QxLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0MS5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyODYsImVtYWlsIjoidGVzdDFAZXhhbXBsZS5jb20ifQ.2b2m62IaWeY971ofeZuk7CsaG1RhM3Vukp5xSYGt3ak
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
WWW-Authenticate:
--- error_code: 401
--- error_log: auth_jwt: token was not provided
--- log_level: info

=== valid location with set multiple on http and location
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt "";
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
--- config
location / {
  auth_jwt "" token=$arg_token;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6InRlc3QzIn0.eyJpc3MiOiJodHRwczovL3Rlc3QzLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QzLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0My5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyOTYsImVtYWlsIjoidGVzdDNAZXhhbXBsZS5jb20ifQ.DEMEn8uyNGKNGFSSOBs3WyyoYUioR4tTwmijqmpcFCWIsV9Zomv9FVqtnTAODWNL0XYilGwOHvZC6yWqiA-UGg
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3QxIn0.eyJpc3MiOiJodHRwczovL3Rlc3QxLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QxLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0MS5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyODYsImVtYWlsIjoidGVzdDFAZXhhbXBsZS5jb20ifQ.2b2m62IaWeY971ofeZuk7CsaG1RhM3Vukp5xSYGt3ak
--- response_headers
X-Jwt-Claim-Iss: https://test3.issuer.example.com
X-Jwt-Claim-Sub: test3.identifier
X-Jwt-Claim-Aud: test3.audience.example.com
X-Jwt-Claim-Email: test3@example.com
WWW-Authenticate:
--- error_code: 200

=== invalid location with set multiple on http and location
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt "";
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
--- config
location / {
  auth_jwt "" token=$arg_token;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /?token=
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3QxIn0.eyJpc3MiOiJodHRwczovL3Rlc3QxLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QxLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0MS5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyODYsImVtYWlsIjoidGVzdDFAZXhhbXBsZS5jb20ifQ.2b2m62IaWeY971ofeZuk7CsaG1RhM3Vukp5xSYGt3ak
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
WWW-Authenticate:
--- error_code: 401
--- error_log: auth_jwt: token was not provided
--- log_level: info

=== set off
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
auth_jwt "";
auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
location / {
  auth_jwt off;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3QxIn0.eyJpc3MiOiJodHRwczovL3Rlc3QxLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QxLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0MS5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyODYsImVtYWlsIjoidGVzdDFAZXhhbXBsZS5jb20ifQ.2b2m62IaWeY971ofeZuk7CsaG1RhM3Vukp5xSYGt3ak
--- response_headers
X-Jwt-Claim-Iss:
X-Jwt-Claim-Sub:
X-Jwt-Claim-Aud:
X-Jwt-Claim-Email:
WWW-Authenticate:
--- error_code: 200

=== exp claim of decimal point
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  add_header 'X-Jwt-Claim-Exp' $jwt_claim_exp;
  add_header 'X-Jwt-Claim-Iat' $jwt_claim_iat;
}
--- request
GET /
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3QxIn0.eyJpc3MiOiJodHRwczovL3Rlc3QxLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QxLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0MS5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAuODg4OTQxLCJpYXQiOiAxNjc1MDQ2MDgzLjg4ODk0MSwiZW1haWwiOiJ0ZXN0MUBleGFtcGxlLmNvbSJ9.c9ZHoWviBaQ8NiGhoWOx6IN9hsmJMBRztg22RHieEdM
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
X-Jwt-Claim-Exp: 4133862000.8889408
X-Jwt-Claim-Iat: 1675046083.888941
WWW-Authenticate: Bearer realm=""
--- error_code: 200

=== kid is not in the JWT header
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_jwt "";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJodHRwczovL3Rlc3QzLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QzLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0My5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NzUxMjA3MzIsImVtYWlsIjoidGVzdDNAZXhhbXBsZS5jb20ifQ.J2rN-QbckpUZ0PmoRT--AOtsOtpB1z-i049a1iKzv58Ax2qH5Vutsc1xMbzwk5D8DpMWECEc5WqIfJSYHoH-oA
--- response_headers
X-Jwt-Claim-Iss: https://test3.issuer.example.com
X-Jwt-Claim-Sub: test3.identifier
X-Jwt-Claim-Aud: test3.audience.example.com
X-Jwt-Claim-Email: test3@example.com
WWW-Authenticate: Bearer realm=""
--- error_code: 200

=== limit_except
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $http_x_id $jwt {
  "test1" $test1_jwt;
  "test2" $test2_jwt;
  default "";
}
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  limit_except GET {
    auth_jwt "" token=$jwt;
    auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  }
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request eval
[
  "GET /",
  "GET /",
  "POST /",
  "POST /"
]
--- more_headers eval
[
  "X-Id: empty",
  "X-Id: test1",
  "X-Id: empty",
  "X-Id: test2"
]
--- error_code eval
[
  200,
  200,
  401,
  200
]
