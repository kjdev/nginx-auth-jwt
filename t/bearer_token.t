use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== test1
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
set $test2_jwks $TEST_NGINX_DATA_DIR/test2.jwks;
set $test3_key $TEST_NGINX_DATA_DIR/test3.json;
set $test5_jwks /test5.jwks;
set $test6_key /test6.json;
location / {
  auth_jwt "test1";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/test1.jwks;
  auth_jwt_key_file $test2_jwks;
  auth_jwt_key_file $test3_key keyval;
  auth_jwt_key_request /test4.jwks;
  auth_jwt_key_request $test5_jwks;
  auth_jwt_key_request $test6_key keyval;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3QxIn0.eyJpc3MiOiJodHRwczovL3Rlc3QxLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QxLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0MS5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyODYsImVtYWlsIjoidGVzdDFAZXhhbXBsZS5jb20ifQ.2b2m62IaWeY971ofeZuk7CsaG1RhM3Vukp5xSYGt3ak
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
WWW-Authenticate: Bearer realm="test1"
--- error_code: 200

=== test2
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
set $test2_jwks $TEST_NGINX_DATA_DIR/test2.jwks;
set $test3_key $TEST_NGINX_DATA_DIR/test3.json;
set $test5_jwks /test5.jwks;
set $test6_key /test6.json;
location / {
  auth_jwt "test2";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/test1.jwks;
  auth_jwt_key_file $test2_jwks;
  auth_jwt_key_file $test3_key keyval;
  auth_jwt_key_request /test4.jwks;
  auth_jwt_key_request $test5_jwks;
  auth_jwt_key_request $test6_key keyval;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCIsImtpZCI6InRlc3QyIn0.eyJpc3MiOiJodHRwczovL3Rlc3QyLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QyLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0Mi5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyOTIsImVtYWlsIjoidGVzdDJAZXhhbXBsZS5jb20ifQ.qnGFuYHDjWLPc_NxNl_e9iSVUrRf1RES_4au-kFlW3zszm1fYP07r2tY1v_g9HCp
--- response_headers
X-Jwt-Claim-Iss: https://test2.issuer.example.com
X-Jwt-Claim-Sub: test2.identifier
X-Jwt-Claim-Aud: test2.audience.example.com
X-Jwt-Claim-Email: test2@example.com
WWW-Authenticate: Bearer realm="test2"
--- error_code: 200

=== test3
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
set $test2_jwks $TEST_NGINX_DATA_DIR/test2.jwks;
set $test3_key $TEST_NGINX_DATA_DIR/test3.json;
set $test5_jwks /test5.jwks;
set $test6_key /test6.json;
location / {
  auth_jwt "test3";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/test1.jwks;
  auth_jwt_key_file $test2_jwks;
  auth_jwt_key_file $test3_key keyval;
  auth_jwt_key_request /test4.jwks;
  auth_jwt_key_request $test5_jwks;
  auth_jwt_key_request $test6_key keyval;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6InRlc3QzIn0.eyJpc3MiOiJodHRwczovL3Rlc3QzLmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QzLmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0My5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTIyOTYsImVtYWlsIjoidGVzdDNAZXhhbXBsZS5jb20ifQ.DEMEn8uyNGKNGFSSOBs3WyyoYUioR4tTwmijqmpcFCWIsV9Zomv9FVqtnTAODWNL0XYilGwOHvZC6yWqiA-UGg
--- response_headers
X-Jwt-Claim-Iss: https://test3.issuer.example.com
X-Jwt-Claim-Sub: test3.identifier
X-Jwt-Claim-Aud: test3.audience.example.com
X-Jwt-Claim-Email: test3@example.com
WWW-Authenticate: Bearer realm="test3"
--- error_code: 200

=== test4
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
set $test2_jwks $TEST_NGINX_DATA_DIR/test2.jwks;
set $test3_key $TEST_NGINX_DATA_DIR/test3.json;
set $test5_jwks /test5.jwks;
set $test6_key /test6.json;
location / {
  auth_jwt "test4";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/test1.jwks;
  auth_jwt_key_file $test2_jwks;
  auth_jwt_key_file $test3_key keyval;
  auth_jwt_key_request /test4.jwks;
  auth_jwt_key_request $test5_jwks;
  auth_jwt_key_request $test6_key keyval;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Q0In0.eyJpc3MiOiJodHRwczovL3Rlc3Q0Lmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3Q0LmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0NC5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTA3OTAsImVtYWlsIjoidGVzdDRAZXhhbXBsZS5jb20ifQ.hsM8VP1zyrUeZnszfKyqsbBZMSBPxJGTLMbjPrp1RfAJiMbIXvBxR_JUV0sEypgUI-pK08ff3VC9vVLBhOJcyHFrbbyRPRwfVZ3RjLqXMzXP98QjxaV42Qi_9QJUc66xfFfs87m_QVFHAwGWQfMNdm1LL3YJdY26kb5e0egD_b8g3MwL2wuxTVoIB0Fs6Mxc_URVXhmwLXyTiGba3mqhERGUlnY4xptSEgHO-kiHhB12t4rUfSoalUXjy_G3SKeZwW2raVd1FWeTGdNRgfBtSNOsHZBPqGqYuKNi_GGjUJ6F5E81kTlvtCYc0ujRUIWCGcZYiCs1VKgr8j80oWQhtg
--- response_headers
X-Jwt-Claim-Iss: https://test4.issuer.example.com
X-Jwt-Claim-Sub: test4.identifier
X-Jwt-Claim-Aud: test4.audience.example.com
X-Jwt-Claim-Email: test4@example.com
WWW-Authenticate: Bearer realm="test4"
--- error_code: 200

=== test5
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
set $test2_jwks $TEST_NGINX_DATA_DIR/test2.jwks;
set $test3_key $TEST_NGINX_DATA_DIR/test3.json;
set $test5_jwks /test5.jwks;
set $test6_key /test6.json;
location / {
  auth_jwt "test5";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/test1.jwks;
  auth_jwt_key_file $test2_jwks;
  auth_jwt_key_file $test3_key keyval;
  auth_jwt_key_request /test4.jwks;
  auth_jwt_key_request $test5_jwks;
  auth_jwt_key_request $test6_key keyval;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCIsImtpZCI6InRlc3Q1In0.eyJpc3MiOiJodHRwczovL3Rlc3Q1Lmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3Q1LmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0NS5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTA3ODQsImVtYWlsIjoidGVzdDVAZXhhbXBsZS5jb20ifQ.f7ktmyoYu1BUgCrdvdG1KV8KF1NjeMCXhijq_loY6574uiUws48rEuNcpVM4MNUa001dtmr_JyVwasmus08G-MJPdFD6GAs8oj1WdmqAdVqTCJp2vL68pIq-p5thhMLgzJ_WX6o5ISezHS-A1MR0PaAVHUWE2FCwtnSqbwomrZ6emRNoXPZDixXkSD3fYiim2lucH91fhh6ambgGjjEBg9dTo_IfNACN2mZNyWGP99oW_7H8IECMKpS7acoxsZV-bucyzTLEtLMvbpxAJ9P8W7lHWBSGVSAfv0BVqkKxe0yBH_IaaIpKR6mpoakQ16Mbh2BCUrPLosLrmf9E2qJMmQ
--- response_headers
X-Jwt-Claim-Iss: https://test5.issuer.example.com
X-Jwt-Claim-Sub: test5.identifier
X-Jwt-Claim-Aud: test5.audience.example.com
X-Jwt-Claim-Email: test5@example.com
WWW-Authenticate: Bearer realm="test5"
--- error_code: 200

=== test6
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
set $test2_jwks $TEST_NGINX_DATA_DIR/test2.jwks;
set $test3_key $TEST_NGINX_DATA_DIR/test3.json;
set $test5_jwks /test5.jwks;
set $test6_key /test6.json;
location / {
  auth_jwt "test6";
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/test1.jwks;
  auth_jwt_key_file $test2_jwks;
  auth_jwt_key_file $test3_key keyval;
  auth_jwt_key_request /test4.jwks;
  auth_jwt_key_request $test5_jwks;
  auth_jwt_key_request $test6_key keyval;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
set $data_dir $TEST_NGINX_DATA_DIR;
include $TEST_NGINX_CONF_DIR/key.conf;
--- request
GET /
--- more_headers
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImtpZCI6InRlc3Q2In0.eyJpc3MiOiJodHRwczovL3Rlc3Q2Lmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3Q2LmlkZW50aWZpZXIiLCJhdWQiOiJ0ZXN0Ni5hdWRpZW5jZS5leGFtcGxlLmNvbSIsImV4cCI6IDQxMzM4NjIwMDAsImlhdCI6IDE2NjI1MTA3NzgsImVtYWlsIjoidGVzdDZAZXhhbXBsZS5jb20ifQ.ntk0Jy_EmbnFOjA3CIitb33eX6YwMYmDrYSbWh4tyXs4B7n3Rb8N3J3bW124h9e27lI_rJKijkhYdi-gOJKjeW1RzppjGWZxryyV1oPwhMV3_Vzbqp-biprm_ukC3ZIEzJT8HlmPoYGTfknhLxKOsi5JZ8oMFFf29cmrNGPMiunbo7jZbJPzNq3qU4syPXcszE-0tH_y1BtuVDhtXlRgKW1vU0Jy_UYJ6wDUfWY_DBTr8tSi_ESGtsVjppRvkYnMYkMReQ-JSHd5mDuTCe33EMHAkKG5N57rwYF6G6COqwenoPJ1lNg2_psGuEsdOKcXevu9PShD8FtZHD53C-Dq6w
--- response_headers
X-Jwt-Claim-Iss: https://test6.issuer.example.com
X-Jwt-Claim-Sub: test6.identifier
X-Jwt-Claim-Aud: test6.audience.example.com
X-Jwt-Claim-Email: test6@example.com
WWW-Authenticate: Bearer realm="test6"
--- error_code: 200
