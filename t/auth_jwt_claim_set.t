use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== set claim
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
auth_jwt_claim_set $jwt_id sub;
auth_jwt_claim_set $jwt_audience aud;
--- config
include $TEST_NGINX_CONF_DIR/jwt.conf;
location / {
  auth_jwt "" token=$test1_jwt;
  auth_jwt_key_file $TEST_NGINX_DATA_DIR/jwks.json;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
  add_header 'X-Jwt-Id' $jwt_id;
  add_header 'X-Jwt-Audience' $jwt_audience;
}
--- request
GET /
--- response_headers
X-Jwt-Claim-Iss: https://test1.issuer.example.com
X-Jwt-Claim-Sub: test1.identifier
X-Jwt-Claim-Aud: test1.audience.example.com
X-Jwt-Claim-Email: test1@example.com
X-Jwt-Id: test1.identifier
X-Jwt-Audience: test1.audience.example.com
--- error_code: 200

=== set claim on server
--- http_config
--- config
auth_jwt_claim_set $jwt_id sub;
auth_jwt_claim_set $jwt_audience aud;
--- must_die

=== set claim on location
--- http_config
--- config
location / {
  auth_jwt_claim_set $jwt_id sub;
  auth_jwt_claim_set $jwt_audience aud;
}
--- must_die
