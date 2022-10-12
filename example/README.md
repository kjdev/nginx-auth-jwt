Use example
===========

Reference implementation of NGINX Plus as relying party for
OpenID Connect authentication.

Google OpenID Connect authentication process based on
https://github.com/nginxinc/nginx-openid-connect scripts.

Dependency
----------

Required Nginx modules.

- [njs module](https://nginx.org/en/docs/njs/)
- [auth_jwt module](https://github.com/kjdev/nginx-auth-jwt)
  - https://github.com/kjdev/nginx-auth-jwt
  - use our own creation. (not a component of NGINX Plus)
- [key-value store](https://github.com/kjdev/nginx-keyval)
  - https://github.com/kjdev/nginx-keyval
  - use our own creation. (not a component of NGINX Plus)

Build Docker image
------------------

``` sh
$ docker build -t app .
```

Configuring
-----------

### Configuring auth_jwt module

#### Add signature verification algorithm specification

`frontend.conf`:

``` diff
         auth_jwt_key_request /_jwks_uri; # Enable when using URL
+        auth_jwt_validate_alg RS256;
```

#### Changed setting for ID token verification

- changed execution phase to PREACCESS
- skip signature verification

> Since the call is made in a subrequest.

`openid_connect.server_conf`:

``` diff
         #  https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
         internal;
         auth_jwt "" token=$arg_token;
+        auth_jwt_phase preaccess;
+        auth_jwt_validate_sig off;
         js_content oidc.validateIdToken;
```

#### Change the claim validation process

> `jwt_claim_<name>` is undefined if it does not exist.

`openid_connect.js`:

``` diff
 function validateIdToken(r) {
     // Check mandatory claims
     var required_claims = ["iat", "iss", "sub"]; // aud is checked separately
     var missing_claims = [];
     for (var i in required_claims) {
-        if (r.variables["jwt_claim_" + required_claims[i]].length == 0 ) {
+        var claim = r.variables["jwt_claim_" + required_claims[i]];
+        if (claim == undefined || claim.length == 0 ) {
             missing_claims.push(required_claims[i]);
         }
     }
```

#### Change `jwt_audience` to `jwt_claim_aud`

> `jwt_claim_<name>` will get a comma-separated string.
>
> It works the same way, so you don't have to modify it.

`openid_connect_configuration.conf`:

``` diff
-auth_jwt_claim_set $jwt_audience aud; # In case aud is an array
 js_import oidc from conf.d/openid_connect.js;
```

`openid_connect.js`:

``` diff
 function validateIdToken(r) {
     // Check mandatory claims
-    var required_claims = ["iat", "iss", "sub"]; // aud is checked separately
+    var required_claims = ["iat", "iss", "sub", "aud"];
     var missing_claims = [];
     for (var i in required_claims) {
         var claim = r.variables["jwt_claim_" + required_claims[i]];
         if (claim == undefined || claim.length == 0 ) {
             missing_claims.push(required_claims[i]);
         }
     }
-    if (r.variables.jwt_audience.length == 0) missing_claims.push("aud");
     if (missing_claims.length) {
@@ - + @@
     // Audience matching
-    var aud = r.variables.jwt_audience.split(",");
+    var aud = r.variables.jwt_claim_aud.split(",");
     if (!aud.includes(r.variables.oidc_client)) {
-        r.error("OIDC ID Token validation error: aud claim (" + r.variables.jwt_audience + ") does not include configured $oidc_client (" + r.variables.oidc_client + ")");
+        r.error("OIDC ID Token validation error: aud claim (" + r.variables.jwt_claim_aud + ") does not include configured $oidc_client (" + r.variables.oidc_client + ")");
         validToken = false;
```

### Configuring key-value store

#### Remove unsupported options

> `[state=file]` and `[timeout=time]` are not supported.

`openid_connect_configuration.conf`:

``` diff
 # Change timeout values to at least the validity period of each token type
-keyval_zone zone=oidc_id_tokens:1M state=conf.d/oidc_id_tokens.json timeout=1h;
-keyval_zone zone=refresh_tokens:1M state=conf.d/refresh_tokens.json timeout=8h;
-keyval_zone zone=oidc_pkce:128K timeout=90s; # Temporary storage for PKCE code verifier.
+keyval_zone zone=oidc_id_tokens:1M;
+keyval_zone zone=refresh_tokens:1M;
+keyval_zone zone=oidc_pkce:128K; # Temporary storage for PKCE code verifier.
```

### Delete Unsupported Configuration

#### Delete status_zone

`openid_connect.server_conf`:

``` diff
     location @do_oidc_flow {
-        status_zone "OIDC start";
@@ - + @@
     location = /_codexch {
         # This location is called by the IdP after successful authentication
-        status_zone "OIDC code exchange";
@@ - + @@
     location = /logout {
-        status_zone "OIDC logout";
@@ - + @@
     location @oidc_error {
         # This location is called when oidcAuth() or oidcCodeExchange() returns an error
-        status_zone "OIDC error";
```

#### Delete api

`openid_connect.server_conf`:

``` diff
-    location /api/ {
-        api write=on;
-        allow 127.0.0.1; # Only the NGINX host may call the NGINX Plus API
-        deny all;
-        access_log off;
-    }
```

### Setup backend server

`frontend.conf`:

``` diff
 upstream my_backend {
     zone my_backend 64k;
-    server 10.0.0.1:80;
+    server 127.0.0.1:8888;
+}
+
+server {
+    listen 8888;
+    location / {
+        add_header Content-Type 'text/plain charset=UTF-8';
+        return 200 "authenticate user name is $http_username\n";
+    }
 }
```

### Configuring Google OpenID Connect

> Modified to the execution environment

`openid_connect_configuration.conf`:

```
map $host $oidc_client {
    default "CLIENT_ID";
}

map $host $oidc_client_secret {
    default "CLIENT_SECRET";
}

map $host $oidc_scopes {
    default "openid+email";
}
```
