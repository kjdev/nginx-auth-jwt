# Troubleshooting

This document describes common issues and solutions for nginx-auth-jwt.

## Issue 1: JWT Validation Always Fails (401 Returned)

**Symptom:** All requests return 401 even with a valid JWT.

**Cause:** The JWT is not being sent in the correct format, or `auth_jwt` is not configured for the matching location.

**Solution:**

Verify the `Authorization` header format. The default method uses Bearer Token:

```bash
curl -H 'Authorization: Bearer <your-jwt-token>' https://example.com/protected
```

If the token is passed via a cookie or query parameter, configure the `token` parameter:

```nginx
# Cookie
auth_jwt "realm" token=$cookie_auth_token;

# Query parameter
auth_jwt "realm" token=$arg_token;
```

Check that `auth_jwt` is not accidentally set to `off` in a child location that overrides a parent configuration:

```nginx
server {
    auth_jwt "realm";
    auth_jwt_key_file /etc/nginx/keys/jwks.json;

    location /public {
        auth_jwt off;  # Explicitly disabled here
    }
}
```

## Issue 2: Key File Not Found

**Symptom:** nginx fails to start or logs show key file errors.

**Cause:** The path specified in `auth_jwt_key_file` does not exist or is not readable by the nginx worker process.

**Solution:**

Verify the file exists and check permissions:

```bash
ls -la /etc/nginx/keys/jwks.json
```

Ensure the nginx worker process can read the file:

```bash
chmod 640 /etc/nginx/keys/jwks.json
chown root:nginx /etc/nginx/keys/jwks.json
```

Validate the nginx configuration:

```bash
nginx -t
```

## Issue 3: Signature Verification Fails

**Symptom:** Requests return 401 with signature-related errors in the logs.

**Cause:** The key format does not match the JWT algorithm, or the key file is malformed.

**Solution:**

Check the key format. JWKS (default) and keyval formats have different structures:

```json
// JWKS format (jwks)
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "my-key-id",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

```json
// keyval format (keyval)
{
  "my-key-id": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

Specify the correct format explicitly in the directive:

```nginx
auth_jwt_key_file /etc/nginx/keys/jwks.json;         # JWKS (default)
auth_jwt_key_file /etc/nginx/keys/keys.json keyval;  # keyval
```

For HMAC algorithms, the keyval value must be the raw secret string (not PEM):

```json
{
  "my-hmac-key": "my-secret-value"
}
```

Ensure the `kid` in the JWT header matches a key in the key file. Enable debug logging to inspect key lookup behavior (see [Log Inspection](#log-inspection)).

## Issue 4: Claim Validation Fails

**Symptom:** Requests return 401 (or 403 if explicitly configured) even though the claim value appears correct.

**Cause:** Type mismatch between the expected value and the actual claim type in the JWT.

**Solution:**

Use the `json=` prefix for non-string types:

```nginx
# Wrong: compares integer claim as string "1697461112"
auth_jwt_require_claim iat eq 1697461112;

# Correct: compares as integer
auth_jwt_require_claim iat eq json=1697461112;
```

```nginx
# Wrong: compares boolean claim as string "true"
auth_jwt_require_claim active eq true;

# Correct: compares as boolean
auth_jwt_require_claim active eq json=true;
```

For array operations (`intersect`, `nintersect`, `in`, `nin`), use JSON array syntax:

```nginx
# Wrong: single string, not an array
auth_jwt_require_claim roles intersect admin;

# Correct: JSON array
auth_jwt_require_claim roles intersect json=["admin","editor"];
```

To inspect the actual claim values in the JWT, decode the token at [jwt.io](https://jwt.io) or use:

```bash
echo '<payload-part>' | base64 -d | python3 -m json.tool
```

## Issue 5: Subrequest Key Fetch Fails

**Symptom:** Requests fail when using `auth_jwt_key_request`, or key fetching is slow.

**Cause:** The subrequest endpoint is returning errors, is not `internal`, or responses are compressed.

**Solution:**

Mark the key fetch location as `internal` and configure caching:

```nginx
proxy_cache_path /data/nginx/cache levels=1 keys_zone=jwks_cache:10m;

server {
    location / {
        auth_jwt "protected";
        auth_jwt_key_request /jwks_uri;
    }

    location = /jwks_uri {
        internal;
        proxy_cache       jwks_cache;
        proxy_cache_valid 200 1h;
        proxy_pass        https://idp.example.com/.well-known/jwks.json;
        # Disable compression to avoid Content-Encoding errors
        proxy_set_header  Accept-Encoding "";
    }
}
```

If the upstream returns a compressed response, the module will reject it. Disable compression by setting `Accept-Encoding: ""` in the proxy request.

**Note:** `auth_jwt_key_request` cannot be used inside a subrequest. If the module is processing a subrequest context, use `auth_jwt_key_file` or set `auth_jwt_phase preaccess` instead.

## Issue 6: Nested Claims Not Working

**Symptom:** `auth_jwt_require_claim` with dot-notation fails even though the claim exists in the JWT payload.

**Cause:** `auth_jwt_allow_nested` is not configured.

**Solution:**

Add `auth_jwt_allow_nested` to the location or server block:

```nginx
location /api/ {
    auth_jwt_allow_nested;
    auth_jwt_require_claim user.role eq admin;
}
```

To access a claim name that literally contains the delimiter character, use the `quote` parameter:

```nginx
auth_jwt_allow_nested delimiter=. quote=';
# Access the claim literally named "user.role"
auth_jwt_require_claim 'user.role' eq admin;
```

**Note:** `auth_jwt_allow_nested` must be in the same or parent context as the `auth_jwt_require_claim` directive.

## Log Inspection

Enable debug logging to diagnose JWT validation issues:

```nginx
error_log /var/log/nginx/error.log debug;
```

Search for auth_jwt-related log entries:

```bash
grep 'auth_jwt' /var/log/nginx/error.log
```

Common log patterns to look for:

- `auth_jwt: token was not provided` — JWT not found in request
- `auth_jwt: failed to parse jwt token` — JWT structure is malformed
- `auth_jwt: rejected due to missing algorithm` — JOSE header `alg` missing
- `auth_jwt: rejected due to missing signature key or signature validate failure` — key mismatch or algorithm mismatch
- `auth_jwt: rejected due to %V variable invalid` — `auth_jwt_require` check failed
- `auth_jwt: rejected due to token expired` — `exp` claim is in the past

## Configuration Validation Errors

Always validate the nginx configuration before reloading:

```bash
nginx -t
```

Common configuration errors:

- **`auth_jwt_key_file` path not found**: Check file path and permissions
- **`auth_jwt_require_claim` invalid operator**: Use one of `eq ne gt ge lt le intersect nintersect in nin`
- **`auth_jwt_require_claim` value too large**: expected values are limited to 4 KiB (4096 bytes)

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Configuration examples
- [INSTALL.md](INSTALL.md): Installation guide
- [SECURITY.md](SECURITY.md): Security considerations
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial version compatibility
