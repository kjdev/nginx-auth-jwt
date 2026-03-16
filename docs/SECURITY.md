# Security Considerations

This document describes security considerations and best practices for deploying nginx-auth-jwt.

## JWT Signature Verification

### Do Not Disable Signature Verification

The `auth_jwt_validate_sig` directive controls whether JWT signatures are verified.

```nginx
# INSECURE: never use in production
auth_jwt_validate_sig off;
```

Disabling signature verification means the module accepts any JWT payload without cryptographic validation. An attacker can craft arbitrary tokens and gain unauthorized access.

**Note:** There is no legitimate production use case for disabling signature verification. The `off` option exists only for testing and debugging.

### Claim Validation Without Signature Verification

Even when `auth_jwt_validate_sig off` is set, `auth_jwt_require_claim` continues to validate claims. However, this provides no security because any client can forge claim values in an unsigned token.

Always keep `auth_jwt_validate_sig on` (the default) in production.

## Key Management Best Practices

### Prefer JWKS Format

Use JWKS (JSON Web Key Set) format for key management. JWKS supports key rotation and multiple keys simultaneously.

```nginx
# Recommended: JWKS format
auth_jwt_key_file /etc/nginx/keys/jwks.json;

# Also supported: keyval format
auth_jwt_key_file /etc/nginx/keys/keys.json keyval;
```

### HMAC vs Asymmetric Keys

**HMAC (HS256/HS384/HS512):**
- The same secret is used for both signing and verification
- Any party holding the secret can forge tokens
- Use only when the token issuer and nginx are fully trusted and co-located

**RSA/ECDSA/EdDSA (RS*/PS*/ES*/EdDSA):**
- Asymmetric: private key signs, public key verifies
- nginx only needs the public key — it cannot forge tokens
- Preferred for multi-party or distributed deployments

### Remote Key Fetching with Caching

When using `auth_jwt_key_request`, always configure `proxy_cache` to avoid a subrequest on every request. Use `internal` to prevent external access to the key endpoint.

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
    }
}
```

**Note:** Always mark JWKS fetch locations as `internal` to prevent direct external access.

### Protect Key Files

Ensure key files are readable only by the nginx worker process:

```bash
chmod 640 /etc/nginx/keys/jwks.json
chown root:nginx /etc/nginx/keys/jwks.json
```

## DoS Defense Mechanisms

### Expected Value Size Limit

The module enforces a 4 KiB (4096-byte) limit on expected values in `auth_jwt_require_claim` and `auth_jwt_require_header`. This helps reduce abuse from excessively large comparison values.

Values exceeding this limit are rejected during request-time requirement evaluation.

### Content-Encoding Detection

When fetching keys via `auth_jwt_key_request`, the module rejects subrequest responses that include a `Content-Encoding` header. This prevents compressed responses from being misinterpreted as key material.

Configure the upstream key server to return uncompressed responses, or suppress compression in the proxy configuration:

```nginx
location = /jwks_uri {
    internal;
    proxy_pass http://idp.example.com/keys;
    # Prevent compressed responses
    proxy_set_header Accept-Encoding "";
}
```

### Subrequest In-Memory Read Limit

Key data fetched via `auth_jwt_key_request` is read entirely into memory within the nginx request processing pipeline. Avoid key endpoints that return excessively large responses.

## Input Validation

### Claim Comparison Types

When using `auth_jwt_require_claim`, be explicit about value types using the `json=` prefix for non-string types:

```nginx
# String comparison (unquoted value is treated as string)
auth_jwt_require_claim jti eq abc123;

# Integer comparison (use json= prefix)
auth_jwt_require_claim iat gt json=1700000000;

# Boolean comparison
auth_jwt_require_claim active eq json=true;

# Array intersection
auth_jwt_require_claim roles intersect json=["admin","editor"];
```

Without the `json=` prefix, all values are compared as strings. This can cause unexpected mismatches for numeric or boolean claims.

### Nested Claims

Enable nested claim access explicitly using `auth_jwt_allow_nested`:

```nginx
location /api/ {
    auth_jwt_allow_nested;
    auth_jwt_require_claim permissions.read eq allow;
}
```

Use the quote parameter to access claim names containing the delimiter character:

```nginx
auth_jwt_allow_nested delimiter=. quote=";
auth_jwt_require_claim '"parent.key"' eq value;
```

## Error Code Design

The module returns the following HTTP status codes:

- **401 Unauthorized**: Default error code. Returned when the token is missing, malformed, expired, signature verification fails, or claim/requirement checks fail.
- **403 Forbidden**: Returned when explicitly configured (e.g., `auth_jwt_require ... error=403`).

Use the `error` parameter in `auth_jwt_require` to explicitly return 403 when appropriate:

```nginx
auth_jwt_require $valid_role error=403;
```

Use `auth_jwt_revocation_list_sub` and `auth_jwt_revocation_list_kid` to deny specific tokens by `sub` or `kid`. Matching entries return 403.

## Known Limitations

- **Nested subrequest key fetching**: `auth_jwt_key_request` cannot be used when the module runs inside a subrequest. Use `auth_jwt_phase preaccess` or `auth_jwt_key_file` in these scenarios.

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Configuration examples
- [INSTALL.md](INSTALL.md): Installation guide
- [SECURITY.md](SECURITY.md): Security considerations
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial version compatibility
