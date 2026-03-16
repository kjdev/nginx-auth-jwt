# Commercial Version Compatibility

This document describes the compatibility between nginx-auth-jwt and the commercial nginx Plus module [ngx_http_auth_jwt_module](http://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html).

## Overview

nginx-auth-jwt is heavily inspired by the nginx Plus commercial JWT authentication module. It implements the core directives with compatible syntax and behavior, while also providing additional directives for extended functionality.

This module is an open-source dynamic module usable with open-source nginx. It does not require nginx Plus.

## Directive Compatibility

### Compatible Directives

The following directives are compatible with the commercial nginx Plus module:

| Commercial Directive | This Module | Notes |
|---|---|---|
| `auth_jwt` | `auth_jwt` | Fully compatible including `token=` parameter |
| `auth_jwt_claim_set` | `auth_jwt_claim_set` | Fully compatible |
| `auth_jwt_header_set` | `auth_jwt_header_set` | Fully compatible |
| `auth_jwt_key_file` | `auth_jwt_key_file` | Compatible; additionally supports `keyval` format |
| `auth_jwt_key_request` | `auth_jwt_key_request` | Compatible; additionally supports `keyval` format |
| `auth_jwt_leeway` | `auth_jwt_leeway` | Fully compatible |
| `auth_jwt_require` | `auth_jwt_require` | Fully compatible including `error=` parameter |

### Partially Compatible Directives

| Commercial Directive | This Module | Notes |
|---|---|---|
| `auth_jwt_key_cache` | — | Not supported; use `proxy_cache` with `auth_jwt_key_request` instead |

### Not Supported Directives

| Commercial Directive | Status | Notes |
|---|---|---|
| `auth_jwt_type` | Not supported | The commercial module supports `signed`, `encrypted`, `nested`. This module supports `signed` JWS tokens only |

### Embedded Variables

The following embedded variables are compatible:

| Commercial Variable | This Module | Notes |
|---|---|---|
| `$jwt_header_<name>` | `$jwt_header_<name>` | Fully compatible |
| `$jwt_claim_<name>` | `$jwt_claim_<name>` | Fully compatible |

This module provides the following additional variable not present in the commercial module:

| This Module Variable | Description |
|---|---|
| `$jwt_claims` | Full JWT claims as JSON string |
| `$jwt_nowtime` | Current Unix timestamp |

## Extensions (This Module Only)

The following directives are available in this module but have no equivalent in the commercial nginx Plus module:

### Validation Control

| Directive | Description |
|---|---|
| `auth_jwt_validate_exp` | Enable/disable `exp` claim validation (default: `on`) |
| `auth_jwt_validate_sig` | Enable/disable signature verification (default: `on`) |

### Processing Phase

| Directive | Description |
|---|---|
| `auth_jwt_phase` | Set processing phase to `preaccess` or `access` (default: `access`) |

### Token Revocation

| Directive | Description |
|---|---|
| `auth_jwt_revocation_list_sub` | Block tokens by `sub` claim using a JSON file |
| `auth_jwt_revocation_list_kid` | Block tokens by `kid` header using a JSON file |

### Advanced Claim Validation

| Directive | Description |
|---|---|
| `auth_jwt_require_claim` | Validate a JWT claim against a value using comparison operators |
| `auth_jwt_require_header` | Validate a JWT header against a value using comparison operators |
| `auth_jwt_allow_nested` | Enable dot-notation access to nested claims/headers |

The `auth_jwt_require_claim` and `auth_jwt_require_header` directives support the following operators:

| Operator | Description |
|---|---|
| `eq` | Equal |
| `ne` | Not equal |
| `gt` | Greater than |
| `ge` | Greater than or equal |
| `lt` | Less than |
| `le` | Less than or equal |
| `intersect` | Array has intersection |
| `nintersect` | Array has no intersection |
| `in` | Value is in array |
| `nin` | Value is not in array |

## Key Format Extensions

Both `auth_jwt_key_file` and `auth_jwt_key_request` support an additional `keyval` format not present in the commercial module:

```nginx
# JWKS format (compatible with commercial module, default)
auth_jwt_key_file /etc/nginx/keys/jwks.json;
auth_jwt_key_file /etc/nginx/keys/jwks.json jwks;

# keyval format (this module extension)
auth_jwt_key_file /etc/nginx/keys/keys.json keyval;
```

keyval format is a simple JSON object mapping key IDs to key values:

```json
{
  "key-id-1": "-----BEGIN PUBLIC KEY-----\n...",
  "hmac-key-1": "shared-secret-value"
}
```

## Algorithm Support

Both the commercial module and this module support:

- HS256, HS384, HS512
- RS256, RS384, RS512
- ES256, ES384, ES512

**Additional algorithms supported by this module:**

- PS256, PS384, PS512 (RSA-PSS)
- ES256K (ECDSA secp256k1)
- EdDSA (Ed25519, Ed448)

## Migration from Commercial Module

A configuration using only the compatible directives can be migrated to this module with no changes:

```nginx
# This configuration works with both the commercial module and nginx-auth-jwt
server {
    location / {
        auth_jwt          "protected area";
        auth_jwt_key_file /etc/nginx/keys/jwks.json;
        auth_jwt_leeway   10s;
    }
}
```

If the commercial configuration uses `auth_jwt_type`, the equivalent behavior in this module is:

- `auth_jwt_type signed` — default behavior, no change needed
- `auth_jwt_type encrypted` — not supported; JWE is not implemented
- `auth_jwt_type nested` — not supported as a type directive; use `auth_jwt_allow_nested` for nested claim access

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Configuration examples
- [INSTALL.md](INSTALL.md): Installation guide
- [SECURITY.md](SECURITY.md): Security considerations
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial version compatibility
