# nginx auth_jwt Module

## Overview

### About This Module

This nginx module implements client authorization by validating the provided [JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) (JWT) using the specified keys.

The module supports [JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515) (JWS) and can be used for [OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html) authentication.

**Key features**:
- Validate JWT tokens from the Authorization header or custom variables
- Verify signatures using [JWKS](https://datatracker.ietf.org/doc/html/rfc7517#section-5) or key-value format keys (file or subrequest)
- Support HMAC, RSA, RSA-PSS, ECDSA, and EdDSA algorithms
- Validate JWT claims with operators (eq, gt, ge, lt, le, in, any, match, and `!` negation prefix)
- Validate [JOSE headers](https://datatracker.ietf.org/doc/html/rfc7515#section-4) with the same operators
- Revocation lists for sub claims and kid headers
- Access nested claims with configurable delimiters

**License**: MIT License

> This module is heavily inspired by the nginx original [http_auth_jwt_module](http://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html).

### Security

This module provides JWT signature verification and claim validation. See [SECURITY.md](docs/SECURITY.md) for security considerations.

### Relationship to the Commercial http_auth_jwt_module

This module provides functionality compatible with the [http_auth_jwt_module from the nginx commercial subscription](http://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html), plus additional features. See [COMMERCIAL_COMPATIBILITY.md](docs/COMMERCIAL_COMPATIBILITY.md) for details.

## Quick Start

See [INSTALL.md](docs/INSTALL.md) for installation instructions.

### Minimal Configuration

```nginx
location / {
    auth_jwt          "closed site";
    auth_jwt_key_file conf/keys.json;
}
```

### JWT from Cookie

```nginx
auth_jwt "closed site" token=$cookie_auth_token;
```

### Subrequest Key Fetch with Caching

```nginx
proxy_cache_path /data/nginx/cache levels=1 keys_zone=foo:10m;

server {
    location / {
        auth_jwt "closed site";
        auth_jwt_key_request /jwks_uri;
    }

    location = /jwks_uri {
        internal;
        proxy_cache foo;
        proxy_pass http://idp.example.com/keys;
    }
}
```

## Directives

This module provides the following directives. See [DIRECTIVES.md](docs/DIRECTIVES.md) for details.

| Directive | Function |
|---|---|
| `auth_jwt` | Enable JWT validation with realm and optional token source |
| `auth_jwt_claim_set` | Set variable to a JWT claim value |
| `auth_jwt_header_set` | Set variable to a JOSE header value |
| `auth_jwt_key_file` | Specify key file for signature verification (JWKS or keyval) |
| `auth_jwt_key_request` | Fetch key via subrequest for signature verification |
| `auth_jwt_validate_exp` | Enable/disable exp claim validation |
| `auth_jwt_validate_sig` | Enable/disable signature validation |
| `auth_jwt_leeway` | Set clock skew leeway for exp/nbf validation |
| `auth_jwt_phase` | Set processing phase (preaccess or access) |
| `auth_jwt_revocation_list_sub` | Specify sub claim revocation list file |
| `auth_jwt_revocation_list_kid` | Specify kid header revocation list file |
| `auth_jwt_require` | Specify additional variable checks |
| `auth_jwt_require_claim` | Validate JWT claims with operators ([JQ-like paths](docs/DIRECTIVES.md#jq-like-field-paths) supported) |
| `auth_jwt_require_header` | Validate JOSE headers with operators |
| `auth_jwt_allow_nested` | Enable nested claim/header access |

## Embedded Variables

This module provides the following nginx variables. See [DIRECTIVES.md](docs/DIRECTIVES.md#embedded-variables) for details.

| Variable | Description |
|----------|-------------|
| `$jwt_header_<name>` | Value of a specified JOSE header |
| `$jwt_claim_<name>` | Value of a specified JWT claim (arrays as comma-separated) |
| `$jwt_claims` | All JWT claims as JSON |
| `$jwt_nowtime` | Current timestamp |

## Appendix

### Supported Algorithms

The module supports the following [JWS algorithms](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms):

| Algorithm Family | Algorithms |
|-----------------|------------|
| HMAC | HS256, HS384, HS512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES256, ES384, ES512, ES256K |
| EdDSA | EdDSA (Ed25519, Ed448) |

### Standards References

- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519): JWT specification
- [RFC 7515 - JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515): JWS specification
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517): JWK specification
- [RFC 6750 - Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750): Bearer token specification
- [OpenID Connect Core 1.0](http://openid.net/specs/openid-connect-core-1_0.html): OpenID Connect specification

### TODO

- `auth_jwt_key_request` in subrequests (nested in-memory subrequest)

## Related Documentation

**Configuration & Operations**:

- [DIRECTIVES.md](docs/DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](docs/EXAMPLES.md): Configuration examples
- [INSTALL.md](docs/INSTALL.md): Installation guide (prerequisites, build instructions)
- [SECURITY.md](docs/SECURITY.md): Security considerations
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): Troubleshooting (common issues, log inspection)

**Reference**:

- [COMMERCIAL_COMPATIBILITY.md](docs/COMMERCIAL_COMPATIBILITY.md): Commercial http_auth_jwt_module compatibility
- [CHANGELOG.md](CHANGELOG.md): Changelog
- [OpenID Connect Authentication Example](example/README.md): OpenID Connect example
