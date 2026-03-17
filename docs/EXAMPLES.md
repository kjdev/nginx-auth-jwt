# Configuration Examples

## Quick Start

### Minimal Configuration

Protect a location with JWT authentication using a local key file:

```nginx
location / {
    auth_jwt          "closed site";
    auth_jwt_key_file conf/keys.json;
}
```

## Configuration Examples by Use Case

### Token from Cookie or Query String

Pass the JWT via a cookie instead of the `Authorization` header:

```nginx
location / {
    auth_jwt          "closed site" token=$cookie_auth_token;
    auth_jwt_key_file conf/keys.json;
}
```

### Multiple Key Files

Specify multiple key files in different formats at the same level:

```nginx
location / {
    auth_jwt          "closed site";
    auth_jwt_key_file conf/key.jwks;
    auth_jwt_key_file conf/keys.json keyval;
}
```

### Key Request with Proxy Cache

Fetch keys dynamically from a remote IdP endpoint with caching to reduce overhead:

```nginx
proxy_cache_path /data/nginx/cache levels=1 keys_zone=foo:10m;

server {
    location / {
        auth_jwt          "closed site";
        auth_jwt_key_request /jwks_uri;
    }

    location = /jwks_uri {
        internal;
        proxy_cache foo;
        proxy_pass  http://idp.example.com/keys;
    }
}
```

### Revocation List by Subject

Deny authentication for specific JWT `sub` values using a revocation list file:

```nginx
location / {
    auth_jwt                     "closed site";
    auth_jwt_key_file            conf/keys.json;
    auth_jwt_revocation_list_sub /path/to/lockeduserslist.json;
}
```

The revocation list file format:

```json
{
    "lockedsub1": {"locked_at": "2023"},
    "lockedsub2": {"locked_reason": "bad user"}
}
```

### Required Claims Validation

Validate specific claim values using operators:

```nginx
http {
    map $request_method $required_jwt_roles {
        "GET" '["SERVICE", "ADMINISTRATORS"]';
    }

    server {
        location = /verify {
            set $expected_less_than_iat 1697461110;

            auth_jwt_require_claim jti  eq        3949117906;
            auth_jwt_require_claim iat  eq        json=1697461112;
            auth_jwt_require       iat  lt        $expected_less_than_iat;
            auth_jwt_require_claim roles intersect $required_jwt_roles;
        }
    }
}
```

### JWT Required Claims Validation Template

Validate standard JWT claims (`iss`, `sub`, `aud`, `exp`) for strict conformance:

```nginx
location / {
    auth_jwt          "closed site";
    auth_jwt_key_file conf/keys.json;

    # Validate exp automatically (default: on)
    auth_jwt_validate_exp on;

    # Require specific issuer
    auth_jwt_require_claim iss eq "https://idp.example.com";

    # Require non-empty subject
    auth_jwt_require $jwt_claim_sub;

    # Require specific audience
    auth_jwt_require_claim aud eq "myapp";
}
```

### Nested Claims

Access claims nested within JSON objects using dot notation:

```nginx
location / {
    auth_jwt          "closed site";
    auth_jwt_key_file conf/keys.json;

    auth_jwt_allow_nested;
    auth_jwt_require_claim grants.access eq allow;
    auth_jwt_require_claim '"grants.key"' eq dot;
}
```

For a JWT payload structured as:

```json
{
    "grants": {
        "access": "allow"
    },
    "grants.key": "dot"
}
```

### nginx map with auth_jwt_require

Use `map` to build conditional validation logic:

```nginx
map $jwt_claim_iss $valid_jwt_iss {
    "https://trusted-idp.example.com" 1;
}

server {
    location / {
        auth_jwt          "closed site";
        auth_jwt_key_file conf/keys.json;
        auth_jwt_require  $valid_jwt_iss;
    }
}
```

### OpenID Connect Integration

For a complete OpenID Connect authentication example including Google as an IdP,
refer to the [example/README.md](../example/README.md).

Key configuration adjustments for OpenID Connect subrequests:

```nginx
location = /_validate_token {
    internal;
    auth_jwt          "" token=$arg_token;
    auth_jwt_phase    preaccess;
    auth_jwt_validate_sig off;
}
```

### Comprehensive Configuration Example

A production-style configuration combining multiple features:

```nginx
http {
    proxy_cache_path /data/nginx/cache levels=1 keys_zone=jwks_cache:10m;

    map $jwt_claim_iss $valid_iss {
        "https://idp.example.com" 1;
    }

    map $request_method $required_roles {
        "GET"  '["reader", "admin"]';
        "POST" '["admin"]';
    }

    server {
        listen 443 ssl;

        location / {
            auth_jwt                     "api";
            auth_jwt_key_request         /jwks_uri;
            auth_jwt_validate_exp        on;
            auth_jwt_leeway              10s;
            auth_jwt_revocation_list_sub /etc/nginx/revoked_subs.json;

            auth_jwt_require       $valid_iss;
            auth_jwt_require_claim aud       eq        "myapi";
            auth_jwt_require_claim roles     intersect $required_roles;
        }

        # Simplified example. For production, consider adding:
        #   proxy_cache_valid 200 12h;
        #   proxy_cache_use_stale error timeout updating;
        # See example/ directory for a complete OIDC configuration.
        location = /jwks_uri {
            internal;
            proxy_cache     jwks_cache;
            proxy_cache_valid 200 1h;
            proxy_pass      http://idp.example.com/.well-known/jwks.json;
        }
    }
}
```

## JQ-like Field Paths

Access nested JWT claims and arrays using JQ-like path syntax. No `auth_jwt_allow_nested` directive is needed.

### Nested Object Access

```nginx
# JWT payload: {"address": {"city": "Tokyo", "zip": "100-0001"}}
location /api {
    auth_jwt "" token=$cookie_token;
    auth_jwt_key_file /etc/nginx/jwks.json;
    auth_jwt_require_claim .address.city eq Tokyo;
}
```

### Array Index Access

```nginx
# JWT payload: {"roles": ["admin", "user"], "groups": [{"name": "engineering"}]}
location /admin {
    auth_jwt "" token=$cookie_token;
    auth_jwt_key_file /etc/nginx/jwks.json;
    auth_jwt_require_claim .roles[0] eq admin;
    auth_jwt_require_claim .groups[0].name eq engineering;
}
```

### Quoted Keys (Keys Containing Dots)

```nginx
# JWT payload: {"dotted.key": "value", "nested": {"dotted.child": "nested_value"}}
location /dotted {
    auth_jwt "" token=$cookie_token;
    auth_jwt_key_file /etc/nginx/jwks.json;
    auth_jwt_require_claim ."dotted.key" eq value;
    auth_jwt_require_claim .nested."dotted.child" eq nested_value;
}
```

### Header Access with JQ Paths

```nginx
# JWT header: {"meta": {"version": "2.0"}}
location /versioned {
    auth_jwt "" token=$cookie_token;
    auth_jwt_key_file /etc/nginx/jwks.json;
    auth_jwt_require_header .meta.version eq 2.0;
}
```

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Configuration examples
- [INSTALL.md](INSTALL.md): Installation guide
- [SECURITY.md](SECURITY.md): Security considerations
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial version compatibility
