# Directives

This document describes all directives provided by the nginx-auth-jwt module for JWT authentication configuration.

## Configuration Examples

For complete configuration examples, see [EXAMPLES.md](EXAMPLES.md).

## Directives

| Directive | Context |
|-----------|---------|
| [auth_jwt](#auth_jwt) | http, server, location, limit_except |
| [auth_jwt_claim_set](#auth_jwt_claim_set) | http |
| [auth_jwt_header_set](#auth_jwt_header_set) | http |
| [auth_jwt_key_file](#auth_jwt_key_file) | http, server, location, limit_except |
| [auth_jwt_key_request](#auth_jwt_key_request) | http, server, location, limit_except |
| [auth_jwt_validate_exp](#auth_jwt_validate_exp) | http, server, location, limit_except |
| [auth_jwt_validate_sig](#auth_jwt_validate_sig) | http, server, location, limit_except |
| [auth_jwt_leeway](#auth_jwt_leeway) | http, server, location |
| [auth_jwt_phase](#auth_jwt_phase) | http, server, location |
| [auth_jwt_revocation_list_sub](#auth_jwt_revocation_list_sub) | http, server, location, limit_except |
| [auth_jwt_revocation_list_kid](#auth_jwt_revocation_list_kid) | http, server, location, limit_except |
| [auth_jwt_require](#auth_jwt_require) | http, server, location, limit_except |
| [auth_jwt_require_claim](#auth_jwt_require_claim) | http, server, location, limit_except |
| [auth_jwt_require_header](#auth_jwt_require_header) | http, server, location, limit_except |
| [auth_jwt_allow_nested](#auth_jwt_allow_nested) | http, server, location |

### auth_jwt

```
Syntax:  auth_jwt string [token=$variable] | off;
Default: auth_jwt off;
Context: http, server, location, limit_except
```

Enables validation of JSON Web Token. The specified string is used as a realm. Parameter value can contain variables.

The optional `token` parameter specifies a variable that contains JSON Web Token. By default, JWT is passed in the `Authorization` header as a [Bearer Token](https://datatracker.ietf.org/doc/html/rfc6750). JWT may also be passed as a cookie or part of a query string:

```nginx
auth_jwt "closed site" token=$cookie_auth_token;
```

The special value `off` cancels the effect of the `auth_jwt` directive inherited from the previous configuration level.

### auth_jwt_claim_set

```
Syntax:  auth_jwt_claim_set $variable name;
Default: -
Context: http
```

Sets the `$variable` to a JWT claim parameter identified by key name. For arrays, the variable keeps a list of array elements separated by commas.

```nginx
auth_jwt_claim_set $jwt_audience aud;
```

### auth_jwt_header_set

```
Syntax:  auth_jwt_header_set $variable name;
Default: -
Context: http
```

Sets the `$variable` to a JOSE header parameter identified by key name. For arrays, the variable keeps a list of array elements separated by commas.

### auth_jwt_key_file

```
Syntax:  auth_jwt_key_file file [jwks | keyval];
Default: -
Context: http, server, location, limit_except
```

Specifies a file for validating JWT signature. Parameter value can contain variables.

Specify `jwks` (default) or `keyval` as the file format:

- `jwks` — [JSON Web Key Set](https://datatracker.ietf.org/doc/html/rfc7517#section-5) format
- `keyval` — JSON in key-value format (e.g., `{"kid": "-----BEGIN PUBLIC KEY-----\nxx.."}`)

Multiple `auth_jwt_key_file` directives can be specified on the same level:

```nginx
auth_jwt_key_file conf/key.jwks;
auth_jwt_key_file conf/keys.json keyval;
```

### auth_jwt_key_request

```
Syntax:  auth_jwt_key_request uri [jwks | keyval];
Default: -
Context: http, server, location, limit_except
```

Allows retrieving a key from a subrequest for validating JWT signature and sets the URI where the subrequest will be sent to. Parameter value can contain variables.

Specify `jwks` (default) or `keyval` as the key format:

- `jwks` — [JSON Web Key Set](https://datatracker.ietf.org/doc/html/rfc7517#section-5) format
- `keyval` — JSON in key-value format

To avoid validation overhead, cache the key response using `proxy_cache`:

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

Multiple `auth_jwt_key_request` directives can be specified on the same level:

```nginx
auth_jwt_key_request /jwks_uri;
auth_jwt_key_request /public_key keyval;
```

### auth_jwt_validate_exp

```
Syntax:  auth_jwt_validate_exp on | off;
Default: auth_jwt_validate_exp on;
Context: http, server, location, limit_except
```

Determines whether to validate the `exp` JWT claim.

> Note: This directive has no effect if `exp` is already verified by the `auth_jwt_require_claim` directive.

### auth_jwt_validate_sig

```
Syntax:  auth_jwt_validate_sig on | off;
Default: auth_jwt_validate_sig on;
Context: http, server, location, limit_except
```

Determines whether to validate the JWT signature.

### auth_jwt_leeway

```
Syntax:  auth_jwt_leeway time;
Default: auth_jwt_leeway 0s;
Context: http, server, location
```

Sets the maximum allowable leeway to compensate for clock skew when verifying the `exp` and `nbf` JWT claims.

### auth_jwt_phase

```
Syntax:  auth_jwt_phase preaccess | access;
Default: auth_jwt_phase access;
Context: http, server, location
```

Specifies the nginx processing phase in which JWT authentication runs.

> Note: The ACCESS phase is not executed when called from a subrequest. When called from a subrequest, `auth_jwt_key_request` cannot be processed (nested in-memory subrequest).

### auth_jwt_revocation_list_sub

```
Syntax:  auth_jwt_revocation_list_sub file;
Default: -
Context: http, server, location, limit_except
```

Specifies a file containing a list of JWT `sub` claims that deny authentication. The file must be a JSON object where each key is a JWT `sub` value to block.

File format:

```json
{"sub": any}
```

Example configuration:

```nginx
auth_jwt_revocation_list_sub /path/to/lockeduserslist.json;
```

Example file:

```json
{
  "lockedsub1": {"locked_at": "2023"},
  "lockedsub2": {"locked_reason": "bad user"},
  "lockedsub3": {"any_other_property": 1}
}
```

### auth_jwt_revocation_list_kid

```
Syntax:  auth_jwt_revocation_list_kid file;
Default: -
Context: http, server, location, limit_except
```

Specifies a file containing a list of JWT `kid` (Key ID) header values that deny authentication. The file must be a JSON object where each key is a JWT `kid` value to revoke.

> Note: Per [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515#page-11), `kid` is an optional parameter. However, when this directive is used, `kid` becomes **required** in the JWT header.

File format:

```json
{"kid": any}
```

Example configuration:

```nginx
auth_jwt_revocation_list_kid /path/to/lockedkidlist.json;
```

Example file:

```json
{
  "test2kid": {"revocation_reason": "unknown"}
}
```

### auth_jwt_require

```
Syntax:  auth_jwt_require $value ... [error=code];
Default: -
Context: http, server, location, limit_except
```

Specifies additional checks for JWT validation. The value can contain text, variables, and their combination, and must start with a variable. Authentication succeeds only if all values are non-empty and not equal to `"0"`.

If any check fails, the 401 error code is returned. The optional `error` parameter allows redefining the error code to any HTTP status code in the range 400-599, excluding nginx internal codes 444 and 499.

```nginx
map $jwt_claim_iss $valid_jwt_iss {
    "good" 1;
}

location / {
    auth_jwt          "closed site";
    auth_jwt_key_file conf/keys.json;
    auth_jwt_require  $valid_jwt_iss;
}
```

### auth_jwt_require_claim

```
Syntax:  auth_jwt_require_claim claim_name operator $variable | json=string | string;
Default: -
Context: http, server, location, limit_except
```

Specifies a requirement for a claim in the JWT token. Multiple directives on the same level are evaluated with AND logic.

- `claim_name` — name of the JWT claim (e.g., `sub`, `roles`, `scope`)
- `operator` — comparison operator (see [Operators](#operators))
- value — one of:
  - `$variable` — an nginx variable containing a JSON value
  - `json=string` — a literal JSON value
  - `string` — a plain string value

```nginx
http {
  map $request_method $required_jwt_roles {
    "GET" '["SERVICE", "ADMINISTRATORS"]';
  }

  server {
    location = /verify {
      set $expected_iat 1697461110;

      auth_jwt_require_claim jti        eq 3949117906;
      auth_jwt_require_claim iat        eq json=1697461112;
      auth_jwt_require_claim iat        lt $expected_iat;
      auth_jwt_require_claim roles any $required_jwt_roles;

      # Regular expression match
      set $email_pattern '"@example\.com"';
      auth_jwt_require_claim email match $email_pattern;

      # Use \z for end-of-string anchor ($ conflicts with nginx variables)
      auth_jwt_require_claim sub match '\A[a-f0-9-]+\z';
    }
  }
}
```

#### JQ-like Field Paths

When `claim_name` (or `header_name`) begins with `.` or `[`, JQ-like field path syntax is used. This enables intuitive access to nested objects and arrays **without** requiring `auth_jwt_allow_nested`.

| Syntax | Description | Example |
|--------|-------------|---------|
| `.key` | Object key access | `.sub`, `.address.city` |
| `."quoted.key"` | Quoted key (for keys containing dots) | `."dotted.key"` |
| `[N]` | Array index access | `.roles[0]`, `.groups[1].name` |

```nginx
# Nested object access
auth_jwt_require_claim .address.city eq Tokyo;

# Array index access
auth_jwt_require_claim .roles[0] eq admin;

# Nested object + array
auth_jwt_require_claim .groups[0].name eq engineering;

# Quoted key (key contains dot)
auth_jwt_require_claim ."dotted.key" eq some_value;

# Nested array
auth_jwt_require_claim .matrix[0][1] eq json=2;

# Header access
auth_jwt_require_header .meta.version eq 2.0;
```

JQ-like paths and delimiter-based paths ([auth_jwt_allow_nested](#auth_jwt_allow_nested)) can coexist in the same configuration.

Invalid JQ-like path syntax is detected at nginx startup as a configuration error.

#### Operators

The following operators are available for use with `auth_jwt_require_claim` and `auth_jwt_require_header`:

| Operator | Description | Negation |
|----------|-------------|----------|
| `eq` | Equal | `!eq` |
| `gt` | Greater than | `!gt` |
| `ge` | Greater than or equal | `!ge` |
| `lt` | Less than | `!lt` |
| `le` | Less than or equal | `!le` |
| `in` | Value is in array or object | `!in` |
| `any` | Has intersection (arrays share at least one element) | `!any` |
| `match` | Regular expression match (PCRE) | `!match` |

Any operator can be negated by prefixing it with `!`. For example, `!eq` means "not equal" and `!any` means "has no intersection".

> **Note:** For the `match` operator, use `\A` and `\z` as anchors instead of `^` and `$`. The `$` character is interpreted as an nginx variable prefix and cannot be used in directive values.
> **Note:** A PCRE match limit (10,000 steps) is enforced for ReDoS defense. Patterns that cause excessive backtracking will be rejected due to match limit exceeded. Static patterns (literal values) are precompiled at config time for better performance.

**Backward-compatible aliases:**

| Alias | Equivalent |
|-------|------------|
| `ne` | `!eq` |
| `nin` | `!in` |
| `intersect` | `any` |
| `nintersect` | `!any` |

#### Comparison Rules

1. Two integer or real values are equal if their numeric values are equal. An integer value is never equal to a real value.
2. Two strings are equal if their UTF-8 content is identical byte by byte.
3. Two arrays are equal if they have the same number of elements and each element in the first array equals the corresponding element in the second array.
4. Two objects are equal if they have exactly the same keys and the value for each key in the first object equals the value of the corresponding key in the second object.

### auth_jwt_require_header

```
Syntax:  auth_jwt_require_header header_name operator $variable | json=string | string;
Default: -
Context: http, server, location, limit_except
```

Specifies a requirement for a JOSE header in the JWT token. All capabilities are the same as for [auth_jwt_require_claim](#auth_jwt_require_claim).

### auth_jwt_allow_nested

```
Syntax:  auth_jwt_allow_nested [delimiter=string] [quote=string];
Default: -
Context: http, server, location
```

Enables access to nested claims and headers in the JWT token using a delimiter-based path syntax.

> **Note:** For an alternative approach that supports array indexing, see [JQ-like Field Paths](#jq-like-field-paths) in the `auth_jwt_require_claim` section.

- `delimiter` — nesting delimiter character (default: `.`)
- `quote` — quote character for keys that contain the delimiter (default: `"`)

```nginx
auth_jwt_allow_nested;
auth_jwt_require_claim grants.access eq allow;
auth_jwt_require_claim '"grants.key"' eq dot;
```

JWT payload example:

```json
{
  "grants": {
    "access": "allow"
  },
  "grants.key": "dot"
}
```

## Embedded Variables

The module provides the following embedded variables:

| Variable | Description |
|----------|-------------|
| `$jwt_header_<name>` | Returns the value of the specified [JOSE header](https://datatracker.ietf.org/doc/html/rfc7515#section-4) |
| `$jwt_claim_<name>` | Returns the value of the specified [JWT claim](https://datatracker.ietf.org/doc/html/rfc7519#section-4). For arrays, elements are joined with commas |
| `$jwt_claims` | Returns all JWT claims as a JSON string |
| `$jwt_nowtime` | Returns the current Unix timestamp |

## Supported Algorithms

The module supports the following JWS algorithms:

| Family | Algorithms |
|--------|-----------|
| HMAC | HS256, HS384, HS512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES256, ES384, ES512, ES256K |
| EdDSA | EdDSA (Ed25519, Ed448) |

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Configuration examples
- [INSTALL.md](INSTALL.md): Installation guide
- [SECURITY.md](SECURITY.md): Security considerations
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial version compatibility
