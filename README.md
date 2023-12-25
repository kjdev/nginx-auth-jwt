nginx-auth-jwt
==============

[JSON Web Token]: https://datatracker.ietf.org/doc/html/rfc7519
[JSON Web Signature]: https://datatracker.ietf.org/doc/html/rfc7515
[JSON Web Key Set]: https://datatracker.ietf.org/doc/html/rfc7517#section-5
[JOSE header]: https://datatracker.ietf.org/doc/html/rfc7515#section-4
[JWT claim]: https://datatracker.ietf.org/doc/html/rfc7519#section-4

This nginx module implements client authorization by validating the provided
[JSON Web Token][] (JWT) using the specified keys.

The module supports [JSON Web Signature][] (JWS).

The module can be used for
[OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html)
authentication.

> This modules is heavenly inspired by the nginx original
> [http_auth_jwt_module](http://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html).

Dependency
----------

- [jansson](http://www.digip.org/jansson/) header and library.
- [OpenSSL](http://www.openssl.org/) header and library.

Installation
------------

### Build install

``` sh
$ : "clone repository"
$ git clone https://github.com/kjdev/nginx-auth-jwt
$ cd nginx-auth-jwt
$ : "get nginx source"
$ NGINX_VERSION=1.x.x # specify nginx version
$ wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
$ tar -zxf nginx-${NGINX_VERSION}.tar.gz
$ cd nginx-${NGINX_VERSION}
$ : "build module"
$ ./configure --add-dynamic-module=../
$ make && make install
```

### Docker

``` sh
$ docker build -t nginx-auth-jwt .
$ : "app.conf: Create nginx configuration"
$ docker run -p 80:80 -v $PWD/app.conf:/etc/nginx/http.d/default.conf nginx-auth-jwt
```

> Github package: ghcr.io/kjdev/nginx-auth-jwt

Supported Algorithms
--------------------

The module supports the following JSON Web
[Algorithms](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms).

JWS algorithms:

- HS256, HS384, HS512
- RS256, RS384, RS512
- ES256, ES384, ES512
- ~~EdDSA (Ed25519 and Ed448 signatures)~~

Configuration
-------------

### Example

```
location / {
  auth_jwt          "closed site";
  auth_jwt_key_file conf/keys.json;
}
```

### Directives

```
Syntax: auth_jwt string [token=$variable] | off;
Default: auth_jwt off;
Context: server
Context: http, server, location
```

Enables validation of JSON Web Token. The specified string is used as a realm.
Parameter value can contain variables.

The optional `token` parameter specifies a variable that contains
JSON Web Token.
By default, JWT is passed in the `Authorization` header as a
[Bearer Token](https://datatracker.ietf.org/doc/html/rfc6750).
JWT may be also passed as a cookie or a part of a query string:

> ```
> auth_jwt "closed site" token=$cookie_auth_token;
> ```

The special value off cancels the effect of the auth_jwt directive inherited
from the previous configuration level.

```
Syntax: auth_jwt_claim_set $variable name ...;
Default: -
Context: http
```

Sets the `variable` to a JWT claim parameter identified by key names.
For arrays, the variable keeps a list of array elements separated by commas.

> ```
> auth_jwt_claim_set $jwt_audience aud;
> ```

```
Syntax: auth_jwt_key_file file [jwks | keyval];
Default: -
Context: http, server, location
```

Specifies a file for validating JWT signature.
Parameter value can contain variables.

Specify `jwks` (default) or `keyval` as the file format.

- jwks: [JSON Web Key Set][] format

- keyval: JSON in key-value format

  > Example: `{"kid": "-----BEGIN PUBLIC KEY-----\nxx.."}`

Several `auth_jwt_key_file` directives can be specified on the same level.

> ```
> auth_jwt_key_file conf/key.jwks;
> auth_jwt_key_file conf/keys.json keyval;
> ```

```
Syntax: auth_jwt_key_request uri [jwks | keyval];
Default: -
Context: http, server, location
```

Allows retrieving a key from a subrequest for validating JWT signature and
sets the URI where the subrequest will be sent to.
Parameter value can contain variables.

Specify `jwks` (default) or `keyval` as the key format.

- jwks: [JSON Web Key Set][] format

- keyval: JSON in key-value format

To avoid validation overhead, it is recommended to cache the key file:

> ```
> proxy_cache_path /data/nginx/cache levels=1 keys_zone=foo:10m;
>
> server {
>   ...
>   location / {
>     auth_jwt "closed site";
>     auth_jwt_key_request /jwks_uri;
>   }
>
>   location = /jwks_uri {
>     internal;
>     proxy_cache foo;
>     proxy_pass  http://idp.example.com/keys;
>   }
> }
> ```

Several `auth_jwt_key_request` directives can be specified on the same level.

> ```
> auth_jwt_key_request /jwks_uri;
> auth_jwt_key_request /public_key keyval;
> ```

```
Syntax: auth_jwt_validate_exp on | off;
Default: auth_jwt_validate_exp on;
Context: http, server, location
```

Determines whether to validating the exp JWT claim.

> Do not process if verified by `auth_jwt_require_claim` directive

```
Syntax: auth_jwt_validate_sig on | off;
Default: auth_jwt_validate_sig on;
Context: http, server, location
```

Determines whether to validating JWT signature.

```
Syntax: auth_jwt_leeway time;
Default: auth_jwt_leeway 0s;
Context: http, server, location
```

Sets the maximum allowable leeway to compensate clock skew
when verifying the exp and nbf JWT claims.

```
Syntax: auth_jwt_phase preaccess | access;
Default: auth_jwt_phase access;
Context: http, server, location
```

Specifies the phase to be processed.

> ACCESS phase is not executed when a call is made from a subrequest.
>
> In the case of a call from a subrequest, `auth_jwt_key_request` cannot
> be processed. (nested in-memory subrequest)

```
Syntax: auth_jwt_revocation_list_sub file;
Default: -
Context: http, server, location
```

Specifies a file with list of JWT sub claims that deny authentication.

Parameter value can contain only filepath to json file with objects.
Every object should have key(jwt sub) and any additional value, if it needed.

> File format:
> ```
> {"sub": any}
> ```

> Example of config:
> ```
> auth_jwt_revocation_list_sub /path/to/lockeduserslist.json;`
> ```

> Example of file:
> ```
> {
>   "lockedsub1": {"locked_at": "2023"},
>   "lockedsub2": {"locked_reason": "bad user"},
>   "lockedsub3": {"any_other_property": 1}
> }
> ```

```
Syntax: auth_jwt_revocation_list_kid file;
Default: -
Context: http, server, location
```

Specifies a file with list of JWT kid headers that deny authentication.

Parameter value can contain only filepath to json file with objects.
Every object should have key(jwt header kid) and any additional value,
if it needed.

> File format:
> ```
> {"kid": any}
> ```

> Example of config:
> ```
> auth_jwt_revocation_list_kid /path/to/lockedkidlist.json;`
> ```

> Example of file:
> ```
> {
>   "test2kid": {"revocation_reason": "unknown"}
> }
> ```

**Note:** as we know, kid is OPTIONAL parameter by
[rfc7515](https://datatracker.ietf.org/doc/html/rfc7515#page-11),
but if you are using auth_jwt_revocation_list_kid directive - it means,
that kid will grow to **REQUIRED**

```
Syntax: auth_jwt_require_claim claim_name operator $variable | json=string | string;
Default: -
Context: http, server, location
```

Specifies a requirement for claim in jwt token.

> Example:
> ```
> http {
>   map $request_method $required_jwt_roles {
>     "GET"  '["SERVICE", "ADMINISTRATORS"]';
>   }
>   server {
>     ...
>     location = /verify {
>       set $expected_less_than_iat 1697461110;
>
>       auth_jwt_require_claim jti eq 3949117906; # string
>       auth_jwt_require_claim iat eq json=1697461112; # integer
>       auth_jwt_require iat lt $expected_less_than_iat;
>       auth_jwt_require_claim roles intersect $required_jwt_roles;
>     }
>     ...
> ```

Several `auth_jwt_require_claim` directives can be specified
on the same level for "AND" logic.

`claim_name` - should be a name of jwt claim. (sub,roles,scope)

`operator` - should be one of:
```
eq = equal operator
ne = not equal operator
gt = greater than operator
ge = greater or equal operator
lt = less than operator
le = less or equal operator
intersect = has intersection operator
nintersect = has not intersection operator
in = in array operator
nin = not in array operator
```
1. Two integer or real values are equal if their contained numeric values
   are equal. An integer value is never equal to a real value, though.
2. Two strings are equal if their contained UTF-8 strings are equal,
   byte by byte. Unicode comparison algorithms are not implemented.
3. Two arrays are equal if they have the same number of elements and each
   element in the first array is equal to the corresponding element
   in the second array.
4. Two objects are equal if they have exactly the same keys and the value
   for each key in the first object is equal to the value of the
   corresponding key in the second object.

`$variable` - should be a nginx variable, that provide
required json[^json] value.

> Examples:
> ```
> set $expected_jti '"3949117906"';
> set $expected_iat 1697461112;
> set $expected_less_than_iat 1697461110;
> map $request_method $role_map_verify {
>   "GET"  '["SERVICE", "ADMINISTRATORS"]';
> }
> ```

[^json]: containing only single value is pretty valid.

```
Syntax: auth_jwt_require_header header_name operator $variable;
Default: -
Context: http, server, location
```
Specifies a requirement for header in jwt token.

All possibilities of this directive are the same as for
```auth_jwt_require_claim``` above.

### Embedded Variables

The module supports embedded variables:

```
$jwt_header_<name>
```

returns the value of a specified [JOSE header][].

```
$jwt_claim_<name>
```

Returns the value of a specified [JWT claim][].
For arrays, the variable keeps a list of array elements separated by commas.

```
$jwt_claims
```

Returns the value of [JWT claim][] (JSON).

```
$jwt_nowtime
```

Returns the value of now timestamp.

Example
-------

- [OpenID Connect Authentication](example/README.md)


TODO
----

- [ ] `auth_jwt_key_request` in subrequests (nested in-memory subrequest)
- Support algorithms
  - [ ] EdDSA (JWK key type: OKP)
