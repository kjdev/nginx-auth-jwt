# Changelog

## [c3a5c95] - 2026-03-18

### Added

- Integrate JQ-like field paths into requirement validation
- Extend `ngx_http_auth_jwt_requirement_t` with parsed segments
- Parse JQ paths at config time, resolve at runtime directly from JSON tree

## [ddede12] - 2026-03-18

### Added

- Add JQ-like field path parser (`ngx_auth_jwt_field.h` / `.c`)
- Support `.key`, `."quoted.key"`, and `[N]` path syntax
- Two-pass parsing with `ngx_pool_t` memory management

## [4812dc8] - 2026-03-16

### Security

- Add size limit for expected values in claim validation to prevent abuse
- Add Content-Encoding detection to reject compressed payloads

## [9bf878b] - 2026-03-16

### Fixed

- Add `ngx_config.h` include and reorder headers for musl libc compatibility

## [89b893b] - 2026-03-16

### Changed

- Simplify cleanup handlers by leveraging pool-based memory management

## [516b95a] - 2026-03-16

### Changed

- Migrate JWT decode layer to `ngx_pool_t` memory management

## [497cd8b] - 2026-03-16

### Changed

- Migrate JWKS layer to `ngx_pool_t` memory management

## [4b3c87c] - 2026-03-13

### Fixed

- Replace `strsep` with `strstr` for correct multi-character delimiter support in nested claims

## [2490b72] - 2026-03-13

### Fixed

- Repair NULL check typo and memory leak in module configuration

## [ee90b82] - 2026-03-12

### Added

- Replace libjwt fork with a native JWKS/JWS implementation (`ngx_auth_jwt_jwks`, `ngx_auth_jwt_jws`)

## [0667525] - 2026-03-12

### Added

- Replace libjwt JWT decode with native `ngx_auth_jwt_decode` layer

## [67a556f] - 2026-03-12

### Added

- Add JSON abstraction layer `ngx_auth_jwt_json` wrapping jansson

## [b70c92e] - 2026-03-12

### Fixed

- JWS 2-pass verification with `kid`-based key lookup fallback and failure logging

## [6c95a46] - 2026-03-12

### Changed

- Improve operator layer with 3-value returns (`NGX_OK` / `NGX_DECLINED` / `NGX_ERROR`) and unified negation handling

## [a4e0269] - 2026-03-12

### Changed

- Rename source files and symbols to `ngx_auth_jwt_*` prefix convention

## [8677a21] - 2025-02-21

### Fixed

- Fix uninitialized struct field in `ngx_http_auth_jwt_set_bearer_header()`

## [bb676de] - 2024-12-09

### Added

- Add `limit_except` context support to all authentication directives

## [335c849] - 2024-11-12

### Changed

- Update libjwt source base to v1.17.2

## [311cde8] - 2024-03-26

### Added

- Add `auth_jwt_allow_nested` delimiter and quote setting directives for nested claim access

## [d9564d9] - 2024-03-28

### Changed

- Extend `auth_jwt_allow_nested` directive context to `http`, `server`, and `location`

## [c8cc690] - 2024-03-27

### Changed

- Improve invalid parameter error reporting in `auth_jwt_allow_nested` directive

## [9236b20] - 2023-12-27

### Added

- Add `auth_jwt_require` directive for flexible claim/header requirement expressions

## [ccb6f08] - 2023-12-27

### Added

- Add `auth_jwt_header_set` directive to set request headers from JWT claims

## [a9e94db] - 2023-12-26

### Changed

- Change scalar value handling for `intersect`/`nintersect` operator in `auth_jwt_require_claim`

## [82ece8e] - 2023-12-25

### Changed

- **BREAKING:** Change `exp` expected value handling in `auth_jwt_require_claim` directive

## [80507b0] - 2023-12-22

### Removed

- Remove `auth_jwt_validate_nbf` directive (use `auth_jwt_require` instead)

## [94b254a] - 2023-12-21

### Removed

- Remove `auth_jwt_validate_iat` directive (use `auth_jwt_require` instead)

## [fdf143f] - 2023-12-21

### Added

- Add `$jwt_nowtime` embedded variable providing current Unix timestamp

## [6158a77] - 2023-12-20

### Removed

- Remove `auth_jwt_validate_alg` directive (use `auth_jwt_require` instead)

## [22e6506] - 2023-12-20

### Removed

- Remove `auth_jwt_validate_iss` directive (use `auth_jwt_require` instead)

## [5f072f3] - 2023-12-20

### Removed

- Remove `auth_jwt_validate_sub` directive (use `auth_jwt_require` instead)

## [f04e813] - 2023-12-20

### Removed

- Remove `auth_jwt_validate_nonce` directive (use `auth_jwt_require` instead)

## [6d299db] - 2023-12-20

### Removed

- Remove `auth_jwt_validate_aud` directive (use `auth_jwt_require` instead)

## [2b12ef0] - 2023-12-04

### Added

- Add `auth_jwt_require_header` directive for JOSE header validation with operators

## [6479297] - 2023-12-04

### Added

- Add `auth_jwt_require_claim` directive for JWT claim validation with operators

## [39a34b3] - 2023-12-04

### Added

- Add `auth_jwt_revocation_list_kid` directive for kid-based key revocation

## [03ee5a6] - 2023-12-04

### Added

- Add `auth_jwt_revocation_list_sub` directive for sub-based token revocation

## [40c9191] - 2023-11-09

### Changed

- Update libjwt source base to v1.15.3

## [4ad19a0] - 2023-11-08

### Added

- Add `auth_jwt_validate_nonce` directive for nonce claim validation

## [68d6b9d] - 2023-11-08

### Added

- Add `auth_jwt_validate_nbf` directive for nbf claim validation

## [eec037f] - 2023-11-08

### Added

- Add `auth_jwt_validate_iat` directive for iat claim validation

## [11db170] - 2023-11-08

### Added

- Add `auth_jwt_validate_sub` directive for sub claim validation

## [6b92858] - 2023-11-08

### Added

- Add `auth_jwt_validate_iss` directive for iss claim validation

## [07304c9] - 2023-11-08

### Changed

- Change validation rules for exp claim

## [3feeca8] - 2023-11-07

### Added

- Add `auth_jwt_validate_aud` directive for aud claim validation

## [eb5b2a5] - 2023-10-04

### Fixed

- Fix segfault when using satisfy directive

## [e582471] - 2023-05-12

### Removed

- Remove `auth_jwt_token_nonce` directive

## [ed331ee] - 2023-03-16

### Fixed

- Fix memory leak in configuration handling

## [f83fe9d] - 2023-02-08

### Added

- Add `$jwt_claims` embedded variable returning all JWT claims as JSON

## [170e49a] - 2023-02-03

### Changed

- Update libjwt source base to v1.15.2

## [9c07833] - 2023-02-01

### Added

- Add JWK thumbprint key support

## [b88b4bf] - 2023-02-01

### Changed

- Fall back to other keys when kid-specified key is invalid

## [40986e4] - 2023-01-31

### Changed

- Make kid key in JWKS optional (no longer required)

## [de3cf55] - 2023-01-31

### Changed

- Validate signature when kid is not present in JWT header

## [618a65b] - 2023-01-30

### Changed

- Support decimal point values in exp claim validation

## [28abef3] - 2022-10-21

### Fixed

- Add error handling for missing kid in JWT header

## [806e34d] - 2022-10-05

### Added

- Initial release with JWT validation, JWKS/keyval key loading, `auth_jwt_claim_set`, `auth_jwt_key_file`, `auth_jwt_key_request`, `auth_jwt_validate_exp`, `auth_jwt_validate_sig`, `auth_jwt_leeway`, `auth_jwt_phase`, and `auth_jwt_allow_nested` directives

[c3a5c95]: https://github.com/kjdev/nginx-auth-jwt/commit/c3a5c95
[ddede12]: https://github.com/kjdev/nginx-auth-jwt/commit/ddede12
[4812dc8]: https://github.com/kjdev/nginx-auth-jwt/commit/4812dc8
[9bf878b]: https://github.com/kjdev/nginx-auth-jwt/commit/9bf878b
[89b893b]: https://github.com/kjdev/nginx-auth-jwt/commit/89b893b
[516b95a]: https://github.com/kjdev/nginx-auth-jwt/commit/516b95a
[497cd8b]: https://github.com/kjdev/nginx-auth-jwt/commit/497cd8b
[4b3c87c]: https://github.com/kjdev/nginx-auth-jwt/commit/4b3c87c
[2490b72]: https://github.com/kjdev/nginx-auth-jwt/commit/2490b72
[ee90b82]: https://github.com/kjdev/nginx-auth-jwt/commit/ee90b82
[0667525]: https://github.com/kjdev/nginx-auth-jwt/commit/0667525
[67a556f]: https://github.com/kjdev/nginx-auth-jwt/commit/67a556f
[b70c92e]: https://github.com/kjdev/nginx-auth-jwt/commit/b70c92e
[6c95a46]: https://github.com/kjdev/nginx-auth-jwt/commit/6c95a46
[a4e0269]: https://github.com/kjdev/nginx-auth-jwt/commit/a4e0269
[8677a21]: https://github.com/kjdev/nginx-auth-jwt/commit/8677a21
[bb676de]: https://github.com/kjdev/nginx-auth-jwt/commit/bb676de
[335c849]: https://github.com/kjdev/nginx-auth-jwt/commit/335c849
[311cde8]: https://github.com/kjdev/nginx-auth-jwt/commit/311cde8
[d9564d9]: https://github.com/kjdev/nginx-auth-jwt/commit/d9564d9
[c8cc690]: https://github.com/kjdev/nginx-auth-jwt/commit/c8cc690
[9236b20]: https://github.com/kjdev/nginx-auth-jwt/commit/9236b20
[ccb6f08]: https://github.com/kjdev/nginx-auth-jwt/commit/ccb6f08
[a9e94db]: https://github.com/kjdev/nginx-auth-jwt/commit/a9e94db
[82ece8e]: https://github.com/kjdev/nginx-auth-jwt/commit/82ece8e
[80507b0]: https://github.com/kjdev/nginx-auth-jwt/commit/80507b0
[94b254a]: https://github.com/kjdev/nginx-auth-jwt/commit/94b254a
[fdf143f]: https://github.com/kjdev/nginx-auth-jwt/commit/fdf143f
[6158a77]: https://github.com/kjdev/nginx-auth-jwt/commit/6158a77
[22e6506]: https://github.com/kjdev/nginx-auth-jwt/commit/22e6506
[5f072f3]: https://github.com/kjdev/nginx-auth-jwt/commit/5f072f3
[f04e813]: https://github.com/kjdev/nginx-auth-jwt/commit/f04e813
[6d299db]: https://github.com/kjdev/nginx-auth-jwt/commit/6d299db
[2b12ef0]: https://github.com/kjdev/nginx-auth-jwt/commit/2b12ef0
[6479297]: https://github.com/kjdev/nginx-auth-jwt/commit/6479297
[39a34b3]: https://github.com/kjdev/nginx-auth-jwt/commit/39a34b3
[03ee5a6]: https://github.com/kjdev/nginx-auth-jwt/commit/03ee5a6
[40c9191]: https://github.com/kjdev/nginx-auth-jwt/commit/40c9191
[4ad19a0]: https://github.com/kjdev/nginx-auth-jwt/commit/4ad19a0
[68d6b9d]: https://github.com/kjdev/nginx-auth-jwt/commit/68d6b9d
[eec037f]: https://github.com/kjdev/nginx-auth-jwt/commit/eec037f
[11db170]: https://github.com/kjdev/nginx-auth-jwt/commit/11db170
[6b92858]: https://github.com/kjdev/nginx-auth-jwt/commit/6b92858
[07304c9]: https://github.com/kjdev/nginx-auth-jwt/commit/07304c9
[3feeca8]: https://github.com/kjdev/nginx-auth-jwt/commit/3feeca8
[eb5b2a5]: https://github.com/kjdev/nginx-auth-jwt/commit/eb5b2a5
[e582471]: https://github.com/kjdev/nginx-auth-jwt/commit/e582471
[ed331ee]: https://github.com/kjdev/nginx-auth-jwt/commit/ed331ee
[f83fe9d]: https://github.com/kjdev/nginx-auth-jwt/commit/f83fe9d
[170e49a]: https://github.com/kjdev/nginx-auth-jwt/commit/170e49a
[9c07833]: https://github.com/kjdev/nginx-auth-jwt/commit/9c07833
[b88b4bf]: https://github.com/kjdev/nginx-auth-jwt/commit/b88b4bf
[40986e4]: https://github.com/kjdev/nginx-auth-jwt/commit/40986e4
[de3cf55]: https://github.com/kjdev/nginx-auth-jwt/commit/de3cf55
[618a65b]: https://github.com/kjdev/nginx-auth-jwt/commit/618a65b
[28abef3]: https://github.com/kjdev/nginx-auth-jwt/commit/28abef3
[806e34d]: https://github.com/kjdev/nginx-auth-jwt/commit/806e34d
