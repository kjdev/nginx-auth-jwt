# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.14.1] - 2026-06-15

### Security

- Scope the signature / exp validation relaxation to the request to fix an authentication bypass. `ngx_http_auth_jwt_validate_requirement()` cleared `cf->validate.sig` / `cf->validate.exp` on the worker-shared `loc_conf` when a matching alg or exp requirement was met. Because the `loc_conf` is treated as read-only during request processing, the cleared flags persisted to every later request on that worker until reload. With an alg requirement that allows both `none` and a signing algorithm (e.g. `alg in [RS256, none]`), a single `alg=none` token permanently set `validate.sig` to 0, after which forged RS256 tokens passed signature verification unchecked and bypassed authentication. The fix snapshots `cf->validate.sig` / `exp` into request-scoped ctx fields at the entry of `ngx_http_auth_jwt_validate()` and routes the requirement relaxation and the built-in exp / sig checks through ctx, so the `loc_conf` is never mutated

## [0.14.0] - 2026-06-03

### Changed

- Bump the submodules to nxe-json 0.5.0 / nxe-jwx 0.2.0, raising the minimum requirements to nxe-json >= 0.5.0 and nxe-jwx >= 0.2.0. nxe-json 0.5.0 promotes the NUL-termination of the `ngx_str_t.data` returned by `nxe_json_string` (`data[len] == '\0'`) to a public contract, and nxe-jwx 0.2.0 documents in its header that `nxe_jwx_token_alg` / `nxe_jwx_token_kid` inherit that contract. This makes the places in `ngx_http_auth_jwt_module.c` that pass `ngx_str_t.data` to C string APIs (`ngx_strcmp`, etc.) for the `alg` / `kid` / revocation-list `sub` comparisons rest on a published contract rather than an implicit dependency on jansson implementation details. No module source changes are involved — only the dependency version pins and the contract being made explicit

### Fixed

- Restore last-file-wins precedence for a key duplicated across repeated `auth_jwt_revocation_list_sub` / `_kid` directives in the same block. Since the nxe-json migration ([42f305c](commit/42f305c)) each file parses into a separate tree appended in load order, and the validator stops at the first matching tree, so a duplicate key resolved to the earliest file — reversing the old `json_object_set_new` overwrite (last-file-wins) semantics and making that commit's "behavior is preserved" claim inaccurate. The revocation value is only used to build the rejection log line; the reject decision is union membership and order-independent, so authentication outcomes were never affected — only the logged value for the rare duplicate-across-files case flipped. `ngx_http_auth_jwt_fill_revocation_list_by_file` now inserts each newly parsed tree at the front of the array (`ngx_memmove` shifting the existing pointers back), so first-match resolves to the latest file again. Merge is unchanged — it still appends parent trees after the child's — so child blocks keep precedence over parent blocks
- Remove the last direct jansson dependency in the Layer 1 module (`ngx_http_auth_jwt_module.c`) and drop `#include <jansson.h>`. The requirement-comparison path was already on nxe-json; the remaining holdout was the `auth_jwt_revocation_list_sub` / `_kid` handling. The revocation storage is redesigned from a jansson object (`json_t *`) to an `ngx_array_t` of parsed `nxe_json_t *` object trees, one per loaded file. nxe-json 0.5.0 has no object-construction / merge API, so the multi-file accumulation that `json_object_set_new` provided is now a union over the tree array, and membership lookups query each tree with `nxe_json_object_get_ns` (a binary-safe hash lookup via jansson's `json_object_getn`). File loading moves from `json_load_file` to an own read (`ngx_open_file` / `ngx_read_fd`) + `nxe_json_parse`, mirroring the keystore file path. Lookup moves from `json_object_foreach` / `json_dumps` to `nxe_json_object_get_ns` / `nxe_json_stringify_compact`, so key matching moves from a NUL-terminated `ngx_strcmp` linear scan to a binary-safe hash lookup that takes the `ngx_str_t` directly. Merge moves from `json_object_update_missing` / `json_copy` to an array union (child trees first, so a child value wins for a key present in both blocks, matching the previous update-missing semantics). For freeing, instead of a per-`loc_conf` cleanup calling `json_delete`, each tree registers a per-tree pool cleanup (`nxe_json_free`) on `cf->pool` at parse time; every tree is freed exactly once on cycle teardown / reload regardless of how many configs reference it after merge, so sharing tree pointers across configs never double-frees. The `ngx_http_auth_jwt_revocation_cleanup` handler and its `create_loc_conf` registration are removed, subsuming the prior reload-leak fix. Behavior is preserved: an empty `{}` loads as an empty list, a 0-byte or non-object file is rejected at config time, and the rejection log lines keep their `sub="..."` / `kid="..."` form. The log value is now encoded with `JSON_ENCODE_ANY`, so scalar revocation values serialize instead of being dropped
- Unify the request-time JSON parsing in `ngx_http_auth_jwt_validate_requirement` (the JWT payload and `json=` user input) from jansson's direct `json_loads` / `json_loadb` calls onto `nxe_json_parse_untrusted`, applying the DoS protections (max depth / array size / string length / object keys) that were previously missing. This also removes the cast of `nxe_json_t` (`typedef void`) to `json_t *` and back that only worked by coincidence. Concretely, `jwt_value_json` / `expected_json` are typed as `nxe_json_t *`, and `json_loads` / `json_loadb` -> `nxe_json_parse_untrusted`, `json_stringn` -> `nxe_json_from_string`, `json_is_number` -> `nxe_json_is_integer || nxe_json_is_real`, `json_integer` -> `nxe_json_from_integer`, `json_delete` -> `nxe_json_free`. `ngx_auth_jwt_operator_validate` already takes `nxe_json_t *`, so matching the caller types removes the cast-based type boundary. Behavior is preserved: the non-`json` expected value stays a string node, so the nbf / exp integer rebuild still happens only when `json=` supplies a number. The structural limits now also apply to `json=` expected values, so an extreme structure (for example an array of 101+ elements) is rejected — this is the intended DoS protection
- Stop the master process from leaking the revocation lists across config reloads. The `auth_jwt_revocation_list_sub` / `auth_jwt_revocation_list_kid` lists are jansson objects (malloc-based, not allocated from an nginx pool), so a plain pool teardown never reclaimed them; they were only released by the `exit_process` handler, which runs on worker exit and only ever freed the http-level (main) `loc_conf`. On `nginx -s reload` the master destroys the old cycle's pool (`ngx_init_cycle` -> `ngx_destroy_pool(old_cycle->pool)`), but that does not `json_delete` the lists, so each reload leaked them in a long-lived master — and server / location level lists were missed even in workers. The lists are now freed by a per-`loc_conf` `ngx_pool_cleanup` registered in `create_loc_conf` (used rather than `merge_loc_conf`, which is only invoked with the server / location `loc_conf` as the child, never the http-main one), so the cleanup runs on both worker exit and master old-cycle teardown and covers every block. The now-empty `exit_process` hook and its module slot are removed. Keysets are unchanged: `nxe_jwx_jwks_parse` already registers per-keyset pool cleanups that free each `EVP_PKEY` on the same teardown path. Verified with valgrind (5 reloads + quit): the master reports 0 definitely/indirectly lost, down from 864 bytes in 12 blocks

## [0.13.1] - 2026-05-21

### Fixed

- Scope the `auth_jwt_require` `error=` parameter to its own directive. Previously the parsed error code was stored on a single location-wide field (`lcf->validate.variable.error`), so writing two directives such as `auth_jwt_require $aud_ok;` followed by `auth_jwt_require $scope_ok error=403;` made the second directive overwrite the first one's default 401 — a failed `$aud_ok` check returned 403, and the merge step inherited the same overwrite across nested locations. The require entries now hold their own `error` field (`ngx_http_auth_jwt_require_variable_t = { complex_value, error_code }`), the parser writes the directive-local `error=` (or the `NGX_HTTP_UNAUTHORIZED` default) onto every entry it pushes for that directive, and the validator returns the failing entry's status instead of a shared value. Single-directive configs keep the existing 401 / explicit `error=` behaviour; only multi-directive setups change. The redundant location-wide `error` field and its `create_loc_conf` / `merge_loc_conf` handling are removed, and the values array merge is updated to the new element type so prepend semantics for inherited directives stay intact

## [0.13.0] - 2026-05-21

### Added

- New `auth_jwt_www_authenticate on | off | <string>` directive controlling the `WWW-Authenticate` response header. The DEFAULT mode keeps the existing `Bearer realm="<realm>"[, error="invalid_token"]` output, `off` suppresses the module's header so a named location reached through `error_page 401` can emit its own value without nginx comma-joining both headers, and any other value is compiled as an `ngx_http_complex_value_t` and written verbatim (with variable interpolation) when authentication fails. Unblocks deploying the module in front of an MCP Resource Server where the `WWW-Authenticate` format mandated by MCP Authorization (`resource_metadata`, `scope`, `error="insufficient_scope"`) cannot coexist with the module's realm-only challenge

## [0.12.0] - 2026-05-18

### Added

- Add `nxe-json` 0.1.0 submodule under `nxe-json/` (jansson wrapper with built-in size, depth, array, string, and key-count limits)

### Changed

- Drop the redundant `ngx_pnalloc(len + 1)` + `ngx_memcpy` in `dump_js_sorted_compact` (`ngx_auth_jwt_claims.c`). `nxe_json_stringify_compact_sorted` returns a buffer with `data[len] == '\0'` since the nxe-json 0.4.1 bump, so the helper can return `str->data` straight to its callers (`ngx_auth_jwt_claims_get_grants_json` / `_get_headers_json`) without duplicating the canonical string for every `$jwt_claim_*` / `$jwt_header_*` variable access
- Bump `nxe-json` submodule to 0.4.1. Guarantees that `nxe_json_stringify_compact` / `_sorted` / `_pretty` return a NUL-terminated buffer (`len` still excludes the terminator), so callers can pass `data` straight to `json_loads`, `strlen`, `%s`, and other C-string APIs without a separate copy. Consumed by the `validate_requirement` segments-branch UB fix
- Drop the remaining `#include <jansson.h>` from `ngx_auth_jwt_claims.c` by adopting `nxe_json_stringify_compact_sorted` (added in `nxe-json` 0.4.0) for the `*_json` accessors. `$jwt_claim_*` / `$jwt_header_*` still serialize with deterministic key ordering, but the sort now goes through the `nxe-json` API instead of reaching down to the underlying jansson handle. `ngx_auth_jwt_claims_get_headers_json` / `_get_grants_json` gain an `ngx_pool_t *pool` parameter so the returned NUL-terminated buffer is pool-owned; `auth_jwt_get_json` and its three call sites in the HTTP module are updated to pass `r->pool`, and `free()` of the previous jansson-allocated buffer is now guarded by a `jwt_value_malloced` flag because the `segments != NULL` branch in `validate_requirement` still uses jansson `json_dumps` directly. Closes the Layer 2 nxe-json migration declared in `CLAUDE.md`
- Bump `nxe-json` submodule to 0.4.0. Adds `nxe_json_stringify_compact_sorted`, the `JSON_SORT_KEYS` wrapper that lets the claims layer remove its direct jansson dependency
- Replace the in-tree JWT decode, JWS verification, and JWKS parsing layers (~2400 LOC) with the `nxe-jwx` submodule. Public directive surface (`auth_jwt_*`) is unchanged
- **Breaking:** `auth_jwt_key_file ... keyval` / `auth_jwt_key_request ... keyval` is now parsed by `nxe_jwx_jwks_parse_keyval`. It natively supports the multi-kid `{"kid1":"...","kid2":"..."}` form, but any value that previously parsed as a private key or fell back to a raw HMAC secret under the legacy parser is now rejected. HMAC secrets must be supplied via a JWKS `kty: "oct"` entry
- **Breaking:** Signature verification adopts `nxe-jwx`'s per-keyset kid-strict policy. The legacy "kid match across all files first, then any key fallback" sequence is reproduced by two passes over the keyset list, and the `kid_tried` audit log is now emitted via `nxe_jwx_jwks_has_kid` only for keysets that actually contain the JWT's kid. Tokens whose `kid` exists in some keyset but whose signature does not verify against any keyset are still rejected; tokens with an absent / empty `kid` follow `nxe-jwx`'s explicit empty-kid handling rather than the legacy lookup heuristic
- Bump `nxe-json` submodule to 0.3.0.
- Bump `nxe-jwx` submodule to 0.1.0. **Breaking:** the `keyval` key file/request format is now restricted to PEM public keys; HMAC secrets must be supplied via a JWKS `kty: "oct"` entry instead.
- Bump `nxe-json` submodule to 0.2.0. Adds `nxe_json_object_get_integer` / `nxe_json_object_get_boolean` helpers and zero-clears extractor out-params on failure
- Replace internal `ngx_auth_jwt_json` wrapper with the `nxe_json` API from the `nxe-json` submodule. No change in runtime behavior for configured JWT validation
- Building from source now requires initializing the submodule (`git clone --recursive` or `git submodule update --init --recursive`)

### Removed

- Drop `ngx_auth_jwt_decode.{c,h}`, `ngx_auth_jwt_jws.{c,h}`, and `ngx_auth_jwt_jwks.{c,h}` from the in-tree sources

### Fixed

- Drop the `(const json_t *) resolved` cast in the `segments != NULL` branch of `validate_requirement`. `ngx_auth_jwt_field_resolve` returns the `nxe_json_t *` opaque handle, so feeding the pointer straight into `json_deep_copy` / `json_dumps` interpreted nxe-json nodes through jansson's `json_t` layout — undefined behaviour today and a runtime trap the moment the nxe-json backend is swapped or instrumented. The branch now mirrors the else branch's serialize-then-parse bridge: `nxe_json_stringify_compact_sorted(resolved, r->pool)` produces a canonical (`JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY`) nul-terminated pool buffer, and `json_loads(..., JSON_DECODE_ANY, NULL)` produces the jansson value passed to `ngx_auth_jwt_operator_validate`. The `jwt_value_malloced` flag and its five `free(jwt_value)` cleanup sites are removed because both branches now hand back pool-owned memory
- Eliminate the duplicate base64url + JSON parse that `ngx_http_auth_jwt_decode_token` performed on every JWT. nxe-jwx already parses the header and payload via nxe-json during `nxe_jwx_decode`; the module previously ran a second decode through `ngx_http_auth_jwt_segment_to_json` solely because Layer 2 (claims / field) consumed jansson types directly. The Layer 2 interface now uses the `nxe_json_t` opaque handle, `ngx_auth_jwt_t` borrows the trees from `nxe_jwx_token_header()` / `nxe_jwx_token_payload()`, and `ngx_auth_jwt_field_resolve` plus the claims / field accessors traverse via `nxe_json_object_get` / `nxe_json_array_get`. The `segment_to_json` helper and its `json_decref` pool cleanup are removed, and `alg` / `kid` lookups in the validation path now reuse `nxe_jwx_token_alg` / `nxe_jwx_token_kid`. The `algorithm` / `kid` locals (and the `validate_requirement` `algorithm` out-parameter) are kept as `const ngx_str_t *` and compared with length-aware `ngx_strncmp` (`len == sizeof(literal) - 1 && ngx_strncmp(data, literal, len) == 0`) instead of casting `data` to `const char *` and calling `ngx_strcmp`, since the nxe-jwx accessors did not document NUL-termination at the time (interim mitigation)
- Defer the `"rejected due to signature validate failure"` audit log in `ngx_http_auth_jwt_keystore_verify` until after both verification passes complete. Previously the log was emitted as soon as pass 1 (kid-matched keysets) exhausted its candidates, so a token that subsequently verified against a pass 2 (fallback) keyset was still recorded as a rejection. The log now fires only when both passes fail, eliminating false positives in audit logs and SIEM aggregation
- Propagate `ngx_http_auth_jwt_keystore_create` / `_append` failures in `ngx_http_auth_jwt_merge_loc_conf` and `ngx_http_auth_jwt_load_keys`. Previously these allocation failures were silently discarded via `(void)` casts, dropping inherited or statically configured keys and surfacing the request as an auth failure. The merge path now logs `NGX_LOG_EMERG` and returns `NGX_CONF_ERROR`; the request path logs `NGX_LOG_CRIT` and returns `NGX_HTTP_INTERNAL_SERVER_ERROR`

## [0.11.0] - 2026-03-24

### Added

- Add `match` operator for PCRE regular expression matching on string claims
- Support negation with `!match` via unified negate prefix
- Integrate JQ-like field paths into requirement validation
- Extend `ngx_http_auth_jwt_requirement_t` with parsed segments
- Parse JQ paths at config time, resolve at runtime directly from JSON tree
- Add JQ-like field path parser (`ngx_auth_jwt_field.h` / `.c`)
- Support `.key`, `."quoted.key"`, and `[N]` path syntax
- Two-pass parsing with `ngx_pool_t` memory management

### Changed

- Extend `error=` parameter range from 401/403 to 400-599 (excluding nginx internal codes 444 and 499)
- Precompile regex patterns at config time for `match` operator with static values
- Dynamic values (containing nginx variables) are compiled per-request using `r->pool`
- Rename `intersect` operator to `any` (`intersect` remains as backward-compatible alias)
- Add unified `!` prefix negation for all operators (e.g. `!eq`, `!any`, `!in`)
- Map legacy negation aliases: `ne` → `!eq`, `nin` → `!in`, `nintersect` → `!any`

### Security

- Add size limit for expected values in claim validation to prevent abuse
- Add Content-Encoding detection to reject compressed payloads

## [0.10.0] - 2026-03-16

### Added

- Replace libjwt fork with a native JWKS/JWS implementation (`ngx_auth_jwt_jwks`, `ngx_auth_jwt_jws`)
- Replace libjwt JWT decode with native `ngx_auth_jwt_decode` layer
- Add JSON abstraction layer `ngx_auth_jwt_json` wrapping jansson

### Changed

- Simplify cleanup handlers by leveraging pool-based memory management
- Migrate JWT decode layer to `ngx_pool_t` memory management
- Migrate JWKS layer to `ngx_pool_t` memory management
- Improve operator layer with 3-value returns (`NGX_OK` / `NGX_DECLINED` / `NGX_ERROR`) and unified negation handling
- Rename source files and symbols to `ngx_auth_jwt_*` prefix convention

### Fixed

- Add `ngx_config.h` include and reorder headers for musl libc compatibility
- Replace `strsep` with `strstr` for correct multi-character delimiter support in nested claims
- Repair NULL check typo and memory leak in module configuration
- JWS 2-pass verification with `kid`-based key lookup fallback and failure logging
- Fix uninitialized struct field in `ngx_http_auth_jwt_set_bearer_header()`

## [0.9.0] - 2024-12-09

### Added

- Add `limit_except` context support to all authentication directives

## [0.8.0] - 2024-11-19

### Changed

- Update libjwt source base to v1.17.2

## [0.7.0] - 2024-04-01

### Added

- Add `auth_jwt_allow_nested` delimiter and quote setting directives for nested claim access

### Changed

- Extend `auth_jwt_allow_nested` directive context to `http`, `server`, and `location`
- Improve invalid parameter error reporting in `auth_jwt_allow_nested` directive

## [0.6.0] - 2023-12-29

### Added

- Add `auth_jwt_require` directive for flexible claim/header requirement expressions
- Add `auth_jwt_header_set` directive to set request headers from JWT claims

## [0.5.0] - 2023-12-26

### Added

- Add `$jwt_nowtime` embedded variable providing current Unix timestamp

### Changed

- Change scalar value handling for `intersect`/`nintersect` operator in `auth_jwt_require_claim`
- **BREAKING:** Change `exp` expected value handling in `auth_jwt_require_claim` directive

### Removed

- Remove `auth_jwt_validate_nbf` directive (use `auth_jwt_require` instead)
- Remove `auth_jwt_validate_iat` directive (use `auth_jwt_require` instead)
- Remove `auth_jwt_validate_alg` directive (use `auth_jwt_require` instead)
- Remove `auth_jwt_validate_iss` directive (use `auth_jwt_require` instead)
- Remove `auth_jwt_validate_sub` directive (use `auth_jwt_require` instead)
- Remove `auth_jwt_validate_nonce` directive (use `auth_jwt_require` instead)
- Remove `auth_jwt_validate_aud` directive (use `auth_jwt_require` instead)

## [0.4.0] - 2023-12-06

### Added

- Add `auth_jwt_require_header` directive for JOSE header validation with operators
- Add `auth_jwt_require_claim` directive for JWT claim validation with operators
- Add `auth_jwt_revocation_list_kid` directive for kid-based key revocation
- Add `auth_jwt_revocation_list_sub` directive for sub-based token revocation

## [0.3.0] - 2023-11-09

### Added

- Add `auth_jwt_validate_nonce` directive for nonce claim validation
- Add `auth_jwt_validate_nbf` directive for nbf claim validation
- Add `auth_jwt_validate_iat` directive for iat claim validation
- Add `auth_jwt_validate_sub` directive for sub claim validation
- Add `auth_jwt_validate_iss` directive for iss claim validation
- Add `auth_jwt_validate_aud` directive for aud claim validation

### Changed

- Update libjwt source base to v1.15.3
- Change validation rules for exp claim

## [0.2.2] - 2023-11-06

### Fixed

- Fix segfault when using satisfy directive

## [0.2.1] - 2023-03-16

### Fixed

- Fix memory leak in configuration handling

## [0.1.0] - 2023-02-08

### Added

- Add `$jwt_claims` embedded variable returning all JWT claims as JSON
- Add JWK thumbprint key support
- Initial release with JWT validation, JWKS/keyval key loading, `auth_jwt_claim_set`, `auth_jwt_key_file`, `auth_jwt_key_request`, `auth_jwt_validate_exp`, `auth_jwt_validate_sig`, `auth_jwt_leeway`, `auth_jwt_phase`, and `auth_jwt_allow_nested` directives

### Changed

- Update libjwt source base to v1.15.2
- Fall back to other keys when kid-specified key is invalid
- Make kid key in JWKS optional (no longer required)
- Validate signature when kid is not present in JWT header
- Support decimal point values in exp claim validation

### Fixed

- Add error handling for missing kid in JWT header
