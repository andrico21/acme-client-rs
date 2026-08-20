# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Tags are bare semver (e.g. `2.2.2`, no `v` prefix). Releases prior to 2.2.0
are documented only in git history and GitHub releases.

## [Unreleased]

## [2.3.4] - 2026-08-20

### Changed

- Refreshed dependencies via `cargo update`. Security- and TLS-relevant
  moves: `aws-lc-rs` 1.17.3 → 1.18.0, `aws-lc-sys` 0.43.0 → 0.44.0,
  `rustls-webpki` 0.103.13 → 0.103.14, `h2` 0.4.15 → 0.4.17,
  `quinn-proto` 0.11.16 → 0.11.17. Direct pins bumped to `base64` 0.23,
  `pem` 4, `clap` 4.6.6, `rcgen` 0.14.9. No source changes — this
  release is dependency and toolchain maintenance only.
- Rust toolchain pinned to 1.97.1 (`rust-toolchain.toml` and all CI
  build images), the current stable.
- macOS release builds moved off the deprecated `macos-14` runner to
  `macos-26`. GitHub fully retires the Sonoma images after 2026-11-02;
  `build-macos-x86_64` already cross-compiles to
  `x86_64-apple-darwin`, so it never depended on an Intel host.
- SemVer-incompatible upgrades to `ecdsa` 0.17, `ed25519-dalek` 3.0,
  `hmac` 0.13, `p256`/`p384`/`p521` 0.14, `rand_core` 0.10, `sha2`
  0.11, and `crypto-common` 0.1.7 remain deferred. `rsa` 0.9.10 still
  requires `digest` 0.10 / `sha2` 0.10, and the JWS code feeds one
  `Sha256` type into both the `rsa` and `ecdsa` signing paths, so a
  partial bump forks the graph into two incompatible `digest` versions
  and fails to build. This set can only move once `rsa` supports
  `digest` 0.11.

## [2.2.5] - 2026-06-10

### Changed

- Refreshed transitive dependencies via `cargo update`: `http` 1.4.1 →
  1.4.2, `js-sys` 0.3.99 → 0.3.100, `regex-syntax` 0.8.10 → 0.8.11,
  `uuid` 1.23.2 → 1.23.3, `wasm-bindgen` (and `-futures`, `-macro`,
  `-macro-support`, `-shared`) 0.2.122 → 0.2.123 / 0.4.72 → 0.4.73,
  `web-sys` 0.3.99 → 0.3.100, `zerocopy` (and `zerocopy-derive`) 0.8.50
  → 0.8.52. No direct dependency bumps; all top-level pins in
  `Cargo.toml` were already at the latest published version of their
  pinned major. SemVer-incompatible upgrades to `hmac` 0.13, `rand_core`
  0.10, `sha2` 0.11, and `crypto-common` 0.1.7 are deferred — the
  RustCrypto stack used here (`ecdsa`, `p256`/`p384`/`p521`, `rsa`,
  `pkcs8`, `ed25519-dalek`, `rcgen`, `scrypt`) still pins the old
  majors, so bumping in isolation would break the build.

## [2.2.4] - 2026-06-04

### Changed

- Refactored `cmd_run` into per-phase modules (`preflight`,
  `account_step`, `order_step`) plus a `RunContext::build` constructor.
  `cmd_run` is now a thin dispatcher: preflight → context build →
  renewal check → account → optional preauth → order → authorize →
  finalize. Pure motion — no behavior change, no CLI/config/output
  change. Removed a redundant wildcard-compatibility check that ran
  twice on every invocation.

## [2.2.3] - 2026-06-04

### Documentation

- Added `CHANGELOG.md` (Keep a Changelog 1.1.0), backfilling 2.2.0–2.2.2.

### Tests

- Integration smoke tests for `--generate-account-key-if-missing`: TC-22b
  exercises the auto-generate happy path; TC-22c is a control case asserting
  that the default behavior (no flag) still errors out when the account key
  is missing.

## [2.2.2] - 2026-06-04

### Changed

- Refreshed transitive dependencies via `cargo update`: `bitflags`
  2.11.1 → 2.12.1, `log` 0.4.30 → 0.4.32, `yoke` 0.8.2 → 0.8.3. No direct
  dependency bumps; all top-level pins in `Cargo.toml` were already at the
  latest published version of their pinned major.

## [2.2.1] - 2026-06-04

### Added

- `--generate-account-key-if-missing` flag (env
  `ACME_GENERATE_ACCOUNT_KEY_IF_MISSING`, config `[run]
  generate_account_key_if_missing`) on the `run` subcommand. When set and
  the configured `--account-key` path does not exist, a fresh account key
  is generated in PKCS#8 PEM at that path before the ACME client is built.
  Honors `--account-key-password*` for at-rest encryption. Default behavior
  is unchanged: missing account key still errors out.
- `--account-key-algorithm <es256|es384|rsa2048|rsa3072|rsa4096>` flag
  (env `ACME_ACCOUNT_KEY_ALGORITHM`, config `[run]
  account_key_algorithm`) controlling the algorithm used when
  auto-generating. Defaults to `es256`. Has no effect unless the
  auto-generate flag is set.

### Documentation

- README "Single-command container usage" subsection documenting the
  one-shot `podman run` flow that combines account-key bootstrap and
  certificate issuance.
- `acme-client-rs.toml.example` entries for both new keys.

## [2.2.0] - 2026-06-04

### Changed

- HTTP client switched from OpenSSL-backed `reqwest` to `rustls`
  (`webpki-root-certs`), removing the OpenSSL runtime dependency. CI
  license allowlist updated to include CDLA-Permissive-2.0.

[Unreleased]: https://github.com/andrico21/acme-client-rs/compare/2.3.4...HEAD
[2.3.4]: https://github.com/andrico21/acme-client-rs/compare/2.3.3...2.3.4
[2.2.5]: https://github.com/andrico21/acme-client-rs/compare/2.2.4...2.2.5
[2.2.4]: https://github.com/andrico21/acme-client-rs/compare/2.2.3...2.2.4
[2.2.3]: https://github.com/andrico21/acme-client-rs/compare/2.2.2...2.2.3
[2.2.2]: https://github.com/andrico21/acme-client-rs/compare/2.2.1...2.2.2
[2.2.1]: https://github.com/andrico21/acme-client-rs/compare/2.2.0...2.2.1
[2.2.0]: https://github.com/andrico21/acme-client-rs/compare/2.1.5...2.2.0
