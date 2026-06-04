# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Tags are bare semver (e.g. `2.2.2`, no `v` prefix). Releases prior to 2.2.0
are documented only in git history and GitHub releases.

## [Unreleased]

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

[Unreleased]: https://github.com/andrico21/acme-client-rs/compare/2.2.2...HEAD
[2.2.2]: https://github.com/andrico21/acme-client-rs/compare/2.2.1...2.2.2
[2.2.1]: https://github.com/andrico21/acme-client-rs/compare/2.2.0...2.2.1
[2.2.0]: https://github.com/andrico21/acme-client-rs/compare/2.1.5...2.2.0
