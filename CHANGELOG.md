# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Tags are bare semver (e.g. `2.2.2`, no `v` prefix). Releases prior to 2.2.0
are documented only in git history and GitHub releases.

## [Unreleased]

## [3.0.0] - 2026-08-27

### Security

- **Text supplied by the ACME server is now scrubbed before it reaches the
  terminal.** A hostile or compromised CA controls the bytes in problem-document
  `detail` fields, directory profile names and descriptions, the ARI
  `explanationURL`, unknown challenge/error type strings, and the certificate
  body printed by `--print-cert`. Those were rendered verbatim, so a CA could
  emit ANSI escape sequences and carriage returns that drive the operator's
  terminal or overwrite log lines. Control characters are now replaced with `·`
  in text output. JSON output was never affected (`serde_json` escapes them).
- **Error output from ACME problem documents is now bounded.** The structured
  branch bypassed the existing 1 KB response-body cap, so a CA could flood
  stderr with an arbitrarily large `detail`. Both the field and the rendered
  subproblem list (max 10) are now capped.
- **The built-in HTTP-01 challenge server sends the full OWASP header set** —
  adding `X-Frame-Options`, `Content-Security-Policy`, `Permissions-Policy`,
  `Cross-Origin-Resource-Policy`, `X-Permitted-Cross-Domain-Policies` and
  `X-DNS-Prefetch-Control` to the headers already sent. HSTS is deliberately
  omitted: RFC 6797 §7.2 requires user agents to ignore it over the plaintext
  that HTTP-01 mandates.
- Debug builds now assert that no terminal-steering bytes reach stdout, so a
  future unsanitized output site fails in tests rather than silently shipping.

`--print-cert` output is unchanged for any legitimate certificate: scrubbing
preserves `\n`, `\t` and CRLF pairs, so both LF- and CRLF-encoded PEM remain
byte-identical and still pipe into `openssl x509`. The certificate written to
disk was never modified.

### Added

- `cargo vet` runs in CI as a blocking supply-chain gate, with the
  `supply-chain/` audit configuration committed. `cargo machete` (unused
  dependencies) and `cargo geiger` (transitive `unsafe` census) run as
  informational, non-blocking steps.
- A scheduled, non-blocking `cargo-mutants` workflow covering the boundary
  validators, the output scrubber and the ARI renewal decision.
- Property-based tests (`proptest`) over DNS/token validation, the scrubber and
  the ARI renewal-instant selector.
- Audit sets from Google, ISRG, Zcash and Embark Studios are imported into
  `cargo vet`, replacing 24 of the blanket `cargo vet init` exemptions with
  real review — including the `hmac`, `signature`, `rand_core`, `rand_chacha`
  and `fiat-crypto` crates behind key generation and JWS signing.

### Changed

- **BREAKING: `revoke-cert`, `pre-authorize`, `show-dns-persist-01` and
  `key-rollover` no longer register an ACME account implicitly.** These
  commands previously called `newAccount` to resolve the account URL, which
  both created an account for an unregistered key and asserted
  `termsOfServiceAgreed: true` on the operator's behalf. They now use an
  `onlyReturnExisting` lookup (RFC 8555 §7.3.1) and fail with a directive
  error if no account exists. Pass `--account-url` if you already know it, or
  the new per-command `--agree-tos` flag to opt in to registration. `run` and
  `account` are unaffected — registration is their intent.
- `--dns-propagation-concurrency` is now a non-zero integer. `0` is rejected by
  the CLI and by config-file parsing.
- **Minimum supported Rust version is now 1.98** (`rust-version` in `Cargo.toml`).
  The crate adopts `str::strip_circumfix`, stabilised in 1.98.
- The `rust-toolchain.toml` pin was removed; CI now builds on whatever `stable`
  resolves to, per RUST_GUIDELINES §12.
- `show-dns-persist-01` and the TLS-ALPN-01 instructions now also print the
  `acmeIdentifier` extension OID (`1.3.6.1.5.5.7.1.31`) alongside the hex value.
- Interrupting with Ctrl-C now reports how many cleanup actions are pending and
  that a second Ctrl-C aborts immediately, instead of a bare message.

### Fixed

- **`--dns-propagation-concurrency 0` deadlocked the client permanently.** The
  value became a `Semaphore` permit count, so every propagation task waited
  forever — after the DNS TXT records had already been published, and with no
  timeout on that path. The type now makes zero unrepresentable.
- **Challenge cleanup no longer depends on Ctrl-C.** The cleanup registry was
  drained only by the SIGINT handler, so an ordinary error return exited
  without rolling back published TXT records or on-disk challenge files. Four
  comments claimed a `Drop`-based rollback that never existed; all are
  corrected. Pre-authorization failure paths now route through the shared
  cleanup helper, so a failed dns-01 pre-authorization removes its TXT record
  on the spot instead of relying on the process-exit drain.
- **A broken stdout pipe no longer reports success for a failed issuance.**
  `… | head` triggered `exit(0)` mid-flow, skipping cleanup and returning 0
  for an issuance that never completed. Writes are now suppressed after a
  broken pipe and the flow runs to its real conclusion; `--output-format json`
  and `--print-cert` exit non-zero if their payload was lost.
- Authorization and challenge polling now honor the server's `Retry-After`
  (RFC 8555 §7.5.1), bounded by both the 5-minute cap and the remaining
  `--challenge-timeout` budget. `Retry-After` in HTTP-date form is now parsed;
  a stale date falls back to the default cadence instead of busy-polling.
- Cleanup handles are now completed after teardown on both the HTTP-01 and DNS
  paths, so a later SIGINT or the process-exit drain cannot re-fire cleanup for
  a resource that was already released.
- An invalid `dns_check_mode` in a config file is now a hard error instead of a
  warning that silently fell back to the default.
- `list-profiles` error bodies are sanitized through `truncate_for_log`,
  matching every other error path; ANSI escapes in a proxy error page can no
  longer reach the terminal.
- `AcmeClient::new` validates its own directory URL instead of relying on
  callers, and the account key's zeroization guarantee is now pinned by a
  compile-time assertion.
- Corrected three `cancel-safe` annotations on `order`, `get-authz` and
  `poll-order`, which called methods documented as NOT cancel-safe.
- Unbalanced IPv6 brackets in an identifier (`[::1` or `::1]`) are now rejected
  instead of being silently reinterpreted as a DNS name.
- Moved blocking filesystem work off the async runtime: the world-readable
  permission check and the HTTP-01 challenge-file write now run on the blocking
  pool. HTTP-01 cleanup is registered before the file is written, so a
  cancellation in that window cannot leak a challenge token.

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

[Unreleased]: https://github.com/andrico21/acme-client-rs/compare/3.0.0...HEAD
[3.0.0]: https://github.com/andrico21/acme-client-rs/compare/2.3.4...3.0.0
[2.3.4]: https://github.com/andrico21/acme-client-rs/compare/2.3.3...2.3.4
[2.2.5]: https://github.com/andrico21/acme-client-rs/compare/2.2.4...2.2.5
[2.2.4]: https://github.com/andrico21/acme-client-rs/compare/2.2.3...2.2.4
[2.2.3]: https://github.com/andrico21/acme-client-rs/compare/2.2.2...2.2.3
[2.2.2]: https://github.com/andrico21/acme-client-rs/compare/2.2.1...2.2.2
[2.2.1]: https://github.com/andrico21/acme-client-rs/compare/2.2.0...2.2.1
[2.2.0]: https://github.com/andrico21/acme-client-rs/compare/2.1.5...2.2.0
