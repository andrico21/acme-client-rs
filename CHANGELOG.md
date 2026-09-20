# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Tags are bare semver (e.g. `2.2.2`, no `v` prefix). Releases prior to 2.2.0
are documented only in git history and GitHub releases.

## [Unreleased]

## [2.5.0] - 2026-09-20

### Security

- **Hook-path validation now checks ancestor-directory ownership, and
  walks both the configured (lexical) and symlink-resolved ancestor
  chains.** This closes the residual W1 (2.4.2) left open: an attacker
  who owned any ancestor directory of a configured hook script — not
  only one with insecure permission bits — could still substitute the
  script, whether directly or via a symlink/hardlink to some other,
  already-trusted executable, since swap capability always requires
  control of the entry's own lexical parent directory.
  `revalidate_hook` (2.4.2) already refuses any *attacker-owned*
  substituted content; this closes the substitution primitive itself,
  matching the design intent from the original review. The remaining
  residual is the unavoidable `stat`(2)→`execve`(2) race — the kernel
  re-resolves the path a second time at spawn, and closing that window
  needs exec-by-fd (`fexecve`/`execveat`), which cannot be expressed
  without `unsafe`, forbidden crate-wide. Revalidating immediately
  before every spawn (2.4.2) narrows this from the flow's full duration
  to microseconds, the strongest mitigation available in safe Rust.

### Changed

- **BREAKING:** every directory above a hook script, up to `/`, must
  now be owned by the effective user or root, in addition to the
  existing not-group/world-writable check. A hook that lives under a
  directory owned by a different account than the one running
  `acme-client-rs` — even one with otherwise-correct permission bits —
  now hard-fails by default. Standard single-user deployment layouts
  are unaffected. Override with `--unsafe-hooks` /
  `ACME_UNSAFE_HOOKS=1` / `[global] unsafe_hooks=true` if you cannot
  immediately re-home or `chown` the hook's directory chain — but note
  that flag does not add any protection of its own.

## [2.4.3] - 2026-09-20

### Changed

- **CA-controlled text in ARI renewal-window validation errors is now
  sanitized.** `RenewalInfo::validate_window`'s three interpolations (the
  start/end timestamps and the inverted-window error) now route through
  the same `sanitize::untrusted_inline` guard used everywhere else CA text
  reaches an error or log message, instead of being the one sink in that
  tier that did not. `tracing-subscriber`'s requirement floor is raised
  to the exact locked `0.3.23`, and a new test drives a real subscriber to
  confirm its message-field escaping actually behaves as assumed, rather
  than trusting the dependency floor alone. Adversarial review found the
  originally filed report on this incidental/incomplete rather than a
  live gap - not a vulnerability fix, but real defense-in-depth.
- **Config-mode env-var reset now also covers
  `--generate-account-key-if-missing` and `--account-key-algorithm`.**
  Previously, once a config file was loaded, `ACME_GENERATE_ACCOUNT_KEY_IF_MISSING`
  and `ACME_ACCOUNT_KEY_ALGORITHM` could still silently apply instead of
  being reset to their defaults like every other non-secret env var in
  config mode.
  **Upgrade note (config-mode users only):**
  - If you relied on `ACME_GENERATE_ACCOUNT_KEY_IF_MISSING=1` *together
    with* `--config`/`ACME_CONFIG`, it no longer bootstraps the account
    key; set `generate_account_key_if_missing = true` in the config file
    (or drop `--config` for that invocation) instead.
  - A config value of `account_key_algorithm` (or
    `generate_account_key_if_missing`) of `false`/omitted is now
    authoritative even when an env var says otherwise - previously only
    an explicit `true` in the config file applied.
  - An invalid `account_key_algorithm` in the config file is now a hard
    error even when `--account-key-algorithm` is also passed on the CLI
    (previously silently ignored in that combination).
- **CI/release reproducibility.** The floating `rust:alpine` container tag
  (release + CI musl legs) is pinned to `rust:1.98-alpine3.23`, matching
  `Containerfile`'s existing pin. `dtolnay/rust-toolchain@master` and every
  `actions/*`/`softprops/*` step across all workflows are pinned to commit
  SHAs instead of mutable tags/branches. Release artifacts now ship
  `SHA256SUMS` alongside the tarballs. Adversarial review rejected the
  originally filed report here too (Docker Hub and GitHub's own runner
  images are already-trusted infrastructure) - this is reproducibility
  hardening for the release pipeline, not a vulnerability fix.

## [2.4.2] - 2026-09-20

### Security

- **Cleanup-drain DNS hook spawn now re-validates ownership/permissions
  immediately before exec, closing the last unguarded hook spawn site.**
  `cleanup.rs`'s `CleanupAction::DnsRecord` arm — reached only from the
  SIGINT drain and the top-level error-recovery path — previously spawned
  the configured `--dns-hook` script without re-running the ownership/
  permission check that every other hook spawn site already performs. An
  attacker who could win a race to substitute an attacker-owned hook script
  between registration and drain (a window bounded by `--challenge-timeout`,
  default 300s, plus `--dns-wait`) could get that script executed, commonly
  as the operator (often root). `CleanupRegistry::run_all_sync` now takes
  the same `--unsafe-hooks` policy the rest of the codebase already threads
  through, and revalidates the hook path immediately before spawning; on
  violation, the cleanup is skipped with a warning naming the hook and the
  DNS record that must be removed manually, rather than executing an
  untrusted script as a privileged user. No behavior change for hooks that
  keep their registered ownership/permissions throughout a run.

### Documentation

- Noted a residual gap in the hook-path validation: directories *above* a
  hook script are checked for group/world write access but not (yet)
  cross-checked against the effective uid or root — an attacker who owns
  an ancestor directory can still substitute the hook. `--unsafe-hooks`
  does not mitigate this; operators should ensure every directory in a
  hook's path is owned by the user running `acme-client-rs` or by root.
  Tracked for a stricter (breaking) fix in a future minor release.
- Documented that hook ownership/permission validation — including the
  above revalidation — is a no-op on Windows; the shipped
  `acme-client-rs-windows-x86_64-msvc.zip` build only ever emits a
  one-time stderr advisory.

## [2.4.1] - 2026-09-18

### Security

- **Locked `rustls` bumped to 0.23.45 for RUSTSEC-2026-0285.** The previously
  locked 0.23.43 accepted TLS 1.3 handshake messages sent at the wrong
  encryption level when they followed a key-changing message in the same record
  ([GHSA-2mjx-qc3c-rqvc](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc)),
  so a peer could send messages that RFC 8446 §5.1 requires to be rejected. The
  handshake transcript stays authenticated, so a network-position attacker
  cannot alter or complete a handshake. 0.23.45 is the first patched release;
  the bump is lockfile-only, with no source changes.

## [2.4.0] - 2026-08-27

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
- A blocking documentation lint (`tests/lint-docs.py`) checks README.md,
  README.RUS.md and the Docker Hub description against the binary, the release
  workflows and each other: example flags must exist, subcommand rows must list
  what `clap` reports as required, internal anchors must resolve, every
  published release artifact and every `ACME_` environment variable must appear
  in the reference tables, the config example must match `generate-config`, and
  the two READMEs must stay structurally identical. Ground truth comes from
  invoking the binary, so the lint follows the CLI as it changes.

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
- Refreshed dependencies via `cargo update`. The security-relevant moves are
  `rustls-webpki` 0.103.14 → 0.103.15 (certificate path validation) and
  `aes-gcm` 0.11.0 → 0.11.1; `h2` 0.4.17 → 0.4.18 covers the HTTP/2 client.

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

[Unreleased]: https://github.com/andrico21/acme-client-rs/compare/2.5.0...HEAD
[2.5.0]: https://github.com/andrico21/acme-client-rs/compare/2.4.3...2.5.0
[2.4.3]: https://github.com/andrico21/acme-client-rs/compare/2.4.2...2.4.3
[2.4.2]: https://github.com/andrico21/acme-client-rs/compare/2.4.1...2.4.2
[2.4.1]: https://github.com/andrico21/acme-client-rs/compare/2.4.0...2.4.1
[2.4.0]: https://github.com/andrico21/acme-client-rs/compare/2.3.4...2.4.0
[2.3.4]: https://github.com/andrico21/acme-client-rs/compare/2.3.3...2.3.4
[2.2.5]: https://github.com/andrico21/acme-client-rs/compare/2.2.4...2.2.5
[2.2.4]: https://github.com/andrico21/acme-client-rs/compare/2.2.3...2.2.4
[2.2.3]: https://github.com/andrico21/acme-client-rs/compare/2.2.2...2.2.3
[2.2.2]: https://github.com/andrico21/acme-client-rs/compare/2.2.1...2.2.2
[2.2.1]: https://github.com/andrico21/acme-client-rs/compare/2.2.0...2.2.1
[2.2.0]: https://github.com/andrico21/acme-client-rs/compare/2.1.5...2.2.0
