---
name: rust-review
description: "Rust code review using project guidelines. USE WHEN: user asks to review Rust code, check code quality, audit a PR, or validate code against standards. Checks ownership, error handling, type safety, async patterns, performance, API design, and OWASP web security."
argument-hint: "File path(s) to review, or 'all' for workspace-wide audit"
---

# Rust Code Review

Review Rust code against the project's mandatory guidelines defined in
`RUST_GUIDELINES.md`. Produces a structured report of violations grouped
by category with severity levels.

## When to Use

- "review this code" / "check code quality"
- "does this follow our Rust guidelines?"
- Before merging any PR with Rust changes
- After writing new code to self-review

## Procedure

### 1. Load Guidelines

Read `RUST_GUIDELINES.md` from the workspace root. This is the authoritative
source - every check below references a specific section.

Also read `README.md` from the workspace root for repository-level constraints
(architecture rules, security posture, release profile).

**Rust toolchain:** the workspace pins `rust-toolchain.toml` to `1.96.0`.
The `(1.95)` markers below tag APIs/lints introduced in Rust 1.95
(stable since 2026-04-16) - they all apply on 1.96 as well.
Be aware of the new/widened clippy lints
that fire under this workspace's `pedantic = "warn"` posture (notably
`duration_suboptimal_units`, `unnecessary_trailing_comma`,
`manual_checked_ops`, `manual_take`) and the stdlib APIs that replace
existing idioms (`Vec::push_mut` family, `Atomic::update`/`try_update`,
`core::hint::cold_path`, `cfg_select!`, `Option::is_none_or`). Flag code
that uses the old patterns where the new ones apply.

### 2. Run the toolchain FIRST (efficiency)

Before any manual review, run the full enforcement pipeline (mirrors
`.github/workflows/rust.yaml`) and read its output. Many rules in Sections
1, 2, 4, 7, 9 are already enforced by the workspace lint config: per-rule
deny entries (e.g. `unwrap_used`, `indexing_slicing`, `panic`,
`wildcard_enum_match_arm`) plus `pedantic = "warn"` and `nursery = "warn"`
group-level opt-ins, all promoted to errors in CI via `-D warnings`.
Do NOT manually re-check what clippy already guarantees - it wastes tokens.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings 2>&1 | tee clippy.log
cargo test --verbose
cargo deny check
bash tests/lint-output-safety.sh
```

If clippy fails, paste the errors into the report and focus manual review
on what clippy cannot catch:

- Architecture/module placement (handler boundaries under `src/handlers/`, helper crates under `src/`)
- API design and naming
- OWASP web security (Section 10) and ACME protocol correctness (RFC 8555, RFC 8738, RFC 9773, draft-ietf-acme-dns-persist, draft-ietf-acme-profiles-01)
- Secrets handling (account keys, EAB HMAC, key-encryption passwords), input validation at system boundaries
- Domain correctness, matching behavior to spec
- Test coverage and test quality (not just count) - see `TESTING.md` for the test layout
- Crate version freshness (`deny.toml` controls advisory and version policy)
- Whether new code exploits 1.95 APIs where appropriate
- Preservation of `#![forbid(unsafe_code)]` and the hardened release profile in `Cargo.toml`

### 3. Identify Files to Review

If specific files given, review those. Otherwise, find all changed `.rs`
files via `git diff --name-only origin/master...HEAD -- '*.rs'`
(or `git diff --name-only HEAD -- '*.rs'` for uncommitted work),
falling back to all `src/**/*.rs` files for a full audit.

**MANDATORY**: Read each file COMPLETELY from scratch before reviewing  - 
do NOT rely on previously cached context or partial reads, even if the file
was read earlier in the conversation. Re-read the full contents every time.
Read in parallel where possible to reduce latency.

### 4. Check Each Category

For every file, check the following categories. For each violation found,
record: file, line(s), category, severity (error/warning/info), the rule
violated, and a fix suggestion with corrected code.

Categories marked **(clippy-enforced)** are guaranteed by the workspace
lint config - skim only, do NOT re-audit manually unless clippy was not
run or the file has `#[allow(...)]` overrides.

#### 4a. Ownership & Borrowing - Section 1 **(mostly clippy-enforced via `needless_pass_by_value`, `redundant_clone`, `clone_on_ref_ptr`)**

- Functions accept `&str` not `&String`, `&[T]` not `&Vec<T>`, `&T` not `&Box<T>`
- No `.clone()` used to satisfy the borrow checker - restructure instead
- `mem::take`/`mem::replace` used for owned enum field moves, not clone
- Consumed args returned in error variants for retryable operations
- Ownership moved when caller does not need the value afterward
- **(1.95)** `Vec::push_mut` / `Vec::insert_mut` / `VecDeque::push_{front,back}_mut` / `LinkedList::push_{front,back}_mut` used instead of `push` + `last_mut().unwrap()` - eliminates forbidden unwrap

#### 4b. Error Handling - Section 2 **(mostly clippy-enforced via `unwrap_used = deny`, `expect_used = warn`, `panic/todo/unimplemented = deny`)**

- No `unwrap()`/`expect()` outside `#[cfg(test)]` or proven invariants with comment
- Errors propagated with `?` operator, not swallowed or panicked
- `TryFrom` used when conversion can fail (not `From` with hidden panics/defaults)
- `unwrap_or`, `unwrap_or_else`, `unwrap_or_default` for fallbacks
- **(1.95)** Project has no `clippy.toml`; do NOT introduce one that weakens lints (e.g. `allow-unwrap-types`) - policy forbids weakening the unwrap deny

#### 4c. Type Safety & Defensive Programming (Section 3)

- Newtypes for domain concepts (IDs, amounts, ports)
- Enums instead of `bool` params where meaning is unclear at call site
- `match` arms exhaustive - no wildcard `_` catch-all on owned enums
- Private fields with validated constructors (`new() -> Result`)
- `#[must_use]` on types/functions where ignoring result is a bug
- No `..Default::default()` hiding new fields - explicit field assignment
- Slice pattern matching preferred over index + length check
- Destructure structs in manual trait impls for future-proofing
- Named unused fields in patterns (`has_fuel: _` not bare `_`)
- **(1.95)** `Option::is_none_or(f)` replaces `opt.is_none() || opt.is_some_and(f)` (clippy `manual_is_variant_and`)

#### 4d. Performance - Section 4 **(mostly clippy-enforced via `box_collection`, `rc_buffer`, `redundant_clone`, `useless_conversion`)**

- No `Box<Vec<T>>`, `Box<String>`, `Arc<String>` - redundant wrappers
- No collect-then-iterate - iterate directly from the iterator
- No `String::from("...")` / `format!("literal")` where `&str` suffices
- HashMap lookups use `&str`, not cloned `String` keys
- Temporary mutability pattern: mutable init then shadow as immutable
- **(1.95)** `Duration::from_mins(n)` / `from_hours(n)` instead of `from_secs(n * 60)` or large `from_secs` values (clippy `duration_suboptimal_units` now fires on these)
- **(1.95)** `Atomic*::update` / `try_update` instead of hand-rolled `compare_exchange` loops
- **(1.95)** `core::hint::cold_path()` in genuinely unlikely branches; perf hint only, never correctness
- **(1.95)** Use `std::mem::take(&mut x)` not `mem::replace(&mut x, Default::default())` (clippy `manual_take`)
- **(1.95)** Clippy `manual_checked_ops` catches hand-rolled overflow checks - prefer `checked_add`/`checked_sub`/`checked_mul`

#### 4e. Async (Section 5)

- No `std::fs` / `std::net` in async functions - use `tokio::fs`, `tokio::net`
- Blocking work wrapped in `tokio::task::spawn_blocking`
- No `std::sync::Mutex` held across `.await` points - use `tokio::sync::Mutex` or minimize scope
- `tokio::select!` for cancellation and timeouts
- `yield_now()` in CPU-bound async loops

#### 4f. Design Patterns (Section 6)

- Builder pattern for complex construction with many optional fields
- RAII guards for resource lifecycle
- Closure variable rebinding to control captures
- Struct decomposition when borrow checker blocks independent field borrowing
- **(1.95)** Prefer `cfg_select!` over the `cfg-if` crate in new code (do NOT proactively migrate existing `cfg-if` usages)
- **(1.95)** `if let` guards in `match` are stable - but remember patterns in the guard do NOT contribute to exhaustiveness (same rule as `if` guards)

#### 4g. Anti-Patterns (Section 7)

- No `Deref` for fake inheritance - use delegation or traits
- No `#![deny(warnings)]` in source - use CI env var instead
- No overreliance on `String` - accept `&str` or `impl Into<String>`

#### 4h. API Design (Section 8)

- Owned string params use `impl Into<String>`, read-only use `&str`
- Constructors with validation return `Result`
- No more than 3-4 boolean parameters - use enums or param struct
- Internal types not exposed in public APIs - wrap third-party types

#### 4i. Clippy & Lints (Section 9) **(config review, not code review)**

- Verify `Cargo.toml` `[lints]` section includes recommended clippy lints
- Check for `indexing_slicing`, `fallible_impl_from`, `wildcard_enum_match_arm`
- Check for `redundant_clone`, `needless_pass_by_value`, `clone_on_ref_ptr`
- **(1.95)** Project has no `clippy.toml`; do NOT introduce one that weakens lints

#### 4j. Web Security - OWASP (Section 10)

- OWASP security headers on all HTTP responses (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and full list from Section 10) - applies to the built-in HTTP-01 challenge server
- Server-fingerprinting headers stripped (Server, X-Powered-By)
- External input validated at system boundary (length, charset, allowlist) - CLI args, config TOML, env vars, ACME server responses, DNS hook script output
- No string interpolation of user input into SQL, shell commands, or API paths - hook scripts (`--dns-hook`, `--on-challenge-ready`, `--on-cert-issued`) MUST receive data via env vars, never via interpolated argv
- Error responses do not leak internals (stack traces, file paths, SQL, IPs) - matches the README's "Clean error messages (no stack traces for operational errors)" promise
- Secrets from env/config, not hardcoded; wrapped in `secrecy::Secret<T>` - applies to EAB HMAC keys, key-encryption passwords, account keys
- Cryptographic randomness uses `OsRng`, not `thread_rng` - critical for nonces, CSR keypair generation, account key generation
- TLS enabled with certificate validation; min TLS 1.2; `--insecure` must be opt-in only and clearly documented as test-only
- SSRF prevention: validate URLs returned by the ACME directory; reject `file://`, private/loopback IPs only in production paths
- Auth attempts and sensitive operations logged with structured tracing - but never log key material, HMAC keys, or passwords

### 5. Check Crate Versions (`Cargo.toml` + `deny.toml`)

For any new or changed dependencies in `Cargo.toml`:

1. Run `cargo search <crate> --limit 1` for each new crate
2. Flag any crate pinned to an old version (compare with search result)
3. Flag pre-release versions (contain `-alpha`, `-beta`, `-rc`, `-pre`)
4. Verify `cargo deny check` passes after changes (advisories, bans, licenses, sources)
5. Check that `Cargo.lock` is committed (this is a binary crate - lockfile is required)

### 6. Check Architecture Constraints (`README.md` + repo layout)

- `#![forbid(unsafe_code)]` MUST remain at the crate root - this is a non-negotiable security property of the project
- Release profile in `Cargo.toml` MUST preserve hardening: `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true`
- Subcommand handlers live under `src/handlers/`: `account.rs`, `cert.rs`, `challenge.rs`, `config.rs`, `hooks.rs`, `order.rs`, plus the multi-file `run_flow/` directory (`mod.rs`, `finalize.rs`, `preauth.rs`, `renewal.rs`, and the `authorize/` subdir). Do NOT inline new subcommands back into `src/main.rs` or `src/cli.rs`.
- `src/cli.rs` contains only clap types (`Cli`, `Commands`, `OutputFormat`, `CertKeyAlgorithm`); business logic stays out
- `src/cli_config.rs` owns the CLI ⇄ config ⇄ env merge (`load_config` + `apply_config`, with the precedence rules documented at the top of the file); `src/config.rs` owns the TOML deserialization types (`Config`, `GlobalConfig`, …) — keep these two responsibilities separate and do NOT replicate merge logic in handlers
- `src/cleanup.rs` is the single SIGINT cleanup registry - new long-lived resources (challenge dirs, DNS records, listening sockets) register here
- Cross-cutting helpers live in dedicated modules: `src/cert_info.rs`, `src/account_key.rs`, `src/csr.rs`, `src/jws.rs`, `src/challenge.rs`, `src/dns_check.rs`, `src/hook_check.rs`, `src/fs_secure.rs`, `src/output.rs`, `src/types.rs`, `src/defaults.rs`
- ACME protocol behavior MUST match the cited RFCs/drafts: RFC 8555 (core), RFC 8738 (IP identifiers), RFC 9773 (ARI), draft-ietf-acme-dns-persist, draft-ietf-acme-profiles-01
- Output format MUST honor `--output-format json|text` and `--silent` globally - new subcommands must respect both, routing through `src/output.rs`

### 7. Output Report

Format as a structured markdown report:

```markdown
## Code Review: <file(s) or scope>

### Summary
- X errors, Y warnings, Z info items
- Categories checked: ownership, errors, types, perf, async, API, OWASP, crate versions

### Errors (must fix before merge)

| File | Line | Category | Rule | Issue | Fix |
|------|------|----------|------|-------|-----|
| ... | ... | ... | ... | ... | ... |

### Warnings (should fix)

| File | Line | Category | Rule | Issue | Fix |
|------|------|----------|------|-------|-----|
| ... | ... | ... | ... | ... | ... |

### Info (consider)

| File | Line | Category | Rule | Issue | Fix |
|------|------|----------|------|-------|-----|
| ... | ... | ... | ... | ... | ... |
```

If no violations found, state "No violations found - all checks passed"
with confirmation of categories checked and file count reviewed.
