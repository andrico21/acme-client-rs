# acme-client-rs

[![CI](https://github.com/andrico21/acme-client-rs/actions/workflows/rust.yaml/badge.svg?branch=master)](https://github.com/andrico21/acme-client-rs/actions/workflows/rust.yaml)

A lightweight, single-binary ACME client implementing [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) with [RFC 9702](https://www.rfc-editor.org/rfc/rfc9702) (ACME Renewal Information) and [DNS-PERSIST-01](https://datatracker.ietf.org/doc/html/draft-sheurich-acme-dns-persist) support. Handles the full certificate lifecycle, from account registration through issuance, renewal, and revocation, in a single ~2 MB binary. The statically linked (musl) Linux binary and the Windows binary have zero runtime dependencies.

Built in Rust (edition 2024) with `#![forbid(unsafe_code)]`, hardened release binaries (CFG, ASLR, full RELRO, NX), and structured JSON output for CI/CD integration.

> **AI Disclosure:** This project was developed with AI assistance using [Claude Opus 4.6](https://www.anthropic.com/claude) (via GitHub Copilot). All code, documentation, and tests were reviewed and validated by the author.

## Installation

Download a prebuilt binary from the [latest release](https://github.com/andrico21/acme-client-rs/releases/latest):

| Artifact | Platform | Linking | Notes |
|---|---|---|---|
| `acme-client-rs-linux-x86_64-musl.tar.gz` | Linux x86_64 | **Static (musl)** | **Recommended.** No runtime dependencies — works on any Linux distro. |
| `acme-client-rs-linux-x86_64-gnu.tar.gz` | Linux x86_64 | Dynamic (GNU) | Requires GLIBC 2.39+ (Ubuntu 24.04+, Fedora 40+, Debian trixie+). |
| `acme-client-rs-darwin-x86_64.tar.gz` | macOS x86_64 | Dynamic | Intel Macs. |
| `acme-client-rs-darwin-arm64.tar.gz` | macOS ARM64 | Dynamic | Apple Silicon (M1+). |
| `acme-client-rs-windows-x86_64-msvc.zip` | Windows x86_64 | Dynamic (MSVC) | Windows 10+. |

**Linux quick install (static binary):**

```sh
curl -sL https://github.com/andrico21/acme-client-rs/releases/latest/download/acme-client-rs-linux-x86_64-musl.tar.gz | tar xz
sudo install -m 755 acme-client-rs /usr/local/bin/
```

> **Tip:** On Linux, always prefer the **musl** binary. The GNU variant dynamically links against the system GLIBC and will fail on distributions shipping GLIBC older than 2.39 (e.g., RHEL 9, Rocky 9, Debian 12, Ubuntu 22.04).

Alternatively, build from source — see [Building](#building) below.

## Features

- Full RFC 8555 protocol: account management, key rollover, order lifecycle, challenge handling, certificate download, revocation
- Four challenge types: HTTP-01 (built-in server or `--challenge-dir`), DNS-01 (interactive, hook scripts, auto-propagation check), DNS-PERSIST-01 (persistent DNS records, [draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/html/draft-sheurich-acme-dns-persist)), TLS-ALPN-01 (interactive)
- External Account Binding (EAB) for CAs that require it (`--eab-kid` + `--eab-hmac-key`)
- Pre-authorization (RFC 8555 Section 7.4.1) via `pre-authorize` subcommand or `--pre-authorize` flag on `run`
- Generic hook scripts: `--on-challenge-ready` (called after each dns-01, dns-persist-01, or tls-alpn-01 challenge is set up) and `--on-cert-issued` (called after certificate is saved)
- IP identifier support (RFC 8738) with IPv6 normalization - auto-detected from CLI input
- Automated end-to-end flow (`run` subcommand) with built-in renewal (`--days N` skips if not due - no separate renew command needed)
- ACME Renewal Information (ARI, RFC 9702): `renewal-info` subcommand to query the CA's suggested renewal window, and `--ari` flag on `run` to use server-recommended renewal timing with `replaces` order linkage
- Optional private key encryption (`--key-password` / `--key-password-file`) using PKCS#8 + AES-256-CBC with scrypt KDF
- Step-by-step manual flow (individual subcommands)
- Six key algorithms: ES256 (default), ES384, ES512, RSA-2048, RSA-4096, Ed25519
- Configurable via CLI flags, config file, or environment variables
- `--insecure` flag for testing with self-signed CAs (e.g., Pebble)
- Clean error messages (no stack traces for operational errors)
- Structured JSON output (`--output-format json`) for machine consumption and CI/CD pipelines

## Quick Start

```sh
# 1. Generate an account key (ES256 by default)
acme-client-rs generate-key

# 2. Run the full flow against a server
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 your.domain.com

# 3. Renew - just re-run with --days (skips if not due yet)
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 --challenge-dir /var/www/html --cert-output /etc/ssl/certs/your.domain.pem --key-output /etc/ssl/private/your.domain.key --days 30 your.domain.com
```

> **Tip:** There is no separate `renew` command. The `run` subcommand with `--days N` is idempotent - it checks the existing certificate and only contacts the CA when renewal is actually needed. Safe to call from cron daily.

### Key Algorithms

```sh
# Default: ES256 (P-256)
acme-client-rs generate-key

# Other algorithms
acme-client-rs generate-key --algorithm es384
acme-client-rs generate-key --algorithm es512
acme-client-rs generate-key --algorithm rsa2048
acme-client-rs generate-key --algorithm rsa4096
acme-client-rs generate-key --algorithm ed25519
```

### Certificate Key Algorithm

The certificate private key (used in the CSR) is separate from the account key. By default, ECDSA P-256 is used. You can change it with `--cert-key-algorithm`:

```sh
# Default: ECDSA P-256
acme-client-rs run --cert-key-algorithm ec-p256 ...

# ECDSA P-384
acme-client-rs run --cert-key-algorithm ec-p384 ...

# Ed25519
acme-client-rs run --cert-key-algorithm ed25519 ...
```

Supported values: `ec-p256` (P-256/SHA-256, default), `ec-p384` (P-384/SHA-384), `ed25519`.

### DNS-01 Challenge

Three modes of operation:

#### Interactive (default)

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-01 your.domain.com
```

The client prints the TXT record to create, then waits for Enter:

```
=== DNS-01 Challenge ===
Create a DNS TXT record:
  Name:  _acme-challenge.your.domain.com
  Type:  TXT
  Value: <base64url-encoded-sha256>

Press Enter once the record has propagated...
```

#### Hook script (`--dns-hook`)

Automate DNS record creation/cleanup with an external script:

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-01 --dns-hook /usr/local/bin/dns-hook.sh your.domain.com
```

The hook script is called twice per authorization:

1. **Before validation** with `ACME_ACTION=create` - create the TXT record
2. **After validation** with `ACME_ACTION=cleanup` - remove the TXT record

Environment variables passed to the hook:

| Variable | Example |
|---|---|
| `ACME_ACTION` | `create` or `cleanup` |
| `ACME_DOMAIN` | `your.domain.com` |
| `ACME_TXT_NAME` | `_acme-challenge.your.domain.com` |
| `ACME_TXT_VALUE` | `aB3xY...base64url...` |

Example hook script (Cloudflare API):

```bash
#!/usr/bin/env bash
set -euo pipefail

# Uses CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID from environment
API="https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records"
AUTH="Authorization: Bearer ${CLOUDFLARE_API_TOKEN}"

case "${ACME_ACTION}" in
  create)
    curl -s -X POST "${API}" -H "${AUTH}" -H "Content-Type: application/json" --data '{"type":"TXT","name":"'"${ACME_TXT_NAME}"'","content":"\"'"${ACME_TXT_VALUE}"'\"","ttl":120}'
    ;;
  cleanup)
    RECORD_ID=$(curl -s "${API}?type=TXT&name=${ACME_TXT_NAME}" -H "${AUTH}" | jq -r '.result[0].id')
    if [ "${RECORD_ID}" != "null" ]; then
      curl -s -X DELETE "${API}/${RECORD_ID}" -H "${AUTH}"
    fi
    ;;
esac
```

#### Auto-propagation check (`--dns-wait`)

Poll DNS until the TXT record is visible (or timeout):

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-01 --dns-hook /usr/local/bin/dns-hook.sh --dns-wait 120 your.domain.com
```

`--dns-wait <SECONDS>` polls every 5 seconds using `dig` (with `nslookup` fallback on Windows) until the TXT record appears or the timeout is reached.

Can be combined with `--dns-hook` (fully automated) or used alone (prints instructions, then auto-waits instead of prompting for Enter).

### TLS-ALPN-01 Challenge (interactive)

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type tls-alpn-01 your.domain.com
```

The client prints the `acmeIdentifier` extension value. You must configure a TLS server on port 443 with a self-signed certificate containing this extension before pressing Enter.

### DNS-PERSIST-01 Challenge (draft-ietf-acme-dns-persist)

DNS-PERSIST-01 uses a persistent DNS TXT record at `_validation-persist.<domain>` to prove domain control. Unlike DNS-01, the record does not change between issuances - once set up, it can be reused for future certificate renewals without modification.

The record binds a domain to your ACME account and a specific CA (identified by issuer domain name).

#### Interactive (default)

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-persist-01 your.domain.com
```

The client prints the TXT record to create, then waits for Enter:

```
=== DNS-PERSIST-01 Challenge ===
Create a DNS TXT record:
  Name:  _validation-persist.your.domain.com
  Type:  TXT
  Value: letsencrypt.org; accounturi=https://acme-server/acme/acct/123

This record is persistent - it can be reused for future issuances.
Unlike dns-01, it does not need to change per issuance.

Press Enter once the record has propagated...
```

#### With policy and persistUntil

For wildcard certificates, use `--persist-policy wildcard`. The `--persist-until` flag sets a Unix timestamp after which the record should be considered expired:

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-persist-01 --persist-policy wildcard --persist-until 1767225600 "*.your.domain.com" your.domain.com
```

This creates a record like:

```
letsencrypt.org; accounturi=https://acme-server/acme/acct/123; policy=wildcard; persistUntil=1767225600
```

#### Hook script (`--dns-hook`)

Automate DNS record creation with an external script:

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-persist-01 --dns-hook /usr/local/bin/dns-hook.sh your.domain.com
```

The hook is called with `ACME_ACTION=create` before validation and `ACME_ACTION=cleanup` after:

| Variable | Example |
|---|---|
| `ACME_ACTION` | `create` or `cleanup` |
| `ACME_DOMAIN` | `your.domain.com` |
| `ACME_TXT_NAME` | `_validation-persist.your.domain.com` |
| `ACME_TXT_VALUE` | `letsencrypt.org; accounturi=https://...` |

#### Auto-propagation check (`--dns-wait`)

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-persist-01 --dns-hook /usr/local/bin/dns-hook.sh --dns-wait 120 your.domain.com
```

#### Show record setup instructions

The `show-dns-persist01` subcommand displays the record you need to create, without running the full ACME flow:

```sh
acme-client-rs --directory https://your-acme-server/directory show-dns-persist01 --domain your.domain.com --issuer-domain-name letsencrypt.org
```

With JSON output:

```sh
acme-client-rs --directory https://your-acme-server/directory --output-format json show-dns-persist01 --domain your.domain.com --issuer-domain-name letsencrypt.org --persist-policy wildcard --persist-until 1767225600
```

> **Note:** DNS-PERSIST-01 is defined in [draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/html/draft-sheurich-acme-dns-persist). Pebble already supports it. Let's Encrypt staging support is expected late Q1 2026, production Q2 2026.

### Using --challenge-dir (reverse proxy integration)

If you already have a web server (nginx, Apache, etc.) serving port 80, use `--challenge-dir` to write the challenge file to a directory it serves:

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 --challenge-dir /var/www/html your.domain.com
```

The client writes the token file to `/var/www/html/.well-known/acme-challenge/<token>` and cleans it up after validation.

### IP Identifiers (RFC 8738)

IP addresses are auto-detected - just pass them as positional arguments:

```sh
# IPv4
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 192.0.2.1

# IPv6 (bracketed or bare)
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 [2001:db8::1]
```

> **Note:** DNS-01 and DNS-PERSIST-01 challenges are not supported for IP identifiers. Use HTTP-01 or TLS-ALPN-01.

### Multi-SAN Certificates

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 example.com www.example.com api.example.com
```

<details>
<summary><h2>Building</h2></summary>

### Standard Release Build

```sh
cargo build --release
```

The binary is at `target/release/acme-client-rs` (or `.exe` on Windows).

### Smallest Hardened Binary

The `release` profile in `Cargo.toml` is already configured for minimum size and no debug info:

```toml
[profile.release]
opt-level = "z"        # Optimize for size (not speed)
lto = true             # Full link-time optimization - eliminates dead code across crates
codegen-units = 1      # Single codegen unit - maximum optimization
panic = "abort"        # No unwind tables - saves ~100-200 KB
strip = true           # Strip all symbols and DWARF debug info
```

Build with all security hardening flags:

#### Windows (MSVC)

```powershell
$env:RUSTFLAGS = "-C control-flow-guard=yes -C link-args=/DYNAMICBASE -C link-args=/HIGHENTROPYVA -C link-args=/NXCOMPAT -C link-args=/CETCOMPAT"
cargo build --release
```

| Flag | Effect |
|---|---|
| `control-flow-guard=yes` | Enables Control Flow Guard (CFG) - prevents call-target hijacking |
| `/DYNAMICBASE` | ASLR - randomizes base address at load time (default on, explicit for clarity) |
| `/HIGHENTROPYVA` | 64-bit high-entropy ASLR - uses full address space |
| `/NXCOMPAT` | DEP/NX - marks stack and heap as non-executable |
| `/CETCOMPAT` | Intel CET shadow stack - hardware-enforced return address protection |

#### Linux (GNU/musl)

**Prerequisites:** The `native-tls` crate uses OpenSSL on Linux. Install the development headers first:

| Distro | Install command |
|---|---|
| Debian / Ubuntu | `sudo apt install pkg-config libssl-dev` |
| RHEL / Fedora | `sudo dnf install pkg-config openssl-devel` |
| Alpine (musl) | `apk add pkgconf openssl-dev openssl-libs-static` |
| Arch | `sudo pacman -S pkg-config openssl` |

```sh
RUSTFLAGS="-C relocation-model=pie -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack" cargo build --release
```

For a fully static binary (no glibc dependency):

```sh
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack" cargo build --release --target x86_64-unknown-linux-musl
```

| Flag | Effect |
|---|---|
| `relocation-model=pie` | Position-Independent Executable - enables ASLR |
| `-z relro` | Read-only relocations - GOT is read-only after startup |
| `-z now` | Full RELRO - resolve all symbols at load time (not lazily) |
| `-z noexecstack` | Non-executable stack (NX) |
| `target-feature=+crt-static` | Statically link the C runtime (with musl) |

#### macOS

```sh
RUSTFLAGS="-C relocation-model=pie" cargo build --release
```

macOS enables most protections by default (ASLR, NX stack, code signing).

### Verify Security Properties

#### Windows

```powershell
# Check binary flags with dumpbin (from VS Developer Command Prompt)
dumpbin /headers target\release\acme-client-rs.exe | Select-String "DLL characteristics"
# Should show: Dynamic base, NX compatible, High Entropy VA, Guard CF, CET Compatible
```

#### Linux

```sh
# checksec (from pwntools or checksec.sh)
checksec --file=target/release/acme-client-rs
# Expected: RELRO=Full, Stack Canary=yes, NX=yes, PIE=yes

# Or manually
readelf -l target/release/acme-client-rs | grep -i "gnu_relro\|gnu_stack"
file target/release/acme-client-rs  # should say "ELF 64-bit ... dynamically linked" or "statically linked"
```

### Building with Podman (or Docker)

You can produce a fully static Linux binary inside a container - no local Rust toolchain or OpenSSL headers needed.

The example below uses a multi-stage build: the first stage compiles against musl with a vendored OpenSSL 3.5.x, and the second stage copies out the binary.

Create a `Containerfile` (works with both `podman` and `docker`):

```dockerfile
# -- Stage 1: Build --
FROM docker.io/library/rust:alpine AS builder

RUN apk add --no-cache musl-dev pkgconf openssl-dev openssl-libs-static perl make

WORKDIR /src
COPY . .

# Static musl build with full security hardening
ENV OPENSSL_STATIC=1
ENV RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack"

RUN cargo build --release && strip target/release/acme-client-rs

# -- Stage 2: Minimal runtime image --
FROM docker.io/library/alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /src/target/release/acme-client-rs /usr/local/bin/acme-client-rs

ENTRYPOINT ["acme-client-rs"]
```

Build and extract the binary:

```sh
# Build the image
podman build -t acme-client-rs .

# Copy the static binary out of the image
podman create --name acme-tmp acme-client-rs
podman cp acme-tmp:/usr/local/bin/acme-client-rs ./acme-client-rs
podman rm acme-tmp

# Verify
file ./acme-client-rs
# -> ELF 64-bit LSB pie executable, x86-64, statically linked
./acme-client-rs --help
```

Or run directly from the container:

```sh
podman run --rm acme-client-rs --help
podman run --rm -v ./certs:/certs:Z acme-client-rs --directory https://acme-server/directory --account-key /certs/account.key run --contact you@example.com your.domain.com
```

> **Note:** Alpine's `openssl-dev` package ships OpenSSL 3.5.x (3.5.5 as of this writing). The `OPENSSL_STATIC=1` env var tells the `openssl-sys` build script to link OpenSSL statically, producing a fully self-contained binary with no runtime dependencies. The `rust:alpine` base image uses musl libc natively, so no cross-compilation target is needed.

To use Docker instead of Podman, simply replace `podman` with `docker` in all commands above.

### Size Comparison

Typical binary sizes (x86_64, Windows MSVC):

| Profile | Approximate Size |
|---|---|
| `debug` (default) | ~25-30 MB |
| `release` (before tuning) | ~4.8 MB |
| `release` (opt-level=z, LTO, strip, abort + CFG/ASLR/DEP/CET) | ~2.3 MB |

</details>

<details>
<summary><h2>Configuration File</h2></summary>

All CLI flags can be set in a TOML config file. Generate a self-documented template:

```sh
acme-client-rs generate-config > acme-client-rs.toml
```

A ready-made example is also included in the repository as `acme-client-rs.toml.example`.

The config file is optional. Load it with `--config <PATH>` or `ACME_CONFIG` env var.

**Priority without config file:** CLI flags > environment variables > built-in defaults.
**Priority with config file:** CLI flags > config file > built-in defaults.

When a config file is loaded, environment variables are **ignored** — the config file is the single source of truth. Exceptions: `ACME_INSECURE`, key passwords (`--key-password-file`), and EAB credentials (`--eab-kid`, `--eab-hmac-key`) are still read from the environment as a fallback for secrets that shouldn't be stored in config files.

Loading behavior:
- `--config <PATH>` (or `ACME_CONFIG` env var): load from the specified path (env vars ignored)
- No config file: CLI flags and environment variables work normally

Example config:

```toml
[global]
directory = "https://acme-v02.api.letsencrypt.org/directory"
account_key = "/etc/acme/account.key"

[run]
domains = ["example.com", "www.example.com"]
contact = "admin@example.com"
challenge_type = "http-01"
challenge_dir = "/var/www/acme"
cert_output = "/etc/ssl/certs/example.com.pem"
key_output = "/etc/ssl/private/example.com.key"
days = 30
```

With this config in place, renewal becomes a single command:

```sh
acme-client-rs --config acme-client-rs.toml run
```

CLI flags override the config file, so you can still customize per invocation:

```sh
acme-client-rs run --challenge-type dns-01 other.domain.com
```

To see the effective merged configuration and where each value comes from:

```sh
acme-client-rs show-config --verbose
```

Each value is annotated with its source: `(cli)`, `(env)`, `(config)`, or `(default)`.

</details>

<details>
<summary><h2>How ACME Works</h2></summary>

The ACME protocol (RFC 8555) automates certificate issuance through a challenge-response flow. Here's how each step maps to `acme-client-rs` commands:

```
Client                                ACME Server (e.g. Let's Encrypt)
  |                                         |
  |  1. GET /directory                      |
  |  ------------------------------------>  |   Discover endpoints
  |  <------------------------------------  |   {newNonce, newAccount, newOrder, ...}
  |                                         |
  |  2. POST /newAccount                    |   -- account --
  |  ------------------------------------>  |   Register or find existing account
  |  <------------------------------------  |   Account URL + status
  |                                         |
  |  3. POST /newOrder                      |   -- order --
  |  ------------------------------------>  |   Request cert for domain(s)
  |  <------------------------------------  |   Order URL + authorization URLs
  |                                         |
  |  4. POST /authz/{id}                    |   -- get-authz --
  |  ------------------------------------>  |   Get challenges for each domain
  |  <------------------------------------  |   [http-01, dns-01, dns-persist-01, tls-alpn-01]
  |                                         |
  |  5. Prove domain control                |   -- serve-http01 / show-dns01 --
  |     HTTP-01: serve token on port 80     |
  |     DNS-01:  create _acme-challenge TXT |
  |     DNS-PERSIST-01: persistent TXT rec  |
  |     TLS-ALPN-01: serve acmeIdentifier   |
  |                                         |
  |  6. POST /challenge/{id}                |   -- respond-challenge --
  |  ------------------------------------>  |   "I'm ready, validate me"
  |  <------------------------------------  |   Challenge status: processing/valid
  |                                         |
  |  7. POST /order/{id}/finalize           |   -- finalize --
  |  ------------------------------------>  |   Submit CSR
  |  <------------------------------------  |   Order status: processing/valid
  |                                         |
  |  8. POST /order/{id}                    |   -- poll-order --
  |  ------------------------------------>  |   Wait for issuance
  |  <------------------------------------  |   Certificate URL
  |                                         |
  |  9. POST /certificate/{id}              |   -- download-cert --
  |  ------------------------------------>  |   Fetch certificate chain
  |  <------------------------------------  |   PEM (end-entity + intermediates)
  |                                         |
  | 10. POST /revokeCert (optional)         |   -- revoke-cert --
  |  ------------------------------------>  |   Revoke a certificate
  |  <------------------------------------  |   200 OK
  |                                         |
  | 11. GET /renewalInfo/{certID} (ARI)     |   -- renewal-info --
  |  ------------------------------------>  |   Query renewal timing (RFC 9702)
  |  <------------------------------------  |   suggestedWindow {start, end}
```

The `run` subcommand executes steps 1-9 automatically (and optionally step 11 with `--ari`). Individual subcommands let you perform each step manually.

> **All requests after step 1 are signed with JWS (JSON Web Signature) using your account key. The server authenticates every request via the key thumbprint.**

</details>

<details>
<summary><h2>Real-World Examples with Let's Encrypt</h2></summary>

### Issue a Certificate (HTTP-01, standalone server)

```sh
# Generate an account key
acme-client-rs generate-key --account-key /etc/acme/account.key

# Issue a certificate (the client binds port 80 for validation)
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key example.com www.example.com
```

### Issue a Certificate (HTTP-01, with nginx)

If nginx already serves port 80, use `--challenge-dir` to drop the token file into the webroot:

```nginx
# /etc/nginx/snippets/acme-challenge.conf
location /.well-known/acme-challenge/ {
    root /var/www/acme;
    try_files $uri =404;
}
```

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --challenge-dir /var/www/acme --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key example.com www.example.com

# Reload nginx to pick up the new cert
sudo systemctl reload nginx
```

### Issue a Wildcard Certificate (DNS-01 or DNS-PERSIST-01)

Wildcards require DNS-01 or DNS-PERSIST-01 validation.

**Interactive** (manual DNS record creation):

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type dns-01 --cert-output /etc/ssl/certs/wildcard.example.com.pem --key-output /etc/ssl/private/wildcard.example.com.key "*.example.com" example.com
```

**Automated** (with hook script and propagation check):

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type dns-01 --dns-hook /usr/local/bin/dns-hook.sh --dns-wait 120 --cert-output /etc/ssl/certs/wildcard.example.com.pem --key-output /etc/ssl/private/wildcard.example.com.key "*.example.com" example.com
```

**DNS-PERSIST-01** (persistent record - no per-issuance changes needed):

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type dns-persist-01 --persist-policy wildcard --cert-output /etc/ssl/certs/wildcard.example.com.pem --key-output /etc/ssl/private/wildcard.example.com.key "*.example.com" example.com
```

### Revoke a Certificate

```sh
# Revoke (no reason code)
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key revoke-cert /etc/ssl/certs/example.com.pem

# Revoke with reason code (4 = superseded)
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key revoke-cert /etc/ssl/certs/example.com.pem --reason 4
```

Reason codes (RFC 5280 Section 5.3.1):

| Code | Reason |
|------|--------|
| 0 | Unspecified |
| 1 | Key compromise |
| 3 | Affiliation changed |
| 4 | Superseded |
| 5 | Cessation of operation |

<details>
<summary><strong>Step-by-Step Manual Flow (Let's Encrypt)</strong></summary>

```sh
export ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
export ACME_ACCOUNT_KEY_FILE=/etc/acme/account.key

# 1. Register account
acme-client-rs account --contact admin@example.com
# Output: Account URL: https://acme-v02.api.letsencrypt.org/acme/acct/123456789

export ACME_ACCOUNT_URL=https://acme-v02.api.letsencrypt.org/acme/acct/123456789

# 2. Place order
acme-client-rs order example.com www.example.com
# Output: Order URL, authorization URLs, finalize URL

# 3. Check each authorization
acme-client-rs get-authz https://acme-v02.api.letsencrypt.org/acme/authz/abc123
# Output: challenge type, token, URL

# 4. Serve the challenge (standalone, port 80)
acme-client-rs serve-http01 --token <token> --port 80 &

# 5. Tell the server to validate
acme-client-rs respond-challenge https://acme-v02.api.letsencrypt.org/acme/chall/xyz789

# 6. Finalize with CSR
acme-client-rs finalize --finalize-url https://acme-v02.api.letsencrypt.org/acme/order/123/finalize example.com www.example.com

# 7. Poll until certificate is ready
acme-client-rs poll-order https://acme-v02.api.letsencrypt.org/acme/order/123

# 8. Download the certificate
acme-client-rs download-cert https://acme-v02.api.letsencrypt.org/acme/cert/abc123 --output /etc/ssl/certs/example.com.pem
```

</details>

</details>

<details>
<summary><h2>Automation</h2></summary>

> **No separate `renew` command needed.** The `run` subcommand doubles as the renewal command when you add `--days N`. It reads the certificate at `--cert-output`, checks how many days remain, and only contacts the CA if renewal is due. Exit code is 0 whether it renewed or skipped.

### Simple Renewal (using built-in `--days`)

The `--days` flag makes `run` idempotent - it skips issuance if the existing certificate has more than N days remaining:

```sh
# Renew only if less than 30 days remain (exits 0 either way)
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --challenge-dir /var/www/acme --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key --days 30 example.com www.example.com && sudo systemctl reload nginx
```

Add to cron for fully automated renewals:

```cron
0 3 * * * root acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --challenge-dir /var/www/acme --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key --days 30 example.com && systemctl reload nginx >> /var/log/acme-renew.log 2>&1
```

### Server-Guided Renewal with ARI (RFC 9702)

ACME Renewal Information (ARI) lets the CA tell your client when to renew. Instead of a fixed `--days` threshold, the server provides a suggested time window based on certificate lifetime, revocation events, or policy changes.

**Query the renewal window:**

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key renewal-info /etc/ssl/certs/example.com.pem
```

Output:

```
CertID:   <base64url(AKI)>.<base64url(Serial)>
Suggested renewal window:
  Start:  2026-04-01T00:00:00Z
  End:    2026-04-15T00:00:00Z
Status:   not yet due (20 days until window opens)
```

**Use ARI in automated renewal:**

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --challenge-dir /var/www/acme --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key --ari example.com www.example.com && sudo systemctl reload nginx
```

How `--ari` works:

1. Parses the existing certificate at `--cert-output`
2. Queries the CA's `renewalInfo` endpoint with the cert's AKI and serial number
3. If the current time is before the suggested window start, skips renewal
4. If within the window (or past it), proceeds with renewal and includes the `replaces` field in the order, allowing the CA to link the new certificate to the old one
5. If ARI is unavailable (server doesn't support it, or the query fails), falls back to `--days` threshold

Combine `--ari` and `--days` for defense in depth:

```sh
# ARI decides timing when available; --days is the safety net
acme-client-rs run --ari --days 30 --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key --contact admin@example.com example.com
```

**Recommended pattern:** set up a daily cron job (or systemd timer) that runs the full `run` command with `--ari --days 30`. Most days the client exits immediately ("renewal window not open yet"). When the CA's suggested window opens, it renews automatically. If ARI is unavailable, `--days 30` acts as a safety net:

```cron
# /etc/cron.d/acme-ari-renew
0 3 * * * root /usr/local/bin/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory \
  --account-key /etc/acme/account.key \
  run --ari --days 30 \
  --contact admin@example.com \
  --challenge-type http-01 --challenge-dir /var/www/acme \
  --cert-output /etc/ssl/certs/example.com.pem \
  --key-output /etc/ssl/private/example.com.key \
  example.com www.example.com \
  && systemctl reload nginx >> /var/log/acme-renew.log 2>&1
```

The key benefit: the CA controls *when* you renew (via the suggested window), which helps spread out renewal load and lets the CA signal early renewal if there's a revocation event or policy change.

> **Note:** ARI requires the CA to advertise a `renewalInfo` URL in its directory. Let's Encrypt supports ARI. When the server doesn't support ARI, `--ari` silently falls back to `--days`.

### Bash Script: Issue and Renew

```bash
#!/usr/bin/env bash
# /usr/local/bin/acme-renew.sh
# Issue or renew a certificate, then reload the web server.
set -euo pipefail

DOMAIN="example.com"
ACME_DIR="https://acme-v02.api.letsencrypt.org/directory"
ACCOUNT_KEY="/etc/acme/account.key"
CERT="/etc/ssl/certs/${DOMAIN}.pem"
KEY="/etc/ssl/private/${DOMAIN}.key"
CONTACT="admin@${DOMAIN}"
WEBROOT="/var/www/acme"
RENEW_DAYS=30

# Check if certificate exists and is not expiring soon
if [ -f "${CERT}" ]; then
    EXPIRY=$(openssl x509 -enddate -noout -in "${CERT}" | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "${EXPIRY}" +%s)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

    if [ "${DAYS_LEFT}" -gt "${RENEW_DAYS}" ]; then
        echo "Certificate valid for ${DAYS_LEFT} days, skipping renewal"
        exit 0
    fi
    echo "Certificate expires in ${DAYS_LEFT} days, renewing..."
fi

# Generate account key if it doesn't exist
if [ ! -f "${ACCOUNT_KEY}" ]; then
    acme-client-rs generate-key --account-key "${ACCOUNT_KEY}"
fi

# Issue/renew the certificate
acme-client-rs --directory "${ACME_DIR}" --account-key "${ACCOUNT_KEY}" run --contact "${CONTACT}" --challenge-type http-01 --challenge-dir "${WEBROOT}" --cert-output "${CERT}" --key-output "${KEY}" "${DOMAIN}" "www.${DOMAIN}"

# Reload web server
sudo systemctl reload nginx

echo "Certificate renewed successfully"
```

```sh
chmod +x /usr/local/bin/acme-renew.sh
```

### Cron Job: Daily Renewal Check

```cron
# /etc/cron.d/acme-renew
# Check daily at 3:00 AM, renew if within 30 days of expiry
0 3 * * * root /usr/local/bin/acme-renew.sh >> /var/log/acme-renew.log 2>&1
```

### systemd Timer: Scheduled Renewal

```ini
# /etc/systemd/system/acme-renew.service
[Unit]
Description=ACME certificate renewal
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/acme-renew.sh
StandardOutput=journal
StandardError=journal
# Security hardening
ProtectSystem=strict
ReadWritePaths=/etc/ssl/certs /etc/ssl/private /etc/acme /var/www/acme
PrivateTmp=true
NoNewPrivileges=true
```

```ini
# /etc/systemd/system/acme-renew.timer
[Unit]
Description=Run ACME renewal twice daily

[Timer]
OnCalendar=*-*-* 03,15:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now acme-renew.timer

# Check timer status
systemctl list-timers acme-renew.timer
# Check logs
journalctl -u acme-renew.service
```

### Multi-Domain Renewal Script

```bash
#!/usr/bin/env bash
# /usr/local/bin/acme-renew-all.sh
# Renew certificates for multiple domains from a config list.
set -euo pipefail

ACME_DIR="https://acme-v02.api.letsencrypt.org/directory"
ACCOUNT_KEY="/etc/acme/account.key"
CONTACT="admin@example.com"
WEBROOT="/var/www/acme"
RENEW_DAYS=30

# Domain list: one primary domain per line, SANs space-separated
DOMAINS_FILE="/etc/acme/domains.txt"
# Example /etc/acme/domains.txt:
#   example.com www.example.com
#   api.example.com
#   *.internal.example.com internal.example.com

RENEWED=0

while IFS= read -r line; do
    [ -z "${line}" ] && continue
    [[ "${line}" =~ ^# ]] && continue

    # First domain is the primary (used for filenames)
    PRIMARY=$(echo "${line}" | awk '{print $1}' | tr -d '*.')
    CERT="/etc/ssl/certs/${PRIMARY}.pem"
    KEY="/etc/ssl/private/${PRIMARY}.key"

    # Check expiry
    if [ -f "${CERT}" ]; then
        DAYS_LEFT=$(( ( $(date -d "$(openssl x509 -enddate -noout -in "${CERT}" | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
        if [ "${DAYS_LEFT}" -gt "${RENEW_DAYS}" ]; then
            echo "[SKIP] ${PRIMARY}: ${DAYS_LEFT} days remaining"
            continue
        fi
        echo "[RENEW] ${PRIMARY}: ${DAYS_LEFT} days remaining"
    else
        echo "[NEW] ${PRIMARY}: no certificate found"
    fi

    # Determine challenge type (wildcard requires dns-01)
    CHALLENGE="http-01"
    EXTRA_ARGS=(--challenge-dir "${WEBROOT}")
    if echo "${line}" | grep -q '\*'; then
        CHALLENGE="dns-01"
        EXTRA_ARGS=()
    fi

    # shellcheck disable=SC2086
    acme-client-rs --directory "${ACME_DIR}" --account-key "${ACCOUNT_KEY}" run --contact "${CONTACT}" --challenge-type "${CHALLENGE}" "${EXTRA_ARGS[@]}" --cert-output "${CERT}" --key-output "${KEY}" ${line}

    RENEWED=$((RENEWED + 1))
done < "${DOMAINS_FILE}"

if [ "${RENEWED}" -gt 0 ]; then
    echo "Renewed ${RENEWED} certificate(s), reloading nginx"
    sudo systemctl reload nginx
fi
```

### Application-Driven: Using Built-in Hook Scripts

The `--on-challenge-ready` and `--on-cert-issued` flags let you run scripts at key points in the ACME flow without writing a wrapper:

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --challenge-dir /var/www/acme --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key --on-cert-issued /usr/local/bin/deploy-cert.sh example.com www.example.com
```

Example `deploy-cert.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
# ACME_DOMAINS, ACME_CERT_PATH, ACME_KEY_PATH, ACME_KEY_ENCRYPTED set by acme-client-rs
echo "Certificate issued for: ${ACME_DOMAINS}"
cp "${ACME_CERT_PATH}" /opt/myapp/tls/cert.pem
cp "${ACME_KEY_PATH}" /opt/myapp/tls/key.pem
chown myapp:myapp /opt/myapp/tls/*.pem
sudo systemctl reload nginx
sudo systemctl restart myapp
```

Example `on-challenge-ready.sh` (e.g., to log or notify):

```bash
#!/usr/bin/env bash
set -euo pipefail
# ACME_DOMAIN, ACME_CHALLENGE_TYPE, ACME_TOKEN (dns-01/tls-alpn-01),
# ACME_KEY_AUTH (dns-01/tls-alpn-01), ACME_TXT_NAME (dns-01/dns-persist-01),
# ACME_TXT_VALUE (dns-01/dns-persist-01) set by acme-client-rs
echo "Challenge ready: ${ACME_CHALLENGE_TYPE} for ${ACME_DOMAIN}"
```

### Application-Driven: Wrapper Script with Hooks

For more complex pre/post logic (e.g., stopping services before binding port 80), a wrapper script gives full control:

```bash
#!/usr/bin/env bash
# /usr/local/bin/acme-with-hooks.sh
# Certificate issuance with pre/post hooks for service management.
set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain>}"
ACME_DIR="https://acme-v02.api.letsencrypt.org/directory"
ACCOUNT_KEY="/etc/acme/account.key"
CERT="/etc/ssl/certs/${DOMAIN}.pem"
KEY="/etc/ssl/private/${DOMAIN}.key"

# -- Pre-hook: stop conflicting services before port 80 bind --
pre_hook() {
    echo "Stopping nginx to free port 80..."
    sudo systemctl stop nginx
}

# -- Post-hook: deploy cert and restart services --
post_hook() {
    echo "Deploying certificate..."
    # Copy to application-specific locations if needed
    cp "${CERT}" /opt/myapp/tls/cert.pem
    cp "${KEY}" /opt/myapp/tls/key.pem
    chown myapp:myapp /opt/myapp/tls/*.pem

    echo "Starting nginx..."
    sudo systemctl start nginx

    echo "Restarting application..."
    sudo systemctl restart myapp
}

# -- Cleanup on failure --
cleanup() {
    echo "Ensuring nginx is running..."
    sudo systemctl start nginx || true
}
trap cleanup ERR

pre_hook

acme-client-rs --directory "${ACME_DIR}" --account-key "${ACCOUNT_KEY}" run --contact "admin@${DOMAIN}" --challenge-type http-01 --cert-output "${CERT}" --key-output "${KEY}" "${DOMAIN}"

post_hook

echo "Done: certificate issued and deployed for ${DOMAIN}"
```

### PowerShell: Windows Scheduled Task

```powershell
# acme-renew.ps1
$domain   = "example.com"
$acmeDir  = "https://acme-v02.api.letsencrypt.org/directory"
$acmeKey  = "C:\ProgramData\acme\account.key"
$certPath = "C:\ProgramData\acme\certs\$domain.pem"
$keyPath  = "C:\ProgramData\acme\certs\$domain.key"
$contact  = "admin@$domain"

# Check if renewal is needed
if (Test-Path $certPath) {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
    $daysLeft = ($cert.NotAfter - (Get-Date)).Days
    if ($daysLeft -gt 30) {
        Write-Host "Certificate valid for $daysLeft days, skipping"
        exit 0
    }
    Write-Host "Certificate expires in $daysLeft days, renewing..."
}

# Run the ACME flow
& acme-client-rs.exe `
  --directory $acmeDir `
  --account-key $acmeKey `
  run `
  --contact $contact `
  --challenge-type http-01 `
  --cert-output $certPath `
  --key-output $keyPath `
  $domain

if ($LASTEXITCODE -ne 0) { throw "ACME renewal failed" }

# Import into Windows certificate store (optional)
$pfxPath = "C:\ProgramData\acme\certs\$domain.pfx"
openssl pkcs12 -export -out $pfxPath -inkey $keyPath -in $certPath -passout pass:
Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\My

Write-Host "Certificate renewed and imported"
```

Register as a scheduled task:

```powershell
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-ExecutionPolicy Bypass -File C:\ProgramData\acme\acme-renew.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "3:00AM"
Register-ScheduledTask -TaskName "ACME Certificate Renewal" `
  -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest
```

</details>

<details>
<summary><h2>Testing with Pebble</h2></summary>

[Pebble](https://github.com/letsencrypt/pebble) is Let's Encrypt's miniature ACME test server. It's the easiest way to test ACME flows locally.

### 1. Start Pebble with Docker Compose

Create a `docker-compose.yml` (or use the one from the Pebble repo):

```yaml
version: "3"
services:
  pebble:
    image: letsencrypt/pebble:latest
    command: pebble -config /test/config/pebble-config.json -strict
    ports:
      - "14000:14000"  # ACME server
      - "15000:15000"  # Management interface
    environment:
      - PEBBLE_VA_NOSLEEP=1           # Speed up validation (no delay)
      - PEBBLE_VA_ALWAYS_VALID=1      # Accept any challenge without checking (for local testing)
      - PEBBLE_WFE_NONCEREJECT=0      # Don't randomly reject nonces

  challtestsrv:
    image: letsencrypt/pebble-challtestsrv:latest
    command: pebble-challtestsrv -defaultIPv4 host.docker.internal
    ports:
      - "8055:8055"   # Challenge test server management
```

Start it:

```sh
docker compose up -d
```

> **Note:** `PEBBLE_VA_ALWAYS_VALID=1` makes Pebble accept all challenges without actually verifying them. This is ideal for local testing where the validation server can't reach your machine. Remove this flag if you want to test real challenge validation.

### 2. Generate an Account Key

```sh
acme-client-rs generate-key --account-key account.key
```

### 3. Test the Full Flow (automated)

The default `--directory` points to `https://localhost:14000/dir` (Pebble's default), so no `--directory` flag is needed:

```sh
acme-client-rs run --contact test@example.com --challenge-type http-01 --http-port 5002 test.example.com
```

> **TLS note:** Pebble uses a self-signed certificate. Use the `--insecure` flag (or `ACME_INSECURE=true`) to skip TLS verification when testing against Pebble.

### 4. Test Step-by-Step (manual flow)

This walks through each ACME protocol step individually:

```sh
# Set variables for convenience
export ACME_DIRECTORY_URL=https://localhost:14000/dir
export ACME_ACCOUNT_KEY_FILE=account.key

# a) Create an account
acme-client-rs account --contact test@example.com
# -> Note the Account URL printed

# b) Place an order
export ACME_ACCOUNT_URL=<account-url-from-above>
acme-client-rs order test.example.com
# -> Note the authz URL(s) and finalize URL

# c) Check authorization details
acme-client-rs get-authz <authz-url>
# -> Note the challenge URL and token for your chosen type

# d) (HTTP-01) Start the challenge server in one terminal
acme-client-rs serve-http01 --token <token> --port 5002

# e) In another terminal, tell the CA the challenge is ready
acme-client-rs respond-challenge <challenge-url>

# f) Finalize the order with a CSR
acme-client-rs finalize --finalize-url <finalize-url> test.example.com

# g) Poll until the certificate is ready
acme-client-rs poll-order <order-url>

# h) Download the certificate
acme-client-rs download-cert <certificate-url> --output cert.pem

# i) (Optional) Revoke the certificate
acme-client-rs revoke-cert cert.pem

# j) (Optional) Deactivate the account
acme-client-rs deactivate-account
```

### 5. Testing Without Docker

You can also run Pebble directly if you have Go installed:

```sh
git clone https://github.com/letsencrypt/pebble.git
cd pebble
go install ./cmd/pebble
PEBBLE_VA_ALWAYS_VALID=1 pebble -config ./test/config/pebble-config.json
```

### Pebble Troubleshooting

| Problem | Solution |
|---|---|
| TLS handshake error connecting to Pebble | Use `--insecure` (or `ACME_INSECURE=true`) to skip TLS verification. Alternatively, set `SSL_CERT_FILE` to Pebble's `test/certs/pebble.minica.pem` |
| Challenge validation fails | Set `PEBBLE_VA_ALWAYS_VALID=1`, or ensure your challenge server is reachable from the Pebble container |
| `badNonce` errors | Normal - the client retries automatically. Set `PEBBLE_WFE_NONCEREJECT=0` to disable random nonce rejection |
| Port 14000 already in use | Stop any existing Pebble instance: `docker compose down` |

</details>

## CLI Reference

### Global Options

| Option | Short | Env Var | Default | Description |
|---|---|---|---|---|
| `--config <PATH>` | | `ACME_CONFIG` | - | Path to TOML config file (env vars ignored when loaded, except secrets) |
| `--directory <URL>` | `-d` | `ACME_DIRECTORY_URL` | `https://localhost:14000/dir` | ACME server directory URL |
| `--account-key <PATH>` | `-k` | `ACME_ACCOUNT_KEY_FILE` | `account.key` | Path to the account key (PKCS#8 PEM) |
| `--account-url <URL>` | `-a` | `ACME_ACCOUNT_URL` | - | Account URL (required after account creation) |
| `--output-format <FMT>` | | `ACME_OUTPUT_FORMAT` | `text` | Output format: `text` (human-readable) or `json` (structured) |
| `--insecure` | | `ACME_INSECURE` | `false` | Disable TLS certificate verification (for testing with self-signed CAs like Pebble) |

Global options can be placed before or after the subcommand.

### Subcommands

| Command | Description |
|---|---|
| `generate-config` | Generate a self-documented TOML config file template |
| `show-config` | Show the effective merged configuration (use `--verbose` to see value sources) |
| `generate-key` | Generate a new account key pair (ES256, ES384, ES512, RSA-2048, RSA-4096, Ed25519) |
| `account` | Create or look up an ACME account |
| `order <domains...>` | Request a new certificate order |
| `get-authz <url>` | Fetch an authorization object |
| `respond-challenge <url>` | Tell the server a challenge is ready |
| `serve-http01` | Serve an HTTP-01 challenge response |
| `show-dns01` | Show DNS-01 TXT record setup instructions |
| `show-dns-persist01` | Show DNS-PERSIST-01 persistent TXT record setup instructions |
| `finalize` | Finalize an order with a new CSR |
| `poll-order <url>` | Poll an order's current status |
| `download-cert <url>` | Download the issued certificate |
| `deactivate-account` | Deactivate the current account |
| `key-rollover` | Rotate the account key (RFC 8555 Section 7.3.5) |
| `pre-authorize` | Pre-authorize an identifier before creating an order (RFC 8555 Section 7.4.1) |
| `renewal-info <path>` | Query ACME Renewal Information for a certificate (RFC 9702) |
| `revoke-cert <path>` | Revoke a certificate |
| `run <domains...>` | Run the full ACME flow end-to-end |

### `run` Options

| Option | Default | Description |
|---|---|---|
| `--contact <EMAIL>` | - | Contact email for the ACME account |
| `--challenge-type <TYPE>` | `http-01` | Challenge type: `http-01`, `dns-01`, `dns-persist-01`, or `tls-alpn-01` |
| `--http-port <PORT>` | `80` | Port for the built-in HTTP-01 server (standalone mode) |
| `--challenge-dir <PATH>` | - | Write HTTP-01 challenge files here instead of starting a server |
| `--dns-hook <SCRIPT>` | - | Path to a DNS-01 hook script (called with `ACME_ACTION=create\|cleanup`) |
| `--dns-wait <SECONDS>` | - | Wait up to N seconds for DNS TXT propagation (polls every 5s) |
| `--dns-propagation-concurrency <N>` | `5` | Max concurrent DNS propagation checks when using `--dns-hook` with multiple domains |
| `--challenge-timeout <SECONDS>` | `300` | Max seconds to wait for challenge validation after responding (polls every 2s) |
| `--cert-output <PATH>` | `certificate.pem` | Save the certificate to this file |
| `--key-output <PATH>` | `private.key` | Save the private key to this file |
| `--days <N>` | - | **Renewal mode:** skip issuance if existing `--cert-output` has more than N days remaining. Use this to make `run` idempotent for cron/scheduled tasks. |
| `--key-password <PW>` | - | Encrypt the private key (PKCS#8, AES-256-CBC + scrypt KDF) |
| `--key-password-file <PATH>` | - | Read the key encryption password from a file (first line) |
| `--on-challenge-ready <SCRIPT>` | - | Run a script after each challenge is ready for validation (dns-01, dns-persist-01, tls-alpn-01; not called for http-01) |
| `--on-cert-issued <SCRIPT>` | - | Run a script after the certificate is issued and saved to disk |
| `--eab-kid <KID>` | - | EAB Key ID from the CA (for CAs that require External Account Binding) |
| `--eab-hmac-key <KEY>` | - | EAB HMAC key (base64url-encoded, from the CA) |
| `--pre-authorize` | `false` | Pre-authorize identifiers via newAuthz before creating the order (RFC 8555 Section 7.4.1) |
| `--persist-policy <POLICY>` | - | Policy for dns-persist-01 records (e.g., `wildcard` for wildcard + subdomain scope) |
| `--persist-until <TIMESTAMP>` | - | Unix timestamp for dns-persist-01 `persistUntil` parameter |
| `--cert-key-algorithm <ALG>` | `ec-p256` | Certificate key algorithm for CSR: `ec-p256`, `ec-p384`, or `ed25519` |
| `--ari` | `false` | **ARI renewal mode (RFC 9702):** query the server's suggested renewal window and skip issuance if the window has not opened. When renewing, the `replaces` field is included in the order to link the new cert to the old one. Falls back to `--days` if ARI is unavailable. |

<details>
<summary><strong>Key Rollover (RFC 8555 Section 7.3.5)</strong></summary>

Rotate your account key without creating a new account:

```sh
# 1. Generate a new key
acme-client-rs generate-key --account-key new-account.key

# 2. Roll over (old key authenticates, new key proves possession)
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key old-account.key --account-url https://acme-v02.api.letsencrypt.org/acme/acct/123456789 key-rollover --new-key new-account.key

# 3. Use the new key for all future requests
mv new-account.key account.key
```

The old and new keys can use different algorithms (e.g., roll from RSA-2048 to ES256).

</details>

### External Account Binding (EAB)

Some CAs require linking your ACME account to an existing external account. The CA provides an EAB Key ID and HMAC key during out-of-band registration.

```sh
# Register with EAB (account subcommand)
acme-client-rs --directory https://acme-server/directory account --contact admin@example.com --eab-kid my-key-id --eab-hmac-key aBase64urlEncodedHmacKey

# Full flow with EAB (run subcommand)
acme-client-rs --directory https://acme-server/directory run --contact admin@example.com --challenge-type http-01 --eab-kid my-key-id --eab-hmac-key aBase64urlEncodedHmacKey example.com
```

> **Note:** `--eab-kid` and `--eab-hmac-key` must be provided together. The HMAC key must be base64url-encoded (as provided by the CA). EAB is only needed for the initial account registration - subsequent requests use the account key.

### Pre-Authorization (RFC 8555 Section 7.4.1)

Pre-authorize identifiers before creating an order (useful for CAs that support it):

```sh
# Pre-authorize a domain (standalone)
acme-client-rs --directory https://acme-server/directory --account-url https://acme-server/acme/acct/123 pre-authorize --domain example.com --challenge-type http-01

# Pre-authorize during the full flow
acme-client-rs --directory https://acme-server/directory run --contact admin@example.com --challenge-type http-01 --pre-authorize example.com
```

> **Note:** Not all ACME servers support pre-authorization. The server must advertise a `newAuthz` URL in its directory.

### Environment Variables

| Variable | Description |
|---|---|
| `ACME_CONFIG` | Config file path (alternative to `--config`) |
| `ACME_DIRECTORY_URL` | ACME directory URL (alternative to `--directory`) |
| `ACME_ACCOUNT_KEY_FILE` | Account key path (alternative to `--account-key`) |
| `ACME_ACCOUNT_URL` | Account URL (alternative to `--account-url`) |
| `ACME_OUTPUT_FORMAT` | Output format: `text` or `json` (alternative to `--output-format`) |
| `ACME_INSECURE` | Disable TLS certificate verification (alternative to `--insecure`) |
| `ACME_KEY_PASSWORD_FILE` | Private key password file path (alternative to `--key-password-file`) |
| `ACME_EAB_KID` | EAB Key ID (alternative to `--eab-kid`) |
| `ACME_EAB_HMAC_KEY` | EAB HMAC key, base64url-encoded (alternative to `--eab-hmac-key`) |
| `RUST_LOG` | Log level filter (e.g., `debug`, `info`, `warn`) |

### DNS Hook Environment Variables

These are set by the client when calling `--dns-hook`:

| Variable | Description |
|---|---|
| `ACME_ACTION` | `create` (before validation) or `cleanup` (after validation) |
| `ACME_DOMAIN` | The domain being validated |
| `ACME_TXT_NAME` | Full DNS record name (e.g., `_acme-challenge.example.com` or `_validation-persist.example.com`) |
| `ACME_TXT_VALUE` | TXT record value (base64url SHA-256 for dns-01, or persistent record value for dns-persist-01) |

### `--on-challenge-ready` Environment Variables

These are set when calling `--on-challenge-ready` (once per domain authorization):

| Variable | Description |
|---|---|
| `ACME_DOMAIN` | The domain being validated |
| `ACME_CHALLENGE_TYPE` | Challenge type (`dns-01`, `dns-persist-01`, or `tls-alpn-01`). Not called for `http-01` (handled automatically). |
| `ACME_TOKEN` | The challenge token (dns-01 and tls-alpn-01 only) |
| `ACME_KEY_AUTH` | The full key authorization string (`token.thumbprint`; dns-01 and tls-alpn-01 only) |
| `ACME_TXT_NAME` | DNS TXT record name (dns-01 and dns-persist-01 only) |
| `ACME_TXT_VALUE` | DNS TXT record value (dns-01 and dns-persist-01 only) |

### `--on-cert-issued` Environment Variables

These are set when calling `--on-cert-issued` (once after certificate is saved):

| Variable | Description |
|---|---|
| `ACME_DOMAINS` | Comma-separated list of domains in the certificate |
| `ACME_CERT_PATH` | Path to the saved certificate file |
| `ACME_KEY_PATH` | Path to the saved private key file |
| `ACME_KEY_ENCRYPTED` | `true` if the key was encrypted, `false` otherwise |

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
