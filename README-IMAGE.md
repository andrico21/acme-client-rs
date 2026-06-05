# acme-client-rs

A lightweight, single-binary ACME client implementing [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) with [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773) (ACME Renewal Information) and [DNS-PERSIST-01](https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist) support. Handles the full certificate lifecycle — account registration, issuance, renewal, and revocation — packaged as a **distroless container image** that runs the statically linked (musl) binary as a non-root user with zero runtime dependencies.

Built in Rust (edition 2024) with `#![forbid(unsafe_code)]`, hardened static musl binary (PIE, full RELRO, NX stack), and structured JSON output for CI/CD integration.

- **GitHub:** <https://github.com/andrico21/acme-client-rs>
- **License:** [Apache-2.0](https://github.com/andrico21/acme-client-rs/blob/master/LICENSE)

## Image Facts

| Property | Value |
|---|---|
| Base image | `gcr.io/distroless/static-debian13:nonroot` |
| User | `nonroot` (**UID 65532**) — non-root by default |
| Shell / package manager | **None** (`docker exec ... sh` will not work) |
| Entrypoint | `/usr/local/bin/acme-client-rs` (pass subcommands/flags directly) |
| Default command | `--help` |
| Working directory | `/data` |
| Declared volume | `/data` (account key + issued cert/key live here) |
| Exposed port | `80/tcp` (built-in HTTP-01 challenge server) |
| Platform | `linux/amd64` |
| Image size | ~10 MB |
| Default env | `TZ=UTC`, `RUST_LOG=info` |

The image is **distroless**: it contains only CA roots, `/etc/passwd` with the `nonroot` user, and the binary. There is no shell, no libc, and no package manager — the only attack surface is the binary itself. Because the `ENTRYPOINT` is the binary, every `docker run` argument after the image name is passed straight to `acme-client-rs`.

## Tags

| Tag | Points to |
|---|---|
| `latest` | Newest stable release |
| `2`, `2.2`, `2.2.4` | Semver major / minor / patch (pinned) |

```sh
# Pull the latest stable image
docker pull andrico21/acme-client-rs:latest

# Pin a specific version (recommended for production)
docker pull andrico21/acme-client-rs:2.2.4
```

For fully immutable deployments, pull by digest:

```sh
docker pull andrico21/acme-client-rs@sha256:<digest>
```

Images are published only after the `Release` workflow succeeds, and each is shipped with an SBOM and SLSA provenance attestation.

## Quick Start

The container runs as UID 65532, so the host directory it writes to (account key, certificate, private key) must be owned by that UID. The examples below are already hardened (`--read-only` rootfs, `--security-opt no-new-privileges`, all capabilities dropped) — see [Hardened / production run](#hardened--production-run) for the rationale:

```sh
# 1. Create a writable data directory for the non-root container user
mkdir -p ./acme-data && sudo chown 65532:65532 ./acme-data

# 2. Generate an account key (ES256 by default) into the mounted volume
docker run --rm \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  -v ./acme-data:/data \
  andrico21/acme-client-rs \
  generate-key --account-key /data/account.key

# 3. Run the full flow (HTTP-01 standalone; publish port 80 for validation)
docker run --rm \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  -p 80:80 \
  -v ./acme-data:/data \
  andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  --account-key /data/account.key \
  run \
    --contact you@example.com \
    --challenge-type http-01 \
    --http-port 80 \
    --cert-output /data/your.domain.pem \
    --key-output /data/your.domain.key \
    your.domain.com

# 4. Renew — re-run with --days (skips if not due yet)
docker run --rm \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  -p 80:80 \
  -v ./acme-data:/data \
  andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  --account-key /data/account.key \
  run \
    --contact you@example.com \
    --challenge-type http-01 \
    --http-port 80 \
    --cert-output /data/your.domain.pem \
    --key-output /data/your.domain.key \
    --days 30 \
    your.domain.com
```

> **Tip:** There is no separate `renew` command. `run --days N` is idempotent — it checks the existing certificate and only contacts the CA when renewal is actually needed. Safe to schedule daily (see [Automation](#automation)).
>
> **Why no `--cap-add NET_BIND_SERVICE`?** The app binds port 80 *inside* the container, but a dropped-all-caps **non-root** process can still do that on modern Docker (20.03+) because the engine sets `net.ipv4.ip_unprivileged_port_start=0` in every container network namespace by default — port 80 needs **no capability at all**. Adding `NET_BIND_SERVICE` for a non-root user is a no-op anyway (the kernel clears it on the UID transition). See [Hardened / production run](#hardened--production-run) for the one runtime where you need a sysctl instead.

### One-shot bootstrap (auto-generate the account key)

For CI/automation, fold the `generate-key` step into `run` with `--generate-account-key-if-missing` (or `ACME_GENERATE_ACCOUNT_KEY_IF_MISSING=1`). If the file at `--account-key` does not exist, a fresh ES256 key is created at that path, then issuance proceeds; if it already exists it is reused unchanged:

```sh
mkdir -p ./acme-data && sudo chown 65532:65532 ./acme-data
docker run --rm \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  -p 80:80 \
  -v ./acme-data:/data \
  andrico21/acme-client-rs \
  --directory https://acme-staging-v02.api.letsencrypt.org/directory \
  --account-key /data/account.key \
  run \
    --contact you@example.com \
    --challenge-type http-01 \
    --http-port 80 \
    --generate-account-key-if-missing \
    --cert-output /data/your.domain.pem \
    --key-output /data/your.domain.key \
    your.domain.com
```

Override the auto-generated key algorithm with `--account-key-algorithm` (`es256` | `es384` | `es512` | `rsa2048` | `rsa4096` | `ed25519`) or `ACME_ACCOUNT_KEY_ALGORITHM`.

## Features

- Full RFC 8555 protocol: account management, key rollover, order lifecycle, challenge handling, certificate download, revocation
- Four challenge types: HTTP-01 (built-in server or `--challenge-dir`), DNS-01 (interactive, hook scripts, auto-propagation check), DNS-PERSIST-01 (persistent DNS records, [draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist)), TLS-ALPN-01 (interactive)
- External Account Binding (EAB) for CAs that require it (`--eab-kid` + `--eab-hmac-key`)
- Pre-authorization (RFC 8555 Section 7.4.1) via `pre-authorize` subcommand or `--pre-authorize` flag on `run`
- Generic hook scripts: `--on-challenge-ready` and `--on-cert-issued` (note: hook scripts must exist *inside* the container — see [Hooks in containers](#hooks-in-containers))
- IP identifier support (RFC 8738) with IPv6 normalization — auto-detected from CLI input
- Automated end-to-end flow (`run` subcommand) with built-in renewal (`--days N` skips if not due — no separate renew command needed)
- Domain mismatch protection: detects when requested domains differ from the existing certificate's SANs, prevents accidental overwrites (`--reissue-on-mismatch` to explicitly allow)
- ACME Renewal Information (ARI, RFC 9773): `renewal-info` subcommand and `--ari` flag on `run` for server-recommended renewal timing with `replaces` order linkage
- Certificate profiles (draft-ietf-acme-profiles-01): `list-profiles` subcommand, `--profile` flag on `order` and `run`
- Optional private key encryption (`--key-password` / `--key-password-file`) using PKCS#8 + AES-256-CBC with scrypt KDF (`N=16384, r=8, p=1`, chosen for OpenSSL CLI interop)
- Step-by-step manual flow (individual subcommands)
- Six key algorithms: ES256 (default), ES384, ES512, RSA-2048, RSA-4096, Ed25519
- Configurable via CLI flags, config file, or environment variables
- `--insecure` flag for testing with self-signed CAs (e.g., Pebble)
- `--silent` flag to suppress all stdout output (exit codes only, for scripted use)
- `--print-cert` flag to print the issued certificate PEM to stdout after saving
- Clean error messages (no stack traces for operational errors)
- Structured JSON output (`--output-format json`) for machine consumption and CI/CD pipelines

## Running the Container

Because the `ENTRYPOINT` is the binary, the invocation pattern is always:

```sh
docker run --rm [docker-opts] andrico21/acme-client-rs [acme-client-rs flags]
```

Show help / version:

```sh
docker run --rm andrico21/acme-client-rs --help
docker run --rm andrico21/acme-client-rs run --help
```

Anything the binary reads or writes (account key, cert, private key, config) must live under a mounted volume — by convention `/data`. The `:Z` SELinux relabel suffix shown in some examples is needed on SELinux hosts (Fedora/RHEL); omit it elsewhere.

### Hardened / production run

The image is already minimal — a single static binary on `distroless/static:nonroot`, running as **UID 65532** with no shell, libc, or package manager. Layer the standard container hardening flags on top for a defense-in-depth runtime. This is the canonical invocation; every example in this document is a variation of it:

```sh
docker run --rm \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  -p 80:80 \
  -v ./acme-data:/data \
  andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory \
  --account-key /data/account.key \
  run \
    --contact you@example.com \
    --challenge-type http-01 \
    --http-port 80 \
    --cert-output /data/your.domain.pem \
    --key-output /data/your.domain.key \
    your.domain.com
```

| Flag | Effect |
|------|--------|
| `--read-only` | Mounts the container root filesystem read-only. Safe here: the binary never writes to the rootfs at runtime — the cert and key are written atomically (temp file + `rename` + `fsync`) **inside the `/data` volume**, which stays writable. |
| `--security-opt no-new-privileges` | Blocks the process (and any child) from gaining privileges via setuid/setgid/file capabilities. The binary never escalates, so this is free. |
| `--cap-drop ALL` | Drops every Linux capability. The binary needs none — **including for binding port 80** (see below). |
| `-v ./acme-data:/data` | The one writable surface. Holds the account key, certificate, and private key. Must be owned by UID 65532. |

> **Note:** `--no-new-privileges` (single dash form) and `no-new-privileges` are both accepted by `--security-opt`; this document uses the canonical `no-new-privileges`.

#### Port 80 with no capabilities (the important part)

The app **binds and listens on port 80 itself** — `--cap-drop ALL` does **not** prevent that, and you do **not** need `--cap-add NET_BIND_SERVICE`. Here is why:

- The HTTP-01 server binds `0.0.0.0:80` **inside the container's network namespace**.
- On modern Docker (20.03+), the engine sets `net.ipv4.ip_unprivileged_port_start=0` in every container netns **by default**, so even a **non-root** process with **zero capabilities** may bind low ports. Port 80 is therefore available with `--cap-drop ALL`.
- Adding `--cap-add NET_BIND_SERVICE` for the non-root user would be a **no-op**: the kernel clears effective/permitted capabilities across the root→non-root UID transition, so the capability never reaches the process. Relying on it *together with* `--no-new-privileges` is a well-known broken combination — which is exactly why the capability is unnecessary here in the first place.

**Fallback** — if your runtime does **not** ship the `ip_unprivileged_port_start=0` default (some plain `containerd` setups, or a host that overrode the sysctl), a non-root bind of 80 fails with `Permission denied`. Fix it without granting capabilities:

```sh
# Option A: lower the unprivileged-port floor for this container only
docker run --rm \
  --read-only --security-opt no-new-privileges --cap-drop ALL \
  --sysctl net.ipv4.ip_unprivileged_port_start=80 \
  -p 80:80 -v ./acme-data:/data \
  andrico21/acme-client-rs ...

# Option B: bind a high port inside the container, reverse-proxy :80 → it on the host
docker run --rm \
  --read-only --security-opt no-new-privileges --cap-drop ALL \
  -p 8080:8080 -v ./acme-data:/data \
  andrico21/acme-client-rs ... run --challenge-type http-01 --http-port 8080 ...
```

> Publishing the port to the host (`-p 80:80`) is a separate concern from the in-container bind. Under **rootless** Docker/Podman, exposing host port 80 itself may require `sysctl net.ipv4.ip_unprivileged_port_start=80` on the host (or mapping to a high host port such as `-p 8080:80`).

### Key Algorithms

```sh
# Default: ES256 (P-256)
docker run --rm -v ./acme-data:/data andrico21/acme-client-rs \
  generate-key --account-key /data/account.key

# Other algorithms
docker run --rm -v ./acme-data:/data andrico21/acme-client-rs \
  generate-key --account-key /data/account.key --algorithm es384
# ... --algorithm es512 | rsa2048 | rsa4096 | ed25519
```

### Certificate Key Algorithm

The certificate private key (used in the CSR) is separate from the account key. By default ECDSA P-256 is used; change it with `--cert-key-algorithm`:

```sh
docker run --rm -p 80:80 -v ./acme-data:/data andrico21/acme-client-rs \
  --account-key /data/account.key \
  run --cert-key-algorithm ec-p384 \
    --cert-output /data/example.com.pem --key-output /data/example.com.key \
    --contact admin@example.com example.com
```

Supported values: `ec-p256` (P-256/SHA-256, default), `ec-p384` (P-384/SHA-384), `ed25519`.

## Challenge Types

### HTTP-01 (built-in standalone server)

The image `EXPOSE`s port 80. Publish it so the CA can reach the built-in challenge server:

```sh
docker run --rm -p 80:80 -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  --account-key /data/account.key \
  run --contact you@example.com --challenge-type http-01 --http-port 80 \
    --cert-output /data/your.domain.pem --key-output /data/your.domain.key \
    your.domain.com
```

### HTTP-01 with `--challenge-dir` (reverse proxy integration)

If another web server already serves port 80, write the challenge file to a directory it serves. Mount that webroot into the container:

```sh
docker run --rm -v /var/www/html:/var/www/html -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  --account-key /data/account.key \
  run --contact you@example.com --challenge-type http-01 \
    --challenge-dir /var/www/html \
    --cert-output /data/your.domain.pem --key-output /data/your.domain.key \
    your.domain.com
```

The client writes the token file to `/var/www/html/.well-known/acme-challenge/<token>` (inside the container, which maps to the host webroot) and cleans it up after validation. No `-p 80:80` is needed in this mode.

### DNS-01 Challenge

Three modes of operation.

#### Interactive (default)

Interactive mode prints the TXT record and waits for **Enter**, so allocate a TTY with `-it`:

```sh
docker run --rm -it -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  --account-key /data/account.key \
  run --contact you@example.com --challenge-type dns-01 \
    --cert-output /data/your.domain.pem --key-output /data/your.domain.key \
    your.domain.com
```

The client prints:

```text
=== DNS-01 Challenge ===
Create a DNS TXT record:
  Name:  _acme-challenge.your.domain.com
  Type:  TXT
  Value: <base64url-encoded-sha256>

Press Enter once the record has propagated...
```

> For unattended container use, prefer `--dns-hook` or `--dns-wait` below over interactive mode.

#### Hook script (`--dns-hook`)

The hook script must be reachable **inside** the container. Mount it (and ensure it's executable on the host). It is called twice per authorization: `ACME_ACTION=create` before validation, `ACME_ACTION=cleanup` after.

```sh
docker run --rm \
  -v ./acme-data:/data \
  -v /usr/local/bin/dns-hook.sh:/hooks/dns-hook.sh:ro \
  -e CLOUDFLARE_API_TOKEN \
  -e CLOUDFLARE_ZONE_ID \
  andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  --account-key /data/account.key \
  run --contact you@example.com --challenge-type dns-01 \
    --dns-hook /hooks/dns-hook.sh \
    --cert-output /data/your.domain.pem --key-output /data/your.domain.key \
    your.domain.com
```

Environment variables passed to the hook:

| Variable | Example |
|---|---|
| `ACME_ACTION` | `create` or `cleanup` |
| `ACME_DOMAIN` | `your.domain.com` |
| `ACME_TXT_NAME` | `_acme-challenge.your.domain.com` |
| `ACME_TXT_VALUE` | `aB3xY...base64url...` |

Example hook script (Cloudflare API). **Note:** distroless has no shell, so a hook that needs `bash`/`curl` cannot run in *this* image — keep DNS automation in an external orchestrator (host cron, CI job, sidecar with a shell), or use `--dns-wait` instead:

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

Poll DNS until the TXT record is visible (or timeout). This needs no shell and works fully unattended inside the container:

```sh
docker run --rm \
  -v ./acme-data:/data \
  -v /usr/local/bin/dns-hook.sh:/hooks/dns-hook.sh:ro \
  andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  --account-key /data/account.key \
  run --contact you@example.com --challenge-type dns-01 \
    --dns-hook /hooks/dns-hook.sh --dns-wait 120 \
    --cert-output /data/your.domain.pem --key-output /data/your.domain.key \
    your.domain.com
```

`--dns-wait <SECONDS>` polls every 5 seconds until the TXT record appears or the timeout is reached. Combine with `--dns-hook` (fully automated) or use it alone (prints instructions, then auto-waits instead of prompting for Enter — no `-it` needed).

### TLS-ALPN-01 Challenge (interactive)

Prints the `acmeIdentifier` extension value; you must configure a TLS server on port 443 with a self-signed certificate containing this extension before pressing Enter. Allocate a TTY:

```sh
docker run --rm -it -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  --account-key /data/account.key \
  run --contact you@example.com --challenge-type tls-alpn-01 \
    --cert-output /data/your.domain.pem --key-output /data/your.domain.key \
    your.domain.com
```

### DNS-PERSIST-01 Challenge (draft-ietf-acme-dns-persist)

DNS-PERSIST-01 uses a persistent DNS TXT record at `_validation-persist.<domain>` to prove domain control. Unlike DNS-01, the record does not change between issuances — once set up, it can be reused for future renewals.

#### Interactive (default)

```sh
docker run --rm -it -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  --account-key /data/account.key \
  run --contact you@example.com --challenge-type dns-persist-01 \
    --cert-output /data/your.domain.pem --key-output /data/your.domain.key \
    your.domain.com
```

The client prints:

```text
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

For wildcard certificates, use `--persist-policy wildcard`. `--persist-until` sets a Unix timestamp after which the record should be considered expired:

```sh
docker run --rm -it -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  --account-key /data/account.key \
  run --contact you@example.com --challenge-type dns-persist-01 \
    --persist-policy wildcard --persist-until 1767225600 \
    --cert-output /data/wildcard.your.domain.pem --key-output /data/wildcard.your.domain.key \
    "*.your.domain.com" your.domain.com
```

This creates a record like:

```text
letsencrypt.org; accounturi=https://acme-server/acme/acct/123; policy=wildcard; persistUntil=1767225600
```

#### Hook script / auto-propagation

Same container mechanics as DNS-01 — mount the hook and/or use `--dns-wait`:

```sh
docker run --rm \
  -v ./acme-data:/data \
  -v /usr/local/bin/dns-hook.sh:/hooks/dns-hook.sh:ro \
  andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  --account-key /data/account.key \
  run --contact you@example.com --challenge-type dns-persist-01 \
    --dns-hook /hooks/dns-hook.sh --dns-wait 120 \
    --cert-output /data/your.domain.pem --key-output /data/your.domain.key \
    your.domain.com
```

Hook variables: `ACME_ACTION`, `ACME_DOMAIN`, `ACME_TXT_NAME` (`_validation-persist.your.domain.com`), `ACME_TXT_VALUE` (`letsencrypt.org; accounturi=https://...`).

#### Show record setup instructions

The `show-dns-persist-01` subcommand displays the record to create without running the full flow:

```sh
docker run --rm andrico21/acme-client-rs \
  --directory https://your-acme-server/directory \
  show-dns-persist-01 --domain your.domain.com --issuer-domain-name letsencrypt.org

# With JSON output and wildcard policy
docker run --rm andrico21/acme-client-rs \
  --directory https://your-acme-server/directory --output-format json \
  show-dns-persist-01 --domain your.domain.com --issuer-domain-name letsencrypt.org \
    --persist-policy wildcard --persist-until 1767225600
```

> **Note:** DNS-PERSIST-01 is defined in [draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist). Pebble already supports it. Let's Encrypt staging support is expected late Q1 2026, production Q2 2026.

### IP Identifiers (RFC 8738)

IP addresses are auto-detected — pass them as positional arguments:

```sh
# IPv4
docker run --rm -p 80:80 -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://your-acme-server/directory --account-key /data/account.key \
  run --contact you@example.com --challenge-type http-01 --http-port 80 \
    --cert-output /data/ip.pem --key-output /data/ip.key 192.0.2.1

# IPv6 (bracketed or bare; brackets quoted to avoid shell glob expansion)
docker run --rm -p 80:80 -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://your-acme-server/directory --account-key /data/account.key \
  run --contact you@example.com --challenge-type http-01 --http-port 80 \
    --cert-output /data/ip6.pem --key-output /data/ip6.key '[2001:db8::1]'
```

> **Note:** DNS-01 and DNS-PERSIST-01 are not supported for IP identifiers. Use HTTP-01 or TLS-ALPN-01.

### Multi-SAN Certificates

```sh
docker run --rm -p 80:80 -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://your-acme-server/directory --account-key /data/account.key \
  run --contact you@example.com --challenge-type http-01 --http-port 80 \
    --cert-output /data/example.com.pem --key-output /data/example.com.key \
    example.com www.example.com api.example.com
```

## Real-World Examples with Let's Encrypt

All commands write the account key and issued cert/key into the mounted `/data` volume. Create it once, owned by UID 65532:

```sh
mkdir -p ./acme-data && sudo chown 65532:65532 ./acme-data
```

### Issue a Certificate (HTTP-01, standalone)

```sh
# Generate an account key
docker run --rm -v ./acme-data:/data andrico21/acme-client-rs \
  generate-key --account-key /data/account.key

# Issue a certificate (the container binds port 80 inside its netns;
# publish it to the host so Let's Encrypt can reach the challenge server)
docker run --rm -p 80:80 -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory \
  --account-key /data/account.key \
  run --contact admin@example.com --challenge-type http-01 --http-port 80 \
    --cert-output /data/example.com.pem --key-output /data/example.com.key \
    example.com www.example.com
```

### Issue a Certificate (HTTP-01, behind nginx on the host)

If nginx already serves port 80 on the host, use `--challenge-dir` and mount the webroot:

```nginx
# /etc/nginx/snippets/acme-challenge.conf
location /.well-known/acme-challenge/ {
    root /var/www/acme;
    try_files $uri =404;
}
```

```sh
docker run --rm -v /var/www/acme:/var/www/acme -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory \
  --account-key /data/account.key \
  run --contact admin@example.com --challenge-type http-01 \
    --challenge-dir /var/www/acme \
    --cert-output /data/example.com.pem --key-output /data/example.com.key \
    example.com www.example.com

# Reload nginx on the host to pick up the new cert
sudo systemctl reload nginx
```

### Issue a Wildcard Certificate (DNS-01 or DNS-PERSIST-01)

Wildcards require DNS-01 or DNS-PERSIST-01.

**Interactive** (manual DNS record creation; needs `-it`):

```sh
docker run --rm -it -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory \
  --account-key /data/account.key \
  run --contact admin@example.com --challenge-type dns-01 \
    --cert-output /data/wildcard.example.com.pem --key-output /data/wildcard.example.com.key \
    "*.example.com" example.com
```

**Automated** (hook script + propagation check):

```sh
docker run --rm \
  -v ./acme-data:/data \
  -v /usr/local/bin/dns-hook.sh:/hooks/dns-hook.sh:ro \
  andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory \
  --account-key /data/account.key \
  run --contact admin@example.com --challenge-type dns-01 \
    --dns-hook /hooks/dns-hook.sh --dns-wait 120 \
    --cert-output /data/wildcard.example.com.pem --key-output /data/wildcard.example.com.key \
    "*.example.com" example.com
```

**DNS-PERSIST-01** (persistent record — no per-issuance changes):

```sh
docker run --rm -it -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory \
  --account-key /data/account.key \
  run --contact admin@example.com --challenge-type dns-persist-01 --persist-policy wildcard \
    --cert-output /data/wildcard.example.com.pem --key-output /data/wildcard.example.com.key \
    "*.example.com" example.com
```

### Revoke a Certificate

```sh
# Revoke (no reason code)
docker run --rm -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory --account-key /data/account.key \
  revoke-cert /data/example.com.pem

# Revoke with reason code (4 = superseded)
docker run --rm -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory --account-key /data/account.key \
  revoke-cert /data/example.com.pem --reason 4
```

Reason codes (RFC 5280 §5.3.1): `0` Unspecified, `1` Key compromise, `3` Affiliation changed, `4` Superseded, `5` Cessation of operation.

### Step-by-Step Manual Flow (env vars via `-e`)

Pass the global settings as environment variables instead of repeating flags. Interactive steps need `-it`:

```sh
# Register account
docker run --rm -it -v ./acme-data:/data \
  -e ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory \
  -e ACME_ACCOUNT_KEY_FILE=/data/account.key \
  andrico21/acme-client-rs account --contact admin@example.com
# -> Account URL: https://acme-v02.api.letsencrypt.org/acme/acct/123456789

# Place an order (pass the account URL via -e ACME_ACCOUNT_URL=...)
docker run --rm -v ./acme-data:/data \
  -e ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory \
  -e ACME_ACCOUNT_KEY_FILE=/data/account.key \
  -e ACME_ACCOUNT_URL=https://acme-v02.api.letsencrypt.org/acme/acct/123456789 \
  andrico21/acme-client-rs order example.com www.example.com

# Check an authorization
docker run --rm -v ./acme-data:/data \
  -e ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory \
  -e ACME_ACCOUNT_KEY_FILE=/data/account.key \
  -e ACME_ACCOUNT_URL=https://acme-v02.api.letsencrypt.org/acme/acct/123456789 \
  andrico21/acme-client-rs get-authz https://acme-v02.api.letsencrypt.org/acme/authz/abc123

# Serve the HTTP-01 challenge (standalone, publish port 80; foreground)
docker run --rm -p 80:80 -v ./acme-data:/data \
  -e ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory \
  -e ACME_ACCOUNT_KEY_FILE=/data/account.key \
  andrico21/acme-client-rs serve-http-01 --token <token> --port 80

# Tell the server to validate
docker run --rm -v ./acme-data:/data \
  -e ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory \
  -e ACME_ACCOUNT_KEY_FILE=/data/account.key \
  -e ACME_ACCOUNT_URL=https://acme-v02.api.letsencrypt.org/acme/acct/123456789 \
  andrico21/acme-client-rs respond-challenge https://acme-v02.api.letsencrypt.org/acme/chall/xyz789

# Finalize with a CSR (--key-output is required; the generated key cannot be recovered later)
docker run --rm -v ./acme-data:/data \
  -e ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory \
  -e ACME_ACCOUNT_KEY_FILE=/data/account.key \
  -e ACME_ACCOUNT_URL=https://acme-v02.api.letsencrypt.org/acme/acct/123456789 \
  andrico21/acme-client-rs finalize \
    --finalize-url https://acme-v02.api.letsencrypt.org/acme/order/123/finalize \
    --key-output /data/example.com.key example.com www.example.com

# Poll until the certificate is ready, then download it
docker run --rm -v ./acme-data:/data \
  -e ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory \
  -e ACME_ACCOUNT_KEY_FILE=/data/account.key \
  -e ACME_ACCOUNT_URL=https://acme-v02.api.letsencrypt.org/acme/acct/123456789 \
  andrico21/acme-client-rs poll-order https://acme-v02.api.letsencrypt.org/acme/order/123

docker run --rm -v ./acme-data:/data \
  -e ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory \
  -e ACME_ACCOUNT_KEY_FILE=/data/account.key \
  -e ACME_ACCOUNT_URL=https://acme-v02.api.letsencrypt.org/acme/acct/123456789 \
  andrico21/acme-client-rs download-cert https://acme-v02.api.letsencrypt.org/acme/cert/abc123 \
    --output /data/example.com.pem
```

## Automation

> **No separate `renew` command needed.** `run --days N` reads the certificate at `--cert-output`, checks how many days remain, and only contacts the CA if renewal is due. Exit code is 0 whether it renewed or skipped — ideal for scheduled containers.

### Docker Compose (one-shot renewal service)

```yaml
services:
  acme:
    image: andrico21/acme-client-rs:latest
    # ENTRYPOINT is the binary; `command` supplies its arguments.
    command:
      - --directory=https://acme-v02.api.letsencrypt.org/directory
      - --account-key=/data/account.key
      - run
      - --contact=admin@example.com
      - --challenge-type=http-01
      - --http-port=80
      - --cert-output=/data/example.com.pem
      - --key-output=/data/example.com.key
      - --days=30
      - example.com
      - www.example.com
    ports:
      - "80:80"
    volumes:
      - ./acme-data:/data
    environment:
      TZ: Europe/Berlin
      RUST_LOG: info
    # Hardening — see "Hardened / production run". The /data volume stays
    # writable; port 80 needs no capability (ip_unprivileged_port_start=0).
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: "no"
```

```sh
# Make the data dir writable for the container's UID, then run once
mkdir -p ./acme-data && sudo chown 65532:65532 ./acme-data
docker compose run --rm acme
```

### Host cron driving the container

```cron
# /etc/cron.d/acme-renew — daily at 03:00, renew if within 30 days of expiry
0 3 * * * root docker run --rm --read-only --security-opt no-new-privileges --cap-drop ALL -p 80:80 -v /srv/acme-data:/data andrico21/acme-client-rs:latest --directory https://acme-v02.api.letsencrypt.org/directory --account-key /data/account.key run --contact admin@example.com --challenge-type http-01 --http-port 80 --cert-output /data/example.com.pem --key-output /data/example.com.key --days 30 example.com www.example.com >> /var/log/acme-renew.log 2>&1
```

### systemd service + timer driving the container

```ini
# /etc/systemd/system/acme-renew.service
[Unit]
Description=ACME certificate renewal (containerized)
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/docker run --rm \
  --read-only --security-opt no-new-privileges --cap-drop ALL \
  -p 80:80 \
  -v /srv/acme-data:/data \
  andrico21/acme-client-rs:latest \
  --directory https://acme-v02.api.letsencrypt.org/directory \
  --account-key /data/account.key \
  run --contact admin@example.com --challenge-type http-01 --http-port 80 \
    --cert-output /data/example.com.pem --key-output /data/example.com.key \
    --days 30 example.com www.example.com
```

```ini
# /etc/systemd/system/acme-renew.timer
[Unit]
Description=Run containerized ACME renewal twice daily

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
systemctl list-timers acme-renew.timer
journalctl -u acme-renew.service
```

### Server-Guided Renewal with ARI (RFC 9773)

ARI lets the CA tell your client when to renew, instead of a fixed `--days` threshold.

**Query the renewal window:**

```sh
docker run --rm -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory --account-key /data/account.key \
  renewal-info /data/example.com.pem
```

```text
CertID:   <base64url(AKI)>.<base64url(Serial)>
Suggested renewal window:
  Start:  2026-04-01T00:00:00Z
  End:    2026-04-15T00:00:00Z
Status:   not yet due (20 days until window opens)
```

**Use ARI in automated renewal** (combine with `--days` as a safety net):

```sh
docker run --rm -p 80:80 -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory --account-key /data/account.key \
  run --contact admin@example.com --challenge-type http-01 --http-port 80 \
    --ari --days 30 \
    --cert-output /data/example.com.pem --key-output /data/example.com.key \
    example.com www.example.com
```

How `--ari` works: it parses the cert at `--cert-output`, queries the CA's `renewalInfo` endpoint (AKI + serial), skips if the current time is before the suggested window, otherwise renews and includes the `replaces` field to link new→old cert. If ARI is unavailable it falls back to `--days`.

> **Note:** ARI requires the CA to advertise a `renewalInfo` URL. Let's Encrypt supports ARI; otherwise `--ari` silently falls back to `--days`.

### Domain Mismatch Protection

When the certificate file already exists, the tool compares the requested domains against the existing cert's SANs. If they differ, it treats this as a **reissuance** (not a renewal):

**Without `--reissue-on-mismatch`** (safe default): logs the mismatch and skips — the existing certificate is never overwritten.

```text
Domain mismatch: cert has [example.com, www.example.com], requested [api.example.com, example.com] (added: [api.example.com], removed: [www.example.com]). Use --reissue-on-mismatch to override.
```

**With `--reissue-on-mismatch`**: issues a new certificate with the updated domain list, bypassing ARI/days checks, overwriting the old cert:

```sh
docker run --rm -p 80:80 -v ./acme-data:/data andrico21/acme-client-rs \
  --account-key /data/account.key \
  run --days 30 --reissue-on-mismatch --http-port 80 \
    --cert-output /data/cert.pem --key-output /data/key.pem \
    --contact admin@example.com example.com api.example.com
```

The comparison is case-insensitive and normalizes IP addresses. If the existing cert cannot be parsed, the mismatch check is skipped (fail-safe).

### Hooks in containers

`--on-challenge-ready` and `--on-cert-issued` run a script at key points. In **this distroless image there is no shell**, so a typical bash hook cannot execute inside the container. Options:

1. **Deploy from outside the container** — the cert/key already land in your mounted `/data`; run your deploy logic on the host after the container exits (the container's exit code reflects success).
2. **Mount a self-contained executable** the binary can `exec` (a static binary with no interpreter dependency), e.g. `-v /opt/deploy:/hooks/deploy:ro` and `--on-cert-issued /hooks/deploy`.

`--on-cert-issued` environment: `ACME_DOMAINS`, `ACME_CERT_PATH`, `ACME_KEY_PATH`, `ACME_KEY_ENCRYPTED`.
`--on-challenge-ready` environment: `ACME_DOMAIN`, `ACME_CHALLENGE_TYPE`, `ACME_TOKEN`, `ACME_KEY_AUTH`, `ACME_TXT_NAME`, `ACME_TXT_VALUE` (subset depends on challenge type; not called for http-01).

## Configuration File

All CLI flags can be set in a TOML config file. Generate a self-documented template (redirect stdout on the host):

```sh
docker run --rm andrico21/acme-client-rs generate-config > acme-client-rs.toml
```

Mount the config into the container and point `--config` (or `ACME_CONFIG`) at it:

```sh
docker run --rm -p 80:80 \
  -v ./acme-client-rs.toml:/etc/acme/acme-client-rs.toml:ro \
  -v ./acme-data:/data \
  andrico21/acme-client-rs --config /etc/acme/acme-client-rs.toml run
```

Example config (note container-internal paths under `/data`):

```toml
[global]
directory = "https://acme-v02.api.letsencrypt.org/directory"
account_key = "/data/account.key"

[run]
domains = ["example.com", "www.example.com"]
contact = "admin@example.com"
challenge_type = "http-01"
http_port = 80
cert_output = "/data/example.com.pem"
key_output = "/data/example.com.key"
days = 30
```

**Priority without config file:** CLI flags > environment variables > built-in defaults.
**Priority with config file:** CLI flags > config file > built-in defaults.

When a config file is loaded, environment variables are **ignored** — the config file is the single source of truth. Exceptions still read from the environment: the safety toggle `ACME_INSECURE` and secret-bearing variables (`ACME_ACCOUNT_KEY_PASSWORD`, `ACME_ACCOUNT_KEY_PASSWORD_FILE`, `ACME_KEY_PASSWORD_FILE`, `ACME_NEW_KEY_PASSWORD`, `ACME_NEW_KEY_PASSWORD_FILE`, `ACME_EAB_KID`, `ACME_EAB_HMAC_KEY`).

Inspect the effective merged config and where each value comes from:

```sh
docker run --rm -v ./acme-client-rs.toml:/etc/acme/acme-client-rs.toml:ro andrico21/acme-client-rs \
  --config /etc/acme/acme-client-rs.toml show-config --verbose
```

Each value is annotated with its source: `(cli)`, `(env)`, `(config)`, or `(default)`.

## Environment Variables (pre-wired in the image)

The image already declares `TZ=UTC` and `RUST_LOG=info`, and documents (commented-out) every supported `ACME_*` setting in its `Containerfile`. Set any of them with `-e`:

| Variable | Description |
|---|---|
| `TZ` | Timezone for log timestamps / cert-expiry formatting (default `UTC`) |
| `RUST_LOG` | Log level: `error` \| `warn` \| `info` \| `debug` \| `trace` (default `info`) |
| `ACME_CONFIG` | Config file path (alternative to `--config`) |
| `ACME_DIRECTORY_URL` | ACME directory URL (alternative to `--directory`) |
| `ACME_ACCOUNT_KEY_FILE` | Account key path (alternative to `--account-key`) |
| `ACME_ACCOUNT_KEY_PASSWORD` | Account key decryption password (prefer the `_FILE` variant) |
| `ACME_ACCOUNT_KEY_PASSWORD_FILE` | Account key decryption password file path |
| `ACME_ACCOUNT_URL` | Account URL (alternative to `--account-url`) |
| `ACME_OUTPUT_FORMAT` | Output format: `text` or `json` |
| `ACME_INSECURE` | Disable TLS verification (testing/self-signed CAs only) |
| `ACME_CONNECT_TIMEOUT` | HTTP connect timeout in seconds |
| `ACME_ALLOW_PRIVATE_NETWORK` | Allow contacting private/loopback IPs (internal CAs) |
| `ACME_UNSAFE_HOOKS` | Downgrade hook ownership/permission errors to warnings |
| `ACME_DNS_CHECK_MODE` | DNS-01 resolver strategy: `authoritative`, `cached`, or `system` |
| `ACME_DNS_CHECK_DNSSEC` | Enable DNSSEC validation on DNS-01 checks |
| `ACME_KEY_PASSWORD_FILE` | Private key password file path |
| `ACME_NEW_KEY_PASSWORD` / `ACME_NEW_KEY_PASSWORD_FILE` | New account key password (for `key-rollover`) |
| `ACME_EAB_KID` / `ACME_EAB_HMAC_KEY` | EAB Key ID / HMAC key (base64url) |
| `ACME_PROFILE` | Certificate profile (draft-ietf-acme-profiles-01) |

### Secrets

For encrypted keys and EAB credentials, prefer the `_FILE` variants and mount the secret read-only (plain env values are visible in `docker inspect`):

```sh
docker run --rm \
  -v ./acme-data:/data \
  -v /run/secrets/account_key_password:/run/secrets/account_key_password:ro \
  -e ACME_ACCOUNT_KEY_PASSWORD_FILE=/run/secrets/account_key_password \
  andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory \
  --account-key /data/account.key \
  show-config
```

## Testing with Pebble

[Pebble](https://github.com/letsencrypt/pebble) is Let's Encrypt's miniature ACME test server — the easiest way to test flows locally. Run it and this client on the same Docker network.

```yaml
# docker-compose.yml
services:
  pebble:
    image: letsencrypt/pebble:latest
    command: pebble -config /test/config/pebble-config.json -strict
    ports:
      - "14000:14000"  # ACME server
      - "15000:15000"  # Management interface
    environment:
      - PEBBLE_VA_NOSLEEP=1           # Speed up validation (no delay)
      - PEBBLE_VA_ALWAYS_VALID=1      # Accept any challenge without checking
      - PEBBLE_WFE_NONCEREJECT=0      # Don't randomly reject nonces

  challtestsrv:
    image: letsencrypt/pebble-challtestsrv:latest
    command: pebble-challtestsrv -defaultIPv4 host.docker.internal
    ports:
      - "8055:8055"
```

```sh
docker compose up -d
```

Generate a key and run the full flow against Pebble. Because containers share the compose network, target Pebble by its service name (`pebble`) and pass `--insecure` (Pebble uses a self-signed cert):

```sh
mkdir -p ./acme-data && sudo chown 65532:65532 ./acme-data

docker run --rm --network <compose-network> -v ./acme-data:/data andrico21/acme-client-rs \
  generate-key --account-key /data/account.key

docker run --rm --network <compose-network> -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://pebble:14000/dir --account-key /data/account.key --insecure \
  run --contact test@example.com --challenge-type http-01 --http-port 5002 \
    --cert-output /data/test.example.com.pem --key-output /data/test.example.com.key \
    test.example.com
```

> **TLS note:** `--insecure` (or `ACME_INSECURE=true`) is **required** against Pebble or any self-signed CA, and implies `--allow-private-network`. Never use it against a production CA.
>
> **Networking note:** for the Pebble VA to reach the client's challenge server you typically run the client as its own compose service on the same network, or use `PEBBLE_VA_ALWAYS_VALID=1` (shown above) so validation succeeds without a reachable challenge endpoint.

### Pebble Troubleshooting

| Problem | Solution |
|---|---|
| TLS handshake error connecting to Pebble | Use `--insecure` (or `ACME_INSECURE=true`); or mount and set `SSL_CERT_FILE` to Pebble's `test/certs/pebble.minica.pem` |
| Challenge validation fails | Set `PEBBLE_VA_ALWAYS_VALID=1`, or ensure the client's challenge server is reachable from the Pebble container (same network) |
| `badNonce` errors | Normal — the client retries automatically. Set `PEBBLE_WFE_NONCEREJECT=0` to disable random nonce rejection |
| Port 14000 already in use | Stop any existing Pebble instance: `docker compose down` |

## CLI Reference

### Global Options

| Option | Short | Env Var | Default | Description |
|---|---|---|---|---|
| `--config <PATH>` | | `ACME_CONFIG` | - | Path to TOML config file (env vars ignored when loaded, except secrets) |
| `--directory <URL>` | `-d` | `ACME_DIRECTORY_URL` | `https://localhost:14000/dir` | ACME server directory URL |
| `--account-key <PATH>` | `-k` | `ACME_ACCOUNT_KEY_FILE` | `account.key` | Path to the account key (PKCS#8 PEM) |
| `--account-key-password <PW>` | | `ACME_ACCOUNT_KEY_PASSWORD` | - | Password to decrypt the account key (visible in process list — prefer the file variant). Conflicts with `--account-key-password-file`. |
| `--account-key-password-file <PATH>` | | `ACME_ACCOUNT_KEY_PASSWORD_FILE` | - | Read the account key decryption password from a file (first non-empty line). Conflicts with `--account-key-password`. |
| `--account-url <URL>` | `-a` | `ACME_ACCOUNT_URL` | - | Account URL (required after account creation) |
| `--output-format <FMT>` | | `ACME_OUTPUT_FORMAT` | `text` | Output format: `text` or `json` |
| `--insecure` | | `ACME_INSECURE` | `false` | Disable TLS certificate verification (self-signed CAs like Pebble). Implies `--allow-private-network`. |
| `--connect-timeout <SECONDS>` | | `ACME_CONNECT_TIMEOUT` | `15` | HTTP connect timeout (TCP + TLS handshake). Whole-request timeout is fixed at 120s. |
| `--allow-private-network` | | `ACME_ALLOW_PRIVATE_NETWORK` | `false` | Allow contacting private/loopback/link-local IPs. Default blocks these to prevent SSRF. Implied by `--insecure`. |
| `--unsafe-hooks` | | `ACME_UNSAFE_HOOKS` | `false` | Downgrade hook-script ownership/permission violations from hard errors to warnings. |
| `--dns-check-mode <MODE>` | | `ACME_DNS_CHECK_MODE` | `authoritative` | DNS-01 propagation resolver: `authoritative`, `cached`, or `system`. |
| `--dns-check-dnssec` | | `ACME_DNS_CHECK_DNSSEC` | `false` | Enable DNSSEC validation on DNS-01 propagation checks. |
| `--silent` | | - | `false` | Suppress all stdout; only the exit code indicates success/failure. |

Global options can be placed before or after the subcommand.

### Subcommands

| Command | Description |
|---|---|
| `generate-config` | Generate a self-documented TOML config file template |
| `show-config` | Show the effective merged configuration (`--verbose` shows sources; `--show-secrets` unmasks passwords/HMAC keys) |
| `generate-key` | Generate a new account key pair. `--force` overwrites an existing key file |
| `account` | Create or look up an ACME account (`--contact`, EAB flags; `--agree-tos` defaults to `true`) |
| `order <domains...>` | Request a new certificate order |
| `get-authz <url>` | Fetch an authorization object |
| `respond-challenge <url>` | Tell the server a challenge is ready |
| `serve-http-01` | Serve an HTTP-01 challenge response (`--token`, `--port`; `--challenge-dir` writes the file instead) |
| `show-dns-01` | Show DNS-01 TXT record setup instructions |
| `show-dns-persist-01` | Show DNS-PERSIST-01 persistent TXT record setup instructions |
| `finalize` | Finalize an order with a new CSR (`--key-output` required; `--cert-key-algorithm`, key-password flags, `--force`) |
| `poll-order <url>` | Poll an order's current status |
| `download-cert <url>` | Download the issued certificate (`--output`, default `certificate.pem`) |
| `deactivate-account` | Deactivate the current account |
| `key-rollover` | Rotate the account key (RFC 8555 §7.3.5). `--new-key` required |
| `pre-authorize` | Pre-authorize an identifier before creating an order (RFC 8555 §7.4.1) |
| `renewal-info <path>` | Query ACME Renewal Information for a certificate (RFC 9773) |
| `list-profiles` | List certificate profiles advertised by the server (draft-ietf-acme-profiles-01) |
| `revoke-cert <path>` | Revoke a certificate |
| `run <domains...>` | Run the full ACME flow end-to-end |

### `run` Options

| Option | Default | Description |
|---|---|---|
| `--contact <EMAIL>` | - | Contact email for the ACME account |
| `--challenge-type <TYPE>` | `http-01` | `http-01`, `dns-01`, `dns-persist-01`, or `tls-alpn-01` |
| `--http-port <PORT>` | `80` | Port for the built-in HTTP-01 server (standalone mode) |
| `--challenge-dir <PATH>` | - | Write HTTP-01 challenge files here instead of starting a server |
| `--dns-hook <SCRIPT>` | - | Path to a DNS-01 hook script (called with `ACME_ACTION=create\|cleanup`) |
| `--dns-wait <SECONDS>` | - | Wait up to N seconds for DNS TXT propagation (polls every 5s) |
| `--dns-propagation-concurrency <N>` | `5` | Max concurrent DNS propagation checks with `--dns-hook` across domains |
| `--challenge-timeout <SECONDS>` | `300` | Max seconds to wait for challenge validation (polls every 2s) |
| `--cert-output <PATH>` | `certificate.pem` | Save the certificate to this file |
| `--key-output <PATH>` | `private.key` | Save the private key to this file |
| `--reuse-key <PATH>` | - | Reuse an existing unencrypted PKCS#8 PEM key for the CSR instead of generating one. Algorithm auto-detected; `--cert-key-algorithm` ignored. |
| `--days <N>` | - | **Renewal mode:** skip issuance if existing `--cert-output` has more than N days remaining. |
| `--key-password <PW>` | - | Encrypt the private key (PKCS#8, AES-256-CBC + scrypt KDF) |
| `--key-password-file <PATH>` | - | Read the key encryption password from a file (first line) |
| `--on-challenge-ready <SCRIPT>` | - | Run a script after each challenge is ready (dns-01, dns-persist-01, tls-alpn-01; not http-01) |
| `--on-cert-issued <SCRIPT>` | - | Run a script after the certificate is issued and saved |
| `--eab-kid <KID>` | - | EAB Key ID from the CA |
| `--eab-hmac-key <KEY>` | - | EAB HMAC key (base64url-encoded) |
| `--pre-authorize` | `false` | Pre-authorize identifiers via newAuthz before creating the order (RFC 8555 §7.4.1) |
| `--persist-policy <POLICY>` | - | Policy for dns-persist-01 records (e.g., `wildcard`) |
| `--persist-until <TIMESTAMP>` | - | Unix timestamp for dns-persist-01 `persistUntil` |
| `--cert-key-algorithm <ALG>` | `ec-p256` | Certificate key algorithm: `ec-p256`, `ec-p384`, or `ed25519` |
| `--ari` | `false` | **ARI renewal mode (RFC 9773):** query the server's suggested window; include `replaces` on renewal. Falls back to `--days`. |
| `--reissue-on-mismatch` | `false` | Allow reissuance when requested domains differ from the existing cert's SANs |
| `--print-cert` | `false` | Print the issued certificate PEM to stdout after saving |
| `--profile <NAME>` | - | Certificate profile to request (draft-ietf-acme-profiles-01) |
| `--force` | `false` | Overwrite the `--key-output` file if it already exists |

### Key Rollover (RFC 8555 §7.3.5)

Rotate your account key without creating a new account. Both keys must be in the mounted volume:

```sh
# 1. Generate a new key
docker run --rm -v ./acme-data:/data andrico21/acme-client-rs \
  generate-key --account-key /data/new-account.key

# 2. Roll over (old key authenticates, new key proves possession)
docker run --rm -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory \
  --account-key /data/account.key \
  --account-url https://acme-v02.api.letsencrypt.org/acme/acct/123456789 \
  key-rollover --new-key /data/new-account.key

# 3. Promote the new key on the host
mv ./acme-data/new-account.key ./acme-data/account.key
```

The old and new keys can use different algorithms (e.g., RSA-2048 → ES256).

### External Account Binding (EAB)

Some CAs require linking your ACME account to an existing external account via a Key ID and HMAC key:

```sh
# Register with EAB
docker run --rm -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-server/directory --account-key /data/account.key \
  account --contact admin@example.com --eab-kid my-key-id --eab-hmac-key aBase64urlEncodedHmacKey

# Full flow with EAB
docker run --rm -p 80:80 -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-server/directory --account-key /data/account.key \
  run --contact admin@example.com --challenge-type http-01 --http-port 80 \
    --eab-kid my-key-id --eab-hmac-key aBase64urlEncodedHmacKey \
    --cert-output /data/example.com.pem --key-output /data/example.com.key example.com
```

> **Note:** `--eab-kid` and `--eab-hmac-key` must be provided together; the HMAC key must be base64url-encoded. EAB is only needed for the initial account registration.

### Pre-Authorization (RFC 8555 §7.4.1)

```sh
# Standalone pre-authorization
docker run --rm -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-server/directory --account-key /data/account.key \
  --account-url https://acme-server/acme/acct/123 \
  pre-authorize --domain example.com --challenge-type http-01

# Pre-authorize during the full flow
docker run --rm -p 80:80 -v ./acme-data:/data andrico21/acme-client-rs \
  --directory https://acme-server/directory --account-key /data/account.key \
  run --contact admin@example.com --challenge-type http-01 --http-port 80 --pre-authorize \
    --cert-output /data/example.com.pem --key-output /data/example.com.key example.com
```

> **Note:** Not all ACME servers support pre-authorization; the server must advertise a `newAuthz` URL.

## License

Licensed under the [Apache License, Version 2.0](https://github.com/andrico21/acme-client-rs/blob/master/LICENSE).
