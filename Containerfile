# syntax=docker/dockerfile:1.7
#
# Multi-stage build for acme-client-rs producing a *distroless* runtime image.
#
# Stage 1 (builder): rust:alpine — compiles a fully static musl binary with
#                    rustls (aws-lc-rs) for TLS — no OpenSSL — and full
#                    security hardening flags (PIE, full RELRO, NX stack).
# Stage 2 (runtime): gcr.io/distroless/static-debian13:nonroot — no shell,
#                    no package manager, no libc; just CA roots, /etc/passwd
#                    with a `nonroot` user (UID 65532), and the binary.
#
# Final image is ~10 MB, runs as non-root by default, and contains zero
# attack surface beyond the binary itself.

# -- Stage 1: Build --
#
# Pin to a specific Rust + Alpine pair for reproducibility. Bump in lockstep
# with `.github/workflows/release.yaml` (rust:X.Y.Z-alpine) and verify Alpine
# tag at https://hub.docker.com/_/rust .
FROM docker.io/library/rust:1.96-alpine3.23 AS builder

RUN apk add --no-cache musl-dev pkgconf

WORKDIR /src
COPY . .

# Scope hardening flags to the *target* triple only. A bare `RUSTFLAGS` would
# also apply to host-built proc-macro crates (e.g. asn1-rs-derive), and
# `+crt-static` makes them un-buildable as dylibs:
#   "cannot produce proc-macro for ... as the target ... does not support these crate types"
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack"

RUN cargo build --release --target x86_64-unknown-linux-musl \
 && strip target/x86_64-unknown-linux-musl/release/acme-client-rs

# -- Stage 2: Distroless runtime --
FROM gcr.io/distroless/static-debian13:nonroot

# Image version, stamped into the OCI `image.version` label. CI passes the
# release tag via `--build-arg VERSION=$tag`; manual local builds default to
# "dev" unless the operator overrides.
ARG VERSION=dev

# OCI image metadata (https://github.com/opencontainers/image-spec/blob/main/annotations.md)
LABEL org.opencontainers.image.title="acme-client-rs" \
      org.opencontainers.image.description="Lightweight, single-binary ACME (RFC 8555) client with RFC 9773 (ARI) and DNS-PERSIST-01 support. Hardened static musl build on a distroless base." \
      org.opencontainers.image.authors="andrico21 <andrico21@users.noreply.github.com>" \
      org.opencontainers.image.source="https://github.com/andrico21/acme-client-rs" \
      org.opencontainers.image.url="https://github.com/andrico21/acme-client-rs" \
      org.opencontainers.image.documentation="https://github.com/andrico21/acme-client-rs#readme" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="andrico21" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian13:nonroot"

COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/acme-client-rs /usr/local/bin/acme-client-rs

# ── Runtime environment ──────────────────────────────────────────────────────
# Timezone (used for log timestamps and certificate-expiry date formatting).
# distroless/static ships zoneinfo at /usr/share/zoneinfo, so this Just Works.
ENV TZ=UTC

# Logging verbosity for the `tracing` subscriber: error | warn | info | debug | trace
ENV RUST_LOG=info

# ── Optional ACME settings (uncomment and set the ones you need) ─────────────
# ACME server directory URL — defaults to Pebble's localhost; override for prod.
#ENV ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory

# Path to the account key (PKCS#8 PEM). Mount the key as a volume.
#ENV ACME_ACCOUNT_KEY_FILE=/data/account.key

# Password (or password-file) to decrypt an encrypted account key.
# Prefer the *_FILE variant — plain ENV is visible in `podman inspect`.
#ENV ACME_ACCOUNT_KEY_PASSWORD_FILE=/run/secrets/account_key_password
#ENV ACME_ACCOUNT_KEY_PASSWORD=changeme

# Account URL (after first registration) — required for non-`run` subcommands.
#ENV ACME_ACCOUNT_URL=https://acme-v02.api.letsencrypt.org/acme/acct/123456789

# Output format: text | json
#ENV ACME_OUTPUT_FORMAT=json

# Path to a TOML config file (when set, env vars below are ignored — see README).
#ENV ACME_CONFIG=/etc/acme/acme-client-rs.toml

# Disable TLS verification — ONLY for testing against Pebble or self-signed CAs.
#ENV ACME_INSECURE=true

# HTTP connect timeout (seconds).
#ENV ACME_CONNECT_TIMEOUT=15

# Allow contacting RFC1918 / loopback / link-local IPs (internal CA deployments).
#ENV ACME_ALLOW_PRIVATE_NETWORK=true

# Hook script ownership/permission policy — leave unset in production.
#ENV ACME_UNSAFE_HOOKS=true

# DNS-01 propagation-check resolver: authoritative | cached | system
#ENV ACME_DNS_CHECK_MODE=authoritative
#ENV ACME_DNS_CHECK_DNSSEC=true

# Encrypted certificate-key password file.
#ENV ACME_KEY_PASSWORD_FILE=/run/secrets/cert_key_password

# Account-key rollover password files.
#ENV ACME_NEW_KEY_PASSWORD_FILE=/run/secrets/new_account_key_password

# External Account Binding (EAB) credentials — required by some CAs.
#ENV ACME_EAB_KID=my-eab-key-id
#ENV ACME_EAB_HMAC_KEY=base64url-encoded-hmac-key

# Certificate profile (draft-ietf-acme-profiles-01).
#ENV ACME_PROFILE=tlsserver

# Port for the built-in HTTP-01 challenge server (matches EXPOSE below).
EXPOSE 80/tcp

# /data is the conventional mount point for account key + issued cert/key.
# distroless/static:nonroot runs as UID 65532 — chown the host directory to
# match (or use `--userns=keep-id` with podman) so the binary can write here.
VOLUME ["/data"]
WORKDIR /data

ENTRYPOINT ["/usr/local/bin/acme-client-rs"]
CMD ["--help"]

# ─────────────────────────────────────────────────────────────────────────────
# Build:
#
#   podman build -t acme-client-rs:2.2.0 -t acme-client-rs:latest .
#
# Run (HTTP-01 standalone, port 80 exposed for ACME validation):
#
# The distroless image runs as UID 65532 (`nonroot`); make the host data dir
# writable for that UID first, then bind-mount it into /data.
#
#   mkdir -p ./acme-data && sudo chown 65532:65532 ./acme-data
#
#   podman run --rm \
#     --name acme-client-rs \
#     -p 80:80/tcp \
#     -v ./acme-data:/data:Z \
#     -e TZ=Europe/Berlin \
#     -e RUST_LOG=info \
#     acme-client-rs:2.2.0 \
#     --directory https://acme-v02.api.letsencrypt.org/directory \
#     --account-key /data/account.key \
#     run \
#       --contact admin@example.com \
#       --challenge-type http-01 \
#       --http-port 80 \
#       --cert-output /data/example.com.pem \
#       --key-output  /data/example.com.key \
#       --days 30 \
#       example.com www.example.com
#
# Notes:
#   • Binding host port 80 may need `sysctl net.ipv4.ip_unprivileged_port_start=80`
#     for rootless podman, or run the podman command via sudo.
#   • The container itself binds 80 *inside* the netns as UID 65532 — that's
#     always allowed (containers have their own privileged-port range).
#   • For renewal cron, drop `--rm` for `--restart=on-failure` and schedule via
#     `systemd-run --on-calendar=daily ...` or a host-level systemd timer.
# ─────────────────────────────────────────────────────────────────────────────
