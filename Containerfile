# syntax=docker/dockerfile:1.7
#
# Multi-stage build for acme-client-rs producing a *distroless* runtime image.
#
# Stage 1 (builder): compiles a fully static musl binary for the requested
#                    platform (linux/amd64, linux/arm64, or linux/arm/v7)
#                    with rustls (aws-lc-rs) for TLS — no OpenSSL — and
#                    security hardening flags: PIE + full RELRO + NX stack on
#                    amd64/arm64; armv7 ships a non-PIE static ET_EXEC with
#                    RELRO/NX because static-pie binaries for
#                    armv7-unknown-linux-musleabihf link but crash at startup
#                    (verified under qemu-arm 7.2 and 10.2).
# Stage 2 (runtime): gcr.io/distroless/static-debian13:nonroot — no shell,
#                    no package manager, no libc; just CA roots, /etc/passwd
#                    with a `nonroot` user (UID 65532), and the binary.
#
# Final image is ~10 MB, runs as non-root by default, and contains zero
# attack surface beyond the binary itself.

# Make Docker's automatic platform arg usable in the FROM selector below
# (linux/amd64 -> amd64, linux/arm64 -> arm64, linux/arm/v7 -> arm).
ARG TARGETARCH

# -- Stage 1: Builder selection --
#
# Base-only selector stages — keep them free of build commands: some
# podman/buildah versions do not prune unused stages the way BuildKit does,
# so any work here would run for every platform on every local build.
#
# amd64/arm64 build natively on rust:alpine (pin Rust + Alpine in lockstep
# with `.github/workflows/release.yaml`; verify the Alpine tag at
# https://hub.docker.com/_/rust). There is NO arm32v7 rust:alpine image, so
# the linux/arm/v7 leg cross-compiles on the build host's own platform
# ($BUILDPLATFORM) inside messense/rust-musl-cross, which carries the
# armv7-musleabihf cross toolchain. Pinned by multi-arch INDEX digest
# (amd64/arm64/arm children) — re-resolve the index digest manually when
# bumping the toolchain.
FROM docker.io/library/rust:1.96-alpine3.23 AS builder-amd64
FROM docker.io/library/rust:1.96-alpine3.23 AS builder-arm64
FROM --platform=$BUILDPLATFORM docker.io/messense/rust-musl-cross@sha256:965d005bc457b10afa22dc9211ee8c64beceab156d2d731a028f6d11d3b3e619 AS builder-arm

# The single build stage: exactly one selector above, chosen per platform leg.
FROM builder-${TARGETARCH} AS builder

ARG TARGETARCH
ARG TARGETVARIANT

# Alpine arches need the musl headers + pkgconf; the messense cross image
# ships its toolchain complete (and has no apk).
RUN case "$TARGETARCH" in amd64|arm64) apk add --no-cache musl-dev pkgconf ;; esac

WORKDIR /src
COPY . .

# Scope hardening flags to the *target* triple only. A bare `RUSTFLAGS` would
# also apply to host-built proc-macro crates (e.g. asn1-rs-derive), and
# `+crt-static` makes them un-buildable as dylibs:
#   "cannot produce proc-macro for ... as the target ... does not support these crate types"
#
# TARGETARCH/TARGETVARIANT are auto-populated by BuildKit/buildah per leg.
# amd64/arm64 build natively (host triple == target triple, std already
# installed). The arm/v7 leg cross-compiles: `rustup target add` first
# (the repo-pinned toolchain ships without armv7 std — E0463 otherwise).
# `--target` stays mandatory for the proc-macro flag scoping above.
#
# armv7 hardening omits PIE deliberately: `-C relocation-model=pie` silently
# yields ET_EXEC there, and forcing `-static-pie` links a binary that
# segfaults at startup (musl static-pie startup defect on this target,
# verified under qemu-arm 7.2 and 10.2). RELRO/NX/static are kept.
RUN case "$TARGETARCH" in \
      amd64) RUST_TARGET=x86_64-unknown-linux-musl; \
             HARDENING="-C target-feature=+crt-static -C relocation-model=pie -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack" ;; \
      arm64) RUST_TARGET=aarch64-unknown-linux-musl; \
             HARDENING="-C target-feature=+crt-static -C relocation-model=pie -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack" ;; \
      arm)   if [ "$TARGETVARIANT" != "v7" ]; then echo "unsupported arm variant: '${TARGETVARIANT}' (only v7)" >&2; exit 1; fi; \
             RUST_TARGET=armv7-unknown-linux-musleabihf; \
             HARDENING="-C target-feature=+crt-static -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack"; \
             rustup target add "$RUST_TARGET" ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && export "CARGO_TARGET_$(printf '%s' "$RUST_TARGET" | tr '[:lower:]-' '[:upper:]_')_RUSTFLAGS=$HARDENING" \
 && cargo build --release --target "$RUST_TARGET" \
 # Cargo's release profile already strips (strip = true); the explicit strip
 # is kept on the alpine arches for parity with release.yaml and skipped on
 # arm, where the cross image's host `strip` cannot process ARM ELF.
 && case "$TARGETARCH" in amd64|arm64) strip "target/$RUST_TARGET/release/acme-client-rs" ;; esac \
 && cp "target/$RUST_TARGET/release/acme-client-rs" /acme-client-rs

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

COPY --from=builder /acme-client-rs /usr/local/bin/acme-client-rs

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
