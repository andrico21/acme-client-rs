#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Fully automated testing for acme-client-rs on a clean Ubuntu + Podman setup
#
# Prerequisites: clean Ubuntu machine with podman installed.
#   sudo apt install -y podman
#
# Usage:
#   chmod +x test-podman.sh
#   ./test-podman.sh              # full build + test
#   ./test-podman.sh --no-build   # skip build, reuse existing binary
#
# What this script does:
#   1. Builds acme-client-rs inside a container (static musl binary)
#   2. Starts Pebble ACME test server via podman
#   3. Waits for Pebble to become healthy
#   4. Runs the full test suite (test.sh) against Pebble
#   5. Cleans up all containers, pods, and images
#
# The script is fully self-contained — no Rust toolchain, no OpenSSL headers,
# no docker-compose, nothing except podman is required on the host.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── CLI flags ─────────────────────────────────────────────────────────────────

SKIP_BUILD=false
for arg in "$@"; do
  case "${arg}" in
    --no-build) SKIP_BUILD=true ;;
  esac
done

# ── Colours ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}"
POD_NAME="acme-test-pod"
PEBBLE_IMAGE="ghcr.io/letsencrypt/pebble:latest"
CHALLTESTSRV_IMAGE="ghcr.io/letsencrypt/pebble-challtestsrv:latest"
BUILDER_IMAGE="docker.io/library/rust:alpine"
ACME_SERVER="https://localhost:14000/dir"
TEST_DOMAIN="localhost"

# Pebble ports
PEBBLE_PORT=14000
PEBBLE_MGMT_PORT=15000
CHALLTESTSRV_PORT=8055

# ── Helpers ──────────────────────────────────────────────────────────────────

log_step() {
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  $1${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

log_info() {
  echo -e "  ${GREEN}✓${NC} $1"
}

log_warn() {
  echo -e "  ${YELLOW}!${NC} $1"
}

log_error() {
  echo -e "  ${RED}✗${NC} $1"
}

# ── Cleanup (runs on exit) ───────────────────────────────────────────────────

cleanup() {
  echo ""
  log_step "Cleanup"

  # Stop and remove the pod (takes all containers with it)
  if podman pod exists "${POD_NAME}" 2>/dev/null; then
    podman pod stop "${POD_NAME}" 2>/dev/null || true
    podman pod rm -f "${POD_NAME}" 2>/dev/null || true
    log_info "Pod '${POD_NAME}' removed"
  fi

  # Remove the builder image we tagged
  if podman image exists acme-client-rs-builder 2>/dev/null; then
    podman rmi -f acme-client-rs-builder 2>/dev/null || true
    log_info "Builder image removed"
  fi

  # Remove the extracted binary
  if [[ -f "${PROJECT_DIR}/target/release/acme-client-rs" ]] && [[ "${BINARY_BUILT:-false}" == "true" ]]; then
    log_info "Binary at target/release/acme-client-rs preserved"
  fi

  echo -e "\n  ${BOLD}Done.${NC}"
}
trap cleanup EXIT

# ── Preflight checks ────────────────────────────────────────────────────────

log_step "Step 0: Preflight Checks"

# Check podman
if ! command -v podman &>/dev/null; then
  log_error "podman is not installed"
  echo "  Install it:  sudo apt update && sudo apt install -y podman"
  exit 1
fi
log_info "podman: $(podman --version)"

# Check project files
if [[ ! -f "${PROJECT_DIR}/Cargo.toml" ]]; then
  log_error "Cargo.toml not found in ${PROJECT_DIR}"
  exit 1
fi
log_info "Project directory: ${PROJECT_DIR}"

if [[ ! -f "${PROJECT_DIR}/test.sh" ]]; then
  log_error "test.sh not found — the test runner is required"
  exit 1
fi
log_info "Test runner: test.sh"

# Check for required tools; install any that are missing
MISSING_PKGS=()
for cmd_pkg in curl:curl openssl:openssl python3:python3 sha256sum:coreutils file:file; do
  cmd="${cmd_pkg%%:*}"
  pkg="${cmd_pkg##*:}"
  if ! command -v "${cmd}" &>/dev/null; then
    MISSING_PKGS+=("${pkg}")
  fi
done

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
  log_warn "Installing missing packages: ${MISSING_PKGS[*]}"
  sudo apt update -qq && sudo apt install -y -qq "${MISSING_PKGS[@]}" >/dev/null 2>&1
fi

log_info "curl: $(curl --version | head -1)"
log_info "openssl: $(openssl version)"
log_info "python3: $(python3 --version 2>&1)"
log_info "sha256sum: $(sha256sum --version | head -1)"

# ═════════════════════════════════════════════════════════════════════════════
# Step 1: Build the binary inside a container
# ═════════════════════════════════════════════════════════════════════════════

log_step "Step 1: Build acme-client-rs (containerized)"

if [[ "${SKIP_BUILD}" == "true" ]] && [[ -x "${PROJECT_DIR}/target/release/acme-client-rs" ]]; then
  log_info "--no-build: reusing existing binary"
else
  mkdir -p "${PROJECT_DIR}/target/release"

  # Use a Containerfile inline via heredoc
  podman build -t acme-client-rs-builder -f - "${PROJECT_DIR}" <<'CONTAINERFILE'
FROM docker.io/library/rust:alpine AS builder
RUN apk add --no-cache build-base pkgconf openssl-dev openssl-libs-static perl make
WORKDIR /src
COPY . .
ENV OPENSSL_STATIC=1
RUN cargo rustc --release -- -C relocation-model=pie -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack \
    && strip target/release/acme-client-rs
CONTAINERFILE

  # Extract the binary from the builder image
  CONTAINER_ID=$(podman create acme-client-rs-builder)
  podman cp "${CONTAINER_ID}:/src/target/release/acme-client-rs" "${PROJECT_DIR}/target/release/acme-client-rs"
  podman rm "${CONTAINER_ID}" >/dev/null
  chmod +x "${PROJECT_DIR}/target/release/acme-client-rs"
  BINARY_BUILT=true
fi

log_info "Binary built: $(file "${PROJECT_DIR}/target/release/acme-client-rs")"

VERSION=$("${PROJECT_DIR}/target/release/acme-client-rs" --version 2>&1 || true)
log_info "Version: ${VERSION}"

# ═════════════════════════════════════════════════════════════════════════════
# Step 2: Start Pebble ACME test server
# ═════════════════════════════════════════════════════════════════════════════

log_step "Step 2: Start Pebble ACME Test Server"

# Clean up any previous pod
if podman pod exists "${POD_NAME}" 2>/dev/null; then
  podman pod stop "${POD_NAME}" 2>/dev/null || true
  podman pod rm -f "${POD_NAME}" 2>/dev/null || true
  log_info "Cleaned up previous pod"
fi

# Create a pod with shared network namespace (containers see each other on localhost)
podman pod create \
  --name "${POD_NAME}" \
  -p "${PEBBLE_PORT}:${PEBBLE_PORT}" \
  -p "${PEBBLE_MGMT_PORT}:${PEBBLE_MGMT_PORT}" \
  -p "${CHALLTESTSRV_PORT}:${CHALLTESTSRV_PORT}"
log_info "Pod '${POD_NAME}' created"

# Start the challenge test server (DNS mock)
podman run -d \
  --pod "${POD_NAME}" \
  --name acme-test-challtestsrv \
  "${CHALLTESTSRV_IMAGE}" \
  pebble-challtestsrv -defaultIPv4 127.0.0.1
log_info "Challenge test server started"

# Start Pebble itself
podman run -d \
  --pod "${POD_NAME}" \
  --name acme-test-pebble \
  -e PEBBLE_VA_NOSLEEP=1 \
  -e PEBBLE_VA_ALWAYS_VALID=1 \
  -e PEBBLE_WFE_NONCEREJECT=0 \
  "${PEBBLE_IMAGE}" \
  -strict
log_info "Pebble ACME server started"

# ═════════════════════════════════════════════════════════════════════════════
# Step 3: Wait for Pebble to become ready
# ═════════════════════════════════════════════════════════════════════════════

log_step "Step 3: Waiting for Pebble to become ready"

MAX_WAIT=60
WAITED=0
while [[ ${WAITED} -lt ${MAX_WAIT} ]]; do
  if curl -sk "https://localhost:${PEBBLE_PORT}/dir" 2>/dev/null | grep -q "newAccount"; then
    break
  fi
  sleep 2
  WAITED=$((WAITED + 2))
  echo -ne "  Waiting... ${WAITED}s / ${MAX_WAIT}s\r"
done

if [[ ${WAITED} -ge ${MAX_WAIT} ]]; then
  log_error "Pebble did not become ready within ${MAX_WAIT}s"
  echo ""
  echo "  Pebble logs:"
  podman logs acme-test-pebble 2>&1 | tail -20 | sed 's/^/    /'
  exit 1
fi

echo ""
log_info "Pebble is ready (took ${WAITED}s)"

# Quick sanity check — print directory
DIRECTORY=$(curl -sk "https://localhost:${PEBBLE_PORT}/dir" 2>/dev/null)
log_info "Directory response: $(echo "${DIRECTORY}" | head -1)"

# ═════════════════════════════════════════════════════════════════════════════
# Step 4: Run the test suite
# ═════════════════════════════════════════════════════════════════════════════

log_step "Step 4: Running Test Suite"

echo ""
echo -e "  ${BOLD}Server:${NC}  ${ACME_SERVER}"
echo -e "  ${BOLD}Domain:${NC}  ${TEST_DOMAIN}"
echo -e "  ${BOLD}Binary:${NC}  ${PROJECT_DIR}/target/release/acme-client-rs"
echo ""

cd "${PROJECT_DIR}"
chmod +x test.sh

# Run the full test suite
# test.sh expects: <acme-server-url> <test-subdomain> [--insecure]
set +e
./test.sh "${ACME_SERVER}" "${TEST_DOMAIN}" --insecure
TEST_EXIT=$?
set -e

# ═════════════════════════════════════════════════════════════════════════════
# Step 5: Report
# ═════════════════════════════════════════════════════════════════════════════

echo ""
log_step "Final Result"

if [[ ${TEST_EXIT} -eq 0 ]]; then
  echo -e "\n  ${GREEN}${BOLD}ALL TESTS PASSED${NC}\n"
else
  echo -e "\n  ${RED}${BOLD}SOME TESTS FAILED (exit code ${TEST_EXIT})${NC}\n"

  echo "  Pebble logs (last 30 lines):"
  podman logs acme-test-pebble 2>&1 | tail -30 | sed 's/^/    /'
fi

exit ${TEST_EXIT}
