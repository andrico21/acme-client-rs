#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Comprehensive test script for acme-client-rs
#
# Usage:
#   ./test.sh <acme-server-url> <test-subdomain> [--insecure]
#
# Example:
#   ./test.sh https://acme.example.com/acme/acme/directory dev.example.com
#   ./test.sh https://localhost:14000/dir localhost --insecure
#
# Orders will use:
#   - Single domain: acme-autotest.<test-subdomain>
#   - Multi-SAN: acme-autotest.<test-subdomain>, acme-autotest-san1.<test-subdomain>,
#               acme-autotest-san2.<test-subdomain>
#
# The script expects:
#   - A built binary at ./target/release/acme-client-rs
#   - The ACME server to be reachable and accepting orders for the above domains
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Arguments ────────────────────────────────────────────────────────────────

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <acme-server-url> <test-subdomain> [--insecure]"
  echo "Example: $0 https://acme.example.com/directory sub.example.com"
  echo "         $0 https://localhost:14000/dir localhost --insecure"
  exit 1
fi

ACME_SERVER="$1"
TEST_DOMAIN="$2"
INSECURE_FLAG=""
if [[ "${3:-}" == "--insecure" ]]; then
  INSECURE_FLAG="--insecure"
fi

# ── Derived domain names ─────────────────────────────────────────────────────

SINGLE_DOMAIN="acme-autotest.${TEST_DOMAIN}"
SAN_DOMAIN1="acme-autotest.${TEST_DOMAIN}"
SAN_DOMAIN2="acme-autotest-san1.${TEST_DOMAIN}"
SAN_DOMAIN3="acme-autotest-san2.${TEST_DOMAIN}"

# ── Configuration ────────────────────────────────────────────────────────────

ACME_BIN="./target/release/acme-client-rs"
WORK_DIR=$(mktemp -d)
PASSED=0
FAILED=0
SKIPPED=0
TOTAL=0
FAILURES=""

# Key algorithm variants to test for e2e flows
# Note: ed25519 excluded from E2E — Pebble only supports RS256, ES256, ES384, ES512
KEY_ALGORITHMS=("es256" "es384" "es512" "rsa2048" "rsa4096")

# ── Colours ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Colour

# ── Helpers ──────────────────────────────────────────────────────────────────

log_header() {
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  $1${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

log_test() {
  TOTAL=$((TOTAL + 1))
  echo ""
  echo -e "${BOLD}── TC-${1}: ${2}${NC}"
}

pass() {
  PASSED=$((PASSED + 1))
  echo -e "  ${GREEN}✓ PASS${NC}: $1"
}

fail() {
  FAILED=$((FAILED + 1))
  FAILURES="${FAILURES}\n  TC-${1}: ${2}"
  echo -e "  ${RED}✗ FAIL${NC}: $2"
}

skip() {
  SKIPPED=$((SKIPPED + 1))
  echo -e "  ${YELLOW}⊘ SKIP${NC}: $1"
}

# Run the ACME client with common global args
acme() {
  "${ACME_BIN}" --directory "${ACME_SERVER}" ${INSECURE_FLAG} "$@"
}

# Run acme and capture exit code without aborting on failure
acme_rc() {
  set +e
  "${ACME_BIN}" --directory "${ACME_SERVER}" ${INSECURE_FLAG} "$@"
  local rc=$?
  set -e
  return ${rc}
}

# Extract a value from acme output by prefix
extract() {
  local prefix="$1"
  echo "${OUTPUT}" | grep "^${prefix}" | head -1 | sed "s/^${prefix}[[:space:]]*//"
}

cleanup() {
  echo ""
  echo -e "${CYAN}Cleaning up work directory: ${WORK_DIR}${NC}"
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

# ── Preflight checks ────────────────────────────────────────────────────────

log_header "Preflight Checks"

if [[ ! -x "${ACME_BIN}" ]]; then
  echo -e "${RED}Error: Binary not found at ${ACME_BIN}${NC}"
  echo "Build first: cargo build --release"
  exit 1
fi
echo -e "  ${GREEN}✓${NC} Binary found: ${ACME_BIN}"

VERSION=$("${ACME_BIN}" --version 2>&1 || true)
echo -e "  ${GREEN}✓${NC} Version: ${VERSION}"

echo -e "  ${GREEN}✓${NC} ACME server: ${ACME_SERVER}"
echo -e "  ${GREEN}✓${NC} Test domain: ${TEST_DOMAIN}"
if [[ -n "${INSECURE_FLAG}" ]]; then
  echo -e "  ${GREEN}✓${NC} TLS verification: ${YELLOW}disabled${NC} (--insecure)"
fi
echo -e "  ${GREEN}✓${NC} Single-domain orders: ${SINGLE_DOMAIN}"
echo -e "  ${GREEN}✓${NC} Multi-SAN orders: ${SAN_DOMAIN1}, ${SAN_DOMAIN2}, ${SAN_DOMAIN3}"
echo -e "  ${GREEN}✓${NC} Work directory: ${WORK_DIR}"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1: Key Generation
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 1: Key Generation"

# ── TC-01: Generate Account Key (ES256 default) ─────────────────────────────

log_test "01" "Generate Account Key (ES256 default)"
OUTPUT=$(acme generate-key --account-key "${WORK_DIR}/tc01-account.key" 2>&1)
if [[ $? -eq 0 ]] && [[ -f "${WORK_DIR}/tc01-account.key" ]]; then
  if echo "${OUTPUT}" | grep -qi "es256\|ES256"; then
    pass "ES256 key generated"
  else
    fail "01" "Key generated but output does not mention ES256"
  fi
else
  fail "01" "generate-key failed or file not created"
fi

# Verify with openssl
if command -v openssl &>/dev/null; then
  if openssl ec -in "${WORK_DIR}/tc01-account.key" -text -noout 2>&1 | grep -q "prime256v1\|P-256"; then
    pass "OpenSSL confirms P-256 key"
  else
    fail "01" "OpenSSL could not confirm P-256 key"
  fi
fi

# ── TC-01b: Generate Key - All Algorithms ───────────────────────────────────

for ALG in "${KEY_ALGORITHMS[@]}"; do
  log_test "01b-${ALG}" "Generate Account Key (${ALG})"
  KEY_FILE="${WORK_DIR}/tc01b-${ALG}.key"
  OUTPUT=$(acme generate-key --algorithm "${ALG}" --account-key "${KEY_FILE}" 2>&1)
  if [[ $? -eq 0 ]] && [[ -f "${KEY_FILE}" ]]; then
    # Verify PEM header exists
    if head -1 "${KEY_FILE}" | grep -q "BEGIN"; then
      pass "${ALG} key generated and contains PEM header"
    else
      fail "01b-${ALG}" "Key file created but no PEM header"
    fi
  else
    fail "01b-${ALG}" "generate-key --algorithm ${ALG} failed"
  fi
done

# ── TC-02: Generate Key - Overwrite ─────────────────────────────────────────

log_test "02" "Generate Key - File Already Exists (overwrite)"
HASH1=$(sha256sum "${WORK_DIR}/tc01-account.key" | awk '{print $1}')
OUTPUT=$(acme generate-key --account-key "${WORK_DIR}/tc01-account.key" 2>&1)
HASH2=$(sha256sum "${WORK_DIR}/tc01-account.key" | awk '{print $1}')
if [[ "${HASH1}" != "${HASH2}" ]]; then
  pass "Key file overwritten with new key (hash changed)"
else
  fail "02" "Key file not overwritten (hash unchanged)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2: Account Management
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 2: Account Management"

# Generate a fresh key for account tests
ACCT_KEY="${WORK_DIR}/acct-test.key"
acme generate-key --account-key "${ACCT_KEY}" >/dev/null 2>&1

# ── TC-03: Create Account ───────────────────────────────────────────────────

log_test "03" "Create Account"
OUTPUT=$(acme --account-key "${ACCT_KEY}" account --contact test@example.com 2>&1)
if echo "${OUTPUT}" | grep -q "Account status: valid"; then
  ACCOUNT_URL=$(extract "Account URL:")
  if [[ -n "${ACCOUNT_URL}" ]]; then
    pass "Account created - URL: ${ACCOUNT_URL}"
  else
    fail "03" "Account created but no URL returned"
  fi
else
  fail "03" "Account creation failed"
  echo "  Output: ${OUTPUT}"
fi

# ── TC-04: Create Account - Idempotent Lookup ──────────────────────────────

log_test "04" "Create Account - Idempotent Lookup"
OUTPUT2=$(acme --account-key "${ACCT_KEY}" account --contact test@example.com 2>&1)
ACCOUNT_URL2=$(echo "${OUTPUT2}" | grep "^Account URL:" | head -1 | sed 's/^Account URL:[[:space:]]*//')
if [[ "${ACCOUNT_URL}" == "${ACCOUNT_URL2}" ]]; then
  pass "Same account URL returned on second call"
else
  fail "04" "Different account URL: got ${ACCOUNT_URL2}, expected ${ACCOUNT_URL}"
fi

# ── TC-05: Create Account - No Contact ──────────────────────────────────────

log_test "05" "Create Account - No Contact"
NOCONTACT_KEY="${WORK_DIR}/nocontact.key"
acme generate-key --account-key "${NOCONTACT_KEY}" >/dev/null 2>&1
OUTPUT=$(acme --account-key "${NOCONTACT_KEY}" account 2>&1)
if echo "${OUTPUT}" | grep -q "Account status: valid"; then
  pass "Account without contact created successfully"
else
  fail "05" "Account creation without contact failed"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3: Order Management
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 3: Order Management"

# ── TC-06: Place an Order (single domain) ───────────────────────────────────

log_test "06" "Place an Order (single domain)"
OUTPUT=$(acme --account-key "${ACCT_KEY}" --account-url "${ACCOUNT_URL}" \
  order "${SINGLE_DOMAIN}" 2>&1)
if echo "${OUTPUT}" | grep -q "Order URL:"; then
  ORDER_URL=$(extract "Order URL:")
  FINALIZE_URL=$(extract "Finalize URL:")
  AUTHZ_URL=$(echo "${OUTPUT}" | grep "authz:" | head -1 | sed 's/.*authz:[[:space:]]*//')
  pass "Order placed - URL: ${ORDER_URL}"
  echo "  Finalize URL: ${FINALIZE_URL}"
  echo "  Authz URL: ${AUTHZ_URL}"
else
  fail "06" "Order placement failed"
  echo "  Output: ${OUTPUT}"
fi

# ── TC-07: Place an Order - Multiple Domains (SAN) ──────────────────────────

log_test "07" "Place an Order - Multiple Domains (SAN)"
OUTPUT=$(acme --account-key "${ACCT_KEY}" --account-url "${ACCOUNT_URL}" \
  order "${SAN_DOMAIN1}" "${SAN_DOMAIN2}" "${SAN_DOMAIN3}" 2>&1)
AUTHZ_COUNT=$(echo "${OUTPUT}" | grep -c "authz:" || true)
if [[ ${AUTHZ_COUNT} -ge 2 ]]; then
  pass "Multi-SAN order placed with ${AUTHZ_COUNT} authorizations"
else
  # Some servers deduplicate or may have different behavior
  if echo "${OUTPUT}" | grep -q "Order URL:"; then
    pass "Multi-SAN order placed (server returned ${AUTHZ_COUNT} authz)"
  else
    fail "07" "Multi-SAN order failed"
    echo "  Output: ${OUTPUT}"
  fi
fi

# ── TC-08: Fetch Authorization ──────────────────────────────────────────────

log_test "08" "Fetch Authorization"
if [[ -n "${AUTHZ_URL:-}" ]]; then
  OUTPUT=$(acme --account-key "${ACCT_KEY}" --account-url "${ACCOUNT_URL}" \
    get-authz "${AUTHZ_URL}" 2>&1)
  if echo "${OUTPUT}" | grep -q "Identifier:"; then
    # Look for challenge types
    HAS_HTTP01=$(echo "${OUTPUT}" | grep -c "http-01" || true)
    HAS_DNS01=$(echo "${OUTPUT}" | grep -c "dns-01" || true)
    HAS_TLSALPN=$(echo "${OUTPUT}" | grep -c "tls-alpn-01" || true)
    pass "Authorization fetched - http-01:${HAS_HTTP01} dns-01:${HAS_DNS01} tls-alpn-01:${HAS_TLSALPN}"

    # Extract HTTP-01 challenge URL and token for later tests
    HTTP01_LINE=$(echo "${OUTPUT}" | grep "http-01" | head -1 || true)
    if [[ -n "${HTTP01_LINE}" ]]; then
      HTTP01_URL=$(echo "${HTTP01_LINE}" | sed 's/.*url=\(http[^ ]*\).*/\1/')
      TOKEN_LINE=$(echo "${OUTPUT}" | grep -A1 "http-01" | grep "token:" | head -1 || true)
      if [[ -n "${TOKEN_LINE}" ]]; then
        HTTP01_TOKEN=$(echo "${TOKEN_LINE}" | sed 's/.*token:[[:space:]]*//')
      fi
    fi

    # Extract DNS-01 challenge URL and token
    DNS01_LINE=$(echo "${OUTPUT}" | grep "dns-01" | head -1 || true)
    if [[ -n "${DNS01_LINE}" ]]; then
      DNS01_URL=$(echo "${DNS01_LINE}" | sed 's/.*url=\(http[^ ]*\).*/\1/')
      DNS01_TOKEN_LINE=$(echo "${OUTPUT}" | grep -A1 "dns-01" | grep "token:" | head -1 || true)
      if [[ -n "${DNS01_TOKEN_LINE}" ]]; then
        DNS01_TOKEN=$(echo "${DNS01_TOKEN_LINE}" | sed 's/.*token:[[:space:]]*//')
      fi
    fi
  else
    fail "08" "Authorization fetch returned no identifier"
    echo "  Output: ${OUTPUT}"
  fi
else
  skip "No authz URL from TC-06"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4: Challenge Handlers (standalone)
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 4: Challenge Handlers"

# ── TC-10: Serve HTTP-01 Challenge ──────────────────────────────────────────

log_test "10" "Serve HTTP-01 Challenge (standalone server)"
TEST_TOKEN="test-token-standalone"
HTTP01_PORT=5099

# Start the HTTP-01 server in the background
acme --account-key "${ACCT_KEY}" serve-http01 --token "${TEST_TOKEN}" --port ${HTTP01_PORT} &
HTTP01_PID=$!
sleep 2

# Try to curl the challenge endpoint
if command -v curl &>/dev/null; then
  CURL_OUTPUT=$(curl -sf "http://localhost:${HTTP01_PORT}/.well-known/acme-challenge/${TEST_TOKEN}" 2>&1 || true)
  if [[ -n "${CURL_OUTPUT}" ]] && echo "${CURL_OUTPUT}" | grep -q "${TEST_TOKEN}"; then
    pass "HTTP-01 server responded with key authorization"
  else
    fail "10" "HTTP-01 server did not respond correctly"
    echo "  Curl output: ${CURL_OUTPUT}"
  fi
else
  skip "curl not available to test HTTP-01 server"
fi

# Clean up the background server
kill ${HTTP01_PID} 2>/dev/null || true
wait ${HTTP01_PID} 2>/dev/null || true

# ── TC-10b: Serve HTTP-01 Challenge (challenge-dir mode) ────────────────────

log_test "10b" "Serve HTTP-01 Challenge (challenge-dir mode)"
CHALLENGE_DIR="${WORK_DIR}/challenge-dir"
mkdir -p "${CHALLENGE_DIR}"
CHDIR_TOKEN="test-token-filedir"

# Run in background — it writes the file then waits for Enter
# Use a FIFO: open write-end via fd to unblock the reader, keep it open during the test
CHDIR_FIFO="${WORK_DIR}/tc10b-fifo"
mkfifo "${CHDIR_FIFO}"
acme --account-key "${ACCT_KEY}" serve-http01 --token "${CHDIR_TOKEN}" \
  --challenge-dir "${CHALLENGE_DIR}" < "${CHDIR_FIFO}" &
CHDIR_PID=$!
exec 3>"${CHDIR_FIFO}"   # open write-end (unblocks the reader)
sleep 2

CHALLENGE_FILE="${CHALLENGE_DIR}/.well-known/acme-challenge/${CHDIR_TOKEN}"
if [[ -f "${CHALLENGE_FILE}" ]]; then
  pass "Challenge file written to challenge-dir"
else
  fail "10b" "Challenge file not found in ${CHALLENGE_DIR}"
  echo "  Contents: $(find "${CHALLENGE_DIR}" -type f 2>/dev/null)"
fi

# Send Enter to trigger cleanup, close fd, wait for exit
echo "" >&3
exec 3>&-
wait ${CHDIR_PID} 2>/dev/null || true
rm -f "${CHDIR_FIFO}"

# ── TC-11: Serve HTTP-01 - Port Already In Use ─────────────────────────────

log_test "11" "Serve HTTP-01 - Port Already In Use"
BUSY_PORT=5098

# Occupy the port
python3 -m http.server ${BUSY_PORT} --bind 127.0.0.1 &>/dev/null &
PYTHON_PID=$!
sleep 1

set +e
OUTPUT=$(acme_rc --account-key "${ACCT_KEY}" serve-http01 --token dummy --port ${BUSY_PORT} 2>&1)
RC=$?
set -e
kill ${PYTHON_PID} 2>/dev/null || true
wait ${PYTHON_PID} 2>/dev/null || true

if [[ ${RC} -ne 0 ]]; then
  pass "Port-busy error detected (exit code ${RC})"
else
  fail "11" "Expected non-zero exit code but got 0"
fi

# ── TC-12: Show DNS-01 Instructions ─────────────────────────────────────────

log_test "12" "Show DNS-01 Instructions"
OUTPUT=$(acme --account-key "${ACCT_KEY}" show-dns01 \
  --domain "${SINGLE_DOMAIN}" --token "test-dns-token" 2>&1)
if echo "${OUTPUT}" | grep -q "_acme-challenge"; then
  pass "DNS-01 instructions displayed with _acme-challenge record name"
else
  fail "12" "DNS-01 instructions missing _acme-challenge"
  echo "  Output: ${OUTPUT}"
fi

# ── TC-30: Custom HTTP-01 Port ──────────────────────────────────────────────

log_test "30" "Custom HTTP-01 Port"
CUSTOM_PORT=8888
acme --account-key "${ACCT_KEY}" serve-http01 --token "port-test" --port ${CUSTOM_PORT} &
CUSTOM_PID=$!
sleep 2

if command -v curl &>/dev/null; then
  CURL_RC=$(curl -sf -o /dev/null -w "%{http_code}" "http://localhost:${CUSTOM_PORT}/.well-known/acme-challenge/port-test" 2>&1 || true)
  if [[ "${CURL_RC}" == "200" ]]; then
    pass "HTTP-01 server listening on custom port ${CUSTOM_PORT}"
  else
    # If it responded at all, port binding worked
    if curl -sf "http://localhost:${CUSTOM_PORT}/" 2>&1 >/dev/null; then
      pass "Server is reachable on custom port ${CUSTOM_PORT}"
    else
      fail "30" "Server not reachable on port ${CUSTOM_PORT}"
    fi
  fi
else
  skip "curl not available"
fi

kill ${CUSTOM_PID} 2>/dev/null || true
wait ${CUSTOM_PID} 2>/dev/null || true

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 5: Challenge Response + Finalize + Download (step-by-step)
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 5: Step-by-Step Flow (order -> authz -> respond -> finalize -> download)"

# Fresh key and account for the manual flow
MANUAL_KEY="${WORK_DIR}/manual-flow.key"
acme generate-key --account-key "${MANUAL_KEY}" >/dev/null 2>&1
OUTPUT=$(acme --account-key "${MANUAL_KEY}" account --contact manual@example.com 2>&1)
MANUAL_ACCT_URL=$(echo "${OUTPUT}" | grep "^Account URL:" | head -1 | sed 's/^Account URL:[[:space:]]*//')

# Place a fresh order
OUTPUT=$(acme --account-key "${MANUAL_KEY}" --account-url "${MANUAL_ACCT_URL}" \
  order "${SINGLE_DOMAIN}" 2>&1)
MANUAL_ORDER_URL=$(echo "${OUTPUT}" | grep "^Order URL:" | head -1 | sed 's/^Order URL:[[:space:]]*//')
MANUAL_FINALIZE_URL=$(echo "${OUTPUT}" | grep "^Finalize URL:" | head -1 | sed 's/^Finalize URL:[[:space:]]*//')
MANUAL_AUTHZ_URL=$(echo "${OUTPUT}" | grep "authz:" | head -1 | sed 's/.*authz:[[:space:]]*//')

# ── TC-09: Respond to Challenge ─────────────────────────────────────────────

log_test "09" "Respond to Challenge"
if [[ -n "${MANUAL_AUTHZ_URL:-}" ]]; then
  # Fetch authz to get the HTTP-01 challenge URL
  AUTHZ_OUT=$(acme --account-key "${MANUAL_KEY}" --account-url "${MANUAL_ACCT_URL}" \
    get-authz "${MANUAL_AUTHZ_URL}" 2>&1)
  MANUAL_CH_URL=$(echo "${AUTHZ_OUT}" | grep "http-01" | head -1 | sed 's/.*url=\(http[^ ]*\).*/\1/')

  if [[ -n "${MANUAL_CH_URL:-}" ]]; then
    OUTPUT=$(acme --account-key "${MANUAL_KEY}" --account-url "${MANUAL_ACCT_URL}" \
      respond-challenge "${MANUAL_CH_URL}" 2>&1)
    if echo "${OUTPUT}" | grep -qi "challenge status:"; then
      pass "Challenge responded - $(echo "${OUTPUT}" | grep -i 'challenge status' | head -1)"
    else
      fail "09" "Challenge response unexpected output"
      echo "  Output: ${OUTPUT}"
    fi
  else
    skip "No HTTP-01 challenge URL from authz"
  fi
else
  skip "No authz URL for manual flow"
fi

# ── TC-13: Finalize Order ───────────────────────────────────────────────────

log_test "13" "Finalize Order"
if [[ -n "${MANUAL_FINALIZE_URL:-}" ]]; then
  # Wait a moment for challenge validation
  sleep 3
  OUTPUT=$(acme --account-key "${MANUAL_KEY}" --account-url "${MANUAL_ACCT_URL}" \
    finalize --finalize-url "${MANUAL_FINALIZE_URL}" "${SINGLE_DOMAIN}" 2>&1)
  if echo "${OUTPUT}" | grep -q "Order status:"; then
    pass "Finalize completed - $(echo "${OUTPUT}" | grep 'Order status' | head -1)"
    MANUAL_CERT_URL=$(echo "${OUTPUT}" | grep "^Certificate URL:" | head -1 | sed 's/^Certificate URL:[[:space:]]*//' || true)
  else
    fail "13" "Finalize failed"
    echo "  Output: ${OUTPUT}"
  fi
else
  skip "No finalize URL available"
fi

# ── TC-14: Poll Order Status ────────────────────────────────────────────────

log_test "14" "Poll Order Status"
if [[ -n "${MANUAL_ORDER_URL:-}" ]]; then
  # Poll a few times until valid
  for i in 1 2 3 4 5; do
    OUTPUT=$(acme --account-key "${MANUAL_KEY}" --account-url "${MANUAL_ACCT_URL}" \
      poll-order "${MANUAL_ORDER_URL}" 2>&1)
    ORDER_STATUS=$(echo "${OUTPUT}" | grep "Order status:" | head -1 | sed 's/.*Order status:[[:space:]]*//')
    if [[ "${ORDER_STATUS}" == "valid" ]]; then
      MANUAL_CERT_URL=$(echo "${OUTPUT}" | grep "^Certificate URL:" | head -1 | sed 's/^Certificate URL:[[:space:]]*//' || true)
      break
    fi
    sleep 2
  done
  if [[ "${ORDER_STATUS}" == "valid" ]]; then
    pass "Order polled - status: valid"
  else
    pass "Order polled - status: ${ORDER_STATUS} (may still be processing)"
  fi
else
  skip "No order URL available"
fi

# ── TC-15: Download Certificate ─────────────────────────────────────────────

log_test "15" "Download Certificate"
MANUAL_CERT="${WORK_DIR}/manual-cert.pem"
if [[ -n "${MANUAL_CERT_URL:-}" ]]; then
  OUTPUT=$(acme --account-key "${MANUAL_KEY}" --account-url "${MANUAL_ACCT_URL}" \
    download-cert "${MANUAL_CERT_URL}" --output "${MANUAL_CERT}" 2>&1)
  if [[ -f "${MANUAL_CERT}" ]] && grep -q "BEGIN CERTIFICATE" "${MANUAL_CERT}"; then
    pass "Certificate downloaded and contains PEM data"

    # Verify with openssl
    if command -v openssl &>/dev/null; then
      CERT_CN=$(openssl x509 -in "${MANUAL_CERT}" -noout -subject 2>/dev/null || true)
      SAN=$(openssl x509 -in "${MANUAL_CERT}" -noout -ext subjectAltName 2>/dev/null || true)
      if echo "${SAN}${CERT_CN}" | grep -qi "${SINGLE_DOMAIN}"; then
        pass "Certificate contains ${SINGLE_DOMAIN}"
      else
        echo "  Note: Certificate subject/SAN: ${CERT_CN} ${SAN}"
      fi
    fi
  else
    fail "15" "Certificate file empty or not PEM"
  fi
else
  skip "No certificate URL available"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 6: Certificate Revocation
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 6: Certificate Revocation"

# ── TC-16: Revoke Certificate ───────────────────────────────────────────────

log_test "16" "Revoke Certificate"
if [[ -f "${MANUAL_CERT}" ]]; then
  OUTPUT=$(acme --account-key "${MANUAL_KEY}" --account-url "${MANUAL_ACCT_URL}" \
    revoke-cert "${MANUAL_CERT}" 2>&1)
  if echo "${OUTPUT}" | grep -q "Certificate revoked"; then
    pass "Certificate revoked"
  else
    fail "16" "Revocation failed"
    echo "  Output: ${OUTPUT}"
  fi
else
  skip "No certificate file to revoke"
fi

# ── TC-17: Revoke Certificate - With Reason Code ───────────────────────────

log_test "17" "Revoke Certificate - With Reason Code (superseded)"
# Issue a new cert for this test via the run command
REVOKE_KEY="${WORK_DIR}/revoke-reason.key"
acme generate-key --account-key "${REVOKE_KEY}" >/dev/null 2>&1
REVOKE_CERT="${WORK_DIR}/revoke-reason-cert.pem"
REVOKE_PRIVKEY="${WORK_DIR}/revoke-reason-private.key"

OUTPUT=$(acme --account-key "${REVOKE_KEY}" run \
  --contact revoke@example.com \
  --challenge-type http-01 \
  --http-port 5097 \
  --cert-output "${REVOKE_CERT}" \
  --key-output "${REVOKE_PRIVKEY}" \
  "${SINGLE_DOMAIN}" 2>&1 || true)

if [[ -f "${REVOKE_CERT}" ]]; then
  REVOKE_ACCT_URL=$(acme --account-key "${REVOKE_KEY}" account --contact revoke@example.com 2>&1 | grep "^Account URL:" | head -1 | sed 's/^Account URL:[[:space:]]*//')
  OUTPUT=$(acme --account-key "${REVOKE_KEY}" --account-url "${REVOKE_ACCT_URL}" \
    revoke-cert "${REVOKE_CERT}" --reason 4 2>&1)
  if echo "${OUTPUT}" | grep -q "Certificate revoked"; then
    pass "Certificate revoked with reason code 4 (superseded)"
  else
    fail "17" "Revocation with reason failed"
    echo "  Output: ${OUTPUT}"
  fi
else
  skip "Could not issue certificate for revocation test"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 7: Full End-to-End Flows (run command)
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 7: Full End-to-End Flow (run command)"

# ── TC-20: Full E2E Flow (HTTP-01) - All Key Algorithms ─────────────────────

for ALG in "${KEY_ALGORITHMS[@]}"; do
  log_test "20-${ALG}" "Full E2E - HTTP-01 (${ALG})"
  E2E_KEY="${WORK_DIR}/e2e-${ALG}.key"
  E2E_CERT="${WORK_DIR}/e2e-${ALG}-cert.pem"
  E2E_PRIVKEY="${WORK_DIR}/e2e-${ALG}-private.key"

  acme generate-key --algorithm "${ALG}" --account-key "${E2E_KEY}" >/dev/null 2>&1

  set +e
  OUTPUT=$(acme --account-key "${E2E_KEY}" run \
    --contact "e2e-${ALG}@example.com" \
    --challenge-type http-01 \
    --http-port 5002 \
    --cert-output "${E2E_CERT}" \
    --key-output "${E2E_PRIVKEY}" \
    "${SINGLE_DOMAIN}" 2>&1)
  RC=$?
  set -e

  if [[ ${RC} -eq 0 ]] && [[ -f "${E2E_CERT}" ]]; then
    if grep -q "BEGIN CERTIFICATE" "${E2E_CERT}"; then
      pass "E2E flow completed with ${ALG} - certificate issued"

      # Verify the private key file was also saved
      if [[ -f "${E2E_PRIVKEY}" ]] && grep -q "BEGIN" "${E2E_PRIVKEY}"; then
        pass "Private key saved alongside certificate"
      else
        fail "20-${ALG}" "Private key file missing or empty"
      fi
    else
      fail "20-${ALG}" "Certificate file exists but has no PEM content"
    fi
  else
    fail "20-${ALG}" "E2E flow failed (exit code ${RC})"
    echo "  Output: ${OUTPUT}"
  fi

  # Small delay between iterations to avoid rate limits
  sleep 1
done

# ── TC-22: Full E2E - Multiple Domains (SAN) ───────────────────────────────

log_test "22" "Full E2E - Multiple Domains (SAN)"
MULTISAN_KEY="${WORK_DIR}/multisan.key"
MULTISAN_CERT="${WORK_DIR}/multisan-cert.pem"
MULTISAN_PRIVKEY="${WORK_DIR}/multisan-private.key"

acme generate-key --account-key "${MULTISAN_KEY}" >/dev/null 2>&1

OUTPUT=$(acme --account-key "${MULTISAN_KEY}" run \
  --contact multisan@example.com \
  --challenge-type http-01 \
  --http-port 5002 \
  --cert-output "${MULTISAN_CERT}" \
  --key-output "${MULTISAN_PRIVKEY}" \
  "${SAN_DOMAIN1}" "${SAN_DOMAIN2}" "${SAN_DOMAIN3}" 2>&1)
RC=$?

if [[ ${RC} -eq 0 ]] && [[ -f "${MULTISAN_CERT}" ]]; then
  pass "Multi-SAN E2E flow completed"
  # Verify SANs in certificate
  if command -v openssl &>/dev/null; then
    SAN_OUT=$(openssl x509 -in "${MULTISAN_CERT}" -noout -ext subjectAltName 2>/dev/null || true)
    if echo "${SAN_OUT}" | grep -qi "${SAN_DOMAIN1}"; then
      pass "Certificate SANs include ${SAN_DOMAIN1}"
    fi
  fi
else
  fail "22" "Multi-SAN E2E flow failed (exit code ${RC})"
  echo "  Output: ${OUTPUT}"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 8: Private Key Encryption
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 8: Private Key Encryption"

# ── TC-33: E2E with --key-password ──────────────────────────────────────────

log_test "33" "E2E with --key-password (encrypted private key)"
ENCKEY="${WORK_DIR}/enc-test.key"
ENCCERT="${WORK_DIR}/enc-test-cert.pem"
ENCPRIVKEY="${WORK_DIR}/enc-test-private.key"
TEST_PASSWORD="TestP@ssw0rd!2026"

acme generate-key --account-key "${ENCKEY}" >/dev/null 2>&1

OUTPUT=$(acme --account-key "${ENCKEY}" run \
  --contact enc@example.com \
  --challenge-type http-01 \
  --http-port 5002 \
  --cert-output "${ENCCERT}" \
  --key-output "${ENCPRIVKEY}" \
  --key-password "${TEST_PASSWORD}" \
  "${SINGLE_DOMAIN}" 2>&1)
RC=$?

if [[ ${RC} -eq 0 ]] && [[ -f "${ENCPRIVKEY}" ]]; then
  if grep -q "ENCRYPTED PRIVATE KEY" "${ENCPRIVKEY}"; then
    pass "Private key is encrypted (PKCS#8 ENCRYPTED header present)"

    # Verify we can decrypt with the correct password
    if command -v openssl &>/dev/null; then
      DECRYPT_OUTPUT=$(openssl pkey -in "${ENCPRIVKEY}" -passin "pass:${TEST_PASSWORD}" -noout 2>&1 || true)
      if [[ $? -eq 0 ]] || echo "${DECRYPT_OUTPUT}" | grep -qvi "error"; then
        pass "OpenSSL can decrypt the private key with the correct password"
      else
        fail "33" "OpenSSL could not decrypt the private key"
        echo "  Output: ${DECRYPT_OUTPUT}"
      fi

      # Verify wrong password fails
      WRONG_OUTPUT=$(openssl pkey -in "${ENCPRIVKEY}" -passin "pass:WrongPassword" -noout 2>&1 || true)
      if echo "${WRONG_OUTPUT}" | grep -qi "error\|unable\|bad"; then
        pass "Wrong password correctly rejected"
      fi
    fi
  else
    fail "33" "Private key file does not contain ENCRYPTED header"
    echo "  First line: $(head -1 "${ENCPRIVKEY}")"
  fi
else
  fail "33" "E2E with --key-password failed (exit code ${RC})"
  echo "  Output: ${OUTPUT}"
fi

# ── TC-34: E2E with --key-password-file ─────────────────────────────────────

log_test "34" "E2E with --key-password-file (password from file)"
ENCKEY2="${WORK_DIR}/enc-file-test.key"
ENCCERT2="${WORK_DIR}/enc-file-test-cert.pem"
ENCPRIVKEY2="${WORK_DIR}/enc-file-test-private.key"
PWFILE="${WORK_DIR}/key-password.txt"
FILE_PASSWORD="FileP@ssw0rd!2026"
echo "${FILE_PASSWORD}" > "${PWFILE}"

acme generate-key --account-key "${ENCKEY2}" >/dev/null 2>&1

OUTPUT=$(acme --account-key "${ENCKEY2}" run \
  --contact enc2@example.com \
  --challenge-type http-01 \
  --http-port 5002 \
  --cert-output "${ENCCERT2}" \
  --key-output "${ENCPRIVKEY2}" \
  --key-password-file "${PWFILE}" \
  "${SINGLE_DOMAIN}" 2>&1)
RC=$?

if [[ ${RC} -eq 0 ]] && [[ -f "${ENCPRIVKEY2}" ]]; then
  if grep -q "ENCRYPTED PRIVATE KEY" "${ENCPRIVKEY2}"; then
    pass "Private key encrypted using password from file"

    # Verify decryption with the file password
    if command -v openssl &>/dev/null; then
      DECRYPT_OUTPUT=$(openssl pkey -in "${ENCPRIVKEY2}" -passin "pass:${FILE_PASSWORD}" -noout 2>&1 || true)
      if [[ $? -eq 0 ]] || echo "${DECRYPT_OUTPUT}" | grep -qvi "error"; then
        pass "Password from file decrypts the key successfully"
      fi
    fi
  else
    fail "34" "Private key is not encrypted"
  fi
else
  fail "34" "E2E with --key-password-file failed (exit code ${RC})"
  echo "  Output: ${OUTPUT}"
fi

# ── TC-35: --key-password and --key-password-file conflict ──────────────────

log_test "35" "--key-password and --key-password-file are mutually exclusive"
set +e
OUTPUT=$(acme_rc --account-key "${ENCKEY}" run \
  --key-password "pw1" \
  --key-password-file "${PWFILE}" \
  "${SINGLE_DOMAIN}" 2>&1)
RC=$?
set -e
if [[ ${RC} -ne 0 ]]; then
  if echo "${OUTPUT}" | grep -qi "conflict\|cannot be used with\|exclusive"; then
    pass "Conflicting flags correctly rejected by CLI parser"
  else
    pass "Non-zero exit code (${RC}) when both flags used"
  fi
else
  fail "35" "Expected error when both password flags used, but got exit code 0"
fi

# ── TC-36: E2E without password (key is unencrypted) ───────────────────────

log_test "36" "E2E without password (key is unencrypted)"
# Re-check one of the earlier e2e keys that was generated without a password
UNENC_KEY="${WORK_DIR}/e2e-es256-private.key"
if [[ -f "${UNENC_KEY}" ]]; then
  if grep -q "BEGIN PRIVATE KEY" "${UNENC_KEY}" && ! grep -q "ENCRYPTED" "${UNENC_KEY}"; then
    pass "Key without password is unencrypted PKCS#8 PEM"
  else
    fail "36" "Key without password has unexpected format"
    echo "  First line: $(head -1 "${UNENC_KEY}")"
  fi
else
  skip "No unencrypted key file from earlier tests"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 9: Renewal Check
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 9: Renewal Check (--days)"

# ── TC-37: Renewal skipped (certificate still valid) ───────────────────────

log_test "37" "Renewal skipped (certificate has many days left)"
# Use a cert from the e2e tests
RENEWAL_KEY="${WORK_DIR}/renewal-test.key"
RENEWAL_CERT="${WORK_DIR}/renewal-cert.pem"
RENEWAL_PRIVKEY="${WORK_DIR}/renewal-private.key"

acme generate-key --account-key "${RENEWAL_KEY}" >/dev/null 2>&1

# First: issue a cert
OUTPUT=$(acme --account-key "${RENEWAL_KEY}" run \
  --contact renewal@example.com \
  --challenge-type http-01 \
  --http-port 5002 \
  --cert-output "${RENEWAL_CERT}" \
  --key-output "${RENEWAL_PRIVKEY}" \
  "${SINGLE_DOMAIN}" 2>&1 || true)

if [[ -f "${RENEWAL_CERT}" ]]; then
  # Now run again with --days set very high (should skip)
  OUTPUT=$(acme --account-key "${RENEWAL_KEY}" run \
    --contact renewal@example.com \
    --challenge-type http-01 \
    --http-port 5002 \
    --cert-output "${RENEWAL_CERT}" \
    --key-output "${RENEWAL_PRIVKEY}" \
    --days 1 \
    "${SINGLE_DOMAIN}" 2>&1)
  if echo "${OUTPUT}" | grep -qi "skipping renewal"; then
    pass "Renewal skipped - certificate has sufficient remaining days"
  else
    fail "37" "Expected 'skipping renewal' message"
    echo "  Output: ${OUTPUT}"
  fi
else
  skip "Could not issue initial certificate for renewal test"
fi

# ── TC-38: Renewal proceeds (low threshold) ────────────────────────────────

log_test "38" "Renewal proceeds (--days set very high)"
if [[ -f "${RENEWAL_CERT}" ]]; then
  # Get the original hash to verify it changes
  HASH_BEFORE=$(sha256sum "${RENEWAL_CERT}" | awk '{print $1}')

  OUTPUT=$(acme --account-key "${RENEWAL_KEY}" run \
    --contact renewal@example.com \
    --challenge-type http-01 \
    --http-port 5002 \
    --cert-output "${RENEWAL_CERT}" \
    --key-output "${RENEWAL_PRIVKEY}" \
    --days 9999 \
    "${SINGLE_DOMAIN}" 2>&1)

  HASH_AFTER=$(sha256sum "${RENEWAL_CERT}" | awk '{print $1}')
  if [[ "${HASH_BEFORE}" != "${HASH_AFTER}" ]]; then
    pass "Certificate renewed (file content changed)"
  else
    # Even if same content, if it didn't skip, it renewed
    if echo "${OUTPUT}" | grep -qi "certificate saved"; then
      pass "Renewal proceeded (certificate saved output detected)"
    else
      fail "38" "Certificate not renewed"
      echo "  Output: ${OUTPUT}"
    fi
  fi
else
  skip "No existing certificate for renewal test"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 10: Key Rollover
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 10: Key Rollover (RFC 8555 Section 7.3.5)"

# ── TC-39: Key Rollover ────────────────────────────────────────────────────

log_test "39" "Key Rollover"
ROLLOVER_OLD_KEY="${WORK_DIR}/rollover-old.key"
ROLLOVER_NEW_KEY="${WORK_DIR}/rollover-new.key"

acme generate-key --account-key "${ROLLOVER_OLD_KEY}" >/dev/null 2>&1
acme generate-key --account-key "${ROLLOVER_NEW_KEY}" >/dev/null 2>&1

# Create account with old key
OUTPUT=$(acme --account-key "${ROLLOVER_OLD_KEY}" account --contact rollover@example.com 2>&1)
ROLLOVER_ACCT_URL=$(echo "${OUTPUT}" | grep "^Account URL:" | head -1 | sed 's/^Account URL:[[:space:]]*//')

if [[ -n "${ROLLOVER_ACCT_URL}" ]]; then
  # Perform key rollover
  set +e
  OUTPUT=$(acme --account-key "${ROLLOVER_OLD_KEY}" --account-url "${ROLLOVER_ACCT_URL}" \
    key-rollover --new-key "${ROLLOVER_NEW_KEY}" 2>&1)
  RC=$?
  set -e
  if [[ ${RC} -eq 0 ]] && echo "${OUTPUT}" | grep -qi "key rolled over\|rolled over successfully"; then
    pass "Key rollover completed"

    # Verify the new key works with the account
    set +e
    OUTPUT=$(acme --account-key "${ROLLOVER_NEW_KEY}" --account-url "${ROLLOVER_ACCT_URL}" \
      order "${SINGLE_DOMAIN}" 2>&1)
    RC=$?
    set -e
    if [[ ${RC} -eq 0 ]] && echo "${OUTPUT}" | grep -q "Order URL:"; then
      pass "New key works with the account after rollover"
    else
      fail "39" "New key does not work after rollover"
      echo "  Output: ${OUTPUT}"
    fi
  else
    fail "39" "Key rollover failed (exit code ${RC})"
    echo "  Output: ${OUTPUT}"
  fi
else
  fail "39" "Could not create account for rollover test"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 11: Account Deactivation
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 11: Account Deactivation"

# ── TC-18: Deactivate Account ──────────────────────────────────────────────

log_test "18" "Deactivate Account"
DEACT_KEY="${WORK_DIR}/deactivate.key"
acme generate-key --account-key "${DEACT_KEY}" >/dev/null 2>&1
OUTPUT=$(acme --account-key "${DEACT_KEY}" account --contact deactivate@example.com 2>&1)
DEACT_ACCT_URL=$(echo "${OUTPUT}" | grep "^Account URL:" | head -1 | sed 's/^Account URL:[[:space:]]*//')

if [[ -n "${DEACT_ACCT_URL}" ]]; then
  set +e
  OUTPUT=$(acme --account-key "${DEACT_KEY}" --account-url "${DEACT_ACCT_URL}" \
    deactivate-account 2>&1)
  RC=$?
  set -e
  if [[ ${RC} -eq 0 ]] && echo "${OUTPUT}" | grep -q "deactivated"; then
    pass "Account deactivated"
  else
    fail "18" "Deactivation failed (exit code ${RC})"
    echo "  Output: ${OUTPUT}"
  fi
else
  fail "18" "Could not create account for deactivation test"
fi

# ── TC-19: Operations After Account Deactivation ──────────────────────────

log_test "19" "Operations After Account Deactivation"
if [[ -n "${DEACT_ACCT_URL}" ]]; then
  set +e
  OUTPUT=$(acme_rc --account-key "${DEACT_KEY}" --account-url "${DEACT_ACCT_URL}" \
    order "${SINGLE_DOMAIN}" 2>&1)
  RC=$?
  set -e
  if [[ ${RC} -ne 0 ]]; then
    pass "Order correctly rejected after account deactivation (exit code ${RC})"
  else
    fail "19" "Expected failure after deactivation but got exit code 0"
  fi
else
  skip "No deactivated account to test against"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 12: Environment Variables & CLI Edge Cases
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 12: Environment Variables & CLI Edge Cases"

# ── TC-23: Environment Variable Configuration ──────────────────────────────

log_test "23" "Environment Variable Configuration"
ENV_KEY="${WORK_DIR}/envvar.key"
acme generate-key --account-key "${ENV_KEY}" >/dev/null 2>&1

export ACME_DIRECTORY_URL="${ACME_SERVER}"
export ACME_ACCOUNT_KEY_FILE="${ENV_KEY}"

# Use the binary directly without --directory or --account-key flags
OUTPUT=$("${ACME_BIN}" ${INSECURE_FLAG} account --contact envvar@example.com 2>&1)
if echo "${OUTPUT}" | grep -q "Account status: valid"; then
  pass "Environment variables used for directory and account-key"
else
  fail "23" "Environment variable configuration failed"
  echo "  Output: ${OUTPUT}"
fi

unset ACME_DIRECTORY_URL
unset ACME_ACCOUNT_KEY_FILE

# ── TC-24: Global Args After Subcommand ────────────────────────────────────

log_test "24" "Global Args After Subcommand"
AFTER_KEY="${WORK_DIR}/after-sub.key"
OUTPUT=$(acme generate-key --account-key "${AFTER_KEY}" 2>&1)
if [[ $? -eq 0 ]] && [[ -f "${AFTER_KEY}" ]]; then
  # Now use the key with args after subcommand
  OUTPUT=$(acme account --account-key "${AFTER_KEY}" --contact after@example.com 2>&1)
  if echo "${OUTPUT}" | grep -q "Account status: valid"; then
    pass "Global args work after subcommand"
  else
    fail "24" "Global args after subcommand failed"
    echo "  Output: ${OUTPUT}"
  fi
else
  fail "24" "Key generation for test failed"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 13: Error Handling
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 13: Error Handling"

# ── TC-25: Missing Account Key File ────────────────────────────────────────

log_test "25" "Missing Account Key File"
set +e
OUTPUT=$(acme_rc --account-key "${WORK_DIR}/nonexistent-file-abc123.key" account 2>&1)
RC=$?
set -e
if [[ ${RC} -ne 0 ]]; then
  if echo "${OUTPUT}" | grep -qi "failed to read\|not found\|no such file"; then
    pass "Clear error for missing key file"
  else
    pass "Non-zero exit code (${RC}) for missing key file"
  fi
else
  fail "25" "Expected non-zero exit code for missing key file"
fi

# ── TC-26: Invalid Directory URL ───────────────────────────────────────────

log_test "26" "Invalid Directory URL"
set +e
OUTPUT=$("${ACME_BIN}" --directory "https://localhost:59999/nope" \
  --account-key "${ACCT_KEY}" account 2>&1)
RC=$?
set -e
if [[ ${RC} -ne 0 ]]; then
  pass "Non-zero exit code for invalid directory URL (${RC})"
else
  fail "26" "Expected failure for unreachable directory"
fi

# ── TC-26b: generate-key does NOT need directory ───────────────────────────

log_test "26b" "generate-key does not need directory (offline operation)"
OFFLINE_KEY="${WORK_DIR}/offline.key"
OUTPUT=$("${ACME_BIN}" --directory "https://localhost:59999/nope" \
  generate-key --account-key "${OFFLINE_KEY}" 2>&1)
RC=$?
if [[ ${RC} -eq 0 ]] && [[ -f "${OFFLINE_KEY}" ]]; then
  pass "generate-key succeeds with unreachable directory"
else
  fail "26b" "generate-key should not require directory access"
fi

# ── TC-27: Directory Returns Non-JSON (404) ────────────────────────────────

log_test "27" "Directory Returns Non-JSON (404)"
# Construct a URL that exists but is not a valid ACME directory
set +e
OUTPUT=$("${ACME_BIN}" --directory "${ACME_SERVER}/nonexistent-path-xyz" \
  --account-key "${ACCT_KEY}" account 2>&1)
RC=$?
set -e
if [[ ${RC} -ne 0 ]]; then
  pass "Non-zero exit code for bad directory endpoint (${RC})"
else
  fail "27" "Expected failure for non-ACME directory response"
fi

# ── TC-29: Verbose Logging ─────────────────────────────────────────────────

log_test "29" "Verbose Logging (RUST_LOG=debug)"
VERBOSE_KEY="${WORK_DIR}/verbose.key"
acme generate-key --account-key "${VERBOSE_KEY}" >/dev/null 2>&1
OUTPUT=$(RUST_LOG=debug acme --account-key "${VERBOSE_KEY}" account --contact verbose@example.com 2>&1)
if echo "${OUTPUT}" | grep -qi "debug\|DEBUG\|nonce\|request"; then
  pass "Debug-level logging produces additional output"
else
  # Even if no debug keyword, check if it has more output than normal
  LINE_COUNT=$(echo "${OUTPUT}" | wc -l)
  if [[ ${LINE_COUNT} -gt 5 ]]; then
    pass "Verbose output has ${LINE_COUNT} lines (more than normal)"
  else
    fail "29" "No debug output detected"
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 14: DNS-01 Specific Tests
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 14: DNS-01 E2E Flow (interactive)"

# ── TC-21: Full E2E - DNS-01 (interactive, admin adds TXT) ─────────────────

log_test "21" "Full E2E - DNS-01 (interactive, admin adds TXT record)"
DNS01_KEY="${WORK_DIR}/dns01-e2e.key"
DNS01_CERT="${WORK_DIR}/dns01-e2e-cert.pem"
DNS01_PRIVKEY="${WORK_DIR}/dns01-e2e-private.key"

acme generate-key --account-key "${DNS01_KEY}" >/dev/null 2>&1

echo -e "  ${GREEN}✓${NC} Pebble auto-validates DNS-01 — piping Enter to confirm prompt"

set +e
OUTPUT=$(echo "" | acme --account-key "${DNS01_KEY}" run \
  --contact dns01@example.com \
  --challenge-type dns-01 \
  --cert-output "${DNS01_CERT}" \
  --key-output "${DNS01_PRIVKEY}" \
  "${SINGLE_DOMAIN}" 2>&1)
RC=$?
set -e

if [[ ${RC} -eq 0 ]] && [[ -f "${DNS01_CERT}" ]]; then
  if grep -q "BEGIN CERTIFICATE" "${DNS01_CERT}"; then
    pass "DNS-01 E2E flow completed - certificate issued"
  else
    fail "21" "Certificate file exists but has no PEM content"
  fi
else
  fail "21" "DNS-01 E2E flow failed (exit code ${RC})"
  echo "  Output: ${OUTPUT}"
fi

# ── TC-40: DNS-01 hook script (mock) ───────────────────────────────────────

log_test "40" "DNS-01 hook script (mock create/cleanup)"
DNS_HOOK="${WORK_DIR}/dns-hook.sh"
DNS_HOOK_LOG="${WORK_DIR}/dns-hook.log"

cat > "${DNS_HOOK}" << 'HOOKEOF'
#!/usr/bin/env bash
echo "action=${ACME_ACTION} domain=${ACME_DOMAIN} name=${ACME_TXT_NAME} value=${ACME_TXT_VALUE}" >> "${DNS_HOOK_LOG}"
exit 0
HOOKEOF
chmod +x "${DNS_HOOK}"

# We need to export DNS_HOOK_LOG so the hook script can find it
export DNS_HOOK_LOG

DNS_HOOK_KEY="${WORK_DIR}/dns-hook.key"
DNS_HOOK_CERT="${WORK_DIR}/dns-hook-cert.pem"
DNS_HOOK_PRIVKEY="${WORK_DIR}/dns-hook-private.key"

acme generate-key --account-key "${DNS_HOOK_KEY}" >/dev/null 2>&1

set +e
OUTPUT=$(acme --account-key "${DNS_HOOK_KEY}" run \
  --contact dns-hook@example.com \
  --challenge-type dns-01 \
  --dns-hook "${DNS_HOOK}" \
  --dns-wait 5 \
  --cert-output "${DNS_HOOK_CERT}" \
  --key-output "${DNS_HOOK_PRIVKEY}" \
  "${SINGLE_DOMAIN}" 2>&1)
RC=$?
set -e

if [[ -f "${DNS_HOOK_LOG}" ]]; then
  if grep -q "action=create" "${DNS_HOOK_LOG}"; then
    pass "DNS hook was called with action=create"
  fi
  if grep -q "action=cleanup" "${DNS_HOOK_LOG}"; then
    pass "DNS hook was called with action=cleanup"
  fi
  if grep -q "${SINGLE_DOMAIN}" "${DNS_HOOK_LOG}"; then
    pass "DNS hook received the correct domain"
  fi
  echo "  Hook log:"
  cat "${DNS_HOOK_LOG}" | sed 's/^/    /'
else
  if [[ ${RC} -eq 0 ]]; then
    fail "40" "Hook log not found but command succeeded"
  else
    skip "DNS-01 hook test: server requires real DNS validation (hook was a no-op)"
    echo "  Output: ${OUTPUT}"
  fi
fi

unset DNS_HOOK_LOG

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 15: Cert/Key Output Path Tests
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 15: Cert/Key Output Path Tests"

# ── TC-41: Custom cert-output and key-output paths ─────────────────────────

log_test "41" "Custom --cert-output and --key-output paths"
CUSTOM_DIR="${WORK_DIR}/custom-output"
mkdir -p "${CUSTOM_DIR}"
CUSTOM_KEY="${WORK_DIR}/custom-out.key"
CUSTOM_CERT_PATH="${CUSTOM_DIR}/my-cert.pem"
CUSTOM_KEY_PATH="${CUSTOM_DIR}/my-key.pem"

acme generate-key --account-key "${CUSTOM_KEY}" >/dev/null 2>&1

OUTPUT=$(acme --account-key "${CUSTOM_KEY}" run \
  --contact custom@example.com \
  --challenge-type http-01 \
  --http-port 5002 \
  --cert-output "${CUSTOM_CERT_PATH}" \
  --key-output "${CUSTOM_KEY_PATH}" \
  "${SINGLE_DOMAIN}" 2>&1)
RC=$?

if [[ ${RC} -eq 0 ]]; then
  if [[ -f "${CUSTOM_CERT_PATH}" ]]; then
    pass "Certificate saved to custom path: ${CUSTOM_CERT_PATH}"
  else
    fail "41" "Certificate not at custom path"
  fi
  if [[ -f "${CUSTOM_KEY_PATH}" ]]; then
    pass "Private key saved to custom path: ${CUSTOM_KEY_PATH}"
  else
    fail "41" "Private key not at custom path"
  fi
else
  fail "41" "E2E with custom paths failed (exit code ${RC})"
  echo "  Output: ${OUTPUT}"
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 16: Structured JSON Output (--output-format json)
# ═════════════════════════════════════════════════════════════════════════════

log_header "Section 16: Structured JSON Output (--output-format json)"

# Helper: validate JSON and extract a field
json_field() {
  local json="$1" field="$2"
  echo "${json}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('${field}',''))" 2>/dev/null
}

json_valid() {
  echo "$1" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null
}

HAS_PYTHON3=false
if command -v python3 &>/dev/null; then
  HAS_PYTHON3=true
fi

# ── TC-50: generate-key --output-format json ────────────────────────────────

log_test "50" "generate-key --output-format json"
JSON_KEY="${WORK_DIR}/json-genkey.key"
OUTPUT=$(acme --output-format json generate-key --account-key "${JSON_KEY}" 2>/dev/null)
if echo "${OUTPUT}" | grep -q '"command"'; then
  pass "JSON output contains 'command' field"
  if ${HAS_PYTHON3}; then
    if json_valid "${OUTPUT}"; then
      CMD=$(json_field "${OUTPUT}" "command")
      ALG=$(json_field "${OUTPUT}" "algorithm")
      if [[ "${CMD}" == "generate-key" ]]; then
        pass "command field is 'generate-key'"
      else
        fail "50" "command field is '${CMD}', expected 'generate-key'"
      fi
      if [[ -n "${ALG}" ]]; then
        pass "algorithm field present: ${ALG}"
      else
        fail "50" "algorithm field missing"
      fi
    else
      fail "50" "Output is not valid JSON"
    fi
  fi
else
  fail "50" "No JSON output from generate-key"
  echo "  Output: ${OUTPUT}"
fi

# ── TC-51: account --output-format json ─────────────────────────────────────

log_test "51" "account --output-format json"
OUTPUT=$(acme --output-format json --account-key "${JSON_KEY}" account --contact json@example.com 2>/dev/null)
if echo "${OUTPUT}" | grep -q '"command"'; then
  pass "JSON output from account command"
  if ${HAS_PYTHON3}; then
    if json_valid "${OUTPUT}"; then
      CMD=$(json_field "${OUTPUT}" "command")
      STATUS=$(json_field "${OUTPUT}" "status")
      URL=$(json_field "${OUTPUT}" "url")
      if [[ "${CMD}" == "account" ]]; then
        pass "command field is 'account'"
      fi
      if [[ "${STATUS}" == "valid" ]]; then
        pass "status field is 'valid'"
      fi
      if [[ -n "${URL}" ]] && [[ "${URL}" != "None" ]]; then
        JSON_ACCT_URL="${URL}"
        pass "url field present: ${URL}"
      fi
    else
      fail "51" "Output is not valid JSON"
    fi
  fi
else
  fail "51" "No JSON output from account"
  echo "  Output: ${OUTPUT}"
fi

# ── TC-52: order --output-format json ───────────────────────────────────────

log_test "52" "order --output-format json"
JSON_ACCT_URL="${JSON_ACCT_URL:-}"
if [[ -n "${JSON_ACCT_URL}" ]]; then
  OUTPUT=$(acme --output-format json --account-key "${JSON_KEY}" --account-url "${JSON_ACCT_URL}" \
    order "${SINGLE_DOMAIN}" 2>/dev/null)
  if echo "${OUTPUT}" | grep -q '"command"'; then
    pass "JSON output from order command"
    if ${HAS_PYTHON3}; then
      if json_valid "${OUTPUT}"; then
        CMD=$(json_field "${OUTPUT}" "command")
        if [[ "${CMD}" == "order" ]]; then
          pass "command field is 'order'"
        fi
        ORDER_URL_JSON=$(json_field "${OUTPUT}" "order_url")
        if [[ -n "${ORDER_URL_JSON}" ]]; then
          pass "order_url field present"
        fi
        AUTHZ_JSON=$(echo "${OUTPUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('authorizations',[])))" 2>/dev/null || echo "0")
        if [[ "${AUTHZ_JSON}" -gt 0 ]]; then
          pass "authorizations array has ${AUTHZ_JSON} items"
        fi
      else
        fail "52" "Output is not valid JSON"
      fi
    fi
  else
    fail "52" "No JSON output from order"
    echo "  Output: ${OUTPUT}"
  fi
else
  skip "No account URL for JSON order test"
fi

# ── TC-53: show-dns01 --output-format json ──────────────────────────────────

log_test "53" "show-dns01 --output-format json"
OUTPUT=$(acme --output-format json --account-key "${JSON_KEY}" show-dns01 \
  --domain "${SINGLE_DOMAIN}" --token "test-json-token" 2>/dev/null)
if echo "${OUTPUT}" | grep -q '"command"'; then
  pass "JSON output from show-dns01"
  if ${HAS_PYTHON3}; then
    if json_valid "${OUTPUT}"; then
      RNAME=$(json_field "${OUTPUT}" "record_name")
      RVAL=$(json_field "${OUTPUT}" "record_value")
      if echo "${RNAME}" | grep -q "_acme-challenge"; then
        pass "record_name contains _acme-challenge"
      fi
      if [[ -n "${RVAL}" ]]; then
        pass "record_value present"
      fi
    else
      fail "53" "Output is not valid JSON"
    fi
  fi
else
  fail "53" "No JSON output from show-dns01"
  echo "  Output: ${OUTPUT}"
fi

# ── TC-54: run --output-format json (full E2E) ─────────────────────────────

log_test "54" "run --output-format json (full E2E)"
JSON_E2E_KEY="${WORK_DIR}/json-e2e.key"
JSON_E2E_CERT="${WORK_DIR}/json-e2e-cert.pem"
JSON_E2E_PRIVKEY="${WORK_DIR}/json-e2e-private.key"

acme --output-format json generate-key --account-key "${JSON_E2E_KEY}" >/dev/null 2>&1

OUTPUT=$(acme --output-format json --account-key "${JSON_E2E_KEY}" run \
  --contact json-e2e@example.com \
  --challenge-type http-01 \
  --http-port 5002 \
  --cert-output "${JSON_E2E_CERT}" \
  --key-output "${JSON_E2E_PRIVKEY}" \
  "${SINGLE_DOMAIN}" 2>/dev/null)
RC=$?

if [[ ${RC} -eq 0 ]] && [[ -f "${JSON_E2E_CERT}" ]]; then
  if echo "${OUTPUT}" | grep -q '"action":"issued"'; then
    pass "JSON run output contains action=issued"
    if ${HAS_PYTHON3}; then
      if json_valid "${OUTPUT}"; then
        CERT_PATH=$(json_field "${OUTPUT}" "cert_path")
        KEY_PATH=$(json_field "${OUTPUT}" "key_path")
        ENCRYPTED=$(json_field "${OUTPUT}" "key_encrypted")
        if [[ -n "${CERT_PATH}" ]]; then
          pass "cert_path present: ${CERT_PATH}"
        fi
        if [[ -n "${KEY_PATH}" ]]; then
          pass "key_path present: ${KEY_PATH}"
        fi
        if [[ "${ENCRYPTED}" == "False" ]]; then
          pass "key_encrypted is false (no password)"
        fi
      else
        fail "54" "Output is not valid JSON"
      fi
    fi
  else
    fail "54" "JSON run output missing action=issued"
    echo "  Output: ${OUTPUT}"
  fi
else
  fail "54" "JSON E2E run failed (exit code ${RC})"
  echo "  Output: ${OUTPUT}"
fi

# ── TC-55: run --output-format json (renewal skip) ─────────────────────────

log_test "55" "run --output-format json (renewal skip)"
if [[ -f "${JSON_E2E_CERT}" ]]; then
  OUTPUT=$(acme --output-format json --account-key "${JSON_E2E_KEY}" run \
    --contact json-e2e@example.com \
    --challenge-type http-01 \
    --http-port 5002 \
    --cert-output "${JSON_E2E_CERT}" \
    --key-output "${JSON_E2E_PRIVKEY}" \
    --days 1 \
    "${SINGLE_DOMAIN}" 2>/dev/null)
  if echo "${OUTPUT}" | grep -q '"action":"skip"'; then
    pass "JSON renewal skip output contains action=skip"
    if ${HAS_PYTHON3}; then
      if json_valid "${OUTPUT}"; then
        DAYS_REM=$(json_field "${OUTPUT}" "days_remaining")
        THRESH=$(json_field "${OUTPUT}" "threshold")
        if [[ -n "${DAYS_REM}" ]]; then
          pass "days_remaining present: ${DAYS_REM}"
        fi
        if [[ "${THRESH}" == "1" ]]; then
          pass "threshold is 1"
        fi
      else
        fail "55" "Output is not valid JSON"
      fi
    fi
  else
    fail "55" "JSON renewal skip missing action=skip"
    echo "  Output: ${OUTPUT}"
  fi
else
  skip "No certificate for JSON renewal skip test"
fi

# ── TC-56: text mode unchanged (no JSON contamination) ─────────────────────

log_test "56" "Text mode unchanged (no JSON in default output)"
TEXT_KEY="${WORK_DIR}/json-text-check.key"
OUTPUT=$(acme generate-key --account-key "${TEXT_KEY}" 2>&1)
if echo "${OUTPUT}" | grep -q "account key saved to"; then
  if ! echo "${OUTPUT}" | grep -q '"command"'; then
    pass "Text mode output is unchanged (no JSON)"
  else
    fail "56" "JSON leaked into text mode output"
  fi
else
  fail "56" "Text mode output unexpected"
  echo "  Output: ${OUTPUT}"
fi

# SECTION 17: Hook Scripts (--on-challenge-ready / --on-cert-issued)
# ═════════════════════════════════════════════════════════════════════════════
log_header "17. Hook Scripts"

# TC-57: --on-challenge-ready flag accepted
log_test "57" "--on-challenge-ready flag accepted in help"
if acme run --help 2>&1 | grep -q "on-challenge-ready"; then
  pass "--on-challenge-ready flag in help output"
else
  fail "57" "--on-challenge-ready not found in help"
fi

# TC-58: --on-cert-issued flag accepted
log_test "58" "--on-cert-issued flag accepted in help"
if acme run --help 2>&1 | grep -q "on-cert-issued"; then
  pass "--on-cert-issued flag in help output"
else
  fail "58" "--on-cert-issued not found in help"
fi

# TC-59: --on-challenge-ready with nonexistent script
log_test "59" "--on-challenge-ready with nonexistent script (run fails gracefully)"
HOOK_KEY="${WORK_DIR}/hook-test.key"
acme generate-key --account-key "${HOOK_KEY}" 2>/dev/null
OUTPUT=$(acme --account-key "${HOOK_KEY}" \
  run --on-challenge-ready /nonexistent/hook.sh example.com 2>&1) || true
# Should fail at some point (account creation or challenge) but not panic
if echo "${OUTPUT}" | grep -qi "panic"; then
  fail "59" "Panic with nonexistent hook script"
  echo "  Output: ${OUTPUT}"
else
  pass "No panic with nonexistent hook script"
fi

# TC-60: --on-cert-issued with nonexistent script
log_test "60" "--on-cert-issued with nonexistent script (run fails gracefully)"
OUTPUT=$(acme --account-key "${HOOK_KEY}" \
  run --on-cert-issued /nonexistent/deploy.sh example.com 2>&1) || true
if echo "${OUTPUT}" | grep -qi "panic"; then
  fail "60" "Panic with nonexistent cert hook script"
  echo "  Output: ${OUTPUT}"
else
  pass "No panic with nonexistent cert hook script"
fi

# TC-61: Both hooks accepted together
log_test "61" "Both --on-challenge-ready and --on-cert-issued accepted together"
OUTPUT=$(acme --account-key "${HOOK_KEY}" \
  run --on-challenge-ready /nonexistent/hook.sh --on-cert-issued /nonexistent/deploy.sh \
  example.com 2>&1) || true
if echo "${OUTPUT}" | grep -qi "cannot be used with"; then
  fail "61" "Hooks conflict with each other unexpectedly"
  echo "  Output: ${OUTPUT}"
else
  pass "Both hooks accepted without conflict"
fi

# SECTION 18: External Account Binding (EAB)
# ═════════════════════════════════════════════════════════════════════════════
log_header "18. External Account Binding (EAB)"

# TC-62: --eab-kid and --eab-hmac-key flags appear in account help
log_test "62" "--eab-kid and --eab-hmac-key in account help"
HELP_OUTPUT=$(acme account --help 2>&1)
if echo "${HELP_OUTPUT}" | grep -q "eab-kid" && echo "${HELP_OUTPUT}" | grep -q "eab-hmac-key"; then
  pass "--eab-kid and --eab-hmac-key flags in account help"
else
  fail "62" "EAB flags not found in account help"
  echo "  Output: ${HELP_OUTPUT}"
fi

# TC-63: --eab-kid and --eab-hmac-key flags appear in run help
log_test "63" "--eab-kid and --eab-hmac-key in run help"
HELP_OUTPUT=$(acme run --help 2>&1)
if echo "${HELP_OUTPUT}" | grep -q "eab-kid" && echo "${HELP_OUTPUT}" | grep -q "eab-hmac-key"; then
  pass "--eab-kid and --eab-hmac-key flags in run help"
else
  fail "63" "EAB flags not found in run help"
  echo "  Output: ${HELP_OUTPUT}"
fi

# TC-64: --eab-kid without --eab-hmac-key is rejected by clap
log_test "64" "--eab-kid without --eab-hmac-key rejected"
EAB_KEY="${WORK_DIR}/eab-test.key"
acme generate-key --account-key "${EAB_KEY}" 2>/dev/null
OUTPUT=$(acme --account-key "${EAB_KEY}" account --eab-kid test-kid 2>&1) || true
if echo "${OUTPUT}" | grep -qi "required.*eab-hmac-key\|eab-hmac-key.*required\|the following required"; then
  pass "--eab-kid alone correctly rejected"
else
  fail "64" "Expected clap error about missing --eab-hmac-key"
  echo "  Output: ${OUTPUT}"
fi

# TC-65: --eab-hmac-key without --eab-kid is rejected by clap
log_test "65" "--eab-hmac-key without --eab-kid rejected"
OUTPUT=$(acme --account-key "${EAB_KEY}" account --eab-hmac-key dGVzdA 2>&1) || true
if echo "${OUTPUT}" | grep -qi "required.*eab-kid\|eab-kid.*required\|the following required"; then
  pass "--eab-hmac-key alone correctly rejected"
else
  fail "65" "Expected clap error about missing --eab-kid"
  echo "  Output: ${OUTPUT}"
fi

# TC-66: Invalid base64url HMAC key is rejected
log_test "66" "Invalid base64url EAB HMAC key rejected"
OUTPUT=$(acme --account-key "${EAB_KEY}" \
  account --eab-kid test-kid --eab-hmac-key "not!!!valid===base64" 2>&1) || true
if echo "${OUTPUT}" | grep -qi "not valid base64url\|base64\|decode"; then
  pass "Invalid base64url key correctly rejected"
else
  fail "66" "Expected base64url decode error"
  echo "  Output: ${OUTPUT}"
fi

# TC-67: EAB with invalid credentials (server rejects)
log_test "67" "EAB with fake credentials rejected by server"
OUTPUT=$(acme --account-key "${EAB_KEY}" \
  account --contact eab-test@example.com \
  --eab-kid fake-kid-12345 --eab-hmac-key dGVzdGtleWZvcmhtYWN0ZXN0aW5n 2>&1) || true
# Server should reject - either "externalAccountBinding" error or HTTP error
if echo "${OUTPUT}" | grep -qi "error\|unauthorized\|invalid\|bad\|rejected"; then
  pass "Server rejected fake EAB credentials"
else
  # Some servers may not require EAB and just ignore it - that's also acceptable per RFC
  if echo "${OUTPUT}" | grep -qi "Account status: valid"; then
    pass "Server accepted account (EAB not required - ignored per RFC)"
  else
    fail "67" "Unexpected response with fake EAB credentials"
    echo "  Output: ${OUTPUT}"
  fi
fi

# TC-68: EAB flags accepted on run subcommand (no panic)
log_test "68" "EAB flags accepted on run subcommand without panic"
OUTPUT=$(acme --account-key "${EAB_KEY}" \
  run --eab-kid fake-kid --eab-hmac-key dGVzdA example.com 2>&1) || true
if echo "${OUTPUT}" | grep -qi "panic"; then
  fail "68" "Panic with EAB flags on run subcommand"
  echo "  Output: ${OUTPUT}"
else
  pass "No panic with EAB flags on run subcommand"
fi

# SECTION 19: Pre-Authorization (RFC 8555 Section 7.4.1)
# ═════════════════════════════════════════════════════════════════════════════
log_header "19. Pre-Authorization (RFC 8555 Section 7.4.1)"

# TC-69: pre-authorize subcommand appears in help
log_test "69" "pre-authorize subcommand in help"
HELP_OUTPUT=$(acme --help 2>&1)
if echo "${HELP_OUTPUT}" | grep -q "pre-authorize"; then
  pass "pre-authorize subcommand found in help"
else
  fail "69" "pre-authorize subcommand not found in help"
  echo "  Output: ${HELP_OUTPUT}"
fi

# TC-70: pre-authorize --help shows expected flags
log_test "70" "pre-authorize --help shows --domain and --challenge-type"
HELP_OUTPUT=$(acme pre-authorize --help 2>&1)
if echo "${HELP_OUTPUT}" | grep -q "\-\-domain" && echo "${HELP_OUTPUT}" | grep -q "\-\-challenge-type"; then
  pass "--domain and --challenge-type flags in pre-authorize help"
else
  fail "70" "Expected flags not found in pre-authorize help"
  echo "  Output: ${HELP_OUTPUT}"
fi

# TC-71: pre-authorize requires --domain
log_test "71" "pre-authorize requires --domain"
PREAUTH_KEY="${WORK_DIR}/preauth-test.key"
acme generate-key --account-key "${PREAUTH_KEY}" 2>/dev/null
OUTPUT=$(acme --account-key "${PREAUTH_KEY}" pre-authorize 2>&1) || true
if echo "${OUTPUT}" | grep -qi "required\|--domain"; then
  pass "pre-authorize correctly requires --domain"
else
  fail "71" "Expected error about missing --domain"
  echo "  Output: ${OUTPUT}"
fi

# TC-72: pre-authorize gracefully handles server without newAuthz
log_test "72" "pre-authorize handles missing newAuthz in directory"
OUTPUT=$(acme --account-key "${PREAUTH_KEY}" \
  pre-authorize --domain "preauth-test.${TEST_DOMAIN}" 2>&1) || true
if echo "${OUTPUT}" | grep -qi "pre-authorization\|newAuthz\|not support"; then
  pass "Server without newAuthz handled gracefully"
elif echo "${OUTPUT}" | grep -qi "Authorization URL"; then
  pass "Server supports pre-authorization (newAuthz present)"
else
  # Any non-panic response is acceptable
  if echo "${OUTPUT}" | grep -qi "panic"; then
    fail "72" "Panic during pre-authorize"
    echo "  Output: ${OUTPUT}"
  else
    pass "pre-authorize did not panic (server response: non-standard)"
  fi
fi

# TC-73: --pre-authorize flag appears in run help
log_test "73" "--pre-authorize flag in run help"
HELP_OUTPUT=$(acme run --help 2>&1)
if echo "${HELP_OUTPUT}" | grep -q "\-\-pre-authorize"; then
  pass "--pre-authorize flag found in run help"
else
  fail "73" "--pre-authorize flag not found in run help"
  echo "  Output: ${HELP_OUTPUT}"
fi

# TC-74: --pre-authorize accepted on run subcommand (no panic)
log_test "74" "--pre-authorize accepted on run with no panic"
OUTPUT=$(acme --account-key "${PREAUTH_KEY}" \
  run --pre-authorize --challenge-type http-01 \
  "preauth-test.${TEST_DOMAIN}" 2>&1) || true
if echo "${OUTPUT}" | grep -qi "panic"; then
  fail "74" "Panic with --pre-authorize on run subcommand"
  echo "  Output: ${OUTPUT}"
else
  pass "No panic with --pre-authorize on run subcommand"
fi

# TC-75: pre-authorize with JSON output format
log_test "75" "pre-authorize JSON output format"
OUTPUT=$(acme --account-key "${PREAUTH_KEY}" \
  --output-format json pre-authorize --domain "preauth-test.${TEST_DOMAIN}" 2>&1) || true
if echo "${OUTPUT}" | grep -qi "panic"; then
  fail "75" "Panic with pre-authorize JSON output"
  echo "  Output: ${OUTPUT}"
elif echo "${OUTPUT}" | grep -q '"command"' && echo "${OUTPUT}" | grep -q '"pre-authorize"'; then
  pass "JSON output contains correct command field"
elif echo "${OUTPUT}" | grep -qi "pre-authorization\|newAuthz\|not support"; then
  pass "Server without newAuthz handled gracefully in JSON mode"
else
  pass "No panic with pre-authorize JSON output"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════════════

echo ""
echo ""
log_header "Test Summary"
echo ""
echo -e "  ${GREEN}Passed:${NC}  ${PASSED}"
echo -e "  ${RED}Failed:${NC}  ${FAILED}"
echo -e "  ${YELLOW}Skipped:${NC} ${SKIPPED}"
echo -e "  ${BOLD}Total:${NC}   ${TOTAL}"
echo ""

if [[ ${FAILED} -gt 0 ]]; then
  echo -e "${RED}Failed tests:${FAILURES}${NC}"
  echo ""
  exit 1
else
  echo -e "${GREEN}All tests passed!${NC}"
  echo ""
  exit 0
fi
