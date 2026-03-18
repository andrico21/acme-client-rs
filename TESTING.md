# Test Cases - acme-client-rs

This document describes test cases for the ACME client using **Pebble** as the test CA.

All tests assume Pebble is running locally. See [README.md](README.md) for setup instructions.

> **Note:** Pebble uses a self-signed TLS certificate. All commands below use `--insecure` to skip TLS verification. In production, never use `--insecure`.

---

## Prerequisites

### Start Pebble

```sh
# docker-compose.yml from README
docker compose up -d
```

Verify Pebble is reachable:

```sh
curl -sk https://localhost:14000/dir | python -m json.tool
```

Expected output (URL paths may vary):

```json
{
    "keyChange": "https://localhost:14000/rollover-account-key",
    "meta": { "termsOfService": "data:text/plain,..." },
    "newAccount": "https://localhost:14000/sign-me-up",
    "newNonce": "https://localhost:14000/nonce-plz",
    "newOrder": "https://localhost:14000/order-plz",
    "renewalInfo": "https://localhost:14000/renewal-info",
    "revokeCert": "https://localhost:14000/revoke-cert"
}
```

### Set Alias (optional)

```sh
# Linux/macOS
alias acme=./target/release/acme-client-rs

# PowerShell
Set-Alias acme .\target\release\acme-client-rs.exe
```

All commands below use `acme` as the alias for brevity.

---

## TC-01: Generate Account Key

**Goal:** Generate a new ES256 PKCS#8 PEM key pair.

```sh
acme generate-key --account-key test-account.key
```

**Expected:**
- Exit code: 0
- Output: `ES256 account key saved to test-account.key`
- File `test-account.key` is created containing a PEM-encoded EC private key

**Verify:**

```sh
# Check it's a valid EC key
openssl ec -in test-account.key -text -noout
```

Should show `ASN1 OID: prime256v1` (P-256).

---

## TC-01b: Generate Key - All Algorithms

**Goal:** Generate account keys for all supported algorithms.

```sh
for alg in es256 es384 es512 rsa2048 rsa4096; do
  acme generate-key --algorithm ${alg} --account-key test-${alg}.key
done
```

> **Note:** Ed25519 is excluded from E2E testing because Pebble only supports RS256, ES256, ES384, ES512.

**Expected:**
- Exit code: 0 for each algorithm
- Each key file created with valid PEM header (`BEGIN`)

---

## TC-02: Generate Key - File Already Exists (overwrite)

**Goal:** Re-running generate-key overwrites the existing file.

```sh
acme generate-key --account-key test-account.key
acme generate-key --account-key test-account.key
```

**Expected:**
- Exit code: 0 both times
- The key file contents change between runs (new random key)

---

## TC-03: Create Account

**Goal:** Register a new ACME account with the CA.

```sh
acme --insecure --account-key test-account.key account --contact test@example.com
```

**Expected:**
- Exit code: 0
- Output includes:
  ```
  Account status: valid
  Account URL:    https://localhost:14000/my-account/<id>
  ```

---

## TC-04: Create Account - Idempotent Lookup

**Goal:** Calling `account` again with the same key returns the existing account.

```sh
acme --insecure --account-key test-account.key account --contact test@example.com
acme --insecure --account-key test-account.key account --contact test@example.com
```

**Expected:**
- Both calls succeed with exit code 0
- Both return the same Account URL

---

## TC-05: Create Account - No Contact

**Goal:** Account creation works without a contact email.

```sh
acme --insecure --account-key test-account.key account
```

**Expected:**
- Exit code: 0
- Output: `Account status: valid`

---

## TC-06: Place an Order

**Goal:** Submit a new certificate order for one domain.

```sh
acme --account-key test-account.key --account-url <account-url-from-TC-03> order test.example.com
```

**Expected:**
- Exit code: 0
- Output includes:
  ```
  Order URL:    https://localhost:14000/my-order/<id>
  Status:       pending
  Finalize URL: https://localhost:14000/finalize-order/<id>
    authz: https://localhost:14000/authZ/<id>
  ```

---

## TC-07: Place an Order - Multiple Domains (SAN)

**Goal:** Order a certificate with multiple Subject Alternative Names.

```sh
acme --account-key test-account.key --account-url <account-url> order test.example.com www.example.com api.example.com
```

**Expected:**
- Exit code: 0
- Three authorization URLs listed (one per domain)

---

## TC-08: Fetch Authorization

**Goal:** Retrieve authorization details and available challenges.

```sh
acme --account-key test-account.key --account-url <account-url> get-authz <authz-url-from-TC-06>
```

**Expected:**
- Exit code: 0
- Output includes:
  ```
  Identifier: test.example.com (dns)
  Status:     pending
    http-01 [pending] url=https://localhost:14000/chalZ/<id>
      token: <base64url-token>
    dns-01 [pending] url=...
      token: ...
    tls-alpn-01 [pending] url=...
      token: ...
  ```

---

## TC-09: Respond to Challenge

**Goal:** Tell the CA a challenge is ready.

```sh
acme --account-key test-account.key --account-url <account-url> respond-challenge <challenge-url-from-TC-08>
```

**Expected:**
- Exit code: 0
- Output: `Challenge status: pending` or `Challenge status: processing`

> **Note:** With `PEBBLE_VA_ALWAYS_VALID=1`, the challenge should transition to `valid` shortly.

---

## TC-10: Serve HTTP-01 Challenge

**Goal:** Start the built-in HTTP-01 validation server.

```sh
# Terminal 1: start server
acme --account-key test-account.key serve-http01 --token <token> --port 5002

# Terminal 2: simulate validation request
curl http://localhost:5002/.well-known/acme-challenge/<token>
```

**Expected:**
- Terminal 1: `HTTP-01 server listening on 0.0.0.0:5002`, then `HTTP-01: served challenge response`, then exits
- Terminal 2: receives the key authorization string `<token>.<thumbprint>`

---

## TC-10b: Serve HTTP-01 Challenge (challenge-dir mode)

**Goal:** Write the challenge file to a directory instead of starting a server.

```sh
acme --account-key test-account.key serve-http01 --token <token> --challenge-dir /var/www/acme
```

**Expected:**
- Exit code: 0
- File created at `/var/www/acme/.well-known/acme-challenge/<token>`

---

## TC-11: Serve HTTP-01 - Port Already In Use

**Goal:** Binding to an occupied port produces a clear error.

```sh
# Terminal 1: occupy port
python -m http.server 5002

# Terminal 2: try to serve
acme --account-key test-account.key serve-http01 --token dummy --port 5002
```

**Expected:**
- Exit code: 1
- Error message:
  ```
  Error: port 5002 is already in use (reverse proxy or other server?)

  Hint: use --challenge-dir <DIR> to write the challenge file
  to a directory your existing web server already serves, e.g.:

  acme-client-rs run example.com --challenge-dir /var/www/html
  ```

---

## TC-12: Show DNS-01 Instructions

**Goal:** Display the TXT record value for DNS-01 validation.

```sh
acme --account-key test-account.key show-dns01 --domain test.example.com --token <token>
```

**Expected:**
- Exit code: 0
- Output (exact value depends on key+token):
  ```
  === DNS-01 Challenge ===
  Create a DNS TXT record:
    Name:  _acme-challenge.test.example.com
    Type:  TXT
    Value: <base64url-encoded-sha256>
  ```
- Command exits immediately (display only, no interactive wait)

---

## TC-13: Finalize Order

**Goal:** Submit CSR to finalize a ready order.

First, ensure all authorizations are valid (use `PEBBLE_VA_ALWAYS_VALID=1` + respond to challenges).

```sh
acme --account-key test-account.key --account-url <account-url> finalize --finalize-url <finalize-url> test.example.com
```

**Expected:**
- Exit code: 0
- Output: `Order status: valid` (or `processing`)
- If valid: `Certificate URL: https://localhost:14000/certZ/<id>`

---

## TC-14: Poll Order Status

**Goal:** Check order status until it becomes valid.

```sh
acme --account-key test-account.key --account-url <account-url> poll-order <order-url>
```

**Expected:**
- Exit code: 0
- Output: `Order status: valid` (after finalization) with `Certificate URL: ...`

---

## TC-15: Download Certificate

**Goal:** Download the issued certificate chain.

```sh
acme --account-key test-account.key --account-url <account-url> download-cert <certificate-url> --output test-cert.pem
```

**Expected:**
- Exit code: 0
- Output: `Certificate saved to test-cert.pem`
- File contains PEM-encoded certificate(s)

**Verify:**

```sh
openssl x509 -in test-cert.pem -text -noout | head -20
```

Should show the domain in Subject Alternative Names.

---

## TC-16: Revoke Certificate

**Goal:** Revoke a previously issued certificate.

> `--account-url` is optional - the client auto-discovers the account if omitted.

```sh
acme --account-key test-account.key revoke-cert test-cert.pem
```

**Expected:**
- Exit code: 0
- Output: `Certificate revoked`

---

## TC-17: Revoke Certificate - With Reason Code

**Goal:** Revoke with an explicit reason (e.g., 4 = superseded).

```sh
acme --account-key test-account.key revoke-cert test-cert.pem --reason 4
```

**Expected:**
- Exit code: 0
- Output: `Certificate revoked`

---

## TC-18: Deactivate Account

**Goal:** Deactivate the ACME account (irreversible).

```sh
acme --account-key test-account.key --account-url <account-url> deactivate-account
```

**Expected:**
- Exit code: 0
- Output: `Account status: deactivated`

---

## TC-19: Operations After Account Deactivation

**Goal:** Verify that operations fail after account deactivation.

```sh
acme --account-key test-account.key --account-url <account-url> order test.example.com
```

**Expected:**
- Exit code: 1
- Error message referencing `unauthorized` or account being deactivated

---

## TC-20: Full End-to-End Flow (HTTP-01)

**Goal:** Run the complete automated flow with HTTP-01 challenge.

> Requires `PEBBLE_VA_ALWAYS_VALID=1` so Pebble doesn't need to reach the HTTP server.

```sh
# Fresh key
acme generate-key --account-key e2e-account.key

# Full flow
acme --insecure --account-key e2e-account.key run --contact e2e@example.com --challenge-type http-01 --http-port 5002 e2e-test.example.com
```

**Expected:**
- Exit code: 0
- Output shows all 6 steps completing:
  ```
  Account status: valid
  Order URL: ...
  Order status: pending
  Authorization for e2e-test.example.com - status: pending
  HTTP-01 server listening on 0.0.0.0:5002
    Challenge response sent - waiting for validationâ€¦
    Authorization status: valid
  Order status: valid
  Certificate saved to certificate.pem
  -----BEGIN CERTIFICATE-----
  ...
  -----END CERTIFICATE-----
  ```
- `certificate.pem` file created with valid PEM content

---

## TC-21: Full End-to-End Flow (DNS-01)

**Goal:** Run the automated flow with DNS-01 (interactive - pauses for DNS record setup).

```sh
acme --account-key e2e-account.key run --contact e2e@example.com --challenge-type dns-01 dns-test.example.com
```

**Expected:**
- Prints DNS TXT record instructions
- Waits for Enter keypress
- After pressing Enter, proceeds through finalization
- With `PEBBLE_VA_ALWAYS_VALID=1`, completes successfully

---

## TC-22: Full End-to-End Flow - Multiple Domains

**Goal:** Issue a multi-SAN certificate through the automated flow.

```sh
acme --account-key e2e-account.key run --contact e2e@example.com --challenge-type http-01 --http-port 5002 san1.example.com san2.example.com san3.example.com
```

**Expected:**
- Three separate authorizations processed
- Single certificate issued with all three SANs

**Verify:**

```sh
openssl x509 -in certificate.pem -text -noout | grep -A5 "Subject Alternative Name"
```

---

## TC-23: Environment Variable Configuration

**Goal:** Verify all three environment variables work as alternatives to flags.

```sh
export ACME_DIRECTORY_URL=https://localhost:14000/dir
export ACME_ACCOUNT_KEY_FILE=e2e-account.key
export ACME_ACCOUNT_URL=<account-url>

# No flags needed
acme order test.example.com
```

**Expected:**
- Exit code: 0
- Uses the directory, key, and account URL from environment

---

## TC-24: Global Args After Subcommand

**Goal:** Verify global options work when placed after the subcommand.

```sh
acme generate-key --account-key after-sub.key
acme account --account-key after-sub.key --contact test@example.com
```

**Expected:**
- Both succeed (exit code 0)
- `--account-key` is recognized after the subcommand name

---

## TC-25: Missing Account Key File

**Goal:** Clear error when the account key file doesn't exist.

```sh
acme --account-key nonexistent.key account
```

**Expected:**
- Exit code: 1
- Error: `Error: failed to read account key from nonexistent.key: ...`

---

## TC-26: Invalid Directory URL

**Goal:** Clear error for an unreachable or wrong directory URL.

```sh
acme --directory https://localhost:9999/nope generate-key --account-key x.key
# generate-key doesn't contact the server - try account instead:
acme --directory https://localhost:9999/nope --account-key test-account.key account
```

**Expected:**
- `generate-key`: succeeds (doesn't need the directory)
- `account`: exit code 1, error about connection refused or ACME directory request failed

---

## TC-26b: generate-key Does Not Need Directory (offline)

**Goal:** `generate-key` succeeds even with an unreachable directory URL (no server contact needed).

```sh
acme --directory https://localhost:59999/nope generate-key --account-key offline.key
```

**Expected:**
- Exit code: 0
- Key file created (offline operation — no directory access required)

---

## TC-27: Directory Returns Non-JSON (404)

**Goal:** Clear error when directory URL returns a non-ACME response.

```sh
acme --directory https://localhost:14000/nonexistent --account-key test-account.key account
```

**Expected:**
- Exit code: 1
- Error: `Error: ACME directory request failed (HTTP 404): ...`

---

## TC-28: Rejected Identifier

**Goal:** Proper error when the CA rejects a domain name.

> This test requires a CA with name constraints (not default Pebble, which allows any domain).

```sh
acme --directory https://constrained-ca/directory --account-key test-account.key --account-url <account-url> order not-allowed-domain.com
```

**Expected:**
- Exit code: 1
- Error: `Error: ACME error (HTTP 400 Bad Request): The server will not issue certificates for the identifier (urn:ietf:params:acme:error:rejectedIdentifier)`
- No stack trace

---

## TC-29: Verbose Logging

**Goal:** Debug-level logging provides detailed protocol information.

```sh
RUST_LOG=debug acme --account-key test-account.key account --contact test@example.com
```

**Expected:**
- Additional log lines showing:
  - Nonce fetch requests
  - JWS signing details
  - Full HTTP request/response flow
  - Directory structure

---

## TC-30: Custom HTTP-01 Port

**Goal:** HTTP-01 server binds to a non-default port.

```sh
acme --account-key test-account.key serve-http01 --token test-token --port 8080
```

**Expected:**
- Output: `HTTP-01 server listening on 0.0.0.0:8080`
- Server accepts connections on port 8080

---

## TC-31: Account URL Required After Creation

**Goal:** Operations that need an account URL fail clearly without one.

```sh
# Skip --account-url
acme --account-key test-account.key order test.example.com
```

**Expected:**
- The client creates a new account automatically (via `build_client` â†’ `AcmeClient::new`), or
- If using the individual `order` command without prior `account`, the signed request uses JWK mode and the CA may reject it

> **Note:** The `run` command handles this automatically by calling `create_account` first.

---

## TC-32: badNonce Retry

**Goal:** Verify the client retries on `badNonce` errors (RFC 8555 Â§6.5).

> Use `PEBBLE_WFE_NONCEREJECT=50` to make Pebble randomly reject 50% of nonces.

```yaml
# docker-compose.yml override
environment:
  - PEBBLE_WFE_NONCEREJECT=50
```

```sh
acme --account-key test-account.key run --contact test@example.com --challenge-type http-01 --http-port 5002 nonce-test.example.com
```

**Expected:**
- Flow completes despite nonce rejections
- With `RUST_LOG=debug`, log shows `Received badNonce - retrying with fresh nonce` messages

---

## TC-33: E2E with --key-password (encrypted private key)

**Goal:** Verify `--key-password` encrypts the issued private key with PKCS#8 AES-256-CBC + scrypt KDF.

```sh
acme --insecure --account-key enc-test.key run --contact enc@example.com --challenge-type http-01 --http-port 5002 --cert-output enc-cert.pem --key-output enc-private.key --key-password "TestP@ssw0rd!2026" test.example.com
```

**Expected:**
- Exit code: 0
- `enc-private.key` contains `ENCRYPTED PRIVATE KEY` PEM header
- `openssl pkey -in enc-private.key -passin pass:TestP@ssw0rd!2026 -noout` succeeds
- Wrong password is rejected

---

## TC-34: E2E with --key-password-file (password from file)

**Goal:** Verify `--key-password-file` reads the encryption password from a file.

```sh
echo "FileP@ssw0rd!2026" > key-password.txt
acme --insecure --account-key enc2.key run --contact enc2@example.com --challenge-type http-01 --http-port 5002 --cert-output enc2-cert.pem --key-output enc2-private.key --key-password-file key-password.txt test.example.com
```

**Expected:**
- Exit code: 0
- `enc2-private.key` contains `ENCRYPTED PRIVATE KEY` PEM header
- Key is decryptable with the file password

---

## TC-35: --key-password and --key-password-file are Mutually Exclusive

**Goal:** Providing both password flags produces a CLI error.

```sh
acme --insecure --account-key test.key run --key-password "pw1" --key-password-file pw.txt test.example.com
```

**Expected:**
- Exit code: non-zero
- Error mentions conflict/mutual exclusivity

---

## TC-36: E2E without Password (key is unencrypted)

**Goal:** Without `--key-password`, the private key is unencrypted PKCS#8 PEM.

**Expected:**
- Key file starts with `BEGIN PRIVATE KEY` (not `ENCRYPTED`)

---

## TC-37: Renewal Skipped (certificate has many days left)

**Goal:** `run --days 1` skips issuance when the existing certificate has more than 1 day remaining.

```sh
# Step 1: Issue a certificate first
acme --insecure --account-key renewal.key run --contact renewal@example.com --challenge-type http-01 --http-port 5002 --cert-output renewal-cert.pem --key-output renewal-key.pem test.example.com

# Step 2: Re-run with --days 1 (should skip - cert has many days left)
acme --insecure --account-key renewal.key run --contact renewal@example.com --challenge-type http-01 --http-port 5002 --cert-output renewal-cert.pem --key-output renewal-key.pem --days 1 test.example.com
```

**Expected:**
- Both commands exit with code 0
- Step 2 output contains `skipping renewal` (case-insensitive)

---

## TC-38: Renewal Proceeds (--days set very high)

**Goal:** `run --days 9999` forces renewal because the certificate has fewer than 9999 days remaining.

```sh
acme --insecure --account-key renewal.key run --contact renewal@example.com --challenge-type http-01 --http-port 5002 --cert-output renewal-cert.pem --key-output renewal-key.pem --days 9999 test.example.com
```

**Expected:**
- Exit code: 0
- Certificate file content changes (new certificate issued)

---

## TC-39: Key Rollover

**Goal:** Rotate the account key to a new key pair.

```sh
acme generate-key --account-key rollover-new.key
acme --insecure --account-key rollover-old.key --account-url <account-url> key-rollover --new-key rollover-new.key
```

**Expected:**
- Exit code: 0
- Output contains `key rolled over` or `rolled over successfully` (case-insensitive)
- New key works for subsequent operations (e.g., placing an order)

---

## TC-40: DNS-01 Hook Script (create/cleanup)

**Goal:** Verify `--dns-hook` is called with `ACME_ACTION=create` before validation and `ACME_ACTION=cleanup` after.

```sh
acme --insecure --account-key dns-hook.key run --contact dns-hook@example.com --challenge-type dns-01 --dns-hook /path/to/hook.sh --cert-output dns-hook-cert.pem --key-output dns-hook-key.pem test.example.com
```

**Expected:**
- Hook called with `action=create` (at least once)
- Hook called with `action=cleanup` (at least once)
- Hook receives the correct domain name
- Certificate issued (with `PEBBLE_VA_ALWAYS_VALID=1`)

---

## TC-40b: DNS-01 Hook Cleanup Called on Propagation Timeout

**Goal:** When `--dns-wait` times out (DNS record never appears), the cleanup hook is still called.

```sh
acme --insecure --account-key dns-hook2.key run --contact dns-hook2@example.com --challenge-type dns-01 --dns-hook /path/to/hook.sh --dns-wait 1 test.example.com
```

**Expected:**
- Exit code: non-zero (propagation timeout)
- Hook log shows at least 1 `action=create` and at least 1 `action=cleanup`
- Cleanup is called on the error path (not only on success)

---

## TC-40c: Multi-Domain DNS-01 Hook (parallel, concurrency=1)

**Goal:** Multi-SAN order with `--dns-hook` and `--dns-propagation-concurrency 1` processes all domains. The semaphore serializes the 3 domains through 1 permit.

```sh
acme --insecure --account-key dns-hook3.key run --contact dns-hook3@example.com --challenge-type dns-01 --dns-hook /path/to/hook.sh --dns-propagation-concurrency 1 --cert-output dns-hook3-cert.pem --key-output dns-hook3-key.pem domain1.example.com domain2.example.com domain3.example.com
```

**Expected:**
- Hook `action=create` called at least 3 times (one per domain)
- Hook `action=cleanup` called at least 3 times (one per domain)
- At least 3 unique domains in hook log
- Exit code: 0 (certificate issued)

---

## TC-40d: Multi-Domain DNS-01 Hook Cleanup on Propagation Timeout

**Goal:** Multi-SAN order with `--dns-wait 1` and `--dns-propagation-concurrency 1` — propagation times out, but cleanup hooks are called for all 3 domains.

```sh
acme --insecure --account-key dns-hook4.key run --contact dns-hook4@example.com --challenge-type dns-01 --dns-hook /path/to/hook.sh --dns-wait 1 --dns-propagation-concurrency 1 domain1.example.com domain2.example.com domain3.example.com
```

**Expected:**
- Exit code: non-zero (propagation timeout)
- Hook `action=create` called at least 3 times
- Hook `action=cleanup` called at least 3 times (on error path)

---

## TC-41: Custom --cert-output and --key-output Paths

**Goal:** Verify certificates and keys are saved to custom paths.

```sh
acme --insecure --account-key custom-out.key run --contact custom@example.com --challenge-type http-01 --http-port 5002 --cert-output /custom/dir/my-cert.pem --key-output /custom/dir/my-key.pem test.example.com
```

**Expected:**
- Exit code: 0
- Certificate at the custom cert path
- Private key at the custom key path

---

## TC-50: generate-key --output-format json

**Goal:** JSON output from `generate-key`.

```sh
acme --output-format json generate-key --account-key json-key.key
```

**Expected:**
- Output is valid JSON containing `"command": "generate-key"` and `"algorithm"` field

---

## TC-51: account --output-format json

**Goal:** JSON output from `account`.

```sh
acme --insecure --output-format json --account-key json-key.key account --contact json@example.com
```

**Expected:**
- Valid JSON with `"command": "account"`, `"status": "valid"`, `"url"` present

---

## TC-52: order --output-format json

**Goal:** JSON output from `order`.

```sh
acme --insecure --output-format json --account-key json-key.key --account-url <url> order test.example.com
```

**Expected:**
- Valid JSON with `"command": "order"`, `"order_url"` present, `"authorizations"` array with length > 0

---

## TC-53: show-dns01 --output-format json

**Goal:** JSON output from `show-dns01`.

```sh
acme --output-format json --account-key json-key.key show-dns01 --domain test.example.com --token test-token
```

**Expected:**
- Valid JSON with `"record_name"` containing `_acme-challenge` and `"record_value"` present

---

## TC-54: run --output-format json (full E2E)

**Goal:** JSON output from a full `run` flow.

```sh
acme --insecure --output-format json --account-key json-e2e.key run --contact json-e2e@example.com --challenge-type http-01 --http-port 5002 --cert-output json-cert.pem --key-output json-key.pem test.example.com
```

**Expected:**
- Exit code: 0
- JSON output contains `"action":"issued"`, `"cert_path"`, `"key_path"`, `"key_encrypted": false`

---

## TC-55: run --output-format json (renewal skip)

**Goal:** JSON output when renewal is skipped.

```sh
acme --insecure --output-format json --account-key json-e2e.key run --contact json-e2e@example.com --challenge-type http-01 --http-port 5002 --cert-output json-cert.pem --key-output json-key.pem --days 1 test.example.com
```

**Expected:**
- JSON output contains `"action":"skip"`, `"days_remaining"`, `"threshold": "1"`

---

## TC-56: Text Mode Unchanged (no JSON contamination)

**Goal:** Default text output has no JSON.

```sh
acme generate-key --account-key text-check.key
```

**Expected:**
- Output contains `account key saved to`
- Output does NOT contain `"command"`

---

## TC-57: --on-challenge-ready Flag Accepted in Help

**Goal:** `acme run --help` lists the `--on-challenge-ready` flag.

**Expected:**
- Help output contains `on-challenge-ready`

---

## TC-58: --on-cert-issued Flag Accepted in Help

**Goal:** `acme run --help` lists the `--on-cert-issued` flag.

**Expected:**
- Help output contains `on-cert-issued`

---

## TC-59: --on-challenge-ready with Nonexistent Script

**Goal:** No panic when `--on-challenge-ready` points to a nonexistent script.

```sh
acme --insecure --account-key hook.key run --on-challenge-ready /nonexistent/hook.sh example.com
```

**Expected:**
- No panic (may fail for other reasons)

---

## TC-60: --on-cert-issued with Nonexistent Script

**Goal:** No panic when `--on-cert-issued` points to a nonexistent script.

```sh
acme --insecure --account-key hook.key run --on-cert-issued /nonexistent/deploy.sh example.com
```

**Expected:**
- No panic (may fail for other reasons)

---

## TC-61: Both Hooks Accepted Together

**Goal:** `--on-challenge-ready` and `--on-cert-issued` can be used simultaneously.

```sh
acme --insecure --account-key hook.key run --on-challenge-ready /nonexistent/hook.sh --on-cert-issued /nonexistent/deploy.sh example.com
```

**Expected:**
- No "cannot be used with" conflict error

---

## TC-62: EAB Flags in Account Help

**Goal:** `acme account --help` shows `--eab-kid` and `--eab-hmac-key`.

**Expected:**
- Help output contains both `eab-kid` and `eab-hmac-key`

---

## TC-63: EAB Flags in Run Help

**Goal:** `acme run --help` shows `--eab-kid` and `--eab-hmac-key`.

**Expected:**
- Help output contains both `eab-kid` and `eab-hmac-key`

---

## TC-64: --eab-kid Without --eab-hmac-key Rejected

**Goal:** Providing `--eab-kid` alone is rejected by clap.

```sh
acme --insecure --account-key eab.key account --eab-kid test-kid
```

**Expected:**
- Exit code: non-zero
- Error mentions `eab-hmac-key` is required

---

## TC-65: --eab-hmac-key Without --eab-kid Rejected

**Goal:** Providing `--eab-hmac-key` alone is rejected by clap.

```sh
acme --insecure --account-key eab.key account --eab-hmac-key dGVzdA
```

**Expected:**
- Exit code: non-zero
- Error mentions `eab-kid` is required

---

## TC-66: Invalid Base64url EAB HMAC Key Rejected

**Goal:** Non-base64url HMAC key is rejected.

```sh
acme --insecure --account-key eab.key account --eab-kid test-kid --eab-hmac-key "not!!!valid===base64"
```

**Expected:**
- Exit code: non-zero
- Error mentions base64 decode failure

---

## TC-67: EAB with Fake Credentials

**Goal:** Server rejects invalid EAB credentials (or accepts if EAB is not required).

```sh
acme --insecure --account-key eab.key account --contact eab-test@example.com --eab-kid fake-kid-12345 --eab-hmac-key dGVzdGtleWZvcmhtYWN0ZXN0aW5n
```

**Expected:**
- Server rejects (error), OR
- Server accepts (EAB not required — ignored per RFC)

---

## TC-68: EAB Flags Accepted on Run Subcommand

**Goal:** No panic when EAB flags are used with `run`.

```sh
acme --insecure --account-key eab.key run --eab-kid fake-kid --eab-hmac-key dGVzdA example.com
```

**Expected:**
- No panic

---

## TC-69: pre-authorize Subcommand in Help

**Goal:** `acme --help` lists the `pre-authorize` subcommand.

**Expected:**
- Help output contains `pre-authorize`

---

## TC-70: pre-authorize --help Shows Expected Flags

**Goal:** `acme pre-authorize --help` shows `--domain` and `--challenge-type`.

**Expected:**
- Help output contains both `--domain` and `--challenge-type`

---

## TC-71: pre-authorize Requires --domain

**Goal:** `pre-authorize` without `--domain` is rejected.

```sh
acme --insecure --account-key preauth.key pre-authorize
```

**Expected:**
- Exit code: non-zero
- Error mentions `--domain` is required

---

## TC-72: pre-authorize Handles Missing newAuthz

**Goal:** Graceful handling when the server does not advertise `newAuthz`.

```sh
acme --insecure --account-key preauth.key pre-authorize --domain preauth-test.example.com
```

**Expected:**
- Clear error about pre-authorization not supported, OR
- Authorization URL returned (if server supports it)
- No panic

---

## TC-73: --pre-authorize Flag in Run Help

**Goal:** `acme run --help` shows `--pre-authorize`.

**Expected:**
- Help output contains `--pre-authorize`

---

## TC-74: --pre-authorize Accepted on Run

**Goal:** No panic when `--pre-authorize` is used with `run`.

```sh
acme --insecure --account-key preauth.key run --pre-authorize --challenge-type http-01 preauth-test.example.com
```

**Expected:**
- No panic

---

## TC-75: pre-authorize JSON Output

**Goal:** JSON output from `pre-authorize`.

```sh
acme --insecure --output-format json --account-key preauth.key pre-authorize --domain preauth-test.example.com
```

**Expected:**
- No panic
- If supported: valid JSON with `"command": "pre-authorize"`
- If not supported: error message

---

## Manual-Only Test Cases

The following test cases require special server configurations and are not included in the automated test script (`tests/test.sh`):

| TC | Description | Requirements |
|----|-------------|-------------|
| 28 | Rejected identifier — CA rejects a domain | CA with name constraints |
| 31 | Missing account URL — operations fail clearly | Manual |
| 32 | badNonce retry — client retries automatically | `PEBBLE_WFE_NONCEREJECT=50` |
| 42 | `run --ari` — ARI-guided renewal | Server with ARI support |
| 43 | `run --ari --days` — ARI with days fallback | Server with ARI support |
| 44 | `renewal-info` on server without ARI | Server without ARI |
| 45–49 | DNS-PERSIST-01 tests | Pebble with dns-persist-01 support |

---

## Summary Matrix

| TC | Command | Challenge | Expectation | Automated |
|----|---------|-----------|-------------|-----------|
| 01 | `generate-key` | - | Key file created | Yes |
| 01b | `generate-key` (all algorithms) | - | All key types generated | Yes |
| 02 | `generate-key` (overwrite) | - | File replaced | Yes |
| 03 | `account` | - | Account created | Yes |
| 04 | `account` (idempotent) | - | Same account returned | Yes |
| 05 | `account` (no contact) | - | Account created | Yes |
| 06 | `order` (single) | - | Order pending | Yes |
| 07 | `order` (multi SAN) | - | Multiple authz URLs | Yes |
| 08 | `get-authz` | - | Challenges listed | Yes |
| 09 | `respond-challenge` | - | Challenge progresses | Yes |
| 10 | `serve-http01` (standalone) | HTTP-01 | Token served | Yes |
| 10b | `serve-http01` (challenge-dir) | HTTP-01 | File written | Yes |
| 11 | `serve-http01` (port busy) | HTTP-01 | Clear error | Yes |
| 12 | `show-dns01` | DNS-01 | TXT instructions | Yes |
| 13 | `finalize` | - | CSR submitted | Yes |
| 14 | `poll-order` | - | Status returned | Yes |
| 15 | `download-cert` | - | PEM saved | Yes |
| 16 | `revoke-cert` | - | Cert revoked | Yes |
| 17 | `revoke-cert` (reason) | - | Revoked with code | Yes |
| 18 | `deactivate-account` | - | Account deactivated | Yes |
| 19 | Operations post-deactivation | - | Rejected | Yes |
| 20 | `run` (e2e, all key algorithms) | HTTP-01 | Full flow succeeds | Yes |
| 21 | `run` (e2e) | DNS-01 | Interactive flow | Yes |
| 22 | `run` (multi-SAN) | HTTP-01 | Multi-domain cert | Yes |
| 23 | Env vars | - | Config from env | Yes |
| 24 | Global args after subcmd | - | Args accepted | Yes |
| 25 | Missing key file | - | Clear error | Yes |
| 26 | Invalid directory URL | - | Clear error | Yes |
| 26b | `generate-key` offline | - | No directory needed | Yes |
| 27 | Directory 404 | - | Clear error | Yes |
| 28 | Rejected identifier | - | Clean ACME error | Manual |
| 29 | `RUST_LOG=debug` | - | Verbose output | Yes |
| 30 | Custom HTTP port | HTTP-01 | Binds correctly | Yes |
| 31 | Missing account URL | - | Handled gracefully | Manual |
| 32 | badNonce retry | - | Auto-retry works | Manual |
| 33 | `run` + `--key-password` | HTTP-01 | Encrypted key | Yes |
| 34 | `run` + `--key-password-file` | HTTP-01 | Password from file | Yes |
| 35 | Password flags conflict | - | Mutual exclusivity | Yes |
| 36 | No password (unencrypted) | - | Plain PKCS#8 PEM | Yes |
| 37 | Renewal skipped (`--days 1`) | HTTP-01 | Skips when not due | Yes |
| 38 | Renewal proceeds (`--days 9999`) | HTTP-01 | Renews when due | Yes |
| 39 | `key-rollover` | - | Key rotated | Yes |
| 40 | DNS-01 hook (create/cleanup) | DNS-01 | Hook called both ways | Yes |
| 40b | DNS-01 hook cleanup on timeout | DNS-01 | Cleanup on error path | Yes |
| 40c | Multi-domain DNS-01 hook (concurrency=1) | DNS-01 | All domains processed | Yes |
| 40d | Multi-domain DNS-01 cleanup on timeout | DNS-01 | Cleanup for all domains | Yes |
| 41 | Custom output paths | HTTP-01 | Files at custom paths | Yes |
| 42 | `run --ari` | HTTP-01 | ARI-guided renewal | Manual |
| 43 | `run --ari --days` | HTTP-01 | ARI with days fallback | Manual |
| 44 | `renewal-info` (no ARI server) | - | Clear error | Manual |
| 45–49 | DNS-PERSIST-01 tests | DNS-PERSIST-01 | Various | Manual |
| 50 | `generate-key` JSON | - | Structured JSON | Yes |
| 51 | `account` JSON | - | Structured JSON | Yes |
| 52 | `order` JSON | - | Structured JSON | Yes |
| 53 | `show-dns01` JSON | - | Structured JSON | Yes |
| 54 | `run` JSON (e2e) | HTTP-01 | `action: issued` | Yes |
| 55 | `run` JSON (renewal skip) | HTTP-01 | `action: skip` | Yes |
| 56 | Text mode unchanged | - | No JSON in text | Yes |
| 57 | `--on-challenge-ready` in help | - | Flag listed | Yes |
| 58 | `--on-cert-issued` in help | - | Flag listed | Yes |
| 59 | `--on-challenge-ready` nonexistent | - | No panic | Yes |
| 60 | `--on-cert-issued` nonexistent | - | No panic | Yes |
| 61 | Both hooks together | - | No conflict | Yes |
| 62 | EAB flags in `account` help | - | Flags listed | Yes |
| 63 | EAB flags in `run` help | - | Flags listed | Yes |
| 64 | `--eab-kid` alone rejected | - | Requires `--eab-hmac-key` | Yes |
| 65 | `--eab-hmac-key` alone rejected | - | Requires `--eab-kid` | Yes |
| 66 | Invalid base64url HMAC key | - | Decode error | Yes |
| 67 | Fake EAB credentials | - | Server rejects or ignores | Yes |
| 68 | EAB on `run` (no panic) | - | No panic | Yes |
| 69 | `pre-authorize` in help | - | Subcommand listed | Yes |
| 70 | `pre-authorize --help` flags | - | `--domain`, `--challenge-type` | Yes |
| 71 | `pre-authorize` requires `--domain` | - | Required arg | Yes |
| 72 | `pre-authorize` missing newAuthz | - | Graceful error | Yes |
| 73 | `--pre-authorize` in `run` help | - | Flag listed | Yes |
| 74 | `--pre-authorize` on `run` | - | No panic | Yes |
| 75 | `pre-authorize` JSON output | - | Structured JSON | Yes |

---

## Live Test Results

Tested against a **step-ca** ACME server on **2026-03-11** using version **1.7.0**.

| TC | Test | Key | Challenge | Result |
|----|------|-----|-----------|--------|
| 01 | Generate key (ES256) | ES256 | - | âœ… Pass |
| 01 | Generate key (ES512) | ES512 | - | âœ… Pass |
| 01 | Generate key (RSA2048) | RSA2048 | - | âœ… Pass |
| 01 | Generate key (Ed25519) | Ed25519 | - | âœ… Pass |
| 02 | Generate key - overwrite | ES256 | - | âœ… Pass |
| 03 | Account creation (standalone) | ES256 | - | âœ… Pass |
| 04 | Account idempotent lookup | ES256 | - | âœ… Pass |
| 05 | Account - no contact | ES256 | - | âœ… Pass |
| 06 | Place an order (single domain) | ES256 | - | âœ… Pass |
| 07 | Place an order - multiple domains (SAN) | ES256 | - | âœ… Pass |
| 08 | Fetch authorization | ES256 | - | âœ… Pass |
| 09 | Respond to challenge | ES256 | HTTP-01 | âœ… Pass |
| 10 | Serve HTTP-01 standalone + curl | ES256 | HTTP-01 | âœ… Pass |
| 11 | Serve HTTP-01 - port busy | ES256 | HTTP-01 | âœ… Pass |
| 12 | Show DNS-01 instructions | ES256 | DNS-01 | âœ… Pass |
| 13 | Finalize order | ES256 | - | âœ… Pass |
| 14 | Poll order status | ES256 | - | âœ… Pass |
| 15 | Download certificate | ES256 | - | âœ… Pass |
| 16 | Revoke cert + double-revoke error | ES256 | - | âœ… Pass |
| 17 | Revoke with reason code (4=superseded) | ES256 | - | âœ… Pass |
| 18 | Account deactivation | ES256 | - | âœ… Pass |
| 19 | Order after deactivation (rejected) | ES256 | - | âœ… Pass |
| 20 | Full e2e run + cert issuance | ES256 | HTTP-01 | âœ… Pass |
| 20 | Full e2e run + cert issuance | ES384 | HTTP-01 | âœ… Pass |
| 20 | Full e2e run + revoke | ES512 | HTTP-01 | âœ… Pass |
| 20 | Full e2e run + revoke | RSA2048 | HTTP-01 | âœ… Pass |
| 20 | Full e2e run + revoke | Ed25519 | HTTP-01 | âœ… Pass |
| 23 | Environment variable configuration | ES256 | - | âœ… Pass |
| 24 | Global args after subcommand | ES256 | - | âœ… Pass |
| 25 | Missing key file | - | - | âœ… Pass |
| 26 | Invalid directory URL | ES256 | - | âœ… Pass |
| 27 | Directory 404 | ES256 | - | âœ… Pass |
| 28 | Rejected identifier (name constraints) | ES256 | HTTP-01 | âœ… Pass |
| 29 | `RUST_LOG=debug` verbose output | ES256 | - | âœ… Pass |
| 30 | Wrong port - warning + clean failure | ES256 | HTTP-01 | âœ… Pass |
| 31 | Missing account URL - handled gracefully | ES256 | - | âœ… Pass |
| 22 | Multi-SAN e2e (2 domains) | ES256 | HTTP-01 | âœ… Pass |
| 21 | DNS-01 e2e (interactive) | ES256 | DNS-01 | âœ… Pass |
