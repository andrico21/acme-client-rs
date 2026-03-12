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
- Output: `es256 account key saved to test-account.key`
- File `test-account.key` is created containing a PEM-encoded EC private key

**Verify:**

```sh
# Check it's a valid EC key
openssl ec -in test-account.key -text -noout
```

Should show `ASN1 OID: prime256v1` (P-256).

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
acme --account-key test-account.key account
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
- Error message: `Error: failed to bind HTTP-01 server on port 5002: ...`

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

## TC-33: --insecure Flag (Self-Signed CA)

**Goal:** Verify that `--insecure` allows connecting to a CA with a self-signed certificate.

```sh
# Without --insecure: should fail with TLS error
acme --account-key test-account.key account --contact test@example.com
# Expected: TLS handshake error

# With --insecure: should succeed
acme --insecure --account-key test-account.key account --contact test@example.com
# Expected: Account status: valid
```

**Expected:**
- Without `--insecure`: exit code 1, TLS certificate verification error
- With `--insecure`: exit code 0, account created successfully

---

## TC-34: Key Rollover

**Goal:** Rotate the account key to a new key pair.

```sh
# Generate a new key
acme generate-key --account-key new-account.key

# Roll over
acme --insecure --account-key test-account.key --account-url <account-url> key-rollover --new-key new-account.key
```

**Expected:**
- Exit code: 0
- Output: `Account key rolled over successfully` followed by `From now on, use the new key: new-account.key`
- Subsequent requests must use `new-account.key`

---

## TC-35: Pre-Authorize (Standalone)

**Goal:** Pre-authorize an identifier before placing an order.

> Note: Not all ACME servers support pre-authorization. The server must advertise a `newAuthz` URL.

```sh
acme --insecure --account-key test-account.key --account-url <account-url> pre-authorize --domain preauth.example.com --challenge-type http-01
```

**Expected:**
- If server supports newAuthz: exit code 0, authorization and challenge details printed
- If server does not support newAuthz: exit code 1, clear error message

---

## TC-36: Pre-Authorize via run --pre-authorize

**Goal:** The `run` subcommand pre-authorizes identifiers before creating the order.

```sh
acme --insecure --account-key test-account.key run --contact test@example.com --challenge-type http-01 --http-port 5002 --pre-authorize preauth-run.example.com
```

**Expected:**
- Exit code: 0 (or clear error if server does not support newAuthz)
- If supported: pre-authorization happens before order creation

---

## TC-37: EAB Account Registration

**Goal:** Register an account with External Account Binding.

> Requires a CA configured to require EAB (e.g., Pebble with `externalAccountBindingRequired: true`).

```sh
acme --insecure --account-key eab-account.key account --contact eab@example.com --eab-kid kid-1 --eab-hmac-key dGVzdGtleQ
```

**Expected:**
- Exit code: 0
- Output: `Account status: valid`
- Server creates account with EAB binding

---

## TC-38: EAB Full E2E Flow

**Goal:** Run the full ACME flow with EAB credentials.

```sh
acme generate-key --account-key eab-e2e.key

acme --insecure --account-key eab-e2e.key run --contact eab@example.com --challenge-type http-01 --http-port 5002 --eab-kid kid-2 --eab-hmac-key dGVzdGtleTI eab-test.example.com
```

**Expected:**
- Exit code: 0
- Certificate issued successfully

---

## TC-39: EAB Rejection (Missing EAB on EAB-Required Server)

**Goal:** Verify the client shows a clear error when EAB is required but not provided.

```sh
acme --insecure --account-key no-eab.key account --contact test@example.com
```

**Expected:**
- Exit code: 1
- Error: `server requires External Account Binding` (or equivalent ACME error)

---

## TC-40: Renewal Info - Query ARI (RFC 9702)

**Goal:** Query the ACME server's renewal information for an existing certificate.

> Requires a server that supports ARI (e.g., Pebble 2.1.0+ or Let's Encrypt).

```sh
# First, issue a certificate
acme --insecure --account-key test-account.key run --contact test@example.com --challenge-type http-01 --http-port 5002 --cert-output ari-test-cert.pem --key-output ari-test-key.pem ari-test.example.com

# Query renewal info
acme --insecure --account-key test-account.key --account-url <account-url> renewal-info ari-test-cert.pem
```

**Expected:**
- Exit code: 0
- Output includes:
  ```
  CertID:   <base64url(AKI)>.<base64url(Serial)>
  Suggested renewal window:
    Start:  <RFC 3339 timestamp>
    End:    <RFC 3339 timestamp>
  Status:   not yet due (N days until window opens)
  ```
- If server does not support ARI: exit code 1, error: `server does not support ARI (no renewalInfo in directory)`

---

## TC-41: Renewal Info - JSON Output

**Goal:** Verify `renewal-info` outputs structured JSON for machine consumption.

```sh
acme --insecure --account-key test-account.key --account-url <account-url> --output-format json renewal-info ari-test-cert.pem
```

**Expected:**
- Exit code: 0
- Output is a single JSON object:
  ```json
  {
    "command": "renewal-info",
    "cert_id": "<base64url(AKI)>.<base64url(Serial)>",
    "suggested_window": {
      "start": "<RFC 3339 timestamp>",
      "end": "<RFC 3339 timestamp>"
    },
    "retry_after": null
  }
  ```

---

## TC-42: Run with --ari (Renewal)

**Goal:** The `run` subcommand uses ARI to decide when to renew and includes `replaces` in the order.

```sh
# Issue an initial certificate
acme --insecure --account-key test-account.key run --contact test@example.com --challenge-type http-01 --http-port 5002 --cert-output ari-run-cert.pem --key-output ari-run-key.pem ari-run.example.com

# Re-run with --ari (should renew if window is open, or skip if not)
acme --insecure --account-key test-account.key run --contact test@example.com --challenge-type http-01 --http-port 5002 --cert-output ari-run-cert.pem --key-output ari-run-key.pem --ari ari-run.example.com
```

**Expected:**
- Exit code: 0
- If the ARI window is open: renews the certificate; with `RUST_LOG=debug`, log shows `Using ARI replaces field`
- If the ARI window has not opened: prints `ARI: renewal window starts <timestamp> - skipping renewal`
- If server doesn't support ARI: warns and falls through to `--days` check (or proceeds with renewal if no `--days`)

---

## TC-43: Run with --ari and --days (Fallback)

**Goal:** When `--ari` is used with `--days`, ARI takes priority; `--days` is the fallback.

```sh
acme --insecure --account-key test-account.key run --contact test@example.com --challenge-type http-01 --http-port 5002 --cert-output ari-days-cert.pem --key-output ari-days-key.pem --ari --days 30 ari-days.example.com
```

**Expected:**
- Exit code: 0
- If ARI is available: uses ARI window to decide
- If ARI fails or is unsupported: falls back to `--days 30` threshold check
- With `RUST_LOG=debug`: shows whether ARI or `--days` was used for the decision

---

## TC-44: Renewal Info - Server Without ARI Support

**Goal:** Clear error when querying ARI on a server that doesn't support it.

```sh
# Use a server without renewalInfo in its directory
acme --insecure --account-key test-account.key --directory https://non-ari-server/directory renewal-info some-cert.pem
```

**Expected:**
- Exit code: 1
- Error: `server does not support ARI (no renewalInfo in directory)`

---

## TC-45: Show DNS-PERSIST-01 Instructions

**Goal:** Display the persistent TXT record value for dns-persist-01 validation.

```sh
acme --insecure --account-key test-account.key show-dns-persist01 --domain test.example.com --issuer-domain-name letsencrypt.org
```

**Expected:**
- Exit code: 0
- Output:
  ```
  === DNS-PERSIST-01 Record ===
  Name:  _validation-persist.test.example.com
  Type:  TXT
  Value: letsencrypt.org; accounturi=https://localhost:14000/my-account/<id>
  ```
- Command exits immediately (display only, no interactive wait)

---

## TC-46: Show DNS-PERSIST-01 - With Policy and PersistUntil

**Goal:** Verify the `--persist-policy` and `--persist-until` flags are included in the record value.

```sh
acme --insecure --account-key test-account.key show-dns-persist01 --domain test.example.com --issuer-domain-name letsencrypt.org --persist-policy wildcard --persist-until 1767225600
```

**Expected:**
- Exit code: 0
- Value includes `; policy=wildcard; persistUntil=1767225600`

---

## TC-47: Show DNS-PERSIST-01 - JSON Output

**Goal:** Verify `show-dns-persist01` outputs structured JSON for machine consumption.

```sh
acme --insecure --account-key test-account.key --output-format json show-dns-persist01 --domain test.example.com --issuer-domain-name letsencrypt.org --persist-policy wildcard
```

**Expected:**
- Exit code: 0
- Output is a single JSON object with `txt_name`, `txt_value`, `domain`, `issuer_domain_name` fields

---

## TC-48: Full End-to-End Flow (DNS-PERSIST-01)

**Goal:** Run the automated flow with DNS-PERSIST-01 (interactive - pauses for DNS record setup).

> Requires Pebble with dns-persist-01 support and `PEBBLE_VA_ALWAYS_VALID=1`.

```sh
acme --insecure --account-key e2e-account.key run --contact e2e@example.com --challenge-type dns-persist-01 dns-persist-test.example.com
```

**Expected:**
- Prints DNS-PERSIST-01 TXT record instructions with `_validation-persist.` prefix
- Shows the issuer domain names from the server
- Waits for Enter keypress
- After pressing Enter, proceeds through finalization
- With `PEBBLE_VA_ALWAYS_VALID=1`, completes successfully
- No cleanup action (records are persistent by design)

---

## TC-49: DNS-PERSIST-01 with Hook Script

**Goal:** Verify `--dns-hook` works with dns-persist-01 (create only, no cleanup).

```sh
acme --insecure --account-key e2e-account.key run --contact e2e@example.com --challenge-type dns-persist-01 --dns-hook /usr/local/bin/dns-hook.sh dns-persist-hook.example.com
```

**Expected:**
- Hook called with `ACME_ACTION=create`, `ACME_TXT_NAME=_validation-persist.dns-persist-hook.example.com`
- No `ACME_ACTION=cleanup` call (records persist)
- Certificate issued successfully

---

## TC-50: DNS-PERSIST-01 - IP Identifier Rejection

**Goal:** Verify dns-persist-01 rejects IP identifiers with a clear error.

```sh
acme --insecure --account-key e2e-account.key run --contact e2e@example.com --challenge-type dns-persist-01 192.0.2.1
```

**Expected:**
- Exit code: 1
- Error: DNS-based challenges are not supported for IP identifiers

---

## TC-51: Generate Config Template

**Goal:** Verify `generate-config` outputs a valid, parseable TOML template with all documented options.

```sh
acme generate-config > test-config.toml
```

**Expected:**
- Exit code: 0
- Output is valid TOML (all values are commented out)
- Contains `[global]`, `[run]`, and `[account]` sections
- All CLI options are documented in comments

---

## TC-52: Show Config - Defaults Only

**Goal:** Verify `show-config` displays the effective configuration when no config file is loaded.

```sh
acme show-config
```

**Expected:**
- Exit code: 0
- Shows `Config file: (none)` or similar
- All values are built-in defaults (e.g., `directory = https://localhost:14000/dir`)

---

## TC-53: Show Config - With Config File

**Goal:** Verify `show-config` merges values from a config file.

```sh
cat > test-config.toml <<EOF
[global]
directory = "https://acme.example.com/dir"
account_key = "/etc/acme/account.key"

[run]
domains = ["example.com", "www.example.com"]
contact = "admin@example.com"
cert_output = "/etc/ssl/certs/example.pem"
days = 30
EOF

acme --config test-config.toml show-config
```

**Expected:**
- Exit code: 0
- `directory` shows the value from the config file
- `domains` shows `["example.com", "www.example.com"]`
- Non-configured values show built-in defaults

---

## TC-54: Show Config - Verbose Source Annotations

**Goal:** Verify `show-config --verbose` annotates each value with its source.

```sh
ACME_INSECURE=true acme --config test-config.toml -d https://override.example.com/dir show-config --verbose
```

**Expected:**
- Exit code: 0
- `directory` shows `(cli)` annotation (CLI override)
- `insecure` shows `(env)` annotation (environment variable)
- `account_key` shows `(config)` annotation (config file)
- `http_port` shows `(default)` annotation (built-in default)

---

## TC-55: Config File - CLI Override Priority

**Goal:** Verify CLI flags override config file values.

```sh
acme --config test-config.toml -d https://cli-override.example.com/dir show-config
```

**Expected:**
- Exit code: 0
- `directory` shows `https://cli-override.example.com/dir` (CLI wins over config)
- Other config file values are preserved

---

## TC-56: Config File - Invalid TOML

**Goal:** Verify a clear error on malformed config file.

```sh
echo "not valid [toml" > bad-config.toml
acme --config bad-config.toml show-config
```

**Expected:**
- Exit code: 1
- Error message mentions TOML parse failure

---

## TC-57: Config File - Unknown Field Rejection

**Goal:** Verify unknown fields in the config file are rejected (`deny_unknown_fields`).

```sh
cat > bad-field.toml <<EOF
[global]
nonexistent_option = "value"
EOF

acme --config bad-field.toml show-config
```

**Expected:**
- Exit code: 1
- Error message mentions unknown field

---

## Summary Matrix

| TC | Command | Challenge | Expectation |
|----|---------|-----------|-------------|
| 01 | `generate-key` | - | Key file created |
| 02 | `generate-key` (overwrite) | - | File replaced |
| 03 | `account` | - | Account created |
| 04 | `account` (idempotent) | - | Same account returned |
| 05 | `account` (no contact) | - | Account created |
| 06 | `order` (single) | - | Order pending |
| 07 | `order` (multi SAN) | - | Multiple authz URLs |
| 08 | `get-authz` | - | Challenges listed |
| 09 | `respond-challenge` | - | Challenge progresses |
| 10 | `serve-http01` | HTTP-01 | Token served |
| 11 | `serve-http01` (port busy) | HTTP-01 | Clear error |
| 12 | `show-dns01` | DNS-01 | TXT instructions |
| 13 | `finalize` | - | CSR submitted |
| 14 | `poll-order` | - | Status returned |
| 15 | `download-cert` | - | PEM saved |
| 16 | `revoke-cert` | - | Cert revoked |
| 17 | `revoke-cert` (reason) | - | Revoked with code |
| 18 | `deactivate-account` | - | Account deactivated |
| 19 | Operations post-deactivation | - | Rejected |
| 20 | `run` (e2e) | HTTP-01 | Full flow succeeds |
| 21 | `run` (e2e) | DNS-01 | Interactive flow |
| 22 | `run` (multi-SAN) | HTTP-01 | Multi-domain cert |
| 23 | Env vars | - | Config from env |
| 24 | Global args after subcmd | - | Args accepted |
| 25 | Missing key file | - | Clear error |
| 26 | Invalid directory URL | - | Clear error |
| 27 | Directory 404 | - | Clear error |
| 28 | Rejected identifier | - | Clean ACME error |
| 29 | `RUST_LOG=debug` | - | Verbose output |
| 30 | Custom HTTP port | HTTP-01 | Binds correctly |
| 31 | Missing account URL | - | Handled gracefully |
| 32 | badNonce retry | - | Auto-retry works |
| 33 | `--insecure` flag | - | TLS skip works |
| 34 | `key-rollover` | - | Key rotated |
| 35 | `pre-authorize` (standalone) | - | Identifier pre-authorized |
| 36 | `run --pre-authorize` | HTTP-01 | Pre-auth before order |
| 37 | `account` + EAB | - | EAB binding accepted |
| 38 | `run` + EAB (e2e) | HTTP-01 | Full flow with EAB |
| 39 | EAB rejection | - | Clear error |
| 40 | `renewal-info` (ARI) | - | Window shown |
| 41 | `renewal-info` (JSON) | - | Structured JSON |
| 42 | `run --ari` | HTTP-01 | ARI-guided renewal |
| 43 | `run --ari --days` | HTTP-01 | ARI with days fallback |
| 44 | `renewal-info` (no ARI server) | - | Clear error |
| 45 | `show-dns-persist01` | DNS-PERSIST-01 | TXT instructions |
| 46 | `show-dns-persist01` (policy+until) | DNS-PERSIST-01 | Extended record value |
| 47 | `show-dns-persist01` (JSON) | DNS-PERSIST-01 | Structured JSON |
| 48 | `run` (e2e) | DNS-PERSIST-01 | Interactive flow |
| 49 | `run` + dns-hook | DNS-PERSIST-01 | Create only, no cleanup |
| 50 | DNS-PERSIST-01 + IP identifier | DNS-PERSIST-01 | Clear rejection |
| 51 | `generate-config` | - | Valid TOML template |
| 52 | `show-config` (defaults) | - | Default values shown |
| 53 | `show-config` (config file) | - | Merged values shown |
| 54 | `show-config --verbose` | - | Source annotations |
| 55 | Config CLI override priority | - | CLI wins over config |
| 56 | Config invalid TOML | - | Clear error |
| 57 | Config unknown field | - | Rejected |

---

## Live Test Results

Tested against a **step-ca** ACME server on **2026-03-11** using version **1.3.2**.

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
