use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Default config file name (auto-loaded from current directory if present).
pub const DEFAULT_CONFIG_FILE: &str = "acme-client-rs.toml";

// ── Config structs (all fields optional - CLI/env override) ─────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Global options (directory, account key, etc.)
    #[serde(default)]
    pub global: GlobalConfig,

    /// Options for the `run` subcommand.
    #[serde(default)]
    pub run: RunConfig,

    /// Options for the `account` subcommand.
    #[serde(default)]
    pub account: AccountConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalConfig {
    /// ACME server directory URL.
    pub directory: Option<String>,
    /// Path to the account key (PKCS#8 PEM).
    pub account_key: Option<PathBuf>,
    /// Account URL (after account creation).
    pub account_url: Option<String>,
    /// Output format: "text" or "json".
    pub output_format: Option<String>,
    /// Disable TLS certificate verification.
    pub insecure: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunConfig {
    /// Contact email address.
    pub contact: Option<String>,
    /// Challenge type: "http-01", "dns-01", "dns-persist-01", or "tls-alpn-01".
    pub challenge_type: Option<String>,
    /// HTTP-01 server port (standalone mode).
    pub http_port: Option<u16>,
    /// Write HTTP-01 challenge files to this directory.
    pub challenge_dir: Option<PathBuf>,
    /// Path to a DNS-01 hook script.
    pub dns_hook: Option<PathBuf>,
    /// Wait up to N seconds for DNS TXT propagation.
    pub dns_wait: Option<u64>,
    /// Max concurrent DNS propagation checks.
    pub dns_propagation_concurrency: Option<usize>,
    /// Max seconds to wait for challenge validation.
    pub challenge_timeout: Option<u64>,
    /// Save the certificate to this file.
    pub cert_output: Option<PathBuf>,
    /// Save the private key to this file.
    pub key_output: Option<PathBuf>,
    /// Skip renewal if existing certificate has more than N days remaining.
    pub days: Option<u32>,
    /// Read the private key encryption password from a file.
    pub key_password_file: Option<PathBuf>,
    /// Run a script after each challenge is ready for validation.
    pub on_challenge_ready: Option<PathBuf>,
    /// Run a script after the certificate is issued and saved.
    pub on_cert_issued: Option<PathBuf>,
    /// EAB Key ID from the CA.
    pub eab_kid: Option<String>,
    /// EAB HMAC key (base64url-encoded).
    pub eab_hmac_key: Option<String>,
    /// Pre-authorize identifiers via newAuthz before creating the order.
    pub pre_authorize: Option<bool>,
    /// Use ACME Renewal Information (RFC 9702) to decide when to renew.
    pub ari: Option<bool>,
    /// Policy for dns-persist-01 records.
    pub persist_policy: Option<String>,
    /// Unix timestamp for dns-persist-01 persistUntil parameter.
    pub persist_until: Option<u64>,
    /// Domain names.
    pub domains: Option<Vec<String>>,
    /// Certificate key algorithm: "ec-p256", "ec-p384", or "ed25519".
    pub cert_key_algorithm: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// Contact email addresses.
    pub contact: Option<Vec<String>>,
    /// EAB Key ID from the CA.
    pub eab_kid: Option<String>,
    /// EAB HMAC key (base64url-encoded).
    pub eab_hmac_key: Option<String>,
}

// ── Loading ─────────────────────────────────────────────────────────────────

impl Config {
    /// Load a config file from the given path. Returns an error if the file
    /// cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        Ok(config)
    }

    /// Check whether the default config file exists in the current directory.
    pub fn default_exists() -> bool {
        Path::new(DEFAULT_CONFIG_FILE).exists()
    }
}

// ── Self-documented template ────────────────────────────────────────────────

/// Return a fully commented TOML config template.
pub fn generate_template() -> &'static str {
    r#"# acme-client-rs configuration file
# All fields are optional. CLI flags always override config file values.
#
# When a config file is loaded (--config or ACME_CONFIG), environment variables
# are IGNORED except for secrets: key passwords, EAB credentials, and --insecure.
# Priority with config: CLI flags > config file > built-in defaults.
# Priority without config: CLI flags > environment variables > built-in defaults.
#
# Load this file with --config <PATH> or set ACME_CONFIG=<PATH>.

# ── Global options ───────────────────────────────────────────────────────────
# These apply to all subcommands.

[global]

# ACME server directory URL.
# CLI: --directory / -d
# Env: ACME_DIRECTORY_URL
# Default: "https://localhost:14000/dir"
# directory = "https://acme-v02.api.letsencrypt.org/directory"

# Path to the account key (PKCS#8 PEM).
# CLI: --account-key / -k
# Env: ACME_ACCOUNT_KEY_FILE
# Default: "account.key"
# account_key = "/etc/acme/account.key"

# Account URL (set after creating an account with the `account` subcommand).
# CLI: --account-url / -a
# Env: ACME_ACCOUNT_URL
# account_url = "https://acme-v02.api.letsencrypt.org/acme/acct/123456789"

# Output format: "text" (human-readable) or "json" (machine-readable).
# CLI: --output-format
# Env: ACME_OUTPUT_FORMAT
# Default: "text"
# output_format = "json"

# Disable TLS certificate verification. Only use for testing with self-signed
# CAs like Pebble - never in production.
# CLI: --insecure
# Env: ACME_INSECURE
# Default: false
# insecure = true

# ── Run subcommand options ───────────────────────────────────────────────────
# These apply when using `acme-client-rs run`.

[run]

# Domain names to include in the certificate.
# CLI: positional arguments after `run`
# domains = ["example.com", "www.example.com"]

# Contact email address for the ACME account.
# CLI: --contact
# contact = "admin@example.com"

# Challenge type: "http-01", "dns-01", "dns-persist-01", or "tls-alpn-01".
# CLI: --challenge-type
# Default: "http-01"
# challenge_type = "http-01"

# Port for the built-in HTTP-01 challenge server (standalone mode).
# CLI: --http-port
# Default: 80
# http_port = 80

# Write HTTP-01 challenge files to this directory instead of starting a server.
# Useful when you have an existing web server (nginx, Apache, etc.).
# CLI: --challenge-dir
# challenge_dir = "/var/www/acme"

# Path to a DNS-01/DNS-PERSIST-01 hook script.
# The script is called with environment variables: ACME_ACTION, ACME_DOMAIN,
# ACME_TXT_NAME, ACME_TXT_VALUE. For both dns-01 and dns-persist-01,
# ACME_ACTION is "create" before validation or "cleanup" after.
# CLI: --dns-hook
# dns_hook = "/usr/local/bin/dns-hook.sh"

# Wait up to N seconds for DNS TXT record propagation (polls every 5 seconds).
# Can be used with --dns-hook (fully automated) or alone (manual + auto-wait).
# CLI: --dns-wait
# dns_wait = 120

# Maximum number of concurrent DNS propagation checks when using --dns-hook
# with multiple domains. Each domain's TXT record is polled in parallel,
# capped at this limit to avoid overwhelming DNS servers.
# CLI: --dns-propagation-concurrency
# Default: 5
# dns_propagation_concurrency = 5

# Maximum seconds to wait for challenge validation after responding.
# Applies to all challenge types. Polls every 2 seconds until valid or timeout.
# CLI: --challenge-timeout
# Default: 300
# challenge_timeout = 300

# Path to save the issued certificate (PEM format, end-entity + intermediates).
# CLI: --cert-output
# Default: "certificate.pem"
# cert_output = "/etc/ssl/certs/example.com.pem"

# Path to save the private key (PKCS#8 PEM format).
# CLI: --key-output
# Default: "private.key"
# key_output = "/etc/ssl/private/example.com.key"

# Renewal mode: skip issuance if the existing certificate at cert_output has
# more than N days remaining. Makes `run` idempotent for cron/scheduled tasks.
# The command exits 0 whether it renewed or skipped.
# CLI: --days
# days = 30

# Path to a file containing the password to encrypt the private key
# (PKCS#8 + AES-256-CBC with scrypt KDF). First line is used, trailing newline stripped.
# CLI: --key-password-file
# Env: ACME_KEY_PASSWORD_FILE
# key_password_file = "/etc/acme/key-password.txt"

# Hook script run after each challenge is set up and ready for validation.
# Environment variables: ACME_DOMAIN, ACME_CHALLENGE_TYPE, ACME_TOKEN (dns-01/tls-alpn-01),
# ACME_KEY_AUTH (dns-01/tls-alpn-01), ACME_TXT_NAME (dns-01/dns-persist-01),
# ACME_TXT_VALUE (dns-01/dns-persist-01).
# CLI: --on-challenge-ready
# on_challenge_ready = "/usr/local/bin/reload-nginx.sh"

# Hook script run after the certificate is issued and saved to disk.
# Environment variables: ACME_DOMAINS, ACME_CERT_PATH, ACME_KEY_PATH, ACME_KEY_ENCRYPTED.
# CLI: --on-cert-issued
# on_cert_issued = "/usr/local/bin/deploy-cert.sh"

# EAB Key ID from the CA (for CAs that require External Account Binding).
# Must be set together with eab_hmac_key.
# CLI: --eab-kid
# Env: ACME_EAB_KID
# eab_kid = "kid-from-ca"

# EAB HMAC key (base64url-encoded, from the CA).
# Must be set together with eab_kid.
# CLI: --eab-hmac-key
# Env: ACME_EAB_HMAC_KEY
# eab_hmac_key = "base64url-encoded-hmac-key"

# Pre-authorize identifiers via newAuthz before creating the order
# (RFC 8555 Section 7.4.1). Not all servers support this.
# CLI: --pre-authorize
# Default: false
# pre_authorize = true

# Use ACME Renewal Information (RFC 9702) to decide when to renew.
# Queries the CA's suggested renewal window. Falls back to `days` if unavailable.
# CLI: --ari
# Default: false
# ari = true

# Policy for dns-persist-01 records (e.g., "wildcard").
# CLI: --persist-policy
# persist_policy = "wildcard"

# Unix timestamp for dns-persist-01 persistUntil parameter.
# After this time, the record should not be used for new validations.
# CLI: --persist-until
# persist_until = 1767225600

# Certificate key algorithm for CSR generation.
# Supported values: "ec-p256" (ECDSA P-256), "ec-p384" (ECDSA P-384), "ed25519".
# CLI: --cert-key-algorithm
# Default: "ec-p256"
# cert_key_algorithm = "ec-p256"

# ── Account subcommand options ───────────────────────────────────────────────
# These apply when using `acme-client-rs account`.

[account]

# Contact email addresses.
# CLI: --contact (repeatable)
# contact = ["admin@example.com"]

# EAB Key ID from the CA.
# CLI: --eab-kid
# Env: ACME_EAB_KID
# eab_kid = "kid-from-ca"

# EAB HMAC key (base64url-encoded, from the CA).
# CLI: --eab-hmac-key
# Env: ACME_EAB_HMAC_KEY
# eab_hmac_key = "base64url-encoded-hmac-key"
"#
}
