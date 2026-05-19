use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use secrecy::SecretString;
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
    /// HTTP connect timeout in seconds (TCP + TLS handshake).
    pub connect_timeout: Option<u64>,
    /// Allow private/loopback/link-local destination IPs (SSRF guard opt-out).
    pub allow_private_network: Option<bool>,
    /// DNS-01 propagation check resolver mode: "authoritative", "cached", or "system".
    pub dns_check_mode: Option<String>,
    /// Require DNSSEC validation for DNS-01 propagation checks.
    pub dns_check_dnssec: Option<bool>,
    /// Downgrade hook ownership/permission violations to warnings (SEC-13 opt-out).
    pub unsafe_hooks: Option<bool>,
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
    pub eab_hmac_key: Option<SecretString>,
    /// Pre-authorize identifiers via newAuthz before creating the order.
    pub pre_authorize: Option<bool>,
    /// Use ACME Renewal Information (RFC 9702) to decide when to renew.
    pub ari: Option<bool>,
    /// Reissue the certificate if requested domains differ from existing cert's SANs.
    pub reissue_on_mismatch: Option<bool>,
    /// Print the certificate PEM to stdout after issuance.
    pub print_cert: Option<bool>,
    /// Policy for dns-persist-01 records.
    pub persist_policy: Option<String>,
    /// Unix timestamp for dns-persist-01 persistUntil parameter.
    pub persist_until: Option<u64>,
    /// Domain names.
    pub domains: Option<Vec<String>>,
    /// Certificate key algorithm: "ec-p256", "ec-p384", or "ed25519".
    pub cert_key_algorithm: Option<String>,
    /// Certificate profile (draft-ietf-acme-profiles-01).
    pub profile: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// Contact email addresses.
    pub contact: Option<Vec<String>>,
    /// EAB Key ID from the CA.
    pub eab_kid: Option<String>,
    /// EAB HMAC key (base64url-encoded).
    pub eab_hmac_key: Option<SecretString>,
}

// ── Loading ─────────────────────────────────────────────────────────────────

impl Config {
    /// Load a config file from the given path. Returns an error if the file
    /// cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let config: Self = toml::from_str(&content)
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
    include_str!("../acme-client-rs.toml.example")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-07 regression: Debug-formatting a populated config must NOT leak
    /// the EAB HMAC secret. `SecretString` redacts itself in Debug output.
    #[test]
    fn debug_format_redacts_eab_hmac_key() {
        let secret_value = "super-secret-hmac-key-value-do-not-leak";
        let cfg = Config {
            global: GlobalConfig::default(),
            run: RunConfig {
                eab_hmac_key: Some(SecretString::from(secret_value.to_string())),
                ..Default::default()
            },
            account: AccountConfig {
                eab_hmac_key: Some(SecretString::from(secret_value.to_string())),
                ..Default::default()
            },
        };
        let debug_output = format!("{cfg:?}");
        assert!(
            !debug_output.contains(secret_value),
            "SECURITY: Debug output leaked HMAC secret: {debug_output}"
        );
    }
}
