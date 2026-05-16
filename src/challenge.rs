//! ACME challenge handlers for HTTP-01, DNS-01, and TLS-ALPN-01.
//!
//! Each sub-module computes the required proof material per RFC 8555 §8.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::jws::AccountKey;

/// Key authorization string (RFC 8555 §8.1):
///   `keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))`
pub fn key_authorization(token: &str, account_key: &AccountKey) -> String {
    format!("{}.{}", token, account_key.thumbprint())
}

// ── HTTP-01 (RFC 8555 §8.3) ────────────────────────────────────────────────

pub mod http01 {
    use super::*;
    use anyhow::{bail, Context, Result};
    use std::path::{Path, PathBuf};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing::info;

    /// Maximum accepted token length (defensive upper bound; real ACME tokens
    /// are ~43 base64url chars from 32 random bytes, but the RFC does not
    /// fix a length).
    const MAX_TOKEN_LEN: usize = 128;

    /// Validate an ACME HTTP-01 challenge token before using it as a path
    /// segment or URL component.
    ///
    /// RFC 8555 §8.3 requires the token to be a base64url string. We accept
    /// only `[A-Za-z0-9_-]{1,128}` and reject anything that could be
    /// interpreted as a path traversal, separator, or empty segment. This
    /// guards against a malicious or compromised ACME server (or unsafe
    /// `serve-http01 --token` input) writing/removing files outside the
    /// challenge directory.
    pub fn validate_token(token: &str) -> Result<()> {
        if token.is_empty() {
            bail!("ACME challenge token is empty");
        }
        if token.len() > MAX_TOKEN_LEN {
            bail!(
                "ACME challenge token is {} bytes; refusing (max {})",
                token.len(),
                MAX_TOKEN_LEN
            );
        }
        for b in token.as_bytes() {
            let ok = matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_');
            if !ok {
                bail!(
                    "ACME challenge token contains invalid character {:?}; \
                     expected base64url alphabet [A-Za-z0-9_-]",
                    *b as char
                );
            }
        }
        Ok(())
    }

    /// The key authorization value to serve as the response body.
    pub fn response_body(token: &str, account_key: &AccountKey) -> String {
        key_authorization(token, account_key)
    }

    /// The well-known path the ACME server will request.
    pub fn challenge_path(token: &str) -> String {
        format!("/.well-known/acme-challenge/{token}")
    }

    /// Write the challenge token file into `<dir>/.well-known/acme-challenge/`.
    ///
    /// Returns the full path to the written file (for cleanup).
    ///
    /// The token is validated against [`validate_token`] before any
    /// filesystem operation. The file itself is created with `O_NOFOLLOW`
    /// where supported to avoid following an attacker-planted symlink in a
    /// shared webroot.
    pub fn write_challenge_file(
        challenge_dir: &Path,
        token: &str,
        account_key: &AccountKey,
    ) -> Result<PathBuf> {
        validate_token(token)?;
        let auth = response_body(token, account_key);
        let well_known = challenge_dir.join(".well-known").join("acme-challenge");
        std::fs::create_dir_all(&well_known).with_context(|| {
            format!(
                "failed to create challenge directory {}",
                well_known.display()
            )
        })?;
        let file_path = well_known.join(token);

        use std::fs::OpenOptions;
        use std::io::Write;
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // 0o644 — challenge file must be world-readable for the webroot
            // mode of HTTP-01 (web server reads as a different user).
            opts.mode(0o644);
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut f = opts.open(&file_path).with_context(|| {
            format!(
                "failed to open challenge file {} (refused to follow symlink?)",
                file_path.display()
            )
        })?;
        f.write_all(auth.as_bytes()).with_context(|| {
            format!("failed to write challenge file {}", file_path.display())
        })?;
        info!("HTTP-01: wrote challenge to {}", file_path.display());
        Ok(file_path)
    }

    /// Remove a previously written challenge file (best-effort).
    pub fn cleanup_challenge_file(path: &Path) {
        if path.exists() {
            if let Err(e) = std::fs::remove_file(path) {
                tracing::warn!("failed to clean up challenge file {}: {e}", path.display());
            } else {
                info!("HTTP-01: cleaned up {}", path.display());
            }
        }
    }

    /// Try to bind a TCP listener on the given port.
    ///
    /// If the port is already in use, returns a user-friendly error
    /// suggesting `--challenge-dir`.
    pub async fn bind_or_suggest(
        port: u16,
    ) -> Result<tokio::net::TcpListener> {
        match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
            Ok(listener) => Ok(listener),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                bail!(
                    "port {port} is already in use (reverse proxy or other server?)\n\
                     \n\
                     Hint: use --challenge-dir <DIR> to write the challenge file\n\
                     to a directory your existing web server already serves, e.g.:\n\
                     \n\
                     acme-client-rs run example.com --challenge-dir /var/www/html"
                );
            }
            Err(e) => {
                Err(e).with_context(|| format!("failed to bind HTTP-01 server on port {port}"))
            }
        }
    }

    /// Spin up a minimal TCP server that answers exactly one validation
    /// request and then shuts down.
    pub async fn serve(token: &str, account_key: &AccountKey, port: u16) -> Result<()> {
        let auth = response_body(token, account_key);
        let path = challenge_path(token);

        let listener = bind_or_suggest(port).await?;
        info!("HTTP-01 server listening on 0.0.0.0:{port}");

        loop {
            let (mut stream, addr) = listener.accept().await?;
            info!("HTTP-01: connection from {addr}");

            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await?;
            let request = String::from_utf8_lossy(&buf[..n]);

            if request.contains(&path) {
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/octet-stream\r\n\
                     Content-Length: {}\r\n\
                     \r\n\
                     {}",
                    auth.len(),
                    auth
                );
                stream.write_all(response.as_bytes()).await?;
                info!("HTTP-01: served challenge response");
                return Ok(());
            }
            let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(not_found.as_bytes()).await?;
        }
    }
}

// ── DNS-01 (RFC 8555 §8.4) ─────────────────────────────────────────────────

pub mod dns01 {
    use super::*;
    use crate::outln;

    /// The value for the `_acme-challenge.<domain>` TXT record:
    ///   `base64url(SHA-256(keyAuthorization))`
    pub fn txt_record_value(token: &str, account_key: &AccountKey) -> String {
        let auth = key_authorization(token, account_key);
        let digest = Sha256::digest(auth.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }

    /// Full DNS record name for the challenge.
    ///
    /// For wildcard identifiers (`*.example.com`), the leading `*.` is
    /// stripped per RFC 8555 §8.4 — the validation record is published
    /// at the base zone, not under a literal `*` label.
    pub fn record_name(domain: &str) -> String {
        let base = domain.strip_prefix("*.").unwrap_or(domain);
        format!("_acme-challenge.{base}")
    }

    /// Print human-readable instructions for manual DNS record setup.
    pub fn print_instructions(domain: &str, token: &str, account_key: &AccountKey) {
        let name = record_name(domain);
        let value = txt_record_value(token, account_key);
        outln!();
        outln!("=== DNS-01 Challenge ===");
        outln!("Create a DNS TXT record:");
        outln!("  Name:  {name}");
        outln!("  Type:  TXT");
        outln!("  Value: {value}");
        outln!();
    }
}

// ── DNS-PERSIST-01 (draft-ietf-acme-dns-persist) ────────────────────────────

pub mod dns_persist01 {
    use crate::outln;
    /// DNS record name for dns-persist-01 validation.
    ///
    /// For wildcard identifiers (`*.example.com`), the leading `*.` is
    /// stripped — the persistent validation record lives at the base zone.
    pub fn record_name(domain: &str) -> String {
        let base = domain.strip_prefix("*.").unwrap_or(domain);
        format!("_validation-persist.{base}")
    }

    /// Construct the TXT record value (RFC 8659 issue-value syntax).
    ///
    ///   `<issuer-domain-name>; accounturi=<uri>[; policy=<p>][; persistUntil=<ts>]`
    pub fn txt_record_value(
        issuer_domain_name: &str,
        account_uri: &str,
        policy: Option<&str>,
        persist_until: Option<u64>,
    ) -> String {
        let mut value = format!("{issuer_domain_name}; accounturi={account_uri}");
        if let Some(p) = policy {
            value.push_str(&format!("; policy={p}"));
        }
        if let Some(ts) = persist_until {
            value.push_str(&format!("; persistUntil={ts}"));
        }
        value
    }

    /// Print human-readable instructions for dns-persist-01 setup.
    pub fn print_instructions(
        domain: &str,
        issuer_domain_names: &[String],
        account_uri: &str,
        policy: Option<&str>,
        persist_until: Option<u64>,
    ) {
        let name = record_name(domain);
        let issuer = &issuer_domain_names[0];
        let value = txt_record_value(issuer, account_uri, policy, persist_until);
        outln!();
        outln!("=== DNS-PERSIST-01 Challenge ===");
        outln!("Create a DNS TXT record:");
        outln!("  Name:  {name}");
        outln!("  Type:  TXT");
        outln!("  Value: {value}");
        if issuer_domain_names.len() > 1 {
            outln!();
            outln!("Available issuer domain names (you may use any one):");
            for idn in issuer_domain_names {
                outln!("  - {idn}");
            }
        }
        outln!();
        outln!("This record is persistent - it can be reused for future issuances.");
        outln!("Unlike dns-01, it does not need to change per issuance.");
        outln!();
    }
}

// ── TLS-ALPN-01 (RFC 8737) ─────────────────────────────────────────────────

pub mod tlsalpn01 {
    use super::*;
    use crate::outln;

    /// ALPN protocol identifier.
    #[allow(dead_code)]
    pub const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

    /// OID for the `acmeIdentifier` certificate extension (1.3.6.1.5.5.7.1.31).
    #[allow(dead_code)]
    pub const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

    /// Compute the DER-encoded `acmeIdentifier` extension value.
    ///
    /// This is the SHA-256 hash of the key authorization wrapped in an ASN.1
    /// OCTET STRING (tag 0x04, length 0x20, 32 bytes of hash).
    pub fn acme_identifier_value(token: &str, account_key: &AccountKey) -> Vec<u8> {
        let auth = key_authorization(token, account_key);
        let hash = Sha256::digest(auth.as_bytes());
        let mut der = Vec::with_capacity(34);
        der.push(0x04); // OCTET STRING tag
        der.push(0x20); // length = 32
        der.extend_from_slice(&hash);
        der
    }

    /// Print human-readable instructions for manual TLS-ALPN-01 setup.
    pub fn print_instructions(domain: &str, token: &str, account_key: &AccountKey) {
        let value = acme_identifier_value(token, account_key);
        let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
        outln!();
        outln!("=== TLS-ALPN-01 Challenge ===");
        outln!("Domain: {domain}");
        outln!("ALPN protocol: acme-tls/1");
        outln!("acmeIdentifier extension (hex): {hex}");
        outln!();
        outln!("Configure a TLS server on port 443 with a self-signed");
        outln!("certificate containing this extension.");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dns01_record_name_strips_wildcard_prefix() {
        assert_eq!(
            super::dns01::record_name("*.example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            super::dns01::record_name("example.com"),
            "_acme-challenge.example.com"
        );
    }

    #[test]
    fn dns_persist01_record_name_strips_wildcard_prefix() {
        assert_eq!(
            super::dns_persist01::record_name("*.example.com"),
            "_validation-persist.example.com"
        );
        assert_eq!(
            super::dns_persist01::record_name("example.com"),
            "_validation-persist.example.com"
        );
    }
}
