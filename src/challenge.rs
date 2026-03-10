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
    use anyhow::{Context, Result};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing::info;

    /// The key authorization value to serve as the response body.
    pub fn response_body(token: &str, account_key: &AccountKey) -> String {
        key_authorization(token, account_key)
    }

    /// The well-known path the ACME server will request.
    pub fn challenge_path(token: &str) -> String {
        format!("/.well-known/acme-challenge/{token}")
    }

    /// Spin up a minimal TCP server that answers exactly one validation
    /// request and then shuts down.
    pub async fn serve(token: &str, account_key: &AccountKey, port: u16) -> Result<()> {
        let auth = response_body(token, account_key);
        let path = challenge_path(token);

        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .with_context(|| format!("failed to bind HTTP-01 server on port {port}"))?;
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

    /// The value for the `_acme-challenge.<domain>` TXT record:
    ///   `base64url(SHA-256(keyAuthorization))`
    pub fn txt_record_value(token: &str, account_key: &AccountKey) -> String {
        let auth = key_authorization(token, account_key);
        let digest = Sha256::digest(auth.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }

    /// Full DNS record name for the challenge.
    pub fn record_name(domain: &str) -> String {
        format!("_acme-challenge.{domain}")
    }

    /// Print human-readable instructions for manual DNS record setup.
    pub fn print_instructions(domain: &str, token: &str, account_key: &AccountKey) {
        let name = record_name(domain);
        let value = txt_record_value(token, account_key);
        println!();
        println!("=== DNS-01 Challenge ===");
        println!("Create a DNS TXT record:");
        println!("  Name:  {name}");
        println!("  Type:  TXT");
        println!("  Value: {value}");
        println!();
        println!("Press Enter once the record has propagated...");
    }
}

// ── TLS-ALPN-01 (RFC 8737) ─────────────────────────────────────────────────

pub mod tlsalpn01 {
    use super::*;

    /// ALPN protocol identifier.
    pub const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

    /// OID for the `acmeIdentifier` certificate extension (1.3.6.1.5.5.7.1.31).
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
        println!();
        println!("=== TLS-ALPN-01 Challenge ===");
        println!("Domain: {domain}");
        println!("ALPN protocol: acme-tls/1");
        println!("acmeIdentifier extension (hex): {hex}");
        println!();
        println!("Configure a TLS server on port 443 with a self-signed");
        println!("certificate containing this extension, then press Enter...");
    }
}
