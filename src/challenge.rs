//! ACME challenge handlers for HTTP-01, DNS-01, and TLS-ALPN-01.
//!
//! Each sub-module computes the required proof material per RFC 8555 §8.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::jws::AccountKey;
use crate::types::ChallengeToken;

/// Key authorization string (RFC 8555 §8.1):
///   `keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))`
pub fn key_authorization(
    token: &ChallengeToken,
    account_key: &AccountKey,
) -> anyhow::Result<String> {
    Ok(format!("{}.{}", token, account_key.thumbprint()?))
}

// ── HTTP-01 (RFC 8555 §8.3) ────────────────────────────────────────────────

pub mod http01 {
    use super::{AccountKey, ChallengeToken, key_authorization};
    use anyhow::{Context, Result, bail};
    use std::path::{Path, PathBuf};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing::info;

    /// The key authorization value to serve as the response body.
    pub fn response_body(
        token: &ChallengeToken,
        account_key: &AccountKey,
    ) -> anyhow::Result<String> {
        key_authorization(token, account_key)
    }

    /// The well-known path the ACME server will request.
    pub fn challenge_path(token: &ChallengeToken) -> String {
        format!("/.well-known/acme-challenge/{token}")
    }

    /// Write the challenge token file into `<dir>/.well-known/acme-challenge/`.
    ///
    /// Returns the full path to the written file (for cleanup).
    ///
    /// The token is a [`ChallengeToken`], which guarantees the RFC 8555 §8.1
    /// `[A-Za-z0-9_-]{1,128}` base64url alphabet — no path-traversal or
    /// separator bytes can appear in `file_path`. The file itself is created
    /// with `O_NOFOLLOW` where supported to avoid following an
    /// attacker-planted symlink in a shared webroot.
    pub fn write_challenge_file(
        challenge_dir: &Path,
        token: &ChallengeToken,
        account_key: &AccountKey,
    ) -> Result<PathBuf> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let auth = response_body(token, account_key)?;
        let well_known = challenge_dir.join(".well-known").join("acme-challenge");
        std::fs::create_dir_all(&well_known).with_context(|| {
            format!(
                "failed to create challenge directory {}",
                well_known.display()
            )
        })?;
        let file_path = well_known.join(token.as_str());

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
        f.write_all(auth.as_bytes())
            .with_context(|| format!("failed to write challenge file {}", file_path.display()))?;
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
    /// On `AddrInUse`, suggests `--challenge-dir`. On `PermissionDenied`
    /// for a privileged port (<1024), suggests root/`CAP_NET_BIND_SERVICE`/
    /// reverse-proxy alternatives. Other errors propagate with context.
    pub async fn bind_or_suggest(port: u16) -> Result<tokio::net::TcpListener> {
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
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && port < 1024 => {
                bail!(
                    "permission denied binding port {port} (privileged port, requires root or CAP_NET_BIND_SERVICE)\n\
                     \n\
                     Pick one:\n\
                       1. Run as root:           sudo acme-client-rs ...\n\
                       2. Grant the capability:  sudo setcap cap_net_bind_service=+ep $(which acme-client-rs)\n\
                       3. Use a high port behind your reverse proxy:\n\
                          acme-client-rs run example.com --http-port 8080\n\
                          (and proxy /.well-known/acme-challenge/ from :80 to :8080)\n\
                       4. Skip binding entirely and let your existing web server serve the file:\n\
                          acme-client-rs run example.com --challenge-dir /var/www/html"
                );
            }
            Err(e) => {
                Err(e).with_context(|| format!("failed to bind HTTP-01 server on port {port}"))
            }
        }
    }

    /// 404 response for non-matching paths. Static — no per-connection allocation.
    /// Security: no `Server` header to avoid identifying the ACME client.
    const NOT_FOUND_RESPONSE: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n";

    /// Serve a single accepted TCP connection: read one request, reply with
    /// the key-authorization body when the path matches, else 404. Errors
    /// are logged at debug level and swallowed — one malformed probe MUST
    /// NOT terminate the listener while other parallel CA validation
    /// probes (e.g. Let's Encrypt multi-perspective: 3+ concurrent
    /// requests) are still in flight.
    pub async fn serve_one_connection(
        mut stream: tokio::net::TcpStream,
        addr: std::net::SocketAddr,
        auth: &str,
        path: &str,
    ) {
        use tokio::time::{Duration, timeout};
        let mut buf = vec![0u8; 4096];
        // Slowloris guard: cap how long a single peer can hold the
        // pre-request read open. CA validation probes complete in well under
        // a second; legitimate traffic doesn't need more.
        let n = match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                tracing::debug!("HTTP-01: read from {addr} failed: {e}");
                return;
            }
            Err(_) => {
                tracing::debug!("HTTP-01: read from {addr} timed out");
                return;
            }
        };
        let req = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[]));
        // Match only the request-target on the request line, never headers or
        // body. Anything looser would serve the key authorization to probes
        // that happen to include the challenge path as a substring elsewhere.
        let request_line = req.split("\r\n").next().unwrap_or("");
        let expected_prefix = format!("GET {path} ");
        let write_res = if request_line.starts_with(&expected_prefix) {
            info!("HTTP-01: serving challenge response to {addr}");
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\
                 X-Content-Type-Options: nosniff\r\n\
                 Connection: close\r\n\r\n{}",
                auth.len(),
                auth
            );
            stream.write_all(resp.as_bytes()).await
        } else {
            stream.write_all(NOT_FOUND_RESPONSE).await
        };
        if let Err(e) = write_res {
            tracing::debug!("HTTP-01: write to {addr} failed: {e}");
        }
    }

    /// Run the accept loop on `listener`, spawning `serve_one_connection`
    /// per accepted TCP connection so parallel CA validation probes are
    /// served concurrently. Only returns if `accept` itself fails (a fatal
    /// listener error); per-connection errors are logged and swallowed.
    pub async fn run_accept_loop(
        listener: tokio::net::TcpListener,
        auth: String,
        path: String,
    ) -> Result<()> {
        let auth: std::sync::Arc<str> = std::sync::Arc::from(auth);
        let path: std::sync::Arc<str> = std::sync::Arc::from(path);
        // Cap concurrent in-flight connections to bound FD/task usage during
        // the validation window. 256 is far above the 3-5 parallel probes a
        // CA's multi-perspective validation actually performs.
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(256));
        loop {
            let (stream, addr) = listener.accept().await?;
            tracing::debug!("HTTP-01: connection from {addr}");
            let auth = std::sync::Arc::clone(&auth);
            let path = std::sync::Arc::clone(&path);
            let Ok(permit) = std::sync::Arc::clone(&semaphore).try_acquire_owned() else {
                tracing::debug!("HTTP-01: dropping {addr}, connection cap reached");
                drop(stream);
                continue;
            };
            tokio::spawn(async move {
                serve_one_connection(stream, addr, &auth, &path).await;
                drop(permit);
            });
        }
    }

    /// Spin up a minimal TCP server that answers ACME HTTP-01 validation
    /// requests until aborted. Multiple concurrent probes from a CA's
    /// multi-perspective validation are served in parallel.
    pub async fn serve(token: &ChallengeToken, account_key: &AccountKey, port: u16) -> Result<()> {
        let auth = response_body(token, account_key)?;
        let path = challenge_path(token);
        let listener = bind_or_suggest(port).await?;
        info!("HTTP-01 server listening on 0.0.0.0:{port}");
        run_accept_loop(listener, auth, path).await
    }
}

// ── DNS-01 (RFC 8555 §8.4) ─────────────────────────────────────────────────

pub mod dns01 {
    use super::{
        AccountKey, ChallengeToken, Digest, Engine, Sha256, URL_SAFE_NO_PAD, key_authorization,
    };
    use crate::outln;

    /// The value for the `_acme-challenge.<domain>` TXT record:
    ///   `base64url(SHA-256(keyAuthorization))`
    pub fn txt_record_value(
        token: &ChallengeToken,
        account_key: &AccountKey,
    ) -> anyhow::Result<String> {
        let auth = key_authorization(token, account_key)?;
        let digest = Sha256::digest(auth.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(digest))
    }

    /// Full DNS record name for the challenge.
    ///
    /// For wildcard identifiers (`*.example.com`), the leading `*.` is
    /// stripped per RFC 8555 §8.4 — the validation record is published
    /// at the base zone, not under a literal `*` label.
    pub fn record_name(domain: &crate::types::DnsName) -> anyhow::Result<crate::types::DnsName> {
        let base = domain
            .as_str()
            .strip_prefix("*.")
            .unwrap_or(domain.as_str());
        crate::types::DnsName::parse(&format!("_acme-challenge.{base}"))
    }

    /// Print human-readable instructions for manual DNS record setup.
    pub fn print_instructions(
        domain: &crate::types::DnsName,
        token: &ChallengeToken,
        account_key: &AccountKey,
    ) -> anyhow::Result<()> {
        let name = record_name(domain)?;
        let value = txt_record_value(token, account_key)?;
        outln!();
        outln!("=== DNS-01 Challenge ===");
        outln!("Create a DNS TXT record:");
        outln!("  Name:  {name}");
        outln!("  Type:  TXT");
        outln!("  Value: {value}");
        outln!();
        Ok(())
    }
}

// ── DNS-PERSIST-01 (draft-ietf-acme-dns-persist) ────────────────────────────

pub mod dns_persist01 {
    use crate::outln;
    /// DNS record name for dns-persist-01 validation.
    ///
    /// For wildcard identifiers (`*.example.com`), the leading `*.` is
    /// stripped — the persistent validation record lives at the base zone.
    pub fn record_name(domain: &crate::types::DnsName) -> anyhow::Result<crate::types::DnsName> {
        let base = domain
            .as_str()
            .strip_prefix("*.")
            .unwrap_or(domain.as_str());
        crate::types::DnsName::parse(&format!("_validation-persist.{base}"))
    }

    /// Construct the TXT record value (RFC 8659 issue-value syntax).
    ///
    ///   `<issuer-domain-name>; accounturi=<uri>[; policy=<p>][; persistUntil=<ts>]`
    pub fn txt_record_value(
        issuer_domain_name: &str,
        account_uri: &str,
        policy: Option<&str>,
        persist_until: Option<u64>,
    ) -> anyhow::Result<String> {
        use std::fmt::Write as _;

        let issuer = crate::client::validate_issuer_domain_name(issuer_domain_name)?;
        let uri = crate::client::validate_account_uri(account_uri)?;
        let mut value = format!("{issuer}; accounturi={uri}");
        if let Some(p) = policy {
            let p = crate::client::validate_caa_parameter_value(p)?;
            write!(&mut value, "; policy={p}")?;
        }
        if let Some(ts) = persist_until {
            write!(&mut value, "; persistUntil={ts}")?;
        }
        Ok(value)
    }

    pub fn print_instructions(
        domain: &crate::types::DnsName,
        issuer_domain_names: &[String],
        account_uri: &str,
        policy: Option<&str>,
        persist_until: Option<u64>,
    ) -> anyhow::Result<()> {
        let name = record_name(domain)?;
        let issuer = issuer_domain_names
            .first()
            .ok_or_else(|| anyhow::anyhow!("issuer_domain_names is empty"))?;
        let value = txt_record_value(issuer, account_uri, policy, persist_until)?;
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
        Ok(())
    }
}

// ── TLS-ALPN-01 (RFC 8737) ─────────────────────────────────────────────────

pub mod tlsalpn01 {
    use super::{AccountKey, ChallengeToken, Digest, Sha256, key_authorization};
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
    pub fn acme_identifier_value(
        token: &ChallengeToken,
        account_key: &AccountKey,
    ) -> anyhow::Result<Vec<u8>> {
        let auth = key_authorization(token, account_key)?;
        let hash = Sha256::digest(auth.as_bytes());
        let mut der = Vec::with_capacity(34);
        der.push(0x04); // OCTET STRING tag
        der.push(0x20); // length = 32
        der.extend_from_slice(&hash);
        Ok(der)
    }

    /// Print human-readable instructions for manual TLS-ALPN-01 setup.
    pub fn print_instructions(
        domain: &str,
        token: &ChallengeToken,
        account_key: &AccountKey,
    ) -> anyhow::Result<()> {
        let value = acme_identifier_value(token, account_key)?;
        let hex: String =
            value
                .iter()
                .fold(String::with_capacity(value.len() * 2), |mut acc, b| {
                    use std::fmt::Write as _;
                    let _ = write!(&mut acc, "{b:02x}");
                    acc
                });
        outln!();
        outln!("=== TLS-ALPN-01 Challenge ===");
        outln!("Domain: {domain}");
        outln!("ALPN protocol: acme-tls/1");
        outln!("acmeIdentifier extension (hex): {hex}");
        outln!();
        outln!("Configure a TLS server on port 443 with a self-signed");
        outln!("certificate containing this extension.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dns01_record_name_strips_wildcard_prefix() -> anyhow::Result<()> {
        let wildcard = crate::types::DnsName::parse("*.example.com")?;
        let bare = crate::types::DnsName::parse("example.com")?;
        assert_eq!(
            super::dns01::record_name(&wildcard)?.as_str(),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            super::dns01::record_name(&bare)?.as_str(),
            "_acme-challenge.example.com"
        );
        Ok(())
    }

    #[test]
    fn dns_persist01_record_name_strips_wildcard_prefix() -> anyhow::Result<()> {
        let wildcard = crate::types::DnsName::parse("*.example.com")?;
        let bare = crate::types::DnsName::parse("example.com")?;
        assert_eq!(
            super::dns_persist01::record_name(&wildcard)?.as_str(),
            "_validation-persist.example.com"
        );
        assert_eq!(
            super::dns_persist01::record_name(&bare)?.as_str(),
            "_validation-persist.example.com"
        );
        Ok(())
    }

    #[test]
    fn dns_persist01_txt_value_happy_path() -> anyhow::Result<()> {
        let v = super::dns_persist01::txt_record_value(
            "letsencrypt.org",
            "https://acme.example/acct/123",
            Some("wildcard"),
            Some(1_700_000_000),
        )?;
        assert_eq!(
            v,
            "letsencrypt.org; accounturi=https://acme.example/acct/123; \
             policy=wildcard; persistUntil=1700000000"
        );
        Ok(())
    }

    #[test]
    fn dns_persist01_txt_value_rejects_issuer_injection() -> anyhow::Result<()> {
        let err = super::dns_persist01::txt_record_value(
            "evil.com; rogue=x",
            "https://acme.example/acct/1",
            None,
            None,
        );
        assert!(err.is_err());
        Ok(())
    }

    #[test]
    fn dns_persist01_txt_value_rejects_uri_injection() -> anyhow::Result<()> {
        let err = super::dns_persist01::txt_record_value(
            "letsencrypt.org",
            "https://acme.example/acct/1;rogue",
            None,
            None,
        );
        assert!(err.is_err());
        Ok(())
    }

    #[test]
    fn dns_persist01_txt_value_rejects_policy_injection() -> anyhow::Result<()> {
        let err = super::dns_persist01::txt_record_value(
            "letsencrypt.org",
            "https://acme.example/acct/1",
            Some("wildcard; rogue=x"),
            None,
        );
        assert!(err.is_err());
        Ok(())
    }

    #[test]
    fn dns_persist01_txt_value_lowercases_issuer() -> anyhow::Result<()> {
        let v = super::dns_persist01::txt_record_value(
            "LetsEncrypt.ORG",
            "https://acme.example/acct/1",
            None,
            None,
        )?;
        assert!(v.starts_with("letsencrypt.org; "));
        Ok(())
    }
}
