//! HTTP transport: SSRF-safe DNS resolver, shared client builder, and the
//! parsed ACME response wrapper used by every signed request.

use anyhow::{Context, Result, bail};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::types::AcmeError;

use super::net_policy::is_private_or_special_ip;

const USER_AGENT_VALUE: &str = concat!("acme-client-rs/", env!("CARGO_PKG_VERSION"));

/// reqwest DNS resolver that rejects hostnames resolving to private,
/// loopback, link-local, multicast or other special-purpose addresses.
/// This is the connect-time half of SSRF defense and closes the
/// DNS-rebinding race that a synchronous pre-check cannot.
pub struct SsrfSafeResolver {
    allow_private: bool,
}

impl SsrfSafeResolver {
    pub fn new(allow_private: bool) -> Arc<Self> {
        Arc::new(Self { allow_private })
    }
}

impl reqwest::dns::Resolve for SsrfSafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_private = self.allow_private;
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let filtered: Vec<SocketAddr> = if allow_private {
                addrs
            } else {
                addrs
                    .into_iter()
                    .filter(|sa| !is_private_or_special_ip(sa.ip()))
                    .collect()
            };
            if filtered.is_empty() {
                let err: Box<dyn std::error::Error + Send + Sync> = format!(
                    "host {host:?} resolved only to private/loopback/special-purpose addresses; \
                     pass --allow-private-network to override"
                )
                .into();
                return Err(err);
            }
            let iter: reqwest::dns::Addrs = Box::new(filtered.into_iter());
            Ok(iter)
        })
    }
}

/// Build a `reqwest::Client` with the project's standard headers, timeouts,
/// redirect policy and TLS settings. Centralizing this prevents drift
/// between `AcmeClient::new` and ad-hoc HTTP calls (e.g. `list-profiles`).
///
/// `connect_timeout_secs` caps TCP + TLS handshake. The whole-request
/// timeout is fixed at 120s. Auto-redirects are disabled because RFC 8555
/// drives its own resource navigation via `Location` headers on
/// non-redirect responses (newAccount, newOrder); transparent 30x
/// following would corrupt nonce handling and hide CA misconfiguration.
pub fn build_http_client(
    danger_accept_invalid_certs: bool,
    connect_timeout_secs: u64,
    allow_private_network: bool,
) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT_VALUE)
        .connect_timeout(std::time::Duration::from_secs(connect_timeout_secs))
        .timeout(std::time::Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(danger_accept_invalid_certs)
        .dns_resolver(SsrfSafeResolver::new(allow_private_network))
        .build()
        .context("failed to build HTTP client")
}

/// SEC-15: cap raw response bodies surfaced in error messages so an HTML 502
/// page from an intermediate proxy doesn't flood the user's terminal / logs,
/// and replace ASCII control bytes (except `\n` / `\t`) with `·` so binary or
/// crafted payloads can't break log alignment with embedded CR / escape codes.
const MAX_BODY_FOR_ERROR: usize = 1024;

pub(crate) fn truncate_for_log(body: &[u8]) -> String {
    let slice = if body.len() > MAX_BODY_FOR_ERROR {
        &body[..MAX_BODY_FOR_ERROR]
    } else {
        body
    };
    let lossy = String::from_utf8_lossy(slice);
    let mut out: String = lossy
        .chars()
        .map(|c| match c {
            '\n' | '\t' => c,
            c if (c as u32) < 0x20 || c == '\x7f' => '·',
            c => c,
        })
        .collect();
    if body.len() > MAX_BODY_FOR_ERROR {
        out.push_str(&format!("… [truncated, {} bytes total]", body.len()));
    }
    out
}

/// Parsed ACME response (status + headers + body bytes).
pub(crate) struct AcmeResponse {
    pub(crate) status: reqwest::StatusCode,
    pub(crate) headers: reqwest::header::HeaderMap,
    pub(crate) body: Vec<u8>,
}

impl AcmeResponse {
    pub(crate) fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).with_context(|| {
            format!(
                "failed to parse response body: {}",
                truncate_for_log(&self.body)
            )
        })
    }

    pub(crate) fn location(&self) -> Result<url::Url> {
        let raw = self
            .headers
            .get("location")
            .context("no Location header in response")?
            .to_str()
            .context("invalid Location header value")?;
        raw.parse()
            .with_context(|| format!("Location header is not a valid URL: {raw}"))
    }

    pub(crate) fn ensure_success(&self) -> Result<()> {
        if self.status.is_client_error() || self.status.is_server_error() {
            if let Ok(err) = serde_json::from_slice::<AcmeError>(&self.body) {
                bail!("ACME error (HTTP {}): {}", self.status, err);
            }
            bail!(
                "HTTP error {}: {}",
                self.status,
                truncate_for_log(&self.body)
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_for_log_caps_oversize_bodies() {
        let big = vec![b'A'; MAX_BODY_FOR_ERROR + 500];
        let out = truncate_for_log(&big);
        assert!(out.contains("truncated"));
        assert!(out.contains(&format!("{} bytes total", MAX_BODY_FOR_ERROR + 500)));
        assert!(out.len() < MAX_BODY_FOR_ERROR + 100);
    }

    #[test]
    fn truncate_for_log_replaces_control_chars_but_keeps_newline_tab() {
        let body = b"line1\nline2\r\x1b[31mred\x1b[0m\tend\x07\x00bell";
        let out = truncate_for_log(body);
        assert!(out.contains("line1\nline2"), "newline preserved: {out:?}");
        assert!(out.contains("\tend"), "tab preserved: {out:?}");
        assert!(!out.contains('\r'), "CR replaced: {out:?}");
        assert!(!out.contains('\x1b'), "ESC replaced: {out:?}");
        assert!(!out.contains('\x07'), "BEL replaced: {out:?}");
        assert!(!out.contains('\x00'), "NUL replaced: {out:?}");
        assert!(out.contains('·'), "replacement char present: {out:?}");
    }

    #[test]
    fn truncate_for_log_handles_invalid_utf8() {
        let body = b"valid\xff\xfeend";
        let out = truncate_for_log(body);
        assert!(out.contains("valid"));
        assert!(out.contains("end"));
    }
}
