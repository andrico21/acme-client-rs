//! HTTP transport: SSRF-safe DNS resolver, shared client builder, and the
//! parsed ACME response wrapper used by every signed request.

use anyhow::{Context, Result, bail};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::sanitize::untrusted_block;
use crate::types::AcmeError;

use super::net_policy::is_private_or_special_ip;

const USER_AGENT_VALUE: &str = concat!("acme-client-rs/", env!("CARGO_PKG_VERSION"));

/// reqwest DNS resolver that rejects hostnames resolving to private,
/// loopback, link-local, multicast or other special-purpose addresses.
/// This is the connect-time half of SSRF defense and closes the
/// DNS-rebinding race that a synchronous pre-check cannot.
pub(super) struct SsrfSafeResolver {
    network: super::net_policy::NetworkPolicy,
}

impl SsrfSafeResolver {
    pub(super) fn new(network: super::net_policy::NetworkPolicy) -> Arc<Self> {
        Arc::new(Self { network })
    }
}

impl reqwest::dns::Resolve for SsrfSafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_private = self.network.allows_private();
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let filtered: Vec<SocketAddr> = if allow_private {
                resolved.collect()
            } else {
                resolved
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
pub(crate) fn build_http_client(
    tls: super::net_policy::TlsPolicy,
    connect_timeout_secs: u64,
    network: super::net_policy::NetworkPolicy,
) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT_VALUE)
        .connect_timeout(std::time::Duration::from_secs(connect_timeout_secs))
        .timeout(std::time::Duration::from_mins(2))
        .redirect(reqwest::redirect::Policy::none())
        // README security posture promises a TLS 1.2 minimum; make the floor
        // explicit instead of relying on the backend default.
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .danger_accept_invalid_certs(tls.accepts_invalid_certs())
        .dns_resolver(SsrfSafeResolver::new(network))
        .build()
        .context("failed to build HTTP client")
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
                untrusted_block(&self.body)
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

    /// Like [`location`](Self::location) but rejects the URL if it points at a
    /// private/loopback/special-purpose address or otherwise violates policy.
    /// A malicious or compromised CA can redirect follow-up navigation
    /// (account/order/authz URLs) at internal services via the `Location`
    /// header; this closes that SSRF vector at the boundary where the URL
    /// first enters the client.
    pub(crate) fn validated_location(
        &self,
        tls: super::net_policy::TlsPolicy,
        network: super::net_policy::NetworkPolicy,
    ) -> Result<url::Url> {
        let url = self.location()?;
        super::url_validation::validate_acme_url(url.as_str(), tls, network)
            .context("Location header URL failed validation")?;
        Ok(url)
    }

    pub(crate) fn ensure_success(&self) -> Result<()> {
        if self.status.is_client_error() || self.status.is_server_error() {
            if let Ok(err) = serde_json::from_slice::<AcmeError>(&self.body) {
                bail!("ACME error (HTTP {}): {}", self.status, err);
            }
            bail!(
                "HTTP error {}: {}",
                self.status,
                untrusted_block(&self.body)
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    fn response_with_location(loc: &str) -> AcmeResponse {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "location",
            reqwest::header::HeaderValue::from_str(loc).expect("valid header"),
        );
        AcmeResponse {
            status: reqwest::StatusCode::CREATED,
            headers,
            body: Vec::new(),
        }
    }

    // M1: a Location pointing at a private/loopback address must be rejected
    // under the production policy, but accepted for a public host.
    #[test]
    fn m1_validated_location_rejects_private_targets() {
        let (tls, net) =
            super::super::net_policy::policies_from_cli_flags(super::super::net_policy::NetFlags {
                insecure: false,
                allow_private_network: false,
            });

        assert!(
            response_with_location("https://acme.example.com/acct/1")
                .validated_location(tls, net)
                .is_ok()
        );

        assert!(
            response_with_location("https://127.0.0.1/acct/1")
                .validated_location(tls, net)
                .is_err()
        );
        assert!(
            response_with_location("https://[::1]/acct/1")
                .validated_location(tls, net)
                .is_err()
        );
        assert!(
            response_with_location("file:///etc/passwd")
                .validated_location(tls, net)
                .is_err()
        );
    }

    #[test]
    fn m1_validated_location_allows_private_with_override() {
        let (tls, net) =
            super::super::net_policy::policies_from_cli_flags(super::super::net_policy::NetFlags {
                insecure: true,
                allow_private_network: true,
            });
        assert!(
            response_with_location("https://127.0.0.1/acct/1")
                .validated_location(tls, net)
                .is_ok()
        );
    }
}
