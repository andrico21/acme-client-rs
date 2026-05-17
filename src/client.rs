//! ACME HTTP client - drives the full RFC 8555 protocol flow.
//!
//! Every mutating request is a signed JWS POST.  Nonces are cached from
//! response headers and a single automatic retry is performed on `badNonce`.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::header::CONTENT_TYPE;
use tracing::{debug, info, warn};

use crate::jws::AccountKey;
use crate::types::*;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

const JOSE_CONTENT_TYPE: &str = "application/jose+json";
const USER_AGENT_VALUE: &str = concat!("acme-client-rs/", env!("CARGO_PKG_VERSION"));

// ── SSRF defenses ───────────────────────────────────────────────────────────
//
// Two complementary checks guard every URL we follow:
//
//   1. `validate_acme_url` — synchronous scheme + literal-IP check applied at
//      every URL ingress (CLI args, server-returned URLs in Directory/Order/
//      Authorization). Cheap, no I/O, catches `file://`, `data:`, embedded
//      IPv4/IPv6 literals in private/loopback ranges.
//
//   2. `SsrfSafeResolver` — wraps the system DNS resolver inside the reqwest
//      `Client`. Catches DNS-rebinding and the case where a hostname resolves
//      to a private IP. This is the layer that matters for `corp.local`-style
//      names that bypass the synchronous check.
//
// Both layers respect `--allow-private-network` (and `--insecure`, which
// implies it). Default: BLOCK.

/// Classify an IP as "must not be reached by an ACME client" unless the
/// operator explicitly opted in. Covers loopback, RFC1918, link-local
/// (incl. cloud metadata at 169.254.169.254), CGNAT, multicast, broadcast,
/// reserved/documentation ranges, IPv6 loopback/ULA/link-local/multicast,
/// and IPv4-mapped IPv6 (a common SSRF bypass).
fn is_private_or_special_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_or_special_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_private_or_special_ipv4(mapped);
            }
            is_private_or_special_ipv6(v6)
        }
    }
}

fn is_private_or_special_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
    {
        return true;
    }
    let o = ip.octets();
    // CGNAT (RFC 6598): 100.64.0.0/10
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return true;
    }
    // IETF protocol assignments (RFC 6890): 192.0.0.0/24
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return true;
    }
    // Benchmarking (RFC 2544): 198.18.0.0/15
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return true;
    }
    // Reserved for future use (RFC 1112): 240.0.0.0/4
    if o[0] >= 240 {
        return true;
    }
    false
}

fn is_private_or_special_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let s = ip.segments();
    // Unique local addresses (RFC 4193): fc00::/7
    if (s[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-local: fe80::/10
    if (s[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // Documentation (RFC 3849): 2001:db8::/32
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return true;
    }
    false
}

/// Validate any URL the client is about to contact.
///
/// TLS policy for ACME URL validation. Distinct enum (not `bool`) so it cannot
/// be positionally swapped with `NetworkPolicy` at call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsPolicy {
    /// `https://` only (RFC 8555 §6.1 default).
    RequireHttps,
    /// Permit `http://` for loopback hosts only — `--insecure`.
    AllowHttpLoopback,
}

/// Network reachability policy for ACME URL validation. Distinct enum so it
/// cannot be positionally swapped with `TlsPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Reject private / loopback / link-local / special-purpose IP literals.
    PublicOnly,
    /// Permit private/special IPs — `--allow-private-network` (also implied by
    /// `TlsPolicy::AllowHttpLoopback`).
    AllowPrivate,
}

impl TlsPolicy {
    fn from_insecure(insecure: bool) -> Self {
        if insecure {
            Self::AllowHttpLoopback
        } else {
            Self::RequireHttps
        }
    }
}

impl NetworkPolicy {
    fn from_allow_private(allow_private: bool) -> Self {
        if allow_private {
            Self::AllowPrivate
        } else {
            Self::PublicOnly
        }
    }
}

/// Build (tls, network) policy pair from the CLI flags as a single call. The
/// canonical conversion used by every handler — keeps the bool→enum hop in one
/// place so call sites read `let (tls, net) = policies_from_cli_flags(...)`.
pub fn policies_from_cli_flags(insecure: bool, allow_private: bool) -> (TlsPolicy, NetworkPolicy) {
    (
        TlsPolicy::from_insecure(insecure),
        NetworkPolicy::from_allow_private(allow_private),
    )
}

/// `tls = AllowHttpLoopback` permits plain `http://` for loopback hosts only
/// (matches historical `--insecure` semantics).
/// `net = AllowPrivate` permits private/loopback/link-local IP literals; it is
/// also implicitly granted when `tls = AllowHttpLoopback`.
///
/// Hostnames (non-literal) are NOT resolved here — that check happens
/// connect-time inside `SsrfSafeResolver`, which closes the DNS-rebinding
/// race that synchronous resolution would leave open.
/// Maximum URL byte-length accepted anywhere we talk to an ACME server.
///
/// Priority-1 (RFC contract): RFC 9110 §4.1 RECOMMENDS that senders and
/// recipients support URIs of at least 8000 octets in protocol elements.
/// We refuse anything beyond that as both an SSRF/log-spam guard and a
/// protocol-sanity check.
pub const MAX_ACME_URL_LEN: usize = 8000;

pub fn validate_acme_url(url: &str, tls: TlsPolicy, net: NetworkPolicy) -> Result<()> {
    if url.len() > MAX_ACME_URL_LEN {
        bail!(
            "URL exceeds {MAX_ACME_URL_LEN} octets ({} bytes); refusing",
            url.len()
        );
    }
    let parsed = reqwest::Url::parse(url).with_context(|| format!("invalid URL {url:?}"))?;
    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        bail!("URL must use https:// (got scheme {scheme:?}); refusing {url:?}");
    }
    // Priority-1 (RFC contract / phishing-shape defense): RFC 9110 §4.2.4
    // says senders MUST NOT generate `userinfo` in http/https URI references
    // and recipients SHOULD treat userinfo from untrusted sources as an error.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("URL must not contain userinfo (user:pass@host); refusing {url:?}");
    }
    let host = parsed.host_str().unwrap_or("");
    let host_ip: Option<IpAddr> = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok();
    let is_loopback_host = host_ip
        .map(|ip| ip.is_loopback())
        .unwrap_or_else(|| matches!(host, "localhost"));
    if scheme == "http" {
        if tls == TlsPolicy::RequireHttps {
            bail!(
                "URL must use https:// (RFC 8555 §6.1). Got http:// for {url:?}. \
                 Pass --insecure only for local testing against a loopback ACME server."
            );
        }
        if !is_loopback_host {
            bail!(
                "--insecure with http:// is only allowed for loopback hosts \
                 (127.0.0.1, ::1, localhost); got host {host:?} in {url:?}"
            );
        }
    }
    let effective_net = if tls == TlsPolicy::AllowHttpLoopback {
        NetworkPolicy::AllowPrivate
    } else {
        net
    };
    if let Some(ip) = host_ip
        && effective_net == NetworkPolicy::PublicOnly
        && is_private_or_special_ip(ip)
    {
        bail!(
            "refusing to contact private/loopback/special-purpose IP {ip} in {url:?}; \
                 pass --allow-private-network to override (e.g. for an internal CA)"
        );
    }
    Ok(())
}

/// Validate an issuer-domain-name as it will appear in a dns-persist-01 TXT
/// record (draft-ietf-acme-dns-persist §3.1, basis RFC 8659 §4.2).
///
/// Priority-1 (RFC contract): rules transcribed from the spec —
/// LDH labels only, no wildcard (`*`), no underscore (`_`),
/// no trailing dot, A-label (Punycode) form if non-ASCII source,
/// ASCII-lowercase, total length ≤ 253 octets, ≥ 1 label.
pub fn validate_issuer_domain_name(s: &str) -> Result<String> {
    if s.is_empty() {
        bail!("issuer-domain-name is empty");
    }
    if s.len() > 253 {
        bail!("issuer-domain-name exceeds 253 octets ({} bytes)", s.len());
    }
    if !s.is_ascii() {
        bail!("issuer-domain-name must be ASCII A-label form (Punycode); got non-ASCII in {s:?}");
    }
    if s.ends_with('.') {
        bail!("issuer-domain-name must not have a trailing dot: {s:?}");
    }
    if s.contains('*') {
        bail!("issuer-domain-name must not contain wildcard '*': {s:?}");
    }
    if s.contains('_') {
        bail!("issuer-domain-name must not contain underscore '_': {s:?}");
    }
    let lower = s.to_ascii_lowercase();
    for label in lower.split('.') {
        if label.is_empty() {
            bail!("issuer-domain-name has empty label: {s:?}");
        }
        if label.len() > 63 {
            bail!("issuer-domain-name label exceeds 63 octets: {label:?}");
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            bail!("issuer-domain-name label must start/end alphanumeric (LDH): {label:?}");
        }
        for &b in bytes {
            if !(b.is_ascii_alphanumeric() || b == b'-') {
                bail!("issuer-domain-name label has non-LDH char {b:?}: {label:?}");
            }
        }
    }
    Ok(lower)
}

/// Validate an `accounturi` value for a dns-persist-01 TXT record.
///
/// Priority-1 (RFC contract): RFC 8657 §3 requires "a URI"; RFC 8659 §4.2
/// value grammar forbids literal `;` (TXT structural separator), control
/// chars, space, DEL. RFC 9110 §4.2.4 forbids userinfo. Fragments are
/// stripped from a URI's identity, so we reject them too.
pub fn validate_account_uri(s: &str) -> Result<String> {
    if s.is_empty() {
        bail!("accounturi is empty");
    }
    if s.len() > MAX_ACME_URL_LEN {
        bail!(
            "accounturi exceeds {MAX_ACME_URL_LEN} octets ({} bytes)",
            s.len()
        );
    }
    if !s.is_ascii() {
        bail!("accounturi must be ASCII (percent-encode non-ASCII): {s:?}");
    }
    if s.contains(';') {
        bail!("accounturi must not contain literal ';' (CAA value separator): {s:?}");
    }
    for &b in s.as_bytes() {
        if b < 0x21 || b == 0x7f {
            bail!("accounturi contains control char or space: byte 0x{b:02x}");
        }
    }
    let parsed = reqwest::Url::parse(s).with_context(|| format!("accounturi not a URI: {s:?}"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("accounturi must not contain userinfo: {s:?}");
    }
    if parsed.fragment().is_some() {
        bail!("accounturi must not contain a fragment: {s:?}");
    }
    Ok(s.to_string())
}

/// Validate a CAA-style parameter value per RFC 8659 §4.2:
///
/// Priority-1 (RFC contract): `value = *(%x21-3A / %x3C-7E)` —
/// printable ASCII excluding space (`%x20`), semicolon (`%x3B`), and DEL (`%x7F`).
pub fn validate_caa_parameter_value(s: &str) -> Result<&str> {
    if s.is_empty() {
        bail!("CAA parameter value is empty");
    }
    for &b in s.as_bytes() {
        let ok = (0x21..=0x3A).contains(&b) || (0x3C..=0x7E).contains(&b);
        if !ok {
            bail!("CAA parameter value has byte 0x{b:02x} outside RFC 8659 §4.2 grammar: {s:?}");
        }
    }
    Ok(s)
}

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

/// Validate an ACME directory URL against RFC 8555 §6.1 ("Use of HTTPS is
/// REQUIRED"). Thin wrapper over `validate_acme_url` that also emits the
/// loopback-testing warning when `http://` is permitted via `--insecure`.
pub fn validate_directory_url(url: &str, tls: TlsPolicy, net: NetworkPolicy) -> Result<()> {
    validate_acme_url(url, tls, net).with_context(|| format!("invalid directory URL {url:?}"))?;
    if reqwest::Url::parse(url)
        .map(|u| u.scheme() == "http")
        .unwrap_or(false)
    {
        warn!("Using plain http:// for ACME directory (loopback only) — TESTING USE ONLY");
    }
    Ok(())
}

// ── Response wrapper ────────────────────────────────────────────────────────

/// SEC-15: cap raw response bodies surfaced in error messages so an HTML 502
/// page from an intermediate proxy doesn't flood the user's terminal / logs,
/// and replace ASCII control bytes (except `\n` / `\t`) with `·` so binary or
/// crafted payloads can't break log alignment with embedded CR / escape codes.
const MAX_BODY_FOR_ERROR: usize = 1024;

fn truncate_for_log(body: &[u8]) -> String {
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
struct AcmeResponse {
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

impl AcmeResponse {
    fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).with_context(|| {
            format!(
                "failed to parse response body: {}",
                truncate_for_log(&self.body)
            )
        })
    }

    fn location(&self) -> Result<String> {
        self.headers
            .get("location")
            .context("no Location header in response")?
            .to_str()
            .context("invalid Location header value")
            .map(String::from)
    }

    fn ensure_success(&self) -> Result<()> {
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

// ── Client ──────────────────────────────────────────────────────────────────

pub struct AcmeClient {
    http: reqwest::Client,
    directory: Directory,
    account_key: AccountKey,
    nonce: Option<String>,
    account_url: Option<String>,
    insecure: bool,
    allow_private: bool,
}

impl AcmeClient {
    /// Create a new client by fetching the ACME directory.
    ///
    /// When `danger_accept_invalid_certs` is `true`, TLS certificate
    /// verification is disabled.  **Only use for testing** (e.g. Pebble).
    /// `connect_timeout_secs` is forwarded to the HTTP client.
    pub async fn new(
        directory_url: &str,
        account_key: AccountKey,
        danger_accept_invalid_certs: bool,
        connect_timeout_secs: u64,
        allow_private_network: bool,
    ) -> Result<Self> {
        let http = build_http_client(
            danger_accept_invalid_certs,
            connect_timeout_secs,
            allow_private_network,
        )?;

        info!("Fetching ACME directory from {}", directory_url);
        let resp = http
            .get(directory_url)
            .send()
            .await
            .context("failed to fetch ACME directory")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            bail!(
                "ACME directory request failed (HTTP {status}): {}",
                truncate_for_log(&body)
            );
        }

        let directory: Directory = resp.json().await.context("failed to parse directory")?;
        debug!(?directory, "ACME directory loaded");

        let insecure = danger_accept_invalid_certs;
        let allow_private = allow_private_network;
        for (label, url) in [
            ("newNonce", directory.new_nonce.as_str()),
            ("newAccount", directory.new_account.as_str()),
            ("newOrder", directory.new_order.as_str()),
            ("revokeCert", directory.revoke_cert.as_str()),
            ("keyChange", directory.key_change.as_str()),
        ] {
            validate_acme_url(
                url,
                TlsPolicy::from_insecure(insecure),
                NetworkPolicy::from_allow_private(allow_private),
            )
            .with_context(|| format!("ACME directory advertises invalid {label} URL"))?;
        }
        if let Some(u) = directory.new_authz.as_deref() {
            validate_acme_url(
                u,
                TlsPolicy::from_insecure(insecure),
                NetworkPolicy::from_allow_private(allow_private),
            )
            .with_context(|| "ACME directory advertises invalid newAuthz URL".to_string())?;
        }
        if let Some(u) = directory.renewal_info.as_deref() {
            validate_acme_url(
                u,
                TlsPolicy::from_insecure(insecure),
                NetworkPolicy::from_allow_private(allow_private),
            )
            .with_context(|| "ACME directory advertises invalid renewalInfo URL".to_string())?;
        }

        Ok(Self {
            http,
            directory,
            account_key,
            nonce: None,
            account_url: None,
            insecure,
            allow_private,
        })
    }

    // ── Accessors ───────────────────────────────────────────────────────

    pub fn set_account_url(&mut self, url: String) {
        self.account_url = Some(url);
    }

    pub fn account_url(&self) -> Option<&str> {
        self.account_url.as_deref()
    }

    pub fn account_key(&self) -> &AccountKey {
        &self.account_key
    }

    #[allow(dead_code)]
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    fn url_policies(&self) -> (TlsPolicy, NetworkPolicy) {
        policies_from_cli_flags(self.insecure, self.allow_private)
    }

    // ── Nonce management (RFC 8555 §7.2) ────────────────────────────────

    async fn fetch_nonce(&self) -> Result<String> {
        {
            let (tls, net) = self.url_policies();
            validate_acme_url(&self.directory.new_nonce, tls, net)
        }
        .with_context(|| "newNonce URL failed validation".to_string())?;
        debug!("Fetching fresh nonce via HEAD {}", self.directory.new_nonce);
        let resp = self
            .http
            .head(&self.directory.new_nonce)
            .send()
            .await
            .context("failed to fetch nonce")?;
        let nonce = resp
            .headers()
            .get("replay-nonce")
            .context("server did not return Replay-Nonce header")?
            .to_str()
            .context("Replay-Nonce is not valid ASCII")?
            .to_string();
        debug!("Obtained nonce: {}", nonce);
        Ok(nonce)
    }

    async fn get_nonce(&mut self) -> Result<String> {
        match self.nonce.take() {
            Some(n) => Ok(n),
            None => self.fetch_nonce().await,
        }
    }

    fn save_nonce(&mut self, headers: &reqwest::header::HeaderMap) {
        if let Some(val) = headers.get("replay-nonce")
            && let Ok(s) = val.to_str()
        {
            self.nonce = Some(s.to_string());
        }
    }

    // ── Signed POST with badNonce retry (RFC 8555 §6.2, §6.5) ──────────

    async fn signed_request(&mut self, url: &str, payload: &str) -> Result<AcmeResponse> {
        {
            let (tls, net) = self.url_policies();
            validate_acme_url(url, tls, net)
        }
        .with_context(|| format!("signed_request target URL failed validation: {url}"))?;
        for attempt in 0u8..2 {
            let nonce = self.get_nonce().await?;

            let body = match self.account_url {
                Some(ref kid) => self.account_key.sign_with_kid(payload, &nonce, url, kid)?,
                None => self.account_key.sign_with_jwk(payload, &nonce, url)?,
            };

            debug!(%url, attempt, "Sending signed POST");
            let resp = self
                .http
                .post(url)
                .header(CONTENT_TYPE, JOSE_CONTENT_TYPE)
                .body(body)
                .send()
                .await
                .context("signed POST request failed")?;

            let status = resp.status();
            let headers = resp.headers().clone();
            self.save_nonce(&headers);

            let body_bytes = resp.bytes().await?.to_vec();

            // On first attempt, check for badNonce and retry (RFC 8555 §6.5)
            if attempt == 0
                && status == reqwest::StatusCode::BAD_REQUEST
                && let Ok(err) = serde_json::from_slice::<AcmeError>(&body_bytes)
                && err.error_type.as_deref() == Some("urn:ietf:params:acme:error:badNonce")
            {
                warn!("Received badNonce - retrying with fresh nonce");
                continue;
            }

            return Ok(AcmeResponse {
                status,
                headers,
                body: body_bytes,
            });
        }
        bail!("signed request to {url} failed after badNonce retry");
    }

    // ── Account operations (RFC 8555 §7.3) ──────────────────────────────

    /// Create (or look up) an ACME account.
    ///
    /// If `eab` is `Some((kid, hmac_key))`, an External Account Binding
    /// (RFC 8555 §7.3.4) is included in the request.
    pub async fn create_account(
        &mut self,
        contact: Option<Vec<String>>,
        terms_of_service_agreed: bool,
        eab: Option<(&str, &[u8])>,
    ) -> Result<Account> {
        info!("Creating/looking-up ACME account");

        let eab_binding = if let Some((kid, hmac_key)) = eab {
            let url = &self.directory.new_account;
            Some(self.account_key.sign_eab(kid, hmac_key, url)?)
        } else if self
            .directory
            .meta
            .as_ref()
            .and_then(|m| m.external_account_required)
            .unwrap_or(false)
        {
            bail!(
                "server requires External Account Binding \
                 (externalAccountRequired: true) - \
                 provide --eab-kid and --eab-hmac-key"
            );
        } else {
            None
        };

        let payload = serde_json::to_string(&NewAccountRequest {
            terms_of_service_agreed,
            contact,
            external_account_binding: eab_binding,
        })?;
        let url = self.directory.new_account.clone();
        let resp = self.signed_request(&url, &payload).await?;
        resp.ensure_success()?;

        let account_url = resp.location()?;
        info!("Account URL: {account_url}");
        self.account_url = Some(account_url);

        resp.json()
    }

    /// Deactivate the current account (RFC 8555 §7.3.6).
    pub async fn deactivate_account(&mut self) -> Result<Account> {
        let url = self
            .account_url
            .clone()
            .context("account URL not set - create an account first")?;
        info!("Deactivating account: {url}");

        let payload = serde_json::to_string(&DeactivateAccountRequest {
            status: "deactivated".into(),
        })?;
        let resp = self.signed_request(&url, &payload).await?;
        resp.ensure_success()?;
        resp.json()
    }

    // ── Order operations (RFC 8555 §7.4) ────────────────────────────────

    /// Submit a new order.  Returns `(order, order_url)`.
    pub async fn new_order(
        &mut self,
        identifiers: Vec<Identifier>,
        profile: Option<String>,
    ) -> Result<(Order, String)> {
        self.new_order_inner(identifiers, None, profile).await
    }

    /// Submit a replacement order (ARI, RFC 9702 §5).
    ///
    /// `replaces` is the ARI certID of the certificate being replaced.
    pub async fn new_order_replacing(
        &mut self,
        identifiers: Vec<Identifier>,
        replaces: String,
        profile: Option<String>,
    ) -> Result<(Order, String)> {
        self.new_order_inner(identifiers, Some(replaces), profile)
            .await
    }

    async fn new_order_inner(
        &mut self,
        identifiers: Vec<Identifier>,
        replaces: Option<String>,
        profile: Option<String>,
    ) -> Result<(Order, String)> {
        if replaces.is_some() {
            info!("Creating replacement order (ARI)");
        } else {
            info!("Creating new order");
        }
        let payload = serde_json::to_string(&NewOrderRequest {
            identifiers,
            not_before: None,
            not_after: None,
            replaces,
            profile,
        })?;
        let url = self.directory.new_order.clone();
        let resp = self.signed_request(&url, &payload).await?;
        resp.ensure_success()?;

        let order_url = resp.location()?;
        info!("Order URL: {order_url}");
        let order: Order = resp.json()?;
        Ok((order, order_url))
    }

    /// Finalize an order by submitting a CSR (RFC 8555 §7.4).
    pub async fn finalize_order(&mut self, finalize_url: &str, csr_der: &[u8]) -> Result<Order> {
        info!("Finalizing order");
        let payload = serde_json::to_string(&FinalizeRequest {
            csr: URL_SAFE_NO_PAD.encode(csr_der),
        })?;
        let resp = self.signed_request(finalize_url, &payload).await?;
        resp.ensure_success()?;
        resp.json()
    }

    /// Poll an order's current status (POST-as-GET).
    pub async fn poll_order(&mut self, order_url: &str) -> Result<Order> {
        debug!("Polling order: {order_url}");
        let resp = self.signed_request(order_url, "").await?;
        resp.ensure_success()?;
        resp.json()
    }

    // ── Authorization & challenge (RFC 8555 §7.5) ───────────────────────

    /// Fetch an authorization object (POST-as-GET).
    pub async fn get_authorization(&mut self, authz_url: &str) -> Result<Authorization> {
        debug!("Fetching authorization: {authz_url}");
        let resp = self.signed_request(authz_url, "").await?;
        resp.ensure_success()?;
        let authz: Authorization = resp.json()?;
        validate_server_identifier(&authz.identifier)?;
        Ok(authz)
    }

    /// Indicate to the server that a challenge is ready (RFC 8555 §7.5.1).
    ///
    /// The payload is an empty JSON object `{}`.
    pub async fn respond_to_challenge(&mut self, challenge_url: &str) -> Result<Challenge> {
        info!("Responding to challenge: {challenge_url}");
        let resp = self.signed_request(challenge_url, "{}").await?;
        resp.ensure_success()?;
        resp.json()
    }

    // ── Certificate (RFC 8555 §7.4.2, §7.6) ────────────────────────────

    /// Download the issued certificate chain (POST-as-GET).
    pub async fn download_certificate(&mut self, cert_url: &str) -> Result<String> {
        info!("Downloading certificate from {cert_url}");
        let resp = self.signed_request(cert_url, "").await?;
        resp.ensure_success()?;
        String::from_utf8(resp.body).context("certificate response is not valid UTF-8")
    }

    /// Roll over the account key (RFC 8555 §7.3.5).
    ///
    /// Replaces the current signing key with `new_key`.  The request is a
    /// nested JWS: the outer JWS is signed by the **old** (current) key
    /// and the inner JWS is signed by the **new** key.
    pub async fn key_change(&mut self, new_key: &AccountKey) -> Result<()> {
        let account_url = self
            .account_url
            .as_ref()
            .context("account URL not set - create an account first")?
            .clone();
        let key_change_url = self.directory.key_change.clone();

        info!("Rolling over account key (key-change)");

        // Inner payload: { "account": "<account-url>", "oldKey": <old-JWK> }
        let inner_payload = serde_json::to_string(&serde_json::json!({
            "account": account_url,
            "oldKey": self.account_key.jwk(),
        }))?;

        // Inner JWS signed by the NEW key (header has alg + jwk of new key + url)
        let inner_jws = new_key.sign_key_change_inner(&inner_payload, &key_change_url)?;

        // Outer JWS: POST to keyChange URL, payload is the inner JWS string
        let resp = self.signed_request(&key_change_url, &inner_jws).await?;
        resp.ensure_success()?;

        info!("Key rollover successful");
        Ok(())
    }

    /// Pre-authorize an identifier (RFC 8555 §7.4.1).
    ///
    /// Sends a POST to the `newAuthz` endpoint before creating an order.
    /// Returns `(authorization, authz_url)`.
    pub async fn new_authorization(
        &mut self,
        identifier: Identifier,
    ) -> Result<(Authorization, String)> {
        let url = self
            .directory
            .new_authz
            .clone()
            .context("server does not support pre-authorization (no newAuthz in directory)")?;
        info!(
            "Pre-authorizing identifier: {} ({})",
            identifier.value, identifier.identifier_type
        );
        let payload = serde_json::to_string(&NewAuthorizationRequest { identifier })?;
        let resp = self.signed_request(&url, &payload).await?;
        resp.ensure_success()?;
        let authz_url = resp.location()?;
        let authz: Authorization = resp.json()?;
        validate_server_identifier(&authz.identifier)?;
        Ok((authz, authz_url))
    }

    /// Revoke a certificate (RFC 8555 §7.6).
    pub async fn revoke_certificate(&mut self, cert_der: &[u8], reason: Option<u8>) -> Result<()> {
        info!("Revoking certificate");
        let payload = serde_json::to_string(&RevokeCertRequest {
            certificate: URL_SAFE_NO_PAD.encode(cert_der),
            reason,
        })?;
        let url = self.directory.revoke_cert.clone();
        let resp = self.signed_request(&url, &payload).await?;
        resp.ensure_success()?;
        Ok(())
    }

    // ── ACME Renewal Information (RFC 9702) ─────────────────────────────

    /// Fetch renewal information for a certificate (RFC 9702 §4).
    ///
    /// Returns the suggested renewal window and an optional `Retry-After`
    /// value (in seconds) from the response header.
    pub async fn get_renewal_info(
        &mut self,
        cert_der: &[u8],
    ) -> Result<(RenewalInfo, Option<u64>)> {
        let base_url = self
            .directory
            .renewal_info
            .as_ref()
            .context("server does not support ARI (no renewalInfo in directory)")?;

        let cert_id = compute_cert_id(cert_der)?;
        let url = format!("{base_url}/{cert_id}");
        info!("Fetching ARI renewal info: {url}");

        let resp = self.signed_request(&url, "").await?;
        resp.ensure_success()?;

        let retry_after = resp
            .headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let info: RenewalInfo = resp.json()?;
        Ok((info, retry_after))
    }

    /// Check whether the server supports ARI (has `renewalInfo` in directory).
    pub fn supports_ari(&self) -> bool {
        self.directory.renewal_info.is_some()
    }

    /// Return the advertised profiles (name → description), if any
    /// (draft-ietf-acme-profiles-01 §3).
    pub fn available_profiles(&self) -> Option<&HashMap<String, String>> {
        self.directory
            .meta
            .as_ref()
            .and_then(|m| m.profiles.as_ref())
    }
}

// ── ARI certID computation (RFC 9702 §4.1) ─────────────────────────────────

/// Compute the ARI certID: `base64url(AKI) "." base64url(Serial)`.
///
/// - AKI = raw bytes of the keyIdentifier from the Authority Key Identifier extension
/// - Serial = DER encoding of the certificate's serial number (as a signed INTEGER)
pub fn compute_cert_id(cert_der: &[u8]) -> Result<String> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow::anyhow!("failed to parse X.509 certificate: {e}"))?;

    // Extract Authority Key Identifier (OID 2.5.29.35)
    let aki_ext = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid == oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        .context("certificate has no Authority Key Identifier extension")?;

    let aki = match aki_ext.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => aki
            .key_identifier
            .as_ref()
            .context("AKI extension has no keyIdentifier")?,
        _ => anyhow::bail!("failed to parse Authority Key Identifier extension"),
    };

    // Serial number: encode as DER INTEGER
    let serial = cert.raw_serial();

    let aki_b64 = URL_SAFE_NO_PAD.encode(aki.0);
    let serial_b64 = URL_SAFE_NO_PAD.encode(serial);

    Ok(format!("{aki_b64}.{serial_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn rejects_non_http_schemes() {
        for url in [
            "file:///etc/passwd",
            "data:text/plain,x",
            "gopher://x",
            "ftp://x/",
        ] {
            assert!(
                validate_acme_url(
                    url,
                    TlsPolicy::AllowHttpLoopback,
                    NetworkPolicy::AllowPrivate
                )
                .is_err(),
                "{url} should be rejected"
            );
        }
    }

    #[test]
    fn https_public_host_ok() {
        assert!(
            validate_acme_url(
                "https://acme-v02.api.letsencrypt.org/directory",
                TlsPolicy::RequireHttps,
                NetworkPolicy::PublicOnly
            )
            .is_ok()
        );
    }

    #[test]
    fn http_rejected_without_insecure() {
        assert!(
            validate_acme_url(
                "http://localhost:14000/dir",
                TlsPolicy::RequireHttps,
                NetworkPolicy::PublicOnly
            )
            .is_err()
        );
    }

    #[test]
    fn http_loopback_ok_with_insecure() {
        for url in [
            "http://localhost/dir",
            "http://127.0.0.1:14000/dir",
            "http://[::1]/dir",
        ] {
            assert!(
                validate_acme_url(url, TlsPolicy::AllowHttpLoopback, NetworkPolicy::PublicOnly)
                    .is_ok(),
                "{url} should pass"
            );
        }
    }

    #[test]
    fn http_non_loopback_rejected_even_with_insecure() {
        assert!(
            validate_acme_url(
                "http://10.0.0.5/dir",
                TlsPolicy::AllowHttpLoopback,
                NetworkPolicy::AllowPrivate
            )
            .is_err()
        );
    }

    #[test]
    fn private_ipv4_literal_rejected_by_default() {
        for url in [
            "https://10.0.0.5/dir",
            "https://192.168.1.1/dir",
            "https://172.16.0.1/dir",
            "https://169.254.169.254/latest/meta-data/",
            "https://100.64.0.1/dir",
        ] {
            assert!(
                validate_acme_url(url, TlsPolicy::RequireHttps, NetworkPolicy::PublicOnly).is_err(),
                "{url} should be rejected"
            );
        }
    }

    #[test]
    fn private_ipv4_literal_allowed_with_opt_in() {
        assert!(
            validate_acme_url(
                "https://10.0.0.5/dir",
                TlsPolicy::RequireHttps,
                NetworkPolicy::AllowPrivate
            )
            .is_ok()
        );
    }

    #[test]
    fn private_ipv6_literal_rejected() {
        for url in [
            "https://[::1]/dir",
            "https://[fc00::1]/dir",
            "https://[fe80::1]/dir",
        ] {
            assert!(
                validate_acme_url(url, TlsPolicy::RequireHttps, NetworkPolicy::PublicOnly).is_err(),
                "{url} should be rejected"
            );
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_blocked_as_ipv4() {
        assert!(
            validate_acme_url(
                "https://[::ffff:10.0.0.5]/dir",
                TlsPolicy::RequireHttps,
                NetworkPolicy::PublicOnly
            )
            .is_err()
        );
        assert!(
            validate_acme_url(
                "https://[::ffff:10.0.0.5]/dir",
                TlsPolicy::RequireHttps,
                NetworkPolicy::AllowPrivate
            )
            .is_ok()
        );
    }

    #[test]
    fn classifies_private_ips() {
        assert!(is_private_or_special_ip(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(is_private_or_special_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(is_private_or_special_ip(IpAddr::V4(Ipv4Addr::new(
            100, 64, 0, 1
        ))));
        assert!(!is_private_or_special_ip(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(!is_private_or_special_ip(IpAddr::V4(Ipv4Addr::new(
            104, 16, 0, 1
        ))));
        assert!(is_private_or_special_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_private_or_special_ip("fc00::1".parse().unwrap()));
        assert!(is_private_or_special_ip("fe80::1".parse().unwrap()));
    }

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

    #[test]
    fn validate_acme_url_rejects_userinfo() {
        for url in [
            "https://attacker@trusted-ca.example/dir",
            "https://user:pass@trusted-ca.example/dir",
            "https://:pw@trusted-ca.example/dir",
        ] {
            assert!(
                validate_acme_url(url, TlsPolicy::RequireHttps, NetworkPolicy::PublicOnly).is_err(),
                "{url} should be rejected"
            );
        }
    }

    #[test]
    fn validate_acme_url_enforces_8000_octet_cap() {
        let host = "https://ca.example/";
        let pad_len = MAX_ACME_URL_LEN - host.len();
        let just_ok = format!("{host}{}", "a".repeat(pad_len));
        assert_eq!(just_ok.len(), MAX_ACME_URL_LEN);
        assert!(
            validate_acme_url(&just_ok, TlsPolicy::RequireHttps, NetworkPolicy::PublicOnly).is_ok()
        );
        let too_long = format!("{host}{}", "a".repeat(pad_len + 1));
        assert!(
            validate_acme_url(
                &too_long,
                TlsPolicy::RequireHttps,
                NetworkPolicy::PublicOnly
            )
            .is_err()
        );
    }

    #[test]
    fn validate_issuer_domain_name_accepts_canonical() {
        for d in ["example.com", "letsencrypt.org", "sub.example.co.uk"] {
            assert!(validate_issuer_domain_name(d).is_ok(), "{d}");
        }
    }

    #[test]
    fn validate_issuer_domain_name_lowercases() {
        let out = validate_issuer_domain_name("Example.COM").unwrap();
        assert_eq!(out, "example.com");
    }

    #[test]
    fn validate_issuer_domain_name_rejects_injection_attempts() {
        for d in [
            "evil.com; rogue=x",
            "evil.com;rogue",
            "evil.com\n",
            "evil.com ",
            "*.example.com",
            "_acme.example.com",
            "example.com.",
            "",
            "café.example",
        ] {
            assert!(
                validate_issuer_domain_name(d).is_err(),
                "{d:?} must be rejected"
            );
        }
    }

    #[test]
    fn validate_issuer_domain_name_enforces_length() {
        let too_long = format!("{}.example", "a".repeat(250));
        assert!(validate_issuer_domain_name(&too_long).is_err());
        let too_long_label = format!("{}.example", "a".repeat(64));
        assert!(validate_issuer_domain_name(&too_long_label).is_err());
    }

    #[test]
    fn validate_account_uri_accepts_https_and_http() {
        assert!(validate_account_uri("https://acme.example/acct/123").is_ok());
        assert!(validate_account_uri("http://acme.example/acct/123").is_ok());
    }

    #[test]
    fn validate_account_uri_rejects_injection_attempts() {
        for u in [
            "https://acme.example/acct;rogue=x",
            "https://acme.example/acct/1\n",
            "https://acme.example/acct/1 ",
            "https://user:pw@acme.example/acct/1",
            "https://attacker@acme.example/acct/1",
            "https://acme.example/acct/1#frag",
            "not-a-url",
            "",
            "https://acmé.example/acct/1",
        ] {
            assert!(validate_account_uri(u).is_err(), "{u:?} must be rejected");
        }
    }

    #[test]
    fn validate_account_uri_accepts_percent_encoded_semicolon() {
        // DNS TXT parsers split on literal `;`, not on `%3B`.
        assert!(validate_account_uri("https://acme.example/acct/1%3Bx").is_ok());
    }

    #[test]
    fn validate_caa_parameter_value_accepts_canonical() {
        for v in ["wildcard", "non-wildcard", "foo-bar", "v=1"] {
            assert!(validate_caa_parameter_value(v).is_ok(), "{v}");
        }
    }

    #[test]
    fn validate_caa_parameter_value_rejects_injection_attempts() {
        for v in [
            "wildcard; rogue=x",
            "wild card",
            "wild\nard",
            "wild\x7fard",
            "wildcardé",
            "",
        ] {
            assert!(
                validate_caa_parameter_value(v).is_err(),
                "{v:?} must be rejected"
            );
        }
    }
}
