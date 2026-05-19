//! `AcmeClient` — RFC 8555 protocol driver.
//!
//! Every mutating request is a signed JWS POST. Nonces are cached from the
//! `Replay-Nonce` response header (RFC 8555 §6.5) and a single automatic
//! retry is performed on `badNonce` using the fresh nonce returned by the
//! rejecting response.
//!
//! The client is decomposed into two sub-structs:
//! - [`Directory`]: immutable after construction; holds the parsed ACME
//!   directory document (RFC 8555 §7.1.1). Public methods borrow URLs from
//!   here via `&self.directory.X` without ever cloning.
//! - [`Transport`]: mutable; holds the HTTP client, nonce cache, account
//!   URL, and the account signing key. Mutating methods take
//!   `&mut self.transport`.
//!
//! Because the two live in disjoint sub-fields, calls like
//! `self.transport.signed_request(&self.directory.new_order, …)` borrow
//! both halves at once without conflict. This is the "Struct Decomposition
//! for Independent Borrowing" pattern (`RUST_GUIDELINES` §6) and is what
//! lets the URL fields be typed as `url::Url` end-to-end instead of `String`.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::header::CONTENT_TYPE;
use std::collections::HashMap;
use tracing::{debug, info, warn};
use url::Url;

use crate::jws::AccountKey;
use crate::types::{
    Account, AcmeError, AcmeErrorType, Authorization, Challenge, DeactivateAccountRequest,
    Directory, FinalizeRequest, Identifier, NewAccountRequest, NewAuthorizationRequest,
    NewOrderRequest, Order, RenewalInfo, RevokeCertRequest, validate_server_identifier,
};

use super::http_transport::{AcmeResponse, build_http_client, truncate_for_log};
use super::net_policy::{NetworkPolicy, TlsPolicy, policies_from_cli_flags};
use super::url_validation::validate_acme_url;

/// Parse RFC 9110 `Retry-After` delta-seconds into a `Duration`.
/// Returns `None` if absent, unparseable, or in HTTP-date form (uncommon for ACME).
fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<std::time::Duration> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    raw.trim()
        .parse::<u64>()
        .ok()
        .map(std::time::Duration::from_secs)
}

const JOSE_CONTENT_TYPE: &str = "application/jose+json";

pub struct AcmeClient {
    /// Immutable after construction (RFC 8555 §7.1.1).
    directory: Directory,
    /// Mutable: nonce cache, account URL, HTTP client, signing key.
    transport: Transport,
}

/// Mutable per-session state extracted from `AcmeClient` so that public
/// methods can borrow `&self.directory.X` (URLs) and `&mut self.transport`
/// at the same call site without a borrow conflict.
struct Transport {
    http: reqwest::Client,
    account_key: AccountKey,
    nonce: Option<String>,
    account_url: Option<String>,
    insecure: bool,
    allow_private: bool,
}

impl Transport {
    fn url_policies(&self) -> (TlsPolicy, NetworkPolicy) {
        policies_from_cli_flags(self.insecure, self.allow_private)
    }

    // ── Nonce management (RFC 8555 §7.2) ────────────────────────────────

    async fn fetch_nonce(&self, new_nonce: &Url) -> Result<String> {
        {
            let (tls, net) = self.url_policies();
            validate_acme_url(new_nonce.as_str(), tls, net)
        }
        .with_context(|| "newNonce URL failed validation".to_string())?;
        debug!("Fetching fresh nonce via HEAD {new_nonce}");
        let resp = self
            .http
            .head(new_nonce.as_str())
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
        debug!("Obtained nonce: {nonce}");
        Ok(nonce)
    }

    async fn get_nonce(&mut self, new_nonce: &Url) -> Result<String> {
        match self.nonce.take() {
            Some(n) => Ok(n),
            None => self.fetch_nonce(new_nonce).await,
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

    /// Send a signed POST to `url`. `new_nonce` is the directory's newNonce
    /// endpoint, used only if the nonce cache is empty.
    async fn signed_request(
        &mut self,
        url: &Url,
        new_nonce: &Url,
        payload: &str,
    ) -> Result<AcmeResponse> {
        let url_str = url.as_str();
        {
            let (tls, net) = self.url_policies();
            validate_acme_url(url_str, tls, net)
        }
        .with_context(|| format!("signed_request target URL failed validation: {url_str}"))?;
        for attempt in 0u8..2 {
            let nonce = self.get_nonce(new_nonce).await?;

            let body = match self.account_url {
                Some(ref kid) => self
                    .account_key
                    .sign_with_kid(payload, &nonce, url_str, kid)?,
                None => self.account_key.sign_with_jwk(payload, &nonce, url_str)?,
            };

            debug!(%url, attempt, "Sending signed POST");
            let resp = self
                .http
                .post(url_str)
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
                && err
                    .error_type
                    .as_ref()
                    .is_some_and(AcmeErrorType::is_bad_nonce)
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
        tls: TlsPolicy,
        connect_timeout_secs: u64,
        network: NetworkPolicy,
    ) -> Result<Self> {
        let http = build_http_client(tls, connect_timeout_secs, network)?;

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

        let insecure = tls.accepts_invalid_certs();
        let allow_private = network.allows_private();
        for (label, url) in [
            ("newNonce", directory.new_nonce.as_str()),
            ("newAccount", directory.new_account.as_str()),
            ("newOrder", directory.new_order.as_str()),
            ("revokeCert", directory.revoke_cert.as_str()),
            ("keyChange", directory.key_change.as_str()),
        ] {
            validate_acme_url(url, tls, network)
                .with_context(|| format!("ACME directory advertises invalid {label} URL"))?;
        }
        if let Some(u) = directory.new_authz.as_ref() {
            validate_acme_url(u.as_str(), tls, network)
                .with_context(|| "ACME directory advertises invalid newAuthz URL".to_string())?;
        }
        if let Some(u) = directory.renewal_info.as_ref() {
            validate_acme_url(u.as_str(), tls, network)
                .with_context(|| "ACME directory advertises invalid renewalInfo URL".to_string())?;
        }

        Ok(Self {
            directory,
            transport: Transport {
                http,
                account_key,
                nonce: None,
                account_url: None,
                insecure,
                allow_private,
            },
        })
    }

    // ── Accessors ───────────────────────────────────────────────────────

    pub fn set_account_url(&mut self, url: impl Into<String>) {
        self.transport.account_url = Some(url.into());
    }

    pub fn account_url(&self) -> Option<&str> {
        self.transport.account_url.as_deref()
    }

    pub fn account_key(&self) -> &AccountKey {
        &self.transport.account_key
    }

    #[allow(dead_code)]
    pub fn directory(&self) -> &Directory {
        &self.directory
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
            Some(self.transport.account_key.sign_eab(
                kid,
                hmac_key,
                self.directory.new_account.as_str(),
            )?)
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
        let resp = self
            .transport
            .signed_request(
                &self.directory.new_account,
                &self.directory.new_nonce,
                &payload,
            )
            .await?;
        resp.ensure_success()?;

        let account_url = resp.location()?;
        info!("Account URL: {account_url}");
        self.transport.account_url = Some(account_url.to_string());

        resp.json()
    }

    /// Deactivate the current account (RFC 8555 §7.3.6).
    pub async fn deactivate_account(&mut self) -> Result<Account> {
        let url: Url = self
            .transport
            .account_url
            .as_deref()
            .context("account URL not set - create an account first")?
            .parse()
            .context("stored account URL is not a valid URL")?;
        info!("Deactivating account: {url}");

        let payload = serde_json::to_string(&DeactivateAccountRequest {
            status: "deactivated".into(),
        })?;
        let resp = self
            .transport
            .signed_request(&url, &self.directory.new_nonce, &payload)
            .await?;
        resp.ensure_success()?;
        resp.json()
    }

    // ── Order operations (RFC 8555 §7.4) ────────────────────────────────

    /// Submit a new order.  Returns `(order, order_url)`.
    pub async fn new_order(
        &mut self,
        identifiers: Vec<Identifier>,
        profile: Option<impl Into<String>>,
    ) -> Result<(Order, Url)> {
        self.new_order_inner(identifiers, None, profile.map(Into::into))
            .await
    }

    /// Submit a replacement order (ARI, RFC 9702 §5).
    ///
    /// `replaces` is the ARI certID of the certificate being replaced.
    pub async fn new_order_replacing(
        &mut self,
        identifiers: Vec<Identifier>,
        replaces: impl Into<String>,
        profile: Option<impl Into<String>>,
    ) -> Result<(Order, Url)> {
        self.new_order_inner(identifiers, Some(replaces.into()), profile.map(Into::into))
            .await
    }

    async fn new_order_inner(
        &mut self,
        identifiers: Vec<Identifier>,
        replaces: Option<String>,
        profile: Option<String>,
    ) -> Result<(Order, Url)> {
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
        let resp = self
            .transport
            .signed_request(
                &self.directory.new_order,
                &self.directory.new_nonce,
                &payload,
            )
            .await?;
        resp.ensure_success()?;

        let order_url = resp.location()?;
        info!("Order URL: {order_url}");
        let order: Order = resp.json()?;
        Ok((order, order_url))
    }

    /// Finalize an order by submitting a CSR (RFC 8555 §7.4).
    pub async fn finalize_order(&mut self, finalize_url: &Url, csr_der: &[u8]) -> Result<Order> {
        info!("Finalizing order");
        let payload = serde_json::to_string(&FinalizeRequest {
            csr: URL_SAFE_NO_PAD.encode(csr_der),
        })?;
        let resp = self
            .transport
            .signed_request(finalize_url, &self.directory.new_nonce, &payload)
            .await?;
        resp.ensure_success()?;
        resp.json()
    }

    /// Poll an order's current status (POST-as-GET).
    pub async fn poll_order(&mut self, order_url: &Url) -> Result<Order> {
        Ok(self.poll_order_with_retry_after(order_url).await?.0)
    }

    /// Poll an order's current status, returning the server-suggested
    /// `Retry-After` delay (RFC 8555 §7.4 / RFC 9110 §10.2.3) if present.
    pub async fn poll_order_with_retry_after(
        &mut self,
        order_url: &Url,
    ) -> Result<(Order, Option<std::time::Duration>)> {
        debug!("Polling order: {order_url}");
        let resp = self
            .transport
            .signed_request(order_url, &self.directory.new_nonce, "")
            .await?;
        resp.ensure_success()?;
        let retry_after = parse_retry_after(&resp.headers);
        let order: Order = resp.json()?;
        Ok((order, retry_after))
    }

    // ── Authorization & challenge (RFC 8555 §7.5) ───────────────────────

    /// Fetch an authorization object (POST-as-GET).
    pub async fn get_authorization(&mut self, authz_url: &Url) -> Result<Authorization> {
        debug!("Fetching authorization: {authz_url}");
        let resp = self
            .transport
            .signed_request(authz_url, &self.directory.new_nonce, "")
            .await?;
        resp.ensure_success()?;
        let authz: Authorization = resp.json()?;
        validate_server_identifier(&authz.identifier)?;
        Ok(authz)
    }

    /// Indicate to the server that a challenge is ready (RFC 8555 §7.5.1).
    ///
    /// The payload is an empty JSON object `{}`.
    pub async fn respond_to_challenge(&mut self, challenge_url: &Url) -> Result<Challenge> {
        info!("Responding to challenge: {challenge_url}");
        let resp = self
            .transport
            .signed_request(challenge_url, &self.directory.new_nonce, "{}")
            .await?;
        resp.ensure_success()?;
        resp.json()
    }

    // ── Certificate (RFC 8555 §7.4.2, §7.6) ────────────────────────────

    /// Download the issued certificate chain (POST-as-GET).
    pub async fn download_certificate(&mut self, cert_url: &Url) -> Result<String> {
        info!("Downloading certificate from {cert_url}");
        let resp = self
            .transport
            .signed_request(cert_url, &self.directory.new_nonce, "")
            .await?;
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
            .transport
            .account_url
            .as_deref()
            .context("account URL not set - create an account first")?;

        info!("Rolling over account key (key-change)");

        // Inner payload: { "account": "<account-url>", "oldKey": <old-JWK> }
        let inner_payload = serde_json::to_string(&serde_json::json!({
            "account": account_url,
            "oldKey": self.transport.account_key.jwk()?,
        }))?;

        // Inner JWS signed by the NEW key (header has alg + jwk of new key + url)
        let inner_jws =
            new_key.sign_key_change_inner(&inner_payload, self.directory.key_change.as_str())?;

        // Outer JWS: POST to keyChange URL, payload is the inner JWS string
        let resp = self
            .transport
            .signed_request(
                &self.directory.key_change,
                &self.directory.new_nonce,
                &inner_jws,
            )
            .await?;
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
    ) -> Result<(Authorization, Url)> {
        let new_authz = self
            .directory
            .new_authz
            .as_ref()
            .context("server does not support pre-authorization (no newAuthz in directory)")?;
        info!(
            "Pre-authorizing identifier: {} ({})",
            identifier.value_str(),
            identifier.type_str()
        );
        let payload = serde_json::to_string(&NewAuthorizationRequest { identifier })?;
        let resp = self
            .transport
            .signed_request(new_authz, &self.directory.new_nonce, &payload)
            .await?;
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
        let resp = self
            .transport
            .signed_request(
                &self.directory.revoke_cert,
                &self.directory.new_nonce,
                &payload,
            )
            .await?;
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
        // RFC 9702 §4.1: ARI URL is `<renewalInfo>/<certID>`. Use Url::join
        // for proper path composition (handles trailing-slash semantics and
        // re-validates the resulting URL).
        let mut joined = base_url.clone();
        joined
            .path_segments_mut()
            .map_err(|()| anyhow::anyhow!("renewalInfo URL is cannot-be-base"))?
            .push(&cert_id);
        info!("Fetching ARI renewal info: {joined}");

        let resp = self
            .transport
            .signed_request(&joined, &self.directory.new_nonce, "")
            .await?;
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
    #[must_use]
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
#[allow(clippy::wildcard_enum_match_arm)]
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
