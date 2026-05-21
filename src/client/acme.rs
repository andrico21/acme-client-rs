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

/// JWS signing-mode selector for `Transport::signed_request_inner`.
///
/// `Auto` picks KID when `account_url` is `Some`, JWK otherwise — the
/// default for every endpoint except `newAccount`. `ForceJwk` overrides
/// the cached `account_url` and signs with the inline JWK, as required
/// by RFC 8555 §6.2 for newAccount even when this client previously
/// learned an account URL (e.g. from a same-process ARI precheck).
#[derive(Clone, Copy)]
enum SigningMode {
    Auto,
    ForceJwk,
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

    // NOT cancel-safe: HEAD newNonce consumes a server nonce; drop mid-flight
    // leaks a nonce slot until the CA's TTL expires.
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

    // NOT cancel-safe: pops cached nonce or calls fetch_nonce; cancellation
    // mid-fetch leaks a nonce.
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
    ///
    /// Signing mode is auto-selected from `account_url`: KID if set,
    /// JWK otherwise. For newAccount, callers MUST use
    /// [`signed_request_force_jwk`] instead — RFC 8555 §6.2 forbids `kid`
    /// on `newAccount` regardless of any cached account URL on the same
    /// client instance.
    // NOT cancel-safe: consumes a nonce and may mutate server state (account,
    // order, authz, challenge). Drop mid-POST leaves CA-side state partially
    // updated; retry with fresh nonce is the only recovery.
    async fn signed_request(
        &mut self,
        url: &Url,
        new_nonce: &Url,
        payload: &str,
    ) -> Result<AcmeResponse> {
        self.signed_request_inner(url, new_nonce, payload, SigningMode::Auto)
            .await
    }

    /// Send a signed POST to `url` with the **JWK** signing mode forced,
    /// regardless of whether `account_url` is already set on this client.
    ///
    /// RFC 8555 §6.2 mandates `jwk` (not `kid`) on `newAccount` requests.
    /// This entry point exists so a single client instance can be reused
    /// for multiple newAccount calls (e.g. after an ARI precheck stashed
    /// an account URL) without violating §6.2.
    // NOT cancel-safe: same as `signed_request`.
    async fn signed_request_force_jwk(
        &mut self,
        url: &Url,
        new_nonce: &Url,
        payload: &str,
    ) -> Result<AcmeResponse> {
        self.signed_request_inner(url, new_nonce, payload, SigningMode::ForceJwk)
            .await
    }

    // NOT cancel-safe: see `signed_request`.
    async fn signed_request_inner(
        &mut self,
        url: &Url,
        new_nonce: &Url,
        payload: &str,
        mode: SigningMode,
    ) -> Result<AcmeResponse> {
        let url_str = url.as_str();
        {
            let (tls, net) = self.url_policies();
            validate_acme_url(url_str, tls, net)
        }
        .with_context(|| format!("signed_request target URL failed validation: {url_str}"))?;
        for attempt in 0u8..2 {
            let nonce = self.get_nonce(new_nonce).await?;

            let body = match (mode, self.account_url.as_deref()) {
                (SigningMode::ForceJwk, _) | (SigningMode::Auto, None) => self
                    .account_key
                    .sign_with_jwk(payload, &nonce, url_str)
                    .with_context(|| format!("failed to sign JWS POST to {url_str} with JWK"))?,
                (SigningMode::Auto, Some(kid)) => self
                    .account_key
                    .sign_with_kid(payload, &nonce, url_str, kid)
                    .with_context(|| format!("failed to sign JWS POST to {url_str} with KID"))?,
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
    // cancel-safe: GET /directory is idempotent and read-only.
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
    // NOT cancel-safe: POST newAccount creates/looks-up account on CA. Drop
    // mid-flight may leave a half-registered account; caller must re-issue with
    // onlyReturnExisting=true to recover.
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
            .signed_request_force_jwk(
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
    // NOT cancel-safe: irreversibly deactivates the account on the CA.
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
    // NOT cancel-safe: creates a new order on the CA (rate-limit consuming).
    pub async fn new_order(
        &mut self,
        identifiers: Vec<Identifier>,
        profile: Option<impl Into<String>>,
    ) -> Result<(Order, Url)> {
        self.new_order_inner(identifiers, None, profile.map(Into::into))
            .await
    }

    /// Submit a replacement order (ARI, RFC 9773 §5).
    ///
    /// `replaces` is the ARI certID of the certificate being replaced.
    // NOT cancel-safe: creates a new (replaces) order on the CA per RFC 9773.
    pub async fn new_order_replacing(
        &mut self,
        identifiers: Vec<Identifier>,
        replaces: impl Into<String>,
        profile: Option<impl Into<String>>,
    ) -> Result<(Order, Url)> {
        self.new_order_inner(identifiers, Some(replaces.into()), profile.map(Into::into))
            .await
    }

    // NOT cancel-safe: inner POST newOrder; same semantics as new_order.
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
    // NOT cancel-safe: submits CSR; CA begins issuance. Drop mid-flight may
    // still produce a certificate on the CA side that the client never sees.
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
    // NOT cancel-safe: POST-as-GET still consumes a nonce, but order state is
    // unaffected; safe to retry.
    pub async fn poll_order(&mut self, order_url: &Url) -> Result<Order> {
        Ok(self.poll_order_with_retry_after(order_url).await?.0)
    }

    /// Poll an order's current status, returning the server-suggested
    /// `Retry-After` delay (RFC 8555 §7.4 / RFC 9110 §10.2.3) if present.
    // NOT cancel-safe: consumes a nonce per poll; order state read-only but
    // nonce leakage on cancel.
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
    // NOT cancel-safe: nonce-consuming POST-as-GET; authz state read-only.
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
    // NOT cancel-safe: triggers CA-side validation attempt; drop mid-flight
    // may still cause the CA to attempt validation against the deployed token.
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
    // NOT cancel-safe: nonce-consuming POST-as-GET; cert payload itself is
    // immutable, so retry is safe.
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
    // NOT cancel-safe: rotates the account key on the CA. Drop mid-flight may
    // leave the CA with the new key active while the client still believes it
    // holds the old one - manual reconciliation required.
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
    // NOT cancel-safe: creates a new authz on the CA (pre-authorization flow).
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
    // NOT cancel-safe: irreversibly revokes the certificate. CA may complete
    // revocation even if the client drops mid-flight.
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

    // ── ACME Renewal Information (RFC 9773) ─────────────────────────────

    /// Fetch renewal information for a certificate (RFC 9773 §4.1).
    ///
    /// Returns the suggested renewal window and an optional `Retry-After`
    /// value (in seconds) from the response header.
    ///
    /// Per RFC 9773 §4.1+§6, the ARI lookup is an **unauthenticated GET**
    /// — it MUST NOT be a POST-as-GET, and it MUST NOT require an account.
    /// This means the call does not consume a nonce and is safe to issue
    /// before `create_account`.
    // cancel-safe: unauthenticated GET; no nonce consumption, no server-side
    // state mutation.
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
        let mut joined = base_url.clone();
        joined
            .path_segments_mut()
            .map_err(|()| anyhow::anyhow!("renewalInfo URL is cannot-be-base"))?
            .push(&cert_id);
        info!("Fetching ARI renewal info: {joined}");

        let url_str = joined.as_str();
        {
            let (tls, net) = self.transport.url_policies();
            validate_acme_url(url_str, tls, net)
        }
        .with_context(|| format!("ARI renewalInfo URL failed validation: {url_str}"))?;

        let resp = self
            .transport
            .http
            .get(url_str)
            .send()
            .await
            .context("ARI renewalInfo GET request failed")?;

        let status = resp.status();
        let headers = resp.headers().clone();
        let body_bytes = resp.bytes().await?.to_vec();
        let parsed = AcmeResponse {
            status,
            headers,
            body: body_bytes,
        };
        parsed.ensure_success()?;

        let retry_after = parsed
            .headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let info: RenewalInfo = parsed.json()?;
        info.validate_window()?;
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

// ── ARI certID computation (RFC 9773 §4.1) ─────────────────────────────────

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

// ── Regression tests ────────────────────────────────────────────────────────
//
// These tests guard the fix for the ARI double-newAccount bug. Before the
// fix, `Transport::signed_request` chose `jwk` vs `kid` purely on whether
// `account_url` was `Some`. Calling `create_account` twice on the same
// client (e.g. with `--ari` doing a precheck) then signed the second
// newAccount with `kid`, which step-ca correctly rejects with HTTP 400
// "jwk expected in protected header" (RFC 8555 §6.2).
#[cfg(test)]
mod regression_tests {
    use super::*;
    use crate::jws::{AccountKey, KeyAlgorithm};
    use anyhow::{Result, anyhow, bail};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[derive(Debug, Clone)]
    struct CapturedRequest {
        method: String,
        path: String,
        body: Vec<u8>,
    }

    #[derive(Clone)]
    struct Route {
        method: &'static str,
        path_prefix: &'static str,
        status_line: &'static str,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    fn build_response(route: &Route, nonce: &str) -> Vec<u8> {
        use std::fmt::Write as _;
        let mut headers = String::new();
        headers.push_str(route.status_line);
        headers.push_str("\r\n");
        let _ = writeln!(headers, "Replay-Nonce: {nonce}\r");
        headers.push_str("connection: close\r\n");
        for (k, v) in &route.extra_headers {
            let _ = writeln!(headers, "{k}: {v}\r");
        }
        let _ = writeln!(headers, "content-length: {}\r", route.body.len());
        headers.push_str("\r\n");
        let mut out = headers.into_bytes();
        out.extend_from_slice(&route.body);
        out
    }

    /// Spawn an inline HTTP/1.1 mock on the given pre-bound listener.
    /// Routes are matched by method + path-prefix.
    fn spawn_mock(listener: TcpListener, routes: Vec<Route>) -> Arc<Mutex<Vec<CapturedRequest>>> {
        let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = Arc::clone(&captured);
        let routes = Arc::new(routes);
        let nonce_counter = Arc::new(Mutex::new(0u64));

        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let captured = Arc::clone(&captured_clone);
                let routes = Arc::clone(&routes);
                let nonce_counter = Arc::clone(&nonce_counter);
                tokio::spawn(async move {
                    // Fire-and-forget: any I/O failure simply drops the
                    // connection. The test will fail loudly via missing
                    // captured requests if the mock can't talk.
                    let _ = handle_connection(socket, &captured, &routes, &nonce_counter).await;
                });
            }
        });

        captured
    }

    async fn handle_connection(
        mut socket: tokio::net::TcpStream,
        captured: &Mutex<Vec<CapturedRequest>>,
        routes: &[Route],
        nonce_counter: &Mutex<u64>,
    ) -> Result<()> {
        // Read until we have full headers (\r\n\r\n), then body by Content-Length.
        let mut buf = Vec::with_capacity(4096);
        let header_end = loop {
            let mut chunk = [0u8; 1024];
            let n = socket.read(&mut chunk).await?;
            if n == 0 {
                bail!("client closed before headers");
            }
            buf.extend_from_slice(chunk.get(..n).ok_or_else(|| anyhow!("range"))?);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if buf.len() > 64 * 1024 {
                bail!("headers too large");
            }
        };

        let header_slice = buf
            .get(..header_end.saturating_sub(4))
            .ok_or_else(|| anyhow!("header range"))?;
        let header_text = std::str::from_utf8(header_slice).context("headers not UTF-8")?;
        let mut lines = header_text.split("\r\n");
        let request_line = lines.next().ok_or_else(|| anyhow!("no request line"))?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();

        let mut content_length: usize = 0;
        for line in lines {
            if let Some((k, v)) = line.split_once(':')
                && k.trim().eq_ignore_ascii_case("content-length")
            {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }

        let body_slice = buf.get(header_end..).ok_or_else(|| anyhow!("body range"))?;
        let mut body = body_slice.to_vec();
        while body.len() < content_length {
            let mut chunk = [0u8; 4096];
            let n = socket.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(chunk.get(..n).ok_or_else(|| anyhow!("range"))?);
        }
        body.truncate(content_length);

        {
            let mut lock = captured.lock().map_err(|_| anyhow!("poisoned"))?;
            lock.push(CapturedRequest {
                method: method.clone(),
                path: path.clone(),
                body: body.clone(),
            });
        }

        let route = routes
            .iter()
            .find(|r| r.method.eq_ignore_ascii_case(&method) && path.starts_with(r.path_prefix));
        let response = match route {
            Some(r) => {
                let counter_value = {
                    let mut ctr = nonce_counter.lock().map_err(|_| anyhow!("poisoned"))?;
                    *ctr += 1;
                    *ctr
                };
                let nonce = format!("nonce-{counter_value:08}");
                build_response(r, &nonce)
            }
            None => {
                b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec()
            }
        };
        socket.write_all(&response).await?;
        socket.shutdown().await?;
        Ok(())
    }

    fn directory_json(port: u16, include_ari: bool) -> Vec<u8> {
        let ari = if include_ari {
            format!(",\"renewalInfo\":\"http://127.0.0.1:{port}/renewalInfo\"")
        } else {
            String::new()
        };
        format!(
            "{{\"newNonce\":\"http://127.0.0.1:{port}/new-nonce\",\
             \"newAccount\":\"http://127.0.0.1:{port}/new-account\",\
             \"newOrder\":\"http://127.0.0.1:{port}/new-order\",\
             \"revokeCert\":\"http://127.0.0.1:{port}/revoke-cert\",\
             \"keyChange\":\"http://127.0.0.1:{port}/key-change\"\
             {ari}}}"
        )
        .into_bytes()
    }

    fn protected_header_of(body: &[u8]) -> Result<serde_json::Value> {
        let flat: serde_json::Value = serde_json::from_slice(body)?;
        let protected_b64 = flat
            .get("protected")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("no protected field"))?;
        let bytes = URL_SAFE_NO_PAD.decode(protected_b64)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn build_client(port: u16) -> Result<AcmeClient> {
        let (tls, net) = super::super::net_policy::policies_from_cli_flags(true, true);
        let key = AccountKey::generate(KeyAlgorithm::Es256)?;
        let url = format!("http://127.0.0.1:{port}/directory");
        AcmeClient::new(&url, key, tls, 5, net).await
    }

    fn account_routes(port: u16, include_ari: bool) -> Vec<Route> {
        vec![
            Route {
                method: "GET",
                path_prefix: "/directory",
                status_line: "HTTP/1.1 200 OK",
                extra_headers: vec![("content-type".into(), "application/json".into())],
                body: directory_json(port, include_ari),
            },
            Route {
                method: "HEAD",
                path_prefix: "/new-nonce",
                status_line: "HTTP/1.1 200 OK",
                extra_headers: vec![],
                body: vec![],
            },
            Route {
                method: "POST",
                path_prefix: "/new-account",
                status_line: "HTTP/1.1 201 Created",
                extra_headers: vec![
                    (
                        "Location".into(),
                        format!("http://127.0.0.1:{port}/account/1"),
                    ),
                    ("content-type".into(), "application/json".into()),
                ],
                body: br#"{"status":"valid"}"#.to_vec(),
            },
        ]
    }

    fn collect_captured(captured: &Mutex<Vec<CapturedRequest>>) -> Result<Vec<CapturedRequest>> {
        Ok(captured.lock().map_err(|_| anyhow!("poisoned"))?.clone())
    }

    // ── T1 ──────────────────────────────────────────────────────────────
    #[tokio::test]
    async fn create_account_signs_with_jwk_even_when_account_url_set() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let captured = spawn_mock(listener, account_routes(port, false));

        let mut client = build_client(port).await?;
        client.create_account(None, true, None).await?;

        let posts: Vec<_> = collect_captured(&captured)?
            .into_iter()
            .filter(|r| r.method == "POST" && r.path == "/new-account")
            .collect();
        assert_eq!(posts.len(), 1, "expected exactly one POST /new-account");
        let first = posts.first().ok_or_else(|| anyhow!("no post"))?;
        let header = protected_header_of(&first.body)?;
        assert!(
            header.get("jwk").is_some(),
            "newAccount protected header must contain `jwk` (RFC 8555 §6.2), got: {header}"
        );
        assert!(
            header.get("kid").is_none(),
            "newAccount protected header must NOT contain `kid`, got: {header}"
        );
        Ok(())
    }

    // ── T2 ──────────────────────────────────────────────────────────────
    #[tokio::test]
    async fn create_account_twice_still_signs_with_jwk_on_second_call() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let captured = spawn_mock(listener, account_routes(port, false));

        let mut client = build_client(port).await?;

        client.create_account(None, true, None).await?;
        assert!(
            client.account_url().is_some(),
            "account_url should be set after first create_account"
        );

        client.create_account(None, true, None).await?;

        let posts: Vec<_> = collect_captured(&captured)?
            .into_iter()
            .filter(|r| r.method == "POST" && r.path == "/new-account")
            .collect();
        assert_eq!(posts.len(), 2, "expected two POST /new-account calls");

        for (i, post) in posts.iter().enumerate() {
            let header = protected_header_of(&post.body)?;
            assert!(
                header.get("jwk").is_some(),
                "newAccount call #{} must use jwk (RFC 8555 §6.2), got: {header}",
                i + 1
            );
            assert!(
                header.get("kid").is_none(),
                "newAccount call #{} must NOT use kid, got: {header}",
                i + 1
            );
        }
        Ok(())
    }

    // ── T3 ──────────────────────────────────────────────────────────────
    #[tokio::test]
    async fn get_renewal_info_uses_unauthenticated_get() -> Result<()> {
        use rcgen::{
            BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        let mut routes = account_routes(port, true);
        routes.push(Route {
            method: "GET",
            path_prefix: "/renewalInfo/",
            status_line: "HTTP/1.1 200 OK",
            extra_headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"suggestedWindow":{"start":"2026-01-01T00:00:00Z","end":"2026-01-02T00:00:00Z"}}"#.to_vec(),
        });
        let captured = spawn_mock(listener, routes);

        // Leaf cert signed by a CA so it carries the AKI extension required
        // by RFC 9773 §4.1 certID computation.
        let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut issuer_params = CertificateParams::new(vec!["Test CA".into()])?;
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = Issuer::new(issuer_params, issuer_key);
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut leaf_params = CertificateParams::new(vec!["test.example".into()])?;
        leaf_params.use_authority_key_identifier_extension = true;
        let leaf = leaf_params.signed_by(&leaf_key, &issuer)?;
        let cert_der = leaf.der().to_vec();

        let mut client = build_client(port).await?;
        // No create_account before the call — verifies the codepath is
        // truly unauthenticated.
        assert!(client.account_url().is_none());
        let (_info, _retry) = client.get_renewal_info(&cert_der).await?;
        assert!(
            client.account_url().is_none(),
            "get_renewal_info must not set account_url"
        );

        let reqs = collect_captured(&captured)?;
        let ari_reqs: Vec<_> = reqs
            .iter()
            .filter(|r| r.path.starts_with("/renewalInfo/"))
            .collect();
        assert_eq!(ari_reqs.len(), 1, "expected one ARI request");
        let ari = ari_reqs.first().ok_or_else(|| anyhow!("no ari"))?;
        assert_eq!(
            ari.method, "GET",
            "ARI must be unauthenticated GET (RFC 9773 §6), not {:?}",
            ari.method
        );
        let any_post_ari = reqs
            .iter()
            .any(|r| r.method == "POST" && r.path.starts_with("/renewalInfo"));
        assert!(!any_post_ari, "ARI must not be a POST");
        Ok(())
    }

    // ── T4 ──────────────────────────────────────────────────────────────
    #[test]
    fn renewal_info_validate_window_rejects_inverted_window() -> Result<()> {
        let json =
            r#"{"suggestedWindow":{"start":"2026-01-02T00:00:00Z","end":"2026-01-01T00:00:00Z"}}"#;
        let info: RenewalInfo = serde_json::from_str(json)?;
        assert!(
            info.validate_window().is_err(),
            "inverted window (end<start) must be rejected"
        );

        let json_equal =
            r#"{"suggestedWindow":{"start":"2026-01-01T00:00:00Z","end":"2026-01-01T00:00:00Z"}}"#;
        let info_equal: RenewalInfo = serde_json::from_str(json_equal)?;
        assert!(
            info_equal.validate_window().is_err(),
            "degenerate window (end==start) must be rejected per RFC 9773 §4.2"
        );
        Ok(())
    }

    // ── T5 ──────────────────────────────────────────────────────────────
    #[test]
    fn renewal_info_parses_explanation_url() -> Result<()> {
        let json = r#"{"suggestedWindow":{"start":"2026-01-01T00:00:00Z","end":"2026-01-02T00:00:00Z"},"explanationURL":"https://example.com/why"}"#;
        let info: RenewalInfo = serde_json::from_str(json)?;
        assert!(info.validate_window().is_ok());
        assert_eq!(
            info.explanation_url.as_deref(),
            Some("https://example.com/why")
        );

        let json_absent =
            r#"{"suggestedWindow":{"start":"2026-01-01T00:00:00Z","end":"2026-01-02T00:00:00Z"}}"#;
        let info_absent: RenewalInfo = serde_json::from_str(json_absent)?;
        assert!(info_absent.explanation_url.is_none());
        Ok(())
    }
}
