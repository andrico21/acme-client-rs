//! ACME HTTP client - drives the full RFC 8555 protocol flow.
//!
//! Every mutating request is a signed JWS POST.  Nonces are cached from
//! response headers and a single automatic retry is performed on `badNonce`.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::header::CONTENT_TYPE;
use tracing::{debug, info, warn};

use crate::jws::AccountKey;
use crate::types::*;

use std::collections::HashMap;

const JOSE_CONTENT_TYPE: &str = "application/jose+json";
const USER_AGENT_VALUE: &str = concat!("acme-client-rs/", env!("CARGO_PKG_VERSION"));

// ── Response wrapper ────────────────────────────────────────────────────────

/// Parsed ACME response (status + headers + body bytes).
struct AcmeResponse {
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

impl AcmeResponse {
    fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .with_context(|| {
                format!(
                    "failed to parse response body: {}",
                    String::from_utf8_lossy(&self.body)
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
                String::from_utf8_lossy(&self.body)
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
    /// Cached Replay-Nonce from the most recent server response.
    nonce: Option<String>,
    /// Account URL (returned in the Location header of newAccount).
    account_url: Option<String>,
}

impl AcmeClient {
    /// Create a new client by fetching the ACME directory.
    ///
    /// When `danger_accept_invalid_certs` is `true`, TLS certificate
    /// verification is disabled.  **Only use for testing** (e.g. Pebble).
    pub async fn new(
        directory_url: &str,
        account_key: AccountKey,
        danger_accept_invalid_certs: bool,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT_VALUE)
            .danger_accept_invalid_certs(danger_accept_invalid_certs)
            .build()
            .context("failed to build HTTP client")?;

        info!("Fetching ACME directory from {}", directory_url);
        let resp = http
            .get(directory_url)
            .send()
            .await
            .context("failed to fetch ACME directory")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "ACME directory request failed (HTTP {status}): {body}",
            );
        }

        let directory: Directory = resp.json().await.context("failed to parse directory")?;
        debug!(?directory, "ACME directory loaded");

        Ok(Self {
            http,
            directory,
            account_key,
            nonce: None,
            account_url: None,
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

    // ── Nonce management (RFC 8555 §7.2) ────────────────────────────────

    async fn fetch_nonce(&self) -> Result<String> {
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
        if let Some(val) = headers.get("replay-nonce") {
            if let Ok(s) = val.to_str() {
                self.nonce = Some(s.to_string());
            }
        }
    }

    // ── Signed POST with badNonce retry (RFC 8555 §6.2, §6.5) ──────────

    async fn signed_request(&mut self, url: &str, payload: &str) -> Result<AcmeResponse> {
        for attempt in 0u8..2 {
            let nonce = self.get_nonce().await?;

            let body = match self.account_url {
                Some(ref kid) => {
                    self.account_key.sign_with_kid(payload, &nonce, url, kid)?
                }
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
            if attempt == 0 && status == reqwest::StatusCode::BAD_REQUEST {
                if let Ok(err) = serde_json::from_slice::<AcmeError>(&body_bytes) {
                    if err.error_type.as_deref()
                        == Some("urn:ietf:params:acme:error:badNonce")
                    {
                        warn!("Received badNonce - retrying with fresh nonce");
                        continue;
                    }
                }
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
        self.new_order_inner(identifiers, Some(replaces), profile).await
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
    pub async fn finalize_order(
        &mut self,
        finalize_url: &str,
        csr_der: &[u8],
    ) -> Result<Order> {
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
        resp.json()
    }

    /// Indicate to the server that a challenge is ready (RFC 8555 §7.5.1).
    ///
    /// The payload is an empty JSON object `{}`.
    pub async fn respond_to_challenge(
        &mut self,
        challenge_url: &str,
    ) -> Result<Challenge> {
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
        info!("Pre-authorizing identifier: {} ({})", identifier.value, identifier.identifier_type);
        let payload = serde_json::to_string(&NewAuthorizationRequest { identifier })?;
        let resp = self.signed_request(&url, &payload).await?;
        resp.ensure_success()?;
        let authz_url = resp.location()?;
        let authz: Authorization = resp.json()?;
        Ok((authz, authz_url))
    }

    /// Revoke a certificate (RFC 8555 §7.6).
    pub async fn revoke_certificate(
        &mut self,
        cert_der: &[u8],
        reason: Option<u8>,
    ) -> Result<()> {
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
