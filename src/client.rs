//! ACME HTTP client — drives the full RFC 8555 protocol flow.
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

const JOSE_CONTENT_TYPE: &str = "application/jose+json";
const USER_AGENT_VALUE: &str = "acme-client-rs/0.1.0";

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
    pub async fn new(directory_url: &str, account_key: AccountKey) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT_VALUE)
            .build()
            .context("failed to build HTTP client")?;

        info!("Fetching ACME directory from {}", directory_url);
        let resp = http
            .get(directory_url)
            .send()
            .await
            .context("failed to fetch ACME directory")?;
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
                        warn!("Received badNonce — retrying with fresh nonce");
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
    pub async fn create_account(
        &mut self,
        contact: Option<Vec<String>>,
        terms_of_service_agreed: bool,
    ) -> Result<Account> {
        info!("Creating/looking-up ACME account");
        let payload = serde_json::to_string(&NewAccountRequest {
            terms_of_service_agreed,
            contact,
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
            .context("account URL not set — create an account first")?;
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
    ) -> Result<(Order, String)> {
        info!("Creating new order");
        let payload = serde_json::to_string(&NewOrderRequest {
            identifiers,
            not_before: None,
            not_after: None,
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
}
