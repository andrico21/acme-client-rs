//! ACME protocol types per RFC 8555

use serde::{Deserialize, Serialize};

// ── Challenge type constants (RFC 8555 §8) ──────────────────────────────────

pub const CHALLENGE_TYPE_HTTP01: &str = "http-01";
pub const CHALLENGE_TYPE_DNS01: &str = "dns-01";
pub const CHALLENGE_TYPE_TLSALPN01: &str = "tls-alpn-01";

// ── Directory (RFC 8555 §7.1.1) ─────────────────────────────────────────────

/// ACME Directory resource — the entry-point for all ACME operations.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub new_authz: Option<String>,
    pub revoke_cert: String,
    pub key_change: String,
    pub meta: Option<DirectoryMeta>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<bool>,
}

// ── Identifier (RFC 8555 §9.7.7) ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub identifier_type: String,
    pub value: String,
}

impl Identifier {
    pub fn dns(value: impl Into<String>) -> Self {
        Self {
            identifier_type: "dns".into(),
            value: value.into(),
        }
    }
}

// ── Account (RFC 8555 §7.1.2, §7.3) ─────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountRequest {
    pub terms_of_service_agreed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub status: AccountStatus,
    pub contact: Option<Vec<String>>,
    pub terms_of_service_agreed: Option<bool>,
    pub orders: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Deactivated => write!(f, "deactivated"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DeactivateAccountRequest {
    pub status: String,
}

// ── Order (RFC 8555 §7.1.3, §7.4) ───────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrderRequest {
    pub identifiers: Vec<Identifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub status: OrderStatus,
    pub expires: Option<String>,
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

impl std::fmt::Display for OrderStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Ready => write!(f, "ready"),
            Self::Processing => write!(f, "processing"),
            Self::Valid => write!(f, "valid"),
            Self::Invalid => write!(f, "invalid"),
        }
    }
}

// ── Authorization (RFC 8555 §7.1.4) ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    pub identifier: Identifier,
    pub status: AuthorizationStatus,
    pub expires: Option<String>,
    pub challenges: Vec<Challenge>,
    pub wildcard: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

impl std::fmt::Display for AuthorizationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Valid => write!(f, "valid"),
            Self::Invalid => write!(f, "invalid"),
            Self::Deactivated => write!(f, "deactivated"),
            Self::Expired => write!(f, "expired"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

// ── Challenge (RFC 8555 §7.1.5, §8) ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub url: String,
    pub status: ChallengeStatus,
    pub validated: Option<String>,
    pub token: Option<String>,
    pub error: Option<AcmeError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

impl std::fmt::Display for ChallengeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Processing => write!(f, "processing"),
            Self::Valid => write!(f, "valid"),
            Self::Invalid => write!(f, "invalid"),
        }
    }
}

// ── Finalize (RFC 8555 §7.4) ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FinalizeRequest {
    pub csr: String,
}

// ── Error (RFC 8555 §6.7, RFC 7807) ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AcmeError {
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub detail: Option<String>,
    pub status: Option<u16>,
    pub subproblems: Option<Vec<Subproblem>>,
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref detail) = self.detail {
            write!(f, "{detail}")?;
        }
        if let Some(ref error_type) = self.error_type {
            write!(f, " ({error_type})")?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct Subproblem {
    #[serde(rename = "type")]
    pub error_type: String,
    pub detail: Option<String>,
    pub identifier: Option<Identifier>,
}

// ── Certificate revocation (RFC 8555 §7.6) ──────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeCertRequest {
    pub certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<u8>,
}
