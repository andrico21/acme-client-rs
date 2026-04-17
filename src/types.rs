//! ACME protocol types per RFC 8555

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Challenge type constants (RFC 8555 §8) ──────────────────────────────────

pub const CHALLENGE_TYPE_HTTP01: &str = "http-01";
pub const CHALLENGE_TYPE_DNS01: &str = "dns-01";
pub const CHALLENGE_TYPE_TLSALPN01: &str = "tls-alpn-01";
pub const CHALLENGE_TYPE_DNS_PERSIST01: &str = "dns-persist-01";

// ── Directory (RFC 8555 §7.1.1) ─────────────────────────────────────────────

/// ACME Directory resource - the entry-point for all ACME operations.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub new_authz: Option<String>,
    pub revoke_cert: String,
    pub key_change: String,
    pub renewal_info: Option<String>,
    pub meta: Option<DirectoryMeta>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<bool>,
    /// Certificate profiles (draft-ietf-acme-profiles-01 §3).
    /// Maps profile name → human-readable description.
    pub profiles: Option<HashMap<String, String>>,
}

// ── Identifier (RFC 8555 §9.7.7, RFC 8738 for IP) ────────────────────────────

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

    /// Create an IP identifier per RFC 8738.
    ///
    /// IPv6 addresses are normalized to their canonical form (RFC 5952)
    /// by parsing and re-formatting through `std::net::IpAddr`.
    pub fn ip(value: impl Into<String>) -> Self {
        let raw = value.into();
        // Normalize: parse as IpAddr then Display it back.
        // This gives canonical IPv6 (compressed, lowercase) per RFC 5952.
        let normalized = raw
            .parse::<std::net::IpAddr>()
            .map(|addr| addr.to_string())
            .unwrap_or(raw);
        Self {
            identifier_type: "ip".into(),
            value: normalized,
        }
    }

    /// Auto-detect whether `value` is an IP address or a DNS name.
    ///
    /// - Bare IPv4 (`1.2.3.4`) → `ip` identifier
    /// - Bare IPv6 (`::1`, `2001:db8::1`) → `ip` identifier
    /// - Bracketed IPv6 (`[::1]`) → `ip` identifier (brackets stripped)
    /// - Anything else → `dns` identifier
    pub fn from_str_auto(value: impl Into<String>) -> Self {
        let s = value.into();
        // Strip brackets for IPv6 literals like [::1]
        let candidate = if s.starts_with('[') && s.ends_with(']') {
            &s[1..s.len() - 1]
        } else {
            &s
        };
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            Self::ip(candidate)
        } else {
            Self::dns(s)
        }
    }

    /// Returns `true` if this is an IP identifier.
    pub fn is_ip(&self) -> bool {
        self.identifier_type == "ip"
    }
}

// ── Account (RFC 8555 §7.1.2, §7.3) ─────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountRequest {
    pub terms_of_service_agreed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
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
    /// ARI replacement indicator (RFC 9702 §5) - the certID of the cert being replaced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
    /// Certificate profile (draft-ietf-acme-profiles-01 §4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct Order {
    pub status: OrderStatus,
    pub expires: Option<String>,
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
    /// Certificate profile (draft-ietf-acme-profiles-01 §4).
    pub profile: Option<String>,
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
#[allow(dead_code)]
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
#[allow(
    dead_code,
    clippy::struct_field_names,
    reason = "'challenge_type' mirrors RFC 8555 JSON field 'type'"
)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub url: String,
    pub status: ChallengeStatus,
    pub validated: Option<String>,
    pub token: Option<String>,
    pub error: Option<AcmeError>,
    /// For dns-persist-01: issuer domain names provided by the CA.
    #[serde(default)]
    pub issuer_domain_names: Option<Vec<String>>,
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

// ── Pre-Authorization (RFC 8555 §7.4.1) ─────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct NewAuthorizationRequest {
    pub identifier: Identifier,
}

// ── Finalize (RFC 8555 §7.4) ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FinalizeRequest {
    pub csr: String,
}

// ── Error (RFC 8555 §6.7, RFC 7807) ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct Subproblem {
    #[serde(rename = "type")]
    pub error_type: String,
    pub detail: Option<String>,
    pub identifier: Option<Identifier>,
}

// ── Certificate revocation (RFC 8555 §7.6) ──────────────────────────────────

// ── ACME Renewal Information (RFC 9702) ──────────────────────────────────────

/// ARI renewal info response (RFC 9702 §4.2).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewalInfo {
    pub suggested_window: RenewalInfoWindow,
}

/// Time window within which the client should attempt renewal.
#[derive(Debug, Deserialize)]
pub struct RenewalInfoWindow {
    pub start: String,
    pub end: String,
}

// ── Certificate revocation (RFC 8555 §7.6) ──────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeCertRequest {
    pub certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<u8>,
}
