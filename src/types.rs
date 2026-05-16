//! ACME protocol types per RFC 8555

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
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

    /// Auto-detect whether `value` is an IP address or a DNS name, and
    /// validate + normalize it for use as an ACME identifier per RFC 8555.
    ///
    /// - Bare IPv4 (`1.2.3.4`) → `ip` identifier
    /// - Bare IPv6 (`::1`, `2001:db8::1`) → `ip` identifier
    /// - Bracketed IPv6 (`[::1]`) → `ip` identifier (brackets stripped)
    /// - Anything else → `dns` identifier, run through
    ///   [`validate_and_normalize_dns`]
    pub fn from_str_auto(value: impl Into<String>) -> Result<Self> {
        let s = value.into();
        // Strip brackets for IPv6 literals like [::1]
        let candidate = if s.starts_with('[') && s.ends_with(']') {
            &s[1..s.len() - 1]
        } else {
            &s
        };
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            Ok(Self::ip(candidate))
        } else {
            Ok(Self::dns(validate_and_normalize_dns(&s)?))
        }
    }

    /// Returns `true` if this is an IP identifier.
    pub fn is_ip(&self) -> bool {
        self.identifier_type == "ip"
    }
}

/// Validate and normalize a DNS identifier per RFC 8555 §7.1.3 / §9.7.5
/// and RFC 5280 §7 (which references RFC 1034 preferred name syntax).
///
/// Steps:
/// 1. Strip a single trailing dot — RFC 1034 preferred name syntax used
///    in certificates has no trailing dot (the dot is the zone-file
///    convention for an absolute name).
/// 2. Reject empty / whitespace-only input.
/// 3. Validate wildcard form: `*` is allowed only as the leftmost label,
///    exactly once, and must be followed by a base domain. Multiple `*`
///    or `*` not in the leftmost position is malformed (RFC 8555 §7.1.3).
/// 4. Run the base (non-wildcard) part through `idna::domain_to_ascii`
///    which lowercases ASCII, validates the labels, and converts any
///    U-labels to A-labels (`xn--…`) per RFC 5890. The wildcard prefix
///    is re-attached after IDN conversion (idna does not accept `*`).
pub fn validate_and_normalize_dns(input: &str) -> Result<String> {
    let trimmed = input.trim_end_matches('.');
    if trimmed.is_empty() {
        bail!("empty DNS identifier");
    }

    let (had_wildcard, base) = if let Some(rest) = trimmed.strip_prefix("*.") {
        if rest.contains('*') {
            bail!("wildcard '*' must appear only as the leftmost label (got {input:?})");
        }
        if rest.is_empty() {
            bail!("wildcard requires a base domain (got {input:?})");
        }
        (true, rest)
    } else {
        if trimmed.contains('*') {
            bail!("'*' is only allowed as the leftmost label (got {input:?})");
        }
        (false, trimmed)
    };

    let normalized_base = idna::domain_to_ascii(base)
        .map_err(|e| anyhow::anyhow!("invalid DNS identifier {input:?}: {e}"))?;

    if !normalized_base
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        bail!(
            "DNS identifier {input:?} contains characters outside [A-Za-z0-9._-] after normalization"
        );
    }
    for label in normalized_base.split('.') {
        if label.is_empty() {
            bail!("DNS identifier {input:?} contains an empty label");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("DNS identifier {input:?} has a label that starts or ends with '-'");
        }
        if label.len() > 63 {
            bail!("DNS identifier {input:?} has a label longer than 63 octets");
        }
    }
    if normalized_base.len() > 253 {
        bail!("DNS identifier {input:?} exceeds 253 octets");
    }

    Ok(if had_wildcard {
        format!("*.{normalized_base}")
    } else {
        normalized_base
    })
}

/// Validate an identifier we received from the ACME server.
///
/// Defense-in-depth (SEC-04): the CA controls the strings inside
/// `Authorization.identifier`, and those values flow into `dig` argv,
/// hook env vars, and DNS record names. A buggy or hostile CA could
/// substitute a value containing shell metacharacters, leading dashes
/// (which `dig` would parse as a flag), or non-DNS-safe bytes. We
/// reject anything that doesn't survive our own normalization, and
/// reject DNS values where normalization would change the string
/// (the CA must echo back exactly what we sent — RFC 8555 §7.1.4).
pub fn validate_server_identifier(id: &Identifier) -> Result<()> {
    match id.identifier_type.as_str() {
        "dns" => {
            let normalized = validate_and_normalize_dns(&id.value).with_context(|| {
                format!("server returned invalid DNS identifier {:?}", id.value)
            })?;
            if normalized != id.value {
                bail!(
                    "server returned DNS identifier {:?} that does not match its normalized form {normalized:?}",
                    id.value
                );
            }
            Ok(())
        }
        "ip" => {
            id.value.parse::<std::net::IpAddr>().map_err(|e| {
                anyhow::anyhow!("server returned invalid IP identifier {:?}: {e}", id.value)
            })?;
            Ok(())
        }
        other => bail!("server returned unknown identifier type {other:?}"),
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
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_normalize_lowercases_and_strips_trailing_dot() {
        assert_eq!(
            validate_and_normalize_dns("EXAMPLE.com.").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn dns_normalize_idn_to_punycode() {
        assert_eq!(
            validate_and_normalize_dns("café.example").unwrap(),
            "xn--caf-dma.example"
        );
    }

    #[test]
    fn dns_normalize_accepts_simple_wildcard() {
        assert_eq!(
            validate_and_normalize_dns("*.example.com").unwrap(),
            "*.example.com"
        );
    }

    #[test]
    fn dns_normalize_rejects_double_wildcard() {
        assert!(validate_and_normalize_dns("**.example.com").is_err());
    }

    #[test]
    fn dns_normalize_rejects_non_leftmost_wildcard() {
        assert!(validate_and_normalize_dns("foo.*.example.com").is_err());
    }

    #[test]
    fn dns_normalize_rejects_bare_wildcard_dot() {
        assert!(validate_and_normalize_dns("*.").is_err());
    }

    #[test]
    fn dns_normalize_rejects_empty() {
        assert!(validate_and_normalize_dns("").is_err());
        assert!(validate_and_normalize_dns(".").is_err());
    }

    #[test]
    fn from_str_auto_routes_ip_vs_dns() {
        let ip = Identifier::from_str_auto("1.2.3.4").unwrap();
        assert!(ip.is_ip());
        let dns = Identifier::from_str_auto("Example.COM").unwrap();
        assert!(!dns.is_ip());
        assert_eq!(dns.value, "example.com");
    }

    #[test]
    fn server_identifier_accepts_normalized_dns() {
        let id = Identifier::dns("example.com");
        assert!(validate_server_identifier(&id).is_ok());
    }

    #[test]
    fn server_identifier_rejects_uppercase_dns() {
        let id = Identifier::dns("Example.COM");
        assert!(validate_server_identifier(&id).is_err());
    }

    #[test]
    fn server_identifier_rejects_dig_flag_injection() {
        let id = Identifier::dns("-X");
        assert!(validate_server_identifier(&id).is_err());
    }

    #[test]
    fn server_identifier_rejects_shell_metacharacters() {
        let id = Identifier::dns("foo;rm -rf /");
        assert!(validate_server_identifier(&id).is_err());
    }

    #[test]
    fn server_identifier_accepts_valid_ip() {
        let id = Identifier::ip("192.0.2.1");
        assert!(validate_server_identifier(&id).is_ok());
    }

    #[test]
    fn server_identifier_rejects_invalid_ip() {
        let id = Identifier::ip("not-an-ip");
        assert!(validate_server_identifier(&id).is_err());
    }

    #[test]
    fn server_identifier_rejects_unknown_type() {
        let id = Identifier {
            identifier_type: "evil".to_string(),
            value: "anything".to_string(),
        };
        assert!(validate_server_identifier(&id).is_err());
    }

    #[test]
    fn dns_normalize_rejects_label_with_leading_or_trailing_dash() {
        assert!(validate_and_normalize_dns("foo-.example").is_err());
        assert!(validate_and_normalize_dns("foo.-bar.example").is_err());
    }

    #[test]
    fn dns_normalize_rejects_empty_label() {
        assert!(validate_and_normalize_dns("foo..example").is_err());
    }

    #[test]
    fn dns_normalize_rejects_label_over_63_chars() {
        let long = "a".repeat(64);
        assert!(validate_and_normalize_dns(&format!("{long}.example")).is_err());
    }

    #[test]
    fn dns_normalize_accepts_underscore_label() {
        assert_eq!(
            validate_and_normalize_dns("_acme-challenge.example.com").unwrap(),
            "_acme-challenge.example.com"
        );
    }
}
