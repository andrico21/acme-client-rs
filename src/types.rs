//! ACME protocol types per RFC 8555

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

// ── Challenge type (RFC 8555 §8) ────────────────────────────────────────────

/// ACME challenge type — strongly-typed replacement for the prior
/// string-literal comparisons.
///
/// `Unknown(String)` preserves forward-compat: if the CA advertises a challenge
/// type we don't recognize (RFC 8737 tls-alpn-01 extensions, future RFC
/// variants), we deserialize it intact and let the standard "match my preferred
/// type" filter skip it, rather than failing the whole order parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChallengeType {
    Http01,
    Dns01,
    TlsAlpn01,
    DnsPersist01,
    Unknown(String),
}

impl ChallengeType {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Http01 => "http-01",
            Self::Dns01 => "dns-01",
            Self::TlsAlpn01 => "tls-alpn-01",
            Self::DnsPersist01 => "dns-persist-01",
            Self::Unknown(s) => s.as_str(),
        }
    }

    pub(crate) fn parse_strict(s: &str) -> Result<Self> {
        match s {
            "http-01" => Ok(Self::Http01),
            "dns-01" => Ok(Self::Dns01),
            "tls-alpn-01" => Ok(Self::TlsAlpn01),
            "dns-persist-01" => Ok(Self::DnsPersist01),
            other => bail!(
                "unknown challenge type {other:?}; expected one of: \
                 http-01, dns-01, tls-alpn-01, dns-persist-01"
            ),
        }
    }
}

impl From<String> for ChallengeType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "http-01" => Self::Http01,
            "dns-01" => Self::Dns01,
            "tls-alpn-01" => Self::TlsAlpn01,
            "dns-persist-01" => Self::DnsPersist01,
            _ => Self::Unknown(s),
        }
    }
}

impl std::fmt::Display for ChallengeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ChallengeType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ChallengeType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(Self::from(String::deserialize(d)?))
    }
}

// ── Directory (RFC 8555 §7.1.1) ─────────────────────────────────────────────

/// ACME Directory resource - the entry-point for all ACME operations.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub(crate) struct Directory {
    pub new_nonce: url::Url,
    pub new_account: url::Url,
    pub new_order: url::Url,
    pub new_authz: Option<url::Url>,
    pub revoke_cert: url::Url,
    pub key_change: url::Url,
    pub renewal_info: Option<url::Url>,
    pub meta: Option<DirectoryMeta>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub(crate) struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<bool>,
    /// Certificate profiles (draft-ietf-acme-profiles-01 §3).
    /// Maps profile name → human-readable description.
    pub profiles: Option<HashMap<String, String>>,
}

// ── Identifier (RFC 8555 §9.7.7, RFC 8738 for IP) ────────────────────────────

/// Validated DNS name suitable for use as an ACME identifier.
///
/// The inner string is **always** the output of [`validate_and_normalize_dns`]
/// (lowercased ASCII, A-label IDN, RFC-conformant labels, optional leftmost
/// `*` wildcard). The field is private — construction is only possible via
/// [`DnsName::parse`] or deserialization (which routes through the same
/// validator via `try_from = "String"`). This makes the
/// "DNS name was checked" invariant a static property of the type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DnsName(String);

impl DnsName {
    /// Validate and normalize `input` from a user-controlled source (CLI
    /// `--domain`, config file), returning a `DnsName` whose inner string
    /// is the canonical form. Lowercases, IDN A-label conversion, etc.
    pub fn parse(input: &str) -> Result<Self> {
        Ok(Self(validate_and_normalize_dns(input)?))
    }

    /// Validate `input` from an untrusted-but-authoritative source (CA
    /// server response). Unlike [`DnsName::parse`], this REJECTS any input
    /// that is not already in canonical form -- RFC 8555 §7.1.4 requires
    /// the CA to echo identifiers verbatim, so a server returning
    /// `Example.COM` is non-conformant (and is the canonical SEC-04
    /// argv-injection vector if accepted and silently normalized).
    pub fn parse_canonical(input: &str) -> Result<Self> {
        let normalized = validate_and_normalize_dns(input)?;
        if normalized != input {
            bail!("DNS identifier {input:?} is not in canonical form (expected {normalized:?})");
        }
        Ok(Self(normalized))
    }

    /// Borrow the canonical DNS string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate an ACME challenge **record name** (e.g.
    /// `_acme-challenge.example.com`). Unlike [`DnsName::parse`], which is
    /// LDH-only for certificate identifiers, this permits the leading `_`
    /// service label. NOT for certificate identifiers.
    pub fn parse_record_name(input: &str) -> Result<Self> {
        Ok(Self(validate_and_normalize_record_name(input)?))
    }
}

impl std::fmt::Display for DnsName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for DnsName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<DnsName> for String {
    fn from(n: DnsName) -> Self {
        n.0
    }
}

impl TryFrom<String> for DnsName {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self> {
        Self::parse_canonical(&s)
    }
}

/// ACME identifier (RFC 8555 §9.7.7, RFC 8738 §3 for IP).
///
/// Modeled as an enum so DNS-only vs IP-only branches are type-checked
/// rather than discovered via a string comparison on a `type` field.
/// `Dns` carries a validated [`DnsName`]; `Ip` carries a parsed
/// [`std::net::IpAddr`] whose `Display` form is RFC 5952-canonical.
///
/// Wire format (unchanged): `{"type":"dns"|"ip","value":"..."}`.
/// Deserialization routes the `value` through each variant's validating
/// constructor — a server returning a malformed IP, mixed-case DNS, or
/// shell-metacharacter-injected name is rejected at the parse boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub(crate) enum Identifier {
    Dns(DnsName),
    Ip(std::net::IpAddr),
}

impl Identifier {
    /// Construct a DNS identifier from raw input, validating + normalizing.
    pub(crate) fn dns(value: &str) -> Result<Self> {
        Ok(Self::Dns(DnsName::parse(value)?))
    }

    /// Construct an IP identifier per RFC 8738. IPv6 is normalized to
    /// RFC 5952 form by the `IpAddr` round-trip.
    pub(crate) fn ip(value: &str) -> Result<Self> {
        let addr: std::net::IpAddr = value
            .parse()
            .with_context(|| format!("not a valid IP address: {value}"))?;
        Ok(Self::Ip(addr))
    }

    /// Auto-detect whether `value` is an IP literal or a DNS name and
    /// dispatch to the appropriate validating constructor.
    ///
    /// - Bare IPv4 (`1.2.3.4`) → [`Identifier::Ip`]
    /// - Bare IPv6 (`::1`, `2001:db8::1`) → [`Identifier::Ip`]
    /// - Bracketed IPv6 (`[::1]`) → [`Identifier::Ip`] (brackets stripped)
    /// - Anything else → [`Identifier::Dns`] via [`DnsName::parse`]
    pub(crate) fn from_str_auto(value: &str) -> Result<Self> {
        // Strip brackets for IPv6 literals like [::1].
        let candidate = value
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(value);
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            Self::ip(candidate)
        } else {
            Self::dns(value)
        }
    }

    /// `true` if this identifier is an IP literal.
    #[allow(dead_code)]
    pub(crate) fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(_))
    }

    /// Wire-format `type` tag (`"dns"` or `"ip"`), for JSON output, logs,
    /// and human-readable formatting.
    pub(crate) fn type_str(&self) -> &'static str {
        match self {
            Self::Dns(_) => "dns",
            Self::Ip(_) => "ip",
        }
    }

    /// Canonical wire-format `value` string. Allocates only for IP.
    /// Use [`Identifier::as_dns`] + [`DnsName::as_str`] for zero-alloc
    /// DNS-only access.
    pub(crate) fn value_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::Dns(n) => std::borrow::Cow::Borrowed(n.as_str()),
            Self::Ip(a) => std::borrow::Cow::Owned(a.to_string()),
        }
    }

    /// Borrow the inner [`DnsName`] when this identifier is a DNS name,
    /// returning `None` for IP identifiers. Used by DNS-only call paths
    /// that take `&DnsName` directly instead of going through
    /// [`Identifier::value_str`].
    pub(crate) fn as_dns(&self) -> Option<&DnsName> {
        match self {
            Self::Dns(n) => Some(n),
            Self::Ip(_) => None,
        }
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dns(n) => f.write_str(n.as_str()),
            Self::Ip(a) => write!(f, "{a}"),
        }
    }
}

/// Whether `_` is permitted in a normalized DNS name.
///
/// Certificate `dNSName` identifiers follow RFC 5280 §7 / RFC 1034
/// preferred name syntax (LDH only — letters, digits, hyphen); `_` is
/// NOT a legal hostname character and MUST be rejected. Challenge record
/// names (`_acme-challenge`, `_validation-persist`) are not certificate
/// identifiers and legitimately carry an underscore service label, so
/// they use a distinct entry point that permits it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UnderscorePolicy {
    Reject,
    AllowServiceLabel,
}

/// Validate and normalize a certificate DNS identifier (LDH-only) per
/// RFC 8555 §7.1.3 / §9.7.5 and RFC 5280 §7 (RFC 1034 preferred name
/// syntax). Rejects `_`; use [`validate_and_normalize_record_name`] for
/// ACME challenge record names that need a leading `_` service label.
pub(crate) fn validate_and_normalize_dns(input: &str) -> Result<String> {
    validate_and_normalize_dns_with(input, UnderscorePolicy::Reject)
}

/// Validate and normalize an ACME challenge **record name**, permitting
/// the leading `_` service label (`_acme-challenge.<host>`,
/// `_validation-persist.<host>`). Same label/length/IDN rules as
/// [`validate_and_normalize_dns`]; only the underscore is additionally
/// allowed. NOT for certificate identifiers.
pub(crate) fn validate_and_normalize_record_name(input: &str) -> Result<String> {
    validate_and_normalize_dns_with(input, UnderscorePolicy::AllowServiceLabel)
}

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
fn validate_and_normalize_dns_with(input: &str, underscore: UnderscorePolicy) -> Result<String> {
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

    if !normalized_base.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '.'
            || c == '-'
            || (c == '_' && underscore == UnderscorePolicy::AllowServiceLabel)
    }) {
        bail!(
            "DNS identifier {input:?} contains characters outside [A-Za-z0-9.-] after normalization"
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
/// With the enum-based [`Identifier`], all SEC-04 defense is enforced at
/// the serde boundary: IP-parse failures, unknown `type` values, and
/// non-canonical DNS strings (RFC 8555 §7.1.4 echo-back violations) are
/// all caught during deserialization by [`DnsName::parse_canonical`] and
/// `IpAddr`'s own `FromStr`. This function remains as a no-op marker
/// for callers that want to assert "yes, I validated this", and as the
/// extension point for any future post-parse identifier checks.
pub(crate) fn validate_server_identifier(_id: &Identifier) -> Result<()> {
    Ok(())
}

// ── Account (RFC 8555 §7.1.2, §7.3) ─────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NewAccountRequest {
    pub terms_of_service_agreed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub(crate) struct Account {
    pub status: AccountStatus,
    pub contact: Option<Vec<String>>,
    pub terms_of_service_agreed: Option<bool>,
    pub orders: Option<url::Url>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AccountStatus {
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
pub(crate) struct DeactivateAccountRequest {
    pub status: String,
}

// ── Order (RFC 8555 §7.1.3, §7.4) ───────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NewOrderRequest {
    pub identifiers: Vec<Identifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// ARI replacement indicator (RFC 9773 §5) - the certID of the cert being replaced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
    /// Certificate profile (draft-ietf-acme-profiles-01 §4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub(crate) struct Order {
    pub status: OrderStatus,
    pub expires: Option<String>,
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub authorizations: Vec<url::Url>,
    pub finalize: url::Url,
    pub certificate: Option<url::Url>,
    /// Certificate profile (draft-ietf-acme-profiles-01 §4).
    pub profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OrderStatus {
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
pub(crate) struct Authorization {
    pub identifier: Identifier,
    pub status: AuthorizationStatus,
    pub expires: Option<String>,
    pub challenges: Vec<Challenge>,
    pub wildcard: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AuthorizationStatus {
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

/// Validated ACME challenge token (RFC 8555 §8.1).
///
/// Tokens are emitted by the CA and echoed back to it inside path components
/// (HTTP-01 well-known URL), DNS labels, and filesystem paths. A malformed
/// or malicious token (path-traversal sequences, NULs, whitespace) would
/// escape every one of those contexts. This newtype enforces the RFC
/// `[A-Za-z0-9_-]{1,128}` base64url alphabet at every construction site:
/// invalid tokens cannot be represented, so callers cannot forget to
/// validate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ChallengeToken(String);

/// Maximum accepted token length. Real ACME tokens are ~43 base64url chars
/// (32 random bytes); RFC 8555 does not fix an upper bound, so we apply a
/// defensive cap to prevent unbounded log/path growth.
const MAX_CHALLENGE_TOKEN_LEN: usize = 128;

impl ChallengeToken {
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("ACME challenge token is empty");
        }
        if s.len() > MAX_CHALLENGE_TOKEN_LEN {
            bail!(
                "ACME challenge token is {} bytes; refusing (max {})",
                s.len(),
                MAX_CHALLENGE_TOKEN_LEN
            );
        }
        for b in s.as_bytes() {
            let ok = matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_');
            if !ok {
                bail!(
                    "ACME challenge token contains invalid character {:?}; \
                     expected base64url alphabet [A-Za-z0-9_-]",
                    *b as char
                );
            }
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ChallengeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ChallengeToken {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self> {
        Self::parse(&s)
    }
}

impl From<ChallengeToken> for String {
    fn from(t: ChallengeToken) -> Self {
        t.0
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, clippy::struct_field_names)]
pub(crate) struct Challenge {
    #[serde(rename = "type")]
    pub challenge_type: ChallengeType,
    pub url: url::Url,
    pub status: ChallengeStatus,
    pub validated: Option<String>,
    pub token: Option<ChallengeToken>,
    pub error: Option<AcmeError>,
    /// For dns-persist-01: issuer domain names provided by the CA.
    #[serde(default)]
    pub issuer_domain_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ChallengeStatus {
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
pub(crate) struct NewAuthorizationRequest {
    pub identifier: Identifier,
}

// ── Finalize (RFC 8555 §7.4) ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(crate) struct FinalizeRequest {
    pub csr: String,
}

// ── Error (RFC 8555 §6.7, RFC 7807) ─────────────────────────────────────────

/// Canonical RFC 8555 §6.7 ACME error type URN.
///
/// Wire format is the full URN `urn:ietf:params:acme:error:<kind>`.
/// The 24 standard kinds map to named variants; CA-specific or
/// post-RFC-8555 extensions deserialize as [`AcmeErrorType::Unknown`]
/// carrying the verbatim wire string (forward-compat per RFC 8555
/// §6.7's "Other error types MAY also be used" clause).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum AcmeErrorType {
    AccountDoesNotExist,
    AlreadyRevoked,
    BadCsr,
    BadNonce,
    BadPublicKey,
    BadRevocationReason,
    BadSignatureAlgorithm,
    Caa,
    Compound,
    Connection,
    Dns,
    ExternalAccountRequired,
    IncorrectResponse,
    InvalidContact,
    Malformed,
    OrderNotReady,
    RateLimited,
    RejectedIdentifier,
    ServerInternal,
    Tls,
    Unauthorized,
    UnsupportedContact,
    UnsupportedIdentifier,
    UserActionRequired,
    /// Catch-all for CA-specific or post-RFC-8555 error URIs (e.g.
    /// RFC 8739 auto-renewal errors, RFC 9799 onionCAARequired). The
    /// inner string is the verbatim wire URN; round-trips losslessly.
    Unknown(String),
}

const ACME_ERROR_URN_PREFIX: &str = "urn:ietf:params:acme:error:";

impl AcmeErrorType {
    /// `true` if this is the RFC 8555 §6.5 `badNonce` error, which
    /// callers must treat specially (retry the request with a fresh
    /// nonce instead of bubbling up).
    pub fn is_bad_nonce(&self) -> bool {
        matches!(self, Self::BadNonce)
    }
}

impl std::fmt::Display for AcmeErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::AccountDoesNotExist => "accountDoesNotExist",
            Self::AlreadyRevoked => "alreadyRevoked",
            Self::BadCsr => "badCSR",
            Self::BadNonce => "badNonce",
            Self::BadPublicKey => "badPublicKey",
            Self::BadRevocationReason => "badRevocationReason",
            Self::BadSignatureAlgorithm => "badSignatureAlgorithm",
            Self::Caa => "caa",
            Self::Compound => "compound",
            Self::Connection => "connection",
            Self::Dns => "dns",
            Self::ExternalAccountRequired => "externalAccountRequired",
            Self::IncorrectResponse => "incorrectResponse",
            Self::InvalidContact => "invalidContact",
            Self::Malformed => "malformed",
            Self::OrderNotReady => "orderNotReady",
            Self::RateLimited => "rateLimited",
            Self::RejectedIdentifier => "rejectedIdentifier",
            Self::ServerInternal => "serverInternal",
            Self::Tls => "tls",
            Self::Unauthorized => "unauthorized",
            Self::UnsupportedContact => "unsupportedContact",
            Self::UnsupportedIdentifier => "unsupportedIdentifier",
            Self::UserActionRequired => "userActionRequired",
            Self::Unknown(s) => return f.write_str(s),
        };
        write!(f, "{ACME_ERROR_URN_PREFIX}{kind}")
    }
}

impl From<AcmeErrorType> for String {
    fn from(e: AcmeErrorType) -> Self {
        e.to_string()
    }
}

impl From<String> for AcmeErrorType {
    fn from(s: String) -> Self {
        match s.strip_prefix(ACME_ERROR_URN_PREFIX) {
            Some("accountDoesNotExist") => Self::AccountDoesNotExist,
            Some("alreadyRevoked") => Self::AlreadyRevoked,
            Some("badCSR") => Self::BadCsr,
            Some("badNonce") => Self::BadNonce,
            Some("badPublicKey") => Self::BadPublicKey,
            Some("badRevocationReason") => Self::BadRevocationReason,
            Some("badSignatureAlgorithm") => Self::BadSignatureAlgorithm,
            Some("caa") => Self::Caa,
            Some("compound") => Self::Compound,
            Some("connection") => Self::Connection,
            Some("dns") => Self::Dns,
            Some("externalAccountRequired") => Self::ExternalAccountRequired,
            Some("incorrectResponse") => Self::IncorrectResponse,
            Some("invalidContact") => Self::InvalidContact,
            Some("malformed") => Self::Malformed,
            Some("orderNotReady") => Self::OrderNotReady,
            Some("rateLimited") => Self::RateLimited,
            Some("rejectedIdentifier") => Self::RejectedIdentifier,
            Some("serverInternal") => Self::ServerInternal,
            Some("tls") => Self::Tls,
            Some("unauthorized") => Self::Unauthorized,
            Some("unsupportedContact") => Self::UnsupportedContact,
            Some("unsupportedIdentifier") => Self::UnsupportedIdentifier,
            Some("userActionRequired") => Self::UserActionRequired,
            _ => Self::Unknown(s),
        }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct AcmeError {
    #[serde(rename = "type")]
    pub error_type: Option<AcmeErrorType>,
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
        if let Some(status) = self.status {
            write!(f, " [status={status}]")?;
        }
        if let Some(ref subs) = self.subproblems
            && !subs.is_empty()
        {
            write!(f, "; subproblems:")?;
            for sp in subs {
                write!(f, " [{}", sp.error_type)?;
                if let Some(ref id) = sp.identifier {
                    write!(f, " {}={}", id.type_str(), id)?;
                }
                if let Some(ref d) = sp.detail {
                    write!(f, ": {d}")?;
                }
                write!(f, "]")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Subproblem {
    #[serde(rename = "type")]
    pub error_type: AcmeErrorType,
    pub detail: Option<String>,
    pub identifier: Option<Identifier>,
}

// ── Certificate revocation (RFC 8555 §7.6) ──────────────────────────────────

// ── ACME Renewal Information (RFC 9773) ──────────────────────────────────────

/// ARI renewal info response (RFC 9773 §4.2).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RenewalInfo {
    pub suggested_window: RenewalInfoWindow,
    #[serde(
        default,
        rename = "explanationURL",
        skip_serializing_if = "Option::is_none"
    )]
    pub explanation_url: Option<String>,
}

impl RenewalInfo {
    /// Validate the suggested window per RFC 9773 §4.2: both endpoints MUST
    /// be RFC 3339 timestamps and `end` MUST be strictly after `start`.
    pub(crate) fn validate_window(&self) -> anyhow::Result<()> {
        use anyhow::Context as _;
        let start = time::OffsetDateTime::parse(
            &self.suggested_window.start,
            &time::format_description::well_known::Rfc3339,
        )
        .with_context(|| {
            format!(
                "ARI suggestedWindow.start is not a valid RFC 3339 timestamp: {}",
                self.suggested_window.start
            )
        })?;
        let end = time::OffsetDateTime::parse(
            &self.suggested_window.end,
            &time::format_description::well_known::Rfc3339,
        )
        .with_context(|| {
            format!(
                "ARI suggestedWindow.end is not a valid RFC 3339 timestamp: {}",
                self.suggested_window.end
            )
        })?;
        if end <= start {
            anyhow::bail!(
                "ARI suggestedWindow violates RFC 9773 §4.2: end ({}) must be strictly after start ({})",
                self.suggested_window.end,
                self.suggested_window.start,
            );
        }
        Ok(())
    }
}

/// Time window within which the client should attempt renewal.
#[derive(Debug, Deserialize)]
pub(crate) struct RenewalInfoWindow {
    pub start: String,
    pub end: String,
}

// ── Certificate revocation (RFC 8555 §7.6) ──────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevokeCertRequest {
    pub certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_type_roundtrips_through_string_for_known_variants() -> anyhow::Result<()> {
        for (variant, wire) in [
            (ChallengeType::Http01, "http-01"),
            (ChallengeType::Dns01, "dns-01"),
            (ChallengeType::TlsAlpn01, "tls-alpn-01"),
            (ChallengeType::DnsPersist01, "dns-persist-01"),
        ] {
            assert_eq!(variant.as_str(), wire);
            assert_eq!(ChallengeType::from(wire.to_string()), variant);
            assert_eq!(ChallengeType::parse_strict(wire)?, variant);
        }
        Ok(())
    }

    #[test]
    fn challenge_type_preserves_unknown_via_from_string() -> anyhow::Result<()> {
        // Wire-side MUST tolerate unknown variants (forward-compat with future
        // RFCs); strict parser MUST reject them.
        let unknown = ChallengeType::from("custom-future-01".to_string());
        assert_eq!(
            unknown,
            ChallengeType::Unknown("custom-future-01".to_string())
        );
        assert_eq!(unknown.as_str(), "custom-future-01");
        assert!(ChallengeType::parse_strict("custom-future-01").is_err());
        Ok(())
    }

    #[test]
    fn challenge_type_serde_roundtrip_through_json() -> anyhow::Result<()> {
        let j = serde_json::to_string(&ChallengeType::DnsPersist01)?;
        assert_eq!(j, "\"dns-persist-01\"");
        let parsed: ChallengeType = serde_json::from_str("\"dns-01\"")?;
        assert_eq!(parsed, ChallengeType::Dns01);
        let unknown: ChallengeType = serde_json::from_str("\"future-02\"")?;
        assert_eq!(unknown, ChallengeType::Unknown("future-02".to_string()));
        Ok(())
    }

    #[test]
    fn dns_normalize_lowercases_and_strips_trailing_dot() -> anyhow::Result<()> {
        assert_eq!(validate_and_normalize_dns("EXAMPLE.com.")?, "example.com");
        Ok(())
    }

    #[test]
    fn dns_normalize_idn_to_punycode() -> anyhow::Result<()> {
        assert_eq!(
            validate_and_normalize_dns("café.example")?,
            "xn--caf-dma.example"
        );
        Ok(())
    }

    #[test]
    fn dns_normalize_accepts_simple_wildcard() -> anyhow::Result<()> {
        assert_eq!(
            validate_and_normalize_dns("*.example.com")?,
            "*.example.com"
        );
        Ok(())
    }

    #[test]
    fn dns_normalize_rejects_double_wildcard() -> anyhow::Result<()> {
        assert!(validate_and_normalize_dns("**.example.com").is_err());
        Ok(())
    }

    #[test]
    fn dns_normalize_rejects_non_leftmost_wildcard() -> anyhow::Result<()> {
        assert!(validate_and_normalize_dns("foo.*.example.com").is_err());
        Ok(())
    }

    #[test]
    fn dns_normalize_rejects_bare_wildcard_dot() -> anyhow::Result<()> {
        assert!(validate_and_normalize_dns("*.").is_err());
        Ok(())
    }

    #[test]
    fn dns_normalize_rejects_empty() -> anyhow::Result<()> {
        assert!(validate_and_normalize_dns("").is_err());
        assert!(validate_and_normalize_dns(".").is_err());
        Ok(())
    }

    #[test]
    fn from_str_auto_routes_ip_vs_dns() -> anyhow::Result<()> {
        let ip = Identifier::from_str_auto("1.2.3.4")?;
        assert!(ip.is_ip());
        let dns = Identifier::from_str_auto("Example.COM")?;
        assert!(!dns.is_ip());
        assert_eq!(dns.value_str(), "example.com");
        Ok(())
    }

    #[test]
    fn server_identifier_accepts_normalized_dns() -> anyhow::Result<()> {
        let id = Identifier::dns("example.com")?;
        assert!(validate_server_identifier(&id).is_ok());
        Ok(())
    }

    #[test]
    fn dns_constructor_normalizes_uppercase() -> anyhow::Result<()> {
        let id = Identifier::dns("Example.COM")?;
        assert_eq!(id.value_str(), "example.com");
        Ok(())
    }

    #[test]
    fn dns_constructor_rejects_dig_flag_injection() -> anyhow::Result<()> {
        assert!(Identifier::dns("-X").is_err());
        Ok(())
    }

    #[test]
    fn dns_constructor_rejects_shell_metacharacters() -> anyhow::Result<()> {
        assert!(Identifier::dns("foo;rm -rf /").is_err());
        Ok(())
    }

    #[test]
    fn server_identifier_accepts_valid_ip() -> anyhow::Result<()> {
        let id = Identifier::ip("192.0.2.1")?;
        assert!(validate_server_identifier(&id).is_ok());
        Ok(())
    }

    #[test]
    fn ip_constructor_rejects_invalid_input() -> anyhow::Result<()> {
        assert!(Identifier::ip("not-an-ip").is_err());
        Ok(())
    }

    #[test]
    fn deserialize_rejects_invalid_ip() -> anyhow::Result<()> {
        let bad = r#"{"type":"ip","value":"not-an-ip"}"#;
        assert!(serde_json::from_str::<Identifier>(bad).is_err());
        Ok(())
    }

    #[test]
    fn deserialize_rejects_unknown_type() -> anyhow::Result<()> {
        let bad = r#"{"type":"evil","value":"anything"}"#;
        assert!(serde_json::from_str::<Identifier>(bad).is_err());
        Ok(())
    }

    #[test]
    fn deserialize_rejects_unnormalized_dns() -> anyhow::Result<()> {
        let bad = r#"{"type":"dns","value":"Example.COM"}"#;
        assert!(serde_json::from_str::<Identifier>(bad).is_err());
        Ok(())
    }

    #[test]
    fn deserialize_accepts_canonical_dns() -> anyhow::Result<()> {
        let ok = r#"{"type":"dns","value":"example.com"}"#;
        let id: Identifier = serde_json::from_str(ok)?;
        assert!(matches!(id, Identifier::Dns(ref n) if n.as_str() == "example.com"));
        Ok(())
    }

    #[test]
    fn deserialize_accepts_ipv4() -> anyhow::Result<()> {
        let ok = r#"{"type":"ip","value":"192.0.2.1"}"#;
        let id: Identifier = serde_json::from_str(ok)?;
        assert!(matches!(id, Identifier::Ip(_)));
        assert_eq!(id.value_str(), "192.0.2.1");
        Ok(())
    }

    #[test]
    fn serialize_round_trip_preserves_wire_format() -> anyhow::Result<()> {
        let id = Identifier::dns("example.com")?;
        let json = serde_json::to_string(&id)?;
        assert_eq!(json, r#"{"type":"dns","value":"example.com"}"#);
        let ip = Identifier::ip("192.0.2.1")?;
        let json = serde_json::to_string(&ip)?;
        assert_eq!(json, r#"{"type":"ip","value":"192.0.2.1"}"#);
        Ok(())
    }

    #[test]
    fn dns_normalize_rejects_label_with_leading_or_trailing_dash() -> anyhow::Result<()> {
        assert!(validate_and_normalize_dns("foo-.example").is_err());
        assert!(validate_and_normalize_dns("foo.-bar.example").is_err());
        Ok(())
    }

    #[test]
    fn dns_normalize_rejects_empty_label() -> anyhow::Result<()> {
        assert!(validate_and_normalize_dns("foo..example").is_err());
        Ok(())
    }

    #[test]
    fn dns_normalize_rejects_label_over_63_chars() -> anyhow::Result<()> {
        let long = "a".repeat(64);
        assert!(validate_and_normalize_dns(&format!("{long}.example")).is_err());
        Ok(())
    }

    #[test]
    fn m3_cert_identifier_ldh_only() -> anyhow::Result<()> {
        assert!(validate_and_normalize_dns("_acme-challenge.example.com").is_err());
        assert!(validate_and_normalize_dns("_bad.example.com").is_err());
        assert!(validate_and_normalize_dns("a_b.example.com").is_err());
        assert!(DnsName::parse("_acme-challenge.example.com").is_err());
        assert!(DnsName::parse_canonical("_acme-challenge.example.com").is_err());
        assert_eq!(validate_and_normalize_dns("example.com")?, "example.com");
        Ok(())
    }

    #[test]
    fn m3_record_name_allows_acme_underscore() -> anyhow::Result<()> {
        assert_eq!(
            validate_and_normalize_record_name("_acme-challenge.example.com")?,
            "_acme-challenge.example.com"
        );
        assert_eq!(
            validate_and_normalize_record_name("_validation-persist.example.com")?,
            "_validation-persist.example.com"
        );
        assert_eq!(
            DnsName::parse_record_name("_acme-challenge.example.com")?.as_str(),
            "_acme-challenge.example.com"
        );
        Ok(())
    }

    #[test]
    fn acme_error_display_includes_subproblems_and_status() -> anyhow::Result<()> {
        let err = AcmeError {
            error_type: Some(AcmeErrorType::RejectedIdentifier),
            detail: Some("Some identifiers were rejected".into()),
            status: Some(400),
            subproblems: Some(vec![
                Subproblem {
                    error_type: AcmeErrorType::Malformed,
                    detail: Some("DNS name has wildcard".into()),
                    identifier: Some(Identifier::dns("*.evil.example")?),
                },
                Subproblem {
                    error_type: AcmeErrorType::InvalidContact,
                    detail: None,
                    identifier: None,
                },
            ]),
        };
        let s = format!("{err}");
        assert!(s.contains("Some identifiers were rejected"));
        assert!(s.contains("rejectedIdentifier"));
        assert!(s.contains("status=400"));
        assert!(s.contains("dns=*.evil.example"));
        assert!(s.contains("DNS name has wildcard"));
        assert!(s.contains("invalidContact"));
        Ok(())
    }

    #[test]
    fn acme_error_display_empty_subproblems_omitted() -> anyhow::Result<()> {
        let err = AcmeError {
            error_type: Some(AcmeErrorType::BadNonce),
            detail: Some("Bad nonce".into()),
            status: None,
            subproblems: Some(vec![]),
        };
        let s = format!("{err}");
        assert!(!s.contains("subproblems"));
        Ok(())
    }

    #[test]
    fn acme_error_type_serde_roundtrip_standard() -> anyhow::Result<()> {
        let json = "\"urn:ietf:params:acme:error:badNonce\"";
        let parsed: AcmeErrorType = serde_json::from_str(json)?;
        assert_eq!(parsed, AcmeErrorType::BadNonce);
        assert!(parsed.is_bad_nonce());
        assert_eq!(serde_json::to_string(&parsed)?, json);
        Ok(())
    }

    #[test]
    fn acme_error_type_serde_unknown_roundtrip_lossless() -> anyhow::Result<()> {
        let json = "\"urn:ietf:params:acme:error:onionCAARequired\"";
        let parsed: AcmeErrorType = serde_json::from_str(json)?;
        assert_eq!(
            parsed,
            AcmeErrorType::Unknown("urn:ietf:params:acme:error:onionCAARequired".into())
        );
        assert!(!parsed.is_bad_nonce());
        assert_eq!(serde_json::to_string(&parsed)?, json);
        Ok(())
    }

    #[test]
    fn acme_error_type_serde_non_acme_urn_preserved() -> anyhow::Result<()> {
        let json = "\"urn:example:custom-error\"";
        let parsed: AcmeErrorType = serde_json::from_str(json)?;
        assert_eq!(
            parsed,
            AcmeErrorType::Unknown("urn:example:custom-error".into())
        );
        assert_eq!(serde_json::to_string(&parsed)?, json);
        Ok(())
    }

    #[test]
    fn challenge_token_parse_accepts_base64url() -> anyhow::Result<()> {
        let t = ChallengeToken::parse("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0")?;
        assert_eq!(t.as_str(), "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0");
        Ok(())
    }

    #[test]
    fn challenge_token_parse_rejects_empty() -> anyhow::Result<()> {
        assert!(ChallengeToken::parse("").is_err());
        Ok(())
    }

    #[test]
    fn challenge_token_parse_rejects_path_traversal() -> anyhow::Result<()> {
        assert!(ChallengeToken::parse("../../etc/passwd").is_err());
        assert!(ChallengeToken::parse("a/b").is_err());
        assert!(ChallengeToken::parse("a\\b").is_err());
        Ok(())
    }

    #[test]
    fn challenge_token_parse_rejects_oversize() -> anyhow::Result<()> {
        let big = "a".repeat(129);
        assert!(ChallengeToken::parse(&big).is_err());
        let max = "a".repeat(128);
        assert!(ChallengeToken::parse(&max).is_ok());
        Ok(())
    }

    #[test]
    fn challenge_token_parse_rejects_non_base64url_chars() -> anyhow::Result<()> {
        for bad in ["a b", "a+b", "a=b", "a.b", "a\nb", "a\0b"] {
            assert!(
                ChallengeToken::parse(bad).is_err(),
                "token {bad:?} should be rejected"
            );
        }
        Ok(())
    }

    #[test]
    fn challenge_token_serde_wire_validation() -> anyhow::Result<()> {
        let parsed: ChallengeToken = serde_json::from_str("\"abc-DEF_123\"")?;
        assert_eq!(parsed.as_str(), "abc-DEF_123");
        assert!(serde_json::from_str::<ChallengeToken>("\"bad/token\"").is_err());
        assert!(serde_json::from_str::<ChallengeToken>("\"\"").is_err());
        Ok(())
    }
}
