//! Synchronous URL + identifier validators applied at every ingress
//! (CLI args, server-returned URLs in Directory/Order/Authorization).
//!
//! See module-level SSRF documentation in `client/mod.rs` for how this
//! layer composes with the connect-time `SsrfSafeResolver`.

use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use tracing::warn;

use super::net_policy::{NetworkPolicy, TlsPolicy, is_private_or_special_ip};

/// Maximum URL byte-length accepted anywhere we talk to an ACME server.
///
/// Priority-1 (RFC contract): RFC 9110 §4.1 RECOMMENDS that senders and
/// recipients support URIs of at least 8000 octets in protocol elements.
/// We refuse anything beyond that as both an SSRF/log-spam guard and a
/// protocol-sanity check.
pub const MAX_ACME_URL_LEN: usize = 8000;

/// Validate any URL the client is about to contact.
///
/// `tls = AllowHttpLoopback` permits plain `http://` for loopback hosts only
/// (matches historical `--insecure` semantics).
/// `net = AllowPrivate` permits private/loopback/link-local IP literals; it is
/// also implicitly granted when `tls = AllowHttpLoopback`.
///
/// Hostnames (non-literal) are NOT resolved here — that check happens
/// connect-time inside `SsrfSafeResolver`, which closes the DNS-rebinding
/// race that synchronous resolution would leave open.
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
    let is_loopback_host =
        host_ip.map_or_else(|| matches!(host, "localhost"), |ip| ip.is_loopback());
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

/// Validate an ACME directory URL against RFC 8555 §6.1 ("Use of HTTPS is
/// REQUIRED"). Thin wrapper over `validate_acme_url` that also emits the
/// loopback-testing warning when `http://` is permitted via `--insecure`.
pub fn validate_directory_url(url: &str, tls: TlsPolicy, net: NetworkPolicy) -> Result<()> {
    validate_acme_url(url, tls, net).with_context(|| format!("invalid directory URL {url:?}"))?;
    if reqwest::Url::parse(url).is_ok_and(|u| u.scheme() == "http") {
        warn!("Using plain http:// for ACME directory (loopback only) — TESTING USE ONLY");
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
        let first = bytes.first().copied().unwrap_or(b'-');
        let last = bytes.last().copied().unwrap_or(b'-');
        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_schemes() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[test]
    fn https_public_host_ok() -> anyhow::Result<()> {
        assert!(
            validate_acme_url(
                "https://acme-v02.api.letsencrypt.org/directory",
                TlsPolicy::RequireHttps,
                NetworkPolicy::PublicOnly
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn http_rejected_without_insecure() -> anyhow::Result<()> {
        assert!(
            validate_acme_url(
                "http://localhost:14000/dir",
                TlsPolicy::RequireHttps,
                NetworkPolicy::PublicOnly
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn http_loopback_ok_with_insecure() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[test]
    fn http_non_loopback_rejected_even_with_insecure() -> anyhow::Result<()> {
        assert!(
            validate_acme_url(
                "http://10.0.0.5/dir",
                TlsPolicy::AllowHttpLoopback,
                NetworkPolicy::AllowPrivate
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn private_ipv4_literal_rejected_by_default() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[test]
    fn private_ipv4_literal_allowed_with_opt_in() -> anyhow::Result<()> {
        assert!(
            validate_acme_url(
                "https://10.0.0.5/dir",
                TlsPolicy::RequireHttps,
                NetworkPolicy::AllowPrivate
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn private_ipv6_literal_rejected() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[test]
    fn ipv4_mapped_ipv6_blocked_as_ipv4() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[test]
    fn validate_acme_url_rejects_userinfo() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[test]
    fn validate_acme_url_enforces_8000_octet_cap() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[test]
    fn validate_issuer_domain_name_accepts_canonical() -> anyhow::Result<()> {
        for d in ["example.com", "letsencrypt.org", "sub.example.co.uk"] {
            assert!(validate_issuer_domain_name(d).is_ok(), "{d}");
        }
        Ok(())
    }

    #[test]
    fn validate_issuer_domain_name_lowercases() -> anyhow::Result<()> {
        let out = validate_issuer_domain_name("Example.COM")?;
        assert_eq!(out, "example.com");
        Ok(())
    }

    #[test]
    fn validate_issuer_domain_name_rejects_injection_attempts() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[test]
    fn validate_issuer_domain_name_enforces_length() -> anyhow::Result<()> {
        let too_long = format!("{}.example", "a".repeat(250));
        assert!(validate_issuer_domain_name(&too_long).is_err());
        let too_long_label = format!("{}.example", "a".repeat(64));
        assert!(validate_issuer_domain_name(&too_long_label).is_err());
        Ok(())
    }

    #[test]
    fn validate_account_uri_accepts_https_and_http() -> anyhow::Result<()> {
        assert!(validate_account_uri("https://acme.example/acct/123").is_ok());
        assert!(validate_account_uri("http://acme.example/acct/123").is_ok());
        Ok(())
    }

    #[test]
    fn validate_account_uri_rejects_injection_attempts() -> anyhow::Result<()> {
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
        Ok(())
    }

    #[test]
    fn validate_account_uri_accepts_percent_encoded_semicolon() -> anyhow::Result<()> {
        // DNS TXT parsers split on literal `;`, not on `%3B`.
        assert!(validate_account_uri("https://acme.example/acct/1%3Bx").is_ok());
        Ok(())
    }

    #[test]
    fn validate_caa_parameter_value_accepts_canonical() -> anyhow::Result<()> {
        for v in ["wildcard", "non-wildcard", "foo-bar", "v=1"] {
            assert!(validate_caa_parameter_value(v).is_ok(), "{v}");
        }
        Ok(())
    }

    #[test]
    fn validate_caa_parameter_value_rejects_injection_attempts() -> anyhow::Result<()> {
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
        Ok(())
    }
}
