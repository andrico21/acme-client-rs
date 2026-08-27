use anyhow::{Context, Result};

/// Parse a PEM certificate and return the number of days until expiry.
// cancel-safe: reads cert from disk + parses. Pure read.
pub(crate) async fn cert_days_remaining(path: &std::path::Path) -> Result<i64> {
    let pem_data = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    // Parse the first PEM block (the end-entity cert) to extract notAfter
    let parsed = pem::parse(&pem_data).context("failed to parse certificate PEM")?;
    let (_, cert) = x509_parser::parse_x509_certificate(parsed.contents())
        .map_err(|e| anyhow::anyhow!("failed to parse X.509 certificate: {e}"))?;
    let not_after = cert.validity().not_after.to_datetime();
    let now = time::OffsetDateTime::now_utc();
    let remaining = not_after - now;
    Ok(remaining.whole_days())
}

/// Parse a PEM certificate and return the set of SAN identifiers (DNS names + IPs).
///
/// DNS names are lowercased; IP addresses are canonicalized via `std::net::IpAddr`.
// cancel-safe: reads cert from disk + parses SAN list. Pure read.
pub(crate) async fn cert_san_identifiers(
    path: &std::path::Path,
) -> Result<std::collections::BTreeSet<String>> {
    use x509_parser::prelude::*;

    let pem_data = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    let parsed = ::pem::parse(&pem_data).context("failed to parse certificate PEM")?;
    let (_, cert) = X509Certificate::from_der(parsed.contents())
        .map_err(|e| anyhow::anyhow!("failed to parse X.509 certificate: {e}"))?;

    let mut ids = std::collections::BTreeSet::new();

    let Some(san_ext) = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
    else {
        return Ok(ids);
    };
    let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() else {
        return Ok(ids);
    };

    for name in &san.general_names {
        match name {
            GeneralName::DNSName(dns) => {
                ids.insert(dns.to_lowercase());
            }
            GeneralName::IPAddress(bytes) => {
                if let Some(addr) = decode_san_ip(bytes) {
                    ids.insert(addr.to_string());
                }
            }
            GeneralName::OtherName(..)
            | GeneralName::RFC822Name(_)
            | GeneralName::X400Address(_)
            | GeneralName::DirectoryName(_)
            | GeneralName::EDIPartyName(_)
            | GeneralName::URI(_)
            | GeneralName::RegisteredID(_)
            | GeneralName::Invalid(..) => {}
        }
    }

    Ok(ids)
}

/// Decode a `SubjectAlternativeName` IP address octet string into an `IpAddr`.
///
/// Per RFC 5280 §4.2.1.6, SAN iPAddress is exactly 4 octets (IPv4) or 16 octets
/// (IPv6). Anything else is malformed and ignored.
fn decode_san_ip(bytes: &[u8]) -> Option<std::net::IpAddr> {
    if let Ok(octets) = <[u8; 4]>::try_from(bytes) {
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)))
    } else if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
        Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
    } else {
        None
    }
}

/// Normalize a domain/IP string for comparison (lowercase, canonical IP form).
pub(crate) fn normalize_identifier(value: &str) -> String {
    // Total by contract, so §10's fallible `strip_circumfix` form is deliberately
    // not used: an unbalanced bracket is not an IP, falls through to the DNS
    // branch, and compares unequal — a malformed SAN must not abort a renewal.
    let candidate = value.strip_circumfix("[", "]").unwrap_or(value);
    if let Ok(ip) = candidate.parse::<std::net::IpAddr>() {
        ip.to_string()
    } else {
        value.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::decode_san_ip;
    use anyhow::Context;
    use std::net::IpAddr;

    #[test]
    fn decode_san_ip_v4() -> anyhow::Result<()> {
        let addr = decode_san_ip(&[192, 0, 2, 1]).context("decode failed")?;
        assert_eq!(addr, "192.0.2.1".parse::<IpAddr>()?);
        Ok(())
    }

    #[test]
    fn decode_san_ip_v6() -> anyhow::Result<()> {
        let bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let addr = decode_san_ip(&bytes).context("decode failed")?;
        assert_eq!(addr, "2001:db8::1".parse::<IpAddr>()?);
        Ok(())
    }

    #[test]
    fn decode_san_ip_rejects_other_lengths() -> anyhow::Result<()> {
        assert!(decode_san_ip(&[]).is_none());
        assert!(decode_san_ip(&[1, 2, 3]).is_none());
        assert!(decode_san_ip(&[0; 5]).is_none());
        assert!(decode_san_ip(&[0; 15]).is_none());
        assert!(decode_san_ip(&[0; 17]).is_none());
        Ok(())
    }

    #[test]
    fn w2_normalize_identifier_handles_brackets_without_panicking() {
        use super::normalize_identifier;

        assert_eq!(normalize_identifier("[::1]"), "::1");
        assert_eq!(normalize_identifier("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(normalize_identifier("EXAMPLE.com"), "example.com");
        assert_eq!(normalize_identifier("192.0.2.1"), "192.0.2.1");

        // Unbalanced / degenerate inputs must fall through untouched rather
        // than panic on a byte-range slice.
        for odd in ["[", "]", "[]", "[::1", "::1]", "[example.com]", ""] {
            assert_eq!(
                normalize_identifier(odd),
                odd.to_lowercase(),
                "input {odd:?}"
            );
        }
    }

    fn write_cert(
        path: &std::path::Path,
        dns: &[&str],
        ips: &[IpAddr],
        not_after: time::OffsetDateTime,
    ) -> anyhow::Result<()> {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params =
            CertificateParams::new(dns.iter().map(|d| (*d).to_owned()).collect::<Vec<_>>())?;
        for ip in ips {
            params.subject_alt_names.push(SanType::IpAddress(*ip));
        }
        params.not_after = not_after;
        std::fs::write(path, params.self_signed(&key)?.pem())?;
        Ok(())
    }

    #[tokio::test]
    async fn cert_days_remaining_counts_whole_days_until_not_after() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("cert.pem");
        // `whole_days()` floors, so a fixture aimed at exactly 30 days would
        // report 29 once setup overhead is subtracted. Add half a day of slack
        // and assert the floored value.
        let not_after =
            time::OffsetDateTime::now_utc() + time::Duration::days(30) + time::Duration::hours(12);
        write_cert(&path, &["a.example"], &[], not_after)?;

        assert_eq!(super::cert_days_remaining(&path).await?, 30);
        Ok(())
    }

    #[tokio::test]
    async fn cert_days_remaining_is_negative_for_an_expired_cert() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("expired.pem");
        let not_after =
            time::OffsetDateTime::now_utc() - time::Duration::days(5) - time::Duration::hours(12);
        write_cert(&path, &["a.example"], &[], not_after)?;

        assert_eq!(super::cert_days_remaining(&path).await?, -5);
        Ok(())
    }

    #[tokio::test]
    async fn cert_san_identifiers_returns_normalized_dns_and_ip_sans() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("san.pem");
        let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(10);
        write_cert(
            &path,
            &["b.example", "A.Example"],
            &["192.0.2.7".parse()?],
            not_after,
        )?;

        let ids = super::cert_san_identifiers(&path).await?;
        assert!(ids.contains("b.example"), "got {ids:?}");
        assert!(
            ids.contains("a.example"),
            "DNS SANs are lowercased: {ids:?}"
        );
        assert!(
            ids.contains("192.0.2.7"),
            "IP SANs are canonicalized: {ids:?}"
        );
        assert_eq!(ids.len(), 3, "exactly the three SANs: {ids:?}");
        Ok(())
    }
}
