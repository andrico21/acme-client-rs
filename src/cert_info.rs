use anyhow::{Context, Result};

/// Parse a PEM certificate and return the number of days until expiry.
pub(crate) fn cert_days_remaining(path: &std::path::Path) -> Result<i64> {
    let pem_data = std::fs::read_to_string(path)
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
pub(crate) fn cert_san_identifiers(
    path: &std::path::Path,
) -> Result<std::collections::BTreeSet<String>> {
    use x509_parser::prelude::*;

    let pem_data = std::fs::read_to_string(path)
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
            _ => {} // Other GeneralName types (rfc822Name, URI, ...) are not used by ACME.
        }
    }

    Ok(ids)
}

/// Decode a SubjectAlternativeName IP address octet string into an `IpAddr`.
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
    // Strip brackets for IPv6 literals like [::1]
    let candidate = if value.starts_with('[') && value.ends_with(']') {
        &value[1..value.len() - 1]
    } else {
        value
    };
    if let Ok(ip) = candidate.parse::<std::net::IpAddr>() {
        ip.to_string()
    } else {
        value.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::decode_san_ip;
    use std::net::IpAddr;

    #[test]
    fn decode_san_ip_v4() {
        let addr = decode_san_ip(&[192, 0, 2, 1]).unwrap();
        assert_eq!(addr, "192.0.2.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn decode_san_ip_v6() {
        let bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let addr = decode_san_ip(&bytes).unwrap();
        assert_eq!(addr, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn decode_san_ip_rejects_other_lengths() {
        assert!(decode_san_ip(&[]).is_none());
        assert!(decode_san_ip(&[1, 2, 3]).is_none());
        assert!(decode_san_ip(&[0; 5]).is_none());
        assert!(decode_san_ip(&[0; 15]).is_none());
        assert!(decode_san_ip(&[0; 17]).is_none());
    }
}
