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

    let san_ext = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME);

    if let Some(ext) = san_ext
        && let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension()
    {
        for name in &san.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    ids.insert(dns.to_lowercase());
                }
                GeneralName::IPAddress(bytes) => {
                    // IPv4 = 4 bytes, IPv6 = 16 bytes
                    let ip: Option<std::net::IpAddr> = match bytes.len() {
                        4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                            bytes[0], bytes[1], bytes[2], bytes[3],
                        ))),
                        16 => {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(bytes);
                            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
                        }
                        _ => None,
                    };
                    if let Some(addr) = ip {
                        ids.insert(addr.to_string());
                    }
                }
                _ => {} // Ignore other GeneralName types
            }
        }
    }

    Ok(ids)
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
