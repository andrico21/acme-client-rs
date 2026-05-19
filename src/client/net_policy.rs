//! Network reachability policy + IP classification used by the SSRF defenses.
//!
//! Two policy enums (`TlsPolicy`, `NetworkPolicy`) and the IP classifier
//! (`is_private_or_special_ip`) live here so URL validation and the
//! connect-time DNS resolver can share them without circular imports.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Classify an IP as "must not be reached by an ACME client" unless the
/// operator explicitly opted in. Covers loopback, RFC1918, link-local
/// (incl. cloud metadata at 169.254.169.254), CGNAT, multicast, broadcast,
/// reserved/documentation ranges, IPv6 loopback/ULA/link-local/multicast,
/// and IPv4-mapped IPv6 (a common SSRF bypass).
pub(crate) fn is_private_or_special_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_or_special_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_private_or_special_ipv4(mapped);
            }
            is_private_or_special_ipv6(v6)
        }
    }
}

fn is_private_or_special_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
    {
        return true;
    }
    let o = ip.octets();
    // CGNAT (RFC 6598): 100.64.0.0/10
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return true;
    }
    // IETF protocol assignments (RFC 6890): 192.0.0.0/24
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return true;
    }
    // Benchmarking (RFC 2544): 198.18.0.0/15
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return true;
    }
    // Reserved for future use (RFC 1112): 240.0.0.0/4
    if o[0] >= 240 {
        return true;
    }
    false
}

fn is_private_or_special_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let s = ip.segments();
    // Unique local addresses (RFC 4193): fc00::/7
    if (s[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-local: fe80::/10
    if (s[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // Documentation (RFC 3849): 2001:db8::/32
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return true;
    }
    false
}

/// TLS policy for ACME URL validation. Distinct enum (not `bool`) so it cannot
/// be positionally swapped with `NetworkPolicy` at call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsPolicy {
    /// `https://` only (RFC 8555 §6.1 default).
    RequireHttps,
    /// Permit `http://` for loopback hosts only — `--insecure`.
    AllowHttpLoopback,
}

/// Network reachability policy for ACME URL validation. Distinct enum so it
/// cannot be positionally swapped with `TlsPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Reject private / loopback / link-local / special-purpose IP literals.
    PublicOnly,
    /// Permit private/special IPs — `--allow-private-network` (also implied by
    /// `TlsPolicy::AllowHttpLoopback`).
    AllowPrivate,
}

impl TlsPolicy {
    pub(crate) fn from_insecure(insecure: bool) -> Self {
        if insecure {
            Self::AllowHttpLoopback
        } else {
            Self::RequireHttps
        }
    }

    pub(crate) fn accepts_invalid_certs(self) -> bool {
        matches!(self, Self::AllowHttpLoopback)
    }
}

impl NetworkPolicy {
    pub(crate) fn from_allow_private(allow_private: bool) -> Self {
        if allow_private {
            Self::AllowPrivate
        } else {
            Self::PublicOnly
        }
    }

    pub(crate) fn allows_private(self) -> bool {
        matches!(self, Self::AllowPrivate)
    }
}

/// Build (tls, network) policy pair from the CLI flags as a single call. The
/// canonical conversion used by every handler — keeps the bool→enum hop in one
/// place so call sites read `let (tls, net) = policies_from_cli_flags(...)`.
pub fn policies_from_cli_flags(insecure: bool, allow_private: bool) -> (TlsPolicy, NetworkPolicy) {
    let tls = TlsPolicy::from_insecure(insecure);
    // --insecure implies private/loopback access: validate_acme_url and the
    // CLI docs both promise this, but the connect-time SsrfSafeResolver only
    // sees NetworkPolicy, so we must fold the implication in here.
    let net = NetworkPolicy::from_allow_private(allow_private || insecure);
    (tls, net)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_private_ips() -> anyhow::Result<()> {
        assert!(is_private_or_special_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_private_or_special_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(is_private_or_special_ip(IpAddr::V4(Ipv4Addr::new(
            100, 64, 0, 1
        ))));
        assert!(!is_private_or_special_ip(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(!is_private_or_special_ip(IpAddr::V4(Ipv4Addr::new(
            104, 16, 0, 1
        ))));
        assert!(is_private_or_special_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_private_or_special_ip("fc00::1".parse()?));
        assert!(is_private_or_special_ip("fe80::1".parse()?));
        Ok(())
    }
}
