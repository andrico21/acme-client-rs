//! DNS TXT propagation check for ACME dns-01 challenges.
//!
//! SEC-12: Replaces subprocess (`dig`/`nslookup`) with `hickory-resolver`,
//! eliminating PATH-injection risk and substring false-positives. Three
//! resolution strategies are exposed via [`DnsCheckMode`]:
//!
//!   * [`DnsCheckMode::Authoritative`] (default) — locate the zone's
//!     nameservers and query them directly, bypassing local/recursive caches.
//!     Matches the perspective the CA's validation resolvers will use.
//!   * [`DnsCheckMode::Cached`] — query well-known public resolvers
//!     (Cloudflare/Google/Quad9).
//!   * [`DnsCheckMode::System`] — use the host's resolver (`resolv.conf` or
//!     platform equivalent).
//!
//! All modes compare TXT record values to the expected key authorization
//! string (RFC 8555 §8.4) using **byte-exact equality**, not substring match.

use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use hickory_resolver::{
    TokioResolver,
    config::{
        CLOUDFLARE, GOOGLE, LookupIpStrategy, NameServerConfig, QUAD9, ResolverConfig, ResolverOpts,
    },
    net::runtime::TokioRuntimeProvider,
    proto::rr::{Name, RData},
};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

/// Resolver strategy for DNS-01 propagation checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum DnsCheckMode {
    /// Query the zone's authoritative nameservers directly (bypasses caches; matches what the CA's resolvers will see). Default.
    Authoritative,
    /// Query well-known public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9). Useful when authoritative-NS lookups are blocked.
    Cached,
    /// Use the host's system resolver (resolv.conf or platform equivalent). May return cached records.
    System,
}

/// Whether the DNS resolver should perform DNSSEC validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dnssec {
    On,
    Off,
}

impl Dnssec {
    fn validate(self) -> bool {
        matches!(self, Self::On)
    }
}

/// Configured DNS resolver for ACME propagation checks.
///
/// Build once per command and reuse across all `txt_matches` calls.
pub struct DnsChecker {
    mode: DnsCheckMode,
    dnssec: Dnssec,
    bootstrap: Arc<TokioResolver>,
}

impl DnsChecker {
    /// Build a checker for the given mode. DNSSEC validation is opt-in.
    pub fn new(mode: DnsCheckMode, dnssec: Dnssec) -> Result<Self> {
        let bootstrap = match mode {
            DnsCheckMode::System => build_system_resolver(dnssec)?,
            DnsCheckMode::Cached | DnsCheckMode::Authoritative => build_public_resolver(dnssec)?,
        };

        Ok(Self {
            mode,
            dnssec,
            bootstrap: Arc::new(bootstrap),
        })
    }

    /// Return true iff any TXT record at `name` exactly matches `expected`.
    // cancel-safe: single DNS TXT lookup, byte-exact comparison. Pure read.
    pub async fn txt_matches(&self, name: &str, expected: &str) -> Result<bool> {
        let fqdn = Name::from_str(name).with_context(|| format!("invalid DNS name: {name}"))?;

        let resolver: Arc<TokioResolver> = match self.mode {
            DnsCheckMode::System | DnsCheckMode::Cached => Arc::clone(&self.bootstrap),
            DnsCheckMode::Authoritative => {
                Arc::new(self.build_authoritative_resolver(&fqdn).await?)
            }
        };

        let lookup = match resolver.txt_lookup(fqdn).await {
            Ok(l) => l,
            Err(e) if e.is_no_records_found() => return Ok(false),
            Err(e) => return Err(anyhow!("TXT lookup for {name} failed: {e}")),
        };

        let expected_bytes = expected.as_bytes();
        for record in lookup.answers() {
            if let RData::TXT(txt) = &record.data
                && joined_txt_matches(&txt.txt_data, expected_bytes)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // cancel-safe: NS lookup + resolver construction; pure read.
    async fn build_authoritative_resolver(&self, name: &Name) -> Result<TokioResolver> {
        // Walk up the labels (e.g. _acme-challenge.foo.example.com →
        // foo.example.com → example.com → com) and use the deepest ancestor
        // that has NS records. This locates the actual zone holding the TXT,
        // which matters when subzones or _acme-challenge CNAMEs are in play.
        let mut candidate = name.clone();
        let ns_names = loop {
            if candidate.num_labels() == 0 {
                return Err(anyhow!(
                    "could not find authoritative nameservers for {name}"
                ));
            }
            match self.bootstrap.ns_lookup(candidate.clone()).await {
                Ok(lookup) => {
                    let mut names: Vec<Name> = Vec::new();
                    for record in lookup.answers() {
                        if let RData::NS(ns) = &record.data {
                            names.push(ns.0.clone());
                        }
                    }
                    if !names.is_empty() {
                        break names;
                    }
                }
                Err(e) if e.is_no_records_found() => {}
                Err(e) => {
                    return Err(anyhow!("NS lookup for {candidate} failed: {e}"));
                }
            }
            candidate = candidate.base_name();
        };

        let mut ns_ips: Vec<IpAddr> = Vec::new();
        for ns_name in &ns_names {
            if let Ok(ip_lookup) = self.bootstrap.lookup_ip(ns_name.clone()).await {
                for ip in ip_lookup.iter() {
                    ns_ips.push(ip);
                }
            }
        }
        if ns_ips.is_empty() {
            return Err(anyhow!(
                "could not resolve any authoritative NS for zone {candidate}"
            ));
        }

        let name_servers: Vec<NameServerConfig> = ns_ips
            .into_iter()
            .map(NameServerConfig::udp_and_tcp)
            .collect();
        let config = ResolverConfig::from_parts(None, vec![], name_servers);

        let mut opts = ResolverOpts::default();
        opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        // Disable caching: a propagation check must always see fresh data,
        // otherwise we would re-confirm a stale positive after the user
        // rotated the TXT value.
        opts.cache_size = 0;
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;
        opts.validate = self.dnssec.validate();

        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .context("failed to build authoritative resolver")?;
        Ok(resolver)
    }
}

fn build_public_resolver(dnssec: Dnssec) -> Result<TokioResolver> {
    let mut name_servers: Vec<NameServerConfig> = Vec::new();
    for group in [&CLOUDFLARE, &GOOGLE, &QUAD9] {
        for ip in group.ips {
            name_servers.push(NameServerConfig::udp_and_tcp(*ip));
        }
    }
    let config = ResolverConfig::from_parts(None, vec![], name_servers);

    let mut opts = ResolverOpts::default();
    opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;
    opts.validate = dnssec.validate();

    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .context("failed to build public DNS resolver")
}

fn build_system_resolver(dnssec: Dnssec) -> Result<TokioResolver> {
    let mut builder = TokioResolver::builder_tokio().context(
        "could not read the system DNS configuration (resolv.conf); \
         fix it or use --dns-check-mode cached|authoritative",
    )?;
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    builder.options_mut().validate = dnssec.validate();
    builder
        .build()
        .context("failed to build system DNS resolver")
}

/// True iff the concatenation of a TXT record's `<character-string>` chunks
/// equals `expected`. RFC 1035 §3.3.14 caps each chunk at 255 bytes, so a
/// longer value (e.g. a dns-persist token) is split and MUST be rejoined
/// before comparison; comparing chunks individually would never match it.
fn joined_txt_matches<C: AsRef<[u8]>>(chunks: &[C], expected: &[u8]) -> bool {
    let mut joined: Vec<u8> = Vec::with_capacity(expected.len());
    for chunk in chunks {
        joined.extend_from_slice(chunk.as_ref());
    }
    joined == expected
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    #[test]
    fn dns_check_mode_variants_are_distinct() -> anyhow::Result<()> {
        assert_ne!(DnsCheckMode::Authoritative, DnsCheckMode::Cached);
        assert_ne!(DnsCheckMode::Cached, DnsCheckMode::System);
        Ok(())
    }

    #[test]
    fn m2_concatenated_txt_chunks_match() {
        let single = b"short-token".to_vec();
        assert!(joined_txt_matches(
            std::slice::from_ref(&single),
            b"short-token"
        ));
        assert!(!joined_txt_matches(&[single], b"short"));

        let long: Vec<u8> = (0..600)
            .map(|i| b'a' + u8::try_from(i % 26).unwrap_or(0))
            .collect();
        let split: Vec<Vec<u8>> = long.chunks(255).map(<[u8]>::to_vec).collect();
        assert!(split.len() >= 3, "value should span multiple chunks");
        assert!(
            joined_txt_matches(&split, &long),
            "multi-chunk value must match its concatenation"
        );

        let part_only = split.first().expect("split is non-empty");
        assert!(
            !joined_txt_matches(&split, part_only),
            "a single chunk must not match the full value"
        );

        let empty: [Vec<u8>; 0] = [];
        assert!(joined_txt_matches(&empty, b""));
        assert!(!joined_txt_matches(&empty, b"x"));
    }

    #[tokio::test]
    async fn invalid_name_returns_error() -> anyhow::Result<()> {
        let checker = DnsChecker::new(DnsCheckMode::Cached, Dnssec::Off)?;
        let err = checker.txt_matches("foo..example.com", "anything").await;
        assert!(err.is_err(), "expected error for malformed DNS name");
        Ok(())
    }

    #[tokio::test]
    #[ignore = "live network: run with `cargo test -- --ignored`"]
    async fn smoke_cached_mode_finds_real_txt() -> anyhow::Result<()> {
        let checker = DnsChecker::new(DnsCheckMode::Cached, Dnssec::Off)?;
        let expected = "v=spf1 include:_spf.google.com ~all";
        let found = checker.txt_matches("google.com", expected).await?;
        assert!(found, "expected to find Google's SPF TXT record");
        Ok(())
    }

    #[tokio::test]
    #[ignore = "live network: run with `cargo test -- --ignored`"]
    async fn smoke_authoritative_mode_finds_real_txt() -> anyhow::Result<()> {
        let checker = DnsChecker::new(DnsCheckMode::Authoritative, Dnssec::Off)?;
        let expected = "v=spf1 include:_spf.google.com ~all";
        let found = checker.txt_matches("google.com", expected).await?;
        assert!(
            found,
            "expected to find Google's SPF TXT record via authoritative NS"
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "live network: run with `cargo test -- --ignored`"]
    async fn smoke_exact_match_rejects_substring() -> anyhow::Result<()> {
        let checker = DnsChecker::new(DnsCheckMode::Cached, Dnssec::Off)?;
        // Substring of the real SPF record — old `dig | contains` impl would
        // falsely return true. Exact-match must reject it.
        let found = checker.txt_matches("google.com", "v=spf1").await?;
        assert!(
            !found,
            "exact match must NOT accept a substring of a real TXT record"
        );
        Ok(())
    }
}
