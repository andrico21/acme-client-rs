//! Single source of truth for built-in default values.
//!
//! Every default literal referenced by clap `#[arg(default_value*)]` in
//! [`crate::cli`] and by `show-config` rendering (`unwrap_or(...)`) in
//! [`crate::handlers::config`] lives here. A drift-detection unit test in
//! [`crate::cli`] asserts each clap default matches the const it references.
//!
//! Strings are `&'static str` so they satisfy clap derive's `default_value`
//! attribute requirement.

pub(crate) mod global {
    /// Local Pebble dev server. Production users override.
    pub(crate) const DIRECTORY_URL: &str = "https://localhost:14000/dir";

    pub(crate) const ACCOUNT_KEY_FILE: &str = "account.key";

    /// TCP + TLS handshake. Whole-request timeout is fixed at 120s elsewhere.
    pub(crate) const CONNECT_TIMEOUT_SECS: u64 = 15;
}

pub(crate) mod run {
    pub(crate) const CHALLENGE_TYPE: &str = "http-01";

    pub(crate) const HTTP_PORT: u16 = 80;

    pub(crate) const DNS_PROPAGATION_CONCURRENCY: usize = 5;

    pub(crate) const CHALLENGE_TIMEOUT_SECS: u64 = 300;

    pub(crate) const CERT_OUTPUT_FILE: &str = "certificate.pem";

    pub(crate) const KEY_OUTPUT_FILE: &str = "private.key";

    pub(crate) const CERT_KEY_ALGORITHM: &str = "ec-p256";
}

/// Internal polling intervals. NOT user-configurable — these tune how often
/// the client wakes up to re-check long-running async operations. Centralized
/// here so a future "tune the cadence" change touches one place, not eight.
pub(crate) mod polling {
    use std::time::Duration;

    /// Sleep between ACME resource re-polls (challenge / authorization / order
    /// status). RFC 8555 §7.5.1 recommends honoring server `Retry-After`; we
    /// fall back to this when the header is absent. Kept short because Pebble
    /// + Let's Encrypt typically transition within a few seconds.
    pub(crate) const ACME_RESOURCE_POLL: Duration = Duration::from_secs(2);

    /// Upper bound applied to server-provided `Retry-After` values. Prevents a
    /// misconfigured CA (or a malicious header) from stalling a renewal job
    /// for hours; legitimate CAs send seconds to low minutes.
    pub(crate) const ACME_RESOURCE_POLL_MAX: Duration = Duration::from_mins(5);

    /// Sleep between DNS TXT propagation re-checks during `--dns-wait`. Longer
    /// than the ACME poll because authoritative-NS query is heavier and TTL
    /// floors on real DNS providers are typically 30-60s — polling faster than
    /// 5s would just waste resolver round-trips without finding the record
    /// sooner.
    pub(crate) const DNS_PROPAGATION_POLL: Duration = Duration::from_secs(5);

    /// Upper bound on order-finalization polling. RFC 8555 §7.4 does not set
    /// one, but a wedged order should not hang the client forever — Let's
    /// Encrypt and Pebble both transition within seconds; 10 minutes is a
    /// generous ceiling that surfaces stuck orders as a clean timeout error.
    pub(crate) const ORDER_POLL_TIMEOUT: Duration = Duration::from_mins(10);
}

/// User-script hook execution bounds.
pub(crate) mod hooks {
    use std::time::Duration;

    /// Maximum wall-clock time any single hook subprocess (DNS, on-cert-issued,
    /// on-challenge-ready, SIGINT cleanup) may run before being killed. A hung
    /// DNS provider script must not stall issuance indefinitely; 5 minutes is
    /// long enough for legitimate DNS API calls + propagation polling inside a
    /// hook, but bounded enough to surface a wedged provider as a clean error.
    pub(crate) const HOOK_TIMEOUT: Duration = Duration::from_mins(5);
}
