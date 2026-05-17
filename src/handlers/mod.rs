//! Subcommand handler implementations.
//!
//! Each `cmd_*` function corresponds to one variant of [`crate::cli::Commands`]
//! and is invoked by the dispatch logic in `main::run`. Handlers are grouped
//! into thematic submodules:
//!
//!   - [`account`]   account-key + ACME account lifecycle
//!   - [`cert`]      post-issuance cert operations (revoke, renewal-info)
//!   - [`challenge`] challenge-helper subcommands (serve, show, pre-authorize)
//!   - [`config`]    config-file generation and inspection
//!   - [`order`]     order placement, authorization, and finalization
//!   - [`run`]       the full end-to-end issuance/renewal flow
//!
//! Helpers used by more than one submodule (DNS TXT propagation check, EAB
//! parsing, hook invocation, the DNS-01 cleanup hook entry-point, wildcard
//! compatibility check, and the RFC 8555 §7.5.1 challenge-terminality check)
//! live in this file and are re-exported to siblings via `pub(super)`.

pub(crate) mod account;
pub(crate) mod cert;
pub(crate) mod challenge;
pub(crate) mod config;
pub(crate) mod order;
pub(crate) mod run_flow;

// Re-export every cmd_* so main.rs can keep `use crate::handlers::*;`.
pub(crate) use account::{cmd_account, cmd_deactivate, cmd_generate_key, cmd_key_rollover};
pub(crate) use cert::{cmd_renewal_info, cmd_revoke};
pub(crate) use challenge::{
    cmd_pre_authorize, cmd_serve_http01, cmd_show_dns_persist01, cmd_show_dns01,
};
pub(crate) use config::{cmd_generate_config, cmd_show_config};
pub(crate) use order::{
    cmd_download_cert, cmd_finalize, cmd_get_authz, cmd_list_profiles, cmd_order, cmd_poll_order,
    cmd_respond_challenge,
};
pub(crate) use run_flow::cmd_run;

use anyhow::{Context, Result};

use crate::dns_check::DnsChecker;
use crate::types::{
    CHALLENGE_TYPE_DNS_PERSIST01, CHALLENGE_TYPE_DNS01, Challenge, ChallengeStatus,
};

// ── DNS TXT propagation check (hickory-resolver, see dns_check.rs) ─────────

/// Check whether a DNS TXT record with the expected value exists, using the
/// configured [`DnsChecker`]. Comparison is byte-exact (no substring match).
pub(super) async fn dns_txt_check(
    checker: &DnsChecker,
    name: &str,
    expected: &str,
) -> Result<bool> {
    checker.txt_matches(name, expected).await
}

// ── EAB helper ──────────────────────────────────────────────────────────────

/// Decode the base64url EAB HMAC key and return `(kid, decoded_key)`.
pub(super) fn parse_eab(
    kid: Option<&str>,
    hmac_key_b64: Option<&str>,
) -> Result<Option<(String, secrecy::SecretBox<Vec<u8>>)>> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    match (kid, hmac_key_b64) {
        (Some(kid), Some(key_b64)) => {
            let key_bytes = URL_SAFE_NO_PAD
                .decode(key_b64)
                .context("--eab-hmac-key is not valid base64url")?;
            Ok(Some((
                kid.to_string(),
                secrecy::SecretBox::new(Box::new(key_bytes)),
            )))
        }
        (None, None) => Ok(None),
        _ => anyhow::bail!("--eab-kid and --eab-hmac-key must both be provided"),
    }
}

// ── Hook helper ─────────────────────────────────────────────────────────────

pub(super) fn run_hook(script: &std::path::Path, env_vars: &[(&str, &str)]) -> Result<()> {
    let mut cmd = std::process::Command::new(script);
    for &(key, val) in env_vars {
        cmd.env(key, val);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to run hook: {}", script.display()))?;
    if !status.success() {
        anyhow::bail!("hook {} exited with {status}", script.display());
    }
    Ok(())
}

/// Invoke a DNS hook to create a DNS-01 challenge TXT record.
///
/// Wraps the standard `ACME_DOMAIN` / `ACME_TXT_NAME` / `ACME_TXT_VALUE` /
/// `ACME_ACTION=create` env contract documented in README. Returns an error
/// if the hook fails to spawn or exits non-zero — callers MUST treat that
/// as fatal because the upcoming validation will fail without the record.
pub(super) fn run_dns_hook_create(
    hook: &std::path::Path,
    domain: &str,
    txt_name: &str,
    txt_value: &str,
) -> Result<()> {
    let status = std::process::Command::new(hook)
        .env("ACME_DOMAIN", domain)
        .env("ACME_TXT_NAME", txt_name)
        .env("ACME_TXT_VALUE", txt_value)
        .env("ACME_ACTION", "create")
        .status()
        .with_context(|| format!("failed to run DNS hook: {}", hook.display()))?;
    if !status.success() {
        anyhow::bail!("DNS hook (create) exited with {status}");
    }
    Ok(())
}

/// Invoke a DNS hook to delete a previously-created DNS-01 TXT record,
/// logging any failure as a warning. Errors are intentionally non-fatal:
/// callers are usually already on an error path (challenge timed out,
/// validation failed) and a missing cleanup must not mask the original
/// failure cause.
pub(super) fn run_dns_hook_cleanup_logged(
    hook: &std::path::Path,
    domain: &str,
    txt_name: &str,
    txt_value: &str,
) {
    let status = std::process::Command::new(hook)
        .env("ACME_DOMAIN", domain)
        .env("ACME_TXT_NAME", txt_name)
        .env("ACME_TXT_VALUE", txt_value)
        .env("ACME_ACTION", "cleanup")
        .status();
    match status {
        Ok(s) if !s.success() => tracing::warn!("DNS hook (cleanup) exited with {s}"),
        Err(e) => tracing::warn!("DNS hook (cleanup) failed: {e}"),
        _ => {}
    }
}

/// Best-effort DNS cleanup hook for parallel-DNS rollback paths where any
/// hook failure would be immediately followed by `anyhow::bail!` anyway,
/// making logging redundant. Use [`run_dns_hook_cleanup_logged`] elsewhere.
pub(super) fn run_dns_hook_cleanup_silent(
    hook: &std::path::Path,
    domain: &str,
    txt_name: &str,
    txt_value: &str,
) {
    let _ = std::process::Command::new(hook)
        .env("ACME_DOMAIN", domain)
        .env("ACME_TXT_NAME", txt_name)
        .env("ACME_TXT_VALUE", txt_value)
        .env("ACME_ACTION", "cleanup")
        .status();
}

/// Reject wildcard identifiers paired with a non-DNS challenge type.
///
/// RFC 8555 §7.1.3 / §8.4: wildcard certificates can only be validated via
/// DNS-based challenges. dns-persist-01 (the persistent-DNS draft) is also
/// accepted because it publishes to the same zone. http-01 and tls-alpn-01
/// must hit a literal hostname and cannot satisfy `*.example.com`.
pub(super) fn check_wildcard_compatible<S: AsRef<str>>(
    domains: &[S],
    challenge_type: &str,
) -> Result<()> {
    let dns_based =
        challenge_type == CHALLENGE_TYPE_DNS01 || challenge_type == CHALLENGE_TYPE_DNS_PERSIST01;
    if dns_based {
        return Ok(());
    }
    if let Some(d) = domains.iter().find(|d| d.as_ref().starts_with("*.")) {
        anyhow::bail!(
            "wildcard identifier {:?} requires a DNS-based challenge \
             (dns-01 or dns-persist-01); got {challenge_type}",
            d.as_ref()
        );
    }
    Ok(())
}

///
/// Per RFC 8555 §7.5.1, a challenge with `status: "invalid"` is terminal.
/// A challenge with `status: "pending"` and an `error` field is NOT terminal —
/// it just means a previous validation attempt failed. Some CAs (e.g. step-ca)
/// validate synchronously and attach errors to still-pending challenges.
pub(super) fn is_challenge_terminal(ch: &Challenge) -> bool {
    ch.status == ChallengeStatus::Invalid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AcmeError, Challenge, ChallengeStatus};

    fn make_challenge(status: ChallengeStatus, error: Option<AcmeError>) -> Challenge {
        Challenge {
            challenge_type: "http-01".to_string(),
            url: "https://example.com/chall/1".to_string(),
            status,
            validated: None,
            token: Some("test-token".to_string()),
            error,
            issuer_domain_names: None,
        }
    }

    fn make_error() -> AcmeError {
        AcmeError {
            error_type: Some("urn:ietf:params:acme:error:connection".to_string()),
            detail: Some("The server could not connect to validation target".to_string()),
            status: None,
            subproblems: None,
        }
    }

    #[test]
    fn pending_without_error_is_not_terminal() {
        let ch = make_challenge(ChallengeStatus::Pending, None);
        assert!(!is_challenge_terminal(&ch));
    }

    #[test]
    fn pending_with_error_is_not_terminal() {
        // step-ca returns error on pending challenge after sync validation failure
        let ch = make_challenge(ChallengeStatus::Pending, Some(make_error()));
        assert!(!is_challenge_terminal(&ch));
    }

    #[test]
    fn processing_without_error_is_not_terminal() {
        let ch = make_challenge(ChallengeStatus::Processing, None);
        assert!(!is_challenge_terminal(&ch));
    }

    #[test]
    fn invalid_with_error_is_terminal() {
        let ch = make_challenge(ChallengeStatus::Invalid, Some(make_error()));
        assert!(is_challenge_terminal(&ch));
    }

    #[test]
    fn invalid_without_error_is_terminal() {
        let ch = make_challenge(ChallengeStatus::Invalid, None);
        assert!(is_challenge_terminal(&ch));
    }

    #[test]
    fn valid_is_not_terminal() {
        let ch = make_challenge(ChallengeStatus::Valid, None);
        assert!(!is_challenge_terminal(&ch));
    }
}
