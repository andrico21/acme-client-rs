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

use crate::cli::{Cli, OutputFormat};
use crate::dns_check::DnsChecker;
use crate::outln;
use crate::types::{Challenge, ChallengeStatus, ChallengeType};

// ── Result emission (JSON or text, respects --silent) ──────────────────────

/// Emit a command's result in either JSON or text form, honoring `--silent`.
///
/// The `json` closure is only invoked on the JSON path, so callers can build
/// `serde_json::Value` lazily without paying for it in text or silent mode.
pub(super) fn emit_result(
    cli: &Cli,
    json: impl FnOnce() -> serde_json::Value,
    text: impl FnOnce(),
) {
    if cli.silent {
        return;
    }
    if cli.output_format == OutputFormat::Json {
        outln!("{}", json());
    } else {
        text();
    }
}

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

// ── Hook helpers ────────────────────────────────────────────────────────────

mod hooks;
pub(super) use hooks::{
    run_dns_hook_cleanup_logged, run_dns_hook_cleanup_silent, run_dns_hook_create, run_hook,
};

/// Reject wildcard identifiers paired with a non-DNS challenge type.
///
/// RFC 8555 §7.1.3 / §8.4: wildcard certificates can only be validated via
/// DNS-based challenges. dns-persist-01 (the persistent-DNS draft) is also
/// accepted because it publishes to the same zone. http-01 and tls-alpn-01
/// must hit a literal hostname and cannot satisfy `*.example.com`.
pub(super) fn check_wildcard_compatible<S: AsRef<str>>(
    domains: &[S],
    challenge_type: &ChallengeType,
) -> Result<()> {
    let dns_based = matches!(
        challenge_type,
        ChallengeType::Dns01 | ChallengeType::DnsPersist01
    );
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

/// Returns true iff the challenge has reached the unrecoverable `invalid` state.
///
/// Per RFC 8555 §7.1.6, `invalid` is a terminal failure state — polling cannot
/// recover. A challenge with `status: "pending"` and an `error` field is NOT
/// failed; it just means a previous validation attempt errored and the CA may
/// retry. Some CAs (e.g. step-ca) validate synchronously and attach errors to
/// still-pending challenges. This is distinct from `valid`, which is also
/// terminal but represents success — callers handle those paths separately.
pub(super) fn is_challenge_failed(ch: &Challenge) -> bool {
    ch.status == ChallengeStatus::Invalid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AcmeError, AcmeErrorType, Challenge, ChallengeStatus, ChallengeToken, ChallengeType,
    };

    fn make_challenge(
        status: ChallengeStatus,
        error: Option<AcmeError>,
    ) -> anyhow::Result<Challenge> {
        Ok(Challenge {
            challenge_type: ChallengeType::Http01,
            url: "https://example.com/chall/1".parse()?,
            status,
            validated: None,
            token: Some(ChallengeToken::parse("test-token")?),
            error,
            issuer_domain_names: None,
        })
    }

    fn make_error() -> AcmeError {
        AcmeError {
            error_type: Some(AcmeErrorType::Connection),
            detail: Some("The server could not connect to validation target".to_string()),
            status: None,
            subproblems: None,
        }
    }

    #[test]
    fn pending_without_error_is_not_terminal() -> anyhow::Result<()> {
        let ch = make_challenge(ChallengeStatus::Pending, None)?;
        assert!(!is_challenge_failed(&ch));
        Ok(())
    }

    #[test]
    fn pending_with_error_is_not_terminal() -> anyhow::Result<()> {
        // step-ca returns error on pending challenge after sync validation failure
        let ch = make_challenge(ChallengeStatus::Pending, Some(make_error()))?;
        assert!(!is_challenge_failed(&ch));
        Ok(())
    }

    #[test]
    fn processing_without_error_is_not_terminal() -> anyhow::Result<()> {
        let ch = make_challenge(ChallengeStatus::Processing, None)?;
        assert!(!is_challenge_failed(&ch));
        Ok(())
    }

    #[test]
    fn invalid_with_error_is_terminal() -> anyhow::Result<()> {
        let ch = make_challenge(ChallengeStatus::Invalid, Some(make_error()))?;
        assert!(is_challenge_failed(&ch));
        Ok(())
    }

    #[test]
    fn invalid_without_error_is_terminal() -> anyhow::Result<()> {
        let ch = make_challenge(ChallengeStatus::Invalid, None)?;
        assert!(is_challenge_failed(&ch));
        Ok(())
    }

    #[test]
    fn valid_is_not_terminal() -> anyhow::Result<()> {
        let ch = make_challenge(ChallengeStatus::Valid, None)?;
        assert!(!is_challenge_failed(&ch));
        Ok(())
    }
}
