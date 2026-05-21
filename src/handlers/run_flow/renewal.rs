//! Renewal-decision phase: SAN/ARI/days-remaining pre-check.
//!
//! Decides whether the run subcommand should issue a new certificate,
//! reissue (after a domain-set change), or skip entirely because the
//! existing cert is still valid by ARI window or `--days` threshold.

use anyhow::Result;

use crate::cert_info::{cert_days_remaining, cert_san_identifiers, normalize_identifier};
use crate::client::compute_cert_id;
use crate::csr::pem_to_der;
use crate::{build_client, outln};

use super::RunContext;

/// Outcome of the renewal pre-check.
///
/// - `Skip`    — existing cert is still valid; `cmd_run` returns immediately.
/// - `Reissue` — domain set changed; issue a new cert without ARI replacement.
/// - `Renew`   — proceed with issuance (may carry an ARI `cert_id` for replaceOrder).
pub(super) enum RenewalDecision {
    Skip,
    Reissue,
    Renew,
}

// cancel-safe: read-only — inspects existing cert + optional ARI HTTP GET.
// No external mutation; drop has no side effects.
pub(super) async fn check(ctx: &mut RunContext<'_>) -> Result<RenewalDecision> {
    if !ctx.cert_output.exists() {
        return Ok(RenewalDecision::Renew);
    }

    let mut skip_renewal_checks = false;

    let requested: std::collections::BTreeSet<String> = ctx
        .domains
        .iter()
        .map(|d| normalize_identifier(d))
        .collect();

    match cert_san_identifiers(ctx.cert_output).await {
        Ok(cert_sans) => {
            if requested != cert_sans {
                let added: Vec<&str> = requested
                    .difference(&cert_sans)
                    .map(std::string::String::as_str)
                    .collect();
                let removed: Vec<&str> = cert_sans
                    .difference(&requested)
                    .map(std::string::String::as_str)
                    .collect();

                if ctx.reissue_on_mismatch {
                    if !ctx.silent {
                        if ctx.json {
                            outln!(
                                "{}",
                                serde_json::json!({
                                    "command": "run",
                                    "action": "reissue",
                                    "reason": "domain_mismatch",
                                    "cert_domains": cert_sans,
                                    "requested_domains": requested,
                                    "added": added,
                                    "removed": removed,
                                })
                            );
                        } else {
                            outln!(
                                "Domain mismatch detected (added: [{}], removed: [{}]), reissuing certificate...",
                                added.join(", "),
                                removed.join(", "),
                            );
                        }
                    }
                    // Skip ARI/days checks — proceed directly to issuance
                    // (ari_cert_id stays None: this is reissuance, not renewal)
                    skip_renewal_checks = true;
                } else {
                    if !ctx.silent {
                        if ctx.json {
                            outln!(
                                "{}",
                                serde_json::json!({
                                    "command": "run",
                                    "action": "skip",
                                    "reason": "domain_mismatch",
                                    "hint": "use --reissue-on-mismatch to override",
                                    "cert_domains": cert_sans,
                                    "requested_domains": requested,
                                    "added": added,
                                    "removed": removed,
                                })
                            );
                        } else {
                            outln!(
                                "Domain mismatch: cert has [{}], requested [{}] (added: [{}], removed: [{}]). \
                                 Use --reissue-on-mismatch to override.",
                                cert_sans
                                    .iter()
                                    .map(std::string::String::as_str)
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                requested
                                    .iter()
                                    .map(std::string::String::as_str)
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                added.join(", "),
                                removed.join(", "),
                            );
                        }
                    }
                    return Ok(RenewalDecision::Skip);
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "Could not read SANs from {}: {e} — skipping domain mismatch check",
                ctx.cert_output.display()
            );
        }
    }

    if skip_renewal_checks {
        return Ok(RenewalDecision::Reissue);
    }

    // ── 0a. ARI-based renewal check (RFC 9773) ─────────────────────
    if ctx.ari {
        match tokio::fs::read_to_string(ctx.cert_output).await {
            Ok(pem_data) => match pem_to_der(&pem_data) {
                Ok(cert_der) => {
                    // RFC 9773 §4.1+§6: ARI lookup is an unauthenticated GET,
                    // so the directory-only client is sufficient and no
                    // newAccount call may precede it (signing newAccount with
                    // a stale account_url breaks RFC 8555 §6.2).
                    let mut ari_client = build_client(ctx.cli).await?;

                    if ari_client.supports_ari() {
                        match ari_client.get_renewal_info(&cert_der).await {
                            Ok((info, _retry_after)) => {
                                let now = time::OffsetDateTime::now_utc();
                                if let Ok(start) = time::OffsetDateTime::parse(
                                    &info.suggested_window.start,
                                    &time::format_description::well_known::Rfc3339,
                                ) {
                                    if now < start {
                                        if !ctx.silent {
                                            if ctx.json {
                                                outln!(
                                                    "{}",
                                                    serde_json::json!({
                                                        "command": "run",
                                                        "action": "skip",
                                                        "reason": "ari",
                                                        "window_start": info.suggested_window.start,
                                                        "window_end": info.suggested_window.end,
                                                        "cert_path": ctx.cert_output.display().to_string(),
                                                    })
                                                );
                                            } else {
                                                outln!(
                                                    "ARI: renewal window starts {} - skipping renewal",
                                                    info.suggested_window.start
                                                );
                                            }
                                        }
                                        ctx.early_client = Some(ari_client);
                                        return Ok(RenewalDecision::Skip);
                                    }
                                    if !ctx.json && !ctx.silent {
                                        outln!(
                                            "ARI: renewal window is open ({} - {}), renewing...",
                                            info.suggested_window.start,
                                            info.suggested_window.end
                                        );
                                    }
                                }
                                if let Ok(cid) = compute_cert_id(&cert_der) {
                                    ctx.ari_cert_id = Some(cid);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "ARI check failed: {e} - falling back to --days check"
                                );
                            }
                        }
                    } else {
                        tracing::warn!(
                            "Server does not support ARI - falling back to --days check"
                        );
                    }
                    ctx.early_client = Some(ari_client);
                }
                Err(e) => {
                    tracing::warn!(
                        "Could not parse certificate {}: {e}",
                        ctx.cert_output.display()
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    "Could not read certificate {}: {e}",
                    ctx.cert_output.display()
                );
            }
        }
    }

    // ── 0b. Days-based renewal check (fallback / standalone) ────────
    if ctx.ari_cert_id.is_none()
        && let Some(threshold) = ctx.days
    {
        match cert_days_remaining(ctx.cert_output).await {
            Ok(remaining) if remaining > i64::from(threshold) => {
                if ctx.json {
                    if !ctx.silent {
                        outln!(
                            "{}",
                            serde_json::json!({
                                "command": "run",
                                "action": "skip",
                                "reason": "days",
                                "days_remaining": remaining,
                                "threshold": threshold,
                                "cert_path": ctx.cert_output.display().to_string(),
                            })
                        );
                    }
                } else if !ctx.silent {
                    outln!(
                        "Certificate {} has {remaining} days remaining (threshold: {threshold}), skipping renewal",
                        ctx.cert_output.display()
                    );
                }
                return Ok(RenewalDecision::Skip);
            }
            Ok(remaining) => {
                if !ctx.json && !ctx.silent {
                    outln!(
                        "Certificate {} expires in {remaining} days (threshold: {threshold}), renewing...",
                        ctx.cert_output.display()
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Could not read certificate {}: {e} - proceeding with renewal",
                    ctx.cert_output.display()
                );
            }
        }
    }

    Ok(RenewalDecision::Renew)
}
