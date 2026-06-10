//! Renewal-decision phase: SAN/ARI/days-remaining pre-check.
//!
//! Decides whether the run subcommand should issue a new certificate,
//! reissue (after a domain-set change), or skip entirely because the
//! existing cert is still valid by ARI window or `--days` threshold.

use anyhow::Result;
use rand_core::RngCore;
use time::OffsetDateTime;

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
// cognitive_complexity: ARI window + --days + mismatch checks form one
// decision tree; splitting would hide the precedence between them.
#[allow(clippy::cognitive_complexity)]
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

    // ── 0a. ARI-based renewal check (RFC 9773 §4.2) ────────────────
    //
    // Per §4.2 step 2 we select a uniformly random instant inside the
    // suggestedWindow and renew iff `now >= selected_instant` (step 3 says
    // that if the selected time is already past, renew immediately —
    // covered naturally by the `now >= instant` check).
    //
    // This is a *randomized stateless approximation* of the spec's
    // schedulable-client algorithm: a fresh draw on every cron invocation
    // still yields the intended fleet-wide load-spreading ramp (the
    // probability of "renew now" rises linearly across the window), at the
    // cost that repeated runs inside a spanning window may flap
    // skip→renew→skip — tolerable for an idempotent cron client that does
    // its own pre-issuance freshness checks.
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
                                match parse_ari_window(
                                    &info.suggested_window.start,
                                    &info.suggested_window.end,
                                ) {
                                    Ok((start, end)) => {
                                        let selected = select_renewal_instant(
                                            start,
                                            end,
                                            rand_core::OsRng.next_u64(),
                                        );
                                        let now = OffsetDateTime::now_utc();
                                        if now < selected {
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
                                                            "selected_instant": format_rfc3339(selected),
                                                            "cert_path": ctx.cert_output.display().to_string(),
                                                        })
                                                    );
                                                } else {
                                                    outln!(
                                                        "ARI: window {} - {}, selected renewal instant {} - skipping renewal",
                                                        info.suggested_window.start,
                                                        info.suggested_window.end,
                                                        format_rfc3339(selected),
                                                    );
                                                }
                                            }
                                            ctx.early_client = Some(ari_client);
                                            return Ok(RenewalDecision::Skip);
                                        }
                                        if !ctx.json && !ctx.silent {
                                            outln!(
                                                "ARI: window {} - {}, selected renewal instant {} - renewing...",
                                                info.suggested_window.start,
                                                info.suggested_window.end,
                                                format_rfc3339(selected),
                                            );
                                        }
                                        if let Ok(cid) = compute_cert_id(&cert_der) {
                                            ctx.ari_cert_id = Some(cid);
                                        }
                                    }
                                    Err(reason) => {
                                        tracing::warn!(
                                            "ARI suggestedWindow invalid ({reason}: start={:?}, end={:?}) - falling back to --days check",
                                            info.suggested_window.start,
                                            info.suggested_window.end,
                                        );
                                    }
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

fn parse_ari_window(
    start: &str,
    end: &str,
) -> Result<(OffsetDateTime, OffsetDateTime), &'static str> {
    let rfc = &time::format_description::well_known::Rfc3339;
    let start_dt = OffsetDateTime::parse(start, rfc).map_err(|_| "unparseable start")?;
    let end_dt = OffsetDateTime::parse(end, rfc).map_err(|_| "unparseable end")?;
    if end_dt <= start_dt {
        return Err("end <= start");
    }
    Ok((start_dt, end_dt))
}

/// Uniform random instant in `[start, end]` per RFC 9773 §4.2 step 2.
/// `random_u64` is caller-supplied (`OsRng` in production) to keep this pure
/// and unit-testable. Saturates on duration overflow (only possible for
/// >292-year windows — irrelevant for ARI, where windows span days).
fn select_renewal_instant(
    start: OffsetDateTime,
    end: OffsetDateTime,
    random_u64: u64,
) -> OffsetDateTime {
    let span_nanos = (end - start).whole_nanoseconds();
    if span_nanos <= 0 {
        return start;
    }
    // Modulo bias: for windows ≤ ~292 years (i64::MAX nanos) the bias is
    // bounded above by span_nanos / 2^64 ≤ 2^-40, far below any timing
    // signal we care about — accept it for code simplicity.
    let span_u128 = span_nanos.unsigned_abs();
    let offset_nanos = u128::from(random_u64) % span_u128;
    let offset_i64 = i64::try_from(offset_nanos).unwrap_or(i64::MAX);
    start.saturating_add(time::Duration::nanoseconds(offset_i64))
}

fn format_rfc3339(dt: OffsetDateTime) -> String {
    dt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| dt.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;
    use time::macros::datetime;

    #[test]
    fn select_returns_start_when_random_is_zero() {
        let start = datetime!(2026-01-01 00:00:00 UTC);
        let end = datetime!(2026-01-15 00:00:00 UTC);
        assert_eq!(select_renewal_instant(start, end, 0), start);
    }

    #[test]
    fn select_returns_within_window_for_arbitrary_random() {
        let start = datetime!(2026-01-01 00:00:00 UTC);
        let end = datetime!(2026-01-15 00:00:00 UTC);
        for r in [1_u64, 42, 1_000_000, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let inst = select_renewal_instant(start, end, r);
            assert!(inst >= start, "instant {inst} < start {start} for r={r}");
            assert!(inst < end, "instant {inst} >= end {end} for r={r}");
        }
    }

    #[test]
    fn select_collapses_to_start_when_end_equals_start() {
        let start = datetime!(2026-01-01 00:00:00 UTC);
        assert_eq!(select_renewal_instant(start, start, 12345), start);
    }

    #[test]
    fn parse_window_accepts_valid_rfc3339_pair() {
        let (s, e) =
            parse_ari_window("2026-04-01T00:00:00Z", "2026-04-15T00:00:00Z").expect("valid window");
        assert_eq!(s, datetime!(2026-04-01 00:00:00 UTC));
        assert_eq!(e, datetime!(2026-04-15 00:00:00 UTC));
    }

    #[test]
    fn parse_window_rejects_unparseable_start() {
        assert_eq!(
            parse_ari_window("not-a-date", "2026-04-15T00:00:00Z"),
            Err("unparseable start"),
        );
    }

    #[test]
    fn parse_window_rejects_unparseable_end() {
        assert_eq!(
            parse_ari_window("2026-04-01T00:00:00Z", "garbage"),
            Err("unparseable end"),
        );
    }

    #[test]
    fn parse_window_rejects_end_before_or_equal_start() {
        assert_eq!(
            parse_ari_window("2026-04-15T00:00:00Z", "2026-04-01T00:00:00Z"),
            Err("end <= start"),
        );
        assert_eq!(
            parse_ari_window("2026-04-01T00:00:00Z", "2026-04-01T00:00:00Z"),
            Err("end <= start"),
        );
    }

    #[test]
    fn fully_past_window_always_renews() {
        let start = datetime!(2000-01-01 00:00:00 UTC);
        let end = datetime!(2000-01-15 00:00:00 UTC);
        let now = OffsetDateTime::now_utc();
        for r in [0_u64, 1, u64::MAX / 3, u64::MAX] {
            let inst = select_renewal_instant(start, end, r);
            assert!(
                now >= inst,
                "now {now} should be >= selected {inst} (r={r})"
            );
        }
    }

    #[test]
    fn fully_future_window_always_skips() {
        let start = datetime!(2099-01-01 00:00:00 UTC);
        let end = datetime!(2099-01-15 00:00:00 UTC);
        let now = OffsetDateTime::now_utc();
        for r in [0_u64, 1, u64::MAX / 3, u64::MAX] {
            let inst = select_renewal_instant(start, end, r);
            assert!(now < inst, "now {now} should be < selected {inst} (r={r})");
        }
    }
}
