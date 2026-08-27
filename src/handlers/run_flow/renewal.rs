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

// cancel-safe: orchestrates renewal pre-check phases only. Phase-local updates
// touch in-process RunContext state; no filesystem or ACME server mutation.
pub(super) async fn check(ctx: &mut RunContext<'_>) -> Result<RenewalDecision> {
    if !crate::fs_secure::path_exists(ctx.cert_output).await {
        return Ok(RenewalDecision::Renew);
    }

    if let Some(decision) = check_domain_mismatch(ctx).await? {
        return Ok(decision);
    }
    if let Some(decision) = check_ari_window(ctx).await? {
        return Ok(decision);
    }
    if let Some(decision) = check_days_threshold(ctx).await? {
        return Ok(decision);
    }

    Ok(RenewalDecision::Renew)
}

// cancel-safe: reads existing certificate SANs only. Cancellation leaves no
// filesystem, ACME server, or RunContext mutation behind.
async fn check_domain_mismatch(ctx: &RunContext<'_>) -> Result<Option<RenewalDecision>> {
    let requested: std::collections::BTreeSet<String> = ctx
        .domains
        .iter()
        .map(|d| normalize_identifier(d))
        .collect();

    match cert_san_identifiers(ctx.cert_output).await {
        Ok(cert_sans) => {
            if requested == cert_sans {
                return Ok(None);
            }
            let added: Vec<&str> = requested
                .difference(&cert_sans)
                .map(String::as_str)
                .collect();
            let removed: Vec<&str> = cert_sans
                .difference(&requested)
                .map(String::as_str)
                .collect();
            Ok(Some(decide_domain_mismatch(
                ctx, &cert_sans, &requested, &added, &removed,
            )))
        }
        Err(e) => {
            tracing::warn!(
                "Could not read SANs from {}: {e} — skipping domain mismatch check",
                ctx.cert_output.display()
            );
            Ok(None)
        }
    }
}

fn decide_domain_mismatch(
    ctx: &RunContext<'_>,
    cert_sans: &std::collections::BTreeSet<String>,
    requested: &std::collections::BTreeSet<String>,
    added: &[&str],
    removed: &[&str],
) -> RenewalDecision {
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
        RenewalDecision::Reissue
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
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", "),
                    requested
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", "),
                    added.join(", "),
                    removed.join(", "),
                );
            }
        }
        RenewalDecision::Skip
    }
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
// cancel-safe: reads the existing certificate, performs directory/ARI GETs, and
// mutates only ctx.early_client / ctx.ari_cert_id in memory. Dropping before
// return leaves no ACME order, account, challenge, or filesystem state.
async fn check_ari_window(ctx: &mut RunContext<'_>) -> Result<Option<RenewalDecision>> {
    if !ctx.ari {
        return Ok(None);
    }
    let Some((cert_der, mut ari_client)) = load_ari_certificate_and_client(ctx).await? else {
        return Ok(None);
    };
    let decision = match fetch_ari_info(&mut ari_client, &cert_der).await {
        Some(info) => apply_ari_info(ctx, &info, &cert_der),
        None => None,
    };
    ctx.early_client = Some(ari_client);
    Ok(decision)
}

// cancel-safe: reads the existing certificate and constructs a directory-only
// client. No ACME account/order/challenge state or filesystem mutation occurs.
async fn load_ari_certificate_and_client(
    ctx: &RunContext<'_>,
) -> Result<Option<(Vec<u8>, crate::client::AcmeClient)>> {
    match tokio::fs::read_to_string(ctx.cert_output).await {
        Ok(pem_data) => match pem_to_der(&pem_data) {
            Ok(cert_der) => {
                // RFC 9773 §4.1+§6: ARI lookup is an unauthenticated GET,
                // so the directory-only client is sufficient and no
                // newAccount call may precede it (signing newAccount with
                // a stale account_url breaks RFC 8555 §6.2).
                let ari_client = build_client(ctx.cli).await?;
                Ok(Some((cert_der, ari_client)))
            }
            Err(e) => {
                tracing::warn!(
                    "Could not parse certificate {}: {e}",
                    ctx.cert_output.display()
                );
                Ok(None)
            }
        },
        Err(e) => {
            tracing::warn!(
                "Could not read certificate {}: {e}",
                ctx.cert_output.display()
            );
            Ok(None)
        }
    }
}

// cancel-safe: performs only unauthenticated ARI GETs. RFC 9773 renewalInfo
// lookup does not mutate CA state or consume order/challenge state.
async fn fetch_ari_info(
    ari_client: &mut crate::client::AcmeClient,
    cert_der: &[u8],
) -> Option<crate::types::RenewalInfo> {
    if !ari_client.supports_ari() {
        tracing::warn!("Server does not support ARI - falling back to --days check");
        return None;
    }
    match ari_client.get_renewal_info(cert_der).await {
        Ok((info, _retry_after)) => Some(info),
        Err(e) => {
            tracing::warn!("ARI check failed: {e} - falling back to --days check");
            None
        }
    }
}

fn apply_ari_info(
    ctx: &mut RunContext<'_>,
    info: &crate::types::RenewalInfo,
    cert_der: &[u8],
) -> Option<RenewalDecision> {
    match parse_ari_window(&info.suggested_window.start, &info.suggested_window.end) {
        Ok((start, end)) => {
            let selected = select_renewal_instant(start, end, rand_core::OsRng.next_u64());
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
                return Some(RenewalDecision::Skip);
            }
            if !ctx.json && !ctx.silent {
                outln!(
                    "ARI: window {} - {}, selected renewal instant {} - renewing...",
                    info.suggested_window.start,
                    info.suggested_window.end,
                    format_rfc3339(selected),
                );
            }
            if let Ok(cid) = compute_cert_id(cert_der) {
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
    None
}

// cancel-safe: reads certificate expiry only. Cancellation leaves no filesystem,
// ACME server, or RunContext mutation behind.
async fn check_days_threshold(ctx: &RunContext<'_>) -> Result<Option<RenewalDecision>> {
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
                return Ok(Some(RenewalDecision::Skip));
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

    Ok(None)
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

    // A 10ns window with random = 9: `%` yields start+9ns, `/` yields start.
    // A containment property cannot separate the two, because division lands a
    // tiny offset that is still inside the window.
    #[test]
    fn selected_instant_uses_modulo_not_division() {
        let start = datetime!(2026-01-01 00:00:00 UTC);
        let end = start + time::Duration::nanoseconds(10);
        assert_eq!(
            select_renewal_instant(start, end, 9),
            start + time::Duration::nanoseconds(9)
        );
    }

    #[test]
    fn format_rfc3339_emits_a_parseable_timestamp() -> Result<()> {
        let dt = datetime!(2026-04-01 12:34:56 UTC);
        let rendered = format_rfc3339(dt);
        assert_eq!(rendered, "2026-04-01T12:34:56Z");
        assert_eq!(
            OffsetDateTime::parse(&rendered, &time::format_description::well_known::Rfc3339)?,
            dt
        );
        Ok(())
    }

    // ── Renew / skip decision ───────────────────────────────────────────

    use crate::cli::{Cli, Commands, RunArgs};

    /// Owns everything `RunContext` borrows, so a context can be handed out
    /// with `ctx(&self)`. `RunArgs` is borrowed back out of `cli.command`
    /// rather than stored alongside it, which would duplicate the state clap
    /// already parsed.
    struct TestCtx {
        cli: Cli,
        registry: crate::cleanup::CleanupRegistry,
        tmp: tempfile::TempDir,
    }

    impl TestCtx {
        fn new(extra: &[&str]) -> anyhow::Result<Self> {
            let tmp = tempfile::tempdir()?;
            // A real account key inside the tempdir. Without this the CLI
            // default resolves to a relative `account.key` in the working
            // directory, which any path reaching `build_client` would read —
            // passing locally only because an untracked one happens to exist.
            let account_key = tmp.path().join("account.key");
            std::fs::write(
                &account_key,
                crate::jws::AccountKey::generate(crate::jws::KeyAlgorithm::Es256)?
                    .to_pkcs8_pem()?,
            )?;

            let mut argv: Vec<String> = vec![
                "acme-client-rs".to_owned(),
                "run".to_owned(),
                "--account-key".to_owned(),
                account_key.display().to_string(),
                "--cert-output".to_owned(),
                tmp.path().join("cert.pem").display().to_string(),
                "--key-output".to_owned(),
                tmp.path().join("key.pem").display().to_string(),
            ];
            argv.extend(extra.iter().map(|s| (*s).to_owned()));
            argv.push("example.com".to_owned());
            let cli = <Cli as clap::Parser>::try_parse_from(argv)?;
            Ok(Self {
                cli,
                registry: crate::cleanup::CleanupRegistry::new(),
                tmp,
            })
        }

        fn cert_path(&self) -> std::path::PathBuf {
            self.tmp.path().join("cert.pem")
        }

        fn run_args(&self) -> Result<&RunArgs> {
            let Commands::Run(args) = &self.cli.command else {
                anyhow::bail!("TestCtx only builds `run` commands");
            };
            Ok(args.as_ref())
        }

        fn ctx(&self) -> Result<RunContext<'_>> {
            let args = self.run_args()?;
            let challenge_type = crate::types::ChallengeType::parse_strict(&args.challenge_type)?;
            RunContext::build(&self.cli, args, challenge_type, &self.registry)
        }
    }

    fn write_cert(path: &std::path::Path, sans: &[&str], days: i64) -> Result<()> {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params =
            CertificateParams::new(sans.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())?;
        // `cert_days_remaining` floors, so add half a day of slack to make the
        // reported whole-day count deterministic.
        params.not_after =
            OffsetDateTime::now_utc() + time::Duration::days(days) + time::Duration::hours(12);
        std::fs::write(path, params.self_signed(&key)?.pem())?;
        Ok(())
    }

    /// Leaf signed by a CA so it carries the Authority Key Identifier that
    /// `compute_cert_id` needs; a plain self-signed cert leaves `ari_cert_id`
    /// silently unset.
    fn leaf_der_with_aki() -> Result<Vec<u8>> {
        use rcgen::{
            BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
        };
        let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut issuer_params = CertificateParams::new(vec!["Test CA".to_owned()])?;
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = Issuer::new(issuer_params, issuer_key);
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut leaf_params = CertificateParams::new(vec!["example.com".to_owned()])?;
        leaf_params.use_authority_key_identifier_extension = true;
        Ok(leaf_params.signed_by(&leaf_key, &issuer)?.der().to_vec())
    }

    fn window(start: &str, end: &str) -> Result<crate::types::RenewalInfo> {
        Ok(serde_json::from_str(&format!(
            r#"{{"suggestedWindow":{{"start":"{start}","end":"{end}"}}}}"#
        ))?)
    }

    async fn days_decision(remaining: i64, threshold: &str) -> Result<Option<RenewalDecision>> {
        let t = TestCtx::new(&["--days", threshold])?;
        write_cert(&t.cert_path(), &["example.com"], remaining)?;
        let ctx = t.ctx()?;
        check_days_threshold(&ctx).await
    }

    #[tokio::test]
    async fn check_renews_when_no_certificate_is_present() -> Result<()> {
        let t = TestCtx::new(&["--days", "30"])?;
        let mut ctx = t.ctx()?;
        assert!(matches!(check(&mut ctx).await?, RenewalDecision::Renew));
        Ok(())
    }

    #[tokio::test]
    async fn days_threshold_skips_only_strictly_above_the_threshold() -> Result<()> {
        assert!(
            matches!(days_decision(60, "30").await?, Some(RenewalDecision::Skip)),
            "60 days left against a 30-day threshold must skip"
        );
        assert!(
            days_decision(10, "30").await?.is_none(),
            "10 days left must proceed to issuance"
        );
        // README documents "skip if MORE than N days remain", so the boundary
        // itself renews.
        assert!(
            days_decision(30, "30").await?.is_none(),
            "exactly N days remaining must renew, not skip"
        );
        Ok(())
    }

    #[tokio::test]
    async fn days_threshold_reads_the_certificate_it_reports_on() -> Result<()> {
        let t = TestCtx::new(&["--days", "30"])?;
        write_cert(&t.cert_path(), &["example.com"], 30)?;
        assert_eq!(
            cert_days_remaining(&t.cert_path()).await?,
            30,
            "fixture must land on the boundary the decision test assumes"
        );
        Ok(())
    }

    async fn mismatch_decision(cert_sans: &[&str]) -> Result<Option<RenewalDecision>> {
        let t = TestCtx::new(&[])?;
        write_cert(&t.cert_path(), cert_sans, 60)?;
        let ctx = t.ctx()?;
        check_domain_mismatch(&ctx).await
    }

    #[tokio::test]
    async fn domain_mismatch_fires_only_when_the_san_set_differs() -> Result<()> {
        assert!(
            mismatch_decision(&["example.com"]).await?.is_none(),
            "an identical SAN set is not a mismatch"
        );
        assert!(
            mismatch_decision(&["other.example"]).await?.is_some(),
            "a changed SAN set is a mismatch"
        );
        Ok(())
    }

    #[tokio::test]
    async fn ari_skips_before_the_selected_instant_and_renews_after() -> Result<()> {
        let der = leaf_der_with_aki()?;

        let t = TestCtx::new(&["--ari"])?;
        let mut ctx = t.ctx()?;
        let future = window("2099-01-01T00:00:00Z", "2099-01-15T00:00:00Z")?;
        assert!(
            matches!(
                apply_ari_info(&mut ctx, &future, &der),
                Some(RenewalDecision::Skip)
            ),
            "a window entirely in the future must skip"
        );
        assert!(
            ctx.ari_cert_id.is_none(),
            "a skipped renewal sets no `replaces` field"
        );
        drop(ctx);

        let t = TestCtx::new(&["--ari"])?;
        let mut ctx = t.ctx()?;
        let past = window("2000-01-01T00:00:00Z", "2000-01-15T00:00:00Z")?;
        assert!(
            apply_ari_info(&mut ctx, &past, &der).is_none(),
            "a window entirely in the past must renew"
        );
        assert!(
            ctx.ari_cert_id.is_some(),
            "renewing links the replaced certificate (RFC 9773 §5)"
        );
        Ok(())
    }

    // With --ari unset, check_ari_window must return before build_client, which
    // would otherwise reach for the ACME directory over the network.
    #[tokio::test]
    async fn check_never_touches_the_network_when_ari_is_off() -> Result<()> {
        let t = TestCtx::new(&["--days", "30"])?;
        write_cert(&t.cert_path(), &["example.com"], 60)?;
        let mut ctx = t.ctx()?;
        assert!(matches!(check(&mut ctx).await?, RenewalDecision::Skip));
        Ok(())
    }

    // ── Operator-facing output of the decision ──────────────────────────
    //
    // `--silent` and `--output-format json` gate every `outln!` on this path.
    // Asserting the captured text is the only way to pin those guards.

    type Sans = std::collections::BTreeSet<String>;

    fn mismatch_output(flags: &[&str]) -> Result<(RenewalDecision, String)> {
        let t = TestCtx::new(flags)?;
        let ctx = t.ctx()?;
        let cert_sans: Sans = ["old.example".to_owned()].into();
        let requested: Sans = ["example.com".to_owned()].into();
        Ok(crate::output::capture(|| {
            decide_domain_mismatch(
                &ctx,
                &cert_sans,
                &requested,
                &["example.com"],
                &["old.example"],
            )
        }))
    }

    #[test]
    fn domain_mismatch_output_honours_silent_and_output_format() -> Result<()> {
        let (decision, out) = mismatch_output(&[])?;
        assert!(matches!(decision, RenewalDecision::Skip));
        assert!(out.contains("Domain mismatch"), "default prints: {out:?}");

        let (_, out) = mismatch_output(&["--silent"])?;
        assert!(out.is_empty(), "--silent prints nothing: {out:?}");

        let (decision, out) = mismatch_output(&["--reissue-on-mismatch"])?;
        assert!(matches!(decision, RenewalDecision::Reissue));
        assert!(out.contains("reissuing"), "{out:?}");

        let (_, out) = mismatch_output(&["--reissue-on-mismatch", "--silent"])?;
        assert!(
            out.is_empty(),
            "--silent prints nothing on reissue: {out:?}"
        );

        let (_, out) = mismatch_output(&["--output-format", "json"])?;
        assert!(out.contains(r#""reason":"domain_mismatch""#), "{out:?}");
        assert!(
            !out.contains("Domain mismatch:"),
            "json mode drops prose: {out:?}"
        );
        Ok(())
    }

    async fn days_output(
        remaining: i64,
        flags: &[&str],
    ) -> Result<(Option<RenewalDecision>, String)> {
        let mut argv: Vec<&str> = vec!["--days", "30"];
        argv.extend_from_slice(flags);
        let t = TestCtx::new(&argv)?;
        write_cert(&t.cert_path(), &["example.com"], remaining)?;
        let ctx = t.ctx()?;
        let (res, out) =
            crate::output::capture_async(|| async { check_days_threshold(&ctx).await }).await;
        Ok((res?, out))
    }

    #[tokio::test]
    async fn days_threshold_output_honours_silent_and_output_format() -> Result<()> {
        let (_, out) = days_output(60, &[]).await?;
        assert!(
            out.contains("days remaining"),
            "skip prints in text: {out:?}"
        );

        let (_, out) = days_output(60, &["--silent"]).await?;
        assert!(out.is_empty(), "skip is silent under --silent: {out:?}");

        let (_, out) = days_output(60, &["--output-format", "json"]).await?;
        assert!(
            out.contains(r#""reason":"days""#),
            "skip emits JSON: {out:?}"
        );

        let (_, out) = days_output(60, &["--output-format", "json", "--silent"]).await?;
        assert!(out.is_empty(), "--silent beats json: {out:?}");

        let (_, out) = days_output(10, &[]).await?;
        assert!(out.contains("renewing"), "renew prints progress: {out:?}");

        // The renew branch is deliberately text-only: `cmd_run` continues to
        // issuance and `finalize` emits the terminal JSON result. Progress JSON
        // here would put two objects on stdout.
        let (_, out) = days_output(10, &["--output-format", "json"]).await?;
        assert!(out.is_empty(), "renew emits no progress JSON: {out:?}");

        let (_, out) = days_output(10, &["--silent"]).await?;
        assert!(out.is_empty(), "renew is silent under --silent: {out:?}");
        Ok(())
    }

    fn ari_output(
        window_bounds: (&str, &str),
        flags: &[&str],
        der: &[u8],
    ) -> Result<(Option<RenewalDecision>, String)> {
        let mut argv: Vec<&str> = vec!["--ari"];
        argv.extend_from_slice(flags);
        let t = TestCtx::new(&argv)?;
        let mut ctx = t.ctx()?;
        let info = window(window_bounds.0, window_bounds.1)?;
        Ok(crate::output::capture(|| {
            apply_ari_info(&mut ctx, &info, der)
        }))
    }

    #[test]
    fn ari_output_honours_silent_and_output_format() -> Result<()> {
        let der = leaf_der_with_aki()?;
        let future = ("2099-01-01T00:00:00Z", "2099-01-15T00:00:00Z");
        let past = ("2000-01-01T00:00:00Z", "2000-01-15T00:00:00Z");

        let (_, out) = ari_output(future, &[], &der)?;
        assert!(
            out.contains("skipping renewal"),
            "skip prints in text: {out:?}"
        );

        let (_, out) = ari_output(future, &["--silent"], &der)?;
        assert!(out.is_empty(), "skip is silent under --silent: {out:?}");

        let (_, out) = ari_output(future, &["--output-format", "json"], &der)?;
        assert!(
            out.contains(r#""reason":"ari""#),
            "skip emits JSON: {out:?}"
        );

        let (_, out) = ari_output(past, &[], &der)?;
        assert!(out.contains("renewing"), "renew prints progress: {out:?}");

        // Same rationale as the days branch: terminal JSON comes from finalize.
        let (_, out) = ari_output(past, &["--output-format", "json"], &der)?;
        assert!(out.is_empty(), "renew emits no progress JSON: {out:?}");

        let (_, out) = ari_output(past, &["--silent"], &der)?;
        assert!(out.is_empty(), "renew is silent under --silent: {out:?}");
        Ok(())
    }

    // ── ARI against a live directory ────────────────────────────────────

    fn write_cert_with_aki(path: &std::path::Path, days: i64) -> Result<()> {
        use rcgen::{
            BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
        };
        let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut issuer_params = CertificateParams::new(vec!["Test CA".to_owned()])?;
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = Issuer::new(issuer_params, issuer_key);

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut leaf_params = CertificateParams::new(vec!["example.com".to_owned()])?;
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.not_after =
            OffsetDateTime::now_utc() + time::Duration::days(days) + time::Duration::hours(12);
        std::fs::write(path, leaf_params.signed_by(&leaf_key, &issuer)?.pem())?;
        Ok(())
    }

    // Deliberately no --days: the ARI decision has to stand on its own, so a
    // mutant that short-circuits the ARI path falls through to `Renew` instead
    // of being masked by the days fallback.
    #[tokio::test]
    async fn ari_skip_requires_the_directory_and_renewal_info_round_trip() -> Result<()> {
        use crate::test_support::{Route, collect_captured, spawn_mock};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let base = format!("http://127.0.0.1:{port}");
        let directory = serde_json::to_vec(&serde_json::json!({
            "newNonce": format!("{base}/n"),
            "newAccount": format!("{base}/a"),
            "newOrder": format!("{base}/o"),
            "revokeCert": format!("{base}/r"),
            "keyChange": format!("{base}/k"),
            "renewalInfo": format!("{base}/renewalInfo"),
        }))?;

        let captured = spawn_mock(
            listener,
            vec![
                Route {
                    method: "GET",
                    path_prefix: "/directory",
                    status_line: "HTTP/1.1 200 OK",
                    extra_headers: vec![("content-type".into(), "application/json".into())],
                    body: directory,
                },
                Route {
                    method: "GET",
                    path_prefix: "/renewalInfo/",
                    status_line: "HTTP/1.1 200 OK",
                    extra_headers: vec![("content-type".into(), "application/json".into())],
                    body: br#"{"suggestedWindow":{"start":"2099-01-01T00:00:00Z","end":"2099-01-15T00:00:00Z"}}"#
                        .to_vec(),
                },
            ],
        );

        let dir_url = format!("{base}/directory");
        let t = TestCtx::new(&["--ari", "--insecure", "--directory", &dir_url])?;
        write_cert_with_aki(&t.cert_path(), 60)?;
        let mut ctx = t.ctx()?;

        assert!(
            matches!(check(&mut ctx).await?, RenewalDecision::Skip),
            "a future ARI window must skip renewal"
        );

        let requests = collect_captured(&captured)?;
        assert!(
            requests.iter().any(|r| r.path.starts_with("/renewalInfo/")),
            "the ARI endpoint must actually be queried: {:?}",
            requests.iter().map(|r| &r.path).collect::<Vec<_>>()
        );
        Ok(())
    }
}

#[cfg(test)]
mod proptests {
    use super::{parse_ari_window, select_renewal_instant};
    use proptest::prelude::*;
    use time::macros::datetime;

    proptest! {
        #[test]
        fn selected_instant_always_lands_inside_the_window(
            span_secs in 1_i64..=(400 * 24 * 3600),
            random in any::<u64>(),
        ) {
            let start = datetime!(2026-01-01 00:00:00 UTC);
            let end = start + time::Duration::seconds(span_secs);
            let inst = select_renewal_instant(start, end, random);
            prop_assert!(inst >= start, "instant {} < start {}", inst, start);
            prop_assert!(inst < end, "instant {} >= end {}", inst, end);
        }

        #[test]
        fn degenerate_windows_collapse_to_start(random in any::<u64>()) {
            let start = datetime!(2026-01-01 00:00:00 UTC);
            prop_assert_eq!(select_renewal_instant(start, start, random), start);
        }

        #[test]
        fn window_parsing_never_panics(start in ".*", end in ".*") {
            let _ = parse_ari_window(&start, &end);
        }
    }
}
