//! Full end-to-end issuance/renewal flow (the 'run' subcommand).
//!
//! This is the largest handler — it orchestrates account lookup, ARI-driven
//! renewal decisions, order placement, challenge fulfillment (HTTP-01,
//! DNS-01, DNS-PERSIST-01, TLS-ALPN-01), CSR generation, finalization,
//! and post-issuance hook invocation.
//!
//! The flow is split across four phase modules — see `CODE_REVIEW.md` item 5.
//! Phase extraction is in progress; today `cmd_run` is still monolithic.

mod authorize;
mod finalize;
mod preauth;
mod renewal;

use anyhow::{Context, Result};
use tracing::info;

use crate::cli::{CertKeyAlgorithm, Cli, OutputFormat, RunArgs};
use crate::client::AcmeClient;
use crate::dns_check::DnsChecker;
use crate::types::{ChallengeType, Identifier};
use crate::{build_client, outln};

use super::{check_wildcard_compatible, parse_eab};

/// Shared state for every phase of the run subcommand.
///
/// Built once in `cmd_run` from CLI args and normalized inputs; each phase
/// module borrows it mutably. Mutable fields (`ari_cert_id`, `early_client`)
/// are set by the renewal phase and consumed by later phases.
pub(super) struct RunContext<'a> {
    pub cli: &'a Cli,
    pub challenge_type: ChallengeType,
    pub http_port: u16,
    pub challenge_dir: Option<&'a std::path::Path>,
    pub dns_hook: Option<&'a std::path::Path>,
    pub dns_wait: Option<u64>,
    pub dns_propagation_concurrency: usize,
    pub challenge_timeout: u64,
    pub cert_output: &'a std::path::Path,
    pub key_output: &'a std::path::Path,
    pub days: Option<u32>,
    pub key_password: Option<&'a str>,
    pub key_password_file: Option<&'a std::path::Path>,
    pub on_challenge_ready: Option<&'a std::path::Path>,
    pub on_cert_issued: Option<&'a std::path::Path>,
    pub eab_kid: Option<&'a str>,
    pub eab_hmac_key: Option<&'a str>,
    pub pre_authorize: bool,
    pub ari: bool,
    pub reissue_on_mismatch: bool,
    pub print_cert: bool,
    pub persist_policy: Option<&'a str>,
    pub persist_until: Option<u64>,
    pub cert_key_alg: CertKeyAlgorithm,
    pub profile: Option<&'a str>,
    pub force: bool,
    pub contact: Option<String>,
    pub cleanup_registry: &'a crate::cleanup::CleanupRegistry,

    pub domains: Vec<String>,
    pub dns_checker: std::sync::Arc<DnsChecker>,
    pub json: bool,
    pub silent: bool,

    pub ari_cert_id: Option<String>,
    pub early_client: Option<AcmeClient>,
}

// ── Full automated flow ─────────────────────────────────────────────────────

pub(crate) async fn cmd_run(
    cli: &Cli,
    args: &RunArgs,
    cleanup_registry: &crate::cleanup::CleanupRegistry,
) -> Result<()> {
    let challenge_type = ChallengeType::parse_strict(&args.challenge_type)?;
    check_wildcard_compatible(&args.domains, &challenge_type)?;

    crate::hook_check::validate_all_hooks(
        &[
            ("dns_hook", args.dns_hook.as_deref()),
            ("on_challenge_ready", args.on_challenge_ready.as_deref()),
            ("on_cert_issued", args.on_cert_issued.as_deref()),
        ],
        cli.unsafe_hooks,
    )?;

    let domains: Vec<String> = args
        .domains
        .iter()
        .map(|d| Identifier::from_str_auto(d).map(|id| id.value_str().into_owned()))
        .collect::<Result<Vec<_>>>()?;

    let dns_checker = std::sync::Arc::new(
        DnsChecker::new(
            cli.dns_check_mode,
            if cli.dns_check_dnssec {
                crate::dns_check::Dnssec::On
            } else {
                crate::dns_check::Dnssec::Off
            },
        )
            .context("failed to initialize DNS resolver for dns-01 propagation checks")?,
    );

    let json = cli.output_format == OutputFormat::Json;
    let silent = cli.silent;

    let mut ctx = RunContext {
        cli,
        challenge_type,
        http_port: args.http_port,
        challenge_dir: args.challenge_dir.as_deref(),
        dns_hook: args.dns_hook.as_deref(),
        dns_wait: args.dns_wait,
        dns_propagation_concurrency: args.dns_propagation_concurrency,
        challenge_timeout: args.challenge_timeout,
        cert_output: &args.cert_output,
        key_output: &args.key_output,
        days: args.days,
        key_password: args.key_password.as_deref(),
        key_password_file: args.key_password_file.as_deref(),
        on_challenge_ready: args.on_challenge_ready.as_deref(),
        on_cert_issued: args.on_cert_issued.as_deref(),
        eab_kid: args.eab_kid.as_deref(),
        eab_hmac_key: args.eab_hmac_key.as_deref(),
        pre_authorize: args.pre_authorize,
        ari: args.ari,
        reissue_on_mismatch: args.reissue_on_mismatch,
        print_cert: args.print_cert,
        persist_policy: args.persist_policy.as_deref(),
        persist_until: args.persist_until,
        cert_key_alg: args.cert_key_algorithm,
        profile: args.profile.as_deref(),
        force: args.force,
        contact: args.contact.clone(),
        cleanup_registry,
        domains,
        dns_checker,
        json,
        silent,
        ari_cert_id: None,
        early_client: None,
    };

    match renewal::check(&mut ctx).await? {
        renewal::RenewalDecision::Skip => return Ok(()),
        renewal::RenewalDecision::Reissue | renewal::RenewalDecision::Renew => {}
    }

    // ── 1. Account ──────────────────────────────────────────────────────
    info!("Step 1: Creating / looking up account");
    let mut client = match ctx.early_client.take() {
        Some(c) => c,
        None => build_client(ctx.cli).await?,
    };
    let contact_list = ctx.contact.take().map(|c| vec![format!("mailto:{c}")]);
    let eab = parse_eab(ctx.eab_kid, ctx.eab_hmac_key)?;
    let eab_ref = eab.as_ref().map(|(kid, key)| {
        use secrecy::ExposeSecret;
        (kid.as_str(), key.expose_secret().as_slice())
    });
    let account = client.create_account(contact_list, true, eab_ref).await?;
    if !ctx.json && !ctx.silent {
        outln!("Account status: {}", account.status);
    }

    if ctx.pre_authorize {
        preauth::preauthorize(&mut ctx, &mut client).await?;
    }

    // ── 2b. New order ───────────────────────────────────────────────────
    info!(
        "Step {}: Placing order",
        if ctx.pre_authorize { 3 } else { 2 }
    );
    let profile_owned = ctx.profile.map(String::from);
    // Validate profile against advertised list (draft-ietf-acme-profiles-01 §4)
    if let Some(ref p) = profile_owned
        && let Some(available) = client.available_profiles()
        && !available.contains_key(p)
    {
        tracing::warn!(
            "Profile \"{p}\" is not advertised by the server (available: {})",
            available.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    check_wildcard_compatible(&ctx.domains, &ctx.challenge_type)?;
    let ids: Vec<Identifier> = ctx
        .domains
        .iter()
        .map(|d| Identifier::from_str_auto(d))
        .collect::<Result<Vec<_>>>()?;
    let (order, order_url) = if let Some(cert_id) = ctx.ari_cert_id.take() {
        info!("Using ARI replaces field (certID: {cert_id})");
        client
            .new_order_replacing(ids, cert_id, profile_owned)
            .await?
    } else {
        client.new_order(ids, profile_owned).await?
    };
    if !ctx.json && !ctx.silent {
        outln!("Order URL:  {order_url}");
        if let Some(ref p) = order.profile {
            outln!("Profile:    {p}");
        }
        outln!("Order status: {}", order.status);
    }

    authorize::authorize(&mut ctx, &mut client, &order).await?;

    finalize::finalize(&mut ctx, &mut client, order, &order_url).await?;

    Ok(())
}
