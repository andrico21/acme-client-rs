//! Full end-to-end issuance/renewal flow (the 'run' subcommand).
//!
//! This is the largest handler — it orchestrates account lookup, ARI-driven
//! renewal decisions, order placement, challenge fulfillment (HTTP-01,
//! DNS-01, DNS-PERSIST-01, TLS-ALPN-01), CSR generation, finalization,
//! and post-issuance hook invocation.
//!
//! `cmd_run` is a thin dispatcher: preflight → context build → renewal
//! check → account → optional preauth → order → authorize → finalize.
//! Each phase lives in a sibling module and borrows the shared `RunContext`.

mod account_step;
mod authorize;
mod finalize;
mod order_step;
mod preauth;
mod preflight;
mod renewal;

use anyhow::{Context, Result};

use crate::cli::{CertKeyAlgorithm, Cli, OutputFormat, RunArgs};
use crate::client::AcmeClient;
use crate::dns_check::DnsChecker;
use crate::types::{ChallengeType, Identifier};

use super::check_wildcard_compatible;

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
    pub reuse_key: Option<&'a std::path::Path>,
    pub days: Option<u32>,
    pub key_password: Option<secrecy::SecretString>,
    pub key_password_file: Option<&'a std::path::Path>,
    pub on_challenge_ready: Option<&'a std::path::Path>,
    pub on_cert_issued: Option<&'a std::path::Path>,
    pub eab_kid: Option<&'a str>,
    pub eab_hmac_key: Option<secrecy::SecretString>,
    pub pre_authorize: bool,
    pub ari: bool,
    pub reissue_on_mismatch: bool,
    pub print_cert: bool,
    pub persist_policy: Option<&'a str>,
    pub persist_until: Option<u64>,
    pub cert_key_alg: CertKeyAlgorithm,
    pub profile: Option<&'a str>,
    pub force: bool,
    pub contact: Option<&'a str>,
    pub cleanup_registry: &'a crate::cleanup::CleanupRegistry,

    pub domains: Vec<String>,
    pub dns_checker: std::sync::Arc<DnsChecker>,
    pub json: bool,
    pub silent: bool,

    pub ari_cert_id: Option<String>,
    pub early_client: Option<AcmeClient>,
}

impl<'a> RunContext<'a> {
    /// Build the shared run-flow context from CLI inputs.
    ///
    /// Sync (no I/O beyond DNS-resolver construction). The caller must have
    /// already parsed `challenge_type` and run preflight validation /
    /// auto-generate-key side effects.
    pub(super) fn build(
        cli: &'a Cli,
        args: &'a RunArgs,
        challenge_type: ChallengeType,
        cleanup_registry: &'a crate::cleanup::CleanupRegistry,
    ) -> Result<Self> {
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

        Ok(RunContext {
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
            reuse_key: args.reuse_key.as_deref(),
            days: args.days,
            key_password: args
                .key_password
                .as_ref()
                .map(|s| secrecy::SecretString::from(s.clone())),
            key_password_file: args.key_password_file.as_deref(),
            on_challenge_ready: args.on_challenge_ready.as_deref(),
            on_cert_issued: args.on_cert_issued.as_deref(),
            eab_kid: args.eab_kid.as_deref(),
            eab_hmac_key: args
                .eab_hmac_key
                .as_ref()
                .map(|s| secrecy::SecretString::from(s.clone())),
            pre_authorize: args.pre_authorize,
            ari: args.ari,
            reissue_on_mismatch: args.reissue_on_mismatch,
            print_cert: args.print_cert,
            persist_policy: args.persist_policy.as_deref(),
            persist_until: args.persist_until,
            cert_key_alg: args.cert_key_algorithm,
            profile: args.profile.as_deref(),
            force: args.force,
            contact: args.contact.as_deref(),
            cleanup_registry,
            domains,
            dns_checker,
            json,
            silent,
            ari_cert_id: None,
            early_client: None,
        })
    }
}

// ── Full automated flow ─────────────────────────────────────────────────────

// NOT cancel-safe: top-level end-to-end flow. Inherits NOT-cancel-safe
// contract from authorize, finalize, and hook calls. CleanupRegistry runs
// on Drop to best-effort rollback (challenge files, DNS records, server
// task) but the issued certificate (if finalize completed) is lost.
pub(crate) async fn cmd_run(
    cli: &Cli,
    args: &RunArgs,
    cleanup_registry: &crate::cleanup::CleanupRegistry,
) -> Result<()> {
    let challenge_type = ChallengeType::parse_strict(&args.challenge_type)?;
    // Wildcard / challenge-type compatibility runs BEFORE preflight so that
    // wildcard rejection happens before any side effect (account-key gen).
    check_wildcard_compatible(&args.domains, &challenge_type)?;

    preflight::run(cli, args).await?;

    let mut ctx = RunContext::build(cli, args, challenge_type, cleanup_registry)?;

    match renewal::check(&mut ctx).await? {
        renewal::RenewalDecision::Skip => return Ok(()),
        renewal::RenewalDecision::Reissue | renewal::RenewalDecision::Renew => {}
    }

    let mut client = account_step::create_or_lookup(&mut ctx).await?;

    if ctx.pre_authorize {
        preauth::preauthorize(&mut ctx, &mut client).await?;
    }

    let (order, order_url) = order_step::place(&mut ctx, &mut client).await?;

    authorize::authorize(&mut ctx, &mut client, &order).await?;

    finalize::finalize(&mut ctx, &mut client, order, &order_url).await?;

    Ok(())
}
