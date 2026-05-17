//! Full end-to-end issuance/renewal flow (the 'run' subcommand).
//!
//! This is the largest handler — it orchestrates account lookup, ARI-driven
//! renewal decisions, order placement, challenge fulfillment (HTTP-01,
//! DNS-01, DNS-PERSIST-01, TLS-ALPN-01), CSR generation, finalization,
//! and post-issuance hook invocation.
//!
//! The flow is split across four phase modules — see CODE_REVIEW.md item 5.
//! Phase extraction is in progress; today `cmd_run` is still monolithic.

mod authorization;
mod finalize;
mod preauth;
mod renewal;

use anyhow::{Context, Result};
use tracing::info;

use crate::cli::{CertKeyAlgorithm, Cli, OutputFormat};
use crate::client::AcmeClient;
use crate::csr::{encrypt_private_key, generate_csr};
use crate::dns_check::DnsChecker;
use crate::types::{Identifier, OrderStatus};
use crate::{build_client, outln};

use super::{check_wildcard_compatible, parse_eab, run_hook};

/// Shared state for every phase of the run subcommand.
///
/// Built once in `cmd_run` from CLI args and normalized inputs; each phase
/// module borrows it mutably. Mutable fields (`ari_cert_id`, `early_client`)
/// are set by the renewal phase and consumed by later phases.
pub(super) struct RunContext<'a> {
    pub cli: &'a Cli,
    pub challenge_type: &'a str,
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn cmd_run(
    cli: &Cli,
    domains: Vec<String>,
    contact: Option<String>,
    challenge_type: &str,
    http_port: u16,
    challenge_dir: Option<&std::path::Path>,
    dns_hook: Option<&std::path::Path>,
    dns_wait: Option<u64>,
    dns_propagation_concurrency: usize,
    challenge_timeout: u64,
    cert_output: &std::path::Path,
    key_output: &std::path::Path,
    days: Option<u32>,
    key_password: Option<&str>,
    key_password_file: Option<&std::path::Path>,
    on_challenge_ready: Option<&std::path::Path>,
    on_cert_issued: Option<&std::path::Path>,
    eab_kid: Option<&str>,
    eab_hmac_key: Option<&str>,
    pre_authorize: bool,
    ari: bool,
    reissue_on_mismatch: bool,
    print_cert: bool,
    persist_policy: Option<&str>,
    persist_until: Option<u64>,
    cert_key_alg: CertKeyAlgorithm,
    profile: Option<&str>,
    force: bool,
    cleanup_registry: &crate::cleanup::CleanupRegistry,
) -> Result<()> {
    check_wildcard_compatible(&domains, challenge_type)?;

    crate::hook_check::validate_all_hooks(
        &[
            ("dns_hook", dns_hook),
            ("on_challenge_ready", on_challenge_ready),
            ("on_cert_issued", on_cert_issued),
        ],
        cli.unsafe_hooks,
    )?;

    let domains: Vec<String> = domains
        .iter()
        .map(|d| Identifier::from_str_auto(d).map(|id| id.value))
        .collect::<Result<Vec<_>>>()?;

    let dns_checker = std::sync::Arc::new(
        DnsChecker::new(cli.dns_check_mode, cli.dns_check_dnssec)
            .context("failed to initialize DNS resolver for dns-01 propagation checks")?,
    );

    let json = cli.output_format == OutputFormat::Json;
    let silent = cli.silent;

    let mut ctx = RunContext {
        cli,
        challenge_type,
        http_port,
        challenge_dir,
        dns_hook,
        dns_wait,
        dns_propagation_concurrency,
        challenge_timeout,
        cert_output,
        key_output,
        days,
        key_password,
        key_password_file,
        on_challenge_ready,
        on_cert_issued,
        eab_kid,
        eab_hmac_key,
        pre_authorize,
        ari,
        reissue_on_mismatch,
        print_cert,
        persist_policy,
        persist_until,
        cert_key_alg,
        profile,
        force,
        contact,
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

    cmd_run_after_renewal(ctx).await
}

#[allow(clippy::too_many_lines)]
async fn cmd_run_after_renewal(mut ctx: RunContext<'_>) -> Result<()> {
    // Re-bind ctx fields as locals so the inlined post-renewal body
    // (extracted in subsequent commits) keeps reading them by their
    // original names. This is a transitional bridge — phases 3-5 of
    // the refactor will replace these with phase fn calls that take
    // `&mut RunContext` directly.
    let cli = ctx.cli;
    let challenge_type = ctx.challenge_type;
    let _http_port = ctx.http_port;
    let _challenge_dir = ctx.challenge_dir;
    let _dns_hook = ctx.dns_hook;
    let _dns_wait = ctx.dns_wait;
    let _dns_propagation_concurrency = ctx.dns_propagation_concurrency;
    let _challenge_timeout = ctx.challenge_timeout;
    let cert_output = ctx.cert_output;
    let key_output = ctx.key_output;
    let key_password = ctx.key_password;
    let key_password_file = ctx.key_password_file;
    let _on_challenge_ready = ctx.on_challenge_ready;
    let on_cert_issued = ctx.on_cert_issued;
    let eab_kid = ctx.eab_kid;
    let eab_hmac_key = ctx.eab_hmac_key;
    let pre_authorize = ctx.pre_authorize;
    let print_cert = ctx.print_cert;
    let _persist_policy = ctx.persist_policy;
    let _persist_until = ctx.persist_until;
    let cert_key_alg = ctx.cert_key_alg;
    let profile = ctx.profile;
    let force = ctx.force;
    let contact = ctx.contact.take();
    let _cleanup_registry = ctx.cleanup_registry;
    let domains: Vec<String> = ctx.domains.clone();
    let _dns_checker = ctx.dns_checker.clone();
    let json = ctx.json;
    let silent = ctx.silent;
    let ari_cert_id = ctx.ari_cert_id.clone();
    let mut early_client = ctx.early_client.take();

    // ── 1. Account ──────────────────────────────────────────────────────
    info!("Step 1: Creating / looking up account");
    let mut client = match early_client.take() {
        Some(c) => c,
        None => build_client(cli).await?,
    };
    let contact_list = contact.map(|c| vec![format!("mailto:{c}")]);
    let eab = parse_eab(eab_kid, eab_hmac_key)?;
    let eab_ref = eab.as_ref().map(|(kid, key)| {
        use secrecy::ExposeSecret;
        (kid.as_str(), key.expose_secret().as_slice())
    });
    let account = client.create_account(contact_list, true, eab_ref).await?;
    if !json && !silent {
        outln!("Account status: {}", account.status);
    }

    if ctx.pre_authorize {
        preauth::preauthorize(&mut ctx, &mut client).await?;
    }

    // ── 2b. New order ───────────────────────────────────────────────────
    info!("Step {}: Placing order", if pre_authorize { 3 } else { 2 });
    let profile_owned = profile.map(String::from);
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
    check_wildcard_compatible(&domains, challenge_type)?;
    let ids: Vec<Identifier> = domains
        .iter()
        .map(Identifier::from_str_auto)
        .collect::<Result<Vec<_>>>()?;
    let (order, order_url) = if let Some(ref cert_id) = ari_cert_id {
        info!("Using ARI replaces field (certID: {cert_id})");
        client
            .new_order_replacing(ids, cert_id.clone(), profile_owned)
            .await?
    } else {
        client.new_order(ids, profile_owned).await?
    };
    if !json && !silent {
        outln!("Order URL:  {order_url}");
        if let Some(ref p) = order.profile {
            outln!("Profile:    {p}");
        }
        outln!("Order status: {}", order.status);
    }

    authorization::authorize(&mut ctx, &mut client, &order).await?;

    // ── Finalize ────────────────────────────────────────────────────────
    info!(
        "Step {}: Finalizing order",
        if pre_authorize { 5 } else { 4 }
    );
    let (csr_der, key_pem) = generate_csr(&domains, cert_key_alg)?;
    let finalize_url = order.finalize.clone();
    let mut order = client.finalize_order(&finalize_url, &csr_der).await?;
    if !json && !silent {
        outln!("Order status: {}", order.status);
    }

    // ── Poll order ──────────────────────────────────────────────────────
    info!(
        "Step {}: Waiting for certificate issuance",
        if pre_authorize { 6 } else { 5 }
    );
    while order.status != OrderStatus::Valid {
        if order.status == OrderStatus::Invalid {
            anyhow::bail!("order became invalid");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        order = client.poll_order(&order_url).await?;
        if !json && !silent {
            outln!("  Order status: {}", order.status);
        }
    }

    // ── Download certificate ────────────────────────────────────────────
    info!(
        "Step {}: Downloading certificate",
        if pre_authorize { 7 } else { 6 }
    );
    let cert_url = order
        .certificate
        .context("order is valid but has no certificate URL")?;
    let cert = client.download_certificate(&cert_url).await?;

    let password: Option<secrecy::SecretString> = if let Some(pw) = key_password {
        Some(secrecy::SecretString::from(pw.to_string()))
    } else if let Some(path) = key_password_file {
        crate::fs_secure::warn_if_world_readable(path, "password");
        let content = zeroize::Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read password file: {}", path.display()))?,
        );
        let pw: Option<String> = content
            .lines()
            .next()
            .map(|line| line.trim().to_string())
            .filter(|pw: &String| !pw.is_empty());
        pw.map(secrecy::SecretString::from)
    } else {
        None
    };

    let key_encrypted = password.is_some();
    if let Some(ref password) = password {
        use secrecy::ExposeSecret;
        let encrypted = encrypt_private_key(&key_pem, password.expose_secret())?;
        crate::fs_secure::write_secret_file(key_output, encrypted.as_bytes(), force)
            .with_context(|| format!("failed to write private key to {}", key_output.display()))?;
        if !json && !silent {
            outln!("Private key saved to {} (encrypted)", key_output.display());
        }
    } else {
        crate::fs_secure::write_secret_file(key_output, key_pem.as_bytes(), force)
            .with_context(|| format!("failed to write private key to {}", key_output.display()))?;
        if !json && !silent {
            outln!("Private key saved to {}", key_output.display());
        }
    }

    std::fs::write(cert_output, &cert)
        .with_context(|| format!("failed to write certificate to {}", cert_output.display()))?;
    if json && !silent {
        outln!(
            "{}",
            serde_json::json!({
                "command": "run",
                "action": "issued",
                "domains": domains,
                "cert_path": cert_output.display().to_string(),
                "key_path": key_output.display().to_string(),
                "key_encrypted": key_encrypted,
                "profile": profile,
            })
        );
    } else if !silent {
        outln!("Certificate saved to {}", cert_output.display());
        if print_cert {
            outln!("{cert}");
        }
    }

    if let Some(script) = on_cert_issued {
        let domains_joined = domains.join(",");
        run_hook(
            script,
            &[
                ("ACME_DOMAINS", &domains_joined),
                ("ACME_CERT_PATH", &cert_output.display().to_string()),
                ("ACME_KEY_PATH", &key_output.display().to_string()),
                (
                    "ACME_KEY_ENCRYPTED",
                    if key_encrypted { "true" } else { "false" },
                ),
            ],
        )?;
    }

    Ok(())
}
