#![forbid(unsafe_code)]

mod account_key;
mod cert_info;
mod challenge;
mod cleanup;
mod cli;
mod cli_config;
mod client;
mod config;
mod csr;
mod defaults;
mod dns_check;
mod fs_secure;
mod handlers;
mod hook_check;
mod jws;
#[macro_use]
mod output;
mod types;

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches};
use tracing::{error, info};

use crate::account_key::{load_account_key_with_password, resolve_account_key_password};
use crate::cli::{Cli, Commands};
use crate::cli_config::{apply_config, load_config};
use crate::client::AcmeClient;
use crate::handlers::{
    cmd_account, cmd_deactivate, cmd_download_cert, cmd_finalize, cmd_generate_config,
    cmd_generate_key, cmd_get_authz, cmd_key_rollover, cmd_list_profiles, cmd_order,
    cmd_poll_order, cmd_pre_authorize, cmd_renewal_info, cmd_respond_challenge, cmd_revoke,
    cmd_run, cmd_serve_http01, cmd_show_config, cmd_show_dns_persist01, cmd_show_dns01,
};

// ── Entry point ─────────────────────────────────────────────────────────────

// NOT cancel-safe: tokio entry point. Spawns the full dispatcher; abort
// during run() inherits the per-command NOT-cancel-safe contracts.
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    // Load config (skip for generate-config)
    let (loaded_config, config_mode) = if matches!(cli.command, Commands::GenerateConfig) {
        (None, false)
    } else {
        match load_config(&cli) {
            Ok(pair) => pair,
            Err(err) => {
                error!("{err:#}");
                std::process::exit(1);
            }
        }
    };

    if let Some(ref config) = loaded_config {
        if let Err(err) = apply_config(&mut cli, &matches, config, config_mode) {
            error!("{err:#}");
            std::process::exit(1);
        }
    } else if config_mode {
        // config_mode was requested but the env/cli pointed nowhere — should not happen
        // (load_config already errors), but guard anyway.
    } else {
        // No config file: CLI > env > defaults — clap already handled this.
        // Just warn if the default config file exists in CWD.
        if !matches!(cli.command, Commands::GenerateConfig) && config::Config::default_exists() {
            info!(
                "Found {} in current directory but no --config or ACME_CONFIG was specified. \
                 Use --config {} or set ACME_CONFIG to load it.",
                config::DEFAULT_CONFIG_FILE,
                config::DEFAULT_CONFIG_FILE,
            );
        }
    }

    output::set_silent(cli.silent);

    let cleanup_registry = cleanup::CleanupRegistry::new();
    let sigint_registry = cleanup_registry.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            error!("Interrupted — running challenge cleanup before exit...");
            sigint_registry.run_all_sync();
            std::process::exit(130);
        }
    });

    if let Err(err) = run(
        cli,
        loaded_config.as_ref(),
        &matches,
        config_mode,
        &cleanup_registry,
    )
    .await
    {
        error!("{err:#}");
        std::process::exit(1);
    }
}

// NOT cancel-safe: dispatcher to every cmd_*; inherits per-command contract.
async fn run(
    cli: Cli,
    loaded_config: Option<&config::Config>,
    matches: &clap::ArgMatches,
    config_mode: bool,
    cleanup_registry: &cleanup::CleanupRegistry,
) -> Result<()> {
    let fmt = cli.output_format;
    match &cli.command {
        Commands::GenerateConfig => cmd_generate_config(cli.silent),
        Commands::ShowConfig {
            verbose,
            show_secrets,
        } => cmd_show_config(
            &cli,
            loaded_config,
            matches,
            *verbose,
            *show_secrets,
            config_mode,
        ),
        Commands::GenerateKey { algorithm, force } => {
            let pw = resolve_account_key_password(
                cli.account_key_password
                    .as_ref()
                    .map(secrecy::ExposeSecret::expose_secret),
                cli.account_key_password_file.as_deref(),
            )
            .await?;
            cmd_generate_key(
                &cli.account_key,
                *algorithm,
                *force,
                fmt,
                cli.silent,
                pw.as_ref(),
            )
            .await
        }
        Commands::Account {
            contact,
            agree_tos,
            eab_kid,
            eab_hmac_key,
        } => {
            cmd_account(
                &cli,
                contact.clone(),
                *agree_tos,
                eab_kid.as_deref(),
                eab_hmac_key.clone(),
            )
            .await
        }
        Commands::Order { domains, profile } => {
            cmd_order(&cli, domains.clone(), profile.clone()).await
        }
        Commands::GetAuthz { url } => cmd_get_authz(&cli, url).await,
        Commands::RespondChallenge { url } => cmd_respond_challenge(&cli, url).await,
        Commands::ServeHttp01 {
            token,
            port,
            challenge_dir,
        } => cmd_serve_http01(&cli, token, *port, challenge_dir.as_deref()).await,
        Commands::ShowDns01 { domain, token } => cmd_show_dns01(&cli, domain, token).await,
        Commands::ShowDnsPersist01 {
            domain,
            issuer_domain_name,
            persist_policy,
            persist_until,
        } => {
            cmd_show_dns_persist01(
                &cli,
                domain,
                issuer_domain_name,
                persist_policy.as_deref(),
                *persist_until,
            )
            .await
        }
        Commands::Finalize {
            finalize_url,
            cert_key_algorithm,
            key_output,
            key_password,
            key_password_file,
            force,
            domains,
        } => {
            cmd_finalize(
                &cli,
                finalize_url,
                domains,
                *cert_key_algorithm,
                key_output,
                key_password.clone(),
                key_password_file.as_deref(),
                *force,
            )
            .await
        }
        Commands::PollOrder { url } => cmd_poll_order(&cli, url).await,
        Commands::DownloadCert { url, output } => cmd_download_cert(&cli, url, output).await,
        Commands::DeactivateAccount => cmd_deactivate(&cli).await,
        Commands::KeyRollover {
            new_key,
            new_key_password,
            new_key_password_file,
        } => {
            cmd_key_rollover(
                &cli,
                new_key,
                new_key_password.clone(),
                new_key_password_file.as_deref(),
            )
            .await
        }
        Commands::RevokeCert { cert_path, reason } => cmd_revoke(&cli, cert_path, *reason).await,
        Commands::RenewalInfo { cert_path } => cmd_renewal_info(&cli, cert_path).await,
        Commands::ListProfiles => cmd_list_profiles(&cli).await,
        Commands::PreAuthorize {
            domain,
            challenge_type,
        } => cmd_pre_authorize(&cli, domain, challenge_type).await,
        Commands::Run(args) => {
            anyhow::ensure!(
                !args.domains.is_empty(),
                "at least one domain is required (pass on CLI or set [run].domains in config)"
            );
            cmd_run(&cli, args, cleanup_registry).await
        }
    }
}

// cancel-safe: reads account key from disk + constructs AcmeClient. Drop
// leaves no external state — the directory has not yet been fetched.
pub(crate) async fn build_client(cli: &Cli) -> Result<AcmeClient> {
    let (tls, net) = client::policies_from_cli_flags(client::NetFlags {
        insecure: cli.insecure,
        allow_private_network: cli.allow_private_network,
    });

    client::validate_directory_url(&cli.directory, tls, net)?;
    let pw = resolve_account_key_password(
        cli.account_key_password
            .as_ref()
            .map(secrecy::ExposeSecret::expose_secret),
        cli.account_key_password_file.as_deref(),
    )
    .await?;
    let key = load_account_key_with_password(
        &cli.account_key,
        pw.as_ref().map(secrecy::ExposeSecret::expose_secret),
    )
    .await?;
    if cli.insecure {
        tracing::warn!("TLS certificate verification is disabled (--insecure)");
    }
    let mut client = AcmeClient::new(&cli.directory, key, tls, cli.connect_timeout, net).await?;
    if let Some(ref url) = cli.account_url {
        client::validate_acme_url(url, tls, net)?;
        client.set_account_url(url.as_str());
    }
    Ok(client)
}
