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
use tracing::info;

use crate::account_key::{load_account_key_with_password, resolve_account_key_password};
use crate::cli::{Cli, Commands};
use crate::cli_config::{apply_config, load_config};
use crate::client::AcmeClient;
use crate::handlers::*;

// ── Entry point ─────────────────────────────────────────────────────────────

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
    let (loaded_config, config_mode) = if !matches!(cli.command, Commands::GenerateConfig) {
        match load_config(&cli) {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("Error: {err:#}");
                std::process::exit(1);
            }
        }
    } else {
        (None, false)
    };

    if let Some(ref config) = loaded_config {
        apply_config(&mut cli, &matches, config, config_mode);
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

    let cleanup_registry = cleanup::CleanupRegistry::default();
    let sigint_registry = cleanup_registry.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("Interrupted — running challenge cleanup before exit...");
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
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}

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
                cli.account_key_password.as_deref(),
                cli.account_key_password_file.as_deref(),
            )?;
            cmd_generate_key(
                &cli.account_key,
                *algorithm,
                *force,
                fmt,
                cli.silent,
                pw.as_ref(),
            )
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
                eab_hmac_key.as_deref(),
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
        } => {
            cmd_serve_http01(
                &cli,
                token,
                *port,
                challenge_dir.as_deref(),
                fmt,
                cli.silent,
            )
            .await
        }
        Commands::ShowDns01 { domain, token } => {
            cmd_show_dns01(&cli, domain, token, fmt, cli.silent)
        }
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
                fmt,
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
                key_password.as_deref(),
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
                new_key_password.as_deref(),
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
        Commands::Run {
            domains,
            contact,
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
            cert_key_algorithm,
            profile,
            force,
        } => {
            anyhow::ensure!(
                !domains.is_empty(),
                "at least one domain is required (pass on CLI or set [run].domains in config)"
            );
            cmd_run(
                &cli,
                domains.clone(),
                contact.clone(),
                challenge_type,
                *http_port,
                challenge_dir.as_deref(),
                dns_hook.as_deref(),
                *dns_wait,
                *dns_propagation_concurrency,
                *challenge_timeout,
                cert_output,
                key_output,
                *days,
                key_password.as_deref(),
                key_password_file.as_deref(),
                on_challenge_ready.as_deref(),
                on_cert_issued.as_deref(),
                eab_kid.as_deref(),
                eab_hmac_key.as_deref(),
                *pre_authorize,
                *ari,
                *reissue_on_mismatch,
                *print_cert,
                persist_policy.as_deref(),
                *persist_until,
                *cert_key_algorithm,
                profile.as_deref(),
                *force,
                cleanup_registry,
            )
            .await
        }
    }
}

pub(crate) async fn build_client(cli: &Cli) -> Result<AcmeClient> {
    use secrecy::ExposeSecret;
    let (tls, net) = client::policies_from_cli_flags(cli.insecure, cli.allow_private_network);

    client::validate_directory_url(&cli.directory, tls, net)?;
    let pw = resolve_account_key_password(
        cli.account_key_password.as_deref(),
        cli.account_key_password_file.as_deref(),
    )?;
    let key =
        load_account_key_with_password(&cli.account_key, pw.as_ref().map(|s| s.expose_secret()))?;
    if cli.insecure {
        tracing::warn!("TLS certificate verification is disabled (--insecure)");
    }
    let mut client = AcmeClient::new(
        &cli.directory,
        key,
        cli.insecure,
        cli.connect_timeout,
        cli.allow_private_network,
    )
    .await?;
    if let Some(ref url) = cli.account_url {
        let (tls, net) = client::policies_from_cli_flags(cli.insecure, cli.allow_private_network);

        client::validate_acme_url(url, tls, net)?;
        client.set_account_url(url.clone());
    }
    Ok(client)
}
