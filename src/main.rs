//! ACME client (RFC 8555) with ARI renewal (RFC 9773), IP identifiers
//! (RFC 8738), and the DNS-PERSIST-01 / profiles drafts. Single hardened
//! binary; see README.md for the full security posture.
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
mod run_dispatch;
mod types;

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches};
use tracing::{error, info};

use crate::account_key::{load_account_key_with_password, resolve_account_key_password};
use crate::cli::{Cli, Commands};
use crate::cli_config::{apply_config, load_config};
use crate::client::AcmeClient;
use crate::handlers::{cmd_run, cmd_show_config};

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

    // Keep the parsed `ArgMatches` alive: `apply_config` (cli_config.rs) and
    // `show-config` need `matches.value_source(...)` to distinguish CLI / env /
    // default provenance. Collapsing this to `Cli::parse()` would discard that
    // source metadata and silently break config-mode precedence.
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
    match &cli.command {
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
        Commands::Run(args) => {
            anyhow::ensure!(
                !args.domains.is_empty(),
                "at least one domain is required (pass on CLI or set [run].domains in config)"
            );
            cmd_run(&cli, args.as_ref(), cleanup_registry).await
        }
        command @ (Commands::GenerateConfig
        | Commands::GenerateKey { .. }
        | Commands::Account { .. }
        | Commands::Order { .. }
        | Commands::GetAuthz { .. }
        | Commands::RespondChallenge { .. }
        | Commands::ServeHttp01 { .. }
        | Commands::ShowDns01 { .. }
        | Commands::ShowDnsPersist01 { .. }
        | Commands::Finalize { .. }
        | Commands::PollOrder { .. }
        | Commands::DownloadCert { .. }
        | Commands::DeactivateAccount
        | Commands::KeyRollover { .. }
        | Commands::RevokeCert { .. }
        | Commands::RenewalInfo { .. }
        | Commands::ListProfiles
        | Commands::PreAuthorize { .. }) => {
            run_dispatch::handle_simple_command(&cli, command).await
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
        let parsed: url::Url = url.parse().context("--account-url is not a valid URL")?;
        client.set_account_url(parsed);
    }
    Ok(client)
}
