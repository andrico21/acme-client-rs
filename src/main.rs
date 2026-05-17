#![forbid(unsafe_code)]

mod challenge;
mod cleanup;
mod cli;
mod client;
mod config;
mod dns_check;
mod fs_secure;
mod handlers;
mod hook_check;
mod jws;
#[macro_use]
mod output;
mod types;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches};
use tracing::info;

use crate::cli::{CertKeyAlgorithm, Cli, Commands, OutputFormat};
use crate::client::AcmeClient;
use crate::dns_check::DnsCheckMode;
use crate::handlers::*;
use crate::jws::AccountKey;

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

/// Load config file if requested. Returns `(config, config_mode)`.
///
/// `config_mode = true` means the user explicitly asked for a config file
/// (via `--config` CLI flag or `ACME_CONFIG` env var) and env vars should be
/// ignored for most fields.
fn load_config(cli: &Cli) -> Result<(Option<config::Config>, bool)> {
    if let Some(ref path) = cli.config {
        fs_secure::warn_if_world_readable(path, "config");
        Ok((Some(config::Config::load(path)?), true))
    } else {
        Ok((None, false))
    }
}

fn apply_config(
    cli: &mut Cli,
    matches: &clap::ArgMatches,
    config: &config::Config,
    config_mode: bool,
) {
    use clap::parser::ValueSource;

    let cfg = &config.global;

    // Helper: in config mode, only CLI overrides config. Env vars are ignored
    // (except for allowed secrets — handled separately).
    // Without config mode, config merges under both env and defaults.
    let should_apply_config = |source: Option<ValueSource>| -> bool {
        match source {
            Some(ValueSource::CommandLine) => false, // CLI always wins
            Some(ValueSource::EnvVariable) if config_mode => true, // config overrides env in config mode
            Some(ValueSource::EnvVariable) => true, // config also overrides env without config mode
            Some(ValueSource::DefaultValue) => true, // config overrides defaults
            _ => true,
        }
    };

    // In config mode, strip env values for global fields that are NOT in the
    // allowed-from-env list. The "allowed from env in config mode" set is:
    //   insecure (ACME_INSECURE)
    // All others (directory, account_key, account_url, output_format,
    // connect_timeout) are config-only when config_mode is true.
    if config_mode {
        // For fields where clap resolved an env value, warn at debug level
        // and let the config value (or default) take over.
        for (id, env_name) in [
            ("directory", "ACME_DIRECTORY_URL"),
            ("account_key", "ACME_ACCOUNT_KEY_FILE"),
            ("account_url", "ACME_ACCOUNT_URL"),
            ("output_format", "ACME_OUTPUT_FORMAT"),
            ("connect_timeout", "ACME_CONNECT_TIMEOUT"),
        ] {
            if matches.value_source(id) == Some(ValueSource::EnvVariable) {
                tracing::debug!(
                    "Config file mode: ignoring {env_name} env var (use --config values or pass --{} on CLI)",
                    id.replace('_', "-"),
                );
            }
        }
    }

    // Global: directory
    if should_apply_config(matches.value_source("directory")) {
        if let Some(ref v) = cfg.directory {
            cli.directory = v.clone();
        } else if config_mode && matches.value_source("directory") == Some(ValueSource::EnvVariable)
        {
            // Reset to default — env var is not allowed in config mode
            cli.directory = "https://localhost:14000/dir".to_string();
        }
    }

    // Global: account_key
    if should_apply_config(matches.value_source("account_key")) {
        if let Some(ref v) = cfg.account_key {
            cli.account_key = v.clone();
        } else if config_mode
            && matches.value_source("account_key") == Some(ValueSource::EnvVariable)
        {
            cli.account_key = PathBuf::from("account.key");
        }
    }

    // Global: account_url
    if should_apply_config(matches.value_source("account_url")) {
        if let Some(ref v) = cfg.account_url {
            cli.account_url = Some(v.clone());
        } else if config_mode
            && matches.value_source("account_url") == Some(ValueSource::EnvVariable)
        {
            cli.account_url = None;
        }
    } else if cli.account_url.is_none() {
        cli.account_url.clone_from(&cfg.account_url);
    }

    // Global: output_format
    if should_apply_config(matches.value_source("output_format")) {
        if let Some(ref v) = cfg.output_format {
            if v == "json" {
                cli.output_format = OutputFormat::Json;
            }
        } else if config_mode
            && matches.value_source("output_format") == Some(ValueSource::EnvVariable)
        {
            cli.output_format = OutputFormat::Text;
        }
    }

    // Global: insecure — ALLOWED from env even in config mode (secret/safety toggle)
    if matches!(
        matches.value_source("insecure"),
        Some(ValueSource::DefaultValue) | None
    ) && let Some(v) = cfg.insecure
    {
        cli.insecure = v;
    }
    // In config mode, if env has ACME_INSECURE but config also sets it, config wins
    // (already handled above: config is applied for DefaultValue).
    // If env has it and config doesn't, env is allowed to survive for insecure.

    // Global: connect_timeout
    if should_apply_config(matches.value_source("connect_timeout")) {
        if let Some(v) = cfg.connect_timeout {
            cli.connect_timeout = v;
        } else if config_mode
            && matches.value_source("connect_timeout") == Some(ValueSource::EnvVariable)
        {
            cli.connect_timeout = 15;
        }
    }

    if matches!(
        matches.value_source("allow_private_network"),
        Some(ValueSource::DefaultValue) | None
    ) && let Some(v) = cfg.allow_private_network
    {
        cli.allow_private_network = v;
    }

    if matches!(
        matches.value_source("unsafe_hooks"),
        Some(ValueSource::DefaultValue) | None
    ) && let Some(v) = cfg.unsafe_hooks
    {
        cli.unsafe_hooks = v;
    }

    if matches!(
        matches.value_source("dns_check_mode"),
        Some(ValueSource::DefaultValue) | None
    ) && let Some(ref s) = cfg.dns_check_mode
    {
        if let Ok(m) = <DnsCheckMode as clap::ValueEnum>::from_str(s, true) {
            cli.dns_check_mode = m;
        } else {
            eprintln!(
                "warning: config: dns_check_mode must be one of: authoritative, cached, system (got {s:?}); using CLI default"
            );
        }
    }

    if matches!(
        matches.value_source("dns_check_dnssec"),
        Some(ValueSource::DefaultValue) | None
    ) && let Some(v) = cfg.dns_check_dnssec
    {
        cli.dns_check_dnssec = v;
    }

    // Run subcommand options
    if let Commands::Run {
        ref mut domains,
        ref mut contact,
        ref mut challenge_type,
        ref mut http_port,
        ref mut challenge_dir,
        ref mut dns_hook,
        ref mut dns_wait,
        ref mut dns_propagation_concurrency,
        ref mut challenge_timeout,
        ref mut cert_output,
        ref mut key_output,
        ref mut days,
        ref mut key_password_file,
        ref mut on_challenge_ready,
        ref mut on_cert_issued,
        ref mut eab_kid,
        ref mut eab_hmac_key,
        ref mut pre_authorize,
        ref mut ari,
        ref mut reissue_on_mismatch,
        ref mut print_cert,
        ref mut persist_policy,
        ref mut persist_until,
        ref mut cert_key_algorithm,
        ref mut profile,
        ..
    } = cli.command
    {
        let cfg_run = &config.run;
        if let Some((_, sub_matches)) = matches.subcommand() {
            if should_apply_config(sub_matches.value_source("challenge_type"))
                && let Some(ref v) = cfg_run.challenge_type
            {
                *challenge_type = v.clone();
            }
            if should_apply_config(sub_matches.value_source("http_port"))
                && let Some(v) = cfg_run.http_port
            {
                *http_port = v;
            }
            if should_apply_config(sub_matches.value_source("cert_output"))
                && let Some(ref v) = cfg_run.cert_output
            {
                *cert_output = v.clone();
            }
            if should_apply_config(sub_matches.value_source("key_output"))
                && let Some(ref v) = cfg_run.key_output
            {
                *key_output = v.clone();
            }
            if should_apply_config(sub_matches.value_source("cert_key_algorithm"))
                && let Some(ref v) = cfg_run.cert_key_algorithm
                && let Ok(a) = <CertKeyAlgorithm as clap::ValueEnum>::from_str(v, true)
            {
                *cert_key_algorithm = a;
            }
        }

        // Domains: CLI takes priority, fall back to config
        if domains.is_empty() {
            if let Some(ref v) = cfg_run.domains {
                *domains = v.clone();
            }
        } else if config_mode && cfg_run.domains.as_ref().is_none_or(|d| d.is_empty()) {
            // Domains from CLI but not in config — inform the user
            info!(
                "Using domains from CLI: {:?} (not set in config file)",
                domains
            );
        }

        // Option fields: simple merge (CLI wins if set)
        if contact.is_none() {
            contact.clone_from(&cfg_run.contact);
        }
        if challenge_dir.is_none() {
            challenge_dir.clone_from(&cfg_run.challenge_dir);
        }
        if dns_hook.is_none() {
            dns_hook.clone_from(&cfg_run.dns_hook);
        }
        if dns_wait.is_none() {
            *dns_wait = cfg_run.dns_wait;
        }
        if *dns_propagation_concurrency == 5
            && let Some(v) = cfg_run.dns_propagation_concurrency
        {
            *dns_propagation_concurrency = v;
        }
        if *challenge_timeout == 300
            && let Some(v) = cfg_run.challenge_timeout
        {
            *challenge_timeout = v;
        }
        if days.is_none() {
            *days = cfg_run.days;
        }
        if on_challenge_ready.is_none() {
            on_challenge_ready.clone_from(&cfg_run.on_challenge_ready);
        }
        if on_cert_issued.is_none() {
            on_cert_issued.clone_from(&cfg_run.on_cert_issued);
        }
        if !*pre_authorize && cfg_run.pre_authorize == Some(true) {
            *pre_authorize = true;
        }
        if !*ari && cfg_run.ari == Some(true) {
            *ari = true;
        }
        if !*reissue_on_mismatch && cfg_run.reissue_on_mismatch == Some(true) {
            *reissue_on_mismatch = true;
        }
        if !*print_cert && cfg_run.print_cert == Some(true) {
            *print_cert = true;
        }
        if persist_policy.is_none() {
            persist_policy.clone_from(&cfg_run.persist_policy);
        }
        if persist_until.is_none() {
            *persist_until = cfg_run.persist_until;
        }
        if profile.is_none() {
            profile.clone_from(&cfg_run.profile);
        }

        // Secrets ALLOWED from env even in config mode:
        //   key_password_file, eab_kid, eab_hmac_key
        if key_password_file.is_none() {
            key_password_file.clone_from(&cfg_run.key_password_file);
        }
        if eab_kid.is_none() {
            eab_kid.clone_from(&cfg_run.eab_kid);
        }
        if eab_hmac_key.is_none() {
            use secrecy::ExposeSecret;
            *eab_hmac_key = cfg_run
                .eab_hmac_key
                .as_ref()
                .map(|s| s.expose_secret().to_string());
        }
    }

    // Account subcommand options
    if let Commands::Account {
        ref mut contact,
        ref mut eab_kid,
        ref mut eab_hmac_key,
        ..
    } = cli.command
    {
        let cfg_acct = &config.account;
        if contact.is_empty()
            && let Some(ref v) = cfg_acct.contact
        {
            *contact = v.clone();
        }
        // Secrets — allowed from env in config mode
        if eab_kid.is_none() {
            eab_kid.clone_from(&cfg_acct.eab_kid);
        }
        if eab_hmac_key.is_none() {
            use secrecy::ExposeSecret;
            *eab_hmac_key = cfg_acct
                .eab_hmac_key
                .as_ref()
                .map(|s| s.expose_secret().to_string());
        }
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

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Parse a PEM certificate and return the number of days until expiry.
pub(crate) fn cert_days_remaining(path: &std::path::Path) -> Result<i64> {
    let pem_data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    // Parse the first PEM block (the end-entity cert) to extract notAfter
    let parsed = pem::parse(&pem_data).context("failed to parse certificate PEM")?;
    let (_, cert) = x509_parser::parse_x509_certificate(parsed.contents())
        .map_err(|e| anyhow::anyhow!("failed to parse X.509 certificate: {e}"))?;
    let not_after = cert.validity().not_after.to_datetime();
    let now = time::OffsetDateTime::now_utc();
    let remaining = not_after - now;
    Ok(remaining.whole_days())
}

/// Parse a PEM certificate and return the set of SAN identifiers (DNS names + IPs).
///
/// DNS names are lowercased; IP addresses are canonicalized via `std::net::IpAddr`.
pub(crate) fn cert_san_identifiers(
    path: &std::path::Path,
) -> Result<std::collections::BTreeSet<String>> {
    use x509_parser::prelude::*;

    let pem_data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let parsed = ::pem::parse(&pem_data).context("failed to parse certificate PEM")?;
    let (_, cert) = X509Certificate::from_der(parsed.contents())
        .map_err(|e| anyhow::anyhow!("failed to parse X.509 certificate: {e}"))?;

    let mut ids = std::collections::BTreeSet::new();

    let san_ext = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME);

    if let Some(ext) = san_ext
        && let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension()
    {
        for name in &san.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    ids.insert(dns.to_lowercase());
                }
                GeneralName::IPAddress(bytes) => {
                    // IPv4 = 4 bytes, IPv6 = 16 bytes
                    let ip: Option<std::net::IpAddr> = match bytes.len() {
                        4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                            bytes[0], bytes[1], bytes[2], bytes[3],
                        ))),
                        16 => {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(bytes);
                            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
                        }
                        _ => None,
                    };
                    if let Some(addr) = ip {
                        ids.insert(addr.to_string());
                    }
                }
                _ => {} // Ignore other GeneralName types
            }
        }
    }

    Ok(ids)
}

/// Normalize a domain/IP string for comparison (lowercase, canonical IP form).
pub(crate) fn normalize_identifier(value: &str) -> String {
    // Strip brackets for IPv6 literals like [::1]
    let candidate = if value.starts_with('[') && value.ends_with(']') {
        &value[1..value.len() - 1]
    } else {
        value
    };
    if let Ok(ip) = candidate.parse::<std::net::IpAddr>() {
        ip.to_string()
    } else {
        value.to_lowercase()
    }
}

pub(crate) fn load_account_key_with_password(
    path: &PathBuf,
    password: Option<&str>,
) -> Result<AccountKey> {
    // SEC-07: wrap PEM in Zeroizing so the on-heap key material is wiped
    // when this function returns, even on the error path.
    let pem = zeroize::Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read account key from {}", path.display()))?,
    );
    AccountKey::from_pkcs8_pem_with_password(&pem, password)
        .with_context(|| format!("failed to load account key from {}", path.display()))
}

/// SEC-08: resolve the account-key password from CLI flag or password file.
/// Returns None when neither is provided (unencrypted-key path).
pub(crate) fn resolve_account_key_password(
    inline: Option<&str>,
    file: Option<&std::path::Path>,
) -> Result<Option<secrecy::SecretString>> {
    if let Some(pw) = inline {
        return Ok(Some(secrecy::SecretString::from(pw.to_string())));
    }
    if let Some(path) = file {
        fs_secure::warn_if_world_readable(path, "password");
        let content =
            zeroize::Zeroizing::new(std::fs::read_to_string(path).with_context(|| {
                format!(
                    "failed to read account-key password file: {}",
                    path.display()
                )
            })?);
        let pw = content
            .lines()
            .next()
            .map(|line| line.trim().to_string())
            .filter(|s: &String| !s.is_empty());
        return Ok(pw.map(secrecy::SecretString::from));
    }
    Ok(None)
}

pub(crate) async fn build_client(cli: &Cli) -> Result<AcmeClient> {
    use secrecy::ExposeSecret;
    client::validate_directory_url(&cli.directory, cli.insecure, cli.allow_private_network)?;
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
        client::validate_acme_url(url, cli.insecure, cli.allow_private_network)?;
        client.set_account_url(url.clone());
    }
    Ok(client)
}

pub(crate) fn generate_csr(
    domains: &[String],
    alg: CertKeyAlgorithm,
) -> Result<(Vec<u8>, zeroize::Zeroizing<String>)> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    let mut params =
        CertificateParams::new(domains.to_vec()).context("failed to create CSR parameters")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domains[0].clone());
    params.distinguished_name = dn;
    let key_pair = match alg {
        CertKeyAlgorithm::EcP256 => KeyPair::generate(),
        CertKeyAlgorithm::EcP384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384),
        CertKeyAlgorithm::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519),
    }
    .context("failed to generate CSR key pair")?;
    let key_pem = zeroize::Zeroizing::new(key_pair.serialize_pem());
    let csr = params
        .serialize_request(&key_pair)
        .context("failed to serialize CSR")?;
    Ok((csr.der().to_vec(), key_pem))
}

pub(crate) fn pem_to_der(pem_data: &str) -> Result<Vec<u8>> {
    let parsed = pem::parse(pem_data).context("failed to parse PEM data")?;
    Ok(parsed.contents().to_vec())
}

pub(crate) fn encrypt_private_key(key_pem: &str, password: &str) -> Result<String> {
    use rand_core::RngCore;

    let parsed = pem::parse(key_pem).context("failed to parse private key PEM")?;
    let pk_info = pkcs8::PrivateKeyInfo::try_from(parsed.contents())
        .map_err(|e| anyhow::anyhow!("failed to parse PKCS#8 private key: {e}"))?;

    // Use log_n=14 (N=16384) for OpenSSL CLI compatibility.
    // Default log_n=17 (N=131072) requires ~128 MB which exceeds OpenSSL's 32 MB scrypt limit.
    let scrypt_params = scrypt::Params::new(14, 8, 1, 32)
        .map_err(|e| anyhow::anyhow!("invalid scrypt parameters: {e}"))?;
    let mut salt = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut iv);
    let pbes2_params = pkcs8::pkcs5::pbes2::Parameters::scrypt_aes256cbc(scrypt_params, &salt, &iv)
        .map_err(|e| anyhow::anyhow!("failed to build PBES2 parameters: {e}"))?;

    let encrypted_doc = pk_info
        .encrypt_with_params(pbes2_params, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to encrypt private key: {e}"))?;
    Ok(pem::encode(&pem::Pem::new(
        "ENCRYPTED PRIVATE KEY",
        encrypted_doc.as_bytes().to_vec(),
    )))
}
