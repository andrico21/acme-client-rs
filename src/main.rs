#![forbid(unsafe_code)]

mod challenge;
mod cleanup;
mod cli;
mod cli_config;
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

use crate::cli::{CertKeyAlgorithm, Cli, Commands};
use crate::cli_config::{apply_config, load_config};
use crate::client::AcmeClient;
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
