//! Resolve effective configuration by merging CLI flags, environment
//! variables, the optional TOML config file, and built-in defaults.
//!
//! Public surface:
//! - [`load_config`]  Read the file if `--config` / `ACME_CONFIG` is set.
//! - [`apply_config`] Mutate a parsed [`Cli`] in place to inject the
//!   resolved values, honoring precedence rules.
//!
//! Precedence (highest → lowest) when a config file IS loaded
//! ("config mode"):
//!
//! 1. CLI flag
//! 2. Config file
//! 3. Built-in default
//!
//! (Environment variables are ignored in config mode for most fields,
//! except for secrets such as `ACME_ACCOUNT_KEY_PASSWORD` / EAB.)
//!
//! Precedence WITHOUT a config file (legacy mode):
//!
//! 1. CLI flag
//! 2. Environment variable
//! 3. Built-in default

use std::path::PathBuf;

use anyhow::Result;
use tracing::info;

use crate::cli::{CertKeyAlgorithm, Cli, Commands, OutputFormat};
use crate::dns_check::DnsCheckMode;
use crate::{config, fs_secure};

/// Load config file if requested. Returns `(config, config_mode)`.
///
/// `config_mode = true` means the user explicitly asked for a config file
/// (via `--config` CLI flag or `ACME_CONFIG` env var) and env vars should be
/// ignored for most fields.
pub(crate) fn load_config(cli: &Cli) -> Result<(Option<config::Config>, bool)> {
    if let Some(ref path) = cli.config {
        fs_secure::warn_if_world_readable(path, "config");
        Ok((Some(config::Config::load(path)?), true))
    } else {
        Ok((None, false))
    }
}

pub(crate) fn apply_config(
    cli: &mut Cli,
    matches: &clap::ArgMatches,
    config: &config::Config,
    config_mode: bool,
) {
    apply_global(cli, matches, &config.global, config_mode);
    apply_run(cli, matches, &config.run, config_mode);
    apply_account(cli, &config.account);
}

/// Returns true when the config-file value should replace the current Cli
/// value: in both modes, config overrides env and default, and CLI always wins.
fn should_apply_config(source: Option<clap::parser::ValueSource>) -> bool {
    use clap::parser::ValueSource;
    !matches!(source, Some(ValueSource::CommandLine))
}

fn apply_global(
    cli: &mut Cli,
    matches: &clap::ArgMatches,
    cfg: &config::GlobalConfig,
    config_mode: bool,
) {
    use clap::parser::ValueSource;

    if config_mode {
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

    if should_apply_config(matches.value_source("directory")) {
        if let Some(ref v) = cfg.directory {
            cli.directory = v.clone();
        } else if config_mode && matches.value_source("directory") == Some(ValueSource::EnvVariable)
        {
            cli.directory = "https://localhost:14000/dir".to_string();
        }
    }

    if should_apply_config(matches.value_source("account_key")) {
        if let Some(ref v) = cfg.account_key {
            cli.account_key = v.clone();
        } else if config_mode
            && matches.value_source("account_key") == Some(ValueSource::EnvVariable)
        {
            cli.account_key = PathBuf::from("account.key");
        }
    }

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

    if matches!(
        matches.value_source("dns_check_dnssec"),
        Some(ValueSource::DefaultValue) | None
    ) && let Some(v) = cfg.dns_check_dnssec
    {
        cli.dns_check_dnssec = v;
    }
}

fn apply_run(
    cli: &mut Cli,
    matches: &clap::ArgMatches,
    cfg_run: &config::RunConfig,
    config_mode: bool,
) {
    let Commands::Run {
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
    else {
        return;
    };

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

    if domains.is_empty() {
        if let Some(ref v) = cfg_run.domains {
            *domains = v.clone();
        }
    } else if config_mode && cfg_run.domains.as_ref().is_none_or(|d| d.is_empty()) {
        info!(
            "Using domains from CLI: {:?} (not set in config file)",
            domains
        );
    }

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

    // Secrets remain allowed from env even in config mode:
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

fn apply_account(cli: &mut Cli, cfg_acct: &config::AccountConfig) {
    let Commands::Account {
        ref mut contact,
        ref mut eab_kid,
        ref mut eab_hmac_key,
        ..
    } = cli.command
    else {
        return;
    };

    if contact.is_empty()
        && let Some(ref v) = cfg_acct.contact
    {
        *contact = v.clone();
    }
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
