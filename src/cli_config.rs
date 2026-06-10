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
//! except for secret-bearing vars such as `ACME_ACCOUNT_KEY_PASSWORD` /
//! `ACME_EAB_HMAC_KEY`. Safety toggles like `ACME_INSECURE` are
//! fail-closed in config mode: env is dropped, config or default(false) wins.)
//!
//! Precedence WITHOUT a config file (legacy mode):
//!
//! 1. CLI flag
//! 2. Environment variable
//! 3. Built-in default

use std::path::PathBuf;

use anyhow::{Context, Result};
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
) -> Result<()> {
    apply_global(cli, matches, &config.global, config_mode)?;
    apply_run(cli, matches, &config.run, config_mode)?;
    apply_order(cli, matches, config_mode);
    apply_account(cli, &config.account);
    Ok(())
}

/// Returns true when the config-file value should replace the current Cli
/// value: in both modes, config overrides env and default, and CLI always wins.
fn should_apply_config(source: Option<clap::parser::ValueSource>) -> bool {
    use clap::parser::ValueSource;
    !matches!(source, Some(ValueSource::CommandLine))
}

/// Resolve one field in the CLI ⇄ config ⇄ env merge. Returns `Some(new)` to
/// assign, or `None` to leave the current value untouched.
///
/// Precedence: an explicit CLI flag always wins (→ leave); otherwise a config
/// value wins; otherwise, in config mode, an env-sourced value is reset to the
/// secure built-in `default` — env must NOT survive config mode. The last rule
/// is the H1 fail-open fix for the security toggles.
fn config_or_env_reset<T>(
    source: Option<clap::parser::ValueSource>,
    config_value: Option<T>,
    config_mode: bool,
    default: T,
) -> Option<T> {
    use clap::parser::ValueSource;
    if matches!(source, Some(ValueSource::CommandLine)) {
        return None;
    }
    if let Some(v) = config_value {
        return Some(v);
    }
    if config_mode && source == Some(ValueSource::EnvVariable) {
        return Some(default);
    }
    None
}

fn apply_global(
    cli: &mut Cli,
    matches: &clap::ArgMatches,
    cfg: &config::GlobalConfig,
    config_mode: bool,
) -> Result<()> {
    use clap::parser::ValueSource;

    if config_mode {
        for (id, env_name) in [
            ("directory", "ACME_DIRECTORY_URL"),
            ("account_key", "ACME_ACCOUNT_KEY_FILE"),
            ("account_url", "ACME_ACCOUNT_URL"),
            ("output_format", "ACME_OUTPUT_FORMAT"),
            ("insecure", "ACME_INSECURE"),
            ("connect_timeout", "ACME_CONNECT_TIMEOUT"),
            ("allow_private_network", "ACME_ALLOW_PRIVATE_NETWORK"),
            ("unsafe_hooks", "ACME_UNSAFE_HOOKS"),
            ("dns_check_mode", "ACME_DNS_CHECK_MODE"),
            ("dns_check_dnssec", "ACME_DNS_CHECK_DNSSEC"),
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
            cli.directory.clone_from(v);
        } else if config_mode && matches.value_source("directory") == Some(ValueSource::EnvVariable)
        {
            cli.directory = crate::defaults::global::DIRECTORY_URL.to_string();
        }
    }

    if should_apply_config(matches.value_source("account_key")) {
        if let Some(ref v) = cfg.account_key {
            cli.account_key.clone_from(v);
        } else if config_mode
            && matches.value_source("account_key") == Some(ValueSource::EnvVariable)
        {
            cli.account_key = PathBuf::from(crate::defaults::global::ACCOUNT_KEY_FILE);
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
            cli.output_format = parse_output_format(v)?;
        } else if config_mode
            && matches.value_source("output_format") == Some(ValueSource::EnvVariable)
        {
            cli.output_format = OutputFormat::Text;
        }
    }

    // Global: insecure — fail-closed in config mode (H1/E2). When a config
    // file is loaded, env `ACME_INSECURE` is dropped so it cannot silently
    // disable TLS verification. Explicit `--insecure` on the CLI always wins,
    // and an explicit `insecure = true` in the config file is honored.
    if let Some(v) = config_or_env_reset(
        matches.value_source("insecure"),
        cfg.insecure,
        config_mode,
        false,
    ) {
        cli.insecure = v;
    }

    // Global: connect_timeout
    if should_apply_config(matches.value_source("connect_timeout")) {
        if let Some(v) = cfg.connect_timeout {
            cli.connect_timeout = v;
        } else if config_mode
            && matches.value_source("connect_timeout") == Some(ValueSource::EnvVariable)
        {
            cli.connect_timeout = crate::defaults::global::CONNECT_TIMEOUT_SECS;
        }
    }

    if let Some(v) = config_or_env_reset(
        matches.value_source("allow_private_network"),
        cfg.allow_private_network,
        config_mode,
        false,
    ) {
        cli.allow_private_network = v;
    }

    if let Some(v) = config_or_env_reset(
        matches.value_source("unsafe_hooks"),
        cfg.unsafe_hooks,
        config_mode,
        false,
    ) {
        cli.unsafe_hooks = v;
    }

    let cfg_dns_mode = cfg.dns_check_mode.as_ref().and_then(|s| {
        <DnsCheckMode as clap::ValueEnum>::from_str(s, true).map_or_else(
            |_| {
                tracing::warn!(
                    "config: dns_check_mode must be one of: authoritative, cached, system (got {s:?}); using CLI default"
                );
                None
            },
            Some,
        )
    });
    if let Some(m) = config_or_env_reset(
        matches.value_source("dns_check_mode"),
        cfg_dns_mode,
        config_mode,
        DnsCheckMode::Authoritative,
    ) {
        cli.dns_check_mode = m;
    }

    if let Some(v) = config_or_env_reset(
        matches.value_source("dns_check_dnssec"),
        cfg.dns_check_dnssec,
        config_mode,
        false,
    ) {
        cli.dns_check_dnssec = v;
    }

    Ok(())
}

/// Parse a config-file `output_format` strictly: unknown values are a hard
/// error (L5), never a silent fallback that could downgrade the format.
fn parse_output_format(value: &str) -> Result<OutputFormat> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        other => anyhow::bail!("config: output_format must be one of: text, json (got {other:?})"),
    }
}

fn apply_run(
    cli: &mut Cli,
    matches: &clap::ArgMatches,
    cfg_run: &config::RunConfig,
    config_mode: bool,
) -> Result<()> {
    let Commands::Run(args) = &mut cli.command else {
        return Ok(());
    };

    if let Some((_, sub_matches)) = matches.subcommand() {
        use clap::parser::ValueSource;

        if config_mode {
            for (id, env_name) in [("profile", "ACME_PROFILE")] {
                if sub_matches.value_source(id) == Some(ValueSource::EnvVariable) {
                    tracing::debug!(
                        "Config file mode: ignoring {env_name} env var (use --config values or pass --{} on CLI)",
                        id.replace('_', "-"),
                    );
                }
            }
        }

        if should_apply_config(sub_matches.value_source("challenge_type"))
            && let Some(ref v) = cfg_run.challenge_type
        {
            crate::types::ChallengeType::parse_strict(v)
                .context("config: invalid challenge_type")?;
            args.challenge_type.clone_from(v);
        }
        if should_apply_config(sub_matches.value_source("http_port"))
            && let Some(v) = cfg_run.http_port
        {
            args.http_port = v;
        }
        if should_apply_config(sub_matches.value_source("cert_output"))
            && let Some(ref v) = cfg_run.cert_output
        {
            args.cert_output.clone_from(v);
        }
        if should_apply_config(sub_matches.value_source("key_output"))
            && let Some(ref v) = cfg_run.key_output
        {
            args.key_output.clone_from(v);
        }
        if should_apply_config(sub_matches.value_source("cert_key_algorithm"))
            && let Some(ref v) = cfg_run.cert_key_algorithm
        {
            args.cert_key_algorithm = <CertKeyAlgorithm as clap::ValueEnum>::from_str(v, true)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "config: cert_key_algorithm must be one of: ec-p256, ec-p384, ed25519 (got {v:?})"
                    )
                })?;
        }
        if should_apply_config(sub_matches.value_source("dns_propagation_concurrency"))
            && let Some(v) = cfg_run.dns_propagation_concurrency
        {
            args.dns_propagation_concurrency = v;
        }
        if should_apply_config(sub_matches.value_source("challenge_timeout"))
            && let Some(v) = cfg_run.challenge_timeout
        {
            args.challenge_timeout = v;
        }
        if let Some(p) = config_or_env_reset(
            sub_matches.value_source("profile"),
            cfg_run.profile.clone().map(Some),
            config_mode,
            None,
        ) {
            args.profile = p;
        }
    }

    if args.domains.is_empty() {
        if let Some(ref v) = cfg_run.domains {
            args.domains.clone_from(v);
        }
    } else if config_mode && cfg_run.domains.as_ref().is_none_or(std::vec::Vec::is_empty) {
        info!(
            "Using domains from CLI: {:?} (not set in config file)",
            args.domains
        );
    }

    if args.contact.is_none() {
        args.contact.clone_from(&cfg_run.contact);
    }
    if args.challenge_dir.is_none() {
        args.challenge_dir.clone_from(&cfg_run.challenge_dir);
    }
    if args.dns_hook.is_none() {
        args.dns_hook.clone_from(&cfg_run.dns_hook);
    }
    if args.dns_wait.is_none() {
        args.dns_wait = cfg_run.dns_wait;
    }
    if args.days.is_none() {
        args.days = cfg_run.days;
    }
    if args.on_challenge_ready.is_none() {
        args.on_challenge_ready
            .clone_from(&cfg_run.on_challenge_ready);
    }
    if args.on_cert_issued.is_none() {
        args.on_cert_issued.clone_from(&cfg_run.on_cert_issued);
    }
    if args.reuse_key.is_none() {
        args.reuse_key.clone_from(&cfg_run.reuse_key);
    }
    if !args.pre_authorize && cfg_run.pre_authorize == Some(true) {
        args.pre_authorize = true;
    }
    if !args.ari && cfg_run.ari == Some(true) {
        args.ari = true;
    }
    if !args.reissue_on_mismatch && cfg_run.reissue_on_mismatch == Some(true) {
        args.reissue_on_mismatch = true;
    }
    if !args.print_cert && cfg_run.print_cert == Some(true) {
        args.print_cert = true;
    }
    if !args.generate_account_key_if_missing
        && cfg_run.generate_account_key_if_missing == Some(true)
    {
        args.generate_account_key_if_missing = true;
    }
    if let Some((_, sub_matches)) = matches.subcommand()
        && should_apply_config(sub_matches.value_source("account_key_algorithm"))
        && let Some(ref v) = cfg_run.account_key_algorithm
    {
        args.account_key_algorithm = <crate::jws::KeyAlgorithm as clap::ValueEnum>::from_str(v, true)
            .map_err(|_| {
                anyhow::anyhow!(
                    "config: account_key_algorithm must be one of: es256, es384, es512, rsa2048, rsa4096, ed25519 (got {v:?})"
                )
            })?;
    }
    if args.persist_policy.is_none() {
        args.persist_policy.clone_from(&cfg_run.persist_policy);
    }
    if args.persist_until.is_none() {
        args.persist_until = cfg_run.persist_until;
    }

    // Secrets remain allowed from env even in config mode:
    //   key_password_file, eab_kid, eab_hmac_key
    if args.key_password_file.is_none() {
        args.key_password_file
            .clone_from(&cfg_run.key_password_file);
    }
    if args.eab_kid.is_none() {
        args.eab_kid.clone_from(&cfg_run.eab_kid);
    }
    if args.eab_hmac_key.is_none() {
        args.eab_hmac_key.clone_from(&cfg_run.eab_hmac_key);
    }

    Ok(())
}

fn apply_order(cli: &mut Cli, matches: &clap::ArgMatches, config_mode: bool) {
    let Commands::Order { profile, .. } = &mut cli.command else {
        return;
    };
    let Some((_, sub_matches)) = matches.subcommand() else {
        return;
    };
    if let Some(p) = config_or_env_reset::<Option<String>>(
        sub_matches.value_source("profile"),
        None,
        config_mode,
        None,
    ) {
        *profile = p;
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
        contact.clone_from(v);
    }
    if eab_kid.is_none() {
        eab_kid.clone_from(&cfg_acct.eab_kid);
    }
    if eab_hmac_key.is_none() {
        eab_hmac_key.clone_from(&cfg_acct.eab_hmac_key);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use clap::parser::ValueSource;

    use super::{config_or_env_reset, should_apply_config};
    use crate::dns_check::DnsCheckMode;

    // H1: an env-sourced safety toggle with no config override must reset to
    // the secure default in config mode (fail-closed); CLI and config still win.
    #[test]
    fn h1_config_mode_resets_env_safety_toggles() {
        assert_eq!(
            config_or_env_reset(Some(ValueSource::CommandLine), Some(true), true, false),
            None,
        );
        assert_eq!(
            config_or_env_reset::<bool>(Some(ValueSource::CommandLine), None, true, false),
            None,
        );
        assert_eq!(
            config_or_env_reset(Some(ValueSource::EnvVariable), Some(true), true, false),
            Some(true),
        );
        assert_eq!(
            config_or_env_reset::<bool>(Some(ValueSource::EnvVariable), None, true, false),
            Some(false),
        );
        assert_eq!(
            config_or_env_reset::<bool>(Some(ValueSource::EnvVariable), None, false, false),
            None,
        );
        assert_eq!(
            config_or_env_reset::<bool>(Some(ValueSource::DefaultValue), None, true, false),
            None,
        );
        assert_eq!(config_or_env_reset::<bool>(None, None, true, false), None);
        assert_eq!(
            config_or_env_reset(
                Some(ValueSource::EnvVariable),
                None,
                true,
                DnsCheckMode::Authoritative,
            ),
            Some(DnsCheckMode::Authoritative),
        );
    }

    #[test]
    fn h1_secure_defaults_are_failclosed() {
        assert_eq!(
            config_or_env_reset::<bool>(Some(ValueSource::EnvVariable), None, true, false),
            Some(false),
        );
    }

    // E2: ACME_INSECURE must fail-closed in config mode — env is dropped,
    // explicit `--insecure` on the CLI always wins, and `insecure = true`
    // in the config file is honored.
    #[test]
    fn h1_insecure_is_failclosed() {
        // (a) env ACME_INSECURE=true + config file WITHOUT `insecure` → false
        assert_eq!(
            config_or_env_reset::<bool>(Some(ValueSource::EnvVariable), None, true, false),
            Some(false),
        );
        // (b) config `insecure = true` (any source on CLI other than CommandLine) → true
        assert_eq!(
            config_or_env_reset(Some(ValueSource::EnvVariable), Some(true), true, false),
            Some(true),
        );
        assert_eq!(
            config_or_env_reset(Some(ValueSource::DefaultValue), Some(true), true, false),
            Some(true),
        );
        // (c) explicit `--insecure` CLI flag + config file → CLI wins (leave current value)
        assert_eq!(
            config_or_env_reset(Some(ValueSource::CommandLine), Some(false), true, false),
            None,
        );
        assert_eq!(
            config_or_env_reset::<bool>(Some(ValueSource::CommandLine), None, true, false),
            None,
        );
    }

    // L3: config-mode reset literals must track the defaults module, not drift.
    #[test]
    fn l3_reset_literals_match_defaults_module() {
        assert_eq!(
            crate::defaults::global::DIRECTORY_URL,
            "https://localhost:14000/dir",
        );
        assert_eq!(crate::defaults::global::ACCOUNT_KEY_FILE, "account.key");
        assert_eq!(crate::defaults::global::CONNECT_TIMEOUT_SECS, 15);
    }

    // L2: env-sourced profile must clear to None in config mode; config/CLI win.
    #[test]
    fn l2_profile_env_reset_in_config_mode() {
        assert_eq!(
            config_or_env_reset::<Option<String>>(Some(ValueSource::EnvVariable), None, true, None,),
            Some(None),
        );
        assert_eq!(
            config_or_env_reset(
                Some(ValueSource::EnvVariable),
                Some(Some("shortlived".to_string())),
                true,
                None,
            ),
            Some(Some("shortlived".to_string())),
        );
        assert_eq!(
            config_or_env_reset::<Option<String>>(Some(ValueSource::CommandLine), None, true, None,),
            None,
        );
        assert_eq!(
            config_or_env_reset::<Option<String>>(
                Some(ValueSource::EnvVariable),
                None,
                false,
                None,
            ),
            None,
        );
    }

    #[test]
    fn should_apply_config_cli_wins() {
        assert!(!should_apply_config(Some(ValueSource::CommandLine)));
        assert!(should_apply_config(Some(ValueSource::EnvVariable)));
        assert!(should_apply_config(Some(ValueSource::DefaultValue)));
        assert!(should_apply_config(None));
    }

    #[test]
    fn l5_output_format_parses_both_and_rejects_unknown() {
        use super::parse_output_format;
        use crate::cli::OutputFormat;
        assert!(matches!(
            parse_output_format("text").expect("text"),
            OutputFormat::Text
        ));
        assert!(matches!(
            parse_output_format("json").expect("json"),
            OutputFormat::Json
        ));
        assert!(parse_output_format("yaml").is_err());
        assert!(parse_output_format("JSON").is_err());
        assert!(parse_output_format("").is_err());
    }

    #[test]
    fn l5_unknown_challenge_and_key_algorithm_are_errors() {
        assert!(crate::types::ChallengeType::parse_strict("bogus-99").is_err());
        assert!(crate::types::ChallengeType::parse_strict("http-01").is_ok());
        assert!(
            <crate::cli::CertKeyAlgorithm as clap::ValueEnum>::from_str("rsa-9000", true).is_err()
        );
        assert!(
            <crate::cli::CertKeyAlgorithm as clap::ValueEnum>::from_str("ec-p256", true).is_ok()
        );
    }
}
