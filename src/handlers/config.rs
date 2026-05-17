//! Configuration subcommands (generate-config, show-config).

use std::path::PathBuf;

use anyhow::Result;

use crate::cli::{Cli, OutputFormat};
use crate::{out, outln};

pub(crate) fn cmd_generate_config(silent: bool) -> Result<()> {
    if !silent {
        out!("{}", crate::config::generate_template());
    }
    Ok(())
}

pub(crate) fn cmd_show_config(
    cli: &Cli,
    loaded_config: Option<&crate::config::Config>,
    matches: &clap::ArgMatches,
    verbose: bool,
    show_secrets: bool,
    config_mode: bool,
) -> Result<()> {
    if cli.silent {
        return Ok(());
    }
    use clap::parser::ValueSource;

    let json = cli.output_format == OutputFormat::Json;

    let redact_secret = |v: &Option<secrecy::SecretString>| -> Option<String> {
        use secrecy::ExposeSecret;
        match v {
            Some(_) if !show_secrets => Some("[REDACTED]".to_string()),
            Some(s) => Some(s.expose_secret().to_string()),
            None => None,
        }
    };
    let opt_secret_string = |v: &Option<secrecy::SecretString>| -> String {
        use secrecy::ExposeSecret;
        match v {
            Some(_) if !show_secrets => "[REDACTED]".to_string(),
            Some(s) => s.expose_secret().to_string(),
            None => "(not set)".to_string(),
        }
    };

    let config_path = cli.config.as_ref().map(|p| p.display().to_string());
    let has_config = loaded_config.is_some();

    // In the new model, sources are simpler:
    //   config_mode: CLI > config > default (env ignored except secrets)
    //   no config:   CLI > env > default
    let global_source = |id: &str, has_config_val: bool| -> &'static str {
        match matches.value_source(id) {
            Some(ValueSource::CommandLine) => "cli",
            Some(ValueSource::EnvVariable) if config_mode && has_config_val => "config",
            Some(ValueSource::EnvVariable) if config_mode => "default",
            Some(ValueSource::EnvVariable) => "env",
            Some(ValueSource::DefaultValue) if has_config_val => "config",
            Some(ValueSource::DefaultValue) => "default",
            _ if has_config_val => "config",
            _ => "default",
        }
    };

    // Source for a [run] or [account] config-only field
    let cfg_source = |has_val: bool| -> &'static str { if has_val { "config" } else { "default" } };

    let cfg_g = loaded_config.map(|c| &c.global);
    let cfg_run = loaded_config.map(|c| &c.run);
    let cfg_acct = loaded_config.map(|c| &c.account);

    let opt_str = |v: &Option<String>| v.as_deref().unwrap_or("(not set)").to_string();
    let opt_path = |v: &Option<PathBuf>| {
        v.as_ref()
            .map_or("(not set)".to_string(), |p| p.display().to_string())
    };
    let opt_u64 = |v: Option<u64>| v.map_or("(not set)".to_string(), |v| v.to_string());
    let opt_u32 = |v: Option<u32>| v.map_or("(not set)".to_string(), |v| v.to_string());
    let opt_u16 = |v: Option<u16>| v.map_or("80".to_string(), |v| v.to_string());
    let opt_bool = |v: Option<bool>| v.unwrap_or(false).to_string();

    if json {
        let mut obj = serde_json::json!({
            "command": "show-config",
            "config_file": config_path,
            "config_mode": config_mode,
            "verbose": verbose,
        });

        let mut g = serde_json::json!({
            "directory": { "value": cli.directory },
            "account_key": { "value": cli.account_key.display().to_string() },
            "account_url": { "value": cli.account_url },
            "output_format": { "value": if cli.output_format == OutputFormat::Json { "json" } else { "text" } },
            "insecure": { "value": cli.insecure },
            "connect_timeout": { "value": cli.connect_timeout },
            "allow_private_network": { "value": cli.allow_private_network },
            "dns_check_mode": { "value": format!("{:?}", cli.dns_check_mode).to_lowercase() },
            "dns_check_dnssec": { "value": cli.dns_check_dnssec },
            "unsafe_hooks": { "value": cli.unsafe_hooks },
        });
        if verbose {
            g["directory"]["source"] = serde_json::json!(global_source(
                "directory",
                cfg_g.and_then(|c| c.directory.as_ref()).is_some()
            ));
            g["account_key"]["source"] = serde_json::json!(global_source(
                "account_key",
                cfg_g.and_then(|c| c.account_key.as_ref()).is_some()
            ));
            g["account_url"]["source"] = serde_json::json!(global_source(
                "account_url",
                cfg_g.and_then(|c| c.account_url.as_ref()).is_some()
            ));
            g["output_format"]["source"] = serde_json::json!(global_source(
                "output_format",
                cfg_g.and_then(|c| c.output_format.as_ref()).is_some()
            ));
            g["insecure"]["source"] = serde_json::json!(global_source(
                "insecure",
                cfg_g.and_then(|c| c.insecure).is_some()
            ));
            g["connect_timeout"]["source"] = serde_json::json!(global_source(
                "connect_timeout",
                cfg_g.and_then(|c| c.connect_timeout).is_some()
            ));
            g["allow_private_network"]["source"] = serde_json::json!(global_source(
                "allow_private_network",
                cfg_g.and_then(|c| c.allow_private_network).is_some()
            ));
            g["dns_check_mode"]["source"] = serde_json::json!(global_source(
                "dns_check_mode",
                cfg_g.and_then(|c| c.dns_check_mode.as_ref()).is_some()
            ));
            g["dns_check_dnssec"]["source"] = serde_json::json!(global_source(
                "dns_check_dnssec",
                cfg_g.and_then(|c| c.dns_check_dnssec).is_some()
            ));
            g["unsafe_hooks"]["source"] = serde_json::json!(global_source(
                "unsafe_hooks",
                cfg_g.and_then(|c| c.unsafe_hooks).is_some()
            ));
        }
        obj["global"] = g;

        if let Some(r) = cfg_run {
            let mut rv = serde_json::json!({
                "domains": { "value": r.domains },
                "contact": { "value": r.contact },
                "challenge_type": { "value": r.challenge_type.as_deref().unwrap_or("http-01") },
                "http_port": { "value": r.http_port.unwrap_or(80) },
                "challenge_dir": { "value": r.challenge_dir.as_ref().map(|p| p.display().to_string()) },
                "dns_hook": { "value": r.dns_hook.as_ref().map(|p| p.display().to_string()) },
                "dns_wait": { "value": r.dns_wait },
                "dns_propagation_concurrency": { "value": r.dns_propagation_concurrency },
                "challenge_timeout": { "value": r.challenge_timeout.unwrap_or(300) },
                "cert_output": { "value": r.cert_output.as_ref().map_or("certificate.pem".to_string(), |p| p.display().to_string()) },
                "key_output": { "value": r.key_output.as_ref().map_or("private.key".to_string(), |p| p.display().to_string()) },
                "days": { "value": r.days },
                "key_password_file": { "value": r.key_password_file.as_ref().map(|p| p.display().to_string()) },
                "on_challenge_ready": { "value": r.on_challenge_ready.as_ref().map(|p| p.display().to_string()) },
                "on_cert_issued": { "value": r.on_cert_issued.as_ref().map(|p| p.display().to_string()) },
                "eab_kid": { "value": r.eab_kid },
                "eab_hmac_key": { "value": redact_secret(&r.eab_hmac_key) },
                "pre_authorize": { "value": r.pre_authorize.unwrap_or(false) },
                "ari": { "value": r.ari.unwrap_or(false) },
                "reissue_on_mismatch": { "value": r.reissue_on_mismatch.unwrap_or(false) },
                "print_cert": { "value": r.print_cert.unwrap_or(false) },
                "persist_policy": { "value": r.persist_policy },
                "persist_until": { "value": r.persist_until },
                "cert_key_algorithm": { "value": r.cert_key_algorithm.as_deref().unwrap_or("ec-p256") },
                "profile": { "value": r.profile },
            });
            if verbose {
                for key in [
                    "domains",
                    "contact",
                    "challenge_type",
                    "http_port",
                    "challenge_dir",
                    "dns_hook",
                    "dns_wait",
                    "dns_propagation_concurrency",
                    "challenge_timeout",
                    "cert_output",
                    "key_output",
                    "days",
                    "key_password_file",
                    "on_challenge_ready",
                    "on_cert_issued",
                    "eab_kid",
                    "eab_hmac_key",
                    "pre_authorize",
                    "ari",
                    "reissue_on_mismatch",
                    "print_cert",
                    "persist_policy",
                    "persist_until",
                    "cert_key_algorithm",
                    "profile",
                ] {
                    let has = !rv[key]["value"].is_null()
                        && rv[key]["value"] != serde_json::json!(false)
                        && rv[key]["value"] != serde_json::json!("http-01")
                        && rv[key]["value"] != serde_json::json!(80)
                        && rv[key]["value"] != serde_json::json!(5)
                        && rv[key]["value"] != serde_json::json!(300)
                        && rv[key]["value"] != serde_json::json!("certificate.pem")
                        && rv[key]["value"] != serde_json::json!("private.key")
                        && rv[key]["value"] != serde_json::json!("ec-p256");
                    rv[key]["source"] = serde_json::json!(cfg_source(has));
                }
            }
            obj["run"] = rv;
        }
        if let Some(a) = cfg_acct {
            let mut av = serde_json::json!({
                "contact": { "value": a.contact },
                "eab_kid": { "value": a.eab_kid },
                "eab_hmac_key": { "value": redact_secret(&a.eab_hmac_key) },
            });
            if verbose {
                av["contact"]["source"] = serde_json::json!(cfg_source(a.contact.is_some()));
                av["eab_kid"]["source"] = serde_json::json!(cfg_source(a.eab_kid.is_some()));
                av["eab_hmac_key"]["source"] =
                    serde_json::json!(cfg_source(a.eab_hmac_key.is_some()));
            }
            obj["account"] = av;
        }
        outln!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        outln!("# Effective configuration");
        if config_mode {
            outln!("# Mode: config file (env vars ignored except secrets)");
        }
        if verbose {
            outln!("# Source annotations: (cli) (env) (config) (default)");
        }
        outln!();
        match &config_path {
            Some(p) => outln!("Config file: {p}"),
            None => outln!("Config file: (none)"),
        }
        outln!();

        let src = |s: &str| {
            if verbose {
                format!("  ({s})")
            } else {
                String::new()
            }
        };

        let dir_src = global_source(
            "directory",
            cfg_g.and_then(|c| c.directory.as_ref()).is_some(),
        );
        let key_src = global_source(
            "account_key",
            cfg_g.and_then(|c| c.account_key.as_ref()).is_some(),
        );
        let url_src = global_source(
            "account_url",
            cfg_g.and_then(|c| c.account_url.as_ref()).is_some(),
        );
        let fmt_src = global_source(
            "output_format",
            cfg_g.and_then(|c| c.output_format.as_ref()).is_some(),
        );
        let ins_src = global_source("insecure", cfg_g.and_then(|c| c.insecure).is_some());
        let ct_src = global_source(
            "connect_timeout",
            cfg_g.and_then(|c| c.connect_timeout).is_some(),
        );
        let apn_src = global_source(
            "allow_private_network",
            cfg_g.and_then(|c| c.allow_private_network).is_some(),
        );
        let dcm_src = global_source(
            "dns_check_mode",
            cfg_g.and_then(|c| c.dns_check_mode.as_ref()).is_some(),
        );
        let dcd_src = global_source(
            "dns_check_dnssec",
            cfg_g.and_then(|c| c.dns_check_dnssec).is_some(),
        );
        let uh_src = global_source("unsafe_hooks", cfg_g.and_then(|c| c.unsafe_hooks).is_some());

        outln!("[global]");
        outln!("  directory       = {}{}", cli.directory, src(dir_src));
        outln!(
            "  account_key     = {}{}",
            cli.account_key.display(),
            src(key_src)
        );
        outln!(
            "  account_url     = {}{}",
            opt_str(&cli.account_url),
            src(url_src)
        );
        outln!(
            "  output_format   = {}{}",
            if cli.output_format == OutputFormat::Json {
                "json"
            } else {
                "text"
            },
            src(fmt_src)
        );
        outln!("  insecure        = {}{}", cli.insecure, src(ins_src));
        outln!("  connect_timeout = {}{}", cli.connect_timeout, src(ct_src));
        outln!(
            "  allow_private_network = {}{}",
            cli.allow_private_network,
            src(apn_src)
        );
        outln!(
            "  dns_check_mode  = {:?}{}",
            cli.dns_check_mode,
            src(dcm_src)
        );
        outln!(
            "  dns_check_dnssec = {}{}",
            cli.dns_check_dnssec,
            src(dcd_src)
        );
        outln!("  unsafe_hooks    = {}{}", cli.unsafe_hooks, src(uh_src));

        if let Some(r) = cfg_run {
            outln!();
            outln!("[run]");
            outln!(
                "  domains            = {:?}{}",
                r.domains.as_deref().unwrap_or(&[]),
                src(cfg_source(r.domains.is_some()))
            );
            outln!(
                "  contact            = {}{}",
                opt_str(&r.contact),
                src(cfg_source(r.contact.is_some()))
            );
            outln!(
                "  challenge_type     = {}{}",
                r.challenge_type.as_deref().unwrap_or("http-01"),
                src(cfg_source(r.challenge_type.is_some()))
            );
            outln!(
                "  http_port          = {}{}",
                opt_u16(r.http_port),
                src(cfg_source(r.http_port.is_some()))
            );
            outln!(
                "  challenge_dir      = {}{}",
                opt_path(&r.challenge_dir),
                src(cfg_source(r.challenge_dir.is_some()))
            );
            outln!(
                "  dns_hook           = {}{}",
                opt_path(&r.dns_hook),
                src(cfg_source(r.dns_hook.is_some()))
            );
            outln!(
                "  dns_wait           = {}{}",
                opt_u64(r.dns_wait),
                src(cfg_source(r.dns_wait.is_some()))
            );
            outln!(
                "  dns_propagation_concurrency = {}{}",
                r.dns_propagation_concurrency.unwrap_or(5),
                src(cfg_source(r.dns_propagation_concurrency.is_some()))
            );
            outln!(
                "  challenge_timeout  = {}{}",
                r.challenge_timeout.unwrap_or(300),
                src(cfg_source(r.challenge_timeout.is_some()))
            );
            outln!(
                "  cert_output        = {}{}",
                r.cert_output
                    .as_ref()
                    .map_or("certificate.pem".to_string(), |p| p.display().to_string()),
                src(cfg_source(r.cert_output.is_some()))
            );
            outln!(
                "  key_output         = {}{}",
                r.key_output
                    .as_ref()
                    .map_or("private.key".to_string(), |p| p.display().to_string()),
                src(cfg_source(r.key_output.is_some()))
            );
            outln!(
                "  days               = {}{}",
                opt_u32(r.days),
                src(cfg_source(r.days.is_some()))
            );
            outln!(
                "  key_password_file  = {}{}",
                opt_path(&r.key_password_file),
                src(cfg_source(r.key_password_file.is_some()))
            );
            outln!(
                "  on_challenge_ready = {}{}",
                opt_path(&r.on_challenge_ready),
                src(cfg_source(r.on_challenge_ready.is_some()))
            );
            outln!(
                "  on_cert_issued     = {}{}",
                opt_path(&r.on_cert_issued),
                src(cfg_source(r.on_cert_issued.is_some()))
            );
            outln!(
                "  eab_kid            = {}{}",
                opt_str(&r.eab_kid),
                src(cfg_source(r.eab_kid.is_some()))
            );
            outln!(
                "  eab_hmac_key       = {}{}",
                opt_secret_string(&r.eab_hmac_key),
                src(cfg_source(r.eab_hmac_key.is_some()))
            );
            outln!(
                "  pre_authorize      = {}{}",
                opt_bool(r.pre_authorize),
                src(cfg_source(r.pre_authorize.is_some()))
            );
            outln!(
                "  ari                = {}{}",
                opt_bool(r.ari),
                src(cfg_source(r.ari.is_some()))
            );
            outln!(
                "  reissue_on_mismatch = {}{}",
                opt_bool(r.reissue_on_mismatch),
                src(cfg_source(r.reissue_on_mismatch.is_some()))
            );
            outln!(
                "  print_cert         = {}{}",
                opt_bool(r.print_cert),
                src(cfg_source(r.print_cert.is_some()))
            );
            outln!(
                "  persist_policy     = {}{}",
                opt_str(&r.persist_policy),
                src(cfg_source(r.persist_policy.is_some()))
            );
            outln!(
                "  persist_until      = {}{}",
                opt_u64(r.persist_until),
                src(cfg_source(r.persist_until.is_some()))
            );
            outln!(
                "  cert_key_algorithm = {}{}",
                r.cert_key_algorithm.as_deref().unwrap_or("ec-p256"),
                src(cfg_source(r.cert_key_algorithm.is_some()))
            );
            outln!(
                "  profile            = {}{}",
                opt_str(&r.profile),
                src(cfg_source(r.profile.is_some()))
            );
        } else if !has_config {
            outln!();
            outln!("[run]");
            outln!("  (no config file loaded - all values from defaults)");
        }

        if let Some(a) = cfg_acct {
            outln!();
            outln!("[account]");
            outln!(
                "  contact      = {:?}{}",
                a.contact.as_deref().unwrap_or(&[]),
                src(cfg_source(a.contact.is_some()))
            );
            outln!(
                "  eab_kid      = {}{}",
                opt_str(&a.eab_kid),
                src(cfg_source(a.eab_kid.is_some()))
            );
            outln!(
                "  eab_hmac_key = {}{}",
                opt_secret_string(&a.eab_hmac_key),
                src(cfg_source(a.eab_hmac_key.is_some()))
            );
        }
    }
    Ok(())
}
