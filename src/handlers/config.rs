//! Configuration subcommands (generate-config, show-config).

use std::path::PathBuf;

use anyhow::Result;
use clap::parser::ValueSource;
use secrecy::{ExposeSecret, SecretString};

use crate::cli::{Cli, OutputFormat};
use crate::defaults;
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
    let ctx = RenderContext {
        cli,
        loaded_config,
        matches,
        verbose,
        show_secrets,
        config_mode,
        config_path: cli.config.as_ref().map(|p| p.display().to_string()),
    };
    if cli.output_format == OutputFormat::Json {
        render_json(&ctx)
    } else {
        render_text(&ctx)
    }
}

// ─── Shared rendering context ─────────────────────────────────────────────────

struct RenderContext<'a> {
    cli: &'a Cli,
    loaded_config: Option<&'a crate::config::Config>,
    matches: &'a clap::ArgMatches,
    verbose: bool,
    show_secrets: bool,
    config_mode: bool,
    config_path: Option<String>,
}

impl RenderContext<'_> {
    fn cfg_g(&self) -> Option<&crate::config::GlobalConfig> {
        self.loaded_config.map(|c| &c.global)
    }
    fn cfg_run(&self) -> Option<&crate::config::RunConfig> {
        self.loaded_config.map(|c| &c.run)
    }
    fn cfg_acct(&self) -> Option<&crate::config::AccountConfig> {
        self.loaded_config.map(|c| &c.account)
    }
    fn has_config(&self) -> bool {
        self.loaded_config.is_some()
    }

    /// Source resolver for a global field (CLI > env/config > default).
    ///
    /// In the new model:
    ///   `config_mode`: CLI > config > default (env ignored except secrets)
    ///   no config:   CLI > env > default
    fn global_source(&self, id: &str, has_config_val: bool) -> &'static str {
        match self.matches.value_source(id) {
            Some(ValueSource::CommandLine) => "cli",
            Some(ValueSource::EnvVariable) if self.config_mode && has_config_val => "config",
            Some(ValueSource::EnvVariable) if self.config_mode => "default",
            Some(ValueSource::EnvVariable) => "env",
            Some(ValueSource::DefaultValue) if has_config_val => "config",
            Some(ValueSource::DefaultValue) => "default",
            _ if has_config_val => "config",
            _ => "default",
        }
    }

    /// Source resolver for a `[run]` or `[account]` config-only field.
    #[allow(clippy::unused_self)]
    fn cfg_source(&self, has_val: bool) -> &'static str {
        if has_val { "config" } else { "default" }
    }

    /// Render an optional secret, honoring `--show-secrets`.
    /// Returns `Some("[REDACTED]" | "<value>")` or `None`.
    fn redact_secret(&self, v: &Option<SecretString>) -> Option<String> {
        match v {
            Some(_) if !self.show_secrets => Some("[REDACTED]".to_string()),
            Some(s) => Some(s.expose_secret().to_string()),
            None => None,
        }
    }

    /// Render an optional secret as a plain string for text output.
    fn opt_secret_string(&self, v: &Option<SecretString>) -> String {
        match v {
            Some(_) if !self.show_secrets => "[REDACTED]".to_string(),
            Some(s) => s.expose_secret().to_string(),
            None => "(not set)".to_string(),
        }
    }

    /// `"  ({src})"` if verbose, else empty - used to annotate text output.
    fn src_annot(&self, s: &str) -> String {
        if self.verbose {
            format!("  ({s})")
        } else {
            String::new()
        }
    }
}

// Stateless display helpers (pure, no context needed).
fn opt_str(v: &Option<String>) -> String {
    v.as_deref().unwrap_or("(not set)").to_string()
}
fn opt_path(v: &Option<PathBuf>) -> String {
    v.as_ref()
        .map_or("(not set)".to_string(), |p| p.display().to_string())
}
fn opt_u64(v: Option<u64>) -> String {
    v.map_or("(not set)".to_string(), |v| v.to_string())
}
fn opt_u32(v: Option<u32>) -> String {
    v.map_or("(not set)".to_string(), |v| v.to_string())
}
fn opt_u16(v: Option<u16>) -> String {
    v.map_or_else(|| defaults::run::HTTP_PORT.to_string(), |v| v.to_string())
}
fn opt_bool(v: Option<bool>) -> String {
    v.unwrap_or(false).to_string()
}

// ─── JSON renderer ────────────────────────────────────────────────────────────

fn set_source(v: &mut serde_json::Value, key: &str, source: &str) {
    if let Some(obj) = v.as_object_mut()
        && let Some(entry) = obj.get_mut(key)
        && let Some(entry_obj) = entry.as_object_mut()
    {
        entry_obj.insert(
            "source".to_string(),
            serde_json::Value::String(source.to_string()),
        );
    }
}

fn get_value<'a>(v: &'a serde_json::Value, key: &str) -> &'a serde_json::Value {
    v.get(key)
        .and_then(|entry| entry.get("value"))
        .unwrap_or(&serde_json::Value::Null)
}

fn render_json(ctx: &RenderContext<'_>) -> Result<()> {
    let cli = ctx.cli;
    let mut obj = serde_json::json!({
        "command": "show-config",
        "config_file": ctx.config_path,
        "config_mode": ctx.config_mode,
        "verbose": ctx.verbose,
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
    if ctx.verbose {
        let cfg_g = ctx.cfg_g();
        set_source(
            &mut g,
            "directory",
            ctx.global_source(
                "directory",
                cfg_g.and_then(|c| c.directory.as_ref()).is_some(),
            ),
        );
        set_source(
            &mut g,
            "account_key",
            ctx.global_source(
                "account_key",
                cfg_g.and_then(|c| c.account_key.as_ref()).is_some(),
            ),
        );
        set_source(
            &mut g,
            "account_url",
            ctx.global_source(
                "account_url",
                cfg_g.and_then(|c| c.account_url.as_ref()).is_some(),
            ),
        );
        set_source(
            &mut g,
            "output_format",
            ctx.global_source(
                "output_format",
                cfg_g.and_then(|c| c.output_format.as_ref()).is_some(),
            ),
        );
        set_source(
            &mut g,
            "insecure",
            ctx.global_source("insecure", cfg_g.and_then(|c| c.insecure).is_some()),
        );
        set_source(
            &mut g,
            "connect_timeout",
            ctx.global_source(
                "connect_timeout",
                cfg_g.and_then(|c| c.connect_timeout).is_some(),
            ),
        );
        set_source(
            &mut g,
            "allow_private_network",
            ctx.global_source(
                "allow_private_network",
                cfg_g.and_then(|c| c.allow_private_network).is_some(),
            ),
        );
        set_source(
            &mut g,
            "dns_check_mode",
            ctx.global_source(
                "dns_check_mode",
                cfg_g.and_then(|c| c.dns_check_mode.as_ref()).is_some(),
            ),
        );
        set_source(
            &mut g,
            "dns_check_dnssec",
            ctx.global_source(
                "dns_check_dnssec",
                cfg_g.and_then(|c| c.dns_check_dnssec).is_some(),
            ),
        );
        set_source(
            &mut g,
            "unsafe_hooks",
            ctx.global_source("unsafe_hooks", cfg_g.and_then(|c| c.unsafe_hooks).is_some()),
        );
    }
    if let Some(obj_map) = obj.as_object_mut() {
        obj_map.insert("global".to_string(), g);
    }

    if let Some(r) = ctx.cfg_run() {
        let mut rv = serde_json::json!({
            "domains": { "value": r.domains },
            "contact": { "value": r.contact },
            "challenge_type": { "value": r.challenge_type.as_deref().unwrap_or(defaults::run::CHALLENGE_TYPE) },
            "http_port": { "value": r.http_port.unwrap_or(defaults::run::HTTP_PORT) },
            "challenge_dir": { "value": r.challenge_dir.as_ref().map(|p| p.display().to_string()) },
            "dns_hook": { "value": r.dns_hook.as_ref().map(|p| p.display().to_string()) },
            "dns_wait": { "value": r.dns_wait },
            "dns_propagation_concurrency": { "value": r.dns_propagation_concurrency },
            "challenge_timeout": { "value": r.challenge_timeout.unwrap_or(defaults::run::CHALLENGE_TIMEOUT_SECS) },
            "cert_output": { "value": r.cert_output.as_ref().map_or_else(|| defaults::run::CERT_OUTPUT_FILE.to_string(), |p| p.display().to_string()) },
            "key_output": { "value": r.key_output.as_ref().map_or_else(|| defaults::run::KEY_OUTPUT_FILE.to_string(), |p| p.display().to_string()) },
            "days": { "value": r.days },
            "key_password_file": { "value": r.key_password_file.as_ref().map(|p| p.display().to_string()) },
            "on_challenge_ready": { "value": r.on_challenge_ready.as_ref().map(|p| p.display().to_string()) },
            "on_cert_issued": { "value": r.on_cert_issued.as_ref().map(|p| p.display().to_string()) },
            "eab_kid": { "value": r.eab_kid },
            "eab_hmac_key": { "value": ctx.redact_secret(&r.eab_hmac_key) },
            "pre_authorize": { "value": r.pre_authorize.unwrap_or(false) },
            "ari": { "value": r.ari.unwrap_or(false) },
            "reissue_on_mismatch": { "value": r.reissue_on_mismatch.unwrap_or(false) },
            "print_cert": { "value": r.print_cert.unwrap_or(false) },
            "persist_policy": { "value": r.persist_policy },
            "persist_until": { "value": r.persist_until },
            "cert_key_algorithm": { "value": r.cert_key_algorithm.as_deref().unwrap_or(defaults::run::CERT_KEY_ALGORITHM) },
            "profile": { "value": r.profile },
        });
        if ctx.verbose {
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
                let value = get_value(&rv, key);
                let has = !value.is_null()
                    && *value != serde_json::json!(false)
                    && *value != serde_json::json!(defaults::run::CHALLENGE_TYPE)
                    && *value != serde_json::json!(defaults::run::HTTP_PORT)
                    && *value != serde_json::json!(defaults::run::DNS_PROPAGATION_CONCURRENCY)
                    && *value != serde_json::json!(defaults::run::CHALLENGE_TIMEOUT_SECS)
                    && *value != serde_json::json!(defaults::run::CERT_OUTPUT_FILE)
                    && *value != serde_json::json!(defaults::run::KEY_OUTPUT_FILE)
                    && *value != serde_json::json!(defaults::run::CERT_KEY_ALGORITHM);
                set_source(&mut rv, key, ctx.cfg_source(has));
            }
        }
        if let Some(obj_map) = obj.as_object_mut() {
            obj_map.insert("run".to_string(), rv);
        }
    }
    if let Some(a) = ctx.cfg_acct() {
        let mut av = serde_json::json!({
            "contact": { "value": a.contact },
            "eab_kid": { "value": a.eab_kid },
            "eab_hmac_key": { "value": ctx.redact_secret(&a.eab_hmac_key) },
        });
        if ctx.verbose {
            set_source(&mut av, "contact", ctx.cfg_source(a.contact.is_some()));
            set_source(&mut av, "eab_kid", ctx.cfg_source(a.eab_kid.is_some()));
            set_source(
                &mut av,
                "eab_hmac_key",
                ctx.cfg_source(a.eab_hmac_key.is_some()),
            );
        }
        if let Some(obj_map) = obj.as_object_mut() {
            obj_map.insert("account".to_string(), av);
        }
    }
    outln!("{}", serde_json::to_string_pretty(&obj)?);
    Ok(())
}

// ─── Text renderer ────────────────────────────────────────────────────────────

fn render_text(ctx: &RenderContext<'_>) -> Result<()> {
    let cli = ctx.cli;
    outln!("# Effective configuration");
    if ctx.config_mode {
        outln!("# Mode: config file (env vars ignored except secrets)");
    }
    if ctx.verbose {
        outln!("# Source annotations: (cli) (env) (config) (default)");
    }
    outln!();
    if let Some(p) = &ctx.config_path {
        outln!("Config file: {p}")
    } else {
        outln!("Config file: (none)")
    }
    outln!();

    let cfg_g = ctx.cfg_g();
    let dir_src = ctx.global_source(
        "directory",
        cfg_g.and_then(|c| c.directory.as_ref()).is_some(),
    );
    let key_src = ctx.global_source(
        "account_key",
        cfg_g.and_then(|c| c.account_key.as_ref()).is_some(),
    );
    let url_src = ctx.global_source(
        "account_url",
        cfg_g.and_then(|c| c.account_url.as_ref()).is_some(),
    );
    let fmt_src = ctx.global_source(
        "output_format",
        cfg_g.and_then(|c| c.output_format.as_ref()).is_some(),
    );
    let ins_src = ctx.global_source("insecure", cfg_g.and_then(|c| c.insecure).is_some());
    let ct_src = ctx.global_source(
        "connect_timeout",
        cfg_g.and_then(|c| c.connect_timeout).is_some(),
    );
    let apn_src = ctx.global_source(
        "allow_private_network",
        cfg_g.and_then(|c| c.allow_private_network).is_some(),
    );
    let dcm_src = ctx.global_source(
        "dns_check_mode",
        cfg_g.and_then(|c| c.dns_check_mode.as_ref()).is_some(),
    );
    let dcd_src = ctx.global_source(
        "dns_check_dnssec",
        cfg_g.and_then(|c| c.dns_check_dnssec).is_some(),
    );
    let uh_src = ctx.global_source("unsafe_hooks", cfg_g.and_then(|c| c.unsafe_hooks).is_some());

    outln!("[global]");
    outln!(
        "  directory       = {}{}",
        cli.directory,
        ctx.src_annot(dir_src)
    );
    outln!(
        "  account_key     = {}{}",
        cli.account_key.display(),
        ctx.src_annot(key_src)
    );
    outln!(
        "  account_url     = {}{}",
        opt_str(&cli.account_url),
        ctx.src_annot(url_src)
    );
    outln!(
        "  output_format   = {}{}",
        if cli.output_format == OutputFormat::Json {
            "json"
        } else {
            "text"
        },
        ctx.src_annot(fmt_src)
    );
    outln!(
        "  insecure        = {}{}",
        cli.insecure,
        ctx.src_annot(ins_src)
    );
    outln!(
        "  connect_timeout = {}{}",
        cli.connect_timeout,
        ctx.src_annot(ct_src)
    );
    outln!(
        "  allow_private_network = {}{}",
        cli.allow_private_network,
        ctx.src_annot(apn_src)
    );
    outln!(
        "  dns_check_mode  = {:?}{}",
        cli.dns_check_mode,
        ctx.src_annot(dcm_src)
    );
    outln!(
        "  dns_check_dnssec = {}{}",
        cli.dns_check_dnssec,
        ctx.src_annot(dcd_src)
    );
    outln!(
        "  unsafe_hooks    = {}{}",
        cli.unsafe_hooks,
        ctx.src_annot(uh_src)
    );

    if let Some(r) = ctx.cfg_run() {
        outln!();
        outln!("[run]");
        outln!(
            "  domains            = {:?}{}",
            r.domains.as_deref().unwrap_or(&[]),
            ctx.src_annot(ctx.cfg_source(r.domains.is_some()))
        );
        outln!(
            "  contact            = {}{}",
            opt_str(&r.contact),
            ctx.src_annot(ctx.cfg_source(r.contact.is_some()))
        );
        outln!(
            "  challenge_type     = {}{}",
            r.challenge_type
                .as_deref()
                .unwrap_or(defaults::run::CHALLENGE_TYPE),
            ctx.src_annot(ctx.cfg_source(r.challenge_type.is_some()))
        );
        outln!(
            "  http_port          = {}{}",
            opt_u16(r.http_port),
            ctx.src_annot(ctx.cfg_source(r.http_port.is_some()))
        );
        outln!(
            "  challenge_dir      = {}{}",
            opt_path(&r.challenge_dir),
            ctx.src_annot(ctx.cfg_source(r.challenge_dir.is_some()))
        );
        outln!(
            "  dns_hook           = {}{}",
            opt_path(&r.dns_hook),
            ctx.src_annot(ctx.cfg_source(r.dns_hook.is_some()))
        );
        outln!(
            "  dns_wait           = {}{}",
            opt_u64(r.dns_wait),
            ctx.src_annot(ctx.cfg_source(r.dns_wait.is_some()))
        );
        outln!(
            "  dns_propagation_concurrency = {}{}",
            r.dns_propagation_concurrency
                .unwrap_or(defaults::run::DNS_PROPAGATION_CONCURRENCY),
            ctx.src_annot(ctx.cfg_source(r.dns_propagation_concurrency.is_some()))
        );
        outln!(
            "  challenge_timeout  = {}{}",
            r.challenge_timeout
                .unwrap_or(defaults::run::CHALLENGE_TIMEOUT_SECS),
            ctx.src_annot(ctx.cfg_source(r.challenge_timeout.is_some()))
        );
        outln!(
            "  cert_output        = {}{}",
            r.cert_output.as_ref().map_or_else(
                || defaults::run::CERT_OUTPUT_FILE.to_string(),
                |p| p.display().to_string()
            ),
            ctx.src_annot(ctx.cfg_source(r.cert_output.is_some()))
        );
        outln!(
            "  key_output         = {}{}",
            r.key_output.as_ref().map_or_else(
                || defaults::run::KEY_OUTPUT_FILE.to_string(),
                |p| p.display().to_string()
            ),
            ctx.src_annot(ctx.cfg_source(r.key_output.is_some()))
        );
        outln!(
            "  days               = {}{}",
            opt_u32(r.days),
            ctx.src_annot(ctx.cfg_source(r.days.is_some()))
        );
        outln!(
            "  key_password_file  = {}{}",
            opt_path(&r.key_password_file),
            ctx.src_annot(ctx.cfg_source(r.key_password_file.is_some()))
        );
        outln!(
            "  on_challenge_ready = {}{}",
            opt_path(&r.on_challenge_ready),
            ctx.src_annot(ctx.cfg_source(r.on_challenge_ready.is_some()))
        );
        outln!(
            "  on_cert_issued     = {}{}",
            opt_path(&r.on_cert_issued),
            ctx.src_annot(ctx.cfg_source(r.on_cert_issued.is_some()))
        );
        outln!(
            "  eab_kid            = {}{}",
            opt_str(&r.eab_kid),
            ctx.src_annot(ctx.cfg_source(r.eab_kid.is_some()))
        );
        outln!(
            "  eab_hmac_key       = {}{}",
            ctx.opt_secret_string(&r.eab_hmac_key),
            ctx.src_annot(ctx.cfg_source(r.eab_hmac_key.is_some()))
        );
        outln!(
            "  pre_authorize      = {}{}",
            opt_bool(r.pre_authorize),
            ctx.src_annot(ctx.cfg_source(r.pre_authorize.is_some()))
        );
        outln!(
            "  ari                = {}{}",
            opt_bool(r.ari),
            ctx.src_annot(ctx.cfg_source(r.ari.is_some()))
        );
        outln!(
            "  reissue_on_mismatch = {}{}",
            opt_bool(r.reissue_on_mismatch),
            ctx.src_annot(ctx.cfg_source(r.reissue_on_mismatch.is_some()))
        );
        outln!(
            "  print_cert         = {}{}",
            opt_bool(r.print_cert),
            ctx.src_annot(ctx.cfg_source(r.print_cert.is_some()))
        );
        outln!(
            "  persist_policy     = {}{}",
            opt_str(&r.persist_policy),
            ctx.src_annot(ctx.cfg_source(r.persist_policy.is_some()))
        );
        outln!(
            "  persist_until      = {}{}",
            opt_u64(r.persist_until),
            ctx.src_annot(ctx.cfg_source(r.persist_until.is_some()))
        );
        outln!(
            "  cert_key_algorithm = {}{}",
            r.cert_key_algorithm
                .as_deref()
                .unwrap_or(defaults::run::CERT_KEY_ALGORITHM),
            ctx.src_annot(ctx.cfg_source(r.cert_key_algorithm.is_some()))
        );
        outln!(
            "  profile            = {}{}",
            opt_str(&r.profile),
            ctx.src_annot(ctx.cfg_source(r.profile.is_some()))
        );
    } else if !ctx.has_config() {
        outln!();
        outln!("[run]");
        outln!("  (no config file loaded - all values from defaults)");
    }

    if let Some(a) = ctx.cfg_acct() {
        outln!();
        outln!("[account]");
        outln!(
            "  contact      = {:?}{}",
            a.contact.as_deref().unwrap_or(&[]),
            ctx.src_annot(ctx.cfg_source(a.contact.is_some()))
        );
        outln!(
            "  eab_kid      = {}{}",
            opt_str(&a.eab_kid),
            ctx.src_annot(ctx.cfg_source(a.eab_kid.is_some()))
        );
        outln!(
            "  eab_hmac_key = {}{}",
            ctx.opt_secret_string(&a.eab_hmac_key),
            ctx.src_annot(ctx.cfg_source(a.eab_hmac_key.is_some()))
        );
    }
    Ok(())
}
