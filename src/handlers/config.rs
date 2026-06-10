//! Configuration subcommands (generate-config, show-config).

use std::path::PathBuf;

use anyhow::Result;
use clap::parser::ValueSource;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value as JsonValue;

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
    let ir = build_ir(&ctx);
    if cli.output_format == OutputFormat::Json {
        render_json(&ctx, &ir)
    } else {
        render_text(&ctx, &ir)
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

// ─── Intermediate representation ──────────────────────────────────────────────
//
// One IR shared by both emitters. Each entry carries:
//   * the JSON key / clap arg id (`key`);
//   * the pre-aligned text label (e.g. `"  directory       = "`) — text
//     alignment varies per field, so labels are baked at populate time;
//   * a typed `json_value` (so JSON keeps its booleans/numbers/null/array shape);
//   * a pre-formatted `text_value` (rendered through the redact/opt helpers);
//   * per-format source labels — `Option<&'static str>` so each emitter can
//     decide independently. `None` ≙ no source line emitted.
//
// JSON and text INFER `[run]` sources DIFFERENTLY today (JSON compares the
// rendered value to the per-key default; text uses `Option::is_some` on the
// raw config). The two formats can therefore disagree on a config key set to
// its default — preserved by storing `json_source` and `text_source`
// independently. The golden fixture exercises this with `connect_timeout = 15`.

struct FieldEntry {
    key: &'static str,
    text_label: &'static str,
    json_value: JsonValue,
    text_value: String,
    json_source: Option<&'static str>,
    text_source: Option<&'static str>,
}

struct Ir {
    global: Vec<FieldEntry>,
    run: Option<Vec<FieldEntry>>,
    account: Option<Vec<FieldEntry>>,
}

fn build_ir(ctx: &RenderContext<'_>) -> Ir {
    Ir {
        global: build_global(ctx),
        run: ctx.cfg_run().map(|r| build_run(ctx, r)),
        account: ctx.cfg_acct().map(|a| build_account(ctx, a)),
    }
}

// Conversions from raw types to JSON values.
fn jstr<S: Into<String>>(s: S) -> JsonValue {
    JsonValue::String(s.into())
}
fn jopt_str(s: &Option<String>) -> JsonValue {
    s.as_ref().map_or(JsonValue::Null, |v| jstr(v.clone()))
}
fn jopt_path(p: &Option<PathBuf>) -> JsonValue {
    p.as_ref()
        .map_or(JsonValue::Null, |v| jstr(v.display().to_string()))
}
fn jopt_u64(v: Option<u64>) -> JsonValue {
    v.map_or(JsonValue::Null, |n| JsonValue::Number(n.into()))
}
fn jopt_u32(v: Option<u32>) -> JsonValue {
    v.map_or(JsonValue::Null, |n| JsonValue::Number(n.into()))
}

// Per-field push! macro keeps each section table compact and readable.
// Without it, rustfmt explodes 5-arg `push(...)` calls into 6 lines apiece,
// inflating the section tables to ~140 LOC of pure boilerplate.
macro_rules! field {
    ($vec:ident, $key:literal, $label:literal, $jv:expr, $tv:expr,
     $jsrc:expr, $tsrc:expr) => {
        $vec.push(FieldEntry {
            key: $key,
            text_label: $label,
            json_value: $jv,
            text_value: $tv,
            json_source: $jsrc,
            text_source: $tsrc,
        });
    };
}

fn build_global(ctx: &RenderContext<'_>) -> Vec<FieldEntry> {
    let cli = ctx.cli;
    let cfg_g = ctx.cfg_g();
    let mut out = Vec::with_capacity(10);
    let src = |key: &'static str, has: bool| ctx.verbose.then(|| ctx.global_source(key, has));

    let dir_has = cfg_g.and_then(|c| c.directory.as_ref()).is_some();
    let key_has = cfg_g.and_then(|c| c.account_key.as_ref()).is_some();
    let url_has = cfg_g.and_then(|c| c.account_url.as_ref()).is_some();
    let fmt_has = cfg_g.and_then(|c| c.output_format.as_ref()).is_some();
    let ins_has = cfg_g.and_then(|c| c.insecure).is_some();
    let ct_has = cfg_g.and_then(|c| c.connect_timeout).is_some();
    let apn_has = cfg_g.and_then(|c| c.allow_private_network).is_some();
    let dcm_has = cfg_g.and_then(|c| c.dns_check_mode.as_ref()).is_some();
    let dcd_has = cfg_g.and_then(|c| c.dns_check_dnssec).is_some();
    let uh_has = cfg_g.and_then(|c| c.unsafe_hooks).is_some();

    let dir = cli.directory.clone();
    let akey = cli.account_key.display().to_string();
    let fmt = if cli.output_format == OutputFormat::Json {
        "json"
    } else {
        "text"
    };
    // Text mode renders Debug form ("Authoritative") — kept verbatim per byte-identity.
    let dcm_text = format!("{:?}", cli.dns_check_mode);
    let dcm_json = dcm_text.to_lowercase();

    field!(
        out,
        "directory",
        "  directory       = ",
        jstr(dir.clone()),
        dir,
        src("directory", dir_has),
        src("directory", dir_has)
    );
    field!(
        out,
        "account_key",
        "  account_key     = ",
        jstr(akey.clone()),
        akey,
        src("account_key", key_has),
        src("account_key", key_has)
    );
    field!(
        out,
        "account_url",
        "  account_url     = ",
        jopt_str(&cli.account_url),
        opt_str(&cli.account_url),
        src("account_url", url_has),
        src("account_url", url_has)
    );
    field!(
        out,
        "output_format",
        "  output_format   = ",
        jstr(fmt),
        fmt.to_string(),
        src("output_format", fmt_has),
        src("output_format", fmt_has)
    );
    field!(
        out,
        "insecure",
        "  insecure        = ",
        JsonValue::Bool(cli.insecure),
        cli.insecure.to_string(),
        src("insecure", ins_has),
        src("insecure", ins_has)
    );
    field!(
        out,
        "connect_timeout",
        "  connect_timeout = ",
        JsonValue::Number(cli.connect_timeout.into()),
        cli.connect_timeout.to_string(),
        src("connect_timeout", ct_has),
        src("connect_timeout", ct_has)
    );
    field!(
        out,
        "allow_private_network",
        "  allow_private_network = ",
        JsonValue::Bool(cli.allow_private_network),
        cli.allow_private_network.to_string(),
        src("allow_private_network", apn_has),
        src("allow_private_network", apn_has)
    );
    field!(
        out,
        "dns_check_mode",
        "  dns_check_mode  = ",
        jstr(dcm_json),
        dcm_text,
        src("dns_check_mode", dcm_has),
        src("dns_check_mode", dcm_has)
    );
    field!(
        out,
        "dns_check_dnssec",
        "  dns_check_dnssec = ",
        JsonValue::Bool(cli.dns_check_dnssec),
        cli.dns_check_dnssec.to_string(),
        src("dns_check_dnssec", dcd_has),
        src("dns_check_dnssec", dcd_has)
    );
    field!(
        out,
        "unsafe_hooks",
        "  unsafe_hooks    = ",
        JsonValue::Bool(cli.unsafe_hooks),
        cli.unsafe_hooks.to_string(),
        src("unsafe_hooks", uh_has),
        src("unsafe_hooks", uh_has)
    );
    out
}

fn build_run(ctx: &RenderContext<'_>, r: &crate::config::RunConfig) -> Vec<FieldEntry> {
    let mut out = Vec::with_capacity(24);

    // Per-format source rules:
    //   JSON: legacy quirk — compare the typed json_value against the
    //   per-key default (`json_value_has_non_default`), preserving the
    //   "default-valued config still annotates as (default)" behaviour.
    //   Text: pure `Option::is_some` on the raw config field.
    let mut push = |key: &'static str,
                    text_label: &'static str,
                    json_value: JsonValue,
                    text_value: String,
                    has_cfg_text: bool| {
        let json_source = ctx
            .verbose
            .then(|| ctx.cfg_source(json_value_has_non_default(&json_value)));
        let text_source = ctx.verbose.then(|| ctx.cfg_source(has_cfg_text));
        out.push(FieldEntry {
            key,
            text_label,
            json_value,
            text_value,
            json_source,
            text_source,
        });
    };

    // Legacy serde-derive shape: None → `null` for JSON; the text emitter
    // still renders `[]` because it goes through Debug formatting on the
    // dereffed slice. Kept asymmetric on purpose for byte-identity.
    push(
        "domains",
        "  domains            = ",
        r.domains.as_ref().map_or(JsonValue::Null, |v| {
            JsonValue::Array(v.iter().map(|s| jstr(s.clone())).collect())
        }),
        format!("{:?}", r.domains.as_deref().unwrap_or(&[])),
        r.domains.is_some(),
    );
    push(
        "contact",
        "  contact            = ",
        jopt_str(&r.contact),
        opt_str(&r.contact),
        r.contact.is_some(),
    );
    let challenge_type = r
        .challenge_type
        .as_deref()
        .unwrap_or(defaults::run::CHALLENGE_TYPE)
        .to_string();
    push(
        "challenge_type",
        "  challenge_type     = ",
        jstr(&challenge_type),
        challenge_type,
        r.challenge_type.is_some(),
    );
    push(
        "http_port",
        "  http_port          = ",
        JsonValue::Number(r.http_port.unwrap_or(defaults::run::HTTP_PORT).into()),
        opt_u16(r.http_port),
        r.http_port.is_some(),
    );
    push(
        "challenge_dir",
        "  challenge_dir      = ",
        jopt_path(&r.challenge_dir),
        opt_path(&r.challenge_dir),
        r.challenge_dir.is_some(),
    );
    push(
        "dns_hook",
        "  dns_hook           = ",
        jopt_path(&r.dns_hook),
        opt_path(&r.dns_hook),
        r.dns_hook.is_some(),
    );
    push(
        "dns_wait",
        "  dns_wait           = ",
        jopt_u64(r.dns_wait),
        opt_u64(r.dns_wait),
        r.dns_wait.is_some(),
    );
    let dns_concurrency = r
        .dns_propagation_concurrency
        .unwrap_or(defaults::run::DNS_PROPAGATION_CONCURRENCY);
    push(
        "dns_propagation_concurrency",
        "  dns_propagation_concurrency = ",
        // Legacy: serializes the raw Option (so None → null), even though
        // the text emitter substitutes the default value when None.
        r.dns_propagation_concurrency
            .map_or(JsonValue::Null, |v| JsonValue::Number(v.into())),
        dns_concurrency.to_string(),
        r.dns_propagation_concurrency.is_some(),
    );
    let challenge_timeout = r
        .challenge_timeout
        .unwrap_or(defaults::run::CHALLENGE_TIMEOUT_SECS);
    push(
        "challenge_timeout",
        "  challenge_timeout  = ",
        JsonValue::Number(challenge_timeout.into()),
        challenge_timeout.to_string(),
        r.challenge_timeout.is_some(),
    );
    let cert_output = r.cert_output.as_ref().map_or_else(
        || defaults::run::CERT_OUTPUT_FILE.to_string(),
        |p| p.display().to_string(),
    );
    push(
        "cert_output",
        "  cert_output        = ",
        jstr(&cert_output),
        cert_output,
        r.cert_output.is_some(),
    );
    let key_output = r.key_output.as_ref().map_or_else(
        || defaults::run::KEY_OUTPUT_FILE.to_string(),
        |p| p.display().to_string(),
    );
    push(
        "key_output",
        "  key_output         = ",
        jstr(&key_output),
        key_output,
        r.key_output.is_some(),
    );
    push(
        "days",
        "  days               = ",
        jopt_u32(r.days),
        opt_u32(r.days),
        r.days.is_some(),
    );
    push(
        "key_password_file",
        "  key_password_file  = ",
        jopt_path(&r.key_password_file),
        opt_path(&r.key_password_file),
        r.key_password_file.is_some(),
    );
    push(
        "on_challenge_ready",
        "  on_challenge_ready = ",
        jopt_path(&r.on_challenge_ready),
        opt_path(&r.on_challenge_ready),
        r.on_challenge_ready.is_some(),
    );
    push(
        "on_cert_issued",
        "  on_cert_issued     = ",
        jopt_path(&r.on_cert_issued),
        opt_path(&r.on_cert_issued),
        r.on_cert_issued.is_some(),
    );
    push(
        "eab_kid",
        "  eab_kid            = ",
        jopt_str(&r.eab_kid),
        opt_str(&r.eab_kid),
        r.eab_kid.is_some(),
    );
    push(
        "eab_hmac_key",
        "  eab_hmac_key       = ",
        ctx.redact_secret(&r.eab_hmac_key)
            .map_or(JsonValue::Null, JsonValue::String),
        ctx.opt_secret_string(&r.eab_hmac_key),
        r.eab_hmac_key.is_some(),
    );
    push(
        "pre_authorize",
        "  pre_authorize      = ",
        JsonValue::Bool(r.pre_authorize.unwrap_or(false)),
        opt_bool(r.pre_authorize),
        r.pre_authorize.is_some(),
    );
    push(
        "ari",
        "  ari                = ",
        JsonValue::Bool(r.ari.unwrap_or(false)),
        opt_bool(r.ari),
        r.ari.is_some(),
    );
    push(
        "reissue_on_mismatch",
        "  reissue_on_mismatch = ",
        JsonValue::Bool(r.reissue_on_mismatch.unwrap_or(false)),
        opt_bool(r.reissue_on_mismatch),
        r.reissue_on_mismatch.is_some(),
    );
    push(
        "print_cert",
        "  print_cert         = ",
        JsonValue::Bool(r.print_cert.unwrap_or(false)),
        opt_bool(r.print_cert),
        r.print_cert.is_some(),
    );
    push(
        "persist_policy",
        "  persist_policy     = ",
        jopt_str(&r.persist_policy),
        opt_str(&r.persist_policy),
        r.persist_policy.is_some(),
    );
    push(
        "persist_until",
        "  persist_until      = ",
        jopt_u64(r.persist_until),
        opt_u64(r.persist_until),
        r.persist_until.is_some(),
    );
    let cert_key_algorithm = r
        .cert_key_algorithm
        .as_deref()
        .unwrap_or(defaults::run::CERT_KEY_ALGORITHM)
        .to_string();
    push(
        "cert_key_algorithm",
        "  cert_key_algorithm = ",
        jstr(&cert_key_algorithm),
        cert_key_algorithm,
        r.cert_key_algorithm.is_some(),
    );
    push(
        "profile",
        "  profile            = ",
        jopt_str(&r.profile),
        opt_str(&r.profile),
        r.profile.is_some(),
    );

    out
}

/// JSON-side source quirk: the legacy renderer decided `(config|default)` by
/// comparing every rendered `[run]` value against ONE keyless chain of ALL
/// `[run]` defaults — not against the field's own default. This false-matches
/// across keys: e.g. `days = 300` collides with the `challenge_timeout` default
/// (300) and annotates `(default)` in verbose JSON while text (`Option::is_some`)
/// says `(config)`. Replicated verbatim — cross-key false matches included —
/// because show-config output is byte-frozen.
fn json_value_has_non_default(value: &JsonValue) -> bool {
    !value.is_null()
        && *value != serde_json::json!(false)
        && *value != serde_json::json!(defaults::run::CHALLENGE_TYPE)
        && *value != serde_json::json!(defaults::run::HTTP_PORT)
        && *value != serde_json::json!(defaults::run::DNS_PROPAGATION_CONCURRENCY)
        && *value != serde_json::json!(defaults::run::CHALLENGE_TIMEOUT_SECS)
        && *value != serde_json::json!(defaults::run::CERT_OUTPUT_FILE)
        && *value != serde_json::json!(defaults::run::KEY_OUTPUT_FILE)
        && *value != serde_json::json!(defaults::run::CERT_KEY_ALGORITHM)
}

fn build_account(ctx: &RenderContext<'_>, a: &crate::config::AccountConfig) -> Vec<FieldEntry> {
    let mut out = Vec::with_capacity(3);
    let mut push = |key: &'static str,
                    text_label: &'static str,
                    json_value: JsonValue,
                    text_value: String,
                    has_cfg: bool| {
        let src = ctx.verbose.then(|| ctx.cfg_source(has_cfg));
        out.push(FieldEntry {
            key,
            text_label,
            json_value,
            text_value,
            json_source: src,
            text_source: src,
        });
    };

    push(
        "contact",
        "  contact      = ",
        a.contact.as_ref().map_or(JsonValue::Null, |v| {
            JsonValue::Array(v.iter().map(|s| jstr(s.clone())).collect())
        }),
        format!("{:?}", a.contact.as_deref().unwrap_or(&[])),
        a.contact.is_some(),
    );
    push(
        "eab_kid",
        "  eab_kid      = ",
        jopt_str(&a.eab_kid),
        opt_str(&a.eab_kid),
        a.eab_kid.is_some(),
    );
    push(
        "eab_hmac_key",
        "  eab_hmac_key = ",
        ctx.redact_secret(&a.eab_hmac_key)
            .map_or(JsonValue::Null, JsonValue::String),
        ctx.opt_secret_string(&a.eab_hmac_key),
        a.eab_hmac_key.is_some(),
    );

    out
}

// ─── JSON renderer ────────────────────────────────────────────────────────────

fn render_json(ctx: &RenderContext<'_>, ir: &Ir) -> Result<()> {
    // Header keys (insertion order is authoritative under serde_json::Map).
    let mut obj = serde_json::json!({
        "command": "show-config",
        "config_file": ctx.config_path,
        "config_mode": ctx.config_mode,
        "verbose": ctx.verbose,
    });

    // `value` is inserted FIRST so `source` (when present) is appended AFTER —
    // matches the legacy `set_source` ordering.
    let section = |entries: &[FieldEntry]| -> JsonValue {
        let mut sec = serde_json::Map::with_capacity(entries.len());
        for e in entries {
            let mut field = serde_json::Map::with_capacity(2);
            field.insert("value".to_string(), e.json_value.clone());
            if let Some(src) = e.json_source {
                field.insert("source".to_string(), jstr(src));
            }
            sec.insert(e.key.to_string(), JsonValue::Object(field));
        }
        JsonValue::Object(sec)
    };

    if let Some(map) = obj.as_object_mut() {
        map.insert("global".to_string(), section(&ir.global));
        if let Some(run) = &ir.run {
            map.insert("run".to_string(), section(run));
        }
        if let Some(account) = &ir.account {
            map.insert("account".to_string(), section(account));
        }
    }
    outln!("{}", serde_json::to_string_pretty(&obj)?);
    Ok(())
}

// ─── Text renderer ────────────────────────────────────────────────────────────

fn render_text(ctx: &RenderContext<'_>, ir: &Ir) -> Result<()> {
    outln!("# Effective configuration");
    if ctx.config_mode {
        outln!("# Mode: config file (env vars ignored except secrets)");
    }
    if ctx.verbose {
        outln!("# Source annotations: (cli) (env) (config) (default)");
    }
    outln!();
    if let Some(p) = &ctx.config_path {
        outln!("Config file: {p}");
    } else {
        outln!("Config file: (none)");
    }
    outln!();

    let emit_section = |entries: &[FieldEntry]| {
        for e in entries {
            let annot = e.text_source.map_or(String::new(), |s| ctx.src_annot(s));
            outln!("{}{}{}", e.text_label, e.text_value, annot);
        }
    };

    outln!("[global]");
    emit_section(&ir.global);

    if let Some(run) = &ir.run {
        outln!();
        outln!("[run]");
        emit_section(run);
    } else if !ctx.has_config() {
        outln!();
        outln!("[run]");
        outln!("  (no config file loaded - all values from defaults)");
    }

    if let Some(account) = &ir.account {
        outln!();
        outln!("[account]");
        emit_section(account);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use clap::FromArgMatches as _;
    use secrecy::SecretString;

    use super::{RenderContext, build_ir};
    use crate::cli::Cli;
    use crate::config::{AccountConfig, Config, GlobalConfig, RunConfig};

    /// Drive clap end-to-end so `value_source()` lookups behave exactly as in
    /// production — same pattern the `cli_config.rs` tests use.
    fn parse_cli(argv: &[&str]) -> (clap::ArgMatches, Cli) {
        let matches = <Cli as clap::CommandFactory>::command()
            .try_get_matches_from(argv)
            .expect("argv parses");
        let cli = Cli::from_arg_matches(&matches).expect("cli builds");
        (matches, cli)
    }

    #[test]
    fn show_config_redacts_eab_hmac_by_default() {
        // (a) Secret-redaction default: eab_hmac_key renders "[REDACTED]"
        // when show_secrets=false and the secret is set.
        let cfg = Config {
            global: GlobalConfig::default(),
            run: RunConfig {
                eab_hmac_key: Some(SecretString::from("PLAINTEXT-MUST-NOT-LEAK".to_string())),
                ..Default::default()
            },
            account: AccountConfig::default(),
        };
        let (matches, cli) = parse_cli(&["acme-client-rs", "show-config"]);
        let ctx = RenderContext {
            cli: &cli,
            loaded_config: Some(&cfg),
            matches: &matches,
            verbose: true,
            show_secrets: false,
            config_mode: true,
            config_path: None,
        };
        let ir = build_ir(&ctx);
        let run = ir.run.expect("run section populated");
        let entry = run
            .iter()
            .find(|e| e.key == "eab_hmac_key")
            .expect("eab_hmac_key in run IR");
        assert_eq!(entry.text_value, "[REDACTED]");
        assert_eq!(
            entry.json_value,
            serde_json::Value::String("[REDACTED]".to_string())
        );
        // Plaintext must not appear in either rendered shape.
        assert!(!entry.text_value.contains("PLAINTEXT-MUST-NOT-LEAK"));
        let json_str = serde_json::to_string(&entry.json_value).expect("serialize");
        assert!(!json_str.contains("PLAINTEXT-MUST-NOT-LEAK"));
    }

    #[test]
    fn show_config_text_renders_unset_optional_as_not_set() {
        // (b) An unset optional renders "(not set)" in text mode.
        let cfg = Config {
            global: GlobalConfig::default(),
            run: RunConfig {
                contact: None,
                ..Default::default()
            },
            account: AccountConfig::default(),
        };
        let (matches, cli) = parse_cli(&["acme-client-rs", "show-config"]);
        let ctx = RenderContext {
            cli: &cli,
            loaded_config: Some(&cfg),
            matches: &matches,
            verbose: false,
            show_secrets: false,
            config_mode: true,
            config_path: None,
        };
        let ir = build_ir(&ctx);
        let run = ir.run.expect("run section populated");
        let entry = run
            .iter()
            .find(|e| e.key == "contact")
            .expect("contact in run IR");
        assert_eq!(entry.text_value, "(not set)");
    }

    #[test]
    fn show_config_verbose_text_annotation_is_two_spaces_paren_source() {
        // (c) Verbose source annotation format: text annotations are
        // EXACTLY two spaces + "(source)" appended (e.g. `value  (config)`).
        let cfg = Config {
            global: GlobalConfig::default(),
            run: RunConfig {
                challenge_type: Some("dns-01".to_string()),
                ..Default::default()
            },
            account: AccountConfig::default(),
        };
        let (matches, cli) = parse_cli(&["acme-client-rs", "show-config", "--verbose"]);
        let ctx = RenderContext {
            cli: &cli,
            loaded_config: Some(&cfg),
            matches: &matches,
            verbose: true,
            show_secrets: false,
            config_mode: true,
            config_path: None,
        };
        let ir = build_ir(&ctx);
        let run = ir.run.expect("run section populated");
        let entry = run
            .iter()
            .find(|e| e.key == "challenge_type")
            .expect("challenge_type in run IR");
        let label = entry
            .text_source
            .expect("verbose mode populates text_source");
        assert_eq!(label, "config");
        // Annotation appended by render_text is `"  (label)"` —
        // exactly two spaces, then the source label in parentheses.
        let annot = ctx.src_annot(label);
        assert_eq!(annot, "  (config)");
    }

    #[test]
    fn show_config_json_source_quirk_cross_key_default_collision() {
        // (d) Legacy JSON-source quirk lock: the JSON side compares each value
        // against ALL [run] defaults (keyless chain), so days=300 — colliding
        // with the challenge_timeout default (300) — annotates "(default)" in
        // verbose JSON while text (Option::is_some) says "(config)". This
        // byte-frozen divergence is deliberate; do not "fix" it per-key.
        let cfg = Config {
            global: GlobalConfig::default(),
            run: RunConfig {
                days: Some(300),
                ..Default::default()
            },
            account: AccountConfig::default(),
        };
        let (matches, cli) = parse_cli(&["acme-client-rs", "show-config", "--verbose"]);
        let ctx = RenderContext {
            cli: &cli,
            loaded_config: Some(&cfg),
            matches: &matches,
            verbose: true,
            show_secrets: false,
            config_mode: true,
            config_path: None,
        };
        let ir = build_ir(&ctx);
        let run = ir.run.expect("run section populated");
        let entry = run
            .iter()
            .find(|e| e.key == "days")
            .expect("days in run IR");
        assert_eq!(entry.json_source, Some("default"));
        assert_eq!(entry.text_source, Some("config"));
    }
}
