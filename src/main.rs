#![forbid(unsafe_code)]

mod challenge;
mod client;
mod config;
mod jws;
mod types;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use tracing::info;

use crate::client::{AcmeClient, compute_cert_id};
use crate::jws::{AccountKey, KeyAlgorithm};
use crate::types::{
    AuthorizationStatus, Identifier, OrderStatus, CHALLENGE_TYPE_DNS01, CHALLENGE_TYPE_HTTP01,
    CHALLENGE_TYPE_TLSALPN01, CHALLENGE_TYPE_DNS_PERSIST01,
};

/// Output format for command results
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Human-readable text (default)
    Text,
    /// Machine-readable JSON (one object per command)
    Json,
}

/// Certificate key algorithm for CSR generation
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum CertKeyAlgorithm {
    /// ECDSA P-256 with SHA-256 (default)
    #[value(name = "ec-p256")]
    EcP256,
    /// ECDSA P-384 with SHA-384
    #[value(name = "ec-p384")]
    EcP384,
    /// Ed25519
    #[value(name = "ed25519")]
    Ed25519,
}

impl std::fmt::Display for CertKeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EcP256 => write!(f, "ec-p256"),
            Self::EcP384 => write!(f, "ec-p384"),
            Self::Ed25519 => write!(f, "ed25519"),
        }
    }
}

/// Simple ACME client for testing ACME flows (RFC 8555)
#[derive(Parser)]
#[command(name = "acme-client-rs", version, about, after_long_help = "\
Examples:
  # Generate a key and issue a certificate (standalone HTTP-01)
  acme-client-rs generate-key
  acme-client-rs --directory https://acme-server/directory run \\
    --contact you@example.com --challenge-type http-01 your.domain.com

  # Renewal (safe to run daily from cron - skips if not due)
  acme-client-rs --directory https://acme-server/directory run \\
    --contact you@example.com --challenge-type http-01 \\
    --cert-output /etc/ssl/certs/your.domain.pem \\
    --key-output /etc/ssl/private/your.domain.key \\
    --days 30 your.domain.com

  # Use environment variables instead of flags
  export ACME_DIRECTORY_URL=https://acme-server/directory
  export ACME_ACCOUNT_KEY_FILE=/etc/acme/account.key
  acme-client-rs run --contact you@example.com your.domain.com")]
struct Cli {
    /// Path to a TOML config file
    #[arg(long, global = true, env = "ACME_CONFIG")]
    config: Option<PathBuf>,

    /// ACME server directory URL
    #[arg(short = 'd', long, global = true, env = "ACME_DIRECTORY_URL", default_value = "https://localhost:14000/dir")]
    directory: String,

    /// Path to the account key (PKCS#8 PEM)
    #[arg(short = 'k', long, global = true, env = "ACME_ACCOUNT_KEY_FILE", default_value = "account.key")]
    account_key: PathBuf,

    /// Account URL (required after account creation)
    #[arg(short = 'a', long, global = true, env = "ACME_ACCOUNT_URL")]
    account_url: Option<String>,

    /// Output format (text or json)
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text, env = "ACME_OUTPUT_FORMAT")]
    output_format: OutputFormat,

    /// Disable TLS certificate verification (for testing with self-signed CAs like Pebble)
    #[arg(long, global = true, env = "ACME_INSECURE")]
    insecure: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a self-documented TOML config file template
    #[command(after_long_help = "\
Prints a fully commented TOML template to stdout. Redirect to a file to create your config:

  acme-client-rs generate-config > acme-client-rs.toml

Then edit the file and uncomment the options you need. Load it with
--config <PATH> or the ACME_CONFIG environment variable.

Priority without config file: CLI flags > environment variables > built-in defaults.
Priority with config file: CLI flags > config file > built-in defaults
(environment variables are ignored except for secrets like key passwords and EAB).")]
    GenerateConfig,

    /// Show effective configuration (resolved from CLI flags, config file, and/or environment)
    #[command(after_long_help = "\
Shows the resolved configuration after merging all sources.
Use --verbose to see the source of each value (cli, env, config, default).\n\
  acme-client-rs show-config\n\
  acme-client-rs show-config --verbose\n\
  acme-client-rs --config /etc/acme/config.toml show-config\n\
  acme-client-rs show-config --output-format json")]
    ShowConfig {
        /// Show the source of each value (cli, env, config, default)
        #[arg(long)]
        verbose: bool,
    },

    /// Generate a new account key pair
    #[command(after_long_help = "\
Examples:
  # Default algorithm (ES256 / P-256)
  acme-client-rs generate-key

  # Specific algorithm
  acme-client-rs generate-key --algorithm es384
  acme-client-rs generate-key --algorithm rsa4096
  acme-client-rs generate-key --algorithm ed25519

  # Custom key path
  acme-client-rs generate-key --account-key /etc/acme/account.key")]
    GenerateKey {
        /// Key algorithm
        #[arg(long, value_enum, default_value_t = KeyAlgorithm::Es256)]
        algorithm: KeyAlgorithm,
    },

    /// Create (or look up) an ACME account
    #[command(after_long_help = "\
Examples:
  # Register with a contact email
  acme-client-rs --directory https://acme-server/directory \\
    account --contact admin@example.com

  # Look up existing account (no contact = lookup only)
  acme-client-rs --directory https://acme-server/directory account")]
    Account {
        /// Contact email addresses
        #[arg(long)]
        contact: Vec<String>,
        /// Agree to the CA's terms of service
        #[arg(long, default_value_t = true)]
        agree_tos: bool,
        /// EAB Key ID from the CA (for CAs that require External Account Binding)
        #[arg(long, requires = "eab_hmac_key", env = "ACME_EAB_KID")]
        eab_kid: Option<String>,
        /// EAB HMAC key (base64url-encoded, from the CA)
        #[arg(long, requires = "eab_kid", env = "ACME_EAB_HMAC_KEY")]
        eab_hmac_key: Option<String>,
    },

    /// Request a new certificate order
    #[command(after_long_help = "\
Examples:
  # Single domain
  acme-client-rs --directory https://acme-server/directory \\
    --account-url https://acme-server/acme/acct/123 \\
    order example.com

  # Multi-SAN
  acme-client-rs order example.com www.example.com api.example.com")]
    Order {
        /// Domain names to include
        #[arg(required = true)]
        domains: Vec<String>,
    },

    /// Fetch an authorization object
    #[command(after_long_help = "\
Examples:
  acme-client-rs get-authz https://acme-server/acme/authz/abc123")]
    GetAuthz {
        /// Authorization URL
        #[arg(required = true)]
        url: String,
    },

    /// Tell the server a challenge is ready
    #[command(after_long_help = "\
Examples:
  acme-client-rs respond-challenge https://acme-server/acme/chall/xyz789")]
    RespondChallenge {
        /// Challenge URL
        #[arg(required = true)]
        url: String,
    },

    /// Serve an HTTP-01 challenge response
    #[command(after_long_help = "\
Examples:
  # Standalone server on port 80
  acme-client-rs serve-http01 --token <TOKEN>

  # Custom port (ensure port 80 is forwarded)
  acme-client-rs serve-http01 --token <TOKEN> --port 5002

  # Write to webroot instead of starting a server
  acme-client-rs serve-http01 --token <TOKEN> --challenge-dir /var/www/html")]
    ServeHttp01 {
        /// Challenge token
        #[arg(long)]
        token: String,
        /// Port to listen on (standalone mode)
        #[arg(long, default_value_t = 80)]
        port: u16,
        /// Write challenge file to this directory instead of starting a server
        #[arg(long)]
        challenge_dir: Option<PathBuf>,
    },

    /// Show DNS-01 setup instructions
    #[command(after_long_help = "\
Examples:
  acme-client-rs show-dns01 --domain example.com --token <TOKEN>")]
    ShowDns01 {
        /// Domain name
        #[arg(long)]
        domain: String,
        /// Challenge token
        #[arg(long)]
        token: String,
    },

    /// Show DNS-PERSIST-01 setup instructions (draft-ietf-acme-dns-persist)
    #[command(after_long_help = "\
Examples:
  # Basic (FQDN-only authorization)
  acme-client-rs --directory https://acme-server/directory \\
    --account-url https://acme-server/acme/acct/123 \\
    show-dns-persist01 --domain example.com \\
    --issuer-domain-name letsencrypt.org

  # With wildcard policy and expiration
  acme-client-rs show-dns-persist01 --domain example.com \\
    --issuer-domain-name letsencrypt.org \\
    --persist-policy wildcard --persist-until 1767225600")]
    ShowDnsPersist01 {
        /// Domain name
        #[arg(long)]
        domain: String,
        /// Issuer domain name (from the challenge object's issuer-domain-names)
        #[arg(long)]
        issuer_domain_name: String,
        /// Policy parameter (e.g., "wildcard" for wildcard + subdomain scope)
        #[arg(long)]
        persist_policy: Option<String>,
        /// Unix timestamp after which the record should not be used for new validations
        #[arg(long)]
        persist_until: Option<u64>,
    },

    /// Finalize an order with a new CSR
    #[command(after_long_help = "\
Examples:
  acme-client-rs finalize \\
    --finalize-url https://acme-server/acme/order/123/finalize \\
    example.com www.example.com")]
    Finalize {
        /// Order finalize URL
        #[arg(long)]
        finalize_url: String,
        /// Certificate key algorithm (ec-p256 | ec-p384 | ed25519)
        #[arg(long, default_value = "ec-p256")]
        cert_key_algorithm: CertKeyAlgorithm,
        /// Domain names for the CSR
        #[arg(required = true)]
        domains: Vec<String>,
    },

    /// Poll an order's current status
    #[command(after_long_help = "\
Examples:
  acme-client-rs poll-order https://acme-server/acme/order/123")]
    PollOrder {
        /// Order URL
        #[arg(required = true)]
        url: String,
    },

    /// Download the issued certificate
    #[command(after_long_help = "\
Examples:
  acme-client-rs download-cert https://acme-server/acme/cert/abc123

  # Custom output path
  acme-client-rs download-cert https://acme-server/acme/cert/abc123 \\
    --output /etc/ssl/certs/example.com.pem")]
    DownloadCert {
        /// Certificate URL
        #[arg(required = true)]
        url: String,
        /// Output file
        #[arg(long, default_value = "certificate.pem")]
        output: PathBuf,
    },

    /// Deactivate the current account
    #[command(after_long_help = "\
Examples:
  acme-client-rs --directory https://acme-server/directory \\
    --account-url https://acme-server/acme/acct/123 \\
    deactivate-account")]
    DeactivateAccount,

    /// Roll over (rotate) the account key (RFC 8555 Section 7.3.5)
    #[command(after_long_help = "\
Examples:
  # 1. Generate a new key
  acme-client-rs generate-key --account-key new-account.key

  # 2. Roll over (old key signs, new key proves possession)
  acme-client-rs --directory https://acme-server/directory \\
    --account-key old-account.key \\
    --account-url https://acme-server/acme/acct/123 \\
    key-rollover --new-key new-account.key

  # 3. Start using the new key
  mv new-account.key account.key")]
    KeyRollover {
        /// Path to the new account key (PKCS#8 PEM, generate first with generate-key)
        #[arg(long, required = true)]
        new_key: PathBuf,
    },

    /// Pre-authorize an identifier before creating an order (RFC 8555 Section 7.4.1)
    #[command(after_long_help = "\
Examples:
  # Pre-authorize a domain
  acme-client-rs --directory https://acme-server/directory \\
    --account-url https://acme-server/acme/acct/123 \\
    pre-authorize --domain example.com --challenge-type http-01

  # Pre-authorize a wildcard (requires dns-01)
  acme-client-rs pre-authorize --domain '*.example.com' --challenge-type dns-01

Note: Not all ACME servers support pre-authorization.
      The server must advertise a newAuthz URL in its directory.")]
    PreAuthorize {
        /// Domain or IP to pre-authorize
        #[arg(long, required = true)]
        domain: String,
        /// Challenge type to use (http-01 | dns-01 | tls-alpn-01)
        #[arg(long, default_value = "http-01")]
        challenge_type: String,
    },

    /// Revoke a certificate
    #[command(after_long_help = "\
Examples:
  # Revoke without a reason
  acme-client-rs --directory https://acme-server/directory \\
    revoke-cert /etc/ssl/certs/example.com.pem

  # Revoke with reason code (4 = superseded)
  acme-client-rs revoke-cert cert.pem --reason 4

  Reason codes: 0=unspecified, 1=keyCompromise, 3=affiliationChanged,
                4=superseded, 5=cessationOfOperation")]
    RevokeCert {
        /// Path to the certificate PEM
        #[arg(required = true)]
        cert_path: PathBuf,
        /// Revocation reason code (RFC 5280 §5.3.1)
        #[arg(long)]
        reason: Option<u8>,
    },

    /// Query ACME Renewal Information for a certificate (RFC 9702)
    #[command(after_long_help = "\
Examples:
  # Check when a certificate should be renewed
  acme-client-rs --directory https://acme-server/directory \\
    renewal-info certificate.pem

  # Machine-readable output
  acme-client-rs --directory https://acme-server/directory \\
    --output-format json renewal-info certificate.pem

Requires the server to support ARI (renewalInfo in its directory).")]
    RenewalInfo {
        /// Path to the certificate PEM
        #[arg(required = true)]
        cert_path: PathBuf,
    },

    /// Run the full ACME flow end-to-end
    #[command(after_long_help = "\
Examples:
  # HTTP-01 with built-in server on port 80
  acme-client-rs --directory https://acme-server/directory run \\
    --contact admin@example.com --challenge-type http-01 \\
    example.com www.example.com

  # HTTP-01 with existing web server (writes token to webroot)
  acme-client-rs run --contact admin@example.com \\
    --challenge-type http-01 --challenge-dir /var/www/html \\
    --cert-output /etc/ssl/certs/example.com.pem \\
    --key-output /etc/ssl/private/example.com.key \\
    example.com

  # DNS-01 with hook script and propagation check
  acme-client-rs run --contact admin@example.com \\
    --challenge-type dns-01 --dns-hook ./dns-hook.sh --dns-wait 120 \\
    '*.example.com' example.com

  # Renewal mode (skip if cert has >30 days left - safe for cron)
  acme-client-rs run --contact admin@example.com \\
    --cert-output /etc/ssl/certs/example.com.pem \\
    --key-output /etc/ssl/private/example.com.key \\
    --days 30 example.com

  # Encrypt the private key with a password
  acme-client-rs run --contact admin@example.com \\
    --key-password-file /etc/acme/key-password.txt \\
    example.com

  # Hook scripts (called after challenge is ready / after cert is issued)
  acme-client-rs run --contact admin@example.com \\
    --on-challenge-ready ./reload-nginx.sh \\
    --on-cert-issued ./deploy-cert.sh \\
    example.com")]
    Run {
        /// Domain names (can also be set in config file under [run].domains)
        domains: Vec<String>,
        /// Contact email
        #[arg(long)]
        contact: Option<String>,
        /// Challenge type to use (http-01 | dns-01 | tls-alpn-01)
        #[arg(long, default_value = "http-01")]
        challenge_type: String,
        /// HTTP-01 server port (standalone mode)
        #[arg(long, default_value_t = 80)]
        http_port: u16,
        /// Write HTTP-01 challenge files to this directory instead of starting a server
        #[arg(long)]
        challenge_dir: Option<PathBuf>,
        /// Path to a DNS-01 hook script (called with ACME_ACTION=create|cleanup)
        #[arg(long)]
        dns_hook: Option<PathBuf>,
        /// Wait up to N seconds for DNS TXT propagation (polls every 5s)
        #[arg(long)]
        dns_wait: Option<u64>,
        /// Save the certificate to this file
        #[arg(long, default_value = "certificate.pem")]
        cert_output: PathBuf,
        /// Save the private key to this file
        #[arg(long, default_value = "private.key")]
        key_output: PathBuf,
        /// Skip renewal if existing certificate has more than N days remaining
        #[arg(long)]
        days: Option<u32>,
        /// Password to encrypt the private key (visible in process list - prefer --key-password-file)
        #[arg(long, conflicts_with = "key_password_file")]
        key_password: Option<String>,
        /// Read the private key encryption password from a file (first line, trailing newline stripped)
        #[arg(long, conflicts_with = "key_password", env = "ACME_KEY_PASSWORD_FILE")]
        key_password_file: Option<PathBuf>,
        /// Run a script after each challenge is ready for validation
        #[arg(long)]
        on_challenge_ready: Option<PathBuf>,
        /// Run a script after the certificate is issued and saved
        #[arg(long)]
        on_cert_issued: Option<PathBuf>,
        /// EAB Key ID from the CA (for CAs that require External Account Binding)
        #[arg(long, requires = "eab_hmac_key", env = "ACME_EAB_KID")]
        eab_kid: Option<String>,
        /// EAB HMAC key (base64url-encoded, from the CA)
        #[arg(long, requires = "eab_kid", env = "ACME_EAB_HMAC_KEY")]
        eab_hmac_key: Option<String>,
        /// Pre-authorize identifiers via newAuthz before creating the order
        #[arg(long)]
        pre_authorize: bool,
        /// Use ACME Renewal Information (RFC 9702) to decide when to renew
        #[arg(long)]
        ari: bool,
        /// Policy for dns-persist-01 records (e.g., "wildcard" for wildcard + subdomain scope)
        #[arg(long)]
        persist_policy: Option<String>,
        /// Unix timestamp for dns-persist-01 persistUntil parameter
        #[arg(long)]
        persist_until: Option<u64>,
        /// Certificate key algorithm (ec-p256 | ec-p384 | ed25519)
        #[arg(long, default_value = "ec-p256")]
        cert_key_algorithm: CertKeyAlgorithm,
    },
}

// ── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
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

    if let Err(err) = run(cli, loaded_config.as_ref(), &matches, config_mode).await {
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
        Ok((Some(config::Config::load(path)?), true))
    } else {
        Ok((None, false))
    }
}

fn apply_config(cli: &mut Cli, matches: &clap::ArgMatches, config: &config::Config, config_mode: bool) {
    use clap::parser::ValueSource;

    let cfg = &config.global;

    // Helper: in config mode, only CLI overrides config. Env vars are ignored
    // (except for allowed secrets — handled separately).
    // Without config mode, config merges under both env and defaults.
    let should_apply_config = |source: Option<ValueSource>| -> bool {
        match source {
            Some(ValueSource::CommandLine) => false, // CLI always wins
            Some(ValueSource::EnvVariable) if config_mode => true, // config overrides env in config mode
            Some(ValueSource::EnvVariable) => true,  // config also overrides env without config mode
            Some(ValueSource::DefaultValue) => true,  // config overrides defaults
            _ => true,
        }
    };

    // In config mode, strip env values for global fields that are NOT in the
    // allowed-from-env list. The "allowed from env in config mode" set is:
    //   insecure (ACME_INSECURE)
    // All others (directory, account_key, account_url, output_format) are
    // config-only when config_mode is true.
    if config_mode {
        // For fields where clap resolved an env value, warn at debug level
        // and let the config value (or default) take over.
        for (id, env_name) in [
            ("directory", "ACME_DIRECTORY_URL"),
            ("account_key", "ACME_ACCOUNT_KEY_FILE"),
            ("account_url", "ACME_ACCOUNT_URL"),
            ("output_format", "ACME_OUTPUT_FORMAT"),
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
        } else if config_mode && matches.value_source("directory") == Some(ValueSource::EnvVariable) {
            // Reset to default — env var is not allowed in config mode
            cli.directory = "https://localhost:14000/dir".to_string();
        }
    }

    // Global: account_key
    if should_apply_config(matches.value_source("account_key")) {
        if let Some(ref v) = cfg.account_key {
            cli.account_key = v.clone();
        } else if config_mode && matches.value_source("account_key") == Some(ValueSource::EnvVariable) {
            cli.account_key = PathBuf::from("account.key");
        }
    }

    // Global: account_url
    if should_apply_config(matches.value_source("account_url")) {
        if let Some(ref v) = cfg.account_url {
            cli.account_url = Some(v.clone());
        } else if config_mode && matches.value_source("account_url") == Some(ValueSource::EnvVariable) {
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
        } else if config_mode && matches.value_source("output_format") == Some(ValueSource::EnvVariable) {
            cli.output_format = OutputFormat::Text;
        }
    }

    // Global: insecure — ALLOWED from env even in config mode (secret/safety toggle)
    if matches!(matches.value_source("insecure"), Some(ValueSource::DefaultValue) | None) {
        if let Some(v) = cfg.insecure {
            cli.insecure = v;
        }
    }
    // In config mode, if env has ACME_INSECURE but config also sets it, config wins
    // (already handled above: config is applied for DefaultValue).
    // If env has it and config doesn't, env is allowed to survive for insecure.

    // Run subcommand options
    if let Commands::Run {
        ref mut domains,
        ref mut contact,
        ref mut challenge_type,
        ref mut http_port,
        ref mut challenge_dir,
        ref mut dns_hook,
        ref mut dns_wait,
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
        ref mut persist_policy,
        ref mut persist_until,
        ref mut cert_key_algorithm,
        ..
    } = cli.command
    {
        let cfg_run = &config.run;
        if let Some((_, sub_matches)) = matches.subcommand() {
            if should_apply_config(sub_matches.value_source("challenge_type")) {
                if let Some(ref v) = cfg_run.challenge_type {
                    *challenge_type = v.clone();
                }
            }
            if should_apply_config(sub_matches.value_source("http_port")) {
                if let Some(v) = cfg_run.http_port {
                    *http_port = v;
                }
            }
            if should_apply_config(sub_matches.value_source("cert_output")) {
                if let Some(ref v) = cfg_run.cert_output {
                    *cert_output = v.clone();
                }
            }
            if should_apply_config(sub_matches.value_source("key_output")) {
                if let Some(ref v) = cfg_run.key_output {
                    *key_output = v.clone();
                }
            }
            if should_apply_config(sub_matches.value_source("cert_key_algorithm")) {
                if let Some(ref v) = cfg_run.cert_key_algorithm {
                    if let Ok(a) = <CertKeyAlgorithm as clap::ValueEnum>::from_str(v, true) {
                        *cert_key_algorithm = a;
                    }
                }
            }
        }

        // Domains: CLI takes priority, fall back to config
        if domains.is_empty() {
            if let Some(ref v) = cfg_run.domains {
                *domains = v.clone();
            }
        } else if config_mode && cfg_run.domains.as_ref().map_or(true, |d| d.is_empty()) {
            // Domains from CLI but not in config — inform the user
            info!(
                "Using domains from CLI: {:?} (not set in config file)",
                domains
            );
        }

        // Option fields: simple merge (CLI wins if set)
        if contact.is_none() { contact.clone_from(&cfg_run.contact); }
        if challenge_dir.is_none() { challenge_dir.clone_from(&cfg_run.challenge_dir); }
        if dns_hook.is_none() { dns_hook.clone_from(&cfg_run.dns_hook); }
        if dns_wait.is_none() { *dns_wait = cfg_run.dns_wait; }
        if days.is_none() { *days = cfg_run.days; }
        if on_challenge_ready.is_none() { on_challenge_ready.clone_from(&cfg_run.on_challenge_ready); }
        if on_cert_issued.is_none() { on_cert_issued.clone_from(&cfg_run.on_cert_issued); }
        if !*pre_authorize { if cfg_run.pre_authorize == Some(true) { *pre_authorize = true; } }
        if !*ari { if cfg_run.ari == Some(true) { *ari = true; } }
        if persist_policy.is_none() { persist_policy.clone_from(&cfg_run.persist_policy); }
        if persist_until.is_none() { *persist_until = cfg_run.persist_until; }

        // Secrets ALLOWED from env even in config mode:
        //   key_password_file, eab_kid, eab_hmac_key
        if key_password_file.is_none() { key_password_file.clone_from(&cfg_run.key_password_file); }
        if eab_kid.is_none() { eab_kid.clone_from(&cfg_run.eab_kid); }
        if eab_hmac_key.is_none() { eab_hmac_key.clone_from(&cfg_run.eab_hmac_key); }
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
        if contact.is_empty() {
            if let Some(ref v) = cfg_acct.contact {
                *contact = v.clone();
            }
        }
        // Secrets — allowed from env in config mode
        if eab_kid.is_none() { eab_kid.clone_from(&cfg_acct.eab_kid); }
        if eab_hmac_key.is_none() { eab_hmac_key.clone_from(&cfg_acct.eab_hmac_key); }
    }
}

async fn run(cli: Cli, loaded_config: Option<&config::Config>, matches: &clap::ArgMatches, config_mode: bool) -> Result<()> {
    let fmt = cli.output_format;
    match &cli.command {
        Commands::GenerateConfig => cmd_generate_config(),
        Commands::ShowConfig { verbose } => cmd_show_config(&cli, loaded_config, matches, *verbose, config_mode),
        Commands::GenerateKey { algorithm } => cmd_generate_key(&cli.account_key, *algorithm, fmt),
        Commands::Account { contact, agree_tos, eab_kid, eab_hmac_key } => {
            cmd_account(&cli, contact.clone(), *agree_tos, eab_kid.as_deref(), eab_hmac_key.as_deref()).await
        }
        Commands::Order { domains } => cmd_order(&cli, domains.clone()).await,
        Commands::GetAuthz { url } => cmd_get_authz(&cli, url).await,
        Commands::RespondChallenge { url } => cmd_respond_challenge(&cli, url).await,
        Commands::ServeHttp01 { token, port, challenge_dir } => {
            cmd_serve_http01(&cli.account_key, token, *port, challenge_dir.as_deref(), fmt).await
        }
        Commands::ShowDns01 { domain, token } => cmd_show_dns01(&cli.account_key, domain, token, fmt),
        Commands::ShowDnsPersist01 { domain, issuer_domain_name, persist_policy, persist_until } => {
            cmd_show_dns_persist01(&cli, &domain, issuer_domain_name, persist_policy.as_deref(), *persist_until, fmt).await
        }
        Commands::Finalize {
            finalize_url,
            cert_key_algorithm,
            domains,
        } => cmd_finalize(&cli, finalize_url, domains, *cert_key_algorithm).await,
        Commands::PollOrder { url } => cmd_poll_order(&cli, url).await,
        Commands::DownloadCert { url, output } => {
            cmd_download_cert(&cli, url, output).await
        }
        Commands::DeactivateAccount => cmd_deactivate(&cli).await,
        Commands::KeyRollover { new_key } => cmd_key_rollover(&cli, new_key).await,
        Commands::RevokeCert { cert_path, reason } => {
            cmd_revoke(&cli, cert_path, *reason).await
        }
        Commands::RenewalInfo { cert_path } => {
            cmd_renewal_info(&cli, cert_path).await
        }
        Commands::PreAuthorize { domain, challenge_type } => {
            cmd_pre_authorize(&cli, domain, challenge_type).await
        }
        Commands::Run {
            domains,
            contact,
            challenge_type,
            http_port,
            challenge_dir,
            dns_hook,
            dns_wait,
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
            persist_policy,
            persist_until,
            cert_key_algorithm,
        } => {
            anyhow::ensure!(!domains.is_empty(), "at least one domain is required (pass on CLI or set [run].domains in config)");
            cmd_run(
                &cli,
                domains.clone(),
                contact.clone(),
                challenge_type,
                *http_port,
                challenge_dir.as_deref(),
                dns_hook.as_deref(),
                *dns_wait,
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
                persist_policy.as_deref(),
                *persist_until,
                *cert_key_algorithm,
            )
            .await
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Parse a PEM certificate and return the number of days until expiry.
fn cert_days_remaining(path: &std::path::Path) -> Result<i64> {
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

fn load_account_key(path: &PathBuf) -> Result<AccountKey> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read account key from {}", path.display()))?;
    AccountKey::from_pkcs8_pem(&pem)
}

async fn build_client(cli: &Cli) -> Result<AcmeClient> {
    let key = load_account_key(&cli.account_key)?;
    if cli.insecure {
        tracing::warn!("TLS certificate verification is disabled (--insecure)");
    }
    let mut client = AcmeClient::new(&cli.directory, key, cli.insecure).await?;
    if let Some(ref url) = cli.account_url {
        client.set_account_url(url.clone());
    }
    Ok(client)
}

fn generate_csr(domains: &[String], alg: CertKeyAlgorithm) -> Result<(Vec<u8>, String)> {
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
    }.context("failed to generate CSR key pair")?;
    let key_pem = key_pair.serialize_pem();
    let csr = params
        .serialize_request(&key_pair)
        .context("failed to serialize CSR")?;
    Ok((csr.der().to_vec(), key_pem))
}

fn pem_to_der(pem_data: &str) -> Result<Vec<u8>> {
    let parsed = pem::parse(pem_data).context("failed to parse PEM data")?;
    Ok(parsed.contents().to_vec())
}

fn encrypt_private_key(key_pem: &str, password: &str) -> Result<String> {
    let parsed = pem::parse(key_pem).context("failed to parse private key PEM")?;
    let pk_info = pkcs8::PrivateKeyInfo::try_from(parsed.contents())
        .map_err(|e| anyhow::anyhow!("failed to parse PKCS#8 private key: {e}"))?;
    let encrypted_doc = pk_info
        .encrypt(rand_core::OsRng, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to encrypt private key: {e}"))?;
    Ok(pem::encode(&pem::Pem::new(
        "ENCRYPTED PRIVATE KEY",
        encrypted_doc.as_bytes().to_vec(),
    )))
}

// ── Individual command handlers ─────────────────────────────────────────────

fn cmd_generate_config() -> Result<()> {
    print!("{}", config::generate_template());
    Ok(())
}

fn cmd_show_config(cli: &Cli, loaded_config: Option<&config::Config>, matches: &clap::ArgMatches, verbose: bool, config_mode: bool) -> Result<()> {
    use clap::parser::ValueSource;

    let json = cli.output_format == OutputFormat::Json;

    let config_path = if let Some(ref p) = cli.config {
        Some(p.display().to_string())
    } else {
        None
    };
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
    let cfg_source = |has_val: bool| -> &'static str {
        if has_val { "config" } else { "default" }
    };

    let cfg_g = loaded_config.map(|c| &c.global);
    let cfg_run = loaded_config.map(|c| &c.run);
    let cfg_acct = loaded_config.map(|c| &c.account);

    let opt_str = |v: &Option<String>| v.as_deref().unwrap_or("(not set)").to_string();
    let opt_path = |v: &Option<PathBuf>| v.as_ref().map_or("(not set)".to_string(), |p| p.display().to_string());
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
        });
        if verbose {
            g["directory"]["source"] = serde_json::json!(global_source("directory", cfg_g.and_then(|c| c.directory.as_ref()).is_some()));
            g["account_key"]["source"] = serde_json::json!(global_source("account_key", cfg_g.and_then(|c| c.account_key.as_ref()).is_some()));
            g["account_url"]["source"] = serde_json::json!(global_source("account_url", cfg_g.and_then(|c| c.account_url.as_ref()).is_some()));
            g["output_format"]["source"] = serde_json::json!(global_source("output_format", cfg_g.and_then(|c| c.output_format.as_ref()).is_some()));
            g["insecure"]["source"] = serde_json::json!(global_source("insecure", cfg_g.and_then(|c| c.insecure).is_some()));
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
                "cert_output": { "value": r.cert_output.as_ref().map_or("certificate.pem".to_string(), |p| p.display().to_string()) },
                "key_output": { "value": r.key_output.as_ref().map_or("private.key".to_string(), |p| p.display().to_string()) },
                "days": { "value": r.days },
                "key_password_file": { "value": r.key_password_file.as_ref().map(|p| p.display().to_string()) },
                "on_challenge_ready": { "value": r.on_challenge_ready.as_ref().map(|p| p.display().to_string()) },
                "on_cert_issued": { "value": r.on_cert_issued.as_ref().map(|p| p.display().to_string()) },
                "eab_kid": { "value": r.eab_kid },
                "eab_hmac_key": { "value": r.eab_hmac_key },
                "pre_authorize": { "value": r.pre_authorize.unwrap_or(false) },
                "ari": { "value": r.ari.unwrap_or(false) },
                "persist_policy": { "value": r.persist_policy },
                "persist_until": { "value": r.persist_until },
                "cert_key_algorithm": { "value": r.cert_key_algorithm.as_deref().unwrap_or("ec-p256") },
            });
            if verbose {
                for key in ["domains", "contact", "challenge_type", "http_port", "challenge_dir",
                    "dns_hook", "dns_wait", "cert_output", "key_output", "days",
                    "key_password_file", "on_challenge_ready", "on_cert_issued",
                    "eab_kid", "eab_hmac_key", "pre_authorize", "ari",
                    "persist_policy", "persist_until", "cert_key_algorithm"]
                {
                    let has = !rv[key]["value"].is_null()
                        && rv[key]["value"] != serde_json::json!(false)
                        && rv[key]["value"] != serde_json::json!("http-01")
                        && rv[key]["value"] != serde_json::json!(80)
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
                "eab_hmac_key": { "value": a.eab_hmac_key },
            });
            if verbose {
                av["contact"]["source"] = serde_json::json!(cfg_source(a.contact.is_some()));
                av["eab_kid"]["source"] = serde_json::json!(cfg_source(a.eab_kid.is_some()));
                av["eab_hmac_key"]["source"] = serde_json::json!(cfg_source(a.eab_hmac_key.is_some()));
            }
            obj["account"] = av;
        }
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("# Effective configuration");
        if config_mode {
            println!("# Mode: config file (env vars ignored except secrets)");
        }
        if verbose {
            println!("# Source annotations: (cli) (env) (config) (default)");
        }
        println!();
        match &config_path {
            Some(p) => println!("Config file: {p}"),
            None => println!("Config file: (none)"),
        }
        println!();

        let src = |s: &str| if verbose { format!("  ({s})") } else { String::new() };

        let dir_src = global_source("directory", cfg_g.and_then(|c| c.directory.as_ref()).is_some());
        let key_src = global_source("account_key", cfg_g.and_then(|c| c.account_key.as_ref()).is_some());
        let url_src = global_source("account_url", cfg_g.and_then(|c| c.account_url.as_ref()).is_some());
        let fmt_src = global_source("output_format", cfg_g.and_then(|c| c.output_format.as_ref()).is_some());
        let ins_src = global_source("insecure", cfg_g.and_then(|c| c.insecure).is_some());

        println!("[global]");
        println!("  directory     = {}{}", cli.directory, src(dir_src));
        println!("  account_key   = {}{}", cli.account_key.display(), src(key_src));
        println!("  account_url   = {}{}", opt_str(&cli.account_url), src(url_src));
        println!("  output_format = {}{}", if cli.output_format == OutputFormat::Json { "json" } else { "text" }, src(fmt_src));
        println!("  insecure      = {}{}", cli.insecure, src(ins_src));

        if let Some(r) = cfg_run {
            println!();
            println!("[run]");
            println!("  domains            = {:?}{}", r.domains.as_deref().unwrap_or(&[]), src(cfg_source(r.domains.is_some())));
            println!("  contact            = {}{}", opt_str(&r.contact), src(cfg_source(r.contact.is_some())));
            println!("  challenge_type     = {}{}", r.challenge_type.as_deref().unwrap_or("http-01"), src(cfg_source(r.challenge_type.is_some())));
            println!("  http_port          = {}{}", opt_u16(r.http_port), src(cfg_source(r.http_port.is_some())));
            println!("  challenge_dir      = {}{}", opt_path(&r.challenge_dir), src(cfg_source(r.challenge_dir.is_some())));
            println!("  dns_hook           = {}{}", opt_path(&r.dns_hook), src(cfg_source(r.dns_hook.is_some())));
            println!("  dns_wait           = {}{}", opt_u64(r.dns_wait), src(cfg_source(r.dns_wait.is_some())));
            println!("  cert_output        = {}{}", r.cert_output.as_ref().map_or("certificate.pem".to_string(), |p| p.display().to_string()), src(cfg_source(r.cert_output.is_some())));
            println!("  key_output         = {}{}", r.key_output.as_ref().map_or("private.key".to_string(), |p| p.display().to_string()), src(cfg_source(r.key_output.is_some())));
            println!("  days               = {}{}", opt_u32(r.days), src(cfg_source(r.days.is_some())));
            println!("  key_password_file  = {}{}", opt_path(&r.key_password_file), src(cfg_source(r.key_password_file.is_some())));
            println!("  on_challenge_ready = {}{}", opt_path(&r.on_challenge_ready), src(cfg_source(r.on_challenge_ready.is_some())));
            println!("  on_cert_issued     = {}{}", opt_path(&r.on_cert_issued), src(cfg_source(r.on_cert_issued.is_some())));
            println!("  eab_kid            = {}{}", opt_str(&r.eab_kid), src(cfg_source(r.eab_kid.is_some())));
            println!("  eab_hmac_key       = {}{}", opt_str(&r.eab_hmac_key), src(cfg_source(r.eab_hmac_key.is_some())));
            println!("  pre_authorize      = {}{}", opt_bool(r.pre_authorize), src(cfg_source(r.pre_authorize.is_some())));
            println!("  ari                = {}{}", opt_bool(r.ari), src(cfg_source(r.ari.is_some())));
            println!("  persist_policy     = {}{}", opt_str(&r.persist_policy), src(cfg_source(r.persist_policy.is_some())));
            println!("  persist_until      = {}{}", opt_u64(r.persist_until), src(cfg_source(r.persist_until.is_some())));
            println!("  cert_key_algorithm = {}{}", r.cert_key_algorithm.as_deref().unwrap_or("ec-p256"), src(cfg_source(r.cert_key_algorithm.is_some())));
        } else if !has_config {
            println!();
            println!("[run]");
            println!("  (no config file loaded - all values from defaults)");
        }

        if let Some(a) = cfg_acct {
            println!();
            println!("[account]");
            println!("  contact      = {:?}{}", a.contact.as_deref().unwrap_or(&[]), src(cfg_source(a.contact.is_some())));
            println!("  eab_kid      = {}{}", opt_str(&a.eab_kid), src(cfg_source(a.eab_kid.is_some())));
            println!("  eab_hmac_key = {}{}", opt_str(&a.eab_hmac_key), src(cfg_source(a.eab_hmac_key.is_some())));
        }
    }
    Ok(())
}

fn cmd_generate_key(path: &PathBuf, algorithm: KeyAlgorithm, fmt: OutputFormat) -> Result<()> {
    let key = AccountKey::generate(algorithm)?;
    let pem = key.to_pkcs8_pem()?;
    std::fs::write(path, pem.as_bytes())
        .with_context(|| format!("failed to write key to {}", path.display()))?;
    if fmt == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "generate-key",
            "algorithm": format!("{algorithm}"),
            "path": path.display().to_string(),
        }));
    } else {
        println!("{algorithm} account key saved to {}", path.display());
    }
    Ok(())
}

async fn cmd_account(
    cli: &Cli,
    contact: Vec<String>,
    agree_tos: bool,
    eab_kid: Option<&str>,
    eab_hmac_key: Option<&str>,
) -> Result<()> {
    let mut client = build_client(cli).await?;
    let contact = if contact.is_empty() {
        None
    } else {
        Some(contact.into_iter().map(|c| format!("mailto:{c}")).collect())
    };
    let eab = parse_eab(eab_kid, eab_hmac_key)?;
    let eab_ref = eab.as_ref().map(|(kid, key)| (kid.as_str(), key.as_slice()));
    let account = client.create_account(contact, agree_tos, eab_ref).await?;
    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "account",
            "status": format!("{}", account.status),
            "url": client.account_url(),
        }));
    } else {
        println!("Account status: {}", account.status);
        if let Some(url) = client.account_url() {
            println!("Account URL:    {url}");
        }
    }
    Ok(())
}

async fn cmd_order(cli: &Cli, domains: Vec<String>) -> Result<()> {
    let mut client = build_client(cli).await?;
    let ids: Vec<Identifier> = domains.iter().map(|d| Identifier::from_str_auto(d)).collect();
    let (order, order_url) = client.new_order(ids).await?;
    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "order",
            "order_url": order_url,
            "status": format!("{}", order.status),
            "finalize_url": order.finalize,
            "authorizations": order.authorizations,
        }));
    } else {
        println!("Order URL:    {order_url}");
        println!("Status:       {}", order.status);
        println!("Finalize URL: {}", order.finalize);
        for url in &order.authorizations {
            println!("  authz: {url}");
        }
    }
    Ok(())
}

async fn cmd_get_authz(cli: &Cli, url: &str) -> Result<()> {
    let mut client = build_client(cli).await?;
    let authz = client.get_authorization(url).await?;
    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "get-authz",
            "identifier": authz.identifier.value,
            "identifier_type": authz.identifier.identifier_type,
            "status": format!("{}", authz.status),
            "challenges": authz.challenges.iter().map(|ch| serde_json::json!({
                "type": ch.challenge_type,
                "status": format!("{}", ch.status),
                "url": ch.url,
                "token": ch.token,
            })).collect::<Vec<_>>(),
        }));
    } else {
        println!(
            "Identifier: {} ({})",
            authz.identifier.value, authz.identifier.identifier_type
        );
        println!("Status:     {}", authz.status);
        for ch in &authz.challenges {
            println!(
                "  {} [{}] url={}",
                ch.challenge_type, ch.status, ch.url
            );
            if let Some(ref t) = ch.token {
                println!("    token: {t}");
            }
        }
    }
    Ok(())
}

async fn cmd_respond_challenge(cli: &Cli, url: &str) -> Result<()> {
    let mut client = build_client(cli).await?;
    let ch = client.respond_to_challenge(url).await?;
    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "respond-challenge",
            "status": format!("{}", ch.status),
        }));
    } else {
        println!("Challenge status: {}", ch.status);
    }
    Ok(())
}

async fn cmd_serve_http01(
    key_path: &PathBuf,
    token: &str,
    port: u16,
    challenge_dir: Option<&std::path::Path>,
    fmt: OutputFormat,
) -> Result<()> {
    let key = load_account_key(key_path)?;
    if let Some(dir) = challenge_dir {
        let file = challenge::http01::write_challenge_file(dir, token, &key)?;
        if fmt == OutputFormat::Json {
            println!("{}", serde_json::json!({
                "command": "serve-http01",
                "mode": "challenge-dir",
                "path": file.display().to_string(),
            }));
        } else {
            println!("Challenge file written to {}", file.display());
        }
        println!("Press Enter after validation to clean up...");
        let _ = std::io::stdin().read_line(&mut String::new());
        challenge::http01::cleanup_challenge_file(&file);
        Ok(())
    } else {
        challenge::http01::serve(token, &key, port).await
    }
}

fn cmd_show_dns01(key_path: &PathBuf, domain: &str, token: &str, fmt: OutputFormat) -> Result<()> {
    let key = load_account_key(key_path)?;
    if fmt == OutputFormat::Json {
        let name = challenge::dns01::record_name(domain);
        let value = challenge::dns01::txt_record_value(token, &key);
        println!("{}", serde_json::json!({
            "command": "show-dns01",
            "domain": domain,
            "record_name": name,
            "record_type": "TXT",
            "record_value": value,
        }));
    } else {
        challenge::dns01::print_instructions(domain, token, &key);
    }
    Ok(())
}

async fn cmd_show_dns_persist01(
    cli: &Cli,
    domain: &str,
    issuer_domain_name: &str,
    persist_policy: Option<&str>,
    persist_until: Option<u64>,
    fmt: OutputFormat,
) -> Result<()> {
    let mut client = build_client(cli).await?;

    // Need account URL for the accounturi parameter
    if client.account_url().is_none() {
        client.create_account(None, true, None).await?;
    }
    let account_uri = client.account_url()
        .context("account URL not known")?
        .to_string();

    let name = challenge::dns_persist01::record_name(domain);
    let value = challenge::dns_persist01::txt_record_value(
        issuer_domain_name, &account_uri, persist_policy, persist_until,
    );

    if fmt == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "show-dns-persist01",
            "domain": domain,
            "record_name": name,
            "record_type": "TXT",
            "record_value": value,
            "issuer_domain_name": issuer_domain_name,
            "account_uri": account_uri,
            "persist_policy": persist_policy,
            "persist_until": persist_until,
        }));
    } else {
        let issuer_names = vec![issuer_domain_name.to_string()];
        challenge::dns_persist01::print_instructions(
            domain, &issuer_names, &account_uri, persist_policy, persist_until,
        );
    }
    Ok(())
}

async fn cmd_finalize(cli: &Cli, finalize_url: &str, domains: &[String], cert_key_alg: CertKeyAlgorithm) -> Result<()> {
    let mut client = build_client(cli).await?;
    let (csr_der, _key_pem) = generate_csr(domains, cert_key_alg)?;
    let order = client.finalize_order(finalize_url, &csr_der).await?;
    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "finalize",
            "status": format!("{}", order.status),
            "certificate_url": order.certificate,
        }));
    } else {
        println!("Order status: {}", order.status);
        if let Some(ref cert_url) = order.certificate {
            println!("Certificate URL: {cert_url}");
        }
    }
    Ok(())
}

async fn cmd_poll_order(cli: &Cli, url: &str) -> Result<()> {
    let mut client = build_client(cli).await?;
    let order = client.poll_order(url).await?;
    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "poll-order",
            "status": format!("{}", order.status),
            "certificate_url": order.certificate,
        }));
    } else {
        println!("Order status: {}", order.status);
        if let Some(ref cert_url) = order.certificate {
            println!("Certificate URL: {cert_url}");
        }
    }
    Ok(())
}

async fn cmd_download_cert(cli: &Cli, url: &str, output: &PathBuf) -> Result<()> {
    let mut client = build_client(cli).await?;
    let cert = client.download_certificate(url).await?;
    std::fs::write(output, &cert)
        .with_context(|| format!("failed to write certificate to {}", output.display()))?;
    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "download-cert",
            "path": output.display().to_string(),
        }));
    } else {
        println!("Certificate saved to {}", output.display());
    }
    Ok(())
}

async fn cmd_deactivate(cli: &Cli) -> Result<()> {
    let mut client = build_client(cli).await?;
    let account = client.deactivate_account().await?;
    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "deactivate-account",
            "status": format!("{}", account.status),
        }));
    } else {
        println!("Account status: {}", account.status);
    }
    Ok(())
}

async fn cmd_key_rollover(cli: &Cli, new_key_path: &PathBuf) -> Result<()> {
    let new_key = load_account_key(new_key_path)?;
    let mut client = build_client(cli).await?;

    // key-change requires KID signing; look up account if URL not provided
    if client.account_url().is_none() {
        client.create_account(None, true, None).await?;
    }

    client.key_change(&new_key).await?;
    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "key-rollover",
            "new_key": new_key_path.display().to_string(),
        }));
    } else {
        println!("Account key rolled over successfully");
        println!("From now on, use the new key: {}", new_key_path.display());
    }
    Ok(())
}

async fn cmd_revoke(cli: &Cli, cert_path: &PathBuf, reason: Option<u8>) -> Result<()> {
    let mut client = build_client(cli).await?;

    // Revocation with an account key requires KID signing (RFC 8555 §7.6).
    // If no --account-url was provided, look up the existing account first.
    if client.account_url().is_none() {
        client.create_account(None, true, None).await?;
    }

    let pem_data = std::fs::read_to_string(cert_path)
        .with_context(|| format!("failed to read certificate from {}", cert_path.display()))?;
    let cert_der = pem_to_der(&pem_data)?;
    client.revoke_certificate(&cert_der, reason).await?;
    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "revoke-cert",
            "path": cert_path.display().to_string(),
            "reason": reason,
        }));
    } else {
        println!("Certificate revoked");
    }
    Ok(())
}

async fn cmd_renewal_info(cli: &Cli, cert_path: &PathBuf) -> Result<()> {
    let mut client = build_client(cli).await?;

    // ARI GET uses POST-as-GET, which needs KID signing
    if client.account_url().is_none() {
        client.create_account(None, true, None).await?;
    }

    let pem_data = std::fs::read_to_string(cert_path)
        .with_context(|| format!("failed to read certificate from {}", cert_path.display()))?;
    let cert_der = pem_to_der(&pem_data)?;
    let cert_id = compute_cert_id(&cert_der)?;
    let (info, retry_after) = client.get_renewal_info(&cert_der).await?;

    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "renewal-info",
            "cert_id": cert_id,
            "suggested_window": {
                "start": info.suggested_window.start,
                "end": info.suggested_window.end,
            },
            "retry_after": retry_after,
        }));
    } else {
        println!("CertID:   {cert_id}");
        println!("Suggested renewal window:");
        println!("  Start:  {}", info.suggested_window.start);
        println!("  End:    {}", info.suggested_window.end);

        // Show whether renewal is due
        if let Ok(end) = time::OffsetDateTime::parse(
            &info.suggested_window.end,
            &time::format_description::well_known::Rfc3339,
        ) {
            let now = time::OffsetDateTime::now_utc();
            if now >= end {
                println!("Status:   renewal overdue (window has passed)");
            } else if let Ok(start) = time::OffsetDateTime::parse(
                &info.suggested_window.start,
                &time::format_description::well_known::Rfc3339,
            ) {
                if now >= start {
                    println!("Status:   renewal recommended (within window)");
                } else {
                    let until = start - now;
                    println!("Status:   not yet due ({} days until window opens)", until.whole_days());
                }
            }
        }
        if let Some(secs) = retry_after {
            println!("Retry-After: {secs}s");
        }
    }
    Ok(())
}

async fn cmd_pre_authorize(cli: &Cli, domain: &str, challenge_type: &str) -> Result<()> {
    let mut client = build_client(cli).await?;

    // Pre-authorization requires KID signing; look up account if URL not provided
    if client.account_url().is_none() {
        client.create_account(None, true, None).await?;
    }

    let identifier = Identifier::from_str_auto(domain);
    let (authz, authz_url) = client.new_authorization(identifier).await?;

    if cli.output_format == OutputFormat::Json {
        println!("{}", serde_json::json!({
            "command": "pre-authorize",
            "identifier": authz.identifier.value,
            "identifier_type": authz.identifier.identifier_type,
            "status": format!("{}", authz.status),
            "authz_url": authz_url,
            "challenges": authz.challenges.iter().map(|ch| serde_json::json!({
                "type": ch.challenge_type,
                "status": format!("{}", ch.status),
                "url": ch.url,
                "token": ch.token,
            })).collect::<Vec<_>>(),
        }));
    } else {
        println!("Authorization URL: {authz_url}");
        println!("Identifier:  {} ({})", authz.identifier.value, authz.identifier.identifier_type);
        println!("Status:      {}", authz.status);
        for ch in &authz.challenges {
            if ch.challenge_type == challenge_type {
                println!("Challenge ({}):", ch.challenge_type);
                println!("  URL:   {}", ch.url);
                println!("  Status: {}", ch.status);
                if let Some(ref t) = ch.token {
                    println!("  Token: {t}");
                    let key_auth = challenge::key_authorization(t, client.account_key());
                    println!("  Key authorization: {key_auth}");
                }
            }
        }
    }
    Ok(())
}

// ── DNS TXT propagation check (dig with nslookup fallback) ──────────────────

/// Check whether a DNS TXT record with the expected value exists.
/// Tries `dig` first; falls back to `nslookup` if `dig` is not available.
async fn dns_txt_check(name: &str, expected: &str) -> Result<bool> {
    // Try dig first
    match tokio::process::Command::new("dig")
        .args(["+short", "TXT", name])
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Ok(stdout.contains(expected));
        }
        Err(e) => {
            tracing::debug!("dig not available ({e}), falling back to nslookup");
        }
    }

    // Fallback: nslookup (available on Windows by default)
    let output = tokio::process::Command::new("nslookup")
        .args(["-type=TXT", name])
        .output()
        .await
        .context("neither 'dig' nor 'nslookup' is available - cannot check DNS propagation")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains(expected))
}

// ── EAB helper ──────────────────────────────────────────────────────────────

/// Decode the base64url EAB HMAC key and return `(kid, decoded_key)`.
fn parse_eab(
    kid: Option<&str>,
    hmac_key_b64: Option<&str>,
) -> Result<Option<(String, Vec<u8>)>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    match (kid, hmac_key_b64) {
        (Some(kid), Some(key_b64)) => {
            let key_bytes = URL_SAFE_NO_PAD
                .decode(key_b64)
                .context("--eab-hmac-key is not valid base64url")?;
            Ok(Some((kid.to_string(), key_bytes)))
        }
        (None, None) => Ok(None),
        _ => anyhow::bail!("--eab-kid and --eab-hmac-key must both be provided"),
    }
}

// ── Hook helper ─────────────────────────────────────────────────────────────

fn run_hook(
    script: &std::path::Path,
    env_vars: &[(&str, &str)],
) -> Result<()> {
    let mut cmd = std::process::Command::new(script);
    for &(key, val) in env_vars {
        cmd.env(key, val);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to run hook: {}", script.display()))?;
    if !status.success() {
        anyhow::bail!("hook {} exited with {status}", script.display());
    }
    Ok(())
}

// ── Full automated flow ─────────────────────────────────────────────────────

async fn cmd_run(
    cli: &Cli,
    domains: Vec<String>,
    contact: Option<String>,
    challenge_type: &str,
    http_port: u16,
    challenge_dir: Option<&std::path::Path>,
    dns_hook: Option<&std::path::Path>,
    dns_wait: Option<u64>,
    cert_output: &std::path::Path,
    key_output: &std::path::Path,
    days: Option<u32>,
    key_password: Option<&str>,
    key_password_file: Option<&std::path::Path>,
    on_challenge_ready: Option<&std::path::Path>,
    on_cert_issued: Option<&std::path::Path>,
    eab_kid: Option<&str>,
    eab_hmac_key: Option<&str>,
    pre_authorize: bool,
    ari: bool,
    persist_policy: Option<&str>,
    persist_until: Option<u64>,
    cert_key_alg: CertKeyAlgorithm,
) -> Result<()> {
    // ── 0. Renewal check ────────────────────────────────────────────────
    let json = cli.output_format == OutputFormat::Json;

    // Track cert ID for ARI replaceOrder (set during ARI check)
    let mut ari_cert_id: Option<String> = None;

    if cert_output.exists() {
        // ── 0a. ARI-based renewal check (RFC 9702) ─────────────────────
        if ari {
            match std::fs::read_to_string(cert_output) {
                Ok(pem_data) => {
                    match pem_to_der(&pem_data) {
                        Ok(cert_der) => {
                            // We need the client to query ARI, build it early
                            let key = load_account_key(&cli.account_key)?;
                            let mut ari_client = AcmeClient::new(
                                &cli.directory, key, cli.insecure,
                            ).await?;
                            // ARI uses POST-as-GET, needs KID
                            ari_client.create_account(None, true, None).await?;

                            if ari_client.supports_ari() {
                                match ari_client.get_renewal_info(&cert_der).await {
                                    Ok((info, _retry_after)) => {
                                        let now = time::OffsetDateTime::now_utc();
                                        if let Ok(start) = time::OffsetDateTime::parse(
                                            &info.suggested_window.start,
                                            &time::format_description::well_known::Rfc3339,
                                        ) {
                                            if now < start {
                                                if json {
                                                    println!("{}", serde_json::json!({
                                                        "command": "run",
                                                        "action": "skip",
                                                        "reason": "ari",
                                                        "window_start": info.suggested_window.start,
                                                        "window_end": info.suggested_window.end,
                                                        "cert_path": cert_output.display().to_string(),
                                                    }));
                                                } else {
                                                    println!(
                                                        "ARI: renewal window starts {} - skipping renewal",
                                                        info.suggested_window.start
                                                    );
                                                }
                                                return Ok(());
                                            }
                                            if !json {
                                                println!(
                                                    "ARI: renewal window is open ({} - {}), renewing...",
                                                    info.suggested_window.start, info.suggested_window.end
                                                );
                                            }
                                        }
                                        // Set cert_id for replaceOrder
                                        if let Ok(cid) = compute_cert_id(&cert_der) {
                                            ari_cert_id = Some(cid);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("ARI check failed: {e} - falling back to --days check");
                                    }
                                }
                            } else {
                                tracing::warn!("Server does not support ARI - falling back to --days check");
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Could not parse certificate {}: {e}", cert_output.display());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Could not read certificate {}: {e}", cert_output.display());
                }
            }
        }

        // ── 0b. Days-based renewal check (fallback / standalone) ────────
        if ari_cert_id.is_none() {
            if let Some(threshold) = days {
                match cert_days_remaining(cert_output) {
                    Ok(remaining) if remaining > threshold as i64 => {
                        if json {
                            println!("{}", serde_json::json!({
                                "command": "run",
                                "action": "skip",
                                "reason": "days",
                                "days_remaining": remaining,
                                "threshold": threshold,
                                "cert_path": cert_output.display().to_string(),
                            }));
                        } else {
                            println!(
                                "Certificate {} has {remaining} days remaining (threshold: {threshold}), skipping renewal",
                                cert_output.display()
                            );
                        }
                        return Ok(());
                    }
                    Ok(remaining) => {
                        if !json {
                            println!(
                                "Certificate {} expires in {remaining} days (threshold: {threshold}), renewing...",
                                cert_output.display()
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Could not read certificate {}: {e} - proceeding with renewal",
                            cert_output.display()
                        );
                    }
                }
            }
        }
    }

    // ── 1. Account ──────────────────────────────────────────────────────
    info!("Step 1: Creating / looking up account");
    let mut client = build_client(cli).await?;
    let contact_list = contact.map(|c| vec![format!("mailto:{c}")]);
    let eab = parse_eab(eab_kid, eab_hmac_key)?;
    let eab_ref = eab.as_ref().map(|(kid, key)| (kid.as_str(), key.as_slice()));
    let account = client.create_account(contact_list, true, eab_ref).await?;
    if !json {
        println!("Account status: {}", account.status);
    }

    // ── 2. Pre-authorization (optional, RFC 8555 §7.4.1) ───────────────
    if pre_authorize {
        info!("Step 2: Pre-authorizing identifiers via newAuthz");
        let ids: Vec<Identifier> = domains.iter().map(|d| Identifier::from_str_auto(d)).collect();
        for id in ids {
            let domain_display = id.value.clone();
            let (authz, authz_url) = client.new_authorization(id).await?;
            if !json {
                println!("Pre-authorization for {} - status: {}", domain_display, authz.status);
                println!("  Authz URL: {authz_url}");
            }

            if authz.status == AuthorizationStatus::Valid {
                if !json {
                    println!("  Already valid, skipping");
                }
                continue;
            }

            let ch = authz
                .challenges
                .iter()
                .find(|c| c.challenge_type == challenge_type)
                .with_context(|| {
                    format!(
                        "no {challenge_type} challenge for {}",
                        domain_display
                    )
                })?;
            let token = if challenge_type != CHALLENGE_TYPE_DNS_PERSIST01 {
                ch.token.as_deref().context("challenge has no token")?
            } else {
                "" // dns-persist-01 has no token
            };
            let challenge_url = ch.url.clone();

            let mut challenge_file: Option<std::path::PathBuf> = None;
            let mut serve_task: Option<tokio::task::JoinHandle<Result<(), anyhow::Error>>> = None;

            match challenge_type {
                CHALLENGE_TYPE_HTTP01 => {
                    if let Some(dir) = challenge_dir {
                        let file = challenge::http01::write_challenge_file(
                            dir, token, client.account_key(),
                        )?;
                        if !json {
                            println!("  Challenge file written to {}", file.display());
                        }
                        challenge_file = Some(file);
                    } else {
                        if http_port != 80 {
                            tracing::warn!(
                                "HTTP-01 validation targets port 80. Server on port {http_port}."
                            );
                        }
                        let auth = challenge::http01::response_body(token, client.account_key());
                        let path = challenge::http01::challenge_path(token);
                        let listener = challenge::http01::bind_or_suggest(http_port).await?;
                        info!("HTTP-01 server listening on 0.0.0.0:{http_port}");
                        serve_task = Some(tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            loop {
                                let (mut stream, _addr) = listener.accept().await?;
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await?;
                                let req = String::from_utf8_lossy(&buf[..n]);
                                if req.contains(&path) {
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n{}",
                                        auth.len(), auth
                                    );
                                    stream.write_all(resp.as_bytes()).await?;
                                    return Ok(());
                                }
                                stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await?;
                            }
                        }));
                    }
                    client.respond_to_challenge(&challenge_url).await?;
                    if !json {
                        println!("  Challenge response sent - waiting for validation...");
                    }
                }
                CHALLENGE_TYPE_DNS01 => {
                    if authz.identifier.is_ip() {
                        anyhow::bail!(
                            "dns-01 challenges are not supported for IP identifiers ({})",
                            authz.identifier.value
                        );
                    }
                    let txt_name = challenge::dns01::record_name(&authz.identifier.value);
                    let txt_value = challenge::dns01::txt_record_value(token, client.account_key());
                    if let Some(hook) = dns_hook {
                        let status = std::process::Command::new(hook)
                            .env("ACME_DOMAIN", &authz.identifier.value)
                            .env("ACME_TXT_NAME", &txt_name)
                            .env("ACME_TXT_VALUE", &txt_value)
                            .env("ACME_ACTION", "create")
                            .status()
                            .with_context(|| format!("failed to run DNS hook: {}", hook.display()))?;
                        if !status.success() {
                            anyhow::bail!("DNS hook (create) exited with {status}");
                        }
                    } else {
                        challenge::dns01::print_instructions(
                            &authz.identifier.value, token, client.account_key(),
                        );
                    }
                    if let Some(timeout_secs) = dns_wait {
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(timeout_secs);
                        let mut found = false;
                        while std::time::Instant::now() < deadline {
                            if dns_txt_check(&txt_name, &txt_value).await? {
                                found = true;
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                        if !found {
                            if let Some(hook) = dns_hook {
                                match std::process::Command::new(hook)
                                    .env("ACME_DOMAIN", &authz.identifier.value)
                                    .env("ACME_TXT_NAME", &txt_name)
                                    .env("ACME_TXT_VALUE", &txt_value)
                                    .env("ACME_ACTION", "cleanup")
                                    .status()
                                {
                                    Ok(s) if !s.success() => tracing::warn!("DNS hook (cleanup) exited with {s}"),
                                    Err(e) => tracing::warn!("DNS hook (cleanup) failed: {e}"),
                                    _ => {}
                                }
                            }
                            anyhow::bail!(
                                "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                            );
                        }
                    } else if dns_hook.is_none() {
                        println!("Press Enter once the record has propagated...");
                        let _ = std::io::stdin().read_line(&mut String::new());
                    }
                    if let Some(script) = on_challenge_ready {
                        let key_auth = challenge::key_authorization(token, client.account_key());
                        let txt_name_ref = challenge::dns01::record_name(&authz.identifier.value);
                        let txt_value_ref = challenge::dns01::txt_record_value(token, client.account_key());
                        run_hook(script, &[
                            ("ACME_DOMAIN", &authz.identifier.value),
                            ("ACME_CHALLENGE_TYPE", challenge_type),
                            ("ACME_TOKEN", token),
                            ("ACME_KEY_AUTH", &key_auth),
                            ("ACME_TXT_NAME", &txt_name_ref),
                            ("ACME_TXT_VALUE", &txt_value_ref),
                        ])?;
                    }
                    client.respond_to_challenge(&challenge_url).await?;
                }
                CHALLENGE_TYPE_DNS_PERSIST01 => {
                    if authz.identifier.is_ip() {
                        anyhow::bail!(
                            "dns-persist-01 challenges are not supported for IP identifiers ({})",
                            authz.identifier.value
                        );
                    }
                    let issuer_names = ch.issuer_domain_names.as_ref()
                        .context("dns-persist-01 challenge has no issuer-domain-names")?;
                    if issuer_names.is_empty() || issuer_names.len() > 10 {
                        anyhow::bail!("malformed dns-persist-01: issuer-domain-names must have 1-10 entries");
                    }
                    let account_uri = client.account_url()
                        .context("account URL not known - cannot construct dns-persist-01 record")?
                        .to_string();
                    let txt_name = challenge::dns_persist01::record_name(&authz.identifier.value);
                    let txt_value = challenge::dns_persist01::txt_record_value(
                        &issuer_names[0], &account_uri, persist_policy, persist_until,
                    );
                    if let Some(hook) = dns_hook {
                        let status = std::process::Command::new(hook)
                            .env("ACME_DOMAIN", &authz.identifier.value)
                            .env("ACME_TXT_NAME", &txt_name)
                            .env("ACME_TXT_VALUE", &txt_value)
                            .env("ACME_ACTION", "create")
                            .status()
                            .with_context(|| format!("failed to run DNS hook: {}", hook.display()))?;
                        if !status.success() {
                            anyhow::bail!("DNS hook (create) exited with {status}");
                        }
                    } else {
                        challenge::dns_persist01::print_instructions(
                            &authz.identifier.value, issuer_names, &account_uri,
                            persist_policy, persist_until,
                        );
                    }
                    if let Some(timeout_secs) = dns_wait {
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(timeout_secs);
                        let mut found = false;
                        while std::time::Instant::now() < deadline {
                            if dns_txt_check(&txt_name, &txt_value).await? {
                                found = true;
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                        if !found {
                            if let Some(hook) = dns_hook {
                                match std::process::Command::new(hook)
                                    .env("ACME_DOMAIN", &authz.identifier.value)
                                    .env("ACME_TXT_NAME", &txt_name)
                                    .env("ACME_TXT_VALUE", &txt_value)
                                    .env("ACME_ACTION", "cleanup")
                                    .status()
                                {
                                    Ok(s) if !s.success() => tracing::warn!("DNS hook (cleanup) exited with {s}"),
                                    Err(e) => tracing::warn!("DNS hook (cleanup) failed: {e}"),
                                    _ => {}
                                }
                            }
                            anyhow::bail!(
                                "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                            );
                        }
                    } else if dns_hook.is_none() {
                        println!("Press Enter once the record has propagated...");
                        let _ = std::io::stdin().read_line(&mut String::new());
                    }
                    if let Some(script) = on_challenge_ready {
                        run_hook(script, &[
                            ("ACME_DOMAIN", &authz.identifier.value),
                            ("ACME_CHALLENGE_TYPE", challenge_type),
                            ("ACME_TXT_NAME", &txt_name),
                            ("ACME_TXT_VALUE", &txt_value),
                        ])?;
                    }
                    client.respond_to_challenge(&challenge_url).await?;
                }
                CHALLENGE_TYPE_TLSALPN01 => {
                    challenge::tlsalpn01::print_instructions(
                        &authz.identifier.value, token, client.account_key(),
                    );
                    println!("Press Enter once the TLS server is configured...");
                    let _ = std::io::stdin().read_line(&mut String::new());
                    if let Some(script) = on_challenge_ready {
                        let key_auth = challenge::key_authorization(token, client.account_key());
                        run_hook(script, &[
                            ("ACME_DOMAIN", &authz.identifier.value),
                            ("ACME_CHALLENGE_TYPE", challenge_type),
                            ("ACME_TOKEN", token),
                            ("ACME_KEY_AUTH", &key_auth),
                        ])?;
                    }
                    client.respond_to_challenge(&challenge_url).await?;
                }
                other => anyhow::bail!("unsupported challenge type: {other}"),
            }

            // Poll authorization until valid (max 5 minutes)
            let poll_deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(300);
            loop {
                if std::time::Instant::now() > poll_deadline {
                    if let Some(handle) = serve_task.take() { handle.abort(); }
                    if let Some(ref f) = challenge_file { challenge::http01::cleanup_challenge_file(f); }
                    anyhow::bail!(
                        "pre-authorization for {} did not complete within 5 minutes",
                        domain_display
                    );
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let a = client.get_authorization(&authz_url).await?;
                if !json {
                    println!("  Authorization status: {}", a.status);
                }
                if let Some(ch) = a.challenges.iter().find(|c| c.challenge_type == challenge_type) {
                    if let Some(ref err) = ch.error {
                        if let Some(handle) = serve_task.take() { handle.abort(); }
                        if let Some(ref f) = challenge_file { challenge::http01::cleanup_challenge_file(f); }
                        anyhow::bail!("challenge validation failed for {}: {err}", domain_display);
                    }
                }
                match a.status {
                    AuthorizationStatus::Valid => break,
                    AuthorizationStatus::Invalid => {
                        if let Some(handle) = serve_task.take() { handle.abort(); }
                        if let Some(ref f) = challenge_file { challenge::http01::cleanup_challenge_file(f); }
                        let detail = a.challenges.iter()
                            .find(|c| c.challenge_type == challenge_type)
                            .and_then(|c| c.error.as_ref())
                            .map(|e| format!(": {e}"))
                            .unwrap_or_default();
                        anyhow::bail!("pre-authorization failed for {}{detail}", domain_display);
                    }
                    _ => continue,
                }
            }

            // Clean up DNS hook if applicable
            if challenge_type == CHALLENGE_TYPE_DNS01 {
                if let Some(hook) = dns_hook {
                    let txt_name = challenge::dns01::record_name(&domain_display);
                    let txt_value = challenge::dns01::txt_record_value(token, client.account_key());
                    let status = std::process::Command::new(hook)
                        .env("ACME_DOMAIN", &domain_display)
                        .env("ACME_TXT_NAME", &txt_name)
                        .env("ACME_TXT_VALUE", &txt_value)
                        .env("ACME_ACTION", "cleanup")
                        .status();
                    match status {
                        Ok(s) if !s.success() => tracing::warn!("DNS hook (cleanup) exited with {s}"),
                        Err(e) => tracing::warn!("DNS hook (cleanup) failed: {e}"),
                        _ => {}
                    }
                }
            }
            if let Some(handle) = serve_task.take() { handle.abort(); }
            if let Some(ref f) = challenge_file { challenge::http01::cleanup_challenge_file(f); }
        }
        if !json {
            println!("All identifiers pre-authorized");
        }
    }

    // ── 2b. New order ───────────────────────────────────────────────────
    info!("Step {}: Placing order", if pre_authorize { 3 } else { 2 });
    let ids: Vec<Identifier> = domains.iter().map(|d| Identifier::from_str_auto(d)).collect();
    let (order, order_url) = if let Some(ref cert_id) = ari_cert_id {
        info!("Using ARI replaces field (certID: {cert_id})");
        client.new_order_replacing(ids, cert_id.clone()).await?
    } else {
        client.new_order(ids).await?
    };
    if !json {
        println!("Order URL:  {order_url}");
        println!("Order status: {}", order.status);
    }

    // ── Authorizations ──────────────────────────────────────────────────
    info!("Step {}: Completing authorizations", if pre_authorize { 4 } else { 3 });
    for authz_url in &order.authorizations {
        let authz = client.get_authorization(authz_url).await?;
        if !json {
            println!(
                "Authorization for {} - status: {}",
                authz.identifier.value, authz.status
            );
        }

        if authz.status == AuthorizationStatus::Valid {
            if !json {
                println!("  Already valid, skipping");
            }
            continue;
        }

        let ch = authz
            .challenges
            .iter()
            .find(|c| c.challenge_type == challenge_type)
            .with_context(|| {
                format!(
                    "no {challenge_type} challenge for {}",
                    authz.identifier.value
                )
            })?;
        let token = if challenge_type != CHALLENGE_TYPE_DNS_PERSIST01 {
            ch.token.as_deref().context("challenge has no token")?
        } else {
            "" // dns-persist-01 has no token
        };
        let challenge_url = ch.url.clone();

        // Track challenge file for cleanup (file mode only)
        let mut challenge_file: Option<std::path::PathBuf> = None;
        // Background HTTP server handle (standalone mode only)
        let mut serve_task: Option<tokio::task::JoinHandle<Result<(), anyhow::Error>>> = None;

        match challenge_type {
            CHALLENGE_TYPE_HTTP01 => {
                let validation_url = format!(
                    "http://{}/.well-known/acme-challenge/{}",
                    authz.identifier.value, token
                );
                info!("ACME server will validate via: {validation_url}");

                if let Some(dir) = challenge_dir {
                    // File mode: write token file for an existing web server
                    let file = challenge::http01::write_challenge_file(
                        dir,
                        token,
                        client.account_key(),
                    )?;
                if !json {
                    println!("  Challenge file written to {}", file.display());
                }
                    challenge_file = Some(file);
                } else {
                    // Standalone mode: bind a TCP server
                    if http_port != 80 {
                        tracing::warn!(
                            "HTTP-01 validation (RFC 8555 §8.3) always targets port 80.\n  \
                             Your server is listening on port {http_port}.\n  \
                             Ensure traffic to port 80 is forwarded to port {http_port}, \
                             or use --challenge-dir with an existing web server."
                        );
                    }
                    let auth = challenge::http01::response_body(
                        token,
                        client.account_key(),
                    );
                    let path = challenge::http01::challenge_path(token);

                    let listener =
                        challenge::http01::bind_or_suggest(http_port).await?;
                    info!("HTTP-01 server listening on 0.0.0.0:{http_port}");

                    serve_task = Some(tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        loop {
                            let (mut stream, addr) = listener.accept().await?;
                            tracing::debug!("HTTP-01: connection from {addr}");
                            let mut buf = vec![0u8; 4096];
                            let n = stream.read(&mut buf).await?;
                            let req = String::from_utf8_lossy(&buf[..n]);
                            if req.contains(&path) {
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: application/octet-stream\r\n\
                                     Content-Length: {}\r\n\r\n{}",
                                    auth.len(),
                                    auth
                                );
                                stream.write_all(resp.as_bytes()).await?;
                                info!("HTTP-01: served challenge response to {addr}");
                                return Ok(());
                            }
                            let not_found =
                                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                            stream.write_all(not_found.as_bytes()).await?;
                        }
                    }));
                }

                let ch_resp = client.respond_to_challenge(&challenge_url).await?;
                if let Some(ref err) = ch_resp.error {
                    // Server already tried to validate and failed
                    if let Some(handle) = serve_task.take() {
                        handle.abort();
                    }
                    if let Some(ref f) = challenge_file {
                        challenge::http01::cleanup_challenge_file(f);
                    }
                    anyhow::bail!(
                        "HTTP-01 validation failed for {}: {err}\n\n\
                         The ACME server tried to reach:\n  {validation_url}\n\n\
                         Make sure this URL is reachable from the ACME server.\n\
                         If HTTP port 80 is served by a reverse proxy, use:\n  \
                         --challenge-dir <WEBROOT>",
                        authz.identifier.value
                    );
                }
                if !json {
                    println!("  Challenge response sent - waiting for validation...");
                }
            }
            CHALLENGE_TYPE_DNS01 => {
                if authz.identifier.is_ip() {
                    anyhow::bail!(
                        "dns-01 challenges are not supported for IP identifiers ({})",
                        authz.identifier.value
                    );
                }
                let txt_name = challenge::dns01::record_name(&authz.identifier.value);
                let txt_value = challenge::dns01::txt_record_value(token, client.account_key());

                if let Some(hook) = dns_hook {
                    // Hook mode: call script with ACME_ACTION=create
                    info!("Calling DNS hook (create): {}", hook.display());
                    let status = std::process::Command::new(hook)
                        .env("ACME_DOMAIN", &authz.identifier.value)
                        .env("ACME_TXT_NAME", &txt_name)
                        .env("ACME_TXT_VALUE", &txt_value)
                        .env("ACME_ACTION", "create")
                        .status()
                        .with_context(|| format!("failed to run DNS hook: {}", hook.display()))?;
                    if !status.success() {
                        anyhow::bail!("DNS hook (create) exited with {status}");
                    }
                } else {
                    // No hook: print instructions for manual setup
                    challenge::dns01::print_instructions(
                        &authz.identifier.value,
                        token,
                        client.account_key(),
                    );
                }

                if let Some(timeout_secs) = dns_wait {
                    // Poll DNS propagation
                    info!("Waiting up to {timeout_secs}s for DNS TXT propagation...");
                    let deadline = std::time::Instant::now()
                        + std::time::Duration::from_secs(timeout_secs);
                    let mut found = false;
                    while std::time::Instant::now() < deadline {
                        if dns_txt_check(&txt_name, &txt_value).await? {
                            info!("DNS TXT record found");
                            found = true;
                            break;
                        }
                        tracing::debug!("DNS TXT not yet visible, retrying in 5s...");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                    if !found {
                        if let Some(hook) = dns_hook {
                            match std::process::Command::new(hook)
                                .env("ACME_DOMAIN", &authz.identifier.value)
                                .env("ACME_TXT_NAME", &txt_name)
                                .env("ACME_TXT_VALUE", &txt_value)
                                .env("ACME_ACTION", "cleanup")
                                .status()
                            {
                                Ok(s) if !s.success() => tracing::warn!("DNS hook (cleanup) exited with {s}"),
                                Err(e) => tracing::warn!("DNS hook (cleanup) failed: {e}"),
                                _ => {}
                            }
                        }
                        anyhow::bail!(
                            "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                        );
                    }
                } else if dns_hook.is_none() {
                    // Interactive: wait for Enter (no hook + no --dns-wait)
                    println!("Press Enter once the record has propagated...");
                    let _ = std::io::stdin().read_line(&mut String::new());
                }

                if let Some(script) = on_challenge_ready {
                    let key_auth = challenge::key_authorization(token, client.account_key());
                    let txt_name_ref = challenge::dns01::record_name(&authz.identifier.value);
                    let txt_value_ref = challenge::dns01::txt_record_value(token, client.account_key());
                    run_hook(script, &[
                        ("ACME_DOMAIN", &authz.identifier.value),
                        ("ACME_CHALLENGE_TYPE", challenge_type),
                        ("ACME_TOKEN", token),
                        ("ACME_KEY_AUTH", &key_auth),
                        ("ACME_TXT_NAME", &txt_name_ref),
                        ("ACME_TXT_VALUE", &txt_value_ref),
                    ])?;
                }

                client.respond_to_challenge(&challenge_url).await?;
            }
            CHALLENGE_TYPE_DNS_PERSIST01 => {
                if authz.identifier.is_ip() {
                    anyhow::bail!(
                        "dns-persist-01 challenges are not supported for IP identifiers ({})",
                        authz.identifier.value
                    );
                }
                let issuer_names = ch.issuer_domain_names.as_ref()
                    .context("dns-persist-01 challenge has no issuer-domain-names")?;
                if issuer_names.is_empty() || issuer_names.len() > 10 {
                    anyhow::bail!("malformed dns-persist-01: issuer-domain-names must have 1-10 entries");
                }
                let account_uri = client.account_url()
                    .context("account URL not known - cannot construct dns-persist-01 record")?
                    .to_string();
                let txt_name = challenge::dns_persist01::record_name(&authz.identifier.value);
                let txt_value = challenge::dns_persist01::txt_record_value(
                    &issuer_names[0], &account_uri, persist_policy, persist_until,
                );

                if let Some(hook) = dns_hook {
                    info!("Calling DNS hook (create): {}", hook.display());
                    let status = std::process::Command::new(hook)
                        .env("ACME_DOMAIN", &authz.identifier.value)
                        .env("ACME_TXT_NAME", &txt_name)
                        .env("ACME_TXT_VALUE", &txt_value)
                        .env("ACME_ACTION", "create")
                        .status()
                        .with_context(|| format!("failed to run DNS hook: {}", hook.display()))?;
                    if !status.success() {
                        anyhow::bail!("DNS hook (create) exited with {status}");
                    }
                } else {
                    challenge::dns_persist01::print_instructions(
                        &authz.identifier.value, issuer_names, &account_uri,
                        persist_policy, persist_until,
                    );
                }

                if let Some(timeout_secs) = dns_wait {
                    info!("Waiting up to {timeout_secs}s for DNS TXT propagation...");
                    let deadline = std::time::Instant::now()
                        + std::time::Duration::from_secs(timeout_secs);
                    let mut found = false;
                    while std::time::Instant::now() < deadline {
                        if dns_txt_check(&txt_name, &txt_value).await? {
                            info!("DNS TXT record found");
                            found = true;
                            break;
                        }
                        tracing::debug!("DNS TXT not yet visible, retrying in 5s...");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                    if !found {
                        if let Some(hook) = dns_hook {
                            match std::process::Command::new(hook)
                                .env("ACME_DOMAIN", &authz.identifier.value)
                                .env("ACME_TXT_NAME", &txt_name)
                                .env("ACME_TXT_VALUE", &txt_value)
                                .env("ACME_ACTION", "cleanup")
                                .status()
                            {
                                Ok(s) if !s.success() => tracing::warn!("DNS hook (cleanup) exited with {s}"),
                                Err(e) => tracing::warn!("DNS hook (cleanup) failed: {e}"),
                                _ => {}
                            }
                        }
                        anyhow::bail!(
                            "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                        );
                    }
                } else if dns_hook.is_none() {
                    println!("Press Enter once the record has propagated...");
                    let _ = std::io::stdin().read_line(&mut String::new());
                }

                if let Some(script) = on_challenge_ready {
                    run_hook(script, &[
                        ("ACME_DOMAIN", &authz.identifier.value),
                        ("ACME_CHALLENGE_TYPE", challenge_type),
                        ("ACME_TXT_NAME", &txt_name),
                        ("ACME_TXT_VALUE", &txt_value),
                    ])?;
                }

                client.respond_to_challenge(&challenge_url).await?;
            }
            CHALLENGE_TYPE_TLSALPN01 => {
                challenge::tlsalpn01::print_instructions(
                    &authz.identifier.value,
                    token,
                    client.account_key(),
                );
                println!("Press Enter once the TLS server is configured...");
                let _ = std::io::stdin().read_line(&mut String::new());

                if let Some(script) = on_challenge_ready {
                    let key_auth = challenge::key_authorization(token, client.account_key());
                    run_hook(script, &[
                        ("ACME_DOMAIN", &authz.identifier.value),
                        ("ACME_CHALLENGE_TYPE", challenge_type),
                        ("ACME_TOKEN", token),
                        ("ACME_KEY_AUTH", &key_auth),
                    ])?;
                }

                client.respond_to_challenge(&challenge_url).await?;
            }
            other => anyhow::bail!("unsupported challenge type: {other}"),
        }

        // Poll authorization until terminal (max 5 minutes)
        let poll_deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(300);
        loop {
            if std::time::Instant::now() > poll_deadline {
                if let Some(handle) = serve_task.take() {
                    handle.abort();
                }
                if let Some(ref f) = challenge_file {
                    challenge::http01::cleanup_challenge_file(f);
                }
                anyhow::bail!(
                    "authorization for {} did not complete within 5 minutes",
                    authz.identifier.value
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let a = client.get_authorization(authz_url).await?;
            if !json {
                println!("  Authorization status: {}", a.status);
            }

            // Surface challenge-level errors early
            if let Some(ch) = a
                .challenges
                .iter()
                .find(|c| c.challenge_type == challenge_type)
            {
                if let Some(ref err) = ch.error {
                    if let Some(handle) = serve_task.take() {
                        handle.abort();
                    }
                    if let Some(ref f) = challenge_file {
                        challenge::http01::cleanup_challenge_file(f);
                    }
                    anyhow::bail!(
                        "challenge validation failed for {}: {err}",
                        authz.identifier.value
                    );
                }
            }

            match a.status {
                AuthorizationStatus::Valid => break,
                AuthorizationStatus::Invalid => {
                    if let Some(handle) = serve_task.take() {
                        handle.abort();
                    }
                    if let Some(ref f) = challenge_file {
                        challenge::http01::cleanup_challenge_file(f);
                    }
                    let detail = a
                        .challenges
                        .iter()
                        .find(|c| c.challenge_type == challenge_type)
                        .and_then(|c| c.error.as_ref())
                        .map(|e| format!(": {e}"))
                        .unwrap_or_default();
                    anyhow::bail!(
                        "authorization failed for {}{detail}",
                        authz.identifier.value
                    );
                }
                _ => continue,
            }
        }

        // Clean up DNS hook record if applicable
        if challenge_type == CHALLENGE_TYPE_DNS01 {
            if let Some(hook) = dns_hook {
                let token = authz
                    .challenges
                    .iter()
                    .find(|c| c.challenge_type == challenge_type)
                    .and_then(|c| c.token.as_deref())
                    .unwrap_or("");
                let txt_name = challenge::dns01::record_name(&authz.identifier.value);
                let txt_value =
                    challenge::dns01::txt_record_value(token, client.account_key());
                info!("Calling DNS hook (cleanup): {}", hook.display());
                let status = std::process::Command::new(hook)
                    .env("ACME_DOMAIN", &authz.identifier.value)
                    .env("ACME_TXT_NAME", &txt_name)
                    .env("ACME_TXT_VALUE", &txt_value)
                    .env("ACME_ACTION", "cleanup")
                    .status();
                match status {
                    Ok(s) if !s.success() => {
                        tracing::warn!("DNS hook (cleanup) exited with {s}");
                    }
                    Err(e) => {
                        tracing::warn!("DNS hook (cleanup) failed: {e}");
                    }
                    _ => {}
                }
            }
        }

        // Clean up after successful validation
        if let Some(handle) = serve_task.take() {
            handle.abort();
        }
        if let Some(ref f) = challenge_file {
            challenge::http01::cleanup_challenge_file(f);
        }
    }

    // ── Finalize ────────────────────────────────────────────────────────
    info!("Step {}: Finalizing order", if pre_authorize { 5 } else { 4 });
    let (csr_der, key_pem) = generate_csr(&domains, cert_key_alg)?;
    let finalize_url = order.finalize.clone();
    let mut order = client.finalize_order(&finalize_url, &csr_der).await?;
    if !json {
        println!("Order status: {}", order.status);
    }

    // ── Poll order ──────────────────────────────────────────────────────
    info!("Step {}: Waiting for certificate issuance", if pre_authorize { 6 } else { 5 });
    while order.status != OrderStatus::Valid {
        if order.status == OrderStatus::Invalid {
            anyhow::bail!("order became invalid");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        order = client.poll_order(&order_url).await?;
        if !json {
            println!("  Order status: {}", order.status);
        }
    }

    // ── Download certificate ────────────────────────────────────────────
    info!("Step {}: Downloading certificate", if pre_authorize { 7 } else { 6 });
    let cert_url = order
        .certificate
        .context("order is valid but has no certificate URL")?;
    let cert = client.download_certificate(&cert_url).await?;

    let password = if let Some(pw) = key_password {
        Some(pw.to_string())
    } else if let Some(path) = key_password_file {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read password file: {}", path.display()))?;
        Some(content.lines().next().unwrap_or("").to_string())
    } else {
        None
    };

    let key_encrypted = password.is_some();
    if let Some(ref password) = password {
        let encrypted = encrypt_private_key(&key_pem, password)?;
        std::fs::write(key_output, encrypted.as_bytes())
            .with_context(|| format!("failed to write private key to {}", key_output.display()))?;
        if !json {
            println!("Private key saved to {} (encrypted)", key_output.display());
        }
    } else {
        std::fs::write(key_output, key_pem.as_bytes())
            .with_context(|| format!("failed to write private key to {}", key_output.display()))?;
        if !json {
            println!("Private key saved to {}", key_output.display());
        }
    }

    std::fs::write(cert_output, &cert)
        .with_context(|| format!("failed to write certificate to {}", cert_output.display()))?;
    if json {
        println!("{}", serde_json::json!({
            "command": "run",
            "action": "issued",
            "domains": domains,
            "cert_path": cert_output.display().to_string(),
            "key_path": key_output.display().to_string(),
            "key_encrypted": key_encrypted,
        }));
    } else {
        println!("Certificate saved to {}", cert_output.display());
        println!("{cert}");
    }

    if let Some(script) = on_cert_issued {
        let domains_joined = domains.join(",");
        run_hook(script, &[
            ("ACME_DOMAINS", &domains_joined),
            ("ACME_CERT_PATH", &cert_output.display().to_string()),
            ("ACME_KEY_PATH", &key_output.display().to_string()),
            ("ACME_KEY_ENCRYPTED", if key_encrypted { "true" } else { "false" }),
        ])?;
    }

    Ok(())
}

