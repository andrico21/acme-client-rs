//! Command-line interface definitions (clap derive types).
//!
//! Extracted from main.rs to keep entry-point file focused on dispatch and
//! orchestration. Pattern-matching against [`Commands`] variants and field
//! access happens from main.rs; everything declared here is therefore
//! `pub(crate)` (or contains `pub(crate)` fields) rather than fully `pub`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::dns_check::DnsCheckMode;
use crate::jws::KeyAlgorithm;

/// Output format for command results
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    /// Human-readable text (default)
    Text,
    /// Machine-readable JSON (one object per command)
    Json,
}

/// Certificate key algorithm for CSR generation
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum CertKeyAlgorithm {
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

/// Production-ready ACME client for issuing and renewing X.509 certificates (RFC 8555)
#[derive(Parser)]
#[command(
    name = "acme-client-rs",
    version,
    about,
    after_long_help = "\
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
  acme-client-rs run --contact you@example.com your.domain.com"
)]
pub(crate) struct Cli {
    /// Path to a TOML config file
    #[arg(long, global = true, env = "ACME_CONFIG")]
    pub(crate) config: Option<PathBuf>,

    /// ACME server directory URL
    #[arg(
        short = 'd',
        long,
        global = true,
        env = "ACME_DIRECTORY_URL",
        default_value = crate::defaults::global::DIRECTORY_URL
    )]
    pub(crate) directory: String,

    /// Path to the account key (PKCS#8 PEM)
    #[arg(
        short = 'k',
        long,
        global = true,
        env = "ACME_ACCOUNT_KEY_FILE",
        default_value = crate::defaults::global::ACCOUNT_KEY_FILE
    )]
    pub(crate) account_key: PathBuf,

    /// Password to decrypt the account key (visible in process list - prefer --account-key-password-file)
    #[arg(
        long,
        global = true,
        env = "ACME_ACCOUNT_KEY_PASSWORD",
        value_parser = parse_secret_string,
        conflicts_with = "account_key_password_file"
    )]
    pub(crate) account_key_password: Option<secrecy::SecretString>,

    /// Read the account key decryption password from a file (first non-empty line)
    #[arg(
        long,
        global = true,
        env = "ACME_ACCOUNT_KEY_PASSWORD_FILE",
        conflicts_with = "account_key_password"
    )]
    pub(crate) account_key_password_file: Option<PathBuf>,

    /// Account URL (required after account creation)
    #[arg(short = 'a', long, global = true, env = "ACME_ACCOUNT_URL")]
    pub(crate) account_url: Option<String>,

    /// Output format (text or json)
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text, env = "ACME_OUTPUT_FORMAT")]
    pub(crate) output_format: OutputFormat,

    /// Disable TLS certificate verification (for testing with self-signed CAs like Pebble)
    #[arg(long, global = true, env = "ACME_INSECURE")]
    pub(crate) insecure: bool,

    /// HTTP connect timeout in seconds (TCP + TLS handshake). The whole-request timeout is fixed at 120s.
    #[arg(
        long,
        global = true,
        default_value_t = crate::defaults::global::CONNECT_TIMEOUT_SECS,
        env = "ACME_CONNECT_TIMEOUT"
    )]
    pub(crate) connect_timeout: u64,

    /// Allow contacting private/loopback/link-local IP addresses (RFC1918, 127/8, 169.254/16, `::1`, `fc00::/7`, `fe80::/10`, etc.). Default: BLOCK to prevent SSRF. Implied by --insecure. Set this for internal/on-prem ACME deployments.
    #[arg(long, global = true, env = "ACME_ALLOW_PRIVATE_NETWORK")]
    pub(crate) allow_private_network: bool,

    /// Downgrade hook-script ownership/permission violations (SEC-13) from hard errors to stderr warnings. Default: refuse to run if any configured hook is not absolute, not owned by current user or root, group/world-writable, or sits in a group/world-writable directory. Set this only if you accept the privilege-escalation risk.
    #[arg(long, global = true, env = "ACME_UNSAFE_HOOKS")]
    pub(crate) unsafe_hooks: bool,

    /// Resolver strategy for DNS-01 propagation checks. Default `authoritative` queries the zone's NS directly (bypasses caches, matches CA-side reads). `cached` uses public resolvers (1.1.1.1/8.8.8.8/9.9.9.9). `system` uses the host's resolv.conf.
    #[arg(long, global = true, value_enum, default_value_t = DnsCheckMode::Authoritative, env = "ACME_DNS_CHECK_MODE")]
    pub(crate) dns_check_mode: DnsCheckMode,

    /// Enable DNSSEC validation on DNS-01 propagation checks. Off by default (parent-zone DNSSEC misconfig outside our control would cause spurious failures).
    #[arg(long, global = true, env = "ACME_DNS_CHECK_DNSSEC")]
    pub(crate) dns_check_dnssec: bool,

    /// Suppress all stdout output (exit codes still signal success/failure)
    #[arg(long, global = true)]
    pub(crate) silent: bool,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Commands {
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
        /// Print EAB HMAC keys in clear (off by default — secrets are redacted)
        #[arg(long)]
        show_secrets: bool,
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
        /// Overwrite the account key file if it already exists.
        #[arg(long)]
        force: bool,
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
  acme-client-rs order example.com www.example.com api.example.com

  # Select a certificate profile (draft-ietf-acme-profiles-01)
  acme-client-rs order --profile tlsserver example.com")]
    Order {
        /// Domain names to include
        #[arg(required = true)]
        domains: Vec<String>,
        /// Certificate profile (draft-ietf-acme-profiles-01)
        #[arg(long, env = "ACME_PROFILE")]
        profile: Option<String>,
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
  acme-client-rs serve-http-01 --token <TOKEN>

  # Custom port (ensure port 80 is forwarded)
  acme-client-rs serve-http-01 --token <TOKEN> --port 5002

  # Write to webroot instead of starting a server
  acme-client-rs serve-http-01 --token <TOKEN> --challenge-dir /var/www/html")]
    #[command(name = "serve-http-01")]
    ServeHttp01 {
        /// Challenge token
        #[arg(long, value_parser = crate::types::ChallengeToken::parse)]
        token: crate::types::ChallengeToken,
        /// Port to listen on (standalone mode)
        #[arg(long, default_value_t = crate::defaults::run::HTTP_PORT)]
        port: u16,
        /// Write challenge file to this directory instead of starting a server
        #[arg(long)]
        challenge_dir: Option<PathBuf>,
    },

    /// Show DNS-01 setup instructions
    #[command(after_long_help = "\
Examples:
  acme-client-rs show-dns-01 --domain example.com --token <TOKEN>")]
    #[command(name = "show-dns-01")]
    ShowDns01 {
        /// Domain name
        #[arg(long)]
        domain: String,
        /// Challenge token
        #[arg(long, value_parser = crate::types::ChallengeToken::parse)]
        token: crate::types::ChallengeToken,
    },

    /// Show DNS-PERSIST-01 setup instructions (draft-ietf-acme-dns-persist)
    #[command(after_long_help = "\
Examples:
  # Basic (FQDN-only authorization)
  acme-client-rs --directory https://acme-server/directory \\
    --account-url https://acme-server/acme/acct/123 \\
    show-dns-persist-01 --domain example.com \\
    --issuer-domain-name letsencrypt.org

  # With wildcard policy and expiration
  acme-client-rs show-dns-persist-01 --domain example.com \\
    --issuer-domain-name letsencrypt.org \\
    --persist-policy wildcard --persist-until 1767225600")]
    #[command(name = "show-dns-persist-01")]
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
    --key-output /etc/ssl/private/example.com.key \\
    example.com www.example.com")]
    Finalize {
        /// Order finalize URL
        #[arg(long)]
        finalize_url: String,
        /// Certificate key algorithm (ec-p256 | ec-p384 | ed25519)
        #[arg(long, default_value = crate::defaults::run::CERT_KEY_ALGORITHM)]
        cert_key_algorithm: CertKeyAlgorithm,
        // Priority 2 (public API): --key-output is REQUIRED to prevent the
        // SEC-20 footgun where a CSR is submitted to the CA but the freshly
        // generated private key is discarded, leaving an unusable certificate.
        /// Save the generated CSR private key to this file (REQUIRED — without this the issued certificate would be unusable)
        #[arg(long)]
        key_output: PathBuf,
        /// Password to encrypt the private key (visible in process list - prefer --key-password-file)
        #[arg(long, conflicts_with = "key_password_file")]
        key_password: Option<String>,
        /// Read the private key encryption password from a file (first line, trailing newline stripped)
        #[arg(long, conflicts_with = "key_password", env = "ACME_KEY_PASSWORD_FILE")]
        key_password_file: Option<PathBuf>,
        /// Overwrite the private key file if it already exists.
        #[arg(long)]
        force: bool,
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
        #[arg(long, default_value = crate::defaults::run::CERT_OUTPUT_FILE)]
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

        /// Password to decrypt the new account key if it is encrypted (visible in process list - prefer --new-key-password-file)
        #[arg(
            long,
            env = "ACME_NEW_KEY_PASSWORD",
            conflicts_with = "new_key_password_file"
        )]
        new_key_password: Option<String>,

        /// Read the new account key decryption password from a file (first non-empty line)
        #[arg(
            long,
            env = "ACME_NEW_KEY_PASSWORD_FILE",
            conflicts_with = "new_key_password"
        )]
        new_key_password_file: Option<PathBuf>,
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
        /// Challenge type to use (http-01 | dns-01 | tls-alpn-01 | dns-persist-01)
        #[arg(long, default_value = crate::defaults::run::CHALLENGE_TYPE)]
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

    /// Query ACME Renewal Information for a certificate (RFC 9773)
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

    /// List certificate profiles advertised by the ACME server (draft-ietf-acme-profiles-01)
    #[command(after_long_help = "\
Examples:
  # Show profiles from Let's Encrypt production
  acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory \\
    list-profiles

  # Machine-readable output
  acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory \\
    --output-format json list-profiles

Requires the server to advertise profiles in its directory metadata.")]
    ListProfiles,

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
    Run(RunArgs),
}

/// Flattened argument struct for the `run` subcommand.
///
/// Extracted from `Commands::Run { ... }` into a `#[derive(Args)]` struct so
/// the run dispatcher does not need a 30-parameter signature mirrored across
/// three layers. Field-level clap attributes (`#[arg(...)]`, defaults, env
/// vars, conflicts, requires) are preserved verbatim from the original
/// inline-variant form — clap derive behaviour is unchanged.
#[derive(Args)]
pub(crate) struct RunArgs {
    /// Domain names (can also be set in config file under [run].domains)
    pub(crate) domains: Vec<String>,
    /// Contact email
    #[arg(long)]
    pub(crate) contact: Option<String>,
    /// Challenge type to use (http-01 | dns-01 | tls-alpn-01 | dns-persist-01)
    #[arg(long, default_value = crate::defaults::run::CHALLENGE_TYPE)]
    pub(crate) challenge_type: String,
    /// HTTP-01 server port (standalone mode)
    #[arg(long, default_value_t = crate::defaults::run::HTTP_PORT)]
    pub(crate) http_port: u16,
    /// Write HTTP-01 challenge files to this directory instead of starting a server
    #[arg(long)]
    pub(crate) challenge_dir: Option<PathBuf>,
    /// Path to a DNS-01 hook script (called with `ACME_ACTION=create|cleanup`)
    #[arg(long)]
    pub(crate) dns_hook: Option<PathBuf>,
    /// Wait up to N seconds for DNS TXT propagation (polls every 5s)
    #[arg(long)]
    pub(crate) dns_wait: Option<u64>,
    /// Max concurrent DNS propagation checks (default: 5)
    #[arg(long, default_value_t = crate::defaults::run::DNS_PROPAGATION_CONCURRENCY)]
    pub(crate) dns_propagation_concurrency: usize,
    /// Max seconds to wait for challenge validation (default: 300)
    #[arg(long, default_value_t = crate::defaults::run::CHALLENGE_TIMEOUT_SECS)]
    pub(crate) challenge_timeout: u64,
    /// Save the certificate to this file
    #[arg(long, default_value = crate::defaults::run::CERT_OUTPUT_FILE)]
    pub(crate) cert_output: PathBuf,
    /// Save the private key to this file
    #[arg(long, default_value = crate::defaults::run::KEY_OUTPUT_FILE)]
    pub(crate) key_output: PathBuf,
    /// Reuse an existing unencrypted PKCS#8 PEM key for the CSR instead of generating a fresh one (e.g. for DANE TLSA pinning). If this path differs from --key-output the key is copied through.
    #[arg(long)]
    pub(crate) reuse_key: Option<PathBuf>,
    /// Skip renewal if existing certificate has more than N days remaining
    #[arg(long)]
    pub(crate) days: Option<u32>,
    /// Password to encrypt the private key (visible in process list - prefer --key-password-file)
    #[arg(long, conflicts_with = "key_password_file")]
    pub(crate) key_password: Option<String>,
    /// Read the private key encryption password from a file (first line, trailing newline stripped)
    #[arg(long, conflicts_with = "key_password", env = "ACME_KEY_PASSWORD_FILE")]
    pub(crate) key_password_file: Option<PathBuf>,
    /// Run a script after each challenge is ready for validation
    #[arg(long)]
    pub(crate) on_challenge_ready: Option<PathBuf>,
    /// Run a script after the certificate is issued and saved
    #[arg(long)]
    pub(crate) on_cert_issued: Option<PathBuf>,
    /// EAB Key ID from the CA (for CAs that require External Account Binding)
    #[arg(long, requires = "eab_hmac_key", env = "ACME_EAB_KID")]
    pub(crate) eab_kid: Option<String>,
    /// EAB HMAC key (base64url-encoded, from the CA)
    #[arg(long, requires = "eab_kid", env = "ACME_EAB_HMAC_KEY")]
    pub(crate) eab_hmac_key: Option<String>,
    /// Pre-authorize identifiers via newAuthz before creating the order
    #[arg(long)]
    pub(crate) pre_authorize: bool,
    /// Use ACME Renewal Information (RFC 9773) to decide when to renew
    #[arg(long)]
    pub(crate) ari: bool,
    /// Reissue the certificate if requested domains differ from existing cert's SANs
    #[arg(long)]
    pub(crate) reissue_on_mismatch: bool,
    /// Print the certificate PEM to stdout after issuance
    #[arg(long)]
    pub(crate) print_cert: bool,
    /// Policy for dns-persist-01 records (e.g., "wildcard" for wildcard + subdomain scope)
    #[arg(long)]
    pub(crate) persist_policy: Option<String>,
    /// Unix timestamp for dns-persist-01 persistUntil parameter
    #[arg(long)]
    pub(crate) persist_until: Option<u64>,
    /// Certificate key algorithm (ec-p256 | ec-p384 | ed25519)
    #[arg(long, default_value = crate::defaults::run::CERT_KEY_ALGORITHM)]
    pub(crate) cert_key_algorithm: CertKeyAlgorithm,
    /// Certificate profile (draft-ietf-acme-profiles-01)
    #[arg(long, env = "ACME_PROFILE")]
    pub(crate) profile: Option<String>,
    /// Overwrite the private key file if it already exists.
    #[arg(long)]
    pub(crate) force: bool,
}

/// clap value parser that wraps a password argument in [`secrecy::SecretString`]
/// so it is zeroized on drop and cannot be accidentally logged in full.
fn parse_secret_string(raw: &str) -> Result<secrecy::SecretString, std::convert::Infallible> {
    Ok(secrecy::SecretString::from(raw.to_string()))
}

/// Partially masks a secret for debug output: keeps the first two and last two
/// characters, replacing the middle with an ellipsis. Values of four or fewer
/// characters are fully masked so short secrets cannot be reconstructed.
fn mask_secret(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 4 {
        return "****".to_string();
    }
    let first: String = chars.iter().take(2).collect();
    let last: String = chars
        .iter()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{first}…{last}")
}

/// Hand-written `Debug` so the private-key encryption password is never shown
/// in full in logs or panic output (only a first-two/last-two mask). The EAB
/// HMAC key is intentionally shown in full: operators rely on its visibility to
/// confirm the External Account Binding credential when debugging onboarding.
/// All fields are destructured so a newly added field forces a compile error
/// here rather than silently escaping the redaction review.
impl std::fmt::Debug for RunArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
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
            reuse_key,
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
        } = self;
        f.debug_struct("RunArgs")
            .field("domains", domains)
            .field("contact", contact)
            .field("challenge_type", challenge_type)
            .field("http_port", http_port)
            .field("challenge_dir", challenge_dir)
            .field("dns_hook", dns_hook)
            .field("dns_wait", dns_wait)
            .field("dns_propagation_concurrency", dns_propagation_concurrency)
            .field("challenge_timeout", challenge_timeout)
            .field("cert_output", cert_output)
            .field("key_output", key_output)
            .field("reuse_key", reuse_key)
            .field("days", days)
            .field("key_password", &key_password.as_deref().map(mask_secret))
            .field("key_password_file", key_password_file)
            .field("on_challenge_ready", on_challenge_ready)
            .field("on_cert_issued", on_cert_issued)
            .field("eab_kid", eab_kid)
            .field("eab_hmac_key", eab_hmac_key)
            .field("pre_authorize", pre_authorize)
            .field("ari", ari)
            .field("reissue_on_mismatch", reissue_on_mismatch)
            .field("print_cert", print_cert)
            .field("persist_policy", persist_policy)
            .field("persist_until", persist_until)
            .field("cert_key_algorithm", cert_key_algorithm)
            .field("profile", profile)
            .field("force", force)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use anyhow::Context;
    use clap::CommandFactory;

    /// Drift detector. If a clap `default_value*` literal is ever inlined again
    /// instead of pointing at `crate::defaults`, the const and the CLI will
    /// disagree and this test will fail. See [`crate::defaults`].
    #[test]
    fn clap_defaults_match_defaults_module() -> anyhow::Result<()> {
        let cmd = Cli::command();

        let global_expected: &[(&str, &str)] = &[
            ("directory", crate::defaults::global::DIRECTORY_URL),
            ("account_key", crate::defaults::global::ACCOUNT_KEY_FILE),
            (
                "connect_timeout",
                &crate::defaults::global::CONNECT_TIMEOUT_SECS.to_string(),
            ),
        ];
        for (arg_id, expected) in global_expected {
            let arg = cmd
                .get_arguments()
                .find(|a| a.get_id() == *arg_id)
                .unwrap_or_else(|| panic!("global arg `{arg_id}` missing"));
            let got: Vec<String> = arg
                .get_default_values()
                .iter()
                .map(|v| v.to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                got,
                vec![expected.to_string()],
                "global arg `{arg_id}` default drifted from crate::defaults",
            );
        }

        let run_expected: &[(&str, &str)] = &[
            ("challenge_type", crate::defaults::run::CHALLENGE_TYPE),
            ("http_port", &crate::defaults::run::HTTP_PORT.to_string()),
            (
                "dns_propagation_concurrency",
                &crate::defaults::run::DNS_PROPAGATION_CONCURRENCY.to_string(),
            ),
            (
                "challenge_timeout",
                &crate::defaults::run::CHALLENGE_TIMEOUT_SECS.to_string(),
            ),
            ("cert_output", crate::defaults::run::CERT_OUTPUT_FILE),
            ("key_output", crate::defaults::run::KEY_OUTPUT_FILE),
            (
                "cert_key_algorithm",
                crate::defaults::run::CERT_KEY_ALGORITHM,
            ),
        ];
        let run = cmd
            .find_subcommand("run")
            .context("`run` subcommand not found")?;
        for (arg_id, expected) in run_expected {
            let arg = run
                .get_arguments()
                .find(|a| a.get_id() == *arg_id)
                .unwrap_or_else(|| panic!("run arg `{arg_id}` missing"));
            let got: Vec<String> = arg
                .get_default_values()
                .iter()
                .map(|v| v.to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                got,
                vec![expected.to_string()],
                "run arg `{arg_id}` default drifted from crate::defaults",
            );
        }
        Ok(())
    }

    #[test]
    fn m5_run_args_debug_masks_password_shows_eab() {
        let cli = Cli::try_parse_from([
            "acme",
            "run",
            "example.com",
            "--key-password",
            "supersecretpw",
            "--eab-kid",
            "kid-123",
            "--eab-hmac-key",
            "visible-hmac-value",
        ])
        .expect("parse run args");
        let Commands::Run(args) = &cli.command else {
            panic!("expected run command");
        };
        let rendered = format!("{args:?}");
        assert!(
            !rendered.contains("supersecretpw"),
            "raw password leaked: {rendered}"
        );
        assert!(
            rendered.contains("su…pw"),
            "password not masked: {rendered}"
        );
        assert!(
            rendered.contains("visible-hmac-value"),
            "eab_hmac_key must be shown in full: {rendered}"
        );
    }

    #[test]
    fn m5_mask_secret_fully_masks_short_values() {
        assert_eq!(mask_secret("abcd"), "****");
        assert_eq!(mask_secret(""), "****");
        assert_eq!(mask_secret("abcde"), "ab…de");
    }

    #[test]
    fn l6_account_key_password_is_secret() {
        use secrecy::ExposeSecret;
        let cli = Cli::try_parse_from([
            "acme",
            "--account-key-password",
            "topsecret",
            "list-profiles",
        ])
        .expect("parse account key password");
        let pw = cli.account_key_password.as_ref().expect("password present");
        assert_eq!(pw.expose_secret(), "topsecret");
    }
}
