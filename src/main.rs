#![forbid(unsafe_code)]

mod challenge;
mod client;
mod jws;
mod types;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;

use crate::client::AcmeClient;
use crate::jws::AccountKey;
use crate::types::{
    AuthorizationStatus, Identifier, OrderStatus, CHALLENGE_TYPE_DNS01, CHALLENGE_TYPE_HTTP01,
    CHALLENGE_TYPE_TLSALPN01,
};

/// Simple ACME client for testing ACME flows (RFC 8555)
#[derive(Parser)]
#[command(name = "acme-client-rs", version, about)]
struct Cli {
    /// ACME server directory URL
    #[arg(long, env = "ACME_DIRECTORY_URL", default_value = "https://localhost:14000/dir")]
    directory: String,

    /// Path to the account key (PKCS#8 PEM)
    #[arg(long, env = "ACME_ACCOUNT_KEY", default_value = "account.key")]
    account_key: PathBuf,

    /// Account URL (required after account creation)
    #[arg(long, env = "ACME_ACCOUNT_URL")]
    account_url: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new ES256 account key pair
    GenerateKey,

    /// Create (or look up) an ACME account
    Account {
        /// Contact email addresses
        #[arg(long)]
        contact: Vec<String>,
        /// Agree to the CA's terms of service
        #[arg(long, default_value_t = true)]
        agree_tos: bool,
    },

    /// Request a new certificate order
    Order {
        /// Domain names to include
        #[arg(required = true)]
        domains: Vec<String>,
    },

    /// Fetch an authorization object
    GetAuthz {
        /// Authorization URL
        #[arg(required = true)]
        url: String,
    },

    /// Tell the server a challenge is ready
    RespondChallenge {
        /// Challenge URL
        #[arg(required = true)]
        url: String,
    },

    /// Serve an HTTP-01 challenge response
    ServeHttp01 {
        /// Challenge token
        #[arg(long)]
        token: String,
        /// Port to listen on
        #[arg(long, default_value_t = 80)]
        port: u16,
    },

    /// Show DNS-01 setup instructions
    ShowDns01 {
        /// Domain name
        #[arg(long)]
        domain: String,
        /// Challenge token
        #[arg(long)]
        token: String,
    },

    /// Finalize an order with a new CSR
    Finalize {
        /// Order finalize URL
        #[arg(long)]
        finalize_url: String,
        /// Domain names for the CSR
        #[arg(required = true)]
        domains: Vec<String>,
    },

    /// Poll an order's current status
    PollOrder {
        /// Order URL
        #[arg(required = true)]
        url: String,
    },

    /// Download the issued certificate
    DownloadCert {
        /// Certificate URL
        #[arg(required = true)]
        url: String,
        /// Output file
        #[arg(long, default_value = "certificate.pem")]
        output: PathBuf,
    },

    /// Deactivate the current account
    DeactivateAccount,

    /// Revoke a certificate
    RevokeCert {
        /// Path to the certificate PEM
        #[arg(required = true)]
        cert_path: PathBuf,
        /// Revocation reason code (RFC 5280 §5.3.1)
        #[arg(long)]
        reason: Option<u8>,
    },

    /// Run the full ACME flow end-to-end
    Run {
        /// Domain names
        #[arg(required = true)]
        domains: Vec<String>,
        /// Contact email
        #[arg(long)]
        contact: Option<String>,
        /// Challenge type to use (http-01 | dns-01 | tls-alpn-01)
        #[arg(long, default_value = "http-01")]
        challenge_type: String,
        /// HTTP-01 server port
        #[arg(long, default_value_t = 80)]
        http_port: u16,
    },
}

// ── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateKey => cmd_generate_key(&cli.account_key),
        Commands::Account { contact, agree_tos } => {
            cmd_account(&cli, contact.clone(), *agree_tos).await
        }
        Commands::Order { domains } => cmd_order(&cli, domains.clone()).await,
        Commands::GetAuthz { url } => cmd_get_authz(&cli, url).await,
        Commands::RespondChallenge { url } => cmd_respond_challenge(&cli, url).await,
        Commands::ServeHttp01 { token, port } => {
            cmd_serve_http01(&cli.account_key, token, *port).await
        }
        Commands::ShowDns01 { domain, token } => cmd_show_dns01(&cli.account_key, domain, token),
        Commands::Finalize {
            finalize_url,
            domains,
        } => cmd_finalize(&cli, finalize_url, domains).await,
        Commands::PollOrder { url } => cmd_poll_order(&cli, url).await,
        Commands::DownloadCert { url, output } => {
            cmd_download_cert(&cli, url, output).await
        }
        Commands::DeactivateAccount => cmd_deactivate(&cli).await,
        Commands::RevokeCert { cert_path, reason } => {
            cmd_revoke(&cli, cert_path, *reason).await
        }
        Commands::Run {
            domains,
            contact,
            challenge_type,
            http_port,
        } => cmd_run(&cli, domains.clone(), contact.clone(), challenge_type, *http_port).await,
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn load_account_key(path: &PathBuf) -> Result<AccountKey> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read account key from {}", path.display()))?;
    AccountKey::from_pkcs8_pem(&pem)
}

async fn build_client(cli: &Cli) -> Result<AcmeClient> {
    let key = load_account_key(&cli.account_key)?;
    let mut client = AcmeClient::new(&cli.directory, key).await?;
    if let Some(ref url) = cli.account_url {
        client.set_account_url(url.clone());
    }
    Ok(client)
}

fn generate_csr(domains: &[String]) -> Result<Vec<u8>> {
    use rcgen::{CertificateParams, KeyPair};

    let params =
        CertificateParams::new(domains.to_vec()).context("failed to create CSR parameters")?;
    let key_pair = KeyPair::generate().context("failed to generate CSR key pair")?;
    let csr = params
        .serialize_request(&key_pair)
        .context("failed to serialize CSR")?;
    Ok(csr.der().to_vec())
}

fn pem_to_der(pem_data: &str) -> Result<Vec<u8>> {
    let parsed = pem::parse(pem_data).context("failed to parse PEM data")?;
    Ok(parsed.contents().to_vec())
}

// ── Individual command handlers ─────────────────────────────────────────────

fn cmd_generate_key(path: &PathBuf) -> Result<()> {
    let key = AccountKey::generate()?;
    let pem = key.to_pkcs8_pem()?;
    std::fs::write(path, pem.as_bytes())
        .with_context(|| format!("failed to write key to {}", path.display()))?;
    println!("Account key saved to {}", path.display());
    Ok(())
}

async fn cmd_account(cli: &Cli, contact: Vec<String>, agree_tos: bool) -> Result<()> {
    let mut client = build_client(cli).await?;
    let contact = if contact.is_empty() {
        None
    } else {
        Some(contact.into_iter().map(|c| format!("mailto:{c}")).collect())
    };
    let account = client.create_account(contact, agree_tos).await?;
    println!("Account status: {}", account.status);
    if let Some(url) = client.account_url() {
        println!("Account URL:    {url}");
    }
    Ok(())
}

async fn cmd_order(cli: &Cli, domains: Vec<String>) -> Result<()> {
    let mut client = build_client(cli).await?;
    let ids: Vec<Identifier> = domains.iter().map(|d| Identifier::dns(d)).collect();
    let (order, order_url) = client.new_order(ids).await?;
    println!("Order URL:    {order_url}");
    println!("Status:       {}", order.status);
    println!("Finalize URL: {}", order.finalize);
    for url in &order.authorizations {
        println!("  authz: {url}");
    }
    Ok(())
}

async fn cmd_get_authz(cli: &Cli, url: &str) -> Result<()> {
    let mut client = build_client(cli).await?;
    let authz = client.get_authorization(url).await?;
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
    Ok(())
}

async fn cmd_respond_challenge(cli: &Cli, url: &str) -> Result<()> {
    let mut client = build_client(cli).await?;
    let ch = client.respond_to_challenge(url).await?;
    println!("Challenge status: {}", ch.status);
    Ok(())
}

async fn cmd_serve_http01(key_path: &PathBuf, token: &str, port: u16) -> Result<()> {
    let key = load_account_key(key_path)?;
    challenge::http01::serve(token, &key, port).await
}

fn cmd_show_dns01(key_path: &PathBuf, domain: &str, token: &str) -> Result<()> {
    let key = load_account_key(key_path)?;
    challenge::dns01::print_instructions(domain, token, &key);
    Ok(())
}

async fn cmd_finalize(cli: &Cli, finalize_url: &str, domains: &[String]) -> Result<()> {
    let mut client = build_client(cli).await?;
    let csr_der = generate_csr(domains)?;
    let order = client.finalize_order(finalize_url, &csr_der).await?;
    println!("Order status: {}", order.status);
    if let Some(ref cert_url) = order.certificate {
        println!("Certificate URL: {cert_url}");
    }
    Ok(())
}

async fn cmd_poll_order(cli: &Cli, url: &str) -> Result<()> {
    let mut client = build_client(cli).await?;
    let order = client.poll_order(url).await?;
    println!("Order status: {}", order.status);
    if let Some(ref cert_url) = order.certificate {
        println!("Certificate URL: {cert_url}");
    }
    Ok(())
}

async fn cmd_download_cert(cli: &Cli, url: &str, output: &PathBuf) -> Result<()> {
    let mut client = build_client(cli).await?;
    let cert = client.download_certificate(url).await?;
    std::fs::write(output, &cert)
        .with_context(|| format!("failed to write certificate to {}", output.display()))?;
    println!("Certificate saved to {}", output.display());
    Ok(())
}

async fn cmd_deactivate(cli: &Cli) -> Result<()> {
    let mut client = build_client(cli).await?;
    let account = client.deactivate_account().await?;
    println!("Account status: {}", account.status);
    Ok(())
}

async fn cmd_revoke(cli: &Cli, cert_path: &PathBuf, reason: Option<u8>) -> Result<()> {
    let mut client = build_client(cli).await?;
    let pem_data = std::fs::read_to_string(cert_path)
        .with_context(|| format!("failed to read certificate from {}", cert_path.display()))?;
    let cert_der = pem_to_der(&pem_data)?;
    client.revoke_certificate(&cert_der, reason).await?;
    println!("Certificate revoked");
    Ok(())
}

// ── Full automated flow ─────────────────────────────────────────────────────

async fn cmd_run(
    cli: &Cli,
    domains: Vec<String>,
    contact: Option<String>,
    challenge_type: &str,
    http_port: u16,
) -> Result<()> {
    // ── 1. Account ──────────────────────────────────────────────────────
    info!("Step 1: Creating / looking up account");
    let mut client = build_client(cli).await?;
    let contact_list = contact.map(|c| vec![format!("mailto:{c}")]);
    let account = client.create_account(contact_list, true).await?;
    println!("Account status: {}", account.status);

    // ── 2. New order ────────────────────────────────────────────────────
    info!("Step 2: Placing order");
    let ids: Vec<Identifier> = domains.iter().map(|d| Identifier::dns(d)).collect();
    let (order, order_url) = client.new_order(ids).await?;
    println!("Order URL:  {order_url}");
    println!("Order status: {}", order.status);

    // ── 3. Authorizations ───────────────────────────────────────────────
    info!("Step 3: Completing authorizations");
    for authz_url in &order.authorizations {
        let authz = client.get_authorization(authz_url).await?;
        println!(
            "Authorization for {} — status: {}",
            authz.identifier.value, authz.status
        );

        if authz.status == AuthorizationStatus::Valid {
            println!("  Already valid, skipping");
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
        let token = ch.token.as_deref().context("challenge has no token")?;
        let challenge_url = ch.url.clone();

        match challenge_type {
            CHALLENGE_TYPE_HTTP01 => {
                // Compute response material while holding only an immutable borrow
                let auth = challenge::http01::response_body(token, client.account_key());
                let path = challenge::http01::challenge_path(token);

                // Bind *before* telling the CA we're ready
                let listener =
                    tokio::net::TcpListener::bind(("0.0.0.0", http_port))
                        .await
                        .with_context(|| {
                            format!("failed to bind HTTP-01 server on port {http_port}")
                        })?;
                info!("HTTP-01 server listening on port {http_port}");

                let serve_handle = tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let (mut stream, _) = listener.accept().await?;
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
                    }
                    Ok::<(), anyhow::Error>(())
                });

                client.respond_to_challenge(&challenge_url).await?;
                println!("  Challenge response sent — waiting for HTTP request…");
                serve_handle.await??;
            }
            CHALLENGE_TYPE_DNS01 => {
                challenge::dns01::print_instructions(
                    &authz.identifier.value,
                    token,
                    client.account_key(),
                );
                let _ = std::io::stdin().read_line(&mut String::new());
                client.respond_to_challenge(&challenge_url).await?;
            }
            CHALLENGE_TYPE_TLSALPN01 => {
                challenge::tlsalpn01::print_instructions(
                    &authz.identifier.value,
                    token,
                    client.account_key(),
                );
                let _ = std::io::stdin().read_line(&mut String::new());
                client.respond_to_challenge(&challenge_url).await?;
            }
            other => anyhow::bail!("unsupported challenge type: {other}"),
        }

        // Poll authorization until terminal
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let a = client.get_authorization(authz_url).await?;
            println!("  Authorization status: {}", a.status);
            match a.status {
                AuthorizationStatus::Valid => break,
                AuthorizationStatus::Invalid => {
                    anyhow::bail!("authorization failed for {}", authz.identifier.value);
                }
                _ => continue,
            }
        }
    }

    // ── 4. Finalize ─────────────────────────────────────────────────────
    info!("Step 4: Finalizing order");
    let csr_der = generate_csr(&domains)?;
    let finalize_url = order.finalize.clone();
    let mut order = client.finalize_order(&finalize_url, &csr_der).await?;
    println!("Order status: {}", order.status);

    // ── 5. Poll order ───────────────────────────────────────────────────
    info!("Step 5: Waiting for certificate issuance");
    while order.status != OrderStatus::Valid {
        if order.status == OrderStatus::Invalid {
            anyhow::bail!("order became invalid");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        order = client.poll_order(&order_url).await?;
        println!("  Order status: {}", order.status);
    }

    // ── 6. Download certificate ─────────────────────────────────────────
    info!("Step 6: Downloading certificate");
    let cert_url = order
        .certificate
        .context("order is valid but has no certificate URL")?;
    let cert = client.download_certificate(&cert_url).await?;

    let cert_file = "certificate.pem";
    std::fs::write(cert_file, &cert)?;
    println!("Certificate saved to {cert_file}");
    println!("{cert}");

    Ok(())
}

