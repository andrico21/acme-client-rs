//! Certificate finalize / poll / download phase.
//!
//! Builds the CSR, posts it to `order.finalize`, polls until the order is
//! `valid`, downloads the certificate chain, and writes the certificate +
//! (optionally encrypted) private key to disk. Fires the `--on-cert-issued`
//! hook last.

use anyhow::{Context, Result};
use tracing::info;

use crate::client::AcmeClient;
use crate::csr::{encrypt_private_key, generate_csr};
use crate::outln;
use crate::types::{Order, OrderStatus};

use super::super::run_hook;
use super::RunContext;

pub(super) async fn finalize(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    order: Order,
    order_url: &url::Url,
) -> Result<()> {
    // ── Finalize ────────────────────────────────────────────────────────
    info!(
        "Step {}: Finalizing order",
        if ctx.pre_authorize { 5 } else { 4 }
    );
    let (csr_der, key_pem) = generate_csr(&ctx.domains, ctx.cert_key_alg)?;
    let mut order = client.finalize_order(&order.finalize, &csr_der).await?;
    if !ctx.json && !ctx.silent {
        outln!("Order status: {}", order.status);
    }

    // ── Poll order ──────────────────────────────────────────────────────
    info!(
        "Step {}: Waiting for certificate issuance",
        if ctx.pre_authorize { 6 } else { 5 }
    );
    while order.status != OrderStatus::Valid {
        if order.status == OrderStatus::Invalid {
            anyhow::bail!("order became invalid");
        }
        tokio::time::sleep(crate::defaults::polling::ACME_RESOURCE_POLL).await;
        order = client.poll_order(order_url).await?;
        if !ctx.json && !ctx.silent {
            outln!("  Order status: {}", order.status);
        }
    }

    // ── Download certificate ────────────────────────────────────────────
    info!(
        "Step {}: Downloading certificate",
        if ctx.pre_authorize { 7 } else { 6 }
    );
    let cert_url = order
        .certificate
        .context("order is valid but has no certificate URL")?;
    let cert = client.download_certificate(&cert_url).await?;

    let password: Option<secrecy::SecretString> = if let Some(pw) = ctx.key_password {
        Some(secrecy::SecretString::from(pw.to_string()))
    } else if let Some(path) = ctx.key_password_file {
        crate::fs_secure::warn_if_world_readable(path, "password");
        let content = zeroize::Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read password file: {}", path.display()))?,
        );
        let pw: Option<String> = content
            .lines()
            .next()
            .map(|line| line.trim().to_string())
            .filter(|pw: &String| !pw.is_empty());
        pw.map(secrecy::SecretString::from)
    } else {
        None
    };

    let key_encrypted = password.is_some();
    if let Some(ref password) = password {
        use secrecy::ExposeSecret;
        let encrypted = encrypt_private_key(&key_pem, password.expose_secret())?;
        crate::fs_secure::write_secret_file(ctx.key_output, encrypted.as_bytes(), ctx.force)
            .with_context(|| {
                format!(
                    "failed to write private key to {}",
                    ctx.key_output.display()
                )
            })?;
        if !ctx.json && !ctx.silent {
            outln!(
                "Private key saved to {} (encrypted)",
                ctx.key_output.display()
            );
        }
    } else {
        crate::fs_secure::write_secret_file(ctx.key_output, key_pem.as_bytes(), ctx.force)
            .with_context(|| {
                format!(
                    "failed to write private key to {}",
                    ctx.key_output.display()
                )
            })?;
        if !ctx.json && !ctx.silent {
            outln!("Private key saved to {}", ctx.key_output.display());
        }
    }

    std::fs::write(ctx.cert_output, &cert).with_context(|| {
        format!(
            "failed to write certificate to {}",
            ctx.cert_output.display()
        )
    })?;
    if ctx.json && !ctx.silent {
        outln!(
            "{}",
            serde_json::json!({
                "command": "run",
                "action": "issued",
                "domains": ctx.domains,
                "cert_path": ctx.cert_output.display().to_string(),
                "key_path": ctx.key_output.display().to_string(),
                "key_encrypted": key_encrypted,
                "profile": ctx.profile,
            })
        );
    } else if !ctx.silent {
        outln!("Certificate saved to {}", ctx.cert_output.display());
        if ctx.print_cert {
            outln!("{cert}");
        }
    }

    if let Some(script) = ctx.on_cert_issued {
        let domains_joined = ctx.domains.join(",");
        run_hook(
            script,
            &[
                ("ACME_DOMAINS", &domains_joined),
                ("ACME_CERT_PATH", &ctx.cert_output.display().to_string()),
                ("ACME_KEY_PATH", &ctx.key_output.display().to_string()),
                (
                    "ACME_KEY_ENCRYPTED",
                    if key_encrypted { "true" } else { "false" },
                ),
            ],
        )?;
    }

    Ok(())
}
