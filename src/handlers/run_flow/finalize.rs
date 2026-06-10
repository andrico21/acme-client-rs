//! Certificate finalize / poll / download phase.
//!
//! Builds the CSR, posts it to `order.finalize`, polls until the order is
//! `valid`, downloads the certificate chain, and writes the certificate +
//! (optionally encrypted) private key to disk. Fires the `--on-cert-issued`
//! hook last.

use anyhow::{Context, Result};
use tracing::info;

use crate::client::AcmeClient;
use crate::csr::{
    build_csr_with_keypair, encrypt_private_key, generate_csr, load_keypair_from_pem_file,
};
use crate::outln;
use crate::types::{Order, OrderStatus};

use super::super::run_hook;
use super::RunContext;

// NOT cancel-safe: generates CSR (off-runtime), submits to CA, polls until
// ready, downloads cert, writes cert + private key to disk, and invokes
// on_cert_issued hook. Drop between finalize POST and disk write would
// orphan the issued certificate (not retrievable without polling order).
// cognitive_complexity: CSR→submit→poll→download→write sequence must stay one
// body for the cancel-safety contract documented above.
#[allow(clippy::cognitive_complexity)]
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
    // CSR generation involves RSA/ECDSA keygen (hundreds of ms for RSA-4096),
    // so it MUST run on the blocking pool, not the async runtime.
    let domains_for_csr = ctx.domains.clone();
    let cert_key_alg = ctx.cert_key_alg;
    let reuse_key_path = ctx.reuse_key.map(std::path::Path::to_path_buf);
    let (csr_der, key_pem) = tokio::task::spawn_blocking(move || {
        if let Some(path) = reuse_key_path {
            let kp = load_keypair_from_pem_file(&path)?;
            build_csr_with_keypair(&domains_for_csr, &kp)
        } else {
            generate_csr(&domains_for_csr, cert_key_alg)
        }
    })
    .await
    .context("CSR generation task panicked")??;
    let mut order = client.finalize_order(&order.finalize, &csr_der).await?;
    if !ctx.json && !ctx.silent {
        outln!("Order status: {}", order.status);
    }

    // ── Poll order ──────────────────────────────────────────────────────
    info!(
        "Step {}: Waiting for certificate issuance",
        if ctx.pre_authorize { 6 } else { 5 }
    );
    let poll_timeout = crate::defaults::polling::ORDER_POLL_TIMEOUT;
    order = tokio::time::timeout(poll_timeout, async {
        let mut order = order;
        while order.status != OrderStatus::Valid {
            if order.status == OrderStatus::Invalid {
                anyhow::bail!("order became invalid");
            }
            let default_sleep = crate::defaults::polling::ACME_RESOURCE_POLL;
            let (next_order, retry_after) = client.poll_order_with_retry_after(order_url).await?;
            order = next_order;
            if !ctx.json && !ctx.silent {
                outln!("  Order status: {}", order.status);
            }
            if order.status == OrderStatus::Valid {
                break;
            }
            let sleep_for = retry_after.map_or(default_sleep, |d| {
                d.min(crate::defaults::polling::ACME_RESOURCE_POLL_MAX)
            });
            tokio::time::sleep(sleep_for).await;
        }
        Ok::<_, anyhow::Error>(order)
    })
    .await
    .with_context(|| {
        format!(
            "order did not reach `valid` within {}s",
            poll_timeout.as_secs()
        )
    })??;

    // ── Download certificate ────────────────────────────────────────────
    info!(
        "Step {}: Downloading certificate",
        if ctx.pre_authorize { 7 } else { 6 }
    );
    let cert_url = order
        .certificate
        .context("order is valid but has no certificate URL")?;
    let cert = client.download_certificate(&cert_url).await?;

    let password: Option<secrecy::SecretString> = if let Some(pw) = ctx.key_password.take() {
        Some(pw)
    } else if let Some(path) = ctx.key_password_file {
        crate::fs_secure::warn_if_world_readable(path, "password");
        let content = zeroize::Zeroizing::new(
            tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("failed to read password file: {}", path.display()))?,
        );
        content
            .lines()
            .next()
            .map(str::trim)
            .filter(|pw| !pw.is_empty())
            .map(secrecy::SecretString::from)
    } else {
        None
    };

    let key_encrypted = password.is_some();
    let key_bytes: zeroize::Zeroizing<Vec<u8>> = if let Some(password) = password {
        let key_pem_owned = key_pem;
        let encrypted = tokio::task::spawn_blocking(move || {
            use secrecy::ExposeSecret;
            encrypt_private_key(&key_pem_owned, password.expose_secret()).map(String::into_bytes)
        })
        .await
        .context("scrypt encryption task panicked")??;
        zeroize::Zeroizing::new(encrypted)
    } else {
        zeroize::Zeroizing::new(key_pem.as_bytes().to_vec())
    };
    // --reuse-key path == --key-output path → on-disk file is the source of
    // truth; skip the write so we don't trip the SEC-08 "refusing to
    // overwrite" guardrail and don't re-encode an unchanged key.
    let skip_key_write = if let Some(src) = ctx.reuse_key {
        paths_resolve_same(src, ctx.key_output).await
    } else {
        false
    };
    let key_output_owned = ctx.key_output.to_path_buf();
    let key_display = ctx.key_output.display().to_string();
    if skip_key_write {
        tokio::task::spawn_blocking(move || {
            crate::fs_secure::ensure_secret_perms(&key_output_owned)
        })
        .await
        .context("ensure_secret_perms task panicked")?
        .with_context(|| format!("failed to re-assert 0600 on {key_display}"))?;
    } else {
        let force = ctx.force;
        tokio::task::spawn_blocking(move || {
            crate::fs_secure::write_secret_file(
                &key_output_owned,
                &key_bytes,
                if force {
                    crate::fs_secure::Overwrite::Allow
                } else {
                    crate::fs_secure::Overwrite::Forbid
                },
            )
        })
        .await
        .context("write_secret_file task panicked")?
        .with_context(|| format!("failed to write private key to {key_display}"))?;
    }
    if !ctx.json && !ctx.silent {
        if skip_key_write {
            outln!(
                "Private key reused from {} (not rewritten)",
                ctx.key_output.display()
            );
        } else if key_encrypted {
            outln!(
                "Private key saved to {} (encrypted)",
                ctx.key_output.display()
            );
        } else {
            outln!("Private key saved to {}", ctx.key_output.display());
        }
    }

    let cert_output_owned = ctx.cert_output.to_path_buf();
    let cert_bytes = cert.clone().into_bytes();
    let cert_display = ctx.cert_output.display().to_string();
    tokio::task::spawn_blocking(move || std::fs::write(&cert_output_owned, &cert_bytes))
        .await
        .context("certificate write task panicked")?
        .with_context(|| format!("failed to write certificate to {cert_display}"))?;
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
            ctx.cli.unsafe_hooks,
        )
        .await?;
    }

    Ok(())
}

// cancel-safe: read-only canonicalize lookups, no side effects.
async fn paths_resolve_same(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (
        tokio::fs::canonicalize(a).await,
        tokio::fs::canonicalize(b).await,
    ) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}
