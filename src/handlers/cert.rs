//! Certificate-management subcommands (revoke, renewal-info).

use std::path::Path;

use anyhow::{Context, Result};

use crate::cli::Cli;
use crate::client::compute_cert_id;
use crate::csr::pem_to_der;
use crate::{build_client, outln};

// NOT cancel-safe: revokes certificate on CA — irreversible side effect.
pub(crate) async fn cmd_revoke(cli: &Cli, cert_path: &Path, reason: Option<u8>) -> Result<()> {
    let mut client = build_client(cli).await?;

    // Revocation with an account key requires KID signing (RFC 8555 §7.6).
    // If no --account-url was provided, look up the existing account first.
    if client.account_url().is_none() {
        client.create_account(None, true, None).await?;
    }

    let pem_data = tokio::fs::read_to_string(cert_path)
        .await
        .with_context(|| format!("failed to read certificate from {}", cert_path.display()))?;
    let cert_der = pem_to_der(&pem_data)?;
    client.revoke_certificate(&cert_der, reason).await?;
    super::emit_result(
        cli,
        || {
            serde_json::json!({
                "command": "revoke-cert",
                "path": cert_path.display().to_string(),
                "reason": reason,
            })
        },
        || outln!("Certificate revoked"),
    );
    Ok(())
}

// cancel-safe: queries ARI endpoint; pure read.
pub(crate) async fn cmd_renewal_info(cli: &Cli, cert_path: &Path) -> Result<()> {
    let mut client = build_client(cli).await?;

    let pem_data = tokio::fs::read_to_string(cert_path)
        .await
        .with_context(|| format!("failed to read certificate from {}", cert_path.display()))?;
    let cert_der = pem_to_der(&pem_data)?;
    let cert_id = compute_cert_id(&cert_der)?;
    let (info, retry_after) = client.get_renewal_info(&cert_der).await?;

    super::emit_result(
        cli,
        || {
            serde_json::json!({
                "command": "renewal-info",
                "cert_id": cert_id,
                "suggested_window": {
                    "start": info.suggested_window.start,
                    "end": info.suggested_window.end,
                },
                "explanation_url": info.explanation_url,
                "retry_after": retry_after,
            })
        },
        || {
            outln!("CertID:   {cert_id}");
            outln!("Suggested renewal window:");
            outln!("  Start:  {}", info.suggested_window.start);
            outln!("  End:    {}", info.suggested_window.end);
            if let Some(ref url) = info.explanation_url {
                outln!("  Explanation: {url}");
            }

            // Show whether renewal is due
            if let Ok(end) = time::OffsetDateTime::parse(
                &info.suggested_window.end,
                &time::format_description::well_known::Rfc3339,
            ) {
                let now = time::OffsetDateTime::now_utc();
                if now >= end {
                    outln!("Status:   renewal overdue (window has passed)");
                } else if let Ok(start) = time::OffsetDateTime::parse(
                    &info.suggested_window.start,
                    &time::format_description::well_known::Rfc3339,
                ) {
                    if now >= start {
                        outln!("Status:   renewal recommended (within window)");
                    } else {
                        let until = start - now;
                        outln!(
                            "Status:   not yet due ({} days until window opens)",
                            until.whole_days()
                        );
                    }
                }
            }
            if let Some(secs) = retry_after {
                outln!("Retry-After: {secs}s");
            }
        },
    );
    Ok(())
}
