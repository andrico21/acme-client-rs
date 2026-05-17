//! Certificate-management subcommands (revoke, renewal-info).

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::cli::{Cli, OutputFormat};
use crate::client::compute_cert_id;
use crate::csr::pem_to_der;
use crate::{build_client, outln};

pub(crate) async fn cmd_revoke(cli: &Cli, cert_path: &PathBuf, reason: Option<u8>) -> Result<()> {
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
    if !cli.silent {
        if cli.output_format == OutputFormat::Json {
            outln!(
                "{}",
                serde_json::json!({
                    "command": "revoke-cert",
                    "path": cert_path.display().to_string(),
                    "reason": reason,
                })
            );
        } else {
            outln!("Certificate revoked");
        }
    }
    Ok(())
}

pub(crate) async fn cmd_renewal_info(cli: &Cli, cert_path: &PathBuf) -> Result<()> {
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

    if !cli.silent {
        if cli.output_format == OutputFormat::Json {
            outln!(
                "{}",
                serde_json::json!({
                    "command": "renewal-info",
                    "cert_id": cert_id,
                    "suggested_window": {
                        "start": info.suggested_window.start,
                        "end": info.suggested_window.end,
                    },
                    "retry_after": retry_after,
                })
            );
        } else {
            outln!("CertID:   {cert_id}");
            outln!("Suggested renewal window:");
            outln!("  Start:  {}", info.suggested_window.start);
            outln!("  End:    {}", info.suggested_window.end);

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
        }
    }
    Ok(())
}
