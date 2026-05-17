//! Sequential authorization path (HTTP-01, TLS-ALPN-01, manual DNS).
//!
//! One identifier at a time: dispatch to a per-challenge-type provisioner,
//! then poll the authorization to a terminal state with appropriate teardown
//! (HTTP server task abort, challenge file removal).

use anyhow::{Context, Result};

use crate::client::AcmeClient;
use crate::outln;
use crate::types::{AuthorizationStatus, ChallengeType, Order};

use super::super::super::is_challenge_failed;
use super::super::RunContext;
use super::provisioners::{
    ProvisionResult, provision_dns_persist01, provision_dns01, provision_http01,
    provision_tlsalpn01,
};

pub(super) async fn run_sequential(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    order: &Order,
) -> Result<()> {
    for authz_url in &order.authorizations {
        let authz = client.get_authorization(authz_url).await?;
        if !ctx.json && !ctx.silent {
            outln!(
                "Authorization for {} - status: {}",
                authz.identifier.value,
                authz.status
            );
        }

        if authz.status == AuthorizationStatus::Valid {
            if !ctx.json && !ctx.silent {
                outln!("  Already valid, skipping");
            }
            continue;
        }

        let ch = authz
            .challenges
            .iter()
            .find(|c| c.challenge_type == ctx.challenge_type)
            .with_context(|| {
                format!(
                    "no {} challenge for {}",
                    ctx.challenge_type, authz.identifier.value
                )
            })?;
        let token = if ctx.challenge_type != ChallengeType::DnsPersist01 {
            ch.token.as_deref().context("challenge has no token")?
        } else {
            "" // dns-persist-01 has no token
        };

        let ProvisionResult {
            challenge_file,
            mut serve_task,
        } = match &ctx.challenge_type {
            ChallengeType::Http01 => provision_http01(ctx, client, &authz, token, &ch.url).await?,
            ChallengeType::Dns01 => provision_dns01(ctx, client, &authz, token, &ch.url).await?,
            ChallengeType::DnsPersist01 => {
                provision_dns_persist01(ctx, client, &authz, ch, &ch.url).await?
            }
            ChallengeType::TlsAlpn01 => {
                provision_tlsalpn01(ctx, client, &authz, token, &ch.url).await?
            }
            other => anyhow::bail!("unsupported challenge type: {other}"),
        };

        // Poll authorization until terminal (max ctx.challenge_timeout)
        let poll_deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(ctx.challenge_timeout);
        loop {
            if std::time::Instant::now() > poll_deadline {
                if let Some(handle) = serve_task.take() {
                    handle.abort();
                }
                if let Some(ref f) = challenge_file {
                    crate::challenge::http01::cleanup_challenge_file(f);
                }
                anyhow::bail!(
                    "authorization for {} did not complete within {}s",
                    authz.identifier.value,
                    ctx.challenge_timeout
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let a = client.get_authorization(authz_url).await?;
            if !ctx.json && !ctx.silent {
                outln!("  Authorization status: {}", a.status);
            }

            // Surface challenge-level errors early (only if terminal)
            if let Some(ch) = a
                .challenges
                .iter()
                .find(|c| c.challenge_type == ctx.challenge_type)
            {
                if is_challenge_failed(ch) {
                    if let Some(handle) = serve_task.take() {
                        handle.abort();
                    }
                    if let Some(ref f) = challenge_file {
                        crate::challenge::http01::cleanup_challenge_file(f);
                    }
                    let detail = ch
                        .error
                        .as_ref()
                        .map(|e| format!(": {e}"))
                        .unwrap_or_default();
                    anyhow::bail!(
                        "challenge validation failed for {}{detail}",
                        authz.identifier.value
                    );
                } else if let Some(ref err) = ch.error {
                    tracing::debug!(
                        "Challenge has error but status is {} (will keep polling): {err}",
                        ch.status
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
                        crate::challenge::http01::cleanup_challenge_file(f);
                    }
                    let detail = a
                        .challenges
                        .iter()
                        .find(|c| c.challenge_type == ctx.challenge_type)
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

        // Clean up after successful validation
        if let Some(handle) = serve_task.take() {
            handle.abort();
        }
        if let Some(ref f) = challenge_file {
            crate::challenge::http01::cleanup_challenge_file(f);
        }
    }
    Ok(())
}
