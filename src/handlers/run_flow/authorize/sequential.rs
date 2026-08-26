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

// NOT cancel-safe: dispatches to provision_* (each carries side effects:
// HTTP server task, DNS hook, file write) and polls CA. Drop between
// provision and final poll leaves dangling cleanup state.

// NOT cancel-safe: delegates to authorize_one per authorization; inherits its
// contract (external provisioning side effects, explicit abort/cleanup).
pub(super) async fn run_sequential(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    order: &Order,
) -> Result<()> {
    for authz_url in &order.authorizations {
        authorize_one(ctx, client, authz_url).await?;
    }
    Ok(())
}

// NOT cancel-safe: dispatches to per-challenge provisioners with external side
// effects and then authorizes one identifier. Caller must run to completion so
// provisioned HTTP resources are explicitly aborted/cleaned.
async fn authorize_one(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    authz_url: &url::Url,
) -> Result<()> {
    let authz = client.get_authorization(authz_url).await?;
    if !ctx.json && !ctx.silent {
        outln!(
            "Authorization for {} - status: {}",
            authz.identifier.value_str(),
            authz.status
        );
    }

    if authz.status == AuthorizationStatus::Valid {
        if !ctx.json && !ctx.silent {
            outln!("  Already valid, skipping");
        }
        return Ok(());
    }

    let ch = authz
        .challenges
        .iter()
        .find(|c| c.challenge_type == ctx.challenge_type)
        .with_context(|| {
            format!(
                "no {} challenge for {}",
                ctx.challenge_type,
                authz.identifier.value_str()
            )
        })?;
    let token = ch.token.as_ref();
    let require_token = || token.context("challenge has no token");

    let mut cleanup = match &ctx.challenge_type {
        ChallengeType::Http01 => {
            provision_http01(ctx, client, &authz, require_token()?, &ch.url).await?
        }
        ChallengeType::Dns01 => {
            provision_dns01(ctx, client, &authz, require_token()?, &ch.url).await?
        }
        ChallengeType::DnsPersist01 => {
            provision_dns_persist01(ctx, client, &authz, ch, &ch.url).await?
        }
        ChallengeType::TlsAlpn01 => {
            provision_tlsalpn01(ctx, client, &authz, require_token()?, &ch.url).await?
        }
        other @ ChallengeType::Unknown(_) => {
            anyhow::bail!("unsupported challenge type: {other}")
        }
    };
    let domain_display = authz.identifier.value_str().into_owned();
    poll_authorization_until_valid(ctx, client, authz_url, &domain_display, &mut cleanup).await?;

    // Clean up after successful validation
    cleanup_provision_result(&mut cleanup);
    Ok(())
}

// NOT cancel-safe: owns the post-provision polling window. Cancellation before
// this helper returns skips explicit HTTP server abort/file cleanup for the
// in-flight challenge.
async fn poll_authorization_until_valid(
    ctx: &RunContext<'_>,
    client: &mut AcmeClient,
    authz_url: &url::Url,
    domain_display: &str,
    cleanup: &mut ProvisionResult,
) -> Result<()> {
    // Poll authorization until terminal (max ctx.challenge_timeout)
    let poll_deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(ctx.challenge_timeout);
    loop {
        if std::time::Instant::now() > poll_deadline {
            cleanup_provision_result(cleanup);
            anyhow::bail!(
                "authorization for {} did not complete within {}s",
                domain_display,
                ctx.challenge_timeout
            );
        }
        tokio::time::sleep(crate::defaults::polling::ACME_RESOURCE_POLL).await;
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
                cleanup_provision_result(cleanup);
                let detail = ch
                    .error
                    .as_ref()
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default();
                anyhow::bail!("challenge validation failed for {domain_display}{detail}");
            } else if let Some(ref err) = ch.error {
                tracing::debug!(
                    "Challenge has error but status is {} (will keep polling): {err}",
                    ch.status
                );
            }
        }

        match a.status {
            AuthorizationStatus::Valid => break,
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Invalid
            | AuthorizationStatus::Deactivated
            | AuthorizationStatus::Expired
            | AuthorizationStatus::Revoked => {
                cleanup_provision_result(cleanup);
                let detail = a
                    .challenges
                    .iter()
                    .find(|c| c.challenge_type == ctx.challenge_type)
                    .and_then(|c| c.error.as_ref())
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default();
                anyhow::bail!(
                    "authorization failed for {} (status: {}){detail}",
                    domain_display,
                    a.status
                );
            }
        }
    }
    Ok(())
}

/// Abort the standalone HTTP-01 server task and remove any challenge file.
///
/// Takes `&mut` and uses `take()` so the `JoinHandle` is always explicitly
/// aborted: dropping one detaches the task instead of stopping it.
fn cleanup_provision_result(cleanup: &mut ProvisionResult) {
    if let Some(handle) = cleanup.serve_task.take() {
        handle.abort();
    }
    if let Some(ref f) = cleanup.challenge_file {
        crate::challenge::http01::cleanup_challenge_file(f);
    }
}
