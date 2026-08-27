//! Parallel-propagation DNS authorization path.
//!
//! Used when `--dns-hook` is set with `dns-01` or `dns-persist-01`. Provisions
//! all TXT records up front, then waits for propagation concurrently
//! (semaphore-limited), then responds to challenges serially to preserve
//! the ACME nonce chain.

use anyhow::{Context, Result};
use tracing::info;

use crate::client::AcmeClient;
use crate::outln;
use crate::types::{AuthorizationStatus, ChallengeType, Order};

use super::super::super::{
    dns_txt_check, is_challenge_failed, run_dns_hook_cleanup_logged, run_dns_hook_cleanup_silent,
    run_dns_hook_create, run_hook,
};
use super::super::RunContext;
use super::DnsPending;

// NOT cancel-safe: creates DNS records via external hook in Phase 1 and
// signals CAs in Phase 3. Drop mid-pipeline leaves published TXT records
// behind: the registry is drained on SIGINT or the top-level error path, not
// on Drop, and that rollback is best-effort. Caller must run to completion.
// The phase helpers below are immediately awaited in sequence, never spawned
// or raced, so extracting them adds no cancellation point the inline awaits
// did not already have.
pub(super) async fn run_phased_dns(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    order: &Order,
) -> Result<()> {
    let hook = ctx
        .dns_hook
        .context("phased DNS pipeline invoked without --dns-hook (dispatcher bug)")?;

    let mut pending = provision_records(ctx, client, order, hook).await?;
    if pending.is_empty() {
        return Ok(());
    }

    wait_for_propagation(ctx, &mut pending, hook).await?;
    run_hooks_and_respond(ctx, client, &pending).await?;
    poll_authorizations_until_valid(ctx, client, &mut pending, hook).await?;
    cleanup_records(ctx, &mut pending, hook).await;
    Ok(())
}

/// TXT-record material derived from an authorization, owned so the caller can
/// drop its borrow of the authorization before awaiting the create hook.
struct DnsRecordMaterial {
    domain: crate::types::DnsName,
    challenge_url: url::Url,
    token: Option<crate::types::ChallengeToken>,
    txt_name: crate::types::DnsName,
    txt_value: String,
}

// NOT cancel-safe: creates DNS records through an external hook; cancellation
// during hook create or rollback can leave remote TXT records behind.
async fn provision_records(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    order: &Order,
    hook: &std::path::Path,
) -> Result<Vec<DnsPending>> {
    let mut pending: Vec<DnsPending> = Vec::new();
    for authz_url in &order.authorizations {
        if let Some(entry) =
            provision_record_for_authz(ctx, client, authz_url, hook, &mut pending).await?
        {
            pending.push(entry);
        }
    }
    Ok(pending)
}

// NOT cancel-safe: may create one DNS record and may run best-effort cleanup
// for previously-created records if hook creation fails.
async fn provision_record_for_authz(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    authz_url: &url::Url,
    hook: &std::path::Path,
    pending: &mut [DnsPending],
) -> Result<Option<DnsPending>> {
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
        return Ok(None);
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

    let material = dns_record_material(ctx, client, &authz, ch)?;

    // Run create hook
    info!(
        "Calling DNS hook (create): {} for {}",
        hook.display(),
        material.domain.as_str()
    );
    if let Err(e) = run_dns_hook_create(
        hook,
        &material.domain,
        &material.txt_name,
        &material.txt_value,
        ctx.cli.unsafe_hooks,
    )
    .await
    {
        // Clean up any records we already created
        cleanup_pending_silent(hook, pending, ctx.cli.unsafe_hooks).await;
        return Err(e);
    }
    let cleanup_handle = ctx
        .cleanup_registry
        .register(crate::cleanup::CleanupAction::DnsRecord {
            hook: hook.to_path_buf(),
            domain: material.domain.clone(),
            txt_name: material.txt_name.clone(),
            txt_value: material.txt_value.clone(),
        });

    Ok(Some(DnsPending {
        authz_url: authz_url.clone(),
        domain: material.domain,
        challenge_url: material.challenge_url,
        token: material.token,
        txt_name: material.txt_name,
        txt_value: material.txt_value,
        cleanup_handle: Some(cleanup_handle),
    }))
}

fn dns_record_material(
    ctx: &RunContext<'_>,
    client: &AcmeClient,
    authz: &crate::types::Authorization,
    ch: &crate::types::Challenge,
) -> Result<DnsRecordMaterial> {
    let (token, dns_for_pending, txt_name, txt_value) = if ctx.challenge_type
        == ChallengeType::Dns01
    {
        let dns = authz.identifier.as_dns().ok_or_else(|| {
            anyhow::anyhow!(
                "dns-01 challenges are not supported for IP identifiers ({})",
                authz.identifier.value_str()
            )
        })?;
        let t = ch.token.clone().context("challenge has no token")?;
        let name = crate::challenge::dns01::record_name(dns)?;
        let value = crate::challenge::dns01::txt_record_value(&t, client.account_key())?;
        (Some(t), dns.clone(), name, value)
    } else {
        // dns-persist-01
        let dns = authz.identifier.as_dns().ok_or_else(|| {
            anyhow::anyhow!(
                "dns-persist-01 challenges are not supported for IP identifiers ({})",
                authz.identifier.value_str()
            )
        })?;
        let issuer_names = ch
            .issuer_domain_names
            .as_ref()
            .context("dns-persist-01 challenge has no issuer-domain-names")?;
        if issuer_names.is_empty() || issuer_names.len() > 10 {
            anyhow::bail!("malformed dns-persist-01: issuer-domain-names must have 1-10 entries");
        }
        let primary_issuer = issuer_names
            .first()
            .context("dns-persist-01 issuer-domain-names is empty")?;
        let account_uri = client
            .account_url()
            .context("account URL not known - cannot construct dns-persist-01 record")?
            .to_owned();
        let name = crate::challenge::dns_persist01::record_name(dns)?;
        let value = crate::challenge::dns_persist01::txt_record_value(
            primary_issuer,
            &account_uri,
            ctx.persist_policy,
            ctx.persist_until,
        )?;
        (None, dns.clone(), name, value)
    };
    Ok(DnsRecordMaterial {
        domain: dns_for_pending,
        challenge_url: ch.url.clone(),
        token,
        txt_name,
        txt_value,
    })
}

// NOT cancel-safe: dropping during best-effort cleanup can leave DNS records
// behind and cleanup handles incomplete.
async fn cleanup_pending_silent(
    hook: &std::path::Path,
    pending: &mut [DnsPending],
    unsafe_hooks: bool,
) {
    for q in pending {
        run_dns_hook_cleanup_silent(hook, &q.domain, &q.txt_name, &q.txt_value, unsafe_hooks).await;
        if let Some(handle) = q.cleanup_handle.take() {
            handle.complete();
        }
    }
}

// NOT cancel-safe: same contract as `cleanup_pending_silent`, but surfaces
// hook failures to the operator. Used where the run is about to abort for a
// reason the operator needs to see.
async fn cleanup_pending_logged(
    hook: &std::path::Path,
    pending: &mut [DnsPending],
    unsafe_hooks: bool,
) {
    for q in pending {
        run_dns_hook_cleanup_logged(hook, &q.domain, &q.txt_name, &q.txt_value, unsafe_hooks).await;
        if let Some(handle) = q.cleanup_handle.take() {
            handle.complete();
        }
    }
}

// NOT cancel-safe: cancellation while waiting skips this phase's immediate
// rollback; DNS records remain registered only for best-effort registry cleanup.
async fn wait_for_propagation(
    ctx: &RunContext<'_>,
    pending: &mut [DnsPending],
    hook: &std::path::Path,
) -> Result<()> {
    let domain_count = pending.len();
    if let Some(timeout_secs) = ctx.dns_wait {
        if domain_count > 1 {
            info!(
                "Waiting up to {timeout_secs}s for DNS TXT propagation across {domain_count} domains (parallel)..."
            );
        } else {
            info!("Waiting up to {timeout_secs}s for DNS TXT propagation...");
        }

        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
            ctx.dns_propagation_concurrency.get(),
        ));
        let mut set: tokio::task::JoinSet<Result<(crate::types::DnsName, bool)>> =
            tokio::task::JoinSet::new();
        for p in pending.iter() {
            let name = p.txt_name.clone();
            let value = p.txt_value.clone();
            let domain = p.domain.clone();
            let sem = std::sync::Arc::clone(&semaphore);
            let checker = std::sync::Arc::clone(ctx.dns_checker().await?);
            set.spawn(async move {
                let _permit = sem
                    .acquire()
                    .await
                    .map_err(|_| anyhow::anyhow!("DNS propagation semaphore closed"))?;
                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
                while std::time::Instant::now() < deadline {
                    match dns_txt_check(&checker, &name, &value).await {
                        Ok(true) => return Ok((domain, true)),
                        #[allow(clippy::match_same_arms)]
                        Ok(false) => {}
                        // Transient resolver errors (NXDOMAIN, SERVFAIL, timeout)
                        // are treated as "not yet propagated" so the deadline path
                        // runs and the cleanup hook fires. Bailing here would skip
                        // cleanup and leak the TXT record (TC-40b/d regression).
                        Err(_) => {}
                    }
                    tokio::time::sleep(crate::defaults::polling::DNS_PROPAGATION_POLL).await;
                }
                Ok((domain, false))
            });
        }

        let mut failed: Vec<crate::types::DnsName> = Vec::new();
        while let Some(result) = set.join_next().await {
            let (domain, found) = result.context("DNS propagation task panicked")??;
            if found {
                info!("DNS TXT record found for {domain}");
            } else {
                failed.push(domain);
            }
        }

        if !failed.is_empty() {
            cleanup_pending_logged(hook, pending, ctx.cli.unsafe_hooks).await;
            anyhow::bail!(
                "DNS TXT records not found within {timeout_secs}s for: {}",
                failed
                    .iter()
                    .map(crate::types::DnsName::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    Ok(())
}

// NOT cancel-safe: runs user hooks and signals ACME challenges; cancellation
// can leave CA validation in progress and DNS records pending cleanup.
async fn run_hooks_and_respond(
    ctx: &RunContext<'_>,
    client: &mut AcmeClient,
    pending: &[DnsPending],
) -> Result<()> {
    for p in pending {
        if let Some(script) = ctx.on_challenge_ready {
            if ctx.challenge_type == ChallengeType::Dns01 {
                let token = p
                    .token
                    .as_ref()
                    .context("dns-01 DnsPending must carry a token")?;
                let key_auth = crate::challenge::key_authorization(token, client.account_key())?;
                run_hook(
                    script,
                    &[
                        ("ACME_DOMAIN", p.domain.as_str()),
                        ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                        ("ACME_TOKEN", token.as_str()),
                        ("ACME_KEY_AUTH", &key_auth),
                        ("ACME_TXT_NAME", p.txt_name.as_str()),
                        ("ACME_TXT_VALUE", &p.txt_value),
                    ],
                    ctx.cli.unsafe_hooks,
                )
                .await?;
            } else {
                run_hook(
                    script,
                    &[
                        ("ACME_DOMAIN", p.domain.as_str()),
                        ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                        ("ACME_TXT_NAME", p.txt_name.as_str()),
                        ("ACME_TXT_VALUE", &p.txt_value),
                    ],
                    ctx.cli.unsafe_hooks,
                )
                .await?;
            }
        }
        client.respond_to_challenge(&p.challenge_url).await?;
        if !ctx.json && !ctx.silent {
            outln!("  Challenge response sent for {}", p.domain);
        }
    }
    Ok(())
}

// NOT cancel-safe: owns the failure-cleanup decision for the whole pending
// set. Cancellation here skips the rollback of every published TXT record;
// only the SIGINT registry remains.
async fn poll_authorizations_until_valid(
    ctx: &RunContext<'_>,
    client: &mut AcmeClient,
    pending: &mut [DnsPending],
    hook: &std::path::Path,
) -> Result<()> {
    for idx in 0..pending.len() {
        // The immutable borrow is confined to this block so it ends before the
        // rollback below takes `&mut pending` — no per-iteration clone needed.
        let outcome = {
            let Some(p) = pending.get(idx) else { continue };
            poll_one_authorization_until_valid(ctx, client, &p.authz_url, &p.domain).await
        };
        if let Err(e) = outcome {
            cleanup_pending_silent(hook, pending, ctx.cli.unsafe_hooks).await;
            return Err(e);
        }
    }
    Ok(())
}

// cancel-safe: pure polling of one authorization. Every failure path is a
// plain `bail!` with no external side effect; rollback of published TXT
// records is owned by the caller, which holds the whole pending set.
async fn poll_one_authorization_until_valid(
    ctx: &RunContext<'_>,
    client: &mut AcmeClient,
    authz_url: &url::Url,
    domain: &crate::types::DnsName,
) -> Result<()> {
    let poll_deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(ctx.challenge_timeout);
    let mut retry_after: Option<std::time::Duration> = None;
    loop {
        let remaining = poll_deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|r| !r.is_zero());
        let Some(remaining) = remaining else {
            anyhow::bail!(
                "authorization for {} did not complete within {}s",
                domain,
                ctx.challenge_timeout
            );
        };
        tokio::time::sleep(super::super::next_poll_delay(retry_after, remaining)).await;
        let (a, next_retry_after) = client.get_authorization_with_retry_after(authz_url).await?;
        retry_after = next_retry_after;
        if !ctx.json && !ctx.silent {
            outln!("  Authorization status for {}: {}", domain, a.status);
        }

        if let Some(ch) = a
            .challenges
            .iter()
            .find(|c| c.challenge_type == ctx.challenge_type)
        {
            if is_challenge_failed(ch) {
                let detail = ch
                    .error
                    .as_ref()
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default();
                anyhow::bail!("challenge validation failed for {domain}{detail}");
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
                let detail = a
                    .challenges
                    .iter()
                    .find(|c| c.challenge_type == ctx.challenge_type)
                    .and_then(|c| c.error.as_ref())
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default();
                anyhow::bail!(
                    "authorization failed for {} (status: {}){detail}",
                    domain,
                    a.status
                );
            }
        }
    }
    Ok(())
}

// NOT cancel-safe: cancellation during cleanup may leave later records
// uncleaned; completed cleanup handles are marked only after each hook returns.
async fn cleanup_records(ctx: &RunContext<'_>, pending: &mut [DnsPending], hook: &std::path::Path) {
    for p in pending {
        info!(
            "Calling DNS hook (cleanup): {} for {}",
            hook.display(),
            p.domain
        );
        run_dns_hook_cleanup_logged(
            hook,
            &p.domain,
            &p.txt_name,
            &p.txt_value,
            ctx.cli.unsafe_hooks,
        )
        .await;
        if let Some(handle) = p.cleanup_handle.take() {
            handle.complete();
        }
    }
}
