//! Pre-authorization phase (RFC 8555 §7.4.1).
//!
//! When `--pre-authorize` is set, fulfill challenges via `newAuthz` for every
//! identifier *before* placing the order. This lets operators front-load the
//! slow validation step (DNS propagation, manual challenges) and place the
//! order only once every identifier is already `valid`.

use anyhow::{Context, Result};
use tracing::info;

use crate::client::AcmeClient;
use crate::outln;
use crate::types::{AuthorizationStatus, ChallengeType, Identifier};

use super::super::{
    dns_txt_check, is_challenge_failed, run_dns_hook_cleanup_logged, run_dns_hook_create, run_hook,
    wait_for_enter,
};
use super::RunContext;

#[derive(Default)]
struct ChallengeCleanup {
    dns_cleanup_handle: Option<crate::cleanup::CleanupHandle>,
    http_cleanup_handle: Option<crate::cleanup::CleanupHandle>,
    dns_cleanup: Option<DnsChallengeCleanup>,
    serve_task: Option<tokio::task::JoinHandle<Result<(), anyhow::Error>>>,
    challenge_file: Option<std::path::PathBuf>,
}

struct DnsChallengeCleanup {
    domain: crate::types::DnsName,
    txt_name: crate::types::DnsName,
    txt_value: String,
}

// NOT cancel-safe: creates ACME authorizations, provisions local/DNS/TLS
// challenge material, and signals CA validation. Registered cleanup covers
// SIGINT best-effort rollback, not arbitrary future cancellation.
pub(super) async fn preauthorize(ctx: &mut RunContext<'_>, client: &mut AcmeClient) -> Result<()> {
    info!("Step 2: Pre-authorizing identifiers via newAuthz");
    let ids: Vec<Identifier> = ctx
        .domains
        .iter()
        .map(|d| Identifier::from_str_auto(d))
        .collect::<Result<Vec<_>>>()?;
    for id in ids {
        preauthorize_identifier(ctx, client, id).await?;
    }
    if !ctx.json && !ctx.silent {
        outln!("All identifiers pre-authorized");
    }
    Ok(())
}

// NOT cancel-safe: `new_authorization` mutates CA-side state, and the selected
// challenge helper may publish local or DNS challenge material before later
// awaits complete.
async fn preauthorize_identifier(
    ctx: &RunContext<'_>,
    client: &mut AcmeClient,
    id: Identifier,
) -> Result<()> {
    let domain_display = id.value_str().into_owned();
    let dns_for_hook = id.as_dns().cloned();
    let (authz, authz_url) = client.new_authorization(id).await?;
    if !ctx.json && !ctx.silent {
        outln!(
            "Pre-authorization for {} - status: {}",
            domain_display,
            authz.status
        );
        outln!("  Authz URL: {authz_url}");
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
        .with_context(|| format!("no {} challenge for {}", ctx.challenge_type, domain_display))?;
    let token = ch.token.as_ref();
    let require_token = || token.context("challenge has no token");
    let challenge_url = ch.url.clone();

    let mut cleanup = match &ctx.challenge_type {
        ChallengeType::Http01 => {
            provision_preauth_http01(ctx, client, require_token()?, &challenge_url).await?
        }
        ChallengeType::Dns01 => {
            provision_preauth_dns01(
                ctx,
                client,
                require_token()?,
                &challenge_url,
                &domain_display,
                dns_for_hook.as_ref(),
            )
            .await?
        }
        ChallengeType::DnsPersist01 => {
            provision_preauth_dns_persist01(
                ctx,
                client,
                ch.issuer_domain_names.as_deref(),
                &challenge_url,
                &domain_display,
                dns_for_hook.as_ref(),
            )
            .await?
        }
        ChallengeType::TlsAlpn01 => {
            provision_preauth_tlsalpn01(
                ctx,
                client,
                require_token()?,
                &challenge_url,
                &authz.identifier,
            )
            .await?
        }
        other @ ChallengeType::Unknown(_) => {
            anyhow::bail!("unsupported challenge type: {other}")
        }
    };

    poll_preauth_until_valid(ctx, client, &authz_url, &domain_display, &mut cleanup).await?;
    cleanup_preauth_challenge(ctx, &mut cleanup).await;
    Ok(())
}

// NOT cancel-safe: publishes HTTP-01 challenge material and then sends the
// nonce-consuming challenge response. In challenge-dir mode, register file
// cleanup before the blocking write so cancellation cannot leak a token file.
async fn provision_preauth_http01(
    ctx: &RunContext<'_>,
    client: &mut AcmeClient,
    token: &crate::types::ChallengeToken,
    challenge_url: &url::Url,
) -> Result<ChallengeCleanup> {
    let mut cleanup = ChallengeCleanup::default();
    if let Some(dir) = ctx.challenge_dir {
        // Cleanup is registered BEFORE the write so a cancellation
        // between the two cannot leak the token file;
        // `cleanup_challenge_file` tolerates a missing path.
        let auth = crate::challenge::http01::response_body(token, client.account_key())?;
        let file = crate::challenge::http01::challenge_file_path(dir, token);
        cleanup.http_cleanup_handle = Some(ctx.cleanup_registry.register(
            crate::cleanup::CleanupAction::HttpChallengeFile(file.clone()),
        ));
        let write_path = file.clone();
        tokio::task::spawn_blocking(move || {
            crate::challenge::http01::write_challenge_file_blocking(&write_path, &auth)
        })
        .await??;
        if !ctx.json && !ctx.silent {
            outln!("  Challenge file written to {}", file.display());
        }
        cleanup.challenge_file = Some(file);
    } else {
        if ctx.http_port != 80 {
            tracing::warn!(
                "HTTP-01 validation targets port 80. Server on port {}.",
                ctx.http_port
            );
        }
        let auth = crate::challenge::http01::response_body(token, client.account_key())?;
        let path = crate::challenge::http01::challenge_path(token);
        let listener = crate::challenge::http01::bind_or_suggest(ctx.http_port).await?;
        info!("HTTP-01 server listening on 0.0.0.0:{}", ctx.http_port);
        let task = tokio::spawn(crate::challenge::http01::run_accept_loop(
            listener, auth, path,
        ));
        cleanup.http_cleanup_handle = Some(ctx.cleanup_registry.register(
            crate::cleanup::CleanupAction::ServerTask(task.abort_handle()),
        ));
        cleanup.serve_task = Some(task);
    }
    client.respond_to_challenge(challenge_url).await?;
    if !ctx.json && !ctx.silent {
        outln!("  Challenge response sent - waiting for validation...");
    }
    Ok(cleanup)
}

// NOT cancel-safe: may run external DNS and challenge-ready hooks, publish DNS
// challenge material, and then send the nonce-consuming challenge response.
async fn provision_preauth_dns01(
    ctx: &RunContext<'_>,
    client: &mut AcmeClient,
    token: &crate::types::ChallengeToken,
    challenge_url: &url::Url,
    domain_display: &str,
    dns_for_hook: Option<&crate::types::DnsName>,
) -> Result<ChallengeCleanup> {
    let dns = dns_for_hook.ok_or_else(|| {
        anyhow::anyhow!("dns-01 challenges are not supported for IP identifiers ({domain_display})")
    })?;
    let txt_name = crate::challenge::dns01::record_name(dns)?;
    let txt_value = crate::challenge::dns01::txt_record_value(token, client.account_key())?;
    let mut dns_cleanup_handle = if let Some(hook) = ctx.dns_hook {
        run_dns_hook_create(hook, dns, &txt_name, &txt_value, ctx.cli.unsafe_hooks).await?;
        Some(
            ctx.cleanup_registry
                .register(crate::cleanup::CleanupAction::DnsRecord {
                    hook: hook.to_path_buf(),
                    domain: dns.clone(),
                    txt_name: txt_name.clone(),
                    txt_value: txt_value.clone(),
                }),
        )
    } else {
        if !ctx.silent {
            crate::challenge::dns01::print_instructions(dns, token, client.account_key())?;
        }
        None
    };
    wait_for_dns_txt_propagation(ctx, dns, &txt_name, &txt_value, &mut dns_cleanup_handle).await?;
    if let Some(script) = ctx.on_challenge_ready {
        let key_auth = crate::challenge::key_authorization(token, client.account_key())?;
        run_hook(
            script,
            &[
                ("ACME_DOMAIN", dns.as_str()),
                ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                ("ACME_TOKEN", token.as_str()),
                ("ACME_KEY_AUTH", &key_auth),
                ("ACME_TXT_NAME", txt_name.as_str()),
                ("ACME_TXT_VALUE", &txt_value),
            ],
            ctx.cli.unsafe_hooks,
        )
        .await?;
    }
    let dns_cleanup = Some(DnsChallengeCleanup {
        domain: dns.clone(),
        txt_name,
        txt_value,
    });
    client.respond_to_challenge(challenge_url).await?;
    Ok(ChallengeCleanup {
        dns_cleanup_handle,
        http_cleanup_handle: None,
        dns_cleanup,
        serve_task: None,
        challenge_file: None,
    })
}

// NOT cancel-safe: may run external DNS and challenge-ready hooks, publish
// persistent DNS validation material, and then send the nonce-consuming
// challenge response.
async fn provision_preauth_dns_persist01(
    ctx: &RunContext<'_>,
    client: &mut AcmeClient,
    issuer_names: Option<&[String]>,
    challenge_url: &url::Url,
    domain_display: &str,
    dns_for_hook: Option<&crate::types::DnsName>,
) -> Result<ChallengeCleanup> {
    let dns = dns_for_hook.ok_or_else(|| {
        anyhow::anyhow!(
            "dns-persist-01 challenges are not supported for IP identifiers ({domain_display})"
        )
    })?;
    let issuer_names =
        issuer_names.context("dns-persist-01 challenge has no issuer-domain-names")?;
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
    let txt_name = crate::challenge::dns_persist01::record_name(dns)?;
    let txt_value = crate::challenge::dns_persist01::txt_record_value(
        primary_issuer,
        &account_uri,
        ctx.persist_policy,
        ctx.persist_until,
    )?;
    let mut dns_cleanup_handle = if let Some(hook) = ctx.dns_hook {
        run_dns_hook_create(hook, dns, &txt_name, &txt_value, ctx.cli.unsafe_hooks).await?;
        Some(
            ctx.cleanup_registry
                .register(crate::cleanup::CleanupAction::DnsRecord {
                    hook: hook.to_path_buf(),
                    domain: dns.clone(),
                    txt_name: txt_name.clone(),
                    txt_value: txt_value.clone(),
                }),
        )
    } else {
        if !ctx.silent {
            crate::challenge::dns_persist01::print_instructions(
                dns,
                issuer_names,
                &account_uri,
                ctx.persist_policy,
                ctx.persist_until,
            )?;
        }
        None
    };
    wait_for_dns_txt_propagation(ctx, dns, &txt_name, &txt_value, &mut dns_cleanup_handle).await?;
    if let Some(script) = ctx.on_challenge_ready {
        run_hook(
            script,
            &[
                ("ACME_DOMAIN", dns.as_str()),
                ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                ("ACME_TXT_NAME", txt_name.as_str()),
                ("ACME_TXT_VALUE", &txt_value),
            ],
            ctx.cli.unsafe_hooks,
        )
        .await?;
    }
    let dns_cleanup = Some(DnsChallengeCleanup {
        domain: dns.clone(),
        txt_name,
        txt_value,
    });
    client.respond_to_challenge(challenge_url).await?;
    Ok(ChallengeCleanup {
        dns_cleanup_handle,
        http_cleanup_handle: None,
        dns_cleanup,
        serve_task: None,
        challenge_file: None,
    })
}

// NOT cancel-safe: waits for operator/hook-provided TLS-ALPN-01 setup and then
// sends the nonce-consuming challenge response.
async fn provision_preauth_tlsalpn01(
    ctx: &RunContext<'_>,
    client: &mut AcmeClient,
    token: &crate::types::ChallengeToken,
    challenge_url: &url::Url,
    identifier: &Identifier,
) -> Result<ChallengeCleanup> {
    if !ctx.silent {
        crate::challenge::tlsalpn01::print_instructions(
            &identifier.value_str(),
            token,
            client.account_key(),
        )?;
        outln!("Press Enter once the TLS server is configured...");
        wait_for_enter().await?;
    }
    if let Some(script) = ctx.on_challenge_ready {
        let key_auth = crate::challenge::key_authorization(token, client.account_key())?;
        run_hook(
            script,
            &[
                ("ACME_DOMAIN", &identifier.value_str()),
                ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                ("ACME_TOKEN", token.as_str()),
                ("ACME_KEY_AUTH", &key_auth),
            ],
            ctx.cli.unsafe_hooks,
        )
        .await?;
    }
    client.respond_to_challenge(challenge_url).await?;
    Ok(ChallengeCleanup::default())
}

// NOT cancel-safe: polls authorization with nonce-consuming POST-as-GET calls.
// Every failure path — timeout, challenge failure, terminal authz status —
// runs the full `cleanup_preauth_challenge` rollback before bailing, so DNS
// records and HTTP artifacts are both released and their registry handles
// completed. Cancellation is the one path that skips this.
async fn poll_preauth_until_valid(
    ctx: &RunContext<'_>,
    client: &mut AcmeClient,
    authz_url: &url::Url,
    domain_display: &str,
    cleanup: &mut ChallengeCleanup,
) -> Result<()> {
    // Poll authorization until valid (max ctx.challenge_timeout)
    let poll_deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(ctx.challenge_timeout);
    let mut retry_after: Option<std::time::Duration> = None;
    loop {
        let remaining = poll_deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|r| !r.is_zero());
        let Some(remaining) = remaining else {
            cleanup_preauth_challenge(ctx, cleanup).await;
            anyhow::bail!(
                "pre-authorization for {} did not complete within {}s",
                domain_display,
                ctx.challenge_timeout
            );
        };
        tokio::time::sleep(super::next_poll_delay(retry_after, remaining)).await;
        let (a, next_retry_after) = client.get_authorization_with_retry_after(authz_url).await?;
        retry_after = next_retry_after;
        if !ctx.json && !ctx.silent {
            outln!("  Authorization status: {}", a.status);
        }
        if let Some(ch) = a
            .challenges
            .iter()
            .find(|c| c.challenge_type == ctx.challenge_type)
        {
            if is_challenge_failed(ch) {
                cleanup_preauth_challenge(ctx, cleanup).await;
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
                cleanup_preauth_challenge(ctx, cleanup).await;
                let detail = a
                    .challenges
                    .iter()
                    .find(|c| c.challenge_type == ctx.challenge_type)
                    .and_then(|c| c.error.as_ref())
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default();
                anyhow::bail!(
                    "pre-authorization failed for {} (status: {}){detail}",
                    domain_display,
                    a.status
                );
            }
        }
    }
    Ok(())
}

// NOT cancel-safe: runs best-effort external DNS cleanup before deregistering
// the cleanup handle, then aborts/removes HTTP artifacts. If cancelled before
// `complete`, the DNS cleanup action remains registered for SIGINT cleanup.
async fn cleanup_preauth_challenge(ctx: &RunContext<'_>, cleanup: &mut ChallengeCleanup) {
    // Clean up DNS hook if applicable (dns-01 and dns-persist-01)
    if let Some(ref dns_cleanup) = cleanup.dns_cleanup
        && let Some(hook) = ctx.dns_hook
    {
        run_dns_hook_cleanup_logged(
            hook,
            &dns_cleanup.domain,
            &dns_cleanup.txt_name,
            &dns_cleanup.txt_value,
            ctx.cli.unsafe_hooks,
        )
        .await;
        if let Some(handle) = cleanup.dns_cleanup_handle.take() {
            handle.complete();
        }
    }
    if let Some(handle) = cleanup.serve_task.take() {
        handle.abort();
    }
    if let Some(ref f) = cleanup.challenge_file {
        crate::challenge::http01::cleanup_challenge_file(f);
    }
    if let Some(handle) = cleanup.http_cleanup_handle.take() {
        handle.complete();
    }
}

// NOT cancel-safe: loops over DNS TXT lookups and may run the logged DNS cleanup
// hook on timeout, completing the registry handle once the record is released.
async fn wait_for_dns_txt_propagation(
    ctx: &RunContext<'_>,
    dns: &crate::types::DnsName,
    txt_name: &crate::types::DnsName,
    txt_value: &str,
    dns_cleanup_handle: &mut Option<crate::cleanup::CleanupHandle>,
) -> Result<()> {
    if let Some(timeout_secs) = ctx.dns_wait {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let mut found = false;
        while std::time::Instant::now() < deadline {
            if dns_txt_check(ctx.dns_checker().await?, txt_name, txt_value).await? {
                found = true;
                break;
            }
            tokio::time::sleep(crate::defaults::polling::DNS_PROPAGATION_POLL).await;
        }
        if !found {
            if let Some(hook) = ctx.dns_hook {
                run_dns_hook_cleanup_logged(hook, dns, txt_name, txt_value, ctx.cli.unsafe_hooks)
                    .await;
                if let Some(handle) = dns_cleanup_handle.take() {
                    handle.complete();
                }
            }
            anyhow::bail!("DNS TXT record for {txt_name} not found within {timeout_secs}s");
        }
    } else if ctx.dns_hook.is_none() && !ctx.silent {
        outln!("Press Enter once the record has propagated...");
        wait_for_enter().await?;
    }
    Ok(())
}
