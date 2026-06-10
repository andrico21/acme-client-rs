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
};
use super::RunContext;

// NOT cancel-safe: same hook + CA-signal contract as the authorize pipeline.
pub(super) async fn preauthorize(ctx: &mut RunContext<'_>, client: &mut AcmeClient) -> Result<()> {
    info!("Step 2: Pre-authorizing identifiers via newAuthz");
    let ids: Vec<Identifier> = ctx
        .domains
        .iter()
        .map(|d| Identifier::from_str_auto(d))
        .collect::<Result<Vec<_>>>()?;
    for id in ids {
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
            continue;
        }

        let ch = authz
            .challenges
            .iter()
            .find(|c| c.challenge_type == ctx.challenge_type)
            .with_context(|| {
                format!("no {} challenge for {}", ctx.challenge_type, domain_display)
            })?;
        let token = ch.token.as_ref();
        let require_token = || token.context("challenge has no token");
        let challenge_url = ch.url.clone();

        let mut challenge_file: Option<std::path::PathBuf> = None;
        let mut serve_task: Option<tokio::task::JoinHandle<Result<(), anyhow::Error>>> = None;
        let mut dns_cleanup_info: Option<(crate::types::DnsName, String)> = None;
        let mut dns_cleanup_handle: Option<crate::cleanup::CleanupHandle> = None;

        match &ctx.challenge_type {
            ChallengeType::Http01 => {
                let token = require_token()?;
                if let Some(dir) = ctx.challenge_dir {
                    let file = crate::challenge::http01::write_challenge_file(
                        dir,
                        token,
                        client.account_key(),
                    )?;
                    if !ctx.json && !ctx.silent {
                        outln!("  Challenge file written to {}", file.display());
                    }
                    let _ = ctx.cleanup_registry.register(
                        crate::cleanup::CleanupAction::HttpChallengeFile(file.clone()),
                    );
                    challenge_file = Some(file);
                } else {
                    if ctx.http_port != 80 {
                        tracing::warn!(
                            "HTTP-01 validation targets port 80. Server on port {}.",
                            ctx.http_port
                        );
                    }
                    let auth =
                        crate::challenge::http01::response_body(token, client.account_key())?;
                    let path = crate::challenge::http01::challenge_path(token);
                    let listener = crate::challenge::http01::bind_or_suggest(ctx.http_port).await?;
                    info!("HTTP-01 server listening on 0.0.0.0:{}", ctx.http_port);
                    let task = tokio::spawn(crate::challenge::http01::run_accept_loop(
                        listener, auth, path,
                    ));
                    let _ =
                        ctx.cleanup_registry
                            .register(crate::cleanup::CleanupAction::ServerTask(
                                task.abort_handle(),
                            ));
                    serve_task = Some(task);
                }
                client.respond_to_challenge(&challenge_url).await?;
                if !ctx.json && !ctx.silent {
                    outln!("  Challenge response sent - waiting for validation...");
                }
            }
            ChallengeType::Dns01 => {
                let token = require_token()?;
                let dns = dns_for_hook.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "dns-01 challenges are not supported for IP identifiers ({domain_display})"
                    )
                })?;
                let txt_name = crate::challenge::dns01::record_name(dns)?;
                let txt_value =
                    crate::challenge::dns01::txt_record_value(token, client.account_key())?;
                if let Some(hook) = ctx.dns_hook {
                    run_dns_hook_create(hook, dns, &txt_name, &txt_value, ctx.cli.unsafe_hooks)
                        .await?;
                    dns_cleanup_handle = Some(ctx.cleanup_registry.register(
                        crate::cleanup::CleanupAction::DnsRecord {
                            hook: hook.to_path_buf(),
                            domain: dns.clone(),
                            txt_name: txt_name.clone(),
                            txt_value: txt_value.clone(),
                        },
                    ));
                } else if !ctx.silent {
                    crate::challenge::dns01::print_instructions(dns, token, client.account_key())?;
                }
                if let Some(timeout_secs) = ctx.dns_wait {
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
                    let mut found = false;
                    while std::time::Instant::now() < deadline {
                        if dns_txt_check(&ctx.dns_checker, txt_name.as_str(), &txt_value).await? {
                            found = true;
                            break;
                        }
                        tokio::time::sleep(crate::defaults::polling::DNS_PROPAGATION_POLL).await;
                    }
                    if !found {
                        if let Some(hook) = ctx.dns_hook {
                            run_dns_hook_cleanup_logged(
                                hook,
                                dns,
                                &txt_name,
                                &txt_value,
                                ctx.cli.unsafe_hooks,
                            )
                            .await;
                        }
                        anyhow::bail!(
                            "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                        );
                    }
                } else if ctx.dns_hook.is_none() && !ctx.silent {
                    outln!("Press Enter once the record has propagated...");
                    let _ = tokio::task::spawn_blocking(|| {
                        std::io::stdin().read_line(&mut String::new())
                    })
                    .await;
                }
                if let Some(script) = ctx.on_challenge_ready {
                    let key_auth =
                        crate::challenge::key_authorization(token, client.account_key())?;
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
                dns_cleanup_info = Some((txt_name, txt_value));
                client.respond_to_challenge(&challenge_url).await?;
            }
            ChallengeType::DnsPersist01 => {
                let dns = dns_for_hook.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "dns-persist-01 challenges are not supported for IP identifiers ({domain_display})"
                    )
                })?;
                let issuer_names = ch
                    .issuer_domain_names
                    .as_ref()
                    .context("dns-persist-01 challenge has no issuer-domain-names")?;
                if issuer_names.is_empty() || issuer_names.len() > 10 {
                    anyhow::bail!(
                        "malformed dns-persist-01: issuer-domain-names must have 1-10 entries"
                    );
                }
                let primary_issuer = issuer_names
                    .first()
                    .context("dns-persist-01 issuer-domain-names is empty")?;
                let account_uri = client
                    .account_url()
                    .context("account URL not known - cannot construct dns-persist-01 record")?
                    .to_string();
                let txt_name = crate::challenge::dns_persist01::record_name(dns)?;
                let txt_value = crate::challenge::dns_persist01::txt_record_value(
                    primary_issuer,
                    &account_uri,
                    ctx.persist_policy,
                    ctx.persist_until,
                )?;
                if let Some(hook) = ctx.dns_hook {
                    run_dns_hook_create(hook, dns, &txt_name, &txt_value, ctx.cli.unsafe_hooks)
                        .await?;
                    dns_cleanup_handle = Some(ctx.cleanup_registry.register(
                        crate::cleanup::CleanupAction::DnsRecord {
                            hook: hook.to_path_buf(),
                            domain: dns.clone(),
                            txt_name: txt_name.clone(),
                            txt_value: txt_value.clone(),
                        },
                    ));
                } else if !ctx.silent {
                    crate::challenge::dns_persist01::print_instructions(
                        dns,
                        issuer_names,
                        &account_uri,
                        ctx.persist_policy,
                        ctx.persist_until,
                    )?;
                }
                if let Some(timeout_secs) = ctx.dns_wait {
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
                    let mut found = false;
                    while std::time::Instant::now() < deadline {
                        if dns_txt_check(&ctx.dns_checker, txt_name.as_str(), &txt_value).await? {
                            found = true;
                            break;
                        }
                        tokio::time::sleep(crate::defaults::polling::DNS_PROPAGATION_POLL).await;
                    }
                    if !found {
                        if let Some(hook) = ctx.dns_hook {
                            run_dns_hook_cleanup_logged(
                                hook,
                                dns,
                                &txt_name,
                                &txt_value,
                                ctx.cli.unsafe_hooks,
                            )
                            .await;
                        }
                        anyhow::bail!(
                            "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                        );
                    }
                } else if ctx.dns_hook.is_none() && !ctx.silent {
                    outln!("Press Enter once the record has propagated...");
                    let _ = tokio::task::spawn_blocking(|| {
                        std::io::stdin().read_line(&mut String::new())
                    })
                    .await;
                }
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
                dns_cleanup_info = Some((txt_name, txt_value));
                client.respond_to_challenge(&challenge_url).await?;
            }
            ChallengeType::TlsAlpn01 => {
                let token = require_token()?;
                if !ctx.silent {
                    crate::challenge::tlsalpn01::print_instructions(
                        &authz.identifier.value_str(),
                        token,
                        client.account_key(),
                    )?;
                    outln!("Press Enter once the TLS server is configured...");
                    let _ = tokio::task::spawn_blocking(|| {
                        std::io::stdin().read_line(&mut String::new())
                    })
                    .await;
                }
                if let Some(script) = ctx.on_challenge_ready {
                    let key_auth =
                        crate::challenge::key_authorization(token, client.account_key())?;
                    run_hook(
                        script,
                        &[
                            ("ACME_DOMAIN", &authz.identifier.value_str()),
                            ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                            ("ACME_TOKEN", token.as_str()),
                            ("ACME_KEY_AUTH", &key_auth),
                        ],
                        ctx.cli.unsafe_hooks,
                    )
                    .await?;
                }
                client.respond_to_challenge(&challenge_url).await?;
            }
            other @ ChallengeType::Unknown(_) => {
                anyhow::bail!("unsupported challenge type: {other}")
            }
        }

        // Poll authorization until valid (max ctx.challenge_timeout)
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
                    "pre-authorization for {} did not complete within {}s",
                    domain_display,
                    ctx.challenge_timeout
                );
            }
            tokio::time::sleep(crate::defaults::polling::ACME_RESOURCE_POLL).await;
            let a = client.get_authorization(&authz_url).await?;
            if !ctx.json && !ctx.silent {
                outln!("  Authorization status: {}", a.status);
            }
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
                        "pre-authorization failed for {} (status: {}){detail}",
                        domain_display,
                        a.status
                    );
                }
            }
        }

        // Clean up DNS hook if applicable (dns-01 and dns-persist-01)
        if let Some((ref txt_name, ref txt_value)) = dns_cleanup_info
            && let Some(hook) = ctx.dns_hook
            && let Some(ref dns) = dns_for_hook
        {
            run_dns_hook_cleanup_logged(hook, dns, txt_name, txt_value, ctx.cli.unsafe_hooks).await;
            if let Some(handle) = &dns_cleanup_handle {
                handle.complete();
            }
        }
        if let Some(handle) = serve_task.take() {
            handle.abort();
        }
        if let Some(ref f) = challenge_file {
            crate::challenge::http01::cleanup_challenge_file(f);
        }
    }
    if !ctx.json && !ctx.silent {
        outln!("All identifiers pre-authorized");
    }
    Ok(())
}
