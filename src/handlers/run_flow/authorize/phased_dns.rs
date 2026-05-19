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

pub(super) async fn run_phased_dns(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    order: &Order,
) -> Result<()> {
    let hook = ctx.dns_hook.unwrap(); // safe: dispatcher only routes here when set

    // Phase 1: Fetch all authorizations and create DNS records
    let mut pending: Vec<DnsPending> = Vec::new();
    for authz_url in &order.authorizations {
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
            continue;
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

        let (token, dns_for_pending, txt_name, txt_value) =
            if ctx.challenge_type == ChallengeType::Dns01 {
                let dns = authz.identifier.as_dns().ok_or_else(|| {
                    anyhow::anyhow!(
                        "dns-01 challenges are not supported for IP identifiers ({})",
                        authz.identifier.value_str()
                    )
                })?;
                let t = ch.token.clone().context("challenge has no token")?;
                let name = crate::challenge::dns01::record_name(dns);
                let value = crate::challenge::dns01::txt_record_value(&t, client.account_key());
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
                    anyhow::bail!(
                        "malformed dns-persist-01: issuer-domain-names must have 1-10 entries"
                    );
                }
                let account_uri = client
                    .account_url()
                    .context("account URL not known - cannot construct dns-persist-01 record")?
                    .to_string();
                let name = crate::challenge::dns_persist01::record_name(dns);
                let value = crate::challenge::dns_persist01::txt_record_value(
                    &issuer_names[0],
                    &account_uri,
                    ctx.persist_policy,
                    ctx.persist_until,
                )?;
                (None, dns.clone(), name, value)
            };

        // Run create hook
        info!(
            "Calling DNS hook (create): {} for {}",
            hook.display(),
            dns_for_pending.as_str()
        );
        if let Err(e) = run_dns_hook_create(hook, &dns_for_pending, &txt_name, &txt_value) {
            // Clean up any records we already created
            for p in &pending {
                run_dns_hook_cleanup_silent(hook, &p.domain, &p.txt_name, &p.txt_value);
            }
            return Err(e);
        }
        ctx.cleanup_registry
            .register(crate::cleanup::CleanupAction::DnsRecord {
                hook: hook.to_path_buf(),
                domain: dns_for_pending.as_str().to_string(),
                txt_name: txt_name.as_str().to_string(),
                txt_value: txt_value.clone(),
            });

        pending.push(DnsPending {
            authz_url: authz_url.clone(),
            domain: dns_for_pending,
            challenge_url: ch.url.clone(),
            token,
            txt_name,
            txt_value,
        });
    }

    if !pending.is_empty() {
        let domain_count = pending.len();

        // Phase 2: Wait for DNS propagation (parallel)
        if let Some(timeout_secs) = ctx.dns_wait {
            if domain_count > 1 {
                info!(
                    "Waiting up to {timeout_secs}s for DNS TXT propagation across {domain_count} ctx.domains (parallel)..."
                );
            } else {
                info!("Waiting up to {timeout_secs}s for DNS TXT propagation...");
            }

            let semaphore =
                std::sync::Arc::new(tokio::sync::Semaphore::new(ctx.dns_propagation_concurrency));
            let mut set: tokio::task::JoinSet<anyhow::Result<(crate::types::DnsName, bool)>> =
                tokio::task::JoinSet::new();
            for p in &pending {
                let name = p.txt_name.clone();
                let value = p.txt_value.clone();
                let domain = p.domain.clone();
                let sem = semaphore.clone();
                let checker = std::sync::Arc::clone(&ctx.dns_checker);
                set.spawn(async move {
                    let _permit = sem.acquire().await.expect("semaphore closed unexpectedly");
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
                    while std::time::Instant::now() < deadline {
                        match dns_txt_check(&checker, name.as_str(), &value).await {
                            Ok(true) => return Ok((domain, true)),
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
                // Clean up ALL created records before bailing
                for p in &pending {
                    run_dns_hook_cleanup_logged(hook, &p.domain, &p.txt_name, &p.txt_value);
                }
                anyhow::bail!(
                    "DNS TXT records not found within {timeout_secs}s for: {}",
                    failed
                        .iter()
                        .map(|d| d.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }

        // Phase 3: ctx.on_challenge_ready hooks + respond_to_challenge (serial)
        for p in &pending {
            if let Some(script) = ctx.on_challenge_ready {
                if ctx.challenge_type == ChallengeType::Dns01 {
                    let token = p
                        .token
                        .as_ref()
                        .expect("dns-01 DnsPending always carries a token");
                    let key_auth = crate::challenge::key_authorization(token, client.account_key());
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
                    )?;
                } else {
                    run_hook(
                        script,
                        &[
                            ("ACME_DOMAIN", p.domain.as_str()),
                            ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                            ("ACME_TXT_NAME", p.txt_name.as_str()),
                            ("ACME_TXT_VALUE", &p.txt_value),
                        ],
                    )?;
                }
            }
            client.respond_to_challenge(&p.challenge_url).await?;
            if !ctx.json && !ctx.silent {
                outln!("  Challenge response sent for {}", p.domain);
            }
        }

        // Phase 4: Poll all authorizations until valid (serial)
        for p in &pending {
            let poll_deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(ctx.challenge_timeout);
            loop {
                if std::time::Instant::now() > poll_deadline {
                    // Clean up remaining records
                    for q in &pending {
                        run_dns_hook_cleanup_silent(hook, &q.domain, &q.txt_name, &q.txt_value);
                    }
                    anyhow::bail!(
                        "authorization for {} did not complete within {}s",
                        p.domain,
                        ctx.challenge_timeout
                    );
                }
                tokio::time::sleep(crate::defaults::polling::ACME_RESOURCE_POLL).await;
                let a = client.get_authorization(&p.authz_url).await?;
                if !ctx.json && !ctx.silent {
                    outln!("  Authorization status for {}: {}", p.domain, a.status);
                }

                if let Some(ch) = a
                    .challenges
                    .iter()
                    .find(|c| c.challenge_type == ctx.challenge_type)
                {
                    if is_challenge_failed(ch) {
                        for q in &pending {
                            run_dns_hook_cleanup_silent(hook, &q.domain, &q.txt_name, &q.txt_value);
                        }
                        let detail = ch
                            .error
                            .as_ref()
                            .map(|e| format!(": {e}"))
                            .unwrap_or_default();
                        anyhow::bail!("challenge validation failed for {}{detail}", p.domain);
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
                        for q in &pending {
                            run_dns_hook_cleanup_silent(hook, &q.domain, &q.txt_name, &q.txt_value);
                        }
                        let detail = a
                            .challenges
                            .iter()
                            .find(|c| c.challenge_type == ctx.challenge_type)
                            .and_then(|c| c.error.as_ref())
                            .map(|e| format!(": {e}"))
                            .unwrap_or_default();
                        anyhow::bail!("authorization failed for {}{detail}", p.domain);
                    }
                    _ => continue,
                }
            }
        }

        // Phase 5: Cleanup all DNS records
        for p in &pending {
            info!(
                "Calling DNS hook (cleanup): {} for {}",
                hook.display(),
                p.domain
            );
            run_dns_hook_cleanup_logged(hook, &p.domain, &p.txt_name, &p.txt_value);
        }
    }
    Ok(())
}
