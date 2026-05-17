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

pub(super) async fn preauthorize(ctx: &mut RunContext<'_>, client: &mut AcmeClient) -> Result<()> {
    info!("Step 2: Pre-authorizing identifiers via newAuthz");
    let ids: Vec<Identifier> = ctx
        .domains
        .iter()
        .map(|d| Identifier::from_str_auto(d))
        .collect::<Result<Vec<_>>>()?;
    for id in ids {
        let domain_display = id.value_str().into_owned();
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
        let token = if ctx.challenge_type != ChallengeType::DnsPersist01 {
            ch.token.as_deref().context("challenge has no token")?
        } else {
            "" // dns-persist-01 has no token
        };
        let challenge_url = ch.url.clone();

        let mut challenge_file: Option<std::path::PathBuf> = None;
        let mut serve_task: Option<tokio::task::JoinHandle<Result<(), anyhow::Error>>> = None;
        let mut dns_cleanup_info: Option<(String, String)> = None;

        match &ctx.challenge_type {
            ChallengeType::Http01 => {
                if let Some(dir) = ctx.challenge_dir {
                    let file = crate::challenge::http01::write_challenge_file(
                        dir,
                        token,
                        client.account_key(),
                    )?;
                    if !ctx.json && !ctx.silent {
                        outln!("  Challenge file written to {}", file.display());
                    }
                    ctx.cleanup_registry.register(
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
                    let auth = crate::challenge::http01::response_body(token, client.account_key());
                    let path = crate::challenge::http01::challenge_path(token);
                    let listener = crate::challenge::http01::bind_or_suggest(ctx.http_port).await?;
                    info!("HTTP-01 server listening on 0.0.0.0:{}", ctx.http_port);
                    let task = tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        loop {
                            let (mut stream, _addr) = listener.accept().await?;
                            let mut buf = vec![0u8; 4096];
                            let n = stream.read(&mut buf).await?;
                            let req = String::from_utf8_lossy(&buf[..n]);
                            if req.contains(&path) {
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nServer: acme-client-rs\r\n\r\n{}",
                                    auth.len(),
                                    auth
                                );
                                stream.write_all(resp.as_bytes()).await?;
                                return Ok(());
                            }
                            stream
                                .write_all(
                                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nServer: acme-client-rs\r\n\r\n",
                                )
                                .await?;
                        }
                    });
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
                if authz.identifier.is_ip() {
                    anyhow::bail!(
                        "dns-01 challenges are not supported for IP identifiers ({})",
                        authz.identifier.value_str()
                    );
                }
                let txt_name = crate::challenge::dns01::record_name(&authz.identifier.value_str());
                let txt_value =
                    crate::challenge::dns01::txt_record_value(token, client.account_key());
                if let Some(hook) = ctx.dns_hook {
                    run_dns_hook_create(
                        hook,
                        &authz.identifier.value_str(),
                        &txt_name,
                        &txt_value,
                    )?;
                    ctx.cleanup_registry
                        .register(crate::cleanup::CleanupAction::DnsRecord {
                            hook: hook.to_path_buf(),
                            domain: authz.identifier.value_str().into_owned(),
                            txt_name: txt_name.clone(),
                            txt_value: txt_value.clone(),
                        });
                } else if !ctx.silent {
                    crate::challenge::dns01::print_instructions(
                        &authz.identifier.value_str(),
                        token,
                        client.account_key(),
                    );
                }
                if let Some(timeout_secs) = ctx.dns_wait {
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
                    let mut found = false;
                    while std::time::Instant::now() < deadline {
                        if dns_txt_check(&ctx.dns_checker, &txt_name, &txt_value).await? {
                            found = true;
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                    if !found {
                        if let Some(hook) = ctx.dns_hook {
                            run_dns_hook_cleanup_logged(
                                hook,
                                &authz.identifier.value_str(),
                                &txt_name,
                                &txt_value,
                            );
                        }
                        anyhow::bail!(
                            "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                        );
                    }
                } else if ctx.dns_hook.is_none() && !ctx.silent {
                    outln!("Press Enter once the record has propagated...");
                    let _ = std::io::stdin().read_line(&mut String::new());
                }
                if let Some(script) = ctx.on_challenge_ready {
                    let key_auth = crate::challenge::key_authorization(token, client.account_key());
                    let txt_name_ref =
                        crate::challenge::dns01::record_name(&authz.identifier.value_str());
                    let txt_value_ref =
                        crate::challenge::dns01::txt_record_value(token, client.account_key());
                    run_hook(
                        script,
                        &[
                            ("ACME_DOMAIN", &authz.identifier.value_str()),
                            ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                            ("ACME_TOKEN", token),
                            ("ACME_KEY_AUTH", &key_auth),
                            ("ACME_TXT_NAME", &txt_name_ref),
                            ("ACME_TXT_VALUE", &txt_value_ref),
                        ],
                    )?;
                }
                dns_cleanup_info = Some((txt_name, txt_value));
                client.respond_to_challenge(&challenge_url).await?;
            }
            ChallengeType::DnsPersist01 => {
                if authz.identifier.is_ip() {
                    anyhow::bail!(
                        "dns-persist-01 challenges are not supported for IP identifiers ({})",
                        authz.identifier.value_str()
                    );
                }
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
                let txt_name =
                    crate::challenge::dns_persist01::record_name(&authz.identifier.value_str());
                let txt_value = crate::challenge::dns_persist01::txt_record_value(
                    &issuer_names[0],
                    &account_uri,
                    ctx.persist_policy,
                    ctx.persist_until,
                )?;
                if let Some(hook) = ctx.dns_hook {
                    run_dns_hook_create(
                        hook,
                        &authz.identifier.value_str(),
                        &txt_name,
                        &txt_value,
                    )?;
                    ctx.cleanup_registry
                        .register(crate::cleanup::CleanupAction::DnsRecord {
                            hook: hook.to_path_buf(),
                            domain: authz.identifier.value_str().into_owned(),
                            txt_name: txt_name.clone(),
                            txt_value: txt_value.clone(),
                        });
                } else if !ctx.silent {
                    crate::challenge::dns_persist01::print_instructions(
                        &authz.identifier.value_str(),
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
                        if dns_txt_check(&ctx.dns_checker, &txt_name, &txt_value).await? {
                            found = true;
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                    if !found {
                        if let Some(hook) = ctx.dns_hook {
                            run_dns_hook_cleanup_logged(
                                hook,
                                &authz.identifier.value_str(),
                                &txt_name,
                                &txt_value,
                            );
                        }
                        anyhow::bail!(
                            "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                        );
                    }
                } else if ctx.dns_hook.is_none() && !ctx.silent {
                    outln!("Press Enter once the record has propagated...");
                    let _ = std::io::stdin().read_line(&mut String::new());
                }
                if let Some(script) = ctx.on_challenge_ready {
                    run_hook(
                        script,
                        &[
                            ("ACME_DOMAIN", &authz.identifier.value_str()),
                            ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                            ("ACME_TXT_NAME", &txt_name),
                            ("ACME_TXT_VALUE", &txt_value),
                        ],
                    )?;
                }
                dns_cleanup_info = Some((txt_name, txt_value));
                client.respond_to_challenge(&challenge_url).await?;
            }
            ChallengeType::TlsAlpn01 => {
                if !ctx.silent {
                    crate::challenge::tlsalpn01::print_instructions(
                        &authz.identifier.value_str(),
                        token,
                        client.account_key(),
                    );
                    outln!("Press Enter once the TLS server is configured...");
                    let _ = std::io::stdin().read_line(&mut String::new());
                }
                if let Some(script) = ctx.on_challenge_ready {
                    let key_auth = crate::challenge::key_authorization(token, client.account_key());
                    run_hook(
                        script,
                        &[
                            ("ACME_DOMAIN", &authz.identifier.value_str()),
                            ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                            ("ACME_TOKEN", token),
                            ("ACME_KEY_AUTH", &key_auth),
                        ],
                    )?;
                }
                client.respond_to_challenge(&challenge_url).await?;
            }
            other => anyhow::bail!("unsupported challenge type: {other}"),
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
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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
                    anyhow::bail!("challenge validation failed for {}{detail}", domain_display);
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
                    anyhow::bail!("pre-authorization failed for {}{detail}", domain_display);
                }
                _ => continue,
            }
        }

        // Clean up DNS hook if applicable (dns-01 and dns-persist-01)
        if let Some((ref txt_name, ref txt_value)) = dns_cleanup_info
            && let Some(hook) = ctx.dns_hook
        {
            run_dns_hook_cleanup_logged(hook, &domain_display, txt_name, txt_value);
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
