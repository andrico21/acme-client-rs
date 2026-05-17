//! Per-domain authorization phase.
//!
//! Drives every authorization on the order to `valid`. Two sub-paths:
//!
//! - **Phased DNS** (used when `--dns-hook` is set with dns-01 / dns-persist-01):
//!   provision all TXT records first, run propagation checks concurrently, then
//!   respond to challenges serially.
//! - **Sequential** (HTTP-01, TLS-ALPN-01, manual DNS): provision + validate
//!   one identifier at a time.

use anyhow::{Context, Result};
use tracing::info;

use crate::client::AcmeClient;
use crate::outln;
use crate::types::{
    AuthorizationStatus, CHALLENGE_TYPE_DNS_PERSIST01, CHALLENGE_TYPE_DNS01, CHALLENGE_TYPE_HTTP01,
    CHALLENGE_TYPE_TLSALPN01, Order,
};

use super::super::{
    dns_txt_check, is_challenge_failed, run_dns_hook_cleanup_logged, run_dns_hook_cleanup_silent,
    run_hook,
};
use super::RunContext;

pub(super) async fn authorize(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    order: &Order,
) -> Result<()> {
    // ── Authorizations ──────────────────────────────────────────────────
    info!(
        "Step {}: Completing authorizations",
        if ctx.pre_authorize { 4 } else { 3 }
    );

    // DNS challenges with a hook benefit from parallel propagation waiting:
    // all TXT records are created first, then all propagation checks run
    // concurrently, then challenges are responded to serially (nonce chain).
    let use_parallel_dns = ctx.dns_hook.is_some()
        && (ctx.challenge_type == CHALLENGE_TYPE_DNS01
            || ctx.challenge_type == CHALLENGE_TYPE_DNS_PERSIST01);

    if use_parallel_dns {
        // ── Phased DNS authorization (parallel propagation wait) ────────
        struct DnsPending {
            authz_url: String,
            domain: String,
            challenge_url: String,
            token: String,
            txt_name: String,
            txt_value: String,
        }
        let hook = ctx.dns_hook.unwrap(); // safe: checked above

        // Phase 1: Fetch all authorizations and create DNS records
        let mut pending: Vec<DnsPending> = Vec::new();
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

            let (token, txt_name, txt_value) = if ctx.challenge_type == CHALLENGE_TYPE_DNS01 {
                if authz.identifier.is_ip() {
                    anyhow::bail!(
                        "dns-01 challenges are not supported for IP identifiers ({})",
                        authz.identifier.value
                    );
                }
                let t = ch
                    .token
                    .as_deref()
                    .context("challenge has no token")?
                    .to_string();
                let name = crate::challenge::dns01::record_name(&authz.identifier.value);
                let value = crate::challenge::dns01::txt_record_value(&t, client.account_key());
                (t, name, value)
            } else {
                // dns-persist-01
                if authz.identifier.is_ip() {
                    anyhow::bail!(
                        "dns-persist-01 challenges are not supported for IP identifiers ({})",
                        authz.identifier.value
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
                let name = crate::challenge::dns_persist01::record_name(&authz.identifier.value);
                let value = crate::challenge::dns_persist01::txt_record_value(
                    &issuer_names[0],
                    &account_uri,
                    ctx.persist_policy,
                    ctx.persist_until,
                )?;
                (String::new(), name, value)
            };

            // Run create hook
            info!(
                "Calling DNS hook (create): {} for {}",
                hook.display(),
                authz.identifier.value
            );
            let status = std::process::Command::new(hook)
                .env("ACME_DOMAIN", &authz.identifier.value)
                .env("ACME_TXT_NAME", &txt_name)
                .env("ACME_TXT_VALUE", &txt_value)
                .env("ACME_ACTION", "create")
                .status()
                .with_context(|| format!("failed to run DNS hook: {}", hook.display()))?;
            if !status.success() {
                // Clean up any records we already created
                for p in &pending {
                    run_dns_hook_cleanup_silent(hook, &p.domain, &p.txt_name, &p.txt_value);
                }
                anyhow::bail!("DNS hook (create) exited with {status}");
            }
            ctx.cleanup_registry
                .register(crate::cleanup::CleanupAction::DnsRecord {
                    hook: hook.to_path_buf(),
                    domain: authz.identifier.value.clone(),
                    txt_name: txt_name.clone(),
                    txt_value: txt_value.clone(),
                });

            pending.push(DnsPending {
                authz_url: authz_url.clone(),
                domain: authz.identifier.value.clone(),
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

                let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
                    ctx.dns_propagation_concurrency,
                ));
                let mut set: tokio::task::JoinSet<anyhow::Result<(String, bool)>> =
                    tokio::task::JoinSet::new();
                for p in &pending {
                    let name = p.txt_name.clone();
                    let value = p.txt_value.clone();
                    let domain = p.domain.clone();
                    let sem = semaphore.clone();
                    let checker = std::sync::Arc::clone(&ctx.dns_checker);
                    set.spawn(async move {
                        let _permit = sem.acquire().await.expect("semaphore closed unexpectedly");
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(timeout_secs);
                        while std::time::Instant::now() < deadline {
                            match dns_txt_check(&checker, &name, &value).await {
                                Ok(true) => return Ok((domain, true)),
                                Ok(false) => {}
                                // Transient resolver errors (NXDOMAIN, SERVFAIL, timeout)
                                // are treated as "not yet propagated" so the deadline path
                                // runs and the cleanup hook fires. Bailing here would skip
                                // cleanup and leak the TXT record (TC-40b/d regression).
                                Err(_) => {}
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                        Ok((domain, false))
                    });
                }

                let mut failed: Vec<String> = Vec::new();
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
                        failed.join(", ")
                    );
                }
            }

            // Phase 3: ctx.on_challenge_ready hooks + respond_to_challenge (serial)
            for p in &pending {
                if let Some(script) = ctx.on_challenge_ready {
                    if ctx.challenge_type == CHALLENGE_TYPE_DNS01 {
                        let key_auth =
                            crate::challenge::key_authorization(&p.token, client.account_key());
                        run_hook(
                            script,
                            &[
                                ("ACME_DOMAIN", p.domain.as_str()),
                                ("ACME_CHALLENGE_TYPE", ctx.challenge_type),
                                ("ACME_TOKEN", &p.token),
                                ("ACME_KEY_AUTH", &key_auth),
                                ("ACME_TXT_NAME", &p.txt_name),
                                ("ACME_TXT_VALUE", &p.txt_value),
                            ],
                        )?;
                    } else {
                        run_hook(
                            script,
                            &[
                                ("ACME_DOMAIN", p.domain.as_str()),
                                ("ACME_CHALLENGE_TYPE", ctx.challenge_type),
                                ("ACME_TXT_NAME", &p.txt_name),
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
                let poll_deadline = std::time::Instant::now()
                    + std::time::Duration::from_secs(ctx.challenge_timeout);
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
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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
                                run_dns_hook_cleanup_silent(
                                    hook,
                                    &q.domain,
                                    &q.txt_name,
                                    &q.txt_value,
                                );
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
                                run_dns_hook_cleanup_silent(
                                    hook,
                                    &q.domain,
                                    &q.txt_name,
                                    &q.txt_value,
                                );
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
    } else {
        // ── Sequential authorization (HTTP-01, TLS-ALPN-01, manual DNS) ─────
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
            let token = if ctx.challenge_type != CHALLENGE_TYPE_DNS_PERSIST01 {
                ch.token.as_deref().context("challenge has no token")?
            } else {
                "" // dns-persist-01 has no token
            };
            let challenge_url = ch.url.clone();

            // Track challenge file for cleanup (file mode only)
            let mut challenge_file: Option<std::path::PathBuf> = None;
            // Background HTTP server handle (standalone mode only)
            let mut serve_task: Option<tokio::task::JoinHandle<Result<(), anyhow::Error>>> = None;

            match ctx.challenge_type {
                CHALLENGE_TYPE_HTTP01 => {
                    let validation_url = format!(
                        "http://{}/.well-known/acme-challenge/{}",
                        authz.identifier.value, token
                    );
                    info!("ACME server will validate via: {validation_url}");

                    if let Some(dir) = ctx.challenge_dir {
                        // File mode: write token file for an existing web server
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
                        // Standalone mode: bind a TCP server
                        if ctx.http_port != 80 {
                            tracing::warn!(
                                "HTTP-01 validation (RFC 8555 §8.3) always targets port 80.\n  \
                             Your server is listening on port {}.\n  \
                             Ensure traffic to port 80 is forwarded to port {}, \
                             or use --challenge-dir with an existing web server.",
                                ctx.http_port,
                                ctx.http_port
                            );
                        }
                        let auth =
                            crate::challenge::http01::response_body(token, client.account_key());
                        let path = crate::challenge::http01::challenge_path(token);

                        let listener =
                            crate::challenge::http01::bind_or_suggest(ctx.http_port).await?;
                        info!("HTTP-01 server listening on 0.0.0.0:{}", ctx.http_port);

                        let task = tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            loop {
                                let (mut stream, addr) = listener.accept().await?;
                                tracing::debug!("HTTP-01: connection from {addr}");
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await?;
                                let req = String::from_utf8_lossy(&buf[..n]);
                                if req.contains(&path) {
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\n\
                                     Content-Type: application/octet-stream\r\n\
                                     Content-Length: {}\r\n\
                                     X-Content-Type-Options: nosniff\r\n\
                                     Connection: close\r\n\
                                     Server: acme-client-rs\r\n\r\n{}",
                                        auth.len(),
                                        auth
                                    );
                                    stream.write_all(resp.as_bytes()).await?;
                                    info!("HTTP-01: served challenge response to {addr}");
                                    return Ok(());
                                }
                                let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nServer: acme-client-rs\r\n\r\n";
                                stream.write_all(not_found.as_bytes()).await?;
                            }
                        });
                        ctx.cleanup_registry
                            .register(crate::cleanup::CleanupAction::ServerTask(
                                task.abort_handle(),
                            ));
                        serve_task = Some(task);
                    }

                    // Yield briefly so the HTTP-01 server task is ready
                    // before telling the CA to validate.
                    tokio::task::yield_now().await;

                    let ch_resp = client.respond_to_challenge(&challenge_url).await?;
                    if let Some(ref err) = ch_resp.error {
                        // Some CAs (e.g. step-ca) validate synchronously during the
                        // challenge POST and may return an error on a still-pending
                        // challenge. Per RFC 8555 §7.5.1 this is just a failed
                        // attempt — the authorization may still succeed on retry.
                        // Log a warning and let the polling loop handle it.
                        tracing::warn!(
                            "HTTP-01 challenge returned error (will keep polling): {err}\n  \
                         Validation URL: {validation_url}"
                        );
                    }
                    if !ctx.json && !ctx.silent {
                        outln!("  Challenge response sent - waiting for validation...");
                    }
                }
                CHALLENGE_TYPE_DNS01 => {
                    if authz.identifier.is_ip() {
                        anyhow::bail!(
                            "dns-01 challenges are not supported for IP identifiers ({})",
                            authz.identifier.value
                        );
                    }
                    let txt_name = crate::challenge::dns01::record_name(&authz.identifier.value);
                    let txt_value =
                        crate::challenge::dns01::txt_record_value(token, client.account_key());

                    // No hook: print instructions for manual setup
                    if !ctx.silent {
                        crate::challenge::dns01::print_instructions(
                            &authz.identifier.value,
                            token,
                            client.account_key(),
                        );
                    }

                    if let Some(timeout_secs) = ctx.dns_wait {
                        // Poll DNS propagation
                        info!("Waiting up to {timeout_secs}s for DNS TXT propagation...");
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(timeout_secs);
                        let mut found = false;
                        while std::time::Instant::now() < deadline {
                            if dns_txt_check(&ctx.dns_checker, &txt_name, &txt_value).await? {
                                info!("DNS TXT record found");
                                found = true;
                                break;
                            }
                            tracing::debug!("DNS TXT not yet visible, retrying in 5s...");
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                        if !found {
                            anyhow::bail!(
                                "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                            );
                        }
                    } else if !ctx.silent {
                        // Interactive: wait for Enter
                        outln!("Press Enter once the record has propagated...");
                        let _ = std::io::stdin().read_line(&mut String::new());
                    }

                    if let Some(script) = ctx.on_challenge_ready {
                        let key_auth =
                            crate::challenge::key_authorization(token, client.account_key());
                        let txt_name_ref =
                            crate::challenge::dns01::record_name(&authz.identifier.value);
                        let txt_value_ref =
                            crate::challenge::dns01::txt_record_value(token, client.account_key());
                        run_hook(
                            script,
                            &[
                                ("ACME_DOMAIN", &authz.identifier.value),
                                ("ACME_CHALLENGE_TYPE", ctx.challenge_type),
                                ("ACME_TOKEN", token),
                                ("ACME_KEY_AUTH", &key_auth),
                                ("ACME_TXT_NAME", &txt_name_ref),
                                ("ACME_TXT_VALUE", &txt_value_ref),
                            ],
                        )?;
                    }

                    client.respond_to_challenge(&challenge_url).await?;
                }
                CHALLENGE_TYPE_DNS_PERSIST01 => {
                    if authz.identifier.is_ip() {
                        anyhow::bail!(
                            "dns-persist-01 challenges are not supported for IP identifiers ({})",
                            authz.identifier.value
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
                        crate::challenge::dns_persist01::record_name(&authz.identifier.value);
                    let txt_value = crate::challenge::dns_persist01::txt_record_value(
                        &issuer_names[0],
                        &account_uri,
                        ctx.persist_policy,
                        ctx.persist_until,
                    )?;

                    // No hook: print instructions for manual setup
                    if !ctx.silent {
                        crate::challenge::dns_persist01::print_instructions(
                            &authz.identifier.value,
                            issuer_names,
                            &account_uri,
                            ctx.persist_policy,
                            ctx.persist_until,
                        )?;
                    }

                    if let Some(timeout_secs) = ctx.dns_wait {
                        info!("Waiting up to {timeout_secs}s for DNS TXT propagation...");
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(timeout_secs);
                        let mut found = false;
                        while std::time::Instant::now() < deadline {
                            if dns_txt_check(&ctx.dns_checker, &txt_name, &txt_value).await? {
                                info!("DNS TXT record found");
                                found = true;
                                break;
                            }
                            tracing::debug!("DNS TXT not yet visible, retrying in 5s...");
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                        if !found {
                            anyhow::bail!(
                                "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                            );
                        }
                    } else if !ctx.silent {
                        outln!("Press Enter once the record has propagated...");
                        let _ = std::io::stdin().read_line(&mut String::new());
                    }

                    if let Some(script) = ctx.on_challenge_ready {
                        run_hook(
                            script,
                            &[
                                ("ACME_DOMAIN", &authz.identifier.value),
                                ("ACME_CHALLENGE_TYPE", ctx.challenge_type),
                                ("ACME_TXT_NAME", &txt_name),
                                ("ACME_TXT_VALUE", &txt_value),
                            ],
                        )?;
                    }

                    client.respond_to_challenge(&challenge_url).await?;
                }
                CHALLENGE_TYPE_TLSALPN01 => {
                    if !ctx.silent {
                        crate::challenge::tlsalpn01::print_instructions(
                            &authz.identifier.value,
                            token,
                            client.account_key(),
                        );
                        outln!("Press Enter once the TLS server is configured...");
                        let _ = std::io::stdin().read_line(&mut String::new());
                    }

                    if let Some(script) = ctx.on_challenge_ready {
                        let key_auth =
                            crate::challenge::key_authorization(token, client.account_key());
                        run_hook(
                            script,
                            &[
                                ("ACME_DOMAIN", &authz.identifier.value),
                                ("ACME_CHALLENGE_TYPE", ctx.challenge_type),
                                ("ACME_TOKEN", token),
                                ("ACME_KEY_AUTH", &key_auth),
                            ],
                        )?;
                    }

                    client.respond_to_challenge(&challenge_url).await?;
                }
                other => anyhow::bail!("unsupported challenge type: {other}"),
            }

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
    } // end sequential authorization
    Ok(())
}
