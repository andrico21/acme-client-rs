//! Full end-to-end issuance/renewal flow (the 'run' subcommand).
//!
//! This is the largest handler — it orchestrates account lookup, ARI-driven
//! renewal decisions, order placement, challenge fulfillment (HTTP-01,
//! DNS-01, DNS-PERSIST-01, TLS-ALPN-01), CSR generation, finalization,
//! and post-issuance hook invocation.

use anyhow::{Context, Result};
use tracing::info;

use crate::cert_info::{cert_days_remaining, cert_san_identifiers, normalize_identifier};
use crate::cli::{CertKeyAlgorithm, Cli, OutputFormat};
use crate::client::{AcmeClient, compute_cert_id};
use crate::csr::{encrypt_private_key, generate_csr, pem_to_der};
use crate::dns_check::DnsChecker;
use crate::types::{
    AuthorizationStatus, CHALLENGE_TYPE_DNS_PERSIST01, CHALLENGE_TYPE_DNS01, CHALLENGE_TYPE_HTTP01,
    CHALLENGE_TYPE_TLSALPN01, Identifier, OrderStatus,
};
use crate::{build_client, outln};

use super::{
    check_wildcard_compatible, dns_txt_check, is_challenge_terminal, parse_eab,
    run_dns_hook_cleanup_logged, run_dns_hook_cleanup_silent, run_dns_hook_create, run_hook,
};
// ── Full automated flow ─────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub(crate) async fn cmd_run(
    cli: &Cli,
    domains: Vec<String>,
    contact: Option<String>,
    challenge_type: &str,
    http_port: u16,
    challenge_dir: Option<&std::path::Path>,
    dns_hook: Option<&std::path::Path>,
    dns_wait: Option<u64>,
    dns_propagation_concurrency: usize,
    challenge_timeout: u64,
    cert_output: &std::path::Path,
    key_output: &std::path::Path,
    days: Option<u32>,
    key_password: Option<&str>,
    key_password_file: Option<&std::path::Path>,
    on_challenge_ready: Option<&std::path::Path>,
    on_cert_issued: Option<&std::path::Path>,
    eab_kid: Option<&str>,
    eab_hmac_key: Option<&str>,
    pre_authorize: bool,
    ari: bool,
    reissue_on_mismatch: bool,
    print_cert: bool,
    persist_policy: Option<&str>,
    persist_until: Option<u64>,
    cert_key_alg: CertKeyAlgorithm,
    profile: Option<&str>,
    force: bool,
    cleanup_registry: &crate::cleanup::CleanupRegistry,
) -> Result<()> {
    check_wildcard_compatible(&domains, challenge_type)?;

    crate::hook_check::validate_all_hooks(
        &[
            ("dns_hook", dns_hook),
            ("on_challenge_ready", on_challenge_ready),
            ("on_cert_issued", on_cert_issued),
        ],
        cli.unsafe_hooks,
    )?;

    let domains: Vec<String> = domains
        .iter()
        .map(|d| Identifier::from_str_auto(d).map(|id| id.value))
        .collect::<Result<Vec<_>>>()?;

    let dns_checker = std::sync::Arc::new(
        DnsChecker::new(cli.dns_check_mode, cli.dns_check_dnssec)
            .context("failed to initialize DNS resolver for dns-01 propagation checks")?,
    );

    // ── 0. Renewal check ────────────────────────────────────────────────
    let json = cli.output_format == OutputFormat::Json;
    let silent = cli.silent;

    // Track cert ID for ARI replaceOrder (set during ARI check)
    let mut ari_cert_id: Option<String> = None;

    // Reuse client built during ARI check to avoid double directory+account fetch
    let mut early_client: Option<AcmeClient> = None;

    if cert_output.exists() {
        // ── 0pre. Domain mismatch check ────────────────────────────────
        let mut skip_renewal_checks = false;

        let requested: std::collections::BTreeSet<String> =
            domains.iter().map(|d| normalize_identifier(d)).collect();

        match cert_san_identifiers(cert_output) {
            Ok(cert_sans) => {
                if requested != cert_sans {
                    let added: Vec<&str> = requested
                        .difference(&cert_sans)
                        .map(|s| s.as_str())
                        .collect();
                    let removed: Vec<&str> = cert_sans
                        .difference(&requested)
                        .map(|s| s.as_str())
                        .collect();

                    if reissue_on_mismatch {
                        if !silent {
                            if json {
                                outln!(
                                    "{}",
                                    serde_json::json!({
                                        "command": "run",
                                        "action": "reissue",
                                        "reason": "domain_mismatch",
                                        "cert_domains": cert_sans,
                                        "requested_domains": requested,
                                        "added": added,
                                        "removed": removed,
                                    })
                                );
                            } else {
                                outln!(
                                    "Domain mismatch detected (added: [{}], removed: [{}]), reissuing certificate...",
                                    added.join(", "),
                                    removed.join(", "),
                                );
                            }
                        }
                        // Skip ARI/days checks — proceed directly to issuance
                        // (ari_cert_id stays None: this is reissuance, not renewal)
                        skip_renewal_checks = true;
                    } else {
                        if !silent {
                            if json {
                                outln!(
                                    "{}",
                                    serde_json::json!({
                                        "command": "run",
                                        "action": "skip",
                                        "reason": "domain_mismatch",
                                        "hint": "use --reissue-on-mismatch to override",
                                        "cert_domains": cert_sans,
                                        "requested_domains": requested,
                                        "added": added,
                                        "removed": removed,
                                    })
                                );
                            } else {
                                outln!(
                                    "Domain mismatch: cert has [{}], requested [{}] (added: [{}], removed: [{}]). \
                                     Use --reissue-on-mismatch to override.",
                                    cert_sans
                                        .iter()
                                        .map(|s| s.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                    requested
                                        .iter()
                                        .map(|s| s.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                    added.join(", "),
                                    removed.join(", "),
                                );
                            }
                        }
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Could not read SANs from {}: {e} — skipping domain mismatch check",
                    cert_output.display()
                );
            }
        }

        if !skip_renewal_checks {
            // ── 0a. ARI-based renewal check (RFC 9702) ─────────────────────
            if ari {
                match std::fs::read_to_string(cert_output) {
                    Ok(pem_data) => {
                        match pem_to_der(&pem_data) {
                            Ok(cert_der) => {
                                // Build client early so we reuse directory + account for step 1
                                let mut ari_client = build_client(cli).await?;
                                // ARI uses POST-as-GET, needs KID
                                ari_client.create_account(None, true, None).await?;

                                if ari_client.supports_ari() {
                                    match ari_client.get_renewal_info(&cert_der).await {
                                        Ok((info, _retry_after)) => {
                                            let now = time::OffsetDateTime::now_utc();
                                            if let Ok(start) = time::OffsetDateTime::parse(
                                                &info.suggested_window.start,
                                                &time::format_description::well_known::Rfc3339,
                                            ) {
                                                if now < start {
                                                    if !silent {
                                                        if json {
                                                            outln!(
                                                                "{}",
                                                                serde_json::json!({
                                                                    "command": "run",
                                                                    "action": "skip",
                                                                    "reason": "ari",
                                                                    "window_start": info.suggested_window.start,
                                                                    "window_end": info.suggested_window.end,
                                                                    "cert_path": cert_output.display().to_string(),
                                                                })
                                                            );
                                                        } else {
                                                            outln!(
                                                                "ARI: renewal window starts {} - skipping renewal",
                                                                info.suggested_window.start
                                                            );
                                                        }
                                                    }
                                                    return Ok(());
                                                }
                                                if !json && !silent {
                                                    outln!(
                                                        "ARI: renewal window is open ({} - {}), renewing...",
                                                        info.suggested_window.start,
                                                        info.suggested_window.end
                                                    );
                                                }
                                            }
                                            // Set cert_id for replaceOrder
                                            if let Ok(cid) = compute_cert_id(&cert_der) {
                                                ari_cert_id = Some(cid);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "ARI check failed: {e} - falling back to --days check"
                                            );
                                        }
                                    }
                                } else {
                                    tracing::warn!(
                                        "Server does not support ARI - falling back to --days check"
                                    );
                                }
                                early_client = Some(ari_client);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Could not parse certificate {}: {e}",
                                    cert_output.display()
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Could not read certificate {}: {e}", cert_output.display());
                    }
                }
            }

            // ── 0b. Days-based renewal check (fallback / standalone) ────────
            if ari_cert_id.is_none()
                && let Some(threshold) = days
            {
                match cert_days_remaining(cert_output) {
                    Ok(remaining) if remaining > threshold as i64 => {
                        if json {
                            if !silent {
                                outln!(
                                    "{}",
                                    serde_json::json!({
                                        "command": "run",
                                        "action": "skip",
                                        "reason": "days",
                                        "days_remaining": remaining,
                                        "threshold": threshold,
                                        "cert_path": cert_output.display().to_string(),
                                    })
                                );
                            }
                        } else if !silent {
                            outln!(
                                "Certificate {} has {remaining} days remaining (threshold: {threshold}), skipping renewal",
                                cert_output.display()
                            );
                        }
                        return Ok(());
                    }
                    Ok(remaining) => {
                        if !json && !silent {
                            outln!(
                                "Certificate {} expires in {remaining} days (threshold: {threshold}), renewing...",
                                cert_output.display()
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Could not read certificate {}: {e} - proceeding with renewal",
                            cert_output.display()
                        );
                    }
                }
            }
        } // if !skip_renewal_checks
    }

    // ── 1. Account ──────────────────────────────────────────────────────
    info!("Step 1: Creating / looking up account");
    let mut client = match early_client.take() {
        Some(c) => c,
        None => build_client(cli).await?,
    };
    let contact_list = contact.map(|c| vec![format!("mailto:{c}")]);
    let eab = parse_eab(eab_kid, eab_hmac_key)?;
    let eab_ref = eab.as_ref().map(|(kid, key)| {
        use secrecy::ExposeSecret;
        (kid.as_str(), key.expose_secret().as_slice())
    });
    let account = client.create_account(contact_list, true, eab_ref).await?;
    if !json && !silent {
        outln!("Account status: {}", account.status);
    }

    // ── 2. Pre-authorization (optional, RFC 8555 §7.4.1) ───────────────
    if pre_authorize {
        info!("Step 2: Pre-authorizing identifiers via newAuthz");
        let ids: Vec<Identifier> = domains
            .iter()
            .map(Identifier::from_str_auto)
            .collect::<Result<Vec<_>>>()?;
        for id in ids {
            let domain_display = id.value.clone();
            let (authz, authz_url) = client.new_authorization(id).await?;
            if !json && !silent {
                outln!(
                    "Pre-authorization for {} - status: {}",
                    domain_display,
                    authz.status
                );
                outln!("  Authz URL: {authz_url}");
            }

            if authz.status == AuthorizationStatus::Valid {
                if !json && !silent {
                    outln!("  Already valid, skipping");
                }
                continue;
            }

            let ch = authz
                .challenges
                .iter()
                .find(|c| c.challenge_type == challenge_type)
                .with_context(|| format!("no {challenge_type} challenge for {}", domain_display))?;
            let token = if challenge_type != CHALLENGE_TYPE_DNS_PERSIST01 {
                ch.token.as_deref().context("challenge has no token")?
            } else {
                "" // dns-persist-01 has no token
            };
            let challenge_url = ch.url.clone();

            let mut challenge_file: Option<std::path::PathBuf> = None;
            let mut serve_task: Option<tokio::task::JoinHandle<Result<(), anyhow::Error>>> = None;
            let mut dns_cleanup_info: Option<(String, String)> = None;

            match challenge_type {
                CHALLENGE_TYPE_HTTP01 => {
                    if let Some(dir) = challenge_dir {
                        let file = crate::challenge::http01::write_challenge_file(
                            dir,
                            token,
                            client.account_key(),
                        )?;
                        if !json && !silent {
                            outln!("  Challenge file written to {}", file.display());
                        }
                        cleanup_registry.register(
                            crate::cleanup::CleanupAction::HttpChallengeFile(file.clone()),
                        );
                        challenge_file = Some(file);
                    } else {
                        if http_port != 80 {
                            tracing::warn!(
                                "HTTP-01 validation targets port 80. Server on port {http_port}."
                            );
                        }
                        let auth =
                            crate::challenge::http01::response_body(token, client.account_key());
                        let path = crate::challenge::http01::challenge_path(token);
                        let listener = crate::challenge::http01::bind_or_suggest(http_port).await?;
                        info!("HTTP-01 server listening on 0.0.0.0:{http_port}");
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
                        cleanup_registry.register(crate::cleanup::CleanupAction::ServerTask(
                            task.abort_handle(),
                        ));
                        serve_task = Some(task);
                    }
                    client.respond_to_challenge(&challenge_url).await?;
                    if !json && !silent {
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
                    if let Some(hook) = dns_hook {
                        run_dns_hook_create(hook, &authz.identifier.value, &txt_name, &txt_value)?;
                        cleanup_registry.register(crate::cleanup::CleanupAction::DnsRecord {
                            hook: hook.to_path_buf(),
                            domain: authz.identifier.value.clone(),
                            txt_name: txt_name.clone(),
                            txt_value: txt_value.clone(),
                        });
                    } else if !silent {
                        crate::challenge::dns01::print_instructions(
                            &authz.identifier.value,
                            token,
                            client.account_key(),
                        );
                    }
                    if let Some(timeout_secs) = dns_wait {
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(timeout_secs);
                        let mut found = false;
                        while std::time::Instant::now() < deadline {
                            if dns_txt_check(&dns_checker, &txt_name, &txt_value).await? {
                                found = true;
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                        if !found {
                            if let Some(hook) = dns_hook {
                                run_dns_hook_cleanup_logged(
                                    hook,
                                    &authz.identifier.value,
                                    &txt_name,
                                    &txt_value,
                                );
                            }
                            anyhow::bail!(
                                "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                            );
                        }
                    } else if dns_hook.is_none() && !silent {
                        outln!("Press Enter once the record has propagated...");
                        let _ = std::io::stdin().read_line(&mut String::new());
                    }
                    if let Some(script) = on_challenge_ready {
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
                                ("ACME_CHALLENGE_TYPE", challenge_type),
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
                        persist_policy,
                        persist_until,
                    )?;
                    if let Some(hook) = dns_hook {
                        run_dns_hook_create(hook, &authz.identifier.value, &txt_name, &txt_value)?;
                        cleanup_registry.register(crate::cleanup::CleanupAction::DnsRecord {
                            hook: hook.to_path_buf(),
                            domain: authz.identifier.value.clone(),
                            txt_name: txt_name.clone(),
                            txt_value: txt_value.clone(),
                        });
                    } else if !silent {
                        crate::challenge::dns_persist01::print_instructions(
                            &authz.identifier.value,
                            issuer_names,
                            &account_uri,
                            persist_policy,
                            persist_until,
                        )?;
                    }
                    if let Some(timeout_secs) = dns_wait {
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(timeout_secs);
                        let mut found = false;
                        while std::time::Instant::now() < deadline {
                            if dns_txt_check(&dns_checker, &txt_name, &txt_value).await? {
                                found = true;
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                        if !found {
                            if let Some(hook) = dns_hook {
                                run_dns_hook_cleanup_logged(
                                    hook,
                                    &authz.identifier.value,
                                    &txt_name,
                                    &txt_value,
                                );
                            }
                            anyhow::bail!(
                                "DNS TXT record for {txt_name} not found within {timeout_secs}s"
                            );
                        }
                    } else if dns_hook.is_none() && !silent {
                        outln!("Press Enter once the record has propagated...");
                        let _ = std::io::stdin().read_line(&mut String::new());
                    }
                    if let Some(script) = on_challenge_ready {
                        run_hook(
                            script,
                            &[
                                ("ACME_DOMAIN", &authz.identifier.value),
                                ("ACME_CHALLENGE_TYPE", challenge_type),
                                ("ACME_TXT_NAME", &txt_name),
                                ("ACME_TXT_VALUE", &txt_value),
                            ],
                        )?;
                    }
                    dns_cleanup_info = Some((txt_name, txt_value));
                    client.respond_to_challenge(&challenge_url).await?;
                }
                CHALLENGE_TYPE_TLSALPN01 => {
                    if !silent {
                        crate::challenge::tlsalpn01::print_instructions(
                            &authz.identifier.value,
                            token,
                            client.account_key(),
                        );
                        outln!("Press Enter once the TLS server is configured...");
                        let _ = std::io::stdin().read_line(&mut String::new());
                    }
                    if let Some(script) = on_challenge_ready {
                        let key_auth =
                            crate::challenge::key_authorization(token, client.account_key());
                        run_hook(
                            script,
                            &[
                                ("ACME_DOMAIN", &authz.identifier.value),
                                ("ACME_CHALLENGE_TYPE", challenge_type),
                                ("ACME_TOKEN", token),
                                ("ACME_KEY_AUTH", &key_auth),
                            ],
                        )?;
                    }
                    client.respond_to_challenge(&challenge_url).await?;
                }
                other => anyhow::bail!("unsupported challenge type: {other}"),
            }

            // Poll authorization until valid (max challenge_timeout)
            let poll_deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(challenge_timeout);
            loop {
                if std::time::Instant::now() > poll_deadline {
                    if let Some(handle) = serve_task.take() {
                        handle.abort();
                    }
                    if let Some(ref f) = challenge_file {
                        crate::challenge::http01::cleanup_challenge_file(f);
                    }
                    anyhow::bail!(
                        "pre-authorization for {} did not complete within {challenge_timeout}s",
                        domain_display
                    );
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let a = client.get_authorization(&authz_url).await?;
                if !json && !silent {
                    outln!("  Authorization status: {}", a.status);
                }
                if let Some(ch) = a
                    .challenges
                    .iter()
                    .find(|c| c.challenge_type == challenge_type)
                {
                    if is_challenge_terminal(ch) {
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
                            .find(|c| c.challenge_type == challenge_type)
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
                && let Some(hook) = dns_hook
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
        if !json && !silent {
            outln!("All identifiers pre-authorized");
        }
    }

    // ── 2b. New order ───────────────────────────────────────────────────
    info!("Step {}: Placing order", if pre_authorize { 3 } else { 2 });
    let profile_owned = profile.map(String::from);
    // Validate profile against advertised list (draft-ietf-acme-profiles-01 §4)
    if let Some(ref p) = profile_owned
        && let Some(available) = client.available_profiles()
        && !available.contains_key(p)
    {
        tracing::warn!(
            "Profile \"{p}\" is not advertised by the server (available: {})",
            available.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    check_wildcard_compatible(&domains, challenge_type)?;
    let ids: Vec<Identifier> = domains
        .iter()
        .map(Identifier::from_str_auto)
        .collect::<Result<Vec<_>>>()?;
    let (order, order_url) = if let Some(ref cert_id) = ari_cert_id {
        info!("Using ARI replaces field (certID: {cert_id})");
        client
            .new_order_replacing(ids, cert_id.clone(), profile_owned)
            .await?
    } else {
        client.new_order(ids, profile_owned).await?
    };
    if !json && !silent {
        outln!("Order URL:  {order_url}");
        if let Some(ref p) = order.profile {
            outln!("Profile:    {p}");
        }
        outln!("Order status: {}", order.status);
    }

    // ── Authorizations ──────────────────────────────────────────────────
    info!(
        "Step {}: Completing authorizations",
        if pre_authorize { 4 } else { 3 }
    );

    // DNS challenges with a hook benefit from parallel propagation waiting:
    // all TXT records are created first, then all propagation checks run
    // concurrently, then challenges are responded to serially (nonce chain).
    let use_parallel_dns = dns_hook.is_some()
        && (challenge_type == CHALLENGE_TYPE_DNS01
            || challenge_type == CHALLENGE_TYPE_DNS_PERSIST01);

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
        let hook = dns_hook.unwrap(); // safe: checked above

        // Phase 1: Fetch all authorizations and create DNS records
        let mut pending: Vec<DnsPending> = Vec::new();
        for authz_url in &order.authorizations {
            let authz = client.get_authorization(authz_url).await?;
            if !json && !silent {
                outln!(
                    "Authorization for {} - status: {}",
                    authz.identifier.value,
                    authz.status
                );
            }
            if authz.status == AuthorizationStatus::Valid {
                if !json && !silent {
                    outln!("  Already valid, skipping");
                }
                continue;
            }

            let ch = authz
                .challenges
                .iter()
                .find(|c| c.challenge_type == challenge_type)
                .with_context(|| {
                    format!(
                        "no {challenge_type} challenge for {}",
                        authz.identifier.value
                    )
                })?;

            let (token, txt_name, txt_value) = if challenge_type == CHALLENGE_TYPE_DNS01 {
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
                    persist_policy,
                    persist_until,
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
            cleanup_registry.register(crate::cleanup::CleanupAction::DnsRecord {
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
            if let Some(timeout_secs) = dns_wait {
                if domain_count > 1 {
                    info!(
                        "Waiting up to {timeout_secs}s for DNS TXT propagation across {domain_count} domains (parallel)..."
                    );
                } else {
                    info!("Waiting up to {timeout_secs}s for DNS TXT propagation...");
                }

                let semaphore =
                    std::sync::Arc::new(tokio::sync::Semaphore::new(dns_propagation_concurrency));
                let mut set: tokio::task::JoinSet<anyhow::Result<(String, bool)>> =
                    tokio::task::JoinSet::new();
                for p in &pending {
                    let name = p.txt_name.clone();
                    let value = p.txt_value.clone();
                    let domain = p.domain.clone();
                    let sem = semaphore.clone();
                    let checker = std::sync::Arc::clone(&dns_checker);
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

            // Phase 3: on_challenge_ready hooks + respond_to_challenge (serial)
            for p in &pending {
                if let Some(script) = on_challenge_ready {
                    if challenge_type == CHALLENGE_TYPE_DNS01 {
                        let key_auth =
                            crate::challenge::key_authorization(&p.token, client.account_key());
                        run_hook(
                            script,
                            &[
                                ("ACME_DOMAIN", p.domain.as_str()),
                                ("ACME_CHALLENGE_TYPE", challenge_type),
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
                                ("ACME_CHALLENGE_TYPE", challenge_type),
                                ("ACME_TXT_NAME", &p.txt_name),
                                ("ACME_TXT_VALUE", &p.txt_value),
                            ],
                        )?;
                    }
                }
                client.respond_to_challenge(&p.challenge_url).await?;
                if !json && !silent {
                    outln!("  Challenge response sent for {}", p.domain);
                }
            }

            // Phase 4: Poll all authorizations until valid (serial)
            for p in &pending {
                let poll_deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(challenge_timeout);
                loop {
                    if std::time::Instant::now() > poll_deadline {
                        // Clean up remaining records
                        for q in &pending {
                            run_dns_hook_cleanup_silent(hook, &q.domain, &q.txt_name, &q.txt_value);
                        }
                        anyhow::bail!(
                            "authorization for {} did not complete within {challenge_timeout}s",
                            p.domain
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    let a = client.get_authorization(&p.authz_url).await?;
                    if !json && !silent {
                        outln!("  Authorization status for {}: {}", p.domain, a.status);
                    }

                    if let Some(ch) = a
                        .challenges
                        .iter()
                        .find(|c| c.challenge_type == challenge_type)
                    {
                        if is_challenge_terminal(ch) {
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
                                .find(|c| c.challenge_type == challenge_type)
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
            if !json && !silent {
                outln!(
                    "Authorization for {} - status: {}",
                    authz.identifier.value,
                    authz.status
                );
            }

            if authz.status == AuthorizationStatus::Valid {
                if !json && !silent {
                    outln!("  Already valid, skipping");
                }
                continue;
            }

            let ch = authz
                .challenges
                .iter()
                .find(|c| c.challenge_type == challenge_type)
                .with_context(|| {
                    format!(
                        "no {challenge_type} challenge for {}",
                        authz.identifier.value
                    )
                })?;
            let token = if challenge_type != CHALLENGE_TYPE_DNS_PERSIST01 {
                ch.token.as_deref().context("challenge has no token")?
            } else {
                "" // dns-persist-01 has no token
            };
            let challenge_url = ch.url.clone();

            // Track challenge file for cleanup (file mode only)
            let mut challenge_file: Option<std::path::PathBuf> = None;
            // Background HTTP server handle (standalone mode only)
            let mut serve_task: Option<tokio::task::JoinHandle<Result<(), anyhow::Error>>> = None;

            match challenge_type {
                CHALLENGE_TYPE_HTTP01 => {
                    let validation_url = format!(
                        "http://{}/.well-known/acme-challenge/{}",
                        authz.identifier.value, token
                    );
                    info!("ACME server will validate via: {validation_url}");

                    if let Some(dir) = challenge_dir {
                        // File mode: write token file for an existing web server
                        let file = crate::challenge::http01::write_challenge_file(
                            dir,
                            token,
                            client.account_key(),
                        )?;
                        if !json && !silent {
                            outln!("  Challenge file written to {}", file.display());
                        }
                        cleanup_registry.register(
                            crate::cleanup::CleanupAction::HttpChallengeFile(file.clone()),
                        );
                        challenge_file = Some(file);
                    } else {
                        // Standalone mode: bind a TCP server
                        if http_port != 80 {
                            tracing::warn!(
                                "HTTP-01 validation (RFC 8555 §8.3) always targets port 80.\n  \
                             Your server is listening on port {http_port}.\n  \
                             Ensure traffic to port 80 is forwarded to port {http_port}, \
                             or use --challenge-dir with an existing web server."
                            );
                        }
                        let auth =
                            crate::challenge::http01::response_body(token, client.account_key());
                        let path = crate::challenge::http01::challenge_path(token);

                        let listener = crate::challenge::http01::bind_or_suggest(http_port).await?;
                        info!("HTTP-01 server listening on 0.0.0.0:{http_port}");

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
                        cleanup_registry.register(crate::cleanup::CleanupAction::ServerTask(
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
                    if !json && !silent {
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
                    if !silent {
                        crate::challenge::dns01::print_instructions(
                            &authz.identifier.value,
                            token,
                            client.account_key(),
                        );
                    }

                    if let Some(timeout_secs) = dns_wait {
                        // Poll DNS propagation
                        info!("Waiting up to {timeout_secs}s for DNS TXT propagation...");
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(timeout_secs);
                        let mut found = false;
                        while std::time::Instant::now() < deadline {
                            if dns_txt_check(&dns_checker, &txt_name, &txt_value).await? {
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
                    } else if !silent {
                        // Interactive: wait for Enter
                        outln!("Press Enter once the record has propagated...");
                        let _ = std::io::stdin().read_line(&mut String::new());
                    }

                    if let Some(script) = on_challenge_ready {
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
                                ("ACME_CHALLENGE_TYPE", challenge_type),
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
                        persist_policy,
                        persist_until,
                    )?;

                    // No hook: print instructions for manual setup
                    if !silent {
                        crate::challenge::dns_persist01::print_instructions(
                            &authz.identifier.value,
                            issuer_names,
                            &account_uri,
                            persist_policy,
                            persist_until,
                        )?;
                    }

                    if let Some(timeout_secs) = dns_wait {
                        info!("Waiting up to {timeout_secs}s for DNS TXT propagation...");
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(timeout_secs);
                        let mut found = false;
                        while std::time::Instant::now() < deadline {
                            if dns_txt_check(&dns_checker, &txt_name, &txt_value).await? {
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
                    } else if !silent {
                        outln!("Press Enter once the record has propagated...");
                        let _ = std::io::stdin().read_line(&mut String::new());
                    }

                    if let Some(script) = on_challenge_ready {
                        run_hook(
                            script,
                            &[
                                ("ACME_DOMAIN", &authz.identifier.value),
                                ("ACME_CHALLENGE_TYPE", challenge_type),
                                ("ACME_TXT_NAME", &txt_name),
                                ("ACME_TXT_VALUE", &txt_value),
                            ],
                        )?;
                    }

                    client.respond_to_challenge(&challenge_url).await?;
                }
                CHALLENGE_TYPE_TLSALPN01 => {
                    if !silent {
                        crate::challenge::tlsalpn01::print_instructions(
                            &authz.identifier.value,
                            token,
                            client.account_key(),
                        );
                        outln!("Press Enter once the TLS server is configured...");
                        let _ = std::io::stdin().read_line(&mut String::new());
                    }

                    if let Some(script) = on_challenge_ready {
                        let key_auth =
                            crate::challenge::key_authorization(token, client.account_key());
                        run_hook(
                            script,
                            &[
                                ("ACME_DOMAIN", &authz.identifier.value),
                                ("ACME_CHALLENGE_TYPE", challenge_type),
                                ("ACME_TOKEN", token),
                                ("ACME_KEY_AUTH", &key_auth),
                            ],
                        )?;
                    }

                    client.respond_to_challenge(&challenge_url).await?;
                }
                other => anyhow::bail!("unsupported challenge type: {other}"),
            }

            // Poll authorization until terminal (max challenge_timeout)
            let poll_deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(challenge_timeout);
            loop {
                if std::time::Instant::now() > poll_deadline {
                    if let Some(handle) = serve_task.take() {
                        handle.abort();
                    }
                    if let Some(ref f) = challenge_file {
                        crate::challenge::http01::cleanup_challenge_file(f);
                    }
                    anyhow::bail!(
                        "authorization for {} did not complete within {challenge_timeout}s",
                        authz.identifier.value
                    );
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let a = client.get_authorization(authz_url).await?;
                if !json && !silent {
                    outln!("  Authorization status: {}", a.status);
                }

                // Surface challenge-level errors early (only if terminal)
                if let Some(ch) = a
                    .challenges
                    .iter()
                    .find(|c| c.challenge_type == challenge_type)
                {
                    if is_challenge_terminal(ch) {
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
                            .find(|c| c.challenge_type == challenge_type)
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

    // ── Finalize ────────────────────────────────────────────────────────
    info!(
        "Step {}: Finalizing order",
        if pre_authorize { 5 } else { 4 }
    );
    let (csr_der, key_pem) = generate_csr(&domains, cert_key_alg)?;
    let finalize_url = order.finalize.clone();
    let mut order = client.finalize_order(&finalize_url, &csr_der).await?;
    if !json && !silent {
        outln!("Order status: {}", order.status);
    }

    // ── Poll order ──────────────────────────────────────────────────────
    info!(
        "Step {}: Waiting for certificate issuance",
        if pre_authorize { 6 } else { 5 }
    );
    while order.status != OrderStatus::Valid {
        if order.status == OrderStatus::Invalid {
            anyhow::bail!("order became invalid");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        order = client.poll_order(&order_url).await?;
        if !json && !silent {
            outln!("  Order status: {}", order.status);
        }
    }

    // ── Download certificate ────────────────────────────────────────────
    info!(
        "Step {}: Downloading certificate",
        if pre_authorize { 7 } else { 6 }
    );
    let cert_url = order
        .certificate
        .context("order is valid but has no certificate URL")?;
    let cert = client.download_certificate(&cert_url).await?;

    let password: Option<secrecy::SecretString> = if let Some(pw) = key_password {
        Some(secrecy::SecretString::from(pw.to_string()))
    } else if let Some(path) = key_password_file {
        crate::fs_secure::warn_if_world_readable(path, "password");
        let content = zeroize::Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read password file: {}", path.display()))?,
        );
        let pw: Option<String> = content
            .lines()
            .next()
            .map(|line| line.trim().to_string())
            .filter(|pw: &String| !pw.is_empty());
        pw.map(secrecy::SecretString::from)
    } else {
        None
    };

    let key_encrypted = password.is_some();
    if let Some(ref password) = password {
        use secrecy::ExposeSecret;
        let encrypted = encrypt_private_key(&key_pem, password.expose_secret())?;
        crate::fs_secure::write_secret_file(key_output, encrypted.as_bytes(), force)
            .with_context(|| format!("failed to write private key to {}", key_output.display()))?;
        if !json && !silent {
            outln!("Private key saved to {} (encrypted)", key_output.display());
        }
    } else {
        crate::fs_secure::write_secret_file(key_output, key_pem.as_bytes(), force)
            .with_context(|| format!("failed to write private key to {}", key_output.display()))?;
        if !json && !silent {
            outln!("Private key saved to {}", key_output.display());
        }
    }

    std::fs::write(cert_output, &cert)
        .with_context(|| format!("failed to write certificate to {}", cert_output.display()))?;
    if json && !silent {
        outln!(
            "{}",
            serde_json::json!({
                "command": "run",
                "action": "issued",
                "domains": domains,
                "cert_path": cert_output.display().to_string(),
                "key_path": key_output.display().to_string(),
                "key_encrypted": key_encrypted,
                "profile": profile,
            })
        );
    } else if !silent {
        outln!("Certificate saved to {}", cert_output.display());
        if print_cert {
            outln!("{cert}");
        }
    }

    if let Some(script) = on_cert_issued {
        let domains_joined = domains.join(",");
        run_hook(
            script,
            &[
                ("ACME_DOMAINS", &domains_joined),
                ("ACME_CERT_PATH", &cert_output.display().to_string()),
                ("ACME_KEY_PATH", &key_output.display().to_string()),
                (
                    "ACME_KEY_ENCRYPTED",
                    if key_encrypted { "true" } else { "false" },
                ),
            ],
        )?;
    }

    Ok(())
}
