//! Per-challenge-type provisioners for the sequential authorization path.
//!
//! Each `provision_*` fn handles the "set up + signal ready + respond" steps
//! for one challenge type. The shared poll loop in `sequential.rs` then waits
//! for the authorization to reach a terminal state.
//!
//! HTTP-01 is the only provisioner that produces teardown state (a challenge
//! file path and/or a background server task). All provisioners return
//! `ProvisionResult` for uniformity.

use anyhow::{Context, Result};
use tracing::info;

use crate::client::AcmeClient;
use crate::outln;
use crate::types::Authorization;

use super::super::super::run_hook;
use super::super::RunContext;

/// Teardown state produced by a provisioner.
///
/// Only HTTP-01 standalone mode populates `serve_task`; only HTTP-01 file mode
/// populates `challenge_file`. Other provisioners return `Default::default()`.
#[derive(Default)]
pub(super) struct ProvisionResult {
    pub challenge_file: Option<std::path::PathBuf>,
    pub serve_task: Option<tokio::task::JoinHandle<Result<(), anyhow::Error>>>,
}

pub(super) async fn provision_http01(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    authz: &Authorization,
    token: &str,
    challenge_url: &str,
) -> Result<ProvisionResult> {
    let mut result = ProvisionResult::default();

    let validation_url = format!(
        "http://{}/.well-known/acme-challenge/{}",
        authz.identifier.value, token
    );
    info!("ACME server will validate via: {validation_url}");

    if let Some(dir) = ctx.challenge_dir {
        // File mode: write token file for an existing web server
        let file =
            crate::challenge::http01::write_challenge_file(dir, token, client.account_key())?;
        if !ctx.json && !ctx.silent {
            outln!("  Challenge file written to {}", file.display());
        }
        ctx.cleanup_registry
            .register(crate::cleanup::CleanupAction::HttpChallengeFile(
                file.clone(),
            ));
        result.challenge_file = Some(file);
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
        let auth = crate::challenge::http01::response_body(token, client.account_key());
        let path = crate::challenge::http01::challenge_path(token);

        let listener = crate::challenge::http01::bind_or_suggest(ctx.http_port).await?;
        info!("HTTP-01 server listening on 0.0.0.0:{}", ctx.http_port);

        let task = tokio::spawn(crate::challenge::http01::run_accept_loop(
            listener, auth, path,
        ));
        ctx.cleanup_registry
            .register(crate::cleanup::CleanupAction::ServerTask(
                task.abort_handle(),
            ));
        result.serve_task = Some(task);
    }

    // Yield briefly so the HTTP-01 server task is ready
    // before telling the CA to validate.
    tokio::task::yield_now().await;

    let ch_resp = client.respond_to_challenge(challenge_url).await?;
    if let Some(ref err) = ch_resp.error {
        // Some CAs (e.g. step-ca) validate synchronously during the
        // challenge POST and may return an error on a still-pending
        // challenge. Per RFC 8555 §7.5.1 this is just a failed
        // attempt — the authorization may still succeed on retry.
        // Log a warning and let the polling loop handle it.
        tracing::warn!("HTTP-01 challenge returned error (will keep polling): {err}");
    }
    if !ctx.json && !ctx.silent {
        outln!("  Challenge response sent - waiting for validation...");
    }

    Ok(result)
}

pub(super) async fn provision_dns01(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    authz: &Authorization,
    token: &str,
    challenge_url: &str,
) -> Result<ProvisionResult> {
    if authz.identifier.is_ip() {
        anyhow::bail!(
            "dns-01 challenges are not supported for IP identifiers ({})",
            authz.identifier.value
        );
    }
    let txt_name = crate::challenge::dns01::record_name(&authz.identifier.value);
    let txt_value = crate::challenge::dns01::txt_record_value(token, client.account_key());

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
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let mut found = false;
        while std::time::Instant::now() < deadline {
            if super::super::super::dns_txt_check(&ctx.dns_checker, &txt_name, &txt_value).await? {
                info!("DNS TXT record found");
                found = true;
                break;
            }
            tracing::debug!("DNS TXT not yet visible, retrying in 5s...");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        if !found {
            anyhow::bail!("DNS TXT record for {txt_name} not found within {timeout_secs}s");
        }
    } else if !ctx.silent {
        // Interactive: wait for Enter
        outln!("Press Enter once the record has propagated...");
        let _ = std::io::stdin().read_line(&mut String::new());
    }

    if let Some(script) = ctx.on_challenge_ready {
        let key_auth = crate::challenge::key_authorization(token, client.account_key());
        let txt_name_ref = crate::challenge::dns01::record_name(&authz.identifier.value);
        let txt_value_ref = crate::challenge::dns01::txt_record_value(token, client.account_key());
        run_hook(
            script,
            &[
                ("ACME_DOMAIN", &authz.identifier.value),
                ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                ("ACME_TOKEN", token),
                ("ACME_KEY_AUTH", &key_auth),
                ("ACME_TXT_NAME", &txt_name_ref),
                ("ACME_TXT_VALUE", &txt_value_ref),
            ],
        )?;
    }

    client.respond_to_challenge(challenge_url).await?;
    Ok(ProvisionResult::default())
}

pub(super) async fn provision_dns_persist01(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    authz: &Authorization,
    ch: &crate::types::Challenge,
    challenge_url: &str,
) -> Result<ProvisionResult> {
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
        anyhow::bail!("malformed dns-persist-01: issuer-domain-names must have 1-10 entries");
    }
    let account_uri = client
        .account_url()
        .context("account URL not known - cannot construct dns-persist-01 record")?
        .to_string();
    let txt_name = crate::challenge::dns_persist01::record_name(&authz.identifier.value);
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
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let mut found = false;
        while std::time::Instant::now() < deadline {
            if super::super::super::dns_txt_check(&ctx.dns_checker, &txt_name, &txt_value).await? {
                info!("DNS TXT record found");
                found = true;
                break;
            }
            tracing::debug!("DNS TXT not yet visible, retrying in 5s...");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        if !found {
            anyhow::bail!("DNS TXT record for {txt_name} not found within {timeout_secs}s");
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
                ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                ("ACME_TXT_NAME", &txt_name),
                ("ACME_TXT_VALUE", &txt_value),
            ],
        )?;
    }

    client.respond_to_challenge(challenge_url).await?;
    Ok(ProvisionResult::default())
}

pub(super) async fn provision_tlsalpn01(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    authz: &Authorization,
    token: &str,
    challenge_url: &str,
) -> Result<ProvisionResult> {
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
        let key_auth = crate::challenge::key_authorization(token, client.account_key());
        run_hook(
            script,
            &[
                ("ACME_DOMAIN", &authz.identifier.value),
                ("ACME_CHALLENGE_TYPE", ctx.challenge_type.as_str()),
                ("ACME_TOKEN", token),
                ("ACME_KEY_AUTH", &key_auth),
            ],
        )?;
    }

    client.respond_to_challenge(challenge_url).await?;
    Ok(ProvisionResult::default())
}
