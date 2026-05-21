//! Order and authorization subcommands (order, list-profiles, get-authz,
//! respond-challenge, finalize, poll-order, download-cert).

use std::path::Path;

use anyhow::{Context, Result};

use crate::cli::{CertKeyAlgorithm, Cli};
use crate::csr::{encrypt_private_key, generate_csr};
use crate::types::Identifier;
use crate::{build_client, outln};

// cancel-safe: client request only; CA-side order created on POST is
// recoverable via account URL but no local state is mutated.
pub(crate) async fn cmd_order(
    cli: &Cli,
    domains: Vec<String>,
    profile: Option<String>,
) -> Result<()> {
    let mut client = build_client(cli).await?;
    // Validate profile against advertised list (draft-ietf-acme-profiles-01 §4)
    if let Some(ref p) = profile
        && let Some(available) = client.available_profiles()
        && !available.contains_key(p)
    {
        tracing::warn!(
            "Profile \"{p}\" is not advertised by the server (available: {})",
            available.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    let ids: Vec<Identifier> = domains
        .iter()
        .map(|d| Identifier::from_str_auto(d))
        .collect::<Result<Vec<_>>>()?;
    let (order, order_url) = client.new_order(ids, profile).await?;
    super::emit_result(
        cli,
        || {
            serde_json::json!({
                "command": "order",
                "order_url": order_url,
                "status": format!("{}", order.status),
                "finalize_url": order.finalize,
                "authorizations": order.authorizations,
                "profile": order.profile,
            })
        },
        || {
            outln!("Order URL:    {order_url}");
            outln!("Status:       {}", order.status);
            if let Some(ref p) = order.profile {
                outln!("Profile:      {p}");
            }
            outln!("Finalize URL: {}", order.finalize);
            for url in &order.authorizations {
                outln!("  authz: {url}");
            }
        },
    );
    Ok(())
}

// cancel-safe: single HTTP GET to list profiles; pure read.
pub(crate) async fn cmd_list_profiles(cli: &Cli) -> Result<()> {
    let (tls, net) =
        crate::client::policies_from_cli_flags(cli.insecure, cli.allow_private_network);

    crate::client::validate_directory_url(&cli.directory, tls, net)?;
    let http = crate::client::build_http_client(tls, cli.connect_timeout, net)?;
    let resp = http
        .get(&cli.directory)
        .send()
        .await
        .context("failed to fetch ACME directory")?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        let truncated: String = body.chars().take(512).collect();
        anyhow::bail!("ACME directory request failed: {truncated}");
    }
    let dir: crate::types::Directory = resp.json().await.context("failed to parse directory")?;
    let profiles = dir.meta.as_ref().and_then(|m| m.profiles.as_ref());
    match profiles {
        Some(profiles) => super::emit_result(
            cli,
            || serde_json::json!({ "command": "list-profiles", "profiles": profiles }),
            || {
                outln!("Available certificate profiles:");
                for (name, description) in profiles {
                    outln!("  {name}: {description}");
                }
            },
        ),
        None => super::emit_result(
            cli,
            || serde_json::json!({ "command": "list-profiles", "profiles": null }),
            || outln!("Server does not advertise any profiles."),
        ),
    }
    Ok(())
}

// cancel-safe: single signed POST-as-GET to authz URL.
pub(crate) async fn cmd_get_authz(cli: &Cli, url: &str) -> Result<()> {
    let (tls, net) =
        crate::client::policies_from_cli_flags(cli.insecure, cli.allow_private_network);

    crate::client::validate_acme_url(url, tls, net)?;
    let url: url::Url = url
        .parse()
        .with_context(|| format!("not a valid URL: {url}"))?;
    let mut client = build_client(cli).await?;
    let authz = client.get_authorization(&url).await?;
    super::emit_result(
        cli,
        || {
            serde_json::json!({
                "command": "get-authz",
                "identifier": authz.identifier.value_str(),
                "identifier_type": authz.identifier.type_str(),
                "status": format!("{}", authz.status),
                "challenges": authz.challenges.iter().map(|ch| serde_json::json!({
                    "type": ch.challenge_type,
                    "status": format!("{}", ch.status),
                    "url": ch.url,
                    "token": ch.token,
                })).collect::<Vec<_>>(),
            })
        },
        || {
            outln!(
                "Identifier: {} ({})",
                authz.identifier.value_str(),
                authz.identifier.type_str()
            );
            outln!("Status:     {}", authz.status);
            for ch in &authz.challenges {
                outln!("  {} [{}] url={}", ch.challenge_type, ch.status, ch.url);
                if let Some(ref t) = ch.token {
                    outln!("    token: {t}");
                }
            }
        },
    );
    Ok(())
}

// NOT cancel-safe: signals CA to validate. Drop after POST cannot recall
// the request — CA may proceed with validation regardless.
pub(crate) async fn cmd_respond_challenge(cli: &Cli, url: &str) -> Result<()> {
    let (tls, net) =
        crate::client::policies_from_cli_flags(cli.insecure, cli.allow_private_network);

    crate::client::validate_acme_url(url, tls, net)?;
    let url: url::Url = url
        .parse()
        .with_context(|| format!("not a valid URL: {url}"))?;
    let mut client = build_client(cli).await?;
    let ch = client.respond_to_challenge(&url).await?;
    super::emit_result(
        cli,
        || serde_json::json!({ "command": "respond-challenge", "status": format!("{}", ch.status) }),
        || outln!("Challenge status: {}", ch.status),
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
// NOT cancel-safe: generates key off-runtime, submits CSR, writes private
// key to disk. Drop between key-write and CSR submission orphans key file;
// drop between submission and exit means caller loses the order URL.
pub(crate) async fn cmd_finalize(
    cli: &Cli,
    finalize_url: &str,
    domains: &[String],
    cert_key_alg: CertKeyAlgorithm,
    key_output: &std::path::Path,
    key_password: Option<secrecy::SecretString>,
    key_password_file: Option<&std::path::Path>,
    force: bool,
) -> Result<()> {
    let (tls, net) =
        crate::client::policies_from_cli_flags(cli.insecure, cli.allow_private_network);

    crate::client::validate_acme_url(finalize_url, tls, net)?;
    let finalize_url: url::Url = finalize_url
        .parse()
        .with_context(|| format!("not a valid URL: {finalize_url}"))?;
    let domains: Vec<String> = domains
        .iter()
        .map(|d| Identifier::from_str_auto(d).map(|id| id.value_str().into_owned()))
        .collect::<Result<Vec<_>>>()?;
    let mut client = build_client(cli).await?;
    let domains_for_csr = domains.clone();
    let (csr_der, key_pem) =
        tokio::task::spawn_blocking(move || generate_csr(&domains_for_csr, cert_key_alg))
            .await
            .context("CSR generation task panicked")??;

    let password: Option<secrecy::SecretString> = if let Some(pw) = key_password {
        Some(pw)
    } else if let Some(path) = key_password_file {
        crate::fs_secure::warn_if_world_readable(path, "password");
        let content = zeroize::Zeroizing::new(
            tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("failed to read password file: {}", path.display()))?,
        );
        let pw: Option<String> = content
            .lines()
            .next()
            .map(|line| line.trim().to_string())
            .filter(|pw| !pw.is_empty());
        pw.map(secrecy::SecretString::from)
    } else {
        None
    };

    let key_encrypted = password.is_some();
    let key_bytes: zeroize::Zeroizing<Vec<u8>> = if let Some(password) = password {
        let key_pem_owned = key_pem;
        let encrypted = tokio::task::spawn_blocking(move || {
            use secrecy::ExposeSecret;
            encrypt_private_key(&key_pem_owned, password.expose_secret())
        })
        .await
        .context("scrypt encryption task panicked")??;
        zeroize::Zeroizing::new(encrypted.into_bytes())
    } else {
        zeroize::Zeroizing::new(key_pem.as_bytes().to_vec())
    };
    let key_output_owned = key_output.to_path_buf();
    let key_display = key_output.display().to_string();
    tokio::task::spawn_blocking(move || {
        crate::fs_secure::write_secret_file(
            &key_output_owned,
            &key_bytes,
            if force {
                crate::fs_secure::Overwrite::Allow
            } else {
                crate::fs_secure::Overwrite::Forbid
            },
        )
    })
    .await
    .context("write_secret_file task panicked")?
    .with_context(|| format!("failed to write private key to {key_display}"))?;

    let order = client.finalize_order(&finalize_url, &csr_der).await?;
    super::emit_result(
        cli,
        || {
            serde_json::json!({
                "command": "finalize",
                "status": format!("{}", order.status),
                "certificate_url": order.certificate,
                "key_path": key_output.display().to_string(),
                "key_encrypted": key_encrypted,
            })
        },
        || {
            if key_encrypted {
                outln!("Private key saved to {} (encrypted)", key_output.display());
            } else {
                outln!("Private key saved to {}", key_output.display());
            }
            outln!("Order status: {}", order.status);
            if let Some(ref cert_url) = order.certificate {
                outln!("Certificate URL: {cert_url}");
            }
        },
    );
    Ok(())
}

// cancel-safe: single POST-as-GET; pure read of order state.
pub(crate) async fn cmd_poll_order(cli: &Cli, url: &str) -> Result<()> {
    let (tls, net) =
        crate::client::policies_from_cli_flags(cli.insecure, cli.allow_private_network);

    crate::client::validate_acme_url(url, tls, net)?;
    let url: url::Url = url
        .parse()
        .with_context(|| format!("not a valid URL: {url}"))?;
    let mut client = build_client(cli).await?;
    let order = client.poll_order(&url).await?;
    super::emit_result(
        cli,
        || {
            serde_json::json!({
                "command": "poll-order",
                "status": format!("{}", order.status),
                "certificate_url": order.certificate,
            })
        },
        || {
            outln!("Order status: {}", order.status);
            if let Some(ref cert_url) = order.certificate {
                outln!("Certificate URL: {cert_url}");
            }
        },
    );
    Ok(())
}

// NOT cancel-safe: downloads certificate then writes to disk. Drop between
// download and write loses the issued cert (re-download possible only if
// the URL is preserved externally).
pub(crate) async fn cmd_download_cert(cli: &Cli, url: &str, output: &Path) -> Result<()> {
    let (tls, net) =
        crate::client::policies_from_cli_flags(cli.insecure, cli.allow_private_network);

    crate::client::validate_acme_url(url, tls, net)?;
    let url: url::Url = url
        .parse()
        .with_context(|| format!("not a valid URL: {url}"))?;
    let mut client = build_client(cli).await?;
    let cert = client.download_certificate(&url).await?;
    tokio::fs::write(output, &cert)
        .await
        .with_context(|| format!("failed to write certificate to {}", output.display()))?;
    super::emit_result(
        cli,
        || serde_json::json!({ "command": "download-cert", "path": output.display().to_string() }),
        || outln!("Certificate saved to {}", output.display()),
    );
    Ok(())
}
