//! Account-management subcommands (generate-key, account, deactivate-account, key-rollover).

use std::path::Path;

use anyhow::{Context, Result};

use crate::account_key::{load_account_key_with_password, resolve_account_key_password};
use crate::cli::{Cli, OutputFormat};
use crate::csr::encrypt_private_key;
use crate::jws::{AccountKey, KeyAlgorithm};
use crate::{build_client, outln};

use super::parse_eab;
// cancel-safe before the final `spawn_blocking` write: pure compute (and an
// off-runtime scrypt task) with no external side effects. NOT cancel-safe
// once the write task is spawned: `spawn_blocking` detaches, so a dropped
// await leaves the blocking task running to completion and the secret file
// may be created after the caller has gone away. There is still no DNS,
// network, or CA-side mutation.
pub(crate) async fn cmd_generate_key(
    path: &Path,
    algorithm: KeyAlgorithm,
    force: bool,
    fmt: OutputFormat,
    silent: bool,
    password: Option<&secrecy::SecretString>,
) -> Result<()> {
    use secrecy::ExposeSecret;
    let key = AccountKey::generate(algorithm)?;
    let pem = zeroize::Zeroizing::new(key.to_pkcs8_pem()?);
    let encrypted = password.is_some();
    let bytes_to_write: zeroize::Zeroizing<Vec<u8>> = if let Some(pw) = password {
        // scrypt N=16384 ≈ 16 MiB / hundreds of ms — must not block reactor.
        let pem_for_task = pem.clone();
        let pw_for_task = zeroize::Zeroizing::new(pw.expose_secret().to_string());
        let encrypted_pem = tokio::task::spawn_blocking(move || {
            encrypt_private_key(&pem_for_task, pw_for_task.as_str())
        })
        .await
        .context("scrypt encryption task panicked")??;
        zeroize::Zeroizing::new(encrypted_pem.into_bytes())
    } else {
        zeroize::Zeroizing::new(pem.as_bytes().to_vec())
    };
    let path_owned = path.to_path_buf();
    let path_display = path.display().to_string();
    tokio::task::spawn_blocking(move || {
        crate::fs_secure::write_secret_file(
            &path_owned,
            &bytes_to_write,
            if force {
                crate::fs_secure::Overwrite::Allow
            } else {
                crate::fs_secure::Overwrite::Forbid
            },
        )
    })
    .await
    .context("write_secret_file task panicked")?
    .with_context(|| format!("failed to write key to {path_display}"))?;
    if !silent {
        if fmt == OutputFormat::Json {
            outln!(
                "{}",
                serde_json::json!({
                    "command": "generate-key",
                    "algorithm": format!("{algorithm}"),
                    "path": path.display().to_string(),
                    "encrypted": encrypted,
                })
            );
        } else if encrypted {
            outln!(
                "{algorithm} account key saved to {} (encrypted)",
                path.display()
            );
        } else {
            outln!("{algorithm} account key saved to {}", path.display());
        }
    }
    Ok(())
}

// NOT cancel-safe: creates ACME account on CA + EAB binding. Drop after
// POST leaves account registered remotely; caller loses the account URL.
pub(crate) async fn cmd_account(
    cli: &Cli,
    contact: Vec<String>,
    agree_tos: bool,
    eab_kid: Option<&str>,
    eab_hmac_key: Option<secrecy::SecretString>,
) -> Result<()> {
    let mut client = build_client(cli).await?;
    let contact = if contact.is_empty() {
        None
    } else {
        Some(contact.into_iter().map(|c| format!("mailto:{c}")).collect())
    };
    let eab = parse_eab(
        eab_kid,
        eab_hmac_key
            .as_ref()
            .map(<secrecy::SecretString as secrecy::ExposeSecret<str>>::expose_secret),
    )?;
    let eab_ref = eab.as_ref().map(|(kid, key)| (kid.as_str(), key));
    let account = client.create_account(contact, agree_tos, eab_ref).await?;
    super::emit_result(
        cli,
        || {
            serde_json::json!({
                "command": "account",
                "status": format!("{}", account.status),
                "url": client.account_url(),
            })
        },
        || {
            outln!("Account status: {}", account.status);
            if let Some(url) = client.account_url() {
                outln!("Account URL:    {url}");
            }
        },
    );
    Ok(())
}

// NOT cancel-safe: deactivates account on CA — irreversible side effect.
pub(crate) async fn cmd_deactivate(cli: &Cli) -> Result<()> {
    let mut client = build_client(cli).await?;
    let account = client.deactivate_account().await?;
    super::emit_result(
        cli,
        || {
            serde_json::json!({
                "command": "deactivate-account",
                "status": format!("{}", account.status),
            })
        },
        || outln!("Account status: {}", account.status),
    );
    Ok(())
}

// NOT cancel-safe: rotates account key on CA. Drop after key-change POST
// but before caller saves the new key reference leaves account using new
// key with no local record.
pub(crate) async fn cmd_key_rollover(
    cli: &Cli,
    new_key_path: &Path,
    new_key_password: Option<secrecy::SecretString>,
    new_key_password_file: Option<&std::path::Path>,
) -> Result<()> {
    use secrecy::ExposeSecret;
    let pw = resolve_account_key_password(
        new_key_password.as_ref().map(ExposeSecret::expose_secret),
        new_key_password_file,
    )
    .await?;
    let new_key =
        load_account_key_with_password(new_key_path, pw.as_ref().map(ExposeSecret::expose_secret))
            .await?;
    let mut client = build_client(cli).await?;

    // key-change requires KID signing; look up account if URL not provided
    if client.account_url().is_none() {
        client.create_account(None, true, None).await?;
    }

    client.key_change(&new_key).await?;
    super::emit_result(
        cli,
        || {
            serde_json::json!({
                "command": "key-rollover",
                "new_key": new_key_path.display().to_string(),
            })
        },
        || {
            outln!("Account key rolled over successfully");
            outln!("From now on, use the new key: {}", new_key_path.display());
        },
    );
    Ok(())
}
