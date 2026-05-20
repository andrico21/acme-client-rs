use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::fs_secure;
use crate::jws::AccountKey;

pub(crate) async fn load_account_key_with_password(
    path: &Path,
    password: Option<&str>,
) -> Result<AccountKey> {
    fs_secure::warn_if_world_readable(path, "account key");
    let path_buf: PathBuf = path.to_path_buf();
    let pem = tokio::task::spawn_blocking(move || {
        std::fs::read_to_string(&path_buf)
            .with_context(|| format!("failed to read account key from {}", path_buf.display()))
            .map(zeroize::Zeroizing::new)
    })
    .await
    .context("account-key read task panicked")??;
    AccountKey::from_pkcs8_pem_with_password(&pem, password)
        .with_context(|| format!("failed to load account key from {}", path.display()))
}

/// SEC-08: resolve the account-key password from CLI flag or password file.
/// Returns None when neither is provided (unencrypted-key path).
pub(crate) async fn resolve_account_key_password(
    inline: Option<&str>,
    file: Option<&std::path::Path>,
) -> Result<Option<secrecy::SecretString>> {
    if let Some(pw) = inline {
        return Ok(Some(secrecy::SecretString::from(pw.to_string())));
    }
    if let Some(path) = file {
        fs_secure::warn_if_world_readable(path, "password");
        let path_buf: PathBuf = path.to_path_buf();
        let content = tokio::task::spawn_blocking(move || {
            std::fs::read_to_string(&path_buf)
                .with_context(|| {
                    format!(
                        "failed to read account-key password file: {}",
                        path_buf.display()
                    )
                })
                .map(zeroize::Zeroizing::new)
        })
        .await
        .context("password-file read task panicked")??;
        let pw = content
            .lines()
            .next()
            .map(|line| line.trim().to_string())
            .filter(|s| !s.is_empty());
        return Ok(pw.map(secrecy::SecretString::from));
    }
    Ok(None)
}
