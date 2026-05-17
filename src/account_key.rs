use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::fs_secure;
use crate::jws::AccountKey;

pub(crate) fn load_account_key_with_password(
    path: &PathBuf,
    password: Option<&str>,
) -> Result<AccountKey> {
    // SEC-07: wrap PEM in Zeroizing so the on-heap key material is wiped
    // when this function returns, even on the error path.
    let pem = zeroize::Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read account key from {}", path.display()))?,
    );
    AccountKey::from_pkcs8_pem_with_password(&pem, password)
        .with_context(|| format!("failed to load account key from {}", path.display()))
}

/// SEC-08: resolve the account-key password from CLI flag or password file.
/// Returns None when neither is provided (unencrypted-key path).
pub(crate) fn resolve_account_key_password(
    inline: Option<&str>,
    file: Option<&std::path::Path>,
) -> Result<Option<secrecy::SecretString>> {
    if let Some(pw) = inline {
        return Ok(Some(secrecy::SecretString::from(pw.to_string())));
    }
    if let Some(path) = file {
        fs_secure::warn_if_world_readable(path, "password");
        let content =
            zeroize::Zeroizing::new(std::fs::read_to_string(path).with_context(|| {
                format!(
                    "failed to read account-key password file: {}",
                    path.display()
                )
            })?);
        let pw = content
            .lines()
            .next()
            .map(|line| line.trim().to_string())
            .filter(|s: &String| !s.is_empty());
        return Ok(pw.map(secrecy::SecretString::from));
    }
    Ok(None)
}
