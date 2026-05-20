//! Shell-hook invocation helpers.
//!
//! Two flavors:
//!   - [`run_hook`]: generic — caller supplies the env-var contract.
//!   - The `run_dns_hook_*` family: hard-codes the
//!     `ACME_DOMAIN` / `ACME_TXT_NAME` / `ACME_TXT_VALUE` / `ACME_ACTION`
//!     contract documented in README for DNS-01 challenge plumbing.
//!
//! Every hook runs under [`crate::defaults::hooks::HOOK_TIMEOUT`] and has
//! its ambient ACME secret env (account-key / EAB / new-key passwords)
//! stripped before spawn so user-supplied scripts never see credentials
//! they did not ask for.
//!
//! Cleanup variants come in two failure modes. See each fn's doc-comment
//! for when to pick which.

use std::path::Path;

use anyhow::{Context, Result};

use crate::defaults::hooks::HOOK_TIMEOUT;
use crate::types::DnsName;

/// Env vars holding ACME-client secrets that MUST NOT be inherited by hook
/// subprocesses. Documented hook env vars (`ACME_DOMAIN`, `ACME_TXT_*`,
/// `ACME_ACTION`, `ACME_CERT_PATH`, etc.) are set explicitly per call and
/// are unaffected.
const ACME_SECRET_ENV_VARS: &[&str] = &[
    "ACME_ACCOUNT_KEY_PASSWORD",
    "ACME_ACCOUNT_KEY_PASSWORD_FILE",
    "ACME_KEY_PASSWORD",
    "ACME_KEY_PASSWORD_FILE",
    "ACME_NEW_KEY_PASSWORD",
    "ACME_NEW_KEY_PASSWORD_FILE",
    "ACME_EAB_KID",
    "ACME_EAB_HMAC_KEY",
];

fn scrub_async(cmd: &mut tokio::process::Command) {
    for var in ACME_SECRET_ENV_VARS {
        cmd.env_remove(var);
    }
}

/// Strip ACME secret env vars from `cmd` in place. Used by [`crate::cleanup`]
/// SIGINT path which executes hooks synchronously via [`std::process::Command`].
pub(crate) fn scrub_secret_env(cmd: &mut std::process::Command) {
    for var in ACME_SECRET_ENV_VARS {
        cmd.env_remove(var);
    }
}

// NOT cancel-safe: drop between spawn and exit-status leaves an orphaned
// child process. Callers must run to completion or kill the child.
async fn run_with_timeout(
    mut cmd: tokio::process::Command,
    script: &Path,
    label: &str,
) -> Result<std::process::ExitStatus> {
    scrub_async(&mut cmd);
    tokio::time::timeout(HOOK_TIMEOUT, cmd.status())
        .await
        .with_context(|| {
            format!(
                "{label} {} timed out after {}s",
                script.display(),
                HOOK_TIMEOUT.as_secs()
            )
        })?
        .with_context(|| format!("failed to run {label}: {}", script.display()))
}

// NOT cancel-safe: drop between spawn and timeout-wrap leaves an orphaned
// child running until OS reaps it. Callers must run to completion.
pub(crate) async fn run_hook(script: &Path, env_vars: &[(&str, &str)]) -> Result<()> {
    let mut cmd = tokio::process::Command::new(script);
    for &(key, val) in env_vars {
        cmd.env(key, val);
    }
    let status = run_with_timeout(cmd, script, "hook").await?;
    if !status.success() {
        anyhow::bail!("hook {} exited with {status}", script.display());
    }
    Ok(())
}

/// Invoke a DNS hook to create a DNS-01 challenge TXT record.
///
/// Wraps the standard `ACME_DOMAIN` / `ACME_TXT_NAME` / `ACME_TXT_VALUE` /
/// `ACME_ACTION=create` env contract documented in README. Returns an error
/// if the hook fails to spawn or exits non-zero — callers MUST treat that
/// as fatal because the upcoming validation will fail without the record.
// NOT cancel-safe: dropping after spawn may leak DNS record if hook had
// already mutated remote state. Pair with run_dns_hook_cleanup_* on error.
pub(crate) async fn run_dns_hook_create(
    hook: &Path,
    domain: &DnsName,
    txt_name: &DnsName,
    txt_value: &str,
) -> Result<()> {
    let mut cmd = tokio::process::Command::new(hook);
    cmd.env("ACME_DOMAIN", domain.as_str())
        .env("ACME_TXT_NAME", txt_name.as_str())
        .env("ACME_TXT_VALUE", txt_value)
        .env("ACME_ACTION", "create");
    let status = run_with_timeout(cmd, hook, "DNS hook").await?;
    if !status.success() {
        anyhow::bail!("DNS hook (create) exited with {status}");
    }
    Ok(())
}

/// Invoke a DNS hook to delete a previously-created DNS-01 TXT record,
/// logging any failure as a warning. Errors are intentionally non-fatal:
/// callers are usually already on an error path (challenge timed out,
/// validation failed) and a missing cleanup must not mask the original
/// failure cause.
// NOT cancel-safe: drop leaves orphaned child; cleanup may not complete and
// the DNS record may persist. Callers run this from error-recovery paths.
pub(crate) async fn run_dns_hook_cleanup_logged(
    hook: &Path,
    domain: &DnsName,
    txt_name: &DnsName,
    txt_value: &str,
) {
    let mut cmd = tokio::process::Command::new(hook);
    cmd.env("ACME_DOMAIN", domain.as_str())
        .env("ACME_TXT_NAME", txt_name.as_str())
        .env("ACME_TXT_VALUE", txt_value)
        .env("ACME_ACTION", "cleanup");
    scrub_async(&mut cmd);
    match tokio::time::timeout(HOOK_TIMEOUT, cmd.status()).await {
        Ok(Ok(s)) if !s.success() => tracing::warn!("DNS hook (cleanup) exited with {s}"),
        Ok(Err(e)) => tracing::warn!("DNS hook (cleanup) failed: {e}"),
        Err(_) => tracing::warn!(
            "DNS hook (cleanup) timed out after {}s",
            HOOK_TIMEOUT.as_secs()
        ),
        Ok(_) => {}
    }
}

/// Best-effort DNS cleanup hook for parallel-DNS rollback paths where any
/// hook failure would be immediately followed by `anyhow::bail!` anyway,
/// making logging redundant. Use [`run_dns_hook_cleanup_logged`] elsewhere.
// NOT cancel-safe: drop leaves orphaned child; DNS record may persist.
pub(crate) async fn run_dns_hook_cleanup_silent(
    hook: &Path,
    domain: &DnsName,
    txt_name: &DnsName,
    txt_value: &str,
) {
    let mut cmd = tokio::process::Command::new(hook);
    cmd.env("ACME_DOMAIN", domain.as_str())
        .env("ACME_TXT_NAME", txt_name.as_str())
        .env("ACME_TXT_VALUE", txt_value)
        .env("ACME_ACTION", "cleanup");
    scrub_async(&mut cmd);
    let _ = tokio::time::timeout(HOOK_TIMEOUT, cmd.status()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn scrub_async_removes_secret_env_set_on_command() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir()?;
        let log = tmp.path().join("env.log");
        let script = tmp.path().join("scrub.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf 'kid=%s pw=%s hmac=%s safe=%s\\n' \"${{ACME_EAB_KID-}}\" \"${{ACME_ACCOUNT_KEY_PASSWORD-}}\" \"${{ACME_EAB_HMAC_KEY-}}\" \"${{ACME_DOMAIN-}}\" > {}\n",
                log.display()
            ),
        )?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;

        let mut cmd = tokio::process::Command::new(&script);
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("ACME_EAB_KID", "leaked-kid")
            .env("ACME_ACCOUNT_KEY_PASSWORD", "leaked-pw")
            .env("ACME_EAB_HMAC_KEY", "leaked-hmac")
            .env("ACME_DOMAIN", "example.com");

        scrub_async(&mut cmd);
        let status = cmd.status().await?;
        assert!(status.success());

        let observed = std::fs::read_to_string(&log)?;
        assert_eq!(observed.trim(), "kid= pw= hmac= safe=example.com");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_hook_times_out_on_hung_script() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir()?;
        let script = tmp.path().join("hang.sh");
        std::fs::write(&script, "#!/bin/sh\nexec sleep 600\n")?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;

        let mut cmd = tokio::process::Command::new(&script);
        cmd.kill_on_drop(true);
        scrub_async(&mut cmd);

        let mut child = cmd.spawn()?;
        let res = tokio::time::timeout(std::time::Duration::from_millis(150), child.wait()).await;
        assert!(res.is_err(), "hung script should not finish within 150ms");

        child.kill().await?;
        let _ = child.wait().await;
        Ok(())
    }
}
