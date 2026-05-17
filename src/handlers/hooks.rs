//! Shell-hook invocation helpers.
//!
//! Two flavors:
//!   - [`run_hook`]: generic — caller supplies the env-var contract.
//!   - The `run_dns_hook_*` family: hard-codes the
//!     `ACME_DOMAIN` / `ACME_TXT_NAME` / `ACME_TXT_VALUE` / `ACME_ACTION`
//!     contract documented in README for DNS-01 challenge plumbing.
//!
//! Cleanup variants come in two failure modes. See each fn's doc-comment
//! for when to pick which.

use std::path::Path;

use anyhow::{Context, Result};

pub(crate) fn run_hook(script: &Path, env_vars: &[(&str, &str)]) -> Result<()> {
    let mut cmd = std::process::Command::new(script);
    for &(key, val) in env_vars {
        cmd.env(key, val);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to run hook: {}", script.display()))?;
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
pub(crate) fn run_dns_hook_create(
    hook: &Path,
    domain: &str,
    txt_name: &str,
    txt_value: &str,
) -> Result<()> {
    let status = std::process::Command::new(hook)
        .env("ACME_DOMAIN", domain)
        .env("ACME_TXT_NAME", txt_name)
        .env("ACME_TXT_VALUE", txt_value)
        .env("ACME_ACTION", "create")
        .status()
        .with_context(|| format!("failed to run DNS hook: {}", hook.display()))?;
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
pub(crate) fn run_dns_hook_cleanup_logged(
    hook: &Path,
    domain: &str,
    txt_name: &str,
    txt_value: &str,
) {
    let status = std::process::Command::new(hook)
        .env("ACME_DOMAIN", domain)
        .env("ACME_TXT_NAME", txt_name)
        .env("ACME_TXT_VALUE", txt_value)
        .env("ACME_ACTION", "cleanup")
        .status();
    match status {
        Ok(s) if !s.success() => tracing::warn!("DNS hook (cleanup) exited with {s}"),
        Err(e) => tracing::warn!("DNS hook (cleanup) failed: {e}"),
        _ => {}
    }
}

/// Best-effort DNS cleanup hook for parallel-DNS rollback paths where any
/// hook failure would be immediately followed by `anyhow::bail!` anyway,
/// making logging redundant. Use [`run_dns_hook_cleanup_logged`] elsewhere.
pub(crate) fn run_dns_hook_cleanup_silent(
    hook: &Path,
    domain: &str,
    txt_name: &str,
    txt_value: &str,
) {
    let _ = std::process::Command::new(hook)
        .env("ACME_DOMAIN", domain)
        .env("ACME_TXT_NAME", txt_name)
        .env("ACME_TXT_VALUE", txt_value)
        .env("ACME_ACTION", "cleanup")
        .status();
}
