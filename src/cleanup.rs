//! SIGINT-safe cleanup registry for in-flight ACME challenges.
//!
//! Issuance commands (`run`, `pre-authorize`) may create
//! transient resources — HTTP-01 challenge files on disk, DNS-01 / dns-persist-01
//! TXT records at the provider via `--dns-hook`, and a local HTTP-01 server
//! task. The happy-path and error-path code already cleans these up, but a
//! `SIGINT` (Ctrl-C) bypasses every `?` and Drop is not guaranteed for in-flight
//! tokio futures.
//!
//! This module provides a process-wide registry that callers populate as they
//! create cleanup-needing state. A SIGINT watcher spawned in `main()` drains
//! the registry synchronously before exiting with code 130, so DNS records and
//! challenge files are not silently leaked when an operator aborts an issuance.
//!
//! Actions are idempotent: rerunning a cleanup on an already-cleaned resource
//! is a no-op (file removal, DNS hook cleanup on a missing record).
//! [`CleanupRegistry::register`] returns a [`CleanupHandle`]; once the
//! happy-path code has finished cleaning a resource it calls
//! [`CleanupHandle::complete`] to de-register that action, so a later SIGINT
//! does not re-invoke a hook for a record that was already torn down. A handle
//! dropped *without* `complete` leaves its action registered, so an early
//! cancel still cleans up — de-registration is opt-in and failure-safe.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::challenge;
use crate::defaults;
use crate::types::DnsName;

/// One unit of work the SIGINT handler will run before exit.
pub enum CleanupAction {
    HttpChallengeFile(PathBuf),
    DnsRecord {
        hook: PathBuf,
        domain: DnsName,
        txt_name: DnsName,
        txt_value: String,
    },
    ServerTask(tokio::task::AbortHandle),
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    actions: Vec<(u64, CleanupAction)>,
}

#[derive(Clone, Default)]
pub struct CleanupRegistry {
    inner: Arc<Mutex<Inner>>,
}

/// De-registration token returned by [`CleanupRegistry::register`].
///
/// Dropping it without calling [`complete`](CleanupHandle::complete) keeps the
/// action registered so an early SIGINT still cleans up.
#[must_use = "hold the handle until cleanup is done, then call complete()"]
pub struct CleanupHandle {
    registry: CleanupRegistry,
    id: u64,
}

impl CleanupHandle {
    /// De-register this action: the happy path already cleaned the resource, so
    /// a later SIGINT must not re-run the hook. Consuming `self` makes
    /// double-complete a compile error and prevents `let _ = register(...)`
    /// misuse from silently dropping the handle without firing cleanup.
    pub fn complete(self) {
        let mut guard = self.registry.lock_recover();
        guard.actions.retain(|(id, _)| *id != self.id);
    }
}

impl CleanupRegistry {
    /// Create an empty registry. Equivalent to [`Default::default`]; provided
    /// for API-guideline conformance (C-COMMON-TRAITS).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock the registry, recovering the guard if a previous holder panicked.
    /// A poisoned mutex must not silently disable all cleanup.
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "cleanup registry mutex poisoned; recovering to drain pending actions"
                );
                poisoned.into_inner()
            }
        }
    }

    pub fn register(&self, action: CleanupAction) -> CleanupHandle {
        let id = {
            let mut guard = self.lock_recover();
            let id = guard.next_id;
            guard.next_id = guard.next_id.wrapping_add(1);
            guard.actions.push((id, action));
            id
        };
        CleanupHandle {
            registry: self.clone(),
            id,
        }
    }

    /// Synchronously execute every registered action. Errors are swallowed —
    /// cleanup is best-effort by design (the original record may already be
    /// gone, the hook may exit non-zero, etc.).
    pub fn run_all_sync(&self) {
        let actions = {
            let mut guard = self.lock_recover();
            std::mem::take(&mut guard.actions)
        };
        for (_, action) in actions {
            run_one(&action);
        }
    }
}

fn run_one(action: &CleanupAction) {
    match action {
        CleanupAction::HttpChallengeFile(path) => {
            challenge::http01::cleanup_challenge_file(path);
        }
        CleanupAction::DnsRecord {
            hook,
            domain,
            txt_name,
            txt_value,
        } => {
            let mut cmd = std::process::Command::new(hook);
            cmd.env("ACME_DOMAIN", domain.as_str())
                .env("ACME_TXT_NAME", txt_name.as_str())
                .env("ACME_TXT_VALUE", txt_value)
                .env("ACME_ACTION", "cleanup");
            crate::handlers::hooks::scrub_secret_env(&mut cmd);
            run_hook_bounded(&mut cmd, defaults::hooks::HOOK_TIMEOUT);
        }
        CleanupAction::ServerTask(handle) => {
            handle.abort();
        }
    }
}

/// Spawn `cmd` and wait at most `timeout` for it to exit. If the deadline
/// passes, kill the child and reap it; if spawn or wait fails, log and
/// continue. Synchronous by design: this runs from the SIGINT cleanup path,
/// which executes outside the tokio runtime after a Ctrl-C.
fn run_hook_bounded(cmd: &mut std::process::Command, timeout: std::time::Duration) {
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cleanup hook failed to spawn: {e}");
            return;
        }
    };
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    tracing::warn!("cleanup hook exceeded timeout {timeout:?}; killing child");
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                tracing::warn!("cleanup hook wait failed: {e}");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;
    use std::io::Write;

    #[test]
    fn run_all_sync_removes_http_challenge_file() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("token");
        let mut f = std::fs::File::create(&path)?;
        f.write_all(b"x")?;
        assert!(path.exists());

        let reg = CleanupRegistry::new();
        let _handle = reg.register(CleanupAction::HttpChallengeFile(path.clone()));
        reg.run_all_sync();
        assert!(!path.exists(), "challenge file should be cleaned");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn run_all_sync_invokes_dns_hook_with_cleanup_action() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir()?;
        let log = tmp.path().join("hook.log");
        let hook = tmp.path().join("hook.sh");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\necho \"$ACME_ACTION:$ACME_DOMAIN:$ACME_TXT_NAME\" >> {}\n",
                log.display()
            ),
        )?;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))?;

        let reg = CleanupRegistry::new();
        let _handle = reg.register(CleanupAction::DnsRecord {
            hook,
            domain: DnsName::parse("example.com")?,
            txt_name: DnsName::parse_record_name("_acme-challenge.example.com")?,
            txt_value: "abc123".into(),
        });
        reg.run_all_sync();

        let contents = std::fs::read_to_string(&log)?;
        assert_eq!(
            contents.trim(),
            "cleanup:example.com:_acme-challenge.example.com"
        );
        Ok(())
    }

    #[test]
    fn run_all_sync_drains_registry() -> anyhow::Result<()> {
        let reg = CleanupRegistry::new();
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("token");
        std::fs::write(&path, "x")?;
        let _handle = reg.register(CleanupAction::HttpChallengeFile(path));
        reg.run_all_sync();
        // Second drain should be a no-op even though file no longer exists.
        reg.run_all_sync();
        Ok(())
    }

    #[test]
    fn l9_complete_removes_action() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let completed = tmp.path().join("completed");
        let pending = tmp.path().join("pending");
        std::fs::write(&completed, "x")?;
        std::fs::write(&pending, "x")?;

        let reg = CleanupRegistry::new();
        let completed_handle = reg.register(CleanupAction::HttpChallengeFile(completed.clone()));
        let _pending_handle = reg.register(CleanupAction::HttpChallengeFile(pending.clone()));
        completed_handle.complete();
        reg.run_all_sync();

        assert!(
            completed.exists(),
            "completed action must not run on SIGINT"
        );
        assert!(!pending.exists(), "pending action must still run");
        Ok(())
    }

    #[test]
    fn l9_poisoned_lock_still_drains() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("token");
        std::fs::write(&path, "x")?;

        let reg = CleanupRegistry::new();
        let poisoner = reg.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoner.inner.lock().expect("lock");
            panic!("poison the mutex");
        }));
        assert!(reg.inner.is_poisoned(), "mutex should be poisoned");

        let _handle = reg.register(CleanupAction::HttpChallengeFile(path.clone()));
        reg.run_all_sync();
        assert!(!path.exists(), "poisoned registry must still drain");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn c3_run_hook_bounded_kills_hung_hook() {
        let start = std::time::Instant::now();
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("60");
        run_hook_bounded(&mut cmd, std::time::Duration::from_secs(1));
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "hung hook must be killed at the deadline, took {elapsed:?}"
        );
    }
}
