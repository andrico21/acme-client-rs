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
//! is a no-op (file removal, DNS hook cleanup on a missing record). The
//! happy-path cleanup code intentionally does **not** de-register actions —
//! relying on idempotency keeps the registration sites small and avoids the
//! risk of forgetting to de-register on a code path.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::challenge;

/// One unit of work the SIGINT handler will run before exit.
pub enum CleanupAction {
    HttpChallengeFile(PathBuf),
    DnsRecord {
        hook: PathBuf,
        domain: String,
        txt_name: String,
        txt_value: String,
    },
    ServerTask(tokio::task::AbortHandle),
}

#[derive(Clone, Default)]
pub struct CleanupRegistry {
    inner: Arc<Mutex<Vec<CleanupAction>>>,
}

impl CleanupRegistry {
    pub fn register(&self, action: CleanupAction) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.push(action);
        }
    }

    /// Synchronously execute every registered action. Errors are swallowed —
    /// cleanup is best-effort by design (the original record may already be
    /// gone, the hook may exit non-zero, etc.).
    pub fn run_all_sync(&self) {
        let actions = match self.inner.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(_) => return,
        };
        for action in actions {
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
            let _ = std::process::Command::new(hook)
                .env("ACME_DOMAIN", domain)
                .env("ACME_TXT_NAME", txt_name)
                .env("ACME_TXT_VALUE", txt_value)
                .env("ACME_ACTION", "cleanup")
                .status();
        }
        CleanupAction::ServerTask(handle) => {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn run_all_sync_removes_http_challenge_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("token");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"x").unwrap();
        assert!(path.exists());

        let reg = CleanupRegistry::default();
        reg.register(CleanupAction::HttpChallengeFile(path.clone()));
        reg.run_all_sync();
        assert!(!path.exists(), "challenge file should be cleaned");
    }

    #[cfg(unix)]
    #[test]
    fn run_all_sync_invokes_dns_hook_with_cleanup_action() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("hook.log");
        let hook = tmp.path().join("hook.sh");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\necho \"$ACME_ACTION:$ACME_DOMAIN:$ACME_TXT_NAME\" >> {}\n",
                log.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        let reg = CleanupRegistry::default();
        reg.register(CleanupAction::DnsRecord {
            hook,
            domain: "example.com".into(),
            txt_name: "_acme-challenge.example.com".into(),
            txt_value: "abc123".into(),
        });
        reg.run_all_sync();

        let contents = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            contents.trim(),
            "cleanup:example.com:_acme-challenge.example.com"
        );
    }

    #[test]
    fn run_all_sync_drains_registry() {
        let reg = CleanupRegistry::default();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("token");
        std::fs::write(&path, "x").unwrap();
        reg.register(CleanupAction::HttpChallengeFile(path.clone()));
        reg.run_all_sync();
        // Second drain should be a no-op even though file no longer exists.
        reg.run_all_sync();
    }
}
