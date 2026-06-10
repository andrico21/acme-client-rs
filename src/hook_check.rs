//! SEC-13: validate hook script paths before exec.
//!
//! Hook scripts (`--dns-hook`, `--on-challenge-ready`, `--on-cert-issued`) are
//! arbitrary code that runs with the privileges of the acme-client process —
//! typically root, since the client needs to write certificates to system
//! locations. A hook script that is writable by an unprivileged user becomes a
//! privilege-escalation primitive against the user running the client.
//!
//! Each configured hook path is checked for four properties before any hook is
//! executed:
//!
//! 1. **Absolute path** — relative paths resolve against the process cwd, which
//!    for cron/systemd may be `/` or some other location the operator did not
//!    intend. Absolute paths leave no ambiguity.
//! 2. **Owner is the effective user or root** — mirrors how `sudo` validates
//!    `/etc/sudoers` and how OpenSSH validates host keys. Either the running
//!    user deployed the hook themselves, or a more-privileged operator (root)
//!    did.
//! 3. **File is not group/world-writable** — `mode & 0o022 == 0`. A writable
//!    bit lets any group member (or anyone, for world-writable) replace the
//!    script contents in place.
//! 4. **Every ancestor directory up to `/` is not group/world-writable** —
//!    even if the file itself is locked down, a writable parent allows
//!    `unlink(2) + rename(2)` to swap in an attacker-controlled file.
//!
//! On non-Unix targets all checks are skipped (Windows' permission model is
//! DACL-based and does not map onto these POSIX bits); a single advisory is
//! printed to stderr on first use.
//!
//! W8 / TOCTOU residual race: validation runs once at preflight and again
//! immediately before every spawn (chokepoint in `handlers::hooks`), but a
//! microscopic stat→execve window remains. The kernel resolves the script
//! path a second time on `execve(2)`; an attacker who can win a race
//! between our last `stat(2)` and the kernel's path resolution could still
//! swap the file. Closing that window would require exec-by-fd
//! (`fexecve(3)` / `execveat(2)` on an fd captured at validation time),
//! which cannot be expressed through `std`/`tokio` process APIs: wiring it
//! in needs `CommandExt::pre_exec` or a manual `fork(2)` — both `unsafe`,
//! and the crate is built with `#![forbid(unsafe_code)]`.
//! The double-check shrinks the window from
//! seconds-to-minutes (preflight → final spawn across the full ACME order)
//! down to microseconds, which is the strongest mitigation available to a
//! pure-safe-Rust binary.

use anyhow::{Context, Result, bail};
use std::path::Path;

/// Outcome of validating a hook path. Callers decide how to act (fail vs warn).
pub(crate) enum HookCheck {
    Ok,
    Violations(Vec<String>),
}

/// Validate one hook script path. Returns the list of violations found.
///
/// On non-Unix targets, returns [`HookCheck::Ok`] after emitting a one-shot
/// stderr advisory.
pub(crate) fn check_hook_path(path: &Path) -> Result<HookCheck> {
    #[cfg(unix)]
    {
        check_hook_path_unix(path)
    }
    #[cfg(not(unix))]
    {
        windows_advisory_once();
        let _ = path;
        Ok(HookCheck::Ok)
    }
}

#[cfg(not(unix))]
fn windows_advisory_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        tracing::warn!(
            "hook ownership/permission checks are not implemented on this platform; \
             ensure hook scripts and their containing directories are only writable by the \
             user running this binary"
        );
    });
}

#[cfg(unix)]
fn check_hook_path_unix(path: &Path) -> Result<HookCheck> {
    use nix::sys::stat::stat;
    use nix::unistd::{Uid, geteuid};
    use std::os::unix::ffi::OsStrExt;

    let mut violations: Vec<String> = Vec::new();

    if !path.is_absolute() {
        violations.push(format!(
            "hook path {} is relative; use an absolute path so cron/systemd \
             cannot resolve it against an attacker-controlled working directory",
            path.display(),
        ));
        // Don't continue with stat() on a relative path — semantics are
        // operator-cwd-dependent and any further check would be misleading.
        return Ok(HookCheck::Violations(violations));
    }

    let st = stat(path).with_context(|| format!("stat({}) failed", path.display()))?;
    let euid = geteuid();
    let owner = Uid::from_raw(st.st_uid);

    if owner != euid && !owner.is_root() {
        violations.push(format!(
            "hook {} is owned by uid {} but must be owned by the current user (uid {}) or root",
            path.display(),
            st.st_uid,
            euid.as_raw(),
        ));
    }

    // mode & 0o022 catches both group-writable (0o020) and world-writable
    // (0o002). st_mode also encodes the file type in the high bits; mask to
    // the permission bits before comparing.
    let mode = st.st_mode & 0o7777;
    if mode & 0o022 != 0 {
        violations.push(format!(
            "hook {} has insecure permissions {:#o}; group/world write must be cleared \
             (try: chmod go-w {})",
            path.display(),
            mode,
            path.display(),
        ));
    }

    // Walk every ancestor up to `/`. A writable directory permits the file to
    // be swapped (unlink + create) regardless of the file's own mode.
    let mut current = path.parent();
    while let Some(dir) = current {
        // Skip empty path segment that .parent() can yield on some inputs.
        if dir.as_os_str().as_bytes().is_empty() {
            break;
        }
        let dst = stat(dir).with_context(|| format!("stat({}) failed", dir.display()))?;
        let dmode = dst.st_mode & 0o7777;
        // World/group-writable directories normally allow an attacker to swap
        // the hook script via unlink+rename. POSIX, however, gives the sticky
        // bit (0o1000) a precise meaning: in a sticky directory only the
        // file's owner, the directory's owner, or root may unlink or rename a
        // file. That is exactly the swap attack we are guarding against, so a
        // sticky world/group-writable directory (the standard /tmp = 1777)
        // does NOT in fact give the attacker unlink/rename capability and
        // must not be flagged. Direct in-place writes by group members are
        // already prevented by the file-permission check at line 105 above.
        let sticky = dmode & 0o1000 != 0;
        if dmode & 0o022 != 0 && !sticky {
            violations.push(format!(
                "directory {} above hook {} has insecure permissions {:#o}; an \
                 unprivileged user can replace the hook script via unlink+rename",
                dir.display(),
                path.display(),
                dmode,
            ));
        }
        current = dir.parent();
    }

    if violations.is_empty() {
        Ok(HookCheck::Ok)
    } else {
        Ok(HookCheck::Violations(violations))
    }
}

/// Validate every configured hook. In strict mode (the default) any violation
/// is a hard error; with `--unsafe-hooks` violations become stderr warnings.
pub(crate) fn validate_all_hooks(
    hooks: &[(&str, Option<&Path>)],
    unsafe_hooks: bool,
) -> Result<()> {
    let mut all_violations: Vec<String> = Vec::new();
    for (label, maybe_path) in hooks {
        let Some(path) = maybe_path else { continue };
        match check_hook_path(path)? {
            HookCheck::Ok => {}
            HookCheck::Violations(vs) => {
                for v in vs {
                    all_violations.push(format!("[{label}] {v}"));
                }
            }
        }
    }
    if all_violations.is_empty() {
        return Ok(());
    }
    if unsafe_hooks {
        for v in &all_violations {
            tracing::warn!("{v}");
        }
        tracing::warn!(
            "continuing with --unsafe-hooks; the above privilege-escalation risks \
             are your responsibility to mitigate"
        );
        return Ok(());
    }
    let joined = all_violations.join("\n  ");
    bail!(
        "refusing to run with insecure hook scripts (SEC-13). Fix the permissions or \
         pass --unsafe-hooks / ACME_UNSAFE_HOOKS=1 / [global] unsafe_hooks=true to override:\n  {joined}"
    );
}

#[cfg(all(test, unix))]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use std::fs::{File, Permissions, set_permissions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn write_hook(path: &Path, mode: u32) -> anyhow::Result<()> {
        let mut f = File::create(path)?;
        writeln!(f, "#!/bin/sh\necho ok")?;
        set_permissions(path, Permissions::from_mode(mode))?;
        Ok(())
    }

    #[test]
    fn relative_path_rejected() -> anyhow::Result<()> {
        let res = check_hook_path(Path::new("relative-hook.sh"))?;
        match res {
            HookCheck::Violations(vs) => {
                assert!(vs.iter().any(|v| v.contains("relative")));
            }
            HookCheck::Ok => panic!("relative path should be rejected"),
        }
        Ok(())
    }

    #[test]
    fn world_writable_file_rejected() -> anyhow::Result<()> {
        let dir = tempdir()?;
        set_permissions(dir.path(), Permissions::from_mode(0o755))?;
        let hook = dir.path().join("hook.sh");
        write_hook(&hook, 0o777)?; // World-writable.
        let res = check_hook_path(&hook)?;
        match res {
            HookCheck::Violations(vs) => {
                assert!(vs.iter().any(|v| v.contains("insecure permissions")));
            }
            HookCheck::Ok => panic!("world-writable file should be rejected"),
        }
        Ok(())
    }

    #[test]
    fn group_writable_file_rejected() -> anyhow::Result<()> {
        let dir = tempdir()?;
        set_permissions(dir.path(), Permissions::from_mode(0o755))?;
        let hook = dir.path().join("hook.sh");
        write_hook(&hook, 0o775)?; // Group-writable.
        let res = check_hook_path(&hook)?;
        match res {
            HookCheck::Violations(vs) => {
                assert!(vs.iter().any(|v| v.contains("insecure permissions")));
            }
            HookCheck::Ok => panic!("group-writable file should be rejected"),
        }
        Ok(())
    }

    #[test]
    fn world_writable_parent_dir_rejected() -> anyhow::Result<()> {
        let dir = tempdir()?;
        // Parent dir world-writable, file itself locked down.
        set_permissions(dir.path(), Permissions::from_mode(0o777))?;
        let hook = dir.path().join("hook.sh");
        write_hook(&hook, 0o755)?;
        let res = check_hook_path(&hook)?;
        match res {
            HookCheck::Violations(vs) => {
                assert!(
                    vs.iter()
                        .any(|v| v.contains("above hook") && v.contains("insecure")),
                    "expected parent-dir violation, got {vs:?}",
                );
            }
            HookCheck::Ok => panic!("world-writable parent should be rejected"),
        }
        // Restore mode so tempdir can clean up.
        set_permissions(dir.path(), Permissions::from_mode(0o755))?;
        Ok(())
    }

    #[test]
    fn validate_all_hooks_strict_fails() -> anyhow::Result<()> {
        let dir = tempdir()?;
        set_permissions(dir.path(), Permissions::from_mode(0o755))?;
        let hook = dir.path().join("bad.sh");
        write_hook(&hook, 0o777)?;
        let Err(err) = validate_all_hooks(&[("dns_hook", Some(&hook))], false) else {
            panic!("expected error for world-writable hook");
        };
        assert!(err.to_string().contains("refusing to run"));
        Ok(())
    }

    #[test]
    fn sticky_world_writable_parent_accepted() -> anyhow::Result<()> {
        let dir = tempdir()?;
        set_permissions(dir.path(), Permissions::from_mode(0o1777))?;
        let hook = dir.path().join("hook.sh");
        write_hook(&hook, 0o755)?;
        let res = check_hook_path(&hook)?;
        assert!(
            matches!(res, HookCheck::Ok),
            "sticky world-writable parent (1777) must not be flagged",
        );
        set_permissions(dir.path(), Permissions::from_mode(0o755))?;
        Ok(())
    }

    #[test]
    fn validate_all_hooks_unsafe_warns_but_passes() -> anyhow::Result<()> {
        let dir = tempdir()?;
        set_permissions(dir.path(), Permissions::from_mode(0o755))?;
        let hook = dir.path().join("bad.sh");
        write_hook(&hook, 0o777)?;
        // Should not bail in --unsafe-hooks mode.
        validate_all_hooks(&[("dns_hook", Some(&hook))], true)?;
        Ok(())
    }

    #[test]
    fn validate_all_hooks_skips_none() -> anyhow::Result<()> {
        // No hooks configured → always Ok regardless of mode.
        validate_all_hooks(&[("dns_hook", None), ("on_cert_issued", None)], false)?;
        Ok(())
    }
}
