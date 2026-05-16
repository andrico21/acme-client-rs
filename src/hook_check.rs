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

use anyhow::{bail, Context, Result};
use std::path::Path;

/// Outcome of validating a hook path. Callers decide how to act (fail vs warn).
pub enum HookCheck {
    Ok,
    Violations(Vec<String>),
}

/// Validate one hook script path. Returns the list of violations found.
///
/// On non-Unix targets, returns [`HookCheck::Ok`] after emitting a one-shot
/// stderr advisory.
pub fn check_hook_path(path: &Path) -> Result<HookCheck> {
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
        eprintln!(
            "warning: hook ownership/permission checks are not implemented on this platform; \
             ensure hook scripts and their containing directories are only writable by the \
             user running this binary"
        );
    });
}

#[cfg(unix)]
fn check_hook_path_unix(path: &Path) -> Result<HookCheck> {
    use nix::sys::stat::stat;
    use nix::unistd::{geteuid, Uid};
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
        if dmode & 0o022 != 0 {
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
pub fn validate_all_hooks(hooks: &[(&str, Option<&Path>)], unsafe_hooks: bool) -> Result<()> {
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
            eprintln!("warning: {v}");
        }
        eprintln!(
            "warning: continuing with --unsafe-hooks; the above privilege-escalation risks \
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
mod tests {
    use super::*;
    use std::fs::{set_permissions, File, Permissions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn write_hook(path: &Path, mode: u32) {
        let mut f = File::create(path).unwrap();
        writeln!(f, "#!/bin/sh\necho ok").unwrap();
        set_permissions(path, Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn relative_path_rejected() {
        let res = check_hook_path(Path::new("relative-hook.sh")).unwrap();
        match res {
            HookCheck::Violations(vs) => {
                assert!(vs.iter().any(|v| v.contains("relative")));
            }
            HookCheck::Ok => panic!("relative path should be rejected"),
        }
    }

    #[test]
    fn world_writable_file_rejected() {
        let dir = tempdir().unwrap();
        set_permissions(dir.path(), Permissions::from_mode(0o755)).unwrap();
        let hook = dir.path().join("hook.sh");
        write_hook(&hook, 0o777); // World-writable.
        let res = check_hook_path(&hook).unwrap();
        match res {
            HookCheck::Violations(vs) => {
                assert!(vs.iter().any(|v| v.contains("insecure permissions")));
            }
            HookCheck::Ok => panic!("world-writable file should be rejected"),
        }
    }

    #[test]
    fn group_writable_file_rejected() {
        let dir = tempdir().unwrap();
        set_permissions(dir.path(), Permissions::from_mode(0o755)).unwrap();
        let hook = dir.path().join("hook.sh");
        write_hook(&hook, 0o775); // Group-writable.
        let res = check_hook_path(&hook).unwrap();
        match res {
            HookCheck::Violations(vs) => {
                assert!(vs.iter().any(|v| v.contains("insecure permissions")));
            }
            HookCheck::Ok => panic!("group-writable file should be rejected"),
        }
    }

    #[test]
    fn world_writable_parent_dir_rejected() {
        let dir = tempdir().unwrap();
        // Parent dir world-writable, file itself locked down.
        set_permissions(dir.path(), Permissions::from_mode(0o777)).unwrap();
        let hook = dir.path().join("hook.sh");
        write_hook(&hook, 0o755);
        let res = check_hook_path(&hook).unwrap();
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
        set_permissions(dir.path(), Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn validate_all_hooks_strict_fails() {
        let dir = tempdir().unwrap();
        set_permissions(dir.path(), Permissions::from_mode(0o755)).unwrap();
        let hook = dir.path().join("bad.sh");
        write_hook(&hook, 0o777);
        let err = validate_all_hooks(&[("dns_hook", Some(&hook))], false).unwrap_err();
        assert!(err.to_string().contains("refusing to run"));
    }

    #[test]
    fn validate_all_hooks_unsafe_warns_but_passes() {
        let dir = tempdir().unwrap();
        set_permissions(dir.path(), Permissions::from_mode(0o755)).unwrap();
        let hook = dir.path().join("bad.sh");
        write_hook(&hook, 0o777);
        // Should not bail in --unsafe-hooks mode.
        validate_all_hooks(&[("dns_hook", Some(&hook))], true).unwrap();
    }

    #[test]
    fn validate_all_hooks_skips_none() {
        // No hooks configured → always Ok regardless of mode.
        validate_all_hooks(&[("dns_hook", None), ("on_cert_issued", None)], false).unwrap();
    }
}
