//! SEC-13: validate hook script paths before exec.
//!
//! Hook scripts (`--dns-hook`, `--on-challenge-ready`, `--on-cert-issued`) are
//! arbitrary code that runs with the privileges of the acme-client process —
//! typically root, since the client needs to write certificates to system
//! locations. A hook script that is writable by an unprivileged user becomes a
//! privilege-escalation primitive against the user running the client.
//!
//! Each configured hook path is checked for five properties before any hook is
//! executed. Properties 4 and 5 (the ancestor walk) are checked on *both* the
//! path exactly as configured and its `std::fs::canonicalize`-resolved
//! target, since either chain can be the one an attacker controls: the
//! lexical parent of the configured path is what must be controlled to swap
//! that path's own entry (whether it is a plain file, a symlink, or a hard
//! link), while a symlinked *ancestor component* would otherwise hide its
//! real subtree from a purely lexical walk:
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
//! 4. **Every ancestor directory up to `/` is owned by the effective user or
//!    root** — an ancestor owned by anyone else can `unlink(2) + rename(2)`
//!    to swap in an attacker-controlled file, regardless of that directory's
//!    mode.
//! 5. **Every ancestor directory up to `/` is not group/world-writable**
//!    (sticky directories such as the standard `/tmp` = `1777` are exempt —
//!    POSIX restricts unlink/rename there to the file's owner, the
//!    directory's owner, or root) — even a correctly-owned ancestor permits
//!    the same swap if it is writable by anyone else.
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

    // Resolve symlinks so the ancestor walk can also reach a symlinked
    // ancestor *component*'s real target (an attacker-owned subtree hidden
    // behind, e.g., /etc/acme/hook.sh -> /opt/deploy/dns.sh would otherwise
    // never have /opt/deploy inspected). This does NOT replace the lexical
    // walk below over `path` itself: whoever controls the directory holding
    // the `path` entry — symlink, hardlink, or plain file — can swap it
    // regardless of where it resolves to, and that directory is a lexical
    // ancestor of `path`, not of `resolved`. Both chains are walked; they
    // coincide (and the second walk is a cheap no-op re-check) whenever
    // `path` involves no symlink at all.
    let resolved = std::fs::canonicalize(path)
        .with_context(|| format!("failed to resolve hook path {}", path.display()))?;

    let st = stat(&resolved).with_context(|| format!("stat({}) failed", resolved.display()))?;
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

    walk_ancestors(path, path, euid, &mut violations)?;
    if resolved != path {
        walk_ancestors(&resolved, path, euid, &mut violations)?;
    }

    if violations.is_empty() {
        Ok(HookCheck::Ok)
    } else {
        Ok(HookCheck::Violations(violations))
    }
}

/// Walk every ancestor of `from` up to `/`, checking ownership and
/// group/world write bits. `hook` (only used in messages) is the path as
/// originally configured, which may differ from `from` when this is the
/// resolved-target chain rather than the lexical one.
#[cfg(unix)]
fn walk_ancestors(
    from: &Path,
    hook: &Path,
    euid: nix::unistd::Uid,
    violations: &mut Vec<String>,
) -> Result<()> {
    use nix::sys::stat::stat;
    use nix::unistd::Uid;
    use std::os::unix::ffi::OsStrExt;

    let mut current = from.parent();
    while let Some(dir) = current {
        // Skip empty path segment that .parent() can yield on some inputs.
        if dir.as_os_str().as_bytes().is_empty() {
            break;
        }
        let dst = stat(dir).with_context(|| format!("stat({}) failed", dir.display()))?;
        let dmode = dst.st_mode & 0o7777;
        let dir_owner = Uid::from_raw(dst.st_uid);
        for fault in ancestor_faults(dir_owner, dmode, euid) {
            violations.push(fault.describe(dir, hook));
        }
        current = dir.parent();
    }
    Ok(())
}

/// A directory can be both foreign-owned and world-writable at once, so
/// [`ancestor_faults`] returns a `Vec`, not an `Option`.
#[derive(Debug, PartialEq)]
enum AncestorFault {
    /// Owned by neither the current effective user nor root. That owner —
    /// not merely anyone able to exploit a group/world write bit — can
    /// unlink+rename the directory's contents regardless of its mode.
    ForeignOwner(u32),
    /// Group- or world-writable and not sticky-exempt.
    InsecurePermissions(nix::sys::stat::mode_t),
}

impl AncestorFault {
    fn describe(&self, dir: &Path, hook: &Path) -> String {
        match self {
            Self::ForeignOwner(uid) => format!(
                "directory {} above hook {} is owned by uid {uid}, not the current user or \
                 root; its owner can replace the hook script via unlink+rename regardless of \
                 its mode",
                dir.display(),
                hook.display(),
            ),
            Self::InsecurePermissions(dmode) => format!(
                "directory {} above hook {} has insecure permissions {:#o}; an \
                 unprivileged user can replace the hook script via unlink+rename",
                dir.display(),
                hook.display(),
                dmode,
            ),
        }
    }
}

/// Pure predicate — no syscalls, no root needed to unit-test — for what is
/// wrong, if anything, with one ancestor directory of a hook path.
fn ancestor_faults(
    dir_owner: nix::unistd::Uid,
    dmode: nix::sys::stat::mode_t,
    euid: nix::unistd::Uid,
) -> Vec<AncestorFault> {
    let mut faults = Vec::new();
    if dir_owner != euid && !dir_owner.is_root() {
        faults.push(AncestorFault::ForeignOwner(dir_owner.as_raw()));
    }
    // World/group-writable directories normally allow an attacker to swap
    // the hook script via unlink+rename. POSIX, however, gives the sticky
    // bit (0o1000) a precise meaning: in a sticky directory only the
    // file's owner, the directory's owner, or root may unlink or rename a
    // file. That is exactly the swap attack being guarded against, so a
    // sticky world/group-writable directory (the standard /tmp = 1777)
    // does NOT in fact give the attacker unlink/rename capability and
    // must not be flagged on mode alone.
    let sticky = dmode & 0o1000 != 0;
    if dmode & 0o022 != 0 && !sticky {
        faults.push(AncestorFault::InsecurePermissions(dmode));
    }
    faults
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
    use nix::unistd::Uid;
    use std::fs::{File, Permissions, set_permissions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn write_hook(path: &Path, mode: u32) -> Result<()> {
        let mut f = File::create(path)?;
        writeln!(f, "#!/bin/sh\necho ok")?;
        set_permissions(path, Permissions::from_mode(mode))?;
        Ok(())
    }

    #[test]
    fn relative_path_rejected() -> Result<()> {
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
    fn world_writable_file_rejected() -> Result<()> {
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
    fn group_writable_file_rejected() -> Result<()> {
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
    fn world_writable_parent_dir_rejected() -> Result<()> {
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

    // §4.1: a symlinked *leaf* hides its real parent directory from a purely
    // lexical ancestor walk. The symlink must be on the final component, not
    // a directory component — stat(2) already follows symlinks for the file
    // check, so a symlinked ancestor is dereferenced and its mode inspected
    // regardless; only a symlinked leaf lets a directory component skip the
    // walk entirely.
    #[test]
    fn symlinked_hook_walks_the_resolved_ancestor_not_the_link_parent() -> Result<()> {
        let tmp = tempdir()?;

        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir)?;
        let real_hook = real_dir.join("hook.sh");
        write_hook(&real_hook, 0o755)?;

        let link_dir = tmp.path().join("link");
        std::fs::create_dir(&link_dir)?;
        set_permissions(&link_dir, Permissions::from_mode(0o755))?;
        let link_hook = link_dir.join("hook.sh");
        std::os::unix::fs::symlink(&real_hook, &link_hook)?;

        // `real/` world-writable and non-sticky: only visible to the walk
        // once the symlink is resolved.
        set_permissions(&real_dir, Permissions::from_mode(0o777))?;
        match check_hook_path(&link_hook)? {
            HookCheck::Violations(vs) => {
                let real_dir_display = real_dir.display().to_string();
                assert!(
                    vs.iter().any(|v| v.contains(&real_dir_display)),
                    "expected a violation naming the resolved ancestor {real_dir:?}, got {vs:?}",
                );
            }
            HookCheck::Ok => {
                panic!("world-writable resolved ancestor must be caught via the symlinked leaf")
            }
        }

        // Non-regression: canonicalization alone must not over-reject a safe
        // resolved ancestor.
        set_permissions(&real_dir, Permissions::from_mode(0o755))?;
        assert!(
            matches!(check_hook_path(&link_hook)?, HookCheck::Ok),
            "safe resolved ancestor must not be flagged merely because the leaf is a symlink",
        );
        Ok(())
    }

    // The inverse of the test above, and the actual historical attack this
    // whole feature exists to close (fix-hook-cleanup-revalidation.md §5):
    // the attacker controls the directory holding the hook *entry* itself
    // (here, a symlink one could equally replace with a hardlink or a plain
    // file) and points it at some other, perfectly safe target — the swap
    // capability lives in the entry's own lexical parent, not in wherever it
    // happens to resolve to. If the walk only followed the resolved chain
    // (as an earlier, incomplete version of this fix did), this directory
    // would never be inspected at all and this would wrongly return `Ok`.
    #[test]
    fn symlinked_hook_also_walks_the_links_own_lexical_parent() -> Result<()> {
        let tmp = tempdir()?;

        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir)?;
        set_permissions(&real_dir, Permissions::from_mode(0o755))?;
        let real_hook = real_dir.join("hook.sh");
        write_hook(&real_hook, 0o755)?;

        let link_dir = tmp.path().join("link");
        std::fs::create_dir(&link_dir)?;
        let link_hook = link_dir.join("hook.sh");
        std::os::unix::fs::symlink(&real_hook, &link_hook)?;

        // `link/` world-writable and non-sticky: the resolved target is
        // completely safe, but anyone can still unlink+recreate the symlink
        // entry itself inside `link/`.
        set_permissions(&link_dir, Permissions::from_mode(0o777))?;
        match check_hook_path(&link_hook)? {
            HookCheck::Violations(vs) => {
                let link_dir_display = link_dir.display().to_string();
                assert!(
                    vs.iter().any(|v| v.contains(&link_dir_display)),
                    "expected a violation naming the symlink's own lexical parent \
                     {link_dir:?}, got {vs:?}",
                );
            }
            HookCheck::Ok => panic!(
                "world-writable lexical parent of a symlinked hook must be caught even \
                 when the resolved target is entirely safe"
            ),
        }
        set_permissions(&link_dir, Permissions::from_mode(0o755))?;
        Ok(())
    }

    // §4.2: the extracted pure predicate, exercised without touching the
    // filesystem (no root needed).
    #[test]
    fn ancestor_faults_predicate_covers_each_boundary() {
        let euid = nix::unistd::geteuid();
        let root = Uid::from_raw(0);
        let foreign = Uid::from_raw(if euid.as_raw() == 65534 { 65533 } else { 65534 });
        let safe_mode: nix::sys::stat::mode_t = 0o755;
        let world_writable_non_sticky: nix::sys::stat::mode_t = 0o777;
        let world_writable_sticky: nix::sys::stat::mode_t = 0o1777;

        assert_eq!(
            ancestor_faults(foreign, safe_mode, euid),
            vec![AncestorFault::ForeignOwner(foreign.as_raw())],
            "foreign owner, safe mode → ForeignOwner only",
        );
        assert_eq!(
            ancestor_faults(root, safe_mode, euid),
            vec![],
            "root-owned, safe mode → no fault",
        );
        assert_eq!(
            ancestor_faults(euid, safe_mode, euid),
            vec![],
            "self-owned, safe mode → no fault",
        );
        assert_eq!(
            ancestor_faults(euid, world_writable_sticky, euid),
            vec![],
            "self-owned, sticky world-writable (/tmp-style 1777) → no fault",
        );
        assert_eq!(
            ancestor_faults(foreign, world_writable_non_sticky, euid),
            vec![
                AncestorFault::ForeignOwner(foreign.as_raw()),
                AncestorFault::InsecurePermissions(world_writable_non_sticky),
            ],
            "foreign owner AND world-writable non-sticky → both faults",
        );
    }

    #[test]
    fn validate_all_hooks_strict_fails() -> Result<()> {
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
    fn sticky_world_writable_parent_accepted() -> Result<()> {
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
    fn validate_all_hooks_unsafe_warns_but_passes() -> Result<()> {
        let dir = tempdir()?;
        set_permissions(dir.path(), Permissions::from_mode(0o755))?;
        let hook = dir.path().join("bad.sh");
        write_hook(&hook, 0o777)?;
        // Should not bail in --unsafe-hooks mode.
        validate_all_hooks(&[("dns_hook", Some(&hook))], true)?;
        Ok(())
    }

    #[test]
    fn validate_all_hooks_skips_none() -> Result<()> {
        // No hooks configured → always Ok regardless of mode.
        validate_all_hooks(&[("dns_hook", None), ("on_cert_issued", None)], false)?;
        Ok(())
    }
}
