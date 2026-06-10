//! Secure on-disk writes for secret material (account keys, private keys).
//!
//! Guarantees:
//! - Mode `0o600` on Unix (owner read/write only) — no `umask` surprises.
//! - `O_NOFOLLOW` on Unix — refuse to follow attacker-planted symlinks.
//! - Atomic: write to a temp file in the same directory, `fsync`, then
//!   `rename`. Readers never observe a half-written secret file.
//! - Refuses to overwrite an existing file unless `force = true`. This
//!   prevents accidental clobbering of an in-use account or private key.

use anyhow::{Context, Result, bail};
use std::path::Path;

/// Whether `write_secret_file` may overwrite an existing file at `path`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overwrite {
    Forbid,
    Allow,
}

/// Write `contents` to `path` with the secret-file guarantees above.
///
/// On non-Unix platforms permissions are not enforced (Windows ACLs are
/// out of scope for this client; the atomic-rename + no-overwrite checks
/// still apply).
pub fn write_secret_file(path: &Path, contents: &[u8], overwrite: Overwrite) -> Result<()> {
    if overwrite == Overwrite::Forbid {
        match std::fs::symlink_metadata(path) {
            Ok(_) => bail!(
                "refusing to overwrite existing file {} (pass --force to override)",
                path.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("failed to stat {}", path.display())),
        }
    } else if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        bail!(
            "refusing to overwrite symlink {} (remove it manually)",
            path.display()
        );
    }

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }

    let file_name = path
        .file_name()
        .with_context(|| format!("invalid output path {}", path.display()))?
        .to_string_lossy();

    // Create the temp file under an unpredictable, randomly-suffixed name with
    // `O_EXCL` (`create_new`) and never `remove_file` an existing temp first:
    // a deterministic name plus pre-removal lets an attacker in a shared parent
    // dir pre-plant or race the temp path (symlink attack / DoS). We retry on
    // the rare `AlreadyExists` collision rather than clobbering.
    let tmp_path = write_unique_temp_file(parent, &file_name, contents)?;

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        if let Err(rm_err) = std::fs::remove_file(&tmp_path) {
            tracing::warn!(
                "failed to remove leftover temp file {} after failed rename: {}",
                tmp_path.display(),
                rm_err
            );
        }
        return Err(e)
            .with_context(|| format!("failed to atomically rename into {}", path.display()));
    }

    fsync_dir(parent).with_context(|| format!("failed to fsync directory {}", parent.display()))?;

    Ok(())
}

const TEMP_NAME_RETRIES: u32 = 8;

/// Write `contents` to a freshly created, randomly named temp file in `parent`
/// and return its path. Each attempt uses `O_EXCL`/`create_new`; an
/// `AlreadyExists` collision (random-name clash or attacker-planted path) is
/// retried with a fresh suffix up to [`TEMP_NAME_RETRIES`] times.
fn write_unique_temp_file(
    parent: &Path,
    file_name: &str,
    contents: &[u8],
) -> Result<std::path::PathBuf> {
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..TEMP_NAME_RETRIES {
        let tmp_name = format!(".{}.acme-tmp.{}", file_name, random_suffix());
        let tmp_path = parent.join(tmp_name);
        match write_temp_file(&tmp_path, contents) {
            Ok(()) => return Ok(tmp_path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to write temp file in {}", parent.display()));
            }
        }
    }
    Err(last_err.map_or_else(
        || anyhow::anyhow!("temp file name collision"),
        anyhow::Error::from,
    ))
    .with_context(|| {
        format!(
            "failed to create unique temp file in {} after {} attempts",
            parent.display(),
            TEMP_NAME_RETRIES
        )
    })
}

/// 16 lowercase-hex characters from 8 bytes of OS CSPRNG entropy.
fn random_suffix() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(16);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(unix)]
fn write_temp_file(tmp_path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(tmp_path)?;
    f.write_all(contents)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_temp_file(tmp_path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp_path)?;
    f.write_all(contents)?;
    f.sync_all()?;
    Ok(())
}

/// Warn (via `tracing::warn!`) if `path` is group- or world-readable on Unix.
///
/// Intended for sensitive inputs (config files, password files) where we
/// cannot refuse to read — the user may have intentionally relaxed perms —
/// but where lax modes likely indicate a misconfiguration. No-op on non-Unix
/// and silently ignores stat failures (the caller will surface read errors).
pub fn warn_if_world_readable(path: &Path, kind: &str) {
    #[cfg(unix)]
    {
        if let Some(mode) = permissive_mode(path) {
            tracing::warn!(
                "{} file {} has permissive mode {:o} (group/world accessible) — consider `chmod 600 {}`",
                kind,
                path.display(),
                mode,
                path.display(),
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, kind);
    }
}

/// Group/world-accessible `0o777` bits of `path`, or `None`. Uses
/// `symlink_metadata` (NOT `metadata`) so a sensitive path that is itself a
/// symlink is flagged via its own `0o777` mode instead of statting the target.
#[cfg(unix)]
fn permissive_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).ok()?;
    let mode = meta.mode() & 0o777;
    (mode & 0o077 != 0).then_some(mode)
}

#[cfg(unix)]
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    let d = std::fs::File::open(dir)?;
    d.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Re-assert `0o600` (owner read/write only) on an existing secret file.
///
/// Used on the `--reuse-key` skip path where the on-disk key is reused
/// as-is: the file may have been created with a permissive umask before
/// this client took ownership of it, so we must enforce the secret-file
/// mode every run, not only when we write.
///
/// On non-Unix platforms this is a documented no-op (Windows ACLs are
/// out of scope for this client, mirroring `write_secret_file`).
pub fn ensure_secret_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod 0600 on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use std::io::Read;

    fn tmpdir(tag: &str) -> anyhow::Result<std::path::PathBuf> {
        let p = std::env::temp_dir().join(format!("acme-fs-secure-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p)?;
        Ok(p)
    }

    #[test]
    fn writes_file_with_0600_on_unix() -> anyhow::Result<()> {
        let dir = tmpdir("writes_0600")?;
        let path = dir.join("k.pem");
        write_secret_file(&path, b"hello", Overwrite::Forbid)?;
        let mut s = String::new();
        std::fs::File::open(&path)?.read_to_string(&mut s)?;
        assert_eq!(s, "hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        Ok(())
    }

    #[test]
    fn refuses_overwrite_without_force() -> anyhow::Result<()> {
        let dir = tmpdir("refuses_overwrite")?;
        let path = dir.join("k.pem");
        write_secret_file(&path, b"first", Overwrite::Forbid)?;
        let Err(err) = write_secret_file(&path, b"second", Overwrite::Forbid) else {
            panic!("expected refusal to overwrite");
        };
        assert!(err.to_string().contains("refusing to overwrite"));
        Ok(())
    }

    #[test]
    fn force_overwrites_regular_file() -> anyhow::Result<()> {
        let dir = tmpdir("force_overwrites")?;
        let path = dir.join("k.pem");
        write_secret_file(&path, b"first", Overwrite::Forbid)?;
        write_secret_file(&path, b"second", Overwrite::Allow)?;
        let mut s = String::new();
        std::fs::File::open(&path)?.read_to_string(&mut s)?;
        assert_eq!(s, "second");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn force_refuses_symlink() -> anyhow::Result<()> {
        let dir = tmpdir("force_refuses_symlink")?;
        let target = dir.join("real");
        std::fs::write(&target, b"x")?;
        let link = dir.join("k.pem");
        std::os::unix::fs::symlink(&target, &link)?;
        let Err(err) = write_secret_file(&link, b"second", Overwrite::Allow) else {
            panic!("expected refusal on symlink");
        };
        assert!(err.to_string().contains("symlink"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn l4_symlink_metadata_used() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("l4_symlink_metadata")?;
        let target = dir.join("secret");
        std::fs::write(&target, b"x")?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(permissive_mode(&target), None);

        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link)?;
        assert!(
            permissive_mode(&link).is_some(),
            "symlink must be flagged via symlink_metadata (metadata would follow to the 0600 target)"
        );
        Ok(())
    }

    #[test]
    fn m4_random_suffix_is_unpredictable() {
        let a = random_suffix();
        let b = random_suffix();
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(
            a, b,
            "two suffixes must differ (random, not pid-deterministic)"
        );
    }

    #[test]
    fn m4_no_leftover_temp_files_after_write() -> anyhow::Result<()> {
        let dir = tmpdir("m4_no_leftover")?;
        let path = dir.join("k.pem");
        write_secret_file(&path, b"secret", Overwrite::Forbid)?;
        let leftover: Vec<_> = std::fs::read_dir(&dir)?
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("acme-tmp"))
            .collect();
        assert!(
            leftover.is_empty(),
            "temp files must not survive: {leftover:?}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn w17_ensure_secret_perms_tightens_0644_to_0600() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("w17_ensure_perms")?;
        let path = dir.join("reused.key");
        std::fs::write(&path, b"PEM")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o644
        );
        ensure_secret_perms(&path)?;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600,
            "ensure_secret_perms must chmod to 0600"
        );
        Ok(())
    }
}
