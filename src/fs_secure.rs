//! Secure on-disk writes for secret material (account keys, private keys).
//!
//! Guarantees:
//! - Mode `0o600` on Unix (owner read/write only) — no `umask` surprises.
//! - `O_NOFOLLOW` on Unix — refuse to follow attacker-planted symlinks.
//! - Atomic: write to a temp file in the same directory, `fsync`, then
//!   `rename`. Readers never observe a half-written secret file.
//! - Refuses to overwrite an existing file unless `force = true`. This
//!   prevents accidental clobbering of an in-use account or private key.

use anyhow::{bail, Context, Result};
use std::path::Path;

/// Write `contents` to `path` with the secret-file guarantees above.
///
/// On non-Unix platforms permissions are not enforced (Windows ACLs are
/// out of scope for this client; the atomic-rename + no-overwrite checks
/// still apply).
pub fn write_secret_file(path: &Path, contents: &[u8], force: bool) -> Result<()> {
    if !force {
        match std::fs::symlink_metadata(path) {
            Ok(_) => bail!(
                "refusing to overwrite existing file {} (pass --force to override)",
                path.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("failed to stat {}", path.display())),
        }
    } else if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            bail!(
                "refusing to overwrite symlink {} (remove it manually)",
                path.display()
            );
        }
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
    let tmp_name = format!(".{}.acme-tmp.{}", file_name, std::process::id());
    let tmp_path = parent.join(tmp_name);

    let _ = std::fs::remove_file(&tmp_path);

    write_temp_file(&tmp_path, contents)
        .with_context(|| format!("failed to write temp file {}", tmp_path.display()))?;

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e)
            .with_context(|| format!("failed to atomically rename into {}", path.display()));
    }

    fsync_dir(parent);

    Ok(())
}

#[cfg(unix)]
fn write_temp_file(tmp_path: &Path, contents: &[u8]) -> Result<()> {
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
fn write_temp_file(tmp_path: &Path, contents: &[u8]) -> Result<()> {
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

#[cfg(unix)]
fn fsync_dir(dir: &Path) {
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("acme-fs-secure-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn writes_file_with_0600_on_unix() {
        let dir = tmpdir("writes_0600");
        let path = dir.join("k.pem");
        write_secret_file(&path, b"hello", false).unwrap();
        let mut s = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn refuses_overwrite_without_force() {
        let dir = tmpdir("refuses_overwrite");
        let path = dir.join("k.pem");
        write_secret_file(&path, b"first", false).unwrap();
        let err = write_secret_file(&path, b"second", false).unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"));
    }

    #[test]
    fn force_overwrites_regular_file() {
        let dir = tmpdir("force_overwrites");
        let path = dir.join("k.pem");
        write_secret_file(&path, b"first", false).unwrap();
        write_secret_file(&path, b"second", true).unwrap();
        let mut s = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "second");
    }

    #[cfg(unix)]
    #[test]
    fn force_refuses_symlink() {
        let dir = tmpdir("force_refuses_symlink");
        let target = dir.join("real");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.join("k.pem");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = write_secret_file(&link, b"second", true).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }
}
