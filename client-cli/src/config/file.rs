//! TOML config file load, write, and byte-level persistence.

use std::path::Path;

use super::types::{ConfigError, FileConfig};

// Test-only hook: when set, `call_tighten` calls this instead of the real
// `tighten_permissions`. Set to `None` to restore real behaviour.
#[cfg(all(unix, test))]
thread_local! {
    pub(crate) static TIGHTEN_PERMISSIONS_FN: std::cell::Cell<
        Option<fn(&std::path::Path) -> std::io::Result<()>>,
    > = std::cell::Cell::new(None);
}

// Test-only hook for Windows crash-recovery: when set, the rename inside the
// recovery block calls this instead of `std::fs::rename`.  Set to `None` to
// restore real behaviour.
#[cfg(all(windows, test))]
thread_local! {
    pub(crate) static CRASH_RECOVERY_RENAME_FN: std::cell::Cell<
        Option<fn(&std::path::Path, &std::path::Path) -> std::io::Result<()>>,
    > = std::cell::Cell::new(None);
}

/// Thin wrapper so tests can inject chmod failures without root.
#[cfg(unix)]
fn call_tighten(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(f) = TIGHTEN_PERMISSIONS_FN.with(|c| c.get()) {
        return f(path);
    }
    super::permissions::tighten_permissions(path)
}

/// Load and parse a TOML config file from `path`.
///
/// Missing files are silently treated as empty configs rather than errors;
/// only files that exist but are malformed return an error.
///
/// On Unix, if the file exists with permissions looser than 0o600, they are
/// tightened to owner-only read/write and a warning is emitted via `tracing::warn!` (not raw stderr).
/// This guards against accidental exposure of API tokens on shared systems.
pub fn load_config_file(path: &Path) -> Result<FileConfig, ConfigError> {
    // Windows crash-recovery: if the process died between the backup-rename
    // and the final rename in `write_bytes`, restore the .bak sibling so the
    // user's config is not silently replaced by a default.
    #[cfg(windows)]
    if !path.is_file() {
        if let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) {
            let backup = parent.join(format!(".{}.bak", file_name.to_string_lossy()));
            if backup.is_file() {
                #[cfg(test)]
                let rename_result = {
                    let hook = CRASH_RECOVERY_RENAME_FN.with(|c| c.get());
                    match hook {
                        Some(f) => f(&backup, path),
                        None => std::fs::rename(&backup, path),
                    }
                };
                #[cfg(not(test))]
                let rename_result = std::fs::rename(&backup, path);
                if let Err(e) = rename_result {
                    tracing::warn!(
                        backup = %backup.display(),
                        path = %path.display(),
                        error = %e,
                        "crash-recovery restore failed; falling back to default config"
                    );
                }
            }
        }
    }

    if !path.is_file() {
        return Ok(FileConfig::default());
    }

    // Tighten permissions on existing files that may have been created
    // without restrictive mode (e.g. by a text editor or manual `echo`).
    // Capture the outcome — on failure we re-check the actual mode below.
    #[cfg(unix)]
    let chmod_err = call_tighten(path).err();

    let content = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::ReadError { path: path.to_path_buf(), source: e })?;
    let config: FileConfig = toml::from_str(&content)
        .map_err(|e| ConfigError::ParseError { path: path.to_path_buf(), source: e })?;

    // If chmod failed, determine the actual mode and decide what to do.
    #[cfg(unix)]
    if let Some(err) = chmod_err {
        use std::os::unix::fs::PermissionsExt;
        let final_mode =
            std::fs::metadata(path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o777); // assume worst-case if metadata unavailable

        if final_mode != 0o600 && config.token.is_some() {
            // The file contains a token and we could not make it owner-only:
            // refuse to expose the secret rather than silently proceeding.
            return Err(ConfigError::InsecurePermissions {
                path: path.to_path_buf(),
                mode: final_mode,
            });
        }

        if final_mode != 0o600 {
            // No token at risk — route through tracing, not raw stderr.
            tracing::warn!(
                path = %path.display(),
                mode = format!("{final_mode:04o}"),
                %err,
                "could not tighten permissions on config file",
            );
        }
    }

    Ok(config)
}

/// Write `data` to `path` with mode 0o600 on Unix (owner-only read/write).
///
/// On non-Unix platforms this uses default permissions.
///
/// Parent directories are **not** created automatically — the caller must
/// ensure they exist.
#[allow(dead_code)] // Public API for future config-writing commands.
pub fn write_config_file(path: &Path, config: &FileConfig) -> Result<(), ConfigError> {
    let content = toml::to_string_pretty(config).map_err(|e| ConfigError::WriteError {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })?;

    write_bytes(path, content.as_bytes())
        .map_err(|e| ConfigError::WriteError { path: path.to_path_buf(), source: e })
}

/// Write raw bytes to `path` with 0o600 on Unix.
///
/// Uses an atomic write: data lands in a sibling temp file with mode 0o600,
/// then the target is replaced in a crash-safe sequence.
///
/// On Unix, [`std::fs::rename`] replaces the target atomically in one syscall,
/// so a partial write can never corrupt the live config.
///
/// On Windows, `std::fs::rename` fails when the destination already exists.
/// Instead the existing config is first renamed to a `.bak` sibling, the temp
/// file is renamed to the final path, and the backup is removed.  If the
/// process crashes between those two renames the old config survives as the
/// `.bak` file and [`load_config_file`] restores it automatically on the next
/// startup.
#[allow(dead_code)] // Called by write_config_file.
fn write_bytes(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or(Path::new("."));
    let file_name = path.file_name().unwrap_or(std::ffi::OsStr::new("config"));
    // Temp file lives in the same directory so rename stays on one filesystem.
    let tmp_name = format!(".{}.{}.tmp", file_name.to_string_lossy(), std::process::id());
    let tmp_path = parent.join(&tmp_name);

    let write_result: std::io::Result<()> = (|| {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true) // 0o600 applies at creation — exclusive open
                .mode(0o600)
                .open(&tmp_path)?
        };

        #[cfg(not(unix))]
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp_path)?;

        file.write_all(data)
        // `file` is dropped (flushed + closed) before the closure returns
    })();

    match write_result {
        Ok(()) => {
            #[cfg(not(windows))]
            {
                std::fs::rename(&tmp_path, path).inspect_err(|_| {
                    let _ = std::fs::remove_file(&tmp_path);
                })
            }

            #[cfg(windows)]
            {
                // `rename` fails on Windows when the destination exists.  Move the
                // existing config to a .bak sibling first so the old data is
                // preserved across the rename window.  load_config_file restores
                // the .bak automatically if we crash before the final rename.
                let backup_path = parent.join(format!(".{}.bak", file_name.to_string_lossy()));
                // A stale .bak from a previous interrupted cleanup (e.g. AV
                // or an indexer holding the file) would cause the rename below
                // to fail with AlreadyExists — Windows does not replace on
                // rename.  Clear it explicitly before entering the swap
                // sequence so subsequent writes do not start failing.
                match std::fs::remove_file(&backup_path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        let _ = std::fs::remove_file(&tmp_path);
                        return Err(e);
                    }
                }
                let had_backup = match std::fs::rename(path, &backup_path) {
                    Ok(()) => true,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                    Err(e) => {
                        let _ = std::fs::remove_file(&tmp_path);
                        return Err(e);
                    }
                };
                if let Err(e) = std::fs::rename(&tmp_path, path) {
                    if had_backup {
                        let _ = std::fs::rename(&backup_path, path);
                    }
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(e);
                }
                if had_backup {
                    let _ = std::fs::remove_file(&backup_path);
                }
                Ok(())
            }
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}
