//! TOML config file load, write, and byte-level persistence.

use std::path::Path;

use super::types::{ConfigError, FileConfig};

/// Load and parse a TOML config file from `path`.
///
/// Missing files are silently treated as empty configs rather than errors;
/// only files that exist but are malformed return an error.
///
/// On Unix, if the file exists with permissions looser than 0o600, they are
/// tightened to owner-only read/write and a warning is printed to stderr.
/// This guards against accidental exposure of API tokens on shared systems.
pub fn load_config_file(path: &Path) -> Result<FileConfig, ConfigError> {
    if !path.is_file() {
        return Ok(FileConfig::default());
    }

    // Tighten permissions on existing files that may have been created
    // without restrictive mode (e.g. by a text editor or manual `echo`).
    #[cfg(unix)]
    super::permissions::tighten_permissions(path);

    let content = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::ReadError { path: path.to_path_buf(), source: e })?;
    toml::from_str(&content)
        .map_err(|e| ConfigError::ParseError { path: path.to_path_buf(), source: e })
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
#[allow(dead_code)] // Called by write_config_file.
fn write_bytes(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
    };

    #[cfg(not(unix))]
    let mut file =
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(path)?;

    file.write_all(data)?;

    // On Unix, .mode() only applies at creation time. If the file already
    // existed with looser permissions, explicitly tighten them.
    #[cfg(unix)]
    super::permissions::tighten_permissions(path);

    Ok(())
}
