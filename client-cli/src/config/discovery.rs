//! Config file path discovery and lightweight env + file resolution helpers.

use std::path::{Path, PathBuf};

use super::file::load_config_file;

/// Resolve only the server URL from env vars and config files.
///
/// Used by commands like `server cert` that need a server URL but no
/// authentication token.  Returns `None` when no server is configured.
pub fn resolve_server_only() -> Option<String> {
    if let Ok(val) = std::env::var("RC_SERVER") {
        if !val.is_empty() {
            return Some(val);
        }
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let path = find_config_file(&cwd).or_else(global_config_path);
    path.and_then(|p| load_config_file(&p).ok()).and_then(|c| c.server)
}

/// Walk up the directory tree from `start`, returning the first
/// `.red-cell-cli.toml` that exists.
///
/// Returns `None` when the filesystem root is reached without finding one.
pub fn find_config_file(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join(".red-cell-cli.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Return the path to the user-global config file:
/// `~/.config/red-cell-cli/config.toml`.
///
/// Returns `None` if the home/config directory cannot be determined.
pub fn global_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("red-cell-cli").join("config.toml"))
}

/// Check whether `enable_local_shell` is set in any config file.
///
/// Resolution: env var `RC_ENABLE_LOCAL_SHELL` (truthy = `1`/`true`/`yes`)
/// → config file → `false`.
pub fn resolve_enable_local_shell() -> bool {
    if let Ok(val) = std::env::var("RC_ENABLE_LOCAL_SHELL") {
        return matches!(val.as_str(), "1" | "true" | "yes");
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let path = find_config_file(&cwd).or_else(global_config_path);
    path.and_then(|p| load_config_file(&p).ok()).and_then(|c| c.enable_local_shell).unwrap_or(false)
}

/// Returns `true` when the CLI has no configuration from any source:
/// no `RC_SERVER`/`RC_TOKEN` env vars and no config file on disk.
pub fn is_unconfigured() -> bool {
    let has_env = std::env::var_os("RC_SERVER").is_some() || std::env::var_os("RC_TOKEN").is_some();
    if has_env {
        return false;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    no_config_on_disk(&cwd)
}

/// Check whether any config file exists — local walk-up or global path.
pub(crate) fn no_config_on_disk(cwd: &Path) -> bool {
    let has_local = find_config_file(cwd).is_some();
    let has_global = global_config_path().is_some_and(|p| p.is_file());
    !has_local && !has_global
}
