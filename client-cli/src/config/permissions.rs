//! Best-effort Unix permission hardening for config file paths.

use std::path::Path;

/// If `mode & 0o777` is not already `0o600`, returns the stderr warning text
/// (including a trailing newline). Used by [`tighten_permissions`] and unit-tested.
#[cfg(unix)]
pub(crate) fn config_permission_tightening_warning(mode: u32) -> Option<String> {
    let mode = mode & 0o777;
    if mode == 0o600 {
        None
    } else {
        Some(format!(
            "warning: config file has insecure permissions ({mode:04o}); tightening to 0600.\n\
If this is unexpected, your config file may have been modified by another process.\n"
        ))
    }
}

/// Tighten file permissions to 0o600 on Unix.
///
/// Before tightening, prints a warning to stderr if the mode was not already
/// `0o600`. Returns the underlying `io::Error` if `set_permissions` fails so
/// callers can decide whether to proceed (e.g. the file has no token) or abort
/// (e.g. the file contains a secret that remains exposed).
#[cfg(unix)]
pub(crate) fn tighten_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)?.permissions().mode();
    if let Some(msg) = config_permission_tightening_warning(mode) {
        eprint!("{msg}");
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
