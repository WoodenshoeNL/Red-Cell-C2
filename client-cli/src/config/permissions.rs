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

/// Best-effort tighten file permissions to 0o600 on Unix.
///
/// Before tightening, prints a warning to stderr if the mode was not already
/// `0o600`. Silently ignores errors (e.g. file owned by another user) so callers
/// never fail due to a permission-hardening attempt.
#[cfg(unix)]
pub(crate) fn tighten_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mode = match std::fs::metadata(path) {
        Ok(m) => m.permissions().mode(),
        Err(_) => return,
    };
    if let Some(msg) = config_permission_tightening_warning(mode) {
        eprint!("{msg}");
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
