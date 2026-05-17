//! Non-Windows (Linux/macOS) fallback implementations for network enumeration.

#![cfg(not(windows))]

use std::process::{Command as SysCommand, Stdio};

use super::types::{NetGroup, NetSession, NetShare, NetUser};

/// Return the DNS domain name of this machine (Linux fallback).
pub(super) fn platform_domain_name() -> String {
    if let Ok(raw) = std::fs::read_to_string("/proc/sys/kernel/domainname") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && trimmed != "(none)" {
            return trimmed.to_string();
        }
    }
    if let Ok(output) =
        SysCommand::new("hostname").arg("-d").stdout(Stdio::piped()).stderr(Stdio::null()).output()
    {
        let domain = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !domain.is_empty() {
            return domain;
        }
    }
    String::new()
}

/// Enumerate currently logged-on users via `who` (Linux fallback).
pub(super) fn platform_logged_on_users() -> Vec<String> {
    let mut users = Vec::new();
    if let Ok(output) = SysCommand::new("who").stdout(Stdio::piped()).stderr(Stdio::null()).output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Some(name) = line.split_whitespace().next() {
                if !users.contains(&name.to_string()) {
                    users.push(name.to_string());
                }
            }
        }
    }
    users
}

/// Enumerate active login sessions via `who` (Linux fallback).
pub(super) fn platform_sessions() -> Vec<NetSession> {
    let mut sessions = Vec::new();
    if let Ok(output) = SysCommand::new("who").stdout(Stdio::piped()).stderr(Stdio::null()).output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                sessions.push(NetSession {
                    client: parts.get(1).unwrap_or(&"").to_string(),
                    user: parts.first().unwrap_or(&"").to_string(),
                    active_secs: 0,
                    idle_secs: 0,
                });
            }
        }
    }
    sessions
}

/// Enumerate network shares (Linux: no Samba equivalent, returns empty list).
pub(super) fn platform_shares() -> Vec<NetShare> {
    Vec::new()
}

/// Enumerate local groups from `/etc/group` (Linux fallback).
pub(super) fn platform_groups() -> Vec<NetGroup> {
    let mut groups = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/group") {
        for line in content.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, ':').collect();
            if let Some(name) = parts.first() {
                groups.push(NetGroup { name: (*name).to_string(), description: String::new() });
            }
        }
    }
    groups
}

/// Enumerate local users from `/etc/passwd` (Linux fallback).
pub(super) fn platform_users() -> Vec<NetUser> {
    let mut users = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, ':').collect();
            if let Some(name) = parts.first() {
                // UID 0 = root = admin equivalent on Linux.
                let uid: u32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(u32::MAX);
                users.push(NetUser { name: (*name).to_string(), is_admin: uid == 0 });
            }
        }
    }
    users
}

/// Enumerate computers in a domain (Linux: no equivalent API, returns empty list).
pub(super) fn platform_computers(_domain: &str) -> Vec<String> {
    Vec::new()
}

/// List domain controllers (Linux: no equivalent API, returns empty list).
pub(super) fn platform_dc_list(_domain: &str) -> Vec<String> {
    Vec::new()
}
