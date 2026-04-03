//! System information queries: domain, hostname, users, groups, sessions.

use std::fs;

use crate::error::PhantomError;

use super::io_error;
use super::types::{GroupEntry, SessionEntry, ShareEntry, UserEntry};

// Re-export memory/protection constants so other modules can use them via `super::sysinfo::`.
pub(super) use super::types::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY,
};

pub(super) fn linux_domain_name() -> String {
    fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                let trimmed = line.trim();
                trimmed
                    .strip_prefix("search ")
                    .or_else(|| trimmed.strip_prefix("domain "))
                    .map(|value| value.trim().to_string())
            })
        })
        .unwrap_or_default()
}

pub(super) fn local_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| String::from("localhost"))
}

pub(super) fn default_net_target(value: &str) -> String {
    if value.is_empty() { local_hostname() } else { value.to_string() }
}

pub(super) fn compatible_computer_list(target: &str) -> Vec<String> {
    let hostname = local_hostname();
    (target.eq_ignore_ascii_case(&hostname)
        || target == "."
        || target.eq_ignore_ascii_case("localhost"))
    .then_some(hostname)
    .into_iter()
    .collect()
}

pub(super) fn compatible_dc_list(target: &str) -> Vec<String> {
    let domain = linux_domain_name();
    if domain.is_empty() || !target.eq_ignore_ascii_case(&domain) {
        return Vec::new();
    }
    vec![local_hostname()]
}

pub(super) fn compatible_share_list() -> Vec<ShareEntry> {
    Vec::new()
}

pub(super) fn logged_on_users() -> Vec<String> {
    parse_logged_on_users(&run_who())
}

pub(super) fn logged_on_sessions() -> Vec<SessionEntry> {
    parse_logged_on_sessions(&run_who())
}

fn run_who() -> String {
    match std::process::Command::new("who").output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
        _ => String::new(),
    }
}

pub(super) fn parse_logged_on_users(output: &str) -> Vec<String> {
    let mut users = output
        .lines()
        .filter_map(|line| line.split_whitespace().next().map(str::to_string))
        .collect::<Vec<_>>();
    users.sort();
    users.dedup();
    users
}

pub(super) fn parse_logged_on_sessions(output: &str) -> Vec<SessionEntry> {
    output
        .lines()
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            let user = parts.first()?.to_string();
            let fallback_client = parts.get(1).copied().unwrap_or_default().to_string();
            let client = line
                .rsplit_once('(')
                .and_then(|(_, suffix)| suffix.strip_suffix(')'))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(&fallback_client)
                .to_string();
            Some(SessionEntry { client, user, active: 0, idle: 0 })
        })
        .collect()
}

pub(super) fn enumerate_groups() -> Result<Vec<GroupEntry>, PhantomError> {
    let contents =
        fs::read_to_string("/etc/group").map_err(|error| io_error("/etc/group", error))?;
    Ok(parse_group_entries(&contents))
}

pub(super) fn parse_group_entries(contents: &str) -> Vec<GroupEntry> {
    let mut groups = contents
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?.trim();
            let _password = fields.next()?;
            let gid = fields.next()?.trim();
            let members = fields.next().unwrap_or_default().trim();
            let description = if members.is_empty() {
                format!("gid={gid}")
            } else {
                format!("gid={gid}; members={members}")
            };
            Some(GroupEntry { name: name.to_string(), description })
        })
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| left.name.cmp(&right.name));
    groups
}

pub(super) fn enumerate_users() -> Result<Vec<UserEntry>, PhantomError> {
    let contents =
        fs::read_to_string("/etc/passwd").map_err(|error| io_error("/etc/passwd", error))?;
    Ok(parse_user_entries(&contents))
}

pub(super) fn parse_user_entries(contents: &str) -> Vec<UserEntry> {
    let mut users = contents
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?.trim();
            let _password = fields.next()?;
            let uid = fields.next()?.trim().parse::<u32>().ok()?;
            Some(UserEntry { name: name.to_string(), is_admin: uid == 0 })
        })
        .collect::<Vec<_>>();
    users.sort_by(|left, right| left.name.cmp(&right.name));
    users
}
