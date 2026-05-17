//! Windows-specific network enumeration via Win32 Net* APIs.

#![cfg(windows)]
#![allow(unsafe_code)]

use tracing::warn;

use super::types::{NetGroup, NetSession, NetShare, NetUser};

/// Decode a null-terminated UTF-16 string from a raw pointer.
///
/// SAFETY: `ptr` must be null or point to a valid null-terminated UTF-16 string.
pub(super) unsafe fn wstr_to_string(ptr: *const u16) -> String {
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
pub(super) fn platform_domain_name() -> String {
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

/// Enumerate currently logged-on users via `NetWkstaUserEnum`.
pub(super) fn platform_logged_on_users() -> Vec<String> {
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

/// Enumerate active login sessions via `NetSessionEnum`.
pub(super) fn platform_sessions() -> Vec<NetSession> {
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

/// Enumerate network shares via `NetShareEnum`.
///
/// Attempts level 2 (`SHARE_INFO_2`, admin-only) to obtain path and permissions.
/// On the first `ERROR_ACCESS_DENIED` at level 2, resets and retries at level 1
/// (`SHARE_INFO_1`), leaving `path` empty and `permissions` zero.
pub(super) fn platform_shares() -> Vec<NetShare> {
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

/// Enumerate local groups via `NetLocalGroupEnum`.
pub(super) fn platform_groups() -> Vec<NetGroup> {
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

/// Resolve the localized name of the built-in Users group (S-1-5-32-545) as a
/// NUL-terminated UTF-16 string.
pub(super) fn builtin_users_name_w() -> Option<Vec<u16>> {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, LookupAccountSidW, SID_NAME_USE, WinBuiltinUsersSid,
    };

    let mut sid_size: u32 = 0;
    // SAFETY: pSid is NULL intentionally; Windows fills cbSid with the required size on first call.
    unsafe {
        CreateWellKnownSid(
            WinBuiltinUsersSid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sid_size,
        );
    }
    if sid_size == 0 {
        return None;
    }

    let mut sid_buf = vec![0u8; sid_size as usize];
    // SAFETY: sid_buf is correctly sized per first call; pDomainSid is NULL for well-known SIDs.
    let ok = unsafe {
        CreateWellKnownSid(
            WinBuiltinUsersSid,
            std::ptr::null_mut(),
            sid_buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut sid_size,
        )
    };
    if ok == FALSE {
        return None;
    }

    let sid_ptr = sid_buf.as_ptr() as *mut core::ffi::c_void;
    let mut name_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut sid_type: SID_NAME_USE = 0;
    // SAFETY: both name and domain buffers are NULL intentionally; Windows fills the length fields.
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

    let mut name_buf = vec![0u16; name_len as usize];
    let mut domain_buf = vec![0u16; domain_len.max(1) as usize];
    // SAFETY: name_buf and domain_buf are correctly sized; sid_ptr remains valid for the lifetime of sid_buf.
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
    Some(name_buf)
}

/// Resolve the localized name of the built-in Administrators group (S-1-5-32-544) as a
/// NUL-terminated UTF-16 string suitable for passing to `NetLocalGroupGetMembers`.
pub(super) fn builtin_administrators_name_w() -> Option<Vec<u16>> {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, LookupAccountSidW, SID_NAME_USE, WinBuiltinAdministratorsSid,
    };

    // Phase 1: query the byte size required for the Administrators SID.
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
    Some(name_buf)
}

/// Collect the lowercase usernames of every member of the built-in local Administrators group.
pub(super) fn administrators_group_members() -> std::collections::HashSet<String> {
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
pub(super) fn platform_users() -> Vec<NetUser> {
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

/// Shared helper: call `NetServerEnum` with the given `server_type` mask
/// against `domain` and return the list of server names.
pub(super) fn platform_servers_by_type(domain: &str, server_type: u32) -> Vec<String> {
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

pub(super) fn platform_computers(domain: &str) -> Vec<String> {
    platform_servers_by_type(
        domain,
        windows_sys::Win32::NetworkManagement::NetManagement::SV_TYPE_ALL,
    )
}

pub(super) fn platform_dc_list(domain: &str) -> Vec<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        SV_TYPE_DOMAIN_BAKCTRL, SV_TYPE_DOMAIN_CTRL,
    };
    platform_servers_by_type(domain, SV_TYPE_DOMAIN_CTRL | SV_TYPE_DOMAIN_BAKCTRL)
}
