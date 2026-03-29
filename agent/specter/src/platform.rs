//! Platform-specific implementations for Specter.
//!
//! Provides OS metadata collection via native APIs on Windows and stub
//! implementations on other platforms (used during cross-compile testing).

// ─── Windows ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::mem;

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, OpenProcessToken, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsDomain, ComputerNameDnsHostname, GetComputerNameExW, RTL_OSVERSIONINFOEXW,
        RtlGetVersion,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId,
    };

    /// Query the OS version via `RtlGetVersion` (kernel-level, not spoofable by
    /// compatibility shims unlike `GetVersionEx`).
    ///
    /// Returns `(major, minor, build, service_pack_major)`.
    pub fn os_version() -> (u32, u32, u32, u16) {
        // SAFETY: OSVERSIONINFOEXW is a plain C struct; zeroing is safe and required by the API.
        let mut info: RTL_OSVERSIONINFOEXW = unsafe { mem::zeroed() };
        info.dwOSVersionInfoSize = mem::size_of::<RTL_OSVERSIONINFOEXW>() as u32;
        // SAFETY: RtlGetVersion always succeeds for this struct size on Windows 2000+.
        unsafe {
            RtlGetVersion(&mut info as *mut RTL_OSVERSIONINFOEXW as *mut _);
        }
        (info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber, info.wServicePackMajor)
    }

    /// Query the DNS hostname via `GetComputerNameExW`.
    ///
    /// Falls back to the `COMPUTERNAME` environment variable on API failure.
    pub fn hostname() -> String {
        let mut size: u32 = 256;
        let mut buf = vec![0u16; size as usize];
        // SAFETY: buf is allocated above with `size` elements; pointers are valid for the call.
        let ok =
            unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut size) };
        if ok != 0 && size > 0 {
            String::from_utf16_lossy(&buf[..size as usize])
        } else {
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| String::from("unknown"))
        }
    }

    /// Return the username from the `USERNAME` environment variable.
    ///
    /// `GetUserNameW` lives in `Secur32.lib`/`Advapi32.lib` which requires extra
    /// link flags; env var is equivalent for a scaffold.
    pub fn username() -> String {
        std::env::var("USERNAME").unwrap_or_else(|_| String::from("unknown"))
    }

    /// Return the DNS domain name of the machine, or `"WORKGROUP"` if not
    /// joined to a domain.
    ///
    /// Uses `GetComputerNameExW(ComputerNameDnsDomain)` which returns an empty
    /// string for workgroup-only machines.
    pub fn domain_name() -> String {
        let mut size: u32 = 256;
        let mut buf = vec![0u16; size as usize];
        // SAFETY: buf is allocated with `size` elements; pointers are valid for the call.
        let ok = unsafe { GetComputerNameExW(ComputerNameDnsDomain, buf.as_mut_ptr(), &mut size) };
        if ok != 0 && size > 0 {
            String::from_utf16_lossy(&buf[..size as usize])
        } else {
            String::from("WORKGROUP")
        }
    }

    /// Return the thread ID of the calling thread via `GetCurrentThreadId`.
    pub fn process_tid() -> u32 {
        // SAFETY: GetCurrentThreadId has no preconditions and always succeeds.
        unsafe { GetCurrentThreadId() }
    }

    /// Return the parent process ID of the current process.
    ///
    /// Enumerates the process list via `CreateToolhelp32Snapshot` and finds the
    /// entry whose PID matches the current process, returning its parent PID.
    /// Returns 0 on any failure.
    pub fn process_ppid() -> u32 {
        // SAFETY: CreateToolhelp32Snapshot, Process32FirstW/NextW, and CloseHandle
        // are safe to call with the arguments provided; the PROCESSENTRY32W struct
        // is zeroed before use as required by the API contract.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return 0;
            }

            let current_pid = GetCurrentProcessId();
            let mut entry: PROCESSENTRY32W = mem::zeroed();
            entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

            let mut ppid = 0u32;
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    if entry.th32ProcessID == current_pid {
                        ppid = entry.th32ParentProcessID;
                        break;
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);
            ppid
        }
    }

    /// Return whether the current process token carries elevated privileges.
    ///
    /// Opens the current process token and queries `TokenElevation`. Returns
    /// `false` on any API failure.
    pub fn is_elevated() -> bool {
        // SAFETY: GetCurrentProcess returns a pseudo-handle that does not need
        // to be closed. OpenProcessToken and GetTokenInformation are called with
        // correctly sized structs; the token handle is closed before return.
        unsafe {
            let mut token = 0isize;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }

            let mut elevation: TOKEN_ELEVATION = mem::zeroed();
            let mut ret_len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut TOKEN_ELEVATION as *mut _,
                mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    /// Return the base address of the current process image.
    ///
    /// Calls `GetModuleHandleW(NULL)` which returns the `HMODULE` (load address)
    /// of the main executable without incrementing its reference count.
    pub fn base_address() -> u64 {
        // SAFETY: Passing null to GetModuleHandleW is documented to return the
        // base address of the calling process's main module. The returned handle
        // must not be passed to FreeLibrary.
        let handle = unsafe { GetModuleHandleW(std::ptr::null()) };
        handle as u64
    }
}

// ─── Non-Windows (Linux / macOS — used during cross-compile test builds) ─────

#[cfg(not(windows))]
mod imp {
    /// OS version placeholder for non-Windows builds.
    pub fn os_version() -> (u32, u32, u32, u16) {
        (0, 0, 0, 0)
    }

    /// Hostname from environment (Linux: `HOSTNAME`, Windows: `COMPUTERNAME`).
    pub fn hostname() -> String {
        std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| String::from("unknown"))
    }

    /// Username from environment (Linux: `USER`, Windows: `USERNAME`).
    pub fn username() -> String {
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| String::from("unknown"))
    }

    /// Domain name stub for non-Windows builds.
    pub fn domain_name() -> String {
        String::from("WORKGROUP")
    }

    /// Thread ID stub for non-Windows builds.
    pub fn process_tid() -> u32 {
        0
    }

    /// Parent process ID stub for non-Windows builds.
    pub fn process_ppid() -> u32 {
        0
    }

    /// Elevation stub for non-Windows builds.
    pub fn is_elevated() -> bool {
        false
    }

    /// Base address stub for non-Windows builds.
    pub fn base_address() -> u64 {
        0
    }
}

// ─── Shared (platform-agnostic) ──────────────────────────────────────────────

/// Return a non-loopback local IPv4 address as a dotted-decimal string.
///
/// Uses a UDP "connect without send" trick: binding to the wildcard address
/// and connecting to a routable destination causes the OS to select the
/// outbound interface via the routing table.  Reading back `local_addr()`
/// reveals the actual source address without transmitting any data.
///
/// Falls back to `"0.0.0.0"` if no suitable interface is found.
pub fn local_ip() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| String::from("0.0.0.0"))
}

// ─── Public re-exports ────────────────────────────────────────────────────────

pub use imp::{
    base_address, domain_name, hostname, is_elevated, os_version, process_ppid, process_tid,
    username,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_version_returns_plausible_values() {
        let (major, _minor, _build, _sp) = os_version();
        // On Windows the major version must be >= 10; on Linux/macOS it will be 0.
        if cfg!(windows) {
            assert!(major >= 10, "expected Windows 10+, got major={major}");
        } else {
            // Stub returns (0, 0, 0, 0) on non-Windows.
            assert_eq!(major, 0);
        }
    }

    #[test]
    fn hostname_returns_non_empty_string() {
        // The host running tests must have a resolvable hostname.
        let name = hostname();
        assert!(!name.is_empty(), "hostname must not be empty");
    }

    #[test]
    fn username_returns_non_empty_string() {
        let name = username();
        assert!(!name.is_empty(), "username must not be empty");
    }

    #[test]
    fn domain_name_returns_non_empty_string() {
        // On Windows: either a real domain or "WORKGROUP".
        // On non-Windows stubs: "WORKGROUP".
        let name = domain_name();
        assert!(!name.is_empty(), "domain_name must not be empty");
    }

    #[test]
    fn process_tid_is_nonzero_on_windows() {
        if cfg!(windows) {
            assert_ne!(process_tid(), 0, "TID must be non-zero on Windows");
        } else {
            // Stub returns 0.
            assert_eq!(process_tid(), 0);
        }
    }

    #[test]
    fn process_ppid_is_nonzero_on_windows() {
        if cfg!(windows) {
            // Every process except PID 0 and 4 (System) has a parent.
            assert_ne!(process_ppid(), 0, "PPID must be non-zero on Windows");
        } else {
            assert_eq!(process_ppid(), 0);
        }
    }

    #[test]
    fn base_address_is_nonzero_on_windows() {
        if cfg!(windows) {
            assert_ne!(base_address(), 0, "base address must be non-zero on Windows");
        } else {
            assert_eq!(base_address(), 0);
        }
    }

    #[test]
    fn local_ip_returns_valid_dotted_decimal() {
        let ip = local_ip();
        // Must be parseable as a valid IPv4 or IPv6 address.
        let parsed = ip.parse::<std::net::IpAddr>();
        assert!(parsed.is_ok(), "local_ip '{ip}' is not a valid IP address");
    }

    #[test]
    fn local_ip_is_not_loopback() {
        let ip = local_ip();
        // On hosts with real network interfaces the routing table should select
        // a non-loopback address.  "0.0.0.0" is acceptable when no interface
        // is available (e.g. a sandboxed CI environment without network).
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            assert!(
                !addr.is_loopback() || ip == "0.0.0.0",
                "local_ip returned loopback address {ip}"
            );
        }
    }
}
