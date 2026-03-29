//! Platform-specific implementations for Specter.
//!
//! Provides OS metadata collection via native APIs on Windows and stub
//! implementations on other platforms (used during cross-compile testing).

// ─── Windows ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::mem;

    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsHostname, GetComputerNameExW, RTL_OSVERSIONINFOEXW, RtlGetVersion,
    };

    /// Query the OS version via `RtlGetVersion` (kernel-level, not spoofable by
    /// compatibility shims unlike `GetVersionEx`).
    ///
    /// Returns `(major, minor, build)`.
    pub fn os_version() -> (u32, u32, u32) {
        // SAFETY: OSVERSIONINFOEXW is a plain C struct; zeroing is safe and required by the API.
        let mut info: RTL_OSVERSIONINFOEXW = unsafe { mem::zeroed() };
        info.dwOSVersionInfoSize = mem::size_of::<RTL_OSVERSIONINFOEXW>() as u32;
        // SAFETY: RtlGetVersion always succeeds for this struct size on Windows 2000+.
        unsafe {
            RtlGetVersion(&mut info as *mut RTL_OSVERSIONINFOEXW as *mut _);
        }
        (info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber)
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
}

// ─── Non-Windows (Linux / macOS — used during cross-compile test builds) ─────

#[cfg(not(windows))]
mod imp {
    /// OS version placeholder for non-Windows builds.
    pub fn os_version() -> (u32, u32, u32) {
        (0, 0, 0)
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
}

// ─── Public re-exports ────────────────────────────────────────────────────────

pub use imp::{hostname, os_version, username};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_version_returns_plausible_triple() {
        let (major, _minor, _build) = os_version();
        // On Windows the major version must be >= 10; on Linux/macOS it will be 0.
        if cfg!(windows) {
            assert!(major >= 10, "expected Windows 10+, got major={major}");
        } else {
            // Stub returns (0, 0, 0) on non-Windows.
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
}
