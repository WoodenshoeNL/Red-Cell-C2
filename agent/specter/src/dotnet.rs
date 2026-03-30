//! .NET CLR hosting for inline assembly execution.
//!
//! **Status: not yet implemented.**  The protocol framing and callback constants
//! are wired up, but actual CLR hosting (loading an assembly and invoking its
//! entry point) is not implemented on any platform.  All calls to
//! [`dotnet_execute`] return a single [`DOTNET_INFO_FAILED`] callback.
//!
//! Tracking issue: see the beads issue for "Implement CLR hosting in Specter
//! dotnet_execute (COM vtable FFI for ICorRuntimeHost)".

use tracing::warn;

// ─── .NET callback info IDs (agent → server) ───────────────────────────────

/// AMSI/ETW patches have been applied (hardware breakpoint engine).
pub const DOTNET_INFO_PATCHED: u32 = 1;
/// Reports the CLR version string being used.
pub const DOTNET_INFO_NET_VERSION: u32 = 2;
/// Assembly entry point has been invoked; includes the thread ID.
pub const DOTNET_INFO_ENTRYPOINT_EXECUTED: u32 = 3;
/// Assembly execution completed successfully.
pub const DOTNET_INFO_FINISHED: u32 = 4;
/// CLR initialisation or assembly execution failed.
pub const DOTNET_INFO_FAILED: u32 = 5;

/// A single .NET execution callback to send to the teamserver.
#[derive(Debug)]
pub struct DotnetCallback {
    /// One of the `DOTNET_INFO_*` constants.
    pub info_id: u32,
    /// Payload bytes for this callback (info-specific encoding).
    pub payload: Vec<u8>,
}

/// Result of a .NET assembly execution attempt.
#[derive(Debug)]
pub struct DotnetResult {
    /// Callback entries to send back to the teamserver.
    pub callbacks: Vec<DotnetCallback>,
    /// Captured stdout output from the assembly, if any.
    pub output: Vec<u8>,
}

/// Execute a .NET assembly using the CLR.
///
/// **Not yet implemented** — returns [`DOTNET_INFO_FAILED`] on all platforms.
///
/// Full CLR hosting requires COM interop via `CLRCreateInstance` →
/// `ICorRuntimeHost` → `Load_3` → `EntryPoint` → `Invoke_3`.  That FFI work
/// is tracked in a separate issue; until it lands this function is a
/// well-labelled stub.
///
/// # Arguments
///
/// * `_pipe_name` — Named pipe path for stdout capture (UTF-16LE decoded).
/// * `_app_domain` — AppDomain name (UTF-16LE decoded).
/// * `_net_version` — Target CLR version string (e.g. `"v4.0.30319"`).
/// * `_assembly_data` — Raw .NET PE bytes.
/// * `_assembly_args` — Command-line arguments for the assembly (UTF-16LE decoded).
#[cfg(windows)]
pub fn dotnet_execute(
    _pipe_name: &str,
    _app_domain: &str,
    _net_version: &str,
    _assembly_data: &[u8],
    _assembly_args: &str,
) -> DotnetResult {
    warn!("dotnet_execute: CLR hosting is not yet implemented — returning failure");
    DotnetResult {
        callbacks: vec![DotnetCallback { info_id: DOTNET_INFO_FAILED, payload: Vec::new() }],
        output: Vec::new(),
    }
}

/// On non-Windows targets, .NET assembly execution is unsupported.
#[cfg(not(windows))]
pub fn dotnet_execute(
    _pipe_name: &str,
    _app_domain: &str,
    _net_version: &str,
    _assembly_data: &[u8],
    _assembly_args: &str,
) -> DotnetResult {
    warn!(".NET assembly execution is only supported on Windows");
    DotnetResult {
        callbacks: vec![DotnetCallback { info_id: DOTNET_INFO_FAILED, payload: Vec::new() }],
        output: Vec::new(),
    }
}

/// Enumerate installed CLR versions.
///
/// On Windows, attempts to load `mscoree.dll` and use `CLRCreateInstance` to
/// enumerate available runtimes.  Returns version strings (e.g. `"v4.0.30319"`).
///
/// On non-Windows, returns an empty list.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn enumerate_clr_versions() -> Vec<String> {
    // CLR version enumeration requires COM interop:
    //   1. CLRCreateInstance → ICLRMetaHost
    //   2. EnumerateInstalledRuntimes → IEnumUnknown
    //   3. For each: QueryInterface → ICLRRuntimeInfo
    //   4. GetVersionString → version string
    //
    // As a pragmatic fallback, we check well-known registry keys that indicate
    // installed .NET Framework versions.

    let mut versions = Vec::new();

    // Check for .NET Framework 4.x via registry
    // HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full
    let subkey = b"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\0";
    let mut hkey: isize = 0;

    // SAFETY: calling RegOpenKeyExA to read registry
    let status = unsafe {
        windows_sys::Win32::System::Registry::RegOpenKeyExA(
            windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_READ,
            &mut hkey,
        )
    };

    if status == 0 {
        // Key exists — .NET 4.x is installed
        let value_name = b"Version\0";
        let mut buf = [0u8; 256];
        let mut buf_len: u32 = buf.len() as u32;
        let mut value_type: u32 = 0;

        let read_status = unsafe {
            windows_sys::Win32::System::Registry::RegQueryValueExA(
                hkey,
                value_name.as_ptr(),
                std::ptr::null(),
                &mut value_type,
                buf.as_mut_ptr(),
                &mut buf_len,
            )
        };

        if read_status == 0 && buf_len > 0 {
            let end = buf_len as usize;
            let version_str = String::from_utf8_lossy(
                &buf[..end.saturating_sub(1)], // strip null terminator
            )
            .to_string();
            if !version_str.is_empty() {
                versions.push(format!("v{version_str}"));
            }
        }

        unsafe {
            windows_sys::Win32::System::Registry::RegCloseKey(hkey);
        }
    }

    // Check for .NET 3.5
    let subkey_35 = b"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v3.5\0";
    let mut hkey_35: isize = 0;
    let status_35 = unsafe {
        windows_sys::Win32::System::Registry::RegOpenKeyExA(
            windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            subkey_35.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_READ,
            &mut hkey_35,
        )
    };
    if status_35 == 0 {
        versions.push("v3.5".to_string());
        unsafe {
            windows_sys::Win32::System::Registry::RegCloseKey(hkey_35);
        }
    }

    // Check for .NET 2.0
    let subkey_20 = b"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727\0";
    let mut hkey_20: isize = 0;
    let status_20 = unsafe {
        windows_sys::Win32::System::Registry::RegOpenKeyExA(
            windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            subkey_20.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_READ,
            &mut hkey_20,
        )
    };
    if status_20 == 0 {
        versions.push("v2.0.50727".to_string());
        unsafe {
            windows_sys::Win32::System::Registry::RegCloseKey(hkey_20);
        }
    }

    versions
}

/// On non-Windows, no CLR versions are available.
#[cfg(not(windows))]
pub fn enumerate_clr_versions() -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both Windows and non-Windows stubs return exactly one FAILED callback.
    #[test]
    fn dotnet_execute_always_returns_single_failed_callback() {
        for assembly in [b"".as_ref(), b"MZ\x90\x00".as_ref()] {
            let result = dotnet_execute("pipe", "domain", "v4.0.30319", assembly, "");
            assert_eq!(result.callbacks.len(), 1, "expected single callback for {:?}", assembly);
            assert_eq!(result.callbacks[0].info_id, DOTNET_INFO_FAILED);
            assert!(result.output.is_empty());
        }
    }

    /// On non-Windows the stub immediately returns a single FAILED callback.
    #[cfg(not(windows))]
    #[test]
    fn non_windows_dotnet_returns_failed() {
        let result = dotnet_execute("pipe", "domain", "v4.0.30319", b"MZ\x90\x00", "args");
        assert_eq!(result.callbacks.len(), 1);
        assert_eq!(result.callbacks[0].info_id, DOTNET_INFO_FAILED);
    }

    /// On Windows the stub also returns a single FAILED callback regardless of
    /// assembly content — CLR hosting is not yet implemented.
    #[cfg(windows)]
    #[test]
    fn windows_dotnet_non_empty_assembly_returns_failed() {
        let result = dotnet_execute("pipe", "domain", "v4.0.30319", b"MZ\x90\x00", "args");
        assert_eq!(result.callbacks.len(), 1);
        assert_eq!(result.callbacks[0].info_id, DOTNET_INFO_FAILED);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_enumerate_returns_empty() {
        assert!(enumerate_clr_versions().is_empty());
    }

    #[test]
    fn dotnet_info_constants_match_teamserver() {
        assert_eq!(DOTNET_INFO_PATCHED, 1);
        assert_eq!(DOTNET_INFO_NET_VERSION, 2);
        assert_eq!(DOTNET_INFO_ENTRYPOINT_EXECUTED, 3);
        assert_eq!(DOTNET_INFO_FINISHED, 4);
        assert_eq!(DOTNET_INFO_FAILED, 5);
    }
}
