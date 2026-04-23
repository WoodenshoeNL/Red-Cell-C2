//! ptrace attach/detach helpers and `/proc/<pid>/mem` read-write utilities.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ptr;

/// Check whether ptrace is permitted on this system.
///
/// Reads `/proc/sys/kernel/yama/ptrace_scope` and returns `true` if injection
/// is feasible:
///   - 0 (classic): any process can ptrace any other (same UID)
///   - 1 (restricted): only descendants, but we can still attach if we are root
///     or the target called `prctl(PR_SET_PTRACER, ...)`
///   - 2 (admin-only): only CAP_SYS_PTRACE holders
///   - 3 (disabled): ptrace completely disabled
///
/// We check our effective UID and capabilities to decide. If Yama is not
/// present (file missing), we assume classic mode (allowed).
pub(super) fn check_ptrace_permission(target_pid: u32) -> bool {
    // Check Yama ptrace_scope.
    let scope = match fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(s) => s.trim().parse::<u32>().unwrap_or(0),
        Err(_) => 0, // No Yama — classic mode.
    };

    let euid = unsafe { libc::geteuid() };
    let is_root = euid == 0;

    match scope {
        0 => true, // Classic — allowed for same UID.
        1 => {
            // Restricted. Root can always attach. Non-root can attach to
            // descendants or prctl-opted targets. We attempt it and let
            // PTRACE_ATTACH fail if not permitted rather than blocking
            // outright, but warn.
            if !is_root {
                tracing::debug!(
                    target_pid,
                    "yama ptrace_scope=1: ptrace restricted to descendants; \
                     injection may fail if target is not a descendant"
                );
            }
            true
        }
        2 => {
            // Admin-only. Check if we have CAP_SYS_PTRACE.
            if is_root {
                true
            } else {
                // Check effective capabilities for CAP_SYS_PTRACE (bit 19).
                match fs::read_to_string("/proc/self/status") {
                    Ok(status) => {
                        for line in status.lines() {
                            if let Some(hex) = line.strip_prefix("CapEff:\t") {
                                if let Ok(caps) = u64::from_str_radix(hex.trim(), 16) {
                                    // CAP_SYS_PTRACE = bit 19
                                    return caps & (1 << 19) != 0;
                                }
                            }
                        }
                        false
                    }
                    Err(_) => false,
                }
            }
        }
        3 => {
            tracing::warn!("yama ptrace_scope=3: ptrace is completely disabled");
            false
        }
        _ => {
            tracing::warn!(scope, "unknown yama ptrace_scope value");
            false
        }
    }
}

/// Write data to a target process's memory via `/proc/<pid>/mem`.
pub(super) fn write_to_proc_mem(pid: u32, addr: u64, data: &[u8]) -> std::io::Result<()> {
    let mem_path = format!("/proc/{pid}/mem");
    let mut file = fs::OpenOptions::new().write(true).open(mem_path)?;
    file.seek(SeekFrom::Start(addr))?;
    file.write_all(data)?;
    Ok(())
}

/// Read data from a target process's memory via `/proc/<pid>/mem`.
pub(super) fn read_from_proc_mem(pid: u32, addr: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mem_path = format!("/proc/{pid}/mem");
    let mut file = fs::OpenOptions::new().read(true).open(mem_path)?;
    file.seek(SeekFrom::Start(addr))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// Wait for a tracee to stop with `SIGTRAP`, forwarding any intervening signals.
///
/// After `PTRACE_CONT`, the tracee may receive unrelated signals (e.g. `SIGALRM`,
/// `SIGCHLD`) before reaching the `int3` instruction.  Those signals are re-delivered
/// with another `PTRACE_CONT` so they are not silently dropped.
///
/// Returns `true` when the tracee stops with `SIGTRAP`; `false` if the process exits,
/// is killed, or `waitpid` fails.
pub(super) fn wait_for_sigtrap(pid: i32) -> bool {
    loop {
        let mut status: i32 = 0;
        // SAFETY: valid pid, tracee is running under ptrace.
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret < 0 {
            return false;
        }
        if libc::WIFSTOPPED(status) {
            let sig = libc::WSTOPSIG(status);
            if sig == libc::SIGTRAP {
                return true;
            }
            // Forward the pending signal and continue waiting.
            // SAFETY: valid pid, tracee is stopped under ptrace.
            unsafe {
                libc::ptrace(
                    libc::PTRACE_CONT,
                    pid,
                    ptr::null_mut::<libc::c_void>(),
                    sig as usize as *mut libc::c_void,
                )
            };
        } else {
            // Process exited or was killed before reaching int3.
            return false;
        }
    }
}

/// Allocate an anonymous RWX page in a stopped tracee by executing a
/// `mmap(NULL, 4096, PROT_RWX, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` syscall
/// stub at the current RIP, then restoring the original bytes.
///
/// Returns the base address of the mapped page, or `None` on failure.
/// The tracee must already be stopped (PTRACE_ATTACH + waitpid done).
pub(super) fn ptrace_mmap_page(pid: u32, regs: &libc::user_regs_struct) -> Option<u64> {
    let pid_i32 = pid as i32;
    let rip = regs.rip;

    // Build x86_64 syscall stub for mmap:
    //   mov rax, 9          ; __NR_mmap
    //   xor rdi, rdi        ; addr = NULL
    //   mov rsi, 0x1000     ; len = 4096
    //   mov rdx, 7          ; prot = PROT_READ|PROT_WRITE|PROT_EXEC
    //   mov r10, 0x22       ; flags = MAP_PRIVATE|MAP_ANONYMOUS
    //   mov r8, -1 (0xFFFFFFFFFFFFFFFF) ; fd = -1
    //   xor r9, r9          ; offset = 0
    //   syscall
    //   int3                ; trap back to us
    let mut stub: Vec<u8> = Vec::new();
    // mov rax, 9
    stub.extend_from_slice(&[0x48, 0xc7, 0xc0, 0x09, 0x00, 0x00, 0x00]);
    // xor rdi, rdi
    stub.extend_from_slice(&[0x48, 0x31, 0xff]);
    // mov rsi, 0x1000
    stub.extend_from_slice(&[0x48, 0xc7, 0xc6, 0x00, 0x10, 0x00, 0x00]);
    // mov rdx, 7
    stub.extend_from_slice(&[0x48, 0xc7, 0xc2, 0x07, 0x00, 0x00, 0x00]);
    // mov r10, 0x22
    stub.extend_from_slice(&[0x49, 0xc7, 0xc2, 0x22, 0x00, 0x00, 0x00]);
    // mov r8, -1
    stub.extend_from_slice(&[0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff]);
    // xor r9, r9
    stub.extend_from_slice(&[0x4d, 0x31, 0xc9]);
    // syscall
    stub.extend_from_slice(&[0x0f, 0x05]);
    // int3
    stub.push(0xcc);

    let stub_len = stub.len();

    // Save original bytes at RIP.
    let orig_bytes = match read_from_proc_mem(pid, rip, stub_len) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, %e, "failed to read original bytes at RIP for mmap stub");
            return None;
        }
    };

    // Write the mmap stub at RIP.
    if let Err(e) = write_to_proc_mem(pid, rip, &stub) {
        tracing::warn!(pid, %e, "failed to write mmap stub at RIP");
        return None;
    }

    // Execute: PTRACE_CONT, wait for SIGTRAP from int3.
    // SAFETY: valid pid, tracee is stopped.
    unsafe { libc::ptrace(libc::PTRACE_CONT, pid_i32, 0, 0) };
    if !wait_for_sigtrap(pid_i32) {
        tracing::warn!(pid, "tracee did not reach SIGTRAP after mmap stub (exited or killed)");
        let _ = write_to_proc_mem(pid, rip, &orig_bytes);
        return None;
    }

    // Read RAX — the mmap return value.
    let mut post_regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid_i32,
            0,
            &mut post_regs as *mut libc::user_regs_struct,
        )
    };
    if ret < 0 {
        tracing::warn!(pid, "GETREGS after mmap stub failed");
        // Restore original bytes best-effort.
        let _ = write_to_proc_mem(pid, rip, &orig_bytes);
        return None;
    }

    let page_addr = post_regs.rax;

    // MAP_FAILED = (void *)-1 = 0xFFFFFFFFFFFFFFFF
    if page_addr == u64::MAX {
        tracing::warn!(pid, "mmap syscall in target returned MAP_FAILED");
        let _ = write_to_proc_mem(pid, rip, &orig_bytes);
        return None;
    }

    // Restore original bytes at RIP.
    if let Err(e) = write_to_proc_mem(pid, rip, &orig_bytes) {
        tracing::warn!(pid, %e, "failed to restore original bytes after mmap stub");
        // The page is allocated but we can't clean up — proceed anyway.
    }

    // Restore original register state (RIP, etc.).
    // SAFETY: valid pid, regs struct.
    unsafe {
        libc::ptrace(libc::PTRACE_SETREGS, pid_i32, 0, regs as *const libc::user_regs_struct);
    }

    Some(page_addr)
}

/// Deallocate a page previously allocated with `ptrace_mmap_page` by executing
/// a `munmap` syscall stub in the tracee. Best-effort — failure is logged but
/// not fatal.
pub(super) fn ptrace_munmap_page(pid: u32, regs: &libc::user_regs_struct, page_addr: u64) {
    let pid_i32 = pid as i32;
    let rip = regs.rip;

    // Build x86_64 syscall stub for munmap(page_addr, 4096):
    //   mov rax, 11         ; __NR_munmap
    //   movabs rdi, page_addr
    //   mov rsi, 0x1000     ; len = 4096
    //   syscall
    //   int3
    let mut stub: Vec<u8> = Vec::new();
    // mov rax, 11
    stub.extend_from_slice(&[0x48, 0xc7, 0xc0, 0x0b, 0x00, 0x00, 0x00]);
    // movabs rdi, page_addr
    stub.extend_from_slice(&[0x48, 0xbf]);
    stub.extend_from_slice(&page_addr.to_le_bytes());
    // mov rsi, 0x1000
    stub.extend_from_slice(&[0x48, 0xc7, 0xc6, 0x00, 0x10, 0x00, 0x00]);
    // syscall
    stub.extend_from_slice(&[0x0f, 0x05]);
    // int3
    stub.push(0xcc);

    let stub_len = stub.len();

    // Save original bytes at RIP.
    let orig_bytes = match read_from_proc_mem(pid, rip, stub_len) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, %e, "failed to read bytes for munmap stub");
            return;
        }
    };

    if let Err(e) = write_to_proc_mem(pid, rip, &stub) {
        tracing::warn!(pid, %e, "failed to write munmap stub");
        return;
    }

    // SAFETY: valid pid, tracee is stopped.
    unsafe { libc::ptrace(libc::PTRACE_CONT, pid_i32, 0, 0) };
    if !wait_for_sigtrap(pid_i32) {
        tracing::warn!(pid, "tracee did not reach SIGTRAP after munmap stub (exited or killed)");
        // Best-effort: try to restore original bytes even though the stub may not have completed.
        let _ = write_to_proc_mem(pid, rip, &orig_bytes);
        return;
    }

    // Restore original bytes and registers.
    let _ = write_to_proc_mem(pid, rip, &orig_bytes);
    unsafe {
        libc::ptrace(libc::PTRACE_SETREGS, pid_i32, 0, regs as *const libc::user_regs_struct);
    }
}
