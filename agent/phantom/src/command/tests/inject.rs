use super::*;

/// Helper to build a `CommandInjectShellcode` task payload.
fn build_inject_shellcode_payload(
    way: i32,
    technique: i32,
    x64: i32,
    shellcode: &[u8],
    argument: &[u8],
    pid: i32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&way.to_le_bytes());
    payload.extend_from_slice(&technique.to_le_bytes());
    payload.extend_from_slice(&x64.to_le_bytes());
    // shellcode as length-prefixed bytes
    payload.extend_from_slice(&(shellcode.len() as i32).to_le_bytes());
    payload.extend_from_slice(shellcode);
    // argument as length-prefixed bytes
    payload.extend_from_slice(&(argument.len() as i32).to_le_bytes());
    payload.extend_from_slice(argument);
    // pid
    payload.extend_from_slice(&pid.to_le_bytes());
    payload
}

/// Helper to build a `CommandInjectDll` task payload.
fn build_inject_dll_payload(
    technique: i32,
    pid: i32,
    dll_ldr: &[u8],
    dll_bytes: &[u8],
    parameter: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&technique.to_le_bytes());
    payload.extend_from_slice(&pid.to_le_bytes());
    payload.extend_from_slice(&(dll_ldr.len() as i32).to_le_bytes());
    payload.extend_from_slice(dll_ldr);
    payload.extend_from_slice(&(dll_bytes.len() as i32).to_le_bytes());
    payload.extend_from_slice(dll_bytes);
    payload.extend_from_slice(&(parameter.len() as i32).to_le_bytes());
    payload.extend_from_slice(parameter);
    payload
}

/// Helper to build a `CommandSpawnDll` task payload.
fn build_spawn_dll_payload(dll_ldr: &[u8], dll_bytes: &[u8], arguments: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(dll_ldr.len() as i32).to_le_bytes());
    payload.extend_from_slice(dll_ldr);
    payload.extend_from_slice(&(dll_bytes.len() as i32).to_le_bytes());
    payload.extend_from_slice(dll_bytes);
    payload.extend_from_slice(&(arguments.len() as i32).to_le_bytes());
    payload.extend_from_slice(arguments);
    payload
}

/// `CommandInjectShellcode` with an invalid PID produces a failure
/// response with status != 0 and the correct command ID.
#[tokio::test]
async fn inject_shellcode_invalid_pid_returns_failure() {
    let shellcode = b"\xcc"; // int3
    let payload = build_inject_shellcode_payload(
        INJECT_WAY_INJECT,
        0, // technique
        1, // x64
        shellcode,
        &[],
        999_999_999, // non-existent PID
    );
    let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 0x10, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { command_id, request_id, payload } = &callbacks[0] else {
        panic!("expected Structured callback, got: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandInjectShellcode));
    assert_eq!(*request_id, 0x10);
    // Status should be non-zero (failure).
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_ne!(status, 0, "injection into non-existent PID must fail");
}

/// `CommandInjectShellcode` with empty shellcode produces a failure response.
#[tokio::test]
async fn inject_shellcode_empty_payload_returns_failure() {
    let payload = build_inject_shellcode_payload(
        INJECT_WAY_EXECUTE,
        0,
        1,
        &[], // empty shellcode
        &[],
        0,
    );
    let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 0x20, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback");
    };
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_eq!(status, INJECT_ERROR_FAILED);
}

/// `CommandInjectShellcode` with unknown injection way returns failure.
#[tokio::test]
async fn inject_shellcode_unknown_way_returns_failure() {
    let payload = build_inject_shellcode_payload(
        99, // unknown way
        0,
        1,
        b"\x90", // NOP
        &[],
        0,
    );
    let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 0x30, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback");
    };
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_eq!(status, INJECT_ERROR_FAILED);
}

/// `CommandInjectDll` with a non-existent PID produces a failure response.
#[tokio::test]
async fn inject_dll_invalid_pid_returns_failure() {
    let dll_bytes = b"\x7fELF_fake_so"; // not a real .so but exercises the path
    let payload = build_inject_dll_payload(
        0,           // technique
        999_999_999, // non-existent PID
        &[],         // dll_ldr (ignored on Linux)
        dll_bytes,
        &[], // parameter
    );
    let package = DemonPackage::new(DemonCommand::CommandInjectDll, 0x40, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { command_id, payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandInjectDll));
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_ne!(status, 0, "injection into non-existent PID must fail");
}

/// `CommandInjectDll` with empty .so bytes produces a failure response.
#[tokio::test]
async fn inject_dll_empty_payload_returns_failure() {
    let payload = build_inject_dll_payload(0, 1, &[], &[], &[]);
    let package = DemonPackage::new(DemonCommand::CommandInjectDll, 0x50, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback");
    };
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_eq!(status, INJECT_ERROR_FAILED);
}

/// `CommandSpawnDll` with empty .so bytes produces a failure response.
#[tokio::test]
async fn spawn_dll_empty_payload_returns_failure() {
    let payload = build_spawn_dll_payload(&[], &[], &[]);
    let package = DemonPackage::new(DemonCommand::CommandSpawnDll, 0x60, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { command_id, payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandSpawnDll));
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_eq!(status, INJECT_ERROR_FAILED);
}

/// Verify that all three injection response payloads are exactly 4 bytes
/// (a single u32 status), matching the Demon protocol.
#[tokio::test]
async fn injection_response_payload_is_4_bytes() {
    let mut state = PhantomState::default();

    // Inject shellcode with empty payload (will fail, but response format is what matters).
    let sc_payload = build_inject_shellcode_payload(INJECT_WAY_EXECUTE, 0, 1, &[], &[], 0);
    execute(
        &DemonPackage::new(DemonCommand::CommandInjectShellcode, 1, sc_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("execute shellcode");

    // Inject DLL with empty payload.
    let dll_payload = build_inject_dll_payload(0, 1, &[], &[], &[]);
    execute(
        &DemonPackage::new(DemonCommand::CommandInjectDll, 2, dll_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("execute dll");

    // Spawn DLL with empty payload.
    let spawn_payload = build_spawn_dll_payload(&[], &[], &[]);
    execute(
        &DemonPackage::new(DemonCommand::CommandSpawnDll, 3, spawn_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("execute spawn dll");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 3);
    for cb in &callbacks {
        let PendingCallback::Structured { payload, .. } = cb else {
            panic!("expected Structured callback");
        };
        assert_eq!(payload.len(), 4, "injection response must be exactly 4 bytes (u32 status)");
    }
}

/// Verify that `find_libc_base` returns a valid address for our own process.
#[test]
fn find_libc_base_returns_valid_address() {
    let pid = std::process::id();
    let base = find_libc_base(pid);
    assert!(base.is_some(), "should find libc in own process");
    assert!(base.expect("checked") > 0);
}

/// Verify that `resolve_dlopen_in_target` returns an address for our own libc.
#[test]
fn resolve_dlopen_returns_valid_address() {
    let pid = std::process::id();
    let libc_base = find_libc_base(pid).expect("find libc base");
    let addr = resolve_dlopen_in_target(libc_base);
    assert!(addr.is_some(), "should resolve dlopen in own process");
    assert!(addr.expect("checked") > libc_base, "dlopen should be past libc base");
}

/// `check_ptrace_permission` should return a boolean without panicking,
/// regardless of the system's Yama configuration.
#[test]
fn check_ptrace_permission_does_not_panic() {
    // Use our own PID — we don't actually ptrace, just check permissions.
    let result = check_ptrace_permission(std::process::id());
    // On most CI/dev systems scope is 0 or 1, so this should be true.
    // We don't assert the value since it depends on the system config,
    // but we verify it doesn't panic.
    let _ = result;
}

/// `check_ptrace_permission` returns false for scope=3 (disabled).
/// We can't easily change the real sysctl in a test, but we verify the
/// function reads the file and returns a sensible value for our own PID.
#[test]
fn check_ptrace_permission_returns_bool_for_own_pid() {
    let allowed = check_ptrace_permission(std::process::id());
    // Read the actual scope to know what to expect.
    let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().parse::<u32>().unwrap_or(0))
        .unwrap_or(0);
    if scope == 3 {
        assert!(!allowed, "scope=3 must deny ptrace");
    }
    // For scope 0/1, allowed should generally be true. For scope 2 it
    // depends on capabilities. We just verify consistency with scope=3.
}

/// `read_from_proc_mem` can read bytes from our own process memory.
#[test]
fn read_from_proc_mem_reads_own_memory() {
    let data: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let addr = data.as_ptr() as u64;
    let result = read_from_proc_mem(std::process::id(), addr, 8);
    assert!(result.is_ok(), "should read own process memory");
    assert_eq!(result.expect("checked"), data);
}

/// `write_to_proc_mem` can overwrite bytes in the current process's memory,
/// verified by reading the same address back with `read_from_proc_mem`.
#[test]
fn write_to_proc_mem_round_trips_own_memory() {
    let mut buf = [0u8; 8];
    let addr = buf.as_mut_ptr() as u64;
    let pid = std::process::id();
    let data = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];

    write_to_proc_mem(pid, addr, &data).expect("write_to_proc_mem should succeed");

    let read_back =
        read_from_proc_mem(pid, addr, 8).expect("read_from_proc_mem after write should succeed");
    assert_eq!(
        read_back.as_slice(),
        &data,
        "bytes read back via /proc/<pid>/mem should match what was written"
    );
    // Confirm the write landed in the actual buffer (volatile read to defeat
    // the optimizer, since the modification went through file I/O).
    let actual: [u8; 8] =
        std::array::from_fn(|i| unsafe { std::ptr::read_volatile(buf.as_ptr().add(i)) });
    assert_eq!(actual, data, "buf should reflect the written bytes");
}

/// `wait_for_sigtrap` returns `true` when the tracee generates a non-SIGTRAP
/// stop (SIGWINCH, whose default action is Ignore) before hitting an `int3`.
/// This exercises the signal-forwarding loop in `wait_for_sigtrap`.
#[test]
fn wait_for_sigtrap_returns_true_after_intervening_signal() {
    // SAFETY: single-threaded test process; child only calls async-signal-safe
    // functions and libc::_exit before returning control.
    let child_pid = unsafe { libc::fork() };
    assert!(child_pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

    if child_pid == 0 {
        // Child: opt into ptrace, stop to sync, raise an intervening SIGWINCH
        // (default action: Ignore on Linux), then trigger SIGTRAP via int3.
        unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            );
            libc::raise(libc::SIGSTOP);
            libc::raise(libc::SIGWINCH);
            std::arch::asm!("int3", options(nostack, nomem));
            libc::_exit(0);
        }
    }

    // Parent: wait for initial SIGSTOP, then continue and let wait_for_sigtrap
    // handle the intervening SIGWINCH and the eventual SIGTRAP.
    let mut status = 0i32;
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
        libc::ptrace(
            libc::PTRACE_CONT,
            child_pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(), // no signal to re-deliver
        );
    }

    let got_trap = wait_for_sigtrap(child_pid);
    assert!(got_trap, "wait_for_sigtrap must return true after SIGWINCH then SIGTRAP");

    // Child is stopped at int3; detach so it can exit, then reap.
    unsafe {
        libc::ptrace(
            libc::PTRACE_DETACH,
            child_pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        );
        libc::waitpid(child_pid, &mut status, 0);
    }
}

/// `wait_for_sigtrap` returns `false` when the tracee exits before reaching a
/// SIGTRAP, exercising the exit-without-trap path in the function.
#[test]
fn wait_for_sigtrap_returns_false_when_tracee_exits() {
    // SAFETY: same constraints as the sigtrap test above.
    let child_pid = unsafe { libc::fork() };
    assert!(child_pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

    if child_pid == 0 {
        // Child: opt into ptrace, stop to sync, then exit without hitting int3.
        unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            );
            libc::raise(libc::SIGSTOP);
            libc::_exit(0);
        }
    }

    // Parent: wait for SIGSTOP, then continue; the child will exit immediately.
    let mut status = 0i32;
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
        libc::ptrace(
            libc::PTRACE_CONT,
            child_pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        );
    }

    // wait_for_sigtrap's internal waitpid will see WIFEXITED and return false.
    // The child is reaped by that waitpid call, so we must not call waitpid again.
    let got_trap = wait_for_sigtrap(child_pid);
    assert!(!got_trap, "wait_for_sigtrap must return false when tracee exits without SIGTRAP");
}
