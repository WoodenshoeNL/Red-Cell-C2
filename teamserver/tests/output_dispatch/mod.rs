//! Shared payload builders for output_dispatch integration tests.
#![allow(dead_code)]

pub mod error;
pub mod job_tracking;
pub mod output;

use red_cell_common::demon::DemonInfoClass;

// ── payload builders ─────────────────────────────────────────────────────────

/// Build a `CommandExit` payload: exit_method as LE u32.
pub fn exit_payload(exit_method: u32) -> Vec<u8> {
    exit_method.to_le_bytes().to_vec()
}

/// Build a `DemonInfo/MemAlloc` payload: info_class(10) + pointer(u64) + size(u32) + prot(u32).
pub fn demon_info_mem_alloc_payload(pointer: u64, size: u32, protection: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonInfoClass::MemAlloc).to_le_bytes());
    p.extend_from_slice(&pointer.to_le_bytes());
    p.extend_from_slice(&size.to_le_bytes());
    p.extend_from_slice(&protection.to_le_bytes());
    p
}

/// Build a truncated `DemonInfo/MemAlloc` payload: only the info_class, no pointer/size/prot.
pub fn demon_info_truncated_payload() -> Vec<u8> {
    u32::from(DemonInfoClass::MemAlloc).to_le_bytes().to_vec()
}

/// Build a `DemonInfo/MemExec` payload: info_class(11) + function(u64) + thread_id(u32).
pub fn demon_info_mem_exec_payload(function: u64, thread_id: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonInfoClass::MemExec).to_le_bytes());
    p.extend_from_slice(&function.to_le_bytes());
    p.extend_from_slice(&thread_id.to_le_bytes());
    p
}

/// Build a `DemonInfo/MemProtect` payload: info_class(12) + memory(u64) + size(u32) + old(u32) + new(u32).
pub fn demon_info_mem_protect_payload(memory: u64, size: u32, old: u32, new: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonInfoClass::MemProtect).to_le_bytes());
    p.extend_from_slice(&memory.to_le_bytes());
    p.extend_from_slice(&size.to_le_bytes());
    p.extend_from_slice(&old.to_le_bytes());
    p.extend_from_slice(&new.to_le_bytes());
    p
}

/// Build a `DemonInfo/ProcCreate` payload: info_class(21) + utf16_path + pid(u32) + success(u32) + piped(u32) + verbose(u32).
pub fn demon_info_proc_create_payload(
    path: &str,
    pid: u32,
    success: bool,
    piped: bool,
    verbose: bool,
) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonInfoClass::ProcCreate).to_le_bytes());
    // UTF-16LE path, length-prefixed with u32 byte count
    let utf16: Vec<u16> = path.encode_utf16().collect();
    let byte_len = (utf16.len() * 2) as u32;
    p.extend_from_slice(&byte_len.to_le_bytes());
    for word in &utf16 {
        p.extend_from_slice(&word.to_le_bytes());
    }
    p.extend_from_slice(&pid.to_le_bytes());
    p.extend_from_slice(&u32::from(success).to_le_bytes());
    p.extend_from_slice(&u32::from(piped).to_le_bytes());
    p.extend_from_slice(&u32::from(verbose).to_le_bytes());
    p
}

/// Build a `DemonInfo` payload with an unknown info class value.
pub fn demon_info_unknown_class_payload(class: u32) -> Vec<u8> {
    class.to_le_bytes().to_vec()
}

/// Build a `CommandJob/List` payload with the given jobs (id, type, state).
pub fn job_list_payload(jobs: &[(u32, u32, u32)]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1u32.to_le_bytes()); // DemonJobCommand::List = 1
    for &(job_id, job_type, state) in jobs {
        p.extend_from_slice(&job_id.to_le_bytes());
        p.extend_from_slice(&job_type.to_le_bytes());
        p.extend_from_slice(&state.to_le_bytes());
    }
    p
}

/// Build a `CommandJob` action payload (Suspend/Resume/KillRemove).
/// `subcommand` is the `DemonJobCommand` discriminant (2, 3, or 4).
pub fn job_action_payload(subcommand: u32, job_id: u32, success: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&subcommand.to_le_bytes());
    p.extend_from_slice(&job_id.to_le_bytes());
    p.extend_from_slice(&u32::from(success).to_le_bytes());
    p
}

/// Build a `CommandJob/Died` payload — subcommand only, no additional fields.
pub fn job_died_payload() -> Vec<u8> {
    5u32.to_le_bytes().to_vec() // DemonJobCommand::Died = 5
}
