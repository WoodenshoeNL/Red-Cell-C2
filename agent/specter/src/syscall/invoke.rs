//! Assembly thunks, PE-scanning helpers, and `SyscallTable` resolution.
//!
//! All items in this module are Windows x86-64 only.  They implement the
//! indirect syscall engine: locating ntdll, extracting SSNs, and providing
//! the `sys_set_config` / `sys_invoke` assembly pair used by every NT wrapper.

#![allow(bad_asm_style)] // `global_asm!` uses Intel/ATT directive strings by design

use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

use super::{SyscallEntry, SyscallError, SyscallTable};

// ── Assembly thunks ───────────────────────────────────────────────────────────

std::arch::global_asm!(
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

// ── Extern declarations ───────────────────────────────────────────────────────

unsafe extern "C" {
    /// Store `config` in `r11` for the immediately following `sys_invoke` call.
    pub(crate) fn sys_set_config(config: *const SyscallEntry);
}

// One assembly entry `sys_invoke`; Rust signatures only reflect arity for callers.
#[allow(clashing_extern_declarations)]
unsafe extern "C" {
    #[link_name = "sys_invoke"]
    pub(crate) fn sys_invoke_4(a: usize, b: usize, c: usize, d: usize) -> i32;

    #[link_name = "sys_invoke"]
    pub(crate) fn sys_invoke_5(a: usize, b: usize, c: usize, d: usize, e: usize) -> i32;

    #[link_name = "sys_invoke"]
    pub(crate) fn sys_invoke_6(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> i32;

    #[link_name = "sys_invoke"]
    #[allow(dead_code)]
    pub(crate) fn sys_invoke_7(
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        e: usize,
        f: usize,
        g: usize,
    ) -> i32;

    #[link_name = "sys_invoke"]
    pub(crate) fn sys_invoke_11(
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

// ── PE constants ──────────────────────────────────────────────────────────────

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

// ── ntdll base resolution ─────────────────────────────────────────────────────

/// Return the base address of `ntdll.dll` in the current process, or
/// `Err(SyscallError::NtdllNotFound)`.
pub(crate) fn ntdll_base() -> Result<*const u8, SyscallError> {
    // SAFETY: "ntdll.dll\0" is a valid null-terminated ASCII string.
    let handle = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr().cast()) };
    if handle.is_null() { Err(SyscallError::NtdllNotFound) } else { Ok(handle as *const u8) }
}

// ── PE export table walk ──────────────────────────────────────────────────────

/// Call `callback` for every named export in the module at `base`, passing
/// the name and the function RVA.
///
/// # Safety
///
/// `base` must point to a valid, mapped PE image.
pub(crate) unsafe fn for_each_export(base: *const u8, mut callback: impl FnMut(&[u8], u32)) {
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
    let addr_of_funcs = unsafe { std::ptr::read_unaligned(exp_dir.add(28) as *const u32) } as usize;
    let addr_of_names = unsafe { std::ptr::read_unaligned(exp_dir.add(32) as *const u32) } as usize;
    let addr_of_ords = unsafe { std::ptr::read_unaligned(exp_dir.add(36) as *const u32) } as usize;

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

// ── SSN / syscall-address extraction ─────────────────────────────────────────

/// Try to extract the SSN from the NT stub prologue at `func_ptr`.
///
/// Returns `Some(ssn)` if the unhooked prologue pattern is found.
pub(crate) fn extract_ssn(func_ptr: *const u8) -> Option<u16> {
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
pub(crate) fn find_syscall_instruction(func_ptr: *const u8) -> Option<u64> {
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
pub(crate) fn stub_size(base: *const u8) -> usize {
    let mut found: [u64; 2] = [0; 2];
    let mut count = 0usize;

    // SAFETY: for_each_export is safe given a valid module base.
    unsafe {
        for_each_export(base, |name, rva| {
            if count >= 2 {
                return;
            }
            if name.starts_with(b"Nt") && rva != 0 {
                let fptr = base.add(rva as usize);
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
pub(crate) fn find_ssn_from_neighbour(func_ptr: *const u8, stub_sz: usize) -> Option<u16> {
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

// ── SyscallTable resolution ───────────────────────────────────────────────────

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

        // Resolve the indirect syscall address from NtAddBootEntry
        // (an "unused" NT function — Demon uses it as a reference stub).
        let indirect_addr = unsafe { find_indirect_syscall_addr(base) };

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
unsafe fn find_indirect_syscall_addr(base: *const u8) -> Option<u64> {
    let mut indirect: Option<u64> = None;
    unsafe {
        for_each_export(base, |name, rva| {
            if indirect.is_some() {
                return;
            }
            if name == b"NtAddBootEntry" {
                let fptr = base.add(rva as usize);
                indirect = find_syscall_instruction(fptr);
            }
        });
        // Fallback: find from any resolved NT function.
        if indirect.is_none() {
            for_each_export(base, |name, rva| {
                if indirect.is_some() {
                    return;
                }
                if name.starts_with(b"Nt") && rva != 0 {
                    let fptr = base.add(rva as usize);
                    if let Some(addr) = find_syscall_instruction(fptr) {
                        indirect = Some(addr);
                    }
                }
            });
        }
    }
    indirect
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// `NTSTATUS` not-supported sentinel for when the table is not initialised.
#[allow(dead_code)]
pub(crate) const STATUS_NOT_SUPPORTED: i32 = 0xC00000BBu32 as i32;

/// Return `Some(entry)` if the entry has been resolved, otherwise `None`.
#[inline]
pub(crate) fn get_entry(entry: &SyscallEntry) -> Option<&SyscallEntry> {
    if entry.is_resolved() { Some(entry) } else { None }
}
