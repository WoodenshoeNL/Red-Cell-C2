//! Shared types and thread-local context for BOF (Beacon Object File) execution.
//!
//! Extracted from `coffeeldr.rs`.  All public types and constants remain
//! re-exported from `coffeeldr` so existing callers need no changes.

use std::sync::{Arc, Mutex};

// ─── BOF output queue ─────────────────────────────────────────────────────

/// Thread-safe queue for BOF callbacks produced by background threads.
///
/// Background BOF threads push their [`BofCallback`]s into this queue; the
/// agent main loop drains it each iteration and forwards the callbacks to the
/// teamserver, preserving the `InlineExecute` callback contract.
pub type BofOutputQueue = Arc<Mutex<Vec<BofCallback>>>;

/// Create a new, empty [`BofOutputQueue`].
pub fn new_bof_output_queue() -> BofOutputQueue {
    Arc::new(Mutex::new(Vec::new()))
}

// ─── BOF callback sub-types (agent → server) ───────────────────────────────

/// Standard output produced by the BOF (via `BeaconPrintf`/`BeaconOutput`).
pub const BOF_CALLBACK_OUTPUT: u32 = 0x00;
/// Error output produced by the BOF.
pub const BOF_CALLBACK_ERROR: u32 = 0x0d;
/// An unhandled exception occurred during BOF execution.
pub const BOF_EXCEPTION: u32 = 1;
/// A required DLL export symbol could not be resolved.
pub const BOF_SYMBOL_NOT_FOUND: u32 = 2;
/// The BOF ran to completion successfully.
pub const BOF_RAN_OK: u32 = 3;
/// The COFF loader could not start the BOF at all.
pub const BOF_COULD_NOT_RUN: u32 = 4;

/// Result of a BOF execution attempt.
#[derive(Debug)]
pub struct BofResult {
    /// Callback entries to send back to the teamserver.
    pub callbacks: Vec<BofCallback>,
}

/// A single BOF callback to be sent to the teamserver.
#[derive(Debug)]
pub struct BofCallback {
    /// One of the `BOF_*` constants.
    pub callback_type: u32,
    /// Payload bytes for this callback (type-specific encoding).
    pub payload: Vec<u8>,
    /// The originating request ID from the teamserver task that triggered this
    /// BOF execution.  Must be preserved so threaded callbacks can be correlated
    /// with the correct task on the teamserver side.
    pub request_id: u32,
}

// ─── Beacon API types and callbacks (Windows) ──────────────────────────────

/// Beacon data parser — matches the Havoc `datap` struct layout from
/// `payloads/Demon/include/core/ObjectApi.h`.
///
/// BOFs allocate this on their stack and pass it to `BeaconDataParse` /
/// `BeaconDataInt` / etc.  The layout must be ABI-compatible with the C
/// definition so that BOF object code can operate on it directly.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DataParser {
    /// Original buffer pointer (retained for the caller to free).
    pub original: *const u8,
    /// Current read cursor into the buffer.
    pub buffer: *const u8,
    /// Remaining bytes from `buffer` to end of data.
    pub length: i32,
    /// Total usable size (set once by `BeaconDataParse`).
    pub size: i32,
}

// Thread-local pointer to the `Vec<u8>` that collects BOF output for the
// current `coffee_execute` invocation.  Set before calling the BOF entry
// point and cleared afterward.
std::thread_local! {
    pub(crate) static BOF_OUTPUT_TLS: std::cell::Cell<*mut Vec<u8>> =
        const { std::cell::Cell::new(std::ptr::null_mut()) };
}

// ─── BOF spawn/token context (thread-local) ──────────────────────────────

/// Configuration context made available to Beacon API callbacks during BOF
/// execution.  Set via [`set_bof_context`] before calling [`coffee_execute`]
/// and cleared via [`clear_bof_context`] afterward.
#[derive(Clone)]
pub struct BofContext {
    /// 64-bit spawn-to path as UTF-16LE (including NUL terminator).
    pub spawn64: Option<Vec<u16>>,
    /// 32-bit spawn-to path as UTF-16LE (including NUL terminator).
    pub spawn32: Option<Vec<u16>>,
}

std::thread_local! {
    pub(crate) static BOF_CONTEXT_TLS: std::cell::Cell<*const BofContext> =
        const { std::cell::Cell::new(std::ptr::null()) };
}

/// Install a [`BofContext`] for the current thread so that Beacon API
/// callbacks (`BeaconGetSpawnTo`, `BeaconSpawnTemporaryProcess`, etc.) can
/// access agent configuration during BOF execution.
///
/// The caller must ensure the referenced `BofContext` outlives the BOF
/// execution and call [`clear_bof_context`] afterward.
pub fn set_bof_context(ctx: &BofContext) {
    BOF_CONTEXT_TLS.with(|cell| cell.set(ctx as *const BofContext));
}

/// Remove the [`BofContext`] from the current thread.
pub fn clear_bof_context() {
    BOF_CONTEXT_TLS.with(|cell| cell.set(std::ptr::null()));
}
