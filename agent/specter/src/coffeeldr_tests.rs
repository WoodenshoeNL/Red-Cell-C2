// Tests for the COFF/BOF loader.  Included as `mod tests` from `coffeeldr.rs`.
//
// `super::*` gives access to all public items re-exported from `coffeeldr`
// (BofResult, BofCallback, BofContext, constants, etc.).
// The beacon API functions live in `beacon_api` and are imported explicitly.

use super::*;
use crate::beacon_api::{
    beacon_cleanup_process, beacon_data_extract, beacon_data_int, beacon_data_length,
    beacon_data_parse, beacon_data_short, beacon_get_spawn_to, beacon_inject_process,
    beacon_inject_temporary_process, beacon_is_admin, beacon_output, beacon_revert_token,
    beacon_spawn_temporary_process, beacon_use_token, bof_beacon_printf, resolve_beacon_api,
    to_wide_char,
};
use crate::bof_context::{BOF_CONTEXT_TLS, BOF_OUTPUT_TLS};

#[test]
fn empty_object_returns_could_not_run() {
    let result = coffee_execute("go", &[], &[], false);
    assert_eq!(result.callbacks.len(), 1);
    assert_eq!(result.callbacks[0].callback_type, BOF_COULD_NOT_RUN);
}

#[test]
fn garbage_object_returns_could_not_run() {
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
    let result = coffee_execute("go", &garbage, &[], false);
    assert_eq!(result.callbacks.len(), 1);
    assert_eq!(result.callbacks[0].callback_type, BOF_COULD_NOT_RUN);
}

// COFF with wrong machine type (i386 = 0x14c instead of AMD64 = 0x8664)
#[test]
fn wrong_machine_type_returns_could_not_run() {
    let mut coff = vec![0u8; 20]; // minimal COFF header
    // Machine = 0x014C (i386)
    coff[0] = 0x4C;
    coff[1] = 0x01;
    let result = coffee_execute("go", &coff, &[], false);
    assert_eq!(result.callbacks.len(), 1);
    assert_eq!(result.callbacks[0].callback_type, BOF_COULD_NOT_RUN);
}

#[cfg(not(windows))]
#[test]
fn non_windows_always_returns_could_not_run() {
    let result = coffee_execute("go", &[0u8; 100], &[], false);
    assert_eq!(result.callbacks.len(), 1);
    assert_eq!(result.callbacks[0].callback_type, BOF_COULD_NOT_RUN);
}

#[cfg(not(windows))]
#[test]
fn threaded_non_windows_stub_returns_none() {
    let result = coffee_execute_threaded(
        "go".to_string(),
        vec![0u8; 20],
        vec![],
        new_bof_output_queue(),
        42,
        BofContext { spawn64: None, spawn32: None },
    );
    assert!(result.is_none());
}

/// Regression test: spawn context carried into a new thread is visible to
/// Beacon API callbacks (`BeaconGetSpawnTo`) running on that thread.
///
/// This exercises the exact pattern used by `bof_thread_entry` — the
/// context is installed on entry to the BOF thread, not on the dispatching
/// thread — verifying that threaded BOFs no longer see a null context.
#[test]
#[allow(unsafe_code)]
fn threaded_bof_spawn_context_visible_in_new_thread() {
    let path64: Vec<u16> = "C:\\Windows\\System32\\rundll32.exe\0".encode_utf16().collect();
    let ctx = BofContext { spawn64: Some(path64.clone()), spawn32: None };

    // Confirm no context is set on the current thread before we begin.
    clear_bof_context();

    let handle = std::thread::spawn(move || {
        // Simulate what bof_thread_entry does: install the context on this
        // thread before executing any BOF callbacks.
        set_bof_context(&ctx);

        let mut buf = vec![0u8; 512];
        // SAFETY: buf is valid and large enough for the path.
        unsafe { beacon_get_spawn_to(0, buf.as_mut_ptr(), buf.len() as i32) };

        clear_bof_context();

        // Return the bytes so the parent thread can inspect them.
        buf
    });

    let buf = handle.join().expect("thread panicked");

    // Verify the UTF-16LE spawn path was returned correctly.
    let byte_len = path64.len() * 2;
    let copied: Vec<u16> =
        (0..path64.len()).map(|i| u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]])).collect();
    assert_eq!(copied, path64);
    // Bytes beyond the path must be zero.
    assert!(buf[byte_len..].iter().all(|&b| b == 0));
}

#[test]
fn new_bof_output_queue_starts_empty() {
    let queue = new_bof_output_queue();
    let guard = queue.lock().expect("lock");
    assert!(guard.is_empty());
}

#[test]
fn bof_output_queue_can_push_and_drain() {
    let queue = new_bof_output_queue();

    // Simulate a background thread pushing callbacks
    {
        let mut guard = queue.lock().expect("lock");
        guard.push(BofCallback {
            callback_type: BOF_RAN_OK,
            payload: vec![1, 2, 3],
            request_id: 7,
        });
        guard.push(BofCallback {
            callback_type: BOF_CALLBACK_OUTPUT,
            payload: vec![4, 5],
            request_id: 7,
        });
    }

    // Drain (take) the callbacks
    let drained = std::mem::take(&mut *queue.lock().expect("lock"));
    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].callback_type, BOF_RAN_OK);
    assert_eq!(drained[1].callback_type, BOF_CALLBACK_OUTPUT);

    // Queue should be empty after drain
    assert!(queue.lock().expect("lock").is_empty());
}

#[test]
fn bof_output_queue_is_thread_safe() {
    let queue = new_bof_output_queue();
    let queue_clone = queue.clone();

    let handle = std::thread::spawn(move || {
        let mut guard = queue_clone.lock().expect("lock");
        guard.push(BofCallback {
            callback_type: BOF_CALLBACK_OUTPUT,
            payload: b"hello from thread".to_vec(),
            request_id: 99,
        });
    });

    handle.join().expect("thread join");

    let guard = queue.lock().expect("lock");
    assert_eq!(guard.len(), 1);
    assert_eq!(guard[0].payload, b"hello from thread");
    assert_eq!(guard[0].request_id, 99);
}

#[test]
fn bof_callback_preserves_request_id() {
    let cb = BofCallback { callback_type: BOF_RAN_OK, payload: vec![], request_id: 0xDEAD };
    assert_eq!(cb.request_id, 0xDEAD);
}

#[test]
fn bof_output_queue_preserves_request_id_across_drain() {
    let queue = new_bof_output_queue();
    let task_id: u32 = 42;

    {
        let mut guard = queue.lock().expect("lock");
        guard.push(BofCallback {
            callback_type: BOF_CALLBACK_OUTPUT,
            payload: b"output data".to_vec(),
            request_id: task_id,
        });
        guard.push(BofCallback {
            callback_type: BOF_RAN_OK,
            payload: Vec::new(),
            request_id: task_id,
        });
    }

    let drained = std::mem::take(&mut *queue.lock().expect("lock"));
    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].request_id, task_id);
    assert_eq!(drained[1].request_id, task_id);
}

// ── Beacon data-parsing API tests ──────────────────────────────────

/// Helper: build a BOF argument buffer with a 4-byte length prefix
/// followed by the given payload.
fn make_arg_buf(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_parse_initialises_parser() {
    // Build buffer: 4-byte prefix + 8 bytes of payload
    let payload = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let buf = make_arg_buf(&payload);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe {
        beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32);
    }
    let parser = unsafe { parser.assume_init() };

    assert_eq!(parser.original, buf.as_ptr());
    assert_eq!(parser.buffer, unsafe { buf.as_ptr().add(4) });
    assert_eq!(parser.length, payload.len() as i32);
    assert_eq!(parser.size, payload.len() as i32);
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_int_reads_le_u32() {
    // Payload: two 32-bit little-endian integers
    let mut payload = Vec::new();
    payload.extend_from_slice(&42u32.to_le_bytes());
    payload.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
    let buf = make_arg_buf(&payload);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    let v1 = unsafe { beacon_data_int(&mut parser) };
    assert_eq!(v1, 42);

    let v2 = unsafe { beacon_data_int(&mut parser) };
    assert_eq!(v2, 0xDEADBEEFu32 as i32);

    assert_eq!(parser.length, 0);
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_int_returns_zero_when_exhausted() {
    // Only 2 bytes of payload — not enough for a 32-bit read.
    let buf = make_arg_buf(&[0xAA, 0xBB]);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    let v = unsafe { beacon_data_int(&mut parser) };
    assert_eq!(v, 0);
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_short_reads_le_u16() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1234u16.to_le_bytes());
    payload.extend_from_slice(&0xBEEFu16.to_le_bytes());
    let buf = make_arg_buf(&payload);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    assert_eq!(unsafe { beacon_data_short(&mut parser) }, 1234);
    assert_eq!(unsafe { beacon_data_short(&mut parser) }, 0xBEEFu16 as i16);
    assert_eq!(parser.length, 0);
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_short_returns_zero_when_exhausted() {
    // 1 byte payload — not enough for a 16-bit read.
    let buf = make_arg_buf(&[0xFF]);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    assert_eq!(unsafe { beacon_data_short(&mut parser) }, 0);
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_extract_reads_length_prefixed_blob() {
    // Payload: length-prefixed string "hello"
    let hello = b"hello";
    let mut payload = Vec::new();
    payload.extend_from_slice(&(hello.len() as u32).to_le_bytes());
    payload.extend_from_slice(hello);
    let buf = make_arg_buf(&payload);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    let mut out_size: i32 = 0;
    let ptr = unsafe { beacon_data_extract(&mut parser, &mut out_size) };
    assert!(!ptr.is_null());
    assert_eq!(out_size, hello.len() as i32);
    let extracted = unsafe { std::slice::from_raw_parts(ptr, out_size as usize) };
    assert_eq!(extracted, hello);
    assert_eq!(parser.length, 0);
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_extract_with_null_size_out() {
    let data = b"ab";
    let mut payload = Vec::new();
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
    let buf = make_arg_buf(&payload);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    // Pass null for size_out — should not crash.
    let ptr = unsafe { beacon_data_extract(&mut parser, std::ptr::null_mut()) };
    assert!(!ptr.is_null());
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_extract_returns_null_when_exhausted() {
    // Empty payload — not enough for 4-byte length prefix.
    let buf = make_arg_buf(&[]);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    let mut out_size: i32 = -1;
    let ptr = unsafe { beacon_data_extract(&mut parser, &mut out_size) };
    assert!(ptr.is_null());
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_extract_rejects_overlong_length_prefix() {
    // Payload has a 4-byte length prefix claiming 100 bytes, but only 3 bytes follow.
    let mut payload = Vec::new();
    payload.extend_from_slice(&100u32.to_le_bytes()); // length = 100
    payload.extend_from_slice(b"abc"); // only 3 bytes
    let buf = make_arg_buf(&payload);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };
    let length_before = parser.length;

    let mut out_size: i32 = -1;
    let ptr = unsafe { beacon_data_extract(&mut parser, &mut out_size) };
    assert!(ptr.is_null(), "overlong length must return null");
    // Parser state must be unchanged (safe state).
    assert_eq!(parser.length, length_before, "parser.length must not change on reject");
    assert_eq!(out_size, -1, "size_out must not be written on reject");
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_extract_rejects_negative_length_prefix() {
    // Payload with 0xFFFFFFFF which is -1 as i32.
    let mut payload = Vec::new();
    payload.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // -1 as i32
    payload.extend_from_slice(b"data");
    let buf = make_arg_buf(&payload);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };
    let length_before = parser.length;

    let mut out_size: i32 = -1;
    let ptr = unsafe { beacon_data_extract(&mut parser, &mut out_size) };
    assert!(ptr.is_null(), "negative length must return null");
    assert_eq!(parser.length, length_before, "parser.length must not change on reject");
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_extract_rejects_length_equal_to_remaining_plus_one() {
    // Exactly one byte more than available after the length prefix.
    let actual_data = b"hi";
    let mut payload = Vec::new();
    // Claim 3 bytes but only 2 follow.
    payload.extend_from_slice(&3u32.to_le_bytes());
    payload.extend_from_slice(actual_data);
    let buf = make_arg_buf(&payload);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    let ptr = unsafe { beacon_data_extract(&mut parser, std::ptr::null_mut()) };
    assert!(ptr.is_null(), "length exceeding remaining by 1 must return null");
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_extract_accepts_exact_fit() {
    // Length prefix exactly matches remaining data — should succeed.
    let data = b"exact";
    let mut payload = Vec::new();
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
    let buf = make_arg_buf(&payload);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    let mut out_size: i32 = 0;
    let ptr = unsafe { beacon_data_extract(&mut parser, &mut out_size) };
    assert!(!ptr.is_null(), "exact-fit length must succeed");
    assert_eq!(out_size, data.len() as i32);
    assert_eq!(parser.length, 0);
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_extract_zero_length_returns_valid_ptr() {
    // A zero-length blob is valid — should return a non-null pointer.
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u32.to_le_bytes()); // length = 0
    let buf = make_arg_buf(&payload);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    let mut out_size: i32 = -1;
    let ptr = unsafe { beacon_data_extract(&mut parser, &mut out_size) };
    assert!(!ptr.is_null(), "zero-length extract must return valid pointer");
    assert_eq!(out_size, 0);
    assert_eq!(parser.length, 0);
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_length_returns_remaining() {
    let payload = [0u8; 10];
    let buf = make_arg_buf(&payload);

    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    assert_eq!(unsafe { beacon_data_length(&mut parser) }, 10);
    // Consume 4 bytes
    let _ = unsafe { beacon_data_int(&mut parser) };
    assert_eq!(unsafe { beacon_data_length(&mut parser) }, 6);
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_mixed_reads() {
    // Build a complex buffer: short(5) + int(100) + extract("test")
    let mut payload = Vec::new();
    payload.extend_from_slice(&5u16.to_le_bytes()); // short
    payload.extend_from_slice(&100u32.to_le_bytes()); // int
    let test_data = b"test";
    payload.extend_from_slice(&(test_data.len() as u32).to_le_bytes());
    payload.extend_from_slice(test_data); // extract

    let buf = make_arg_buf(&payload);
    let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
    unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
    let mut parser = unsafe { parser.assume_init() };

    assert_eq!(unsafe { beacon_data_short(&mut parser) }, 5);
    assert_eq!(unsafe { beacon_data_int(&mut parser) }, 100);
    let mut sz: i32 = 0;
    let ptr = unsafe { beacon_data_extract(&mut parser, &mut sz) };
    assert_eq!(sz, 4);
    assert_eq!(unsafe { std::slice::from_raw_parts(ptr, sz as usize) }, b"test");
    assert_eq!(unsafe { beacon_data_length(&mut parser) }, 0);
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_parse_null_parser_does_not_crash() {
    unsafe { beacon_data_parse(std::ptr::null_mut(), [0u8; 8].as_ptr(), 8) };
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_int_null_parser_returns_zero() {
    assert_eq!(unsafe { beacon_data_int(std::ptr::null_mut()) }, 0);
}

#[test]
#[allow(unsafe_code)]
fn beacon_data_length_null_parser_returns_zero() {
    assert_eq!(unsafe { beacon_data_length(std::ptr::null_mut()) }, 0);
}

// ── Beacon output API tests ────────────────────────────────────────

#[test]
#[allow(unsafe_code)]
fn beacon_output_appends_to_tls_buffer() {
    let mut buf: Vec<u8> = Vec::new();
    BOF_OUTPUT_TLS.with(|cell| cell.set(&mut buf as *mut Vec<u8>));

    let data = b"hello world";
    unsafe { beacon_output(0, data.as_ptr(), data.len() as i32) };

    BOF_OUTPUT_TLS.with(|cell| cell.set(std::ptr::null_mut()));

    assert_eq!(buf, b"hello world");
}

#[test]
#[allow(unsafe_code)]
fn beacon_output_null_data_is_noop() {
    let mut buf: Vec<u8> = Vec::new();
    BOF_OUTPUT_TLS.with(|cell| cell.set(&mut buf as *mut Vec<u8>));

    unsafe { beacon_output(0, std::ptr::null(), 10) };

    BOF_OUTPUT_TLS.with(|cell| cell.set(std::ptr::null_mut()));

    assert!(buf.is_empty());
}

#[test]
#[allow(unsafe_code)]
fn beacon_printf_captures_plain_string() {
    let mut buf: Vec<u8> = Vec::new();
    BOF_OUTPUT_TLS.with(|cell| cell.set(&mut buf as *mut Vec<u8>));

    let fmt = b"test output\0";
    unsafe { bof_beacon_printf(0, fmt.as_ptr()) };

    BOF_OUTPUT_TLS.with(|cell| cell.set(std::ptr::null_mut()));

    assert_eq!(buf, b"test output");
}

/// Regression test: `BeaconPrintf("pid=%d", pid)` must produce
/// the formatted value, not the literal `%d`.
#[test]
#[allow(unsafe_code)]
fn beacon_printf_formats_int_placeholder() {
    let mut buf: Vec<u8> = Vec::new();
    BOF_OUTPUT_TLS.with(|cell| cell.set(&mut buf as *mut Vec<u8>));

    let fmt = b"pid=%d\0";
    unsafe { bof_beacon_printf(0, fmt.as_ptr(), 42i32) };

    BOF_OUTPUT_TLS.with(|cell| cell.set(std::ptr::null_mut()));
    assert_eq!(std::str::from_utf8(&buf).ok(), Some("pid=42"));
}

/// Regression test: `BeaconPrintf("name=%s addr=0x%x", name, addr)`.
#[test]
#[allow(unsafe_code)]
fn beacon_printf_formats_string_and_hex() {
    let mut buf: Vec<u8> = Vec::new();
    BOF_OUTPUT_TLS.with(|cell| cell.set(&mut buf as *mut Vec<u8>));

    let fmt = b"name=%s addr=0x%x\0";
    let name = b"explorer.exe\0";
    unsafe {
        bof_beacon_printf(0, fmt.as_ptr(), name.as_ptr(), 0xDEADu32);
    }

    BOF_OUTPUT_TLS.with(|cell| cell.set(std::ptr::null_mut()));
    assert_eq!(std::str::from_utf8(&buf).ok(), Some("name=explorer.exe addr=0xdead"),);
}

/// Regression test: `%%` literal percent.
#[test]
#[allow(unsafe_code)]
fn beacon_printf_formats_percent_literal() {
    let mut buf: Vec<u8> = Vec::new();
    BOF_OUTPUT_TLS.with(|cell| cell.set(&mut buf as *mut Vec<u8>));

    let fmt = b"100%%\0";
    unsafe { bof_beacon_printf(0, fmt.as_ptr()) };

    BOF_OUTPUT_TLS.with(|cell| cell.set(std::ptr::null_mut()));
    assert_eq!(std::str::from_utf8(&buf).ok(), Some("100%"));
}

// ── toWideChar tests ───────────────────────────────────────────────

#[test]
#[allow(unsafe_code)]
fn to_wide_char_converts_ascii() {
    let src = b"Hi\0";
    let mut dst = [0u16; 4];
    let result = unsafe { to_wide_char(src.as_ptr(), dst.as_mut_ptr(), 4) };
    assert_eq!(result, 1); // TRUE
    assert_eq!(dst[0], b'H' as u16);
    assert_eq!(dst[1], b'i' as u16);
    assert_eq!(dst[2], 0);
}

#[test]
#[allow(unsafe_code)]
fn to_wide_char_null_returns_zero() {
    let mut dst = [0u16; 4];
    assert_eq!(unsafe { to_wide_char(std::ptr::null(), dst.as_mut_ptr(), 4) }, 0);
    assert_eq!(unsafe { to_wide_char(b"x\0".as_ptr(), std::ptr::null_mut(), 4) }, 0);
}

// ── resolve_beacon_api tests ───────────────────────────────────────

#[test]
fn resolve_beacon_api_known_symbols() {
    assert!(resolve_beacon_api("__imp_BeaconDataParse").is_some());
    assert!(resolve_beacon_api("__imp_BeaconDataInt").is_some());
    assert!(resolve_beacon_api("__imp_BeaconDataShort").is_some());
    assert!(resolve_beacon_api("__imp_BeaconDataExtract").is_some());
    assert!(resolve_beacon_api("__imp_BeaconDataLength").is_some());
    assert!(resolve_beacon_api("__imp_BeaconOutput").is_some());
    assert!(resolve_beacon_api("__imp_BeaconPrintf").is_some());
    assert!(resolve_beacon_api("__imp_BeaconGetSpawnTo").is_some());
    assert!(resolve_beacon_api("__imp_BeaconSpawnTemporaryProcess").is_some());
    assert!(resolve_beacon_api("__imp_BeaconInjectProcess").is_some());
    assert!(resolve_beacon_api("__imp_BeaconInjectTemporaryProcess").is_some());
    assert!(resolve_beacon_api("__imp_BeaconCleanupProcess").is_some());
    assert!(resolve_beacon_api("__imp_BeaconIsAdmin").is_some());
    assert!(resolve_beacon_api("__imp_BeaconUseToken").is_some());
    assert!(resolve_beacon_api("__imp_BeaconRevertToken").is_some());
    assert!(resolve_beacon_api("__imp_toWideChar").is_some());
}

#[test]
fn resolve_beacon_api_unknown_returns_none() {
    assert!(resolve_beacon_api("__imp_BeaconInformation").is_none());
    assert!(resolve_beacon_api("not_a_beacon_api").is_none());
}

#[test]
fn resolve_beacon_api_returns_distinct_addresses() {
    let addrs: Vec<u64> = [
        "__imp_BeaconDataParse",
        "__imp_BeaconDataInt",
        "__imp_BeaconDataShort",
        "__imp_BeaconDataExtract",
        "__imp_BeaconDataLength",
        "__imp_BeaconOutput",
        "__imp_BeaconPrintf",
        "__imp_BeaconGetSpawnTo",
        "__imp_BeaconSpawnTemporaryProcess",
        "__imp_BeaconInjectProcess",
        "__imp_BeaconInjectTemporaryProcess",
        "__imp_BeaconCleanupProcess",
        "__imp_BeaconIsAdmin",
        "__imp_BeaconUseToken",
        "__imp_BeaconRevertToken",
        "__imp_toWideChar",
    ]
    .iter()
    .map(|s| resolve_beacon_api(s).expect("known"))
    .collect();

    // All addresses should be non-zero and unique.
    for &a in &addrs {
        assert_ne!(a, 0);
    }
    let unique: std::collections::HashSet<u64> = addrs.iter().copied().collect();
    assert_eq!(unique.len(), addrs.len());
}

// ── BofContext / spawn config tests ───────────────────────────────────

#[test]
fn bof_context_set_and_clear() {
    let ctx = BofContext {
        spawn64: Some(vec![b'C' as u16, b':' as u16, b'\\' as u16, 0]),
        spawn32: None,
    };
    set_bof_context(&ctx);
    BOF_CONTEXT_TLS.with(|cell| assert!(!cell.get().is_null()));
    clear_bof_context();
    BOF_CONTEXT_TLS.with(|cell| assert!(cell.get().is_null()));
}

#[test]
#[allow(unsafe_code)]
fn beacon_get_spawn_to_copies_64bit_path() {
    let path: Vec<u16> = "C:\\Windows\\System32\\rundll32.exe\0".encode_utf16().collect();
    let ctx = BofContext { spawn64: Some(path.clone()), spawn32: None };
    set_bof_context(&ctx);

    let mut buf = vec![0u8; 256];
    unsafe { beacon_get_spawn_to(0, buf.as_mut_ptr(), buf.len() as i32) };

    clear_bof_context();

    // Verify the UTF-16LE bytes were copied.
    let byte_len = path.len() * 2;
    let copied: Vec<u16> =
        (0..path.len()).map(|i| u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]])).collect();
    assert_eq!(copied, path);
    // Rest of buffer should be zero.
    assert!(buf[byte_len..].iter().all(|&b| b == 0));
}

#[test]
#[allow(unsafe_code)]
fn beacon_get_spawn_to_copies_32bit_path() {
    let path: Vec<u16> = "C:\\Windows\\SysWOW64\\rundll32.exe\0".encode_utf16().collect();
    let ctx = BofContext { spawn64: None, spawn32: Some(path.clone()) };
    set_bof_context(&ctx);

    let mut buf = vec![0u8; 256];
    unsafe { beacon_get_spawn_to(1, buf.as_mut_ptr(), buf.len() as i32) };

    clear_bof_context();

    let copied: Vec<u16> =
        (0..path.len()).map(|i| u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]])).collect();
    assert_eq!(copied, path);
}

#[test]
#[allow(unsafe_code)]
fn beacon_get_spawn_to_no_context_is_noop() {
    clear_bof_context();
    let mut buf = vec![0xFFu8; 16];
    unsafe { beacon_get_spawn_to(0, buf.as_mut_ptr(), buf.len() as i32) };
    // Buffer unchanged.
    assert!(buf.iter().all(|&b| b == 0xFF));
}

#[test]
#[allow(unsafe_code)]
fn beacon_get_spawn_to_null_buffer_is_noop() {
    let ctx = BofContext { spawn64: Some(vec![b'A' as u16, 0]), spawn32: None };
    set_bof_context(&ctx);
    // Should not crash.
    unsafe { beacon_get_spawn_to(0, std::ptr::null_mut(), 256) };
    clear_bof_context();
}

#[test]
#[allow(unsafe_code)]
fn beacon_get_spawn_to_buffer_too_small_is_noop() {
    let path: Vec<u16> = "C:\\long\\path.exe\0".encode_utf16().collect();
    let ctx = BofContext { spawn64: Some(path), spawn32: None };
    set_bof_context(&ctx);

    let mut buf = vec![0xFFu8; 4]; // too small
    unsafe { beacon_get_spawn_to(0, buf.as_mut_ptr(), buf.len() as i32) };

    clear_bof_context();
    // Buffer unchanged — path didn't fit.
    assert!(buf.iter().all(|&b| b == 0xFF));
}

#[test]
#[allow(unsafe_code)]
fn beacon_get_spawn_to_no_path_configured_is_noop() {
    let ctx = BofContext { spawn64: None, spawn32: None };
    set_bof_context(&ctx);

    let mut buf = vec![0xFFu8; 16];
    unsafe { beacon_get_spawn_to(0, buf.as_mut_ptr(), buf.len() as i32) };

    clear_bof_context();
    assert!(buf.iter().all(|&b| b == 0xFF));
}

#[cfg(not(windows))]
#[test]
#[allow(unsafe_code)]
fn beacon_spawn_temporary_process_non_windows_returns_false() {
    let mut si = [0u8; 104]; // STARTUPINFOW size on 64-bit
    let mut pi = [0u8; 24]; // PROCESS_INFORMATION size on 64-bit
    let result = unsafe { beacon_spawn_temporary_process(0, 1, si.as_mut_ptr(), pi.as_mut_ptr()) };
    assert_eq!(result, 0);
}

#[cfg(not(windows))]
#[test]
#[allow(unsafe_code)]
fn beacon_inject_process_non_windows_is_noop() {
    // Should not crash.
    unsafe {
        beacon_inject_process(0, 1234, [0u8; 4].as_ptr(), 4, 0, std::ptr::null(), 0);
    }
}

#[cfg(not(windows))]
#[test]
#[allow(unsafe_code)]
fn beacon_inject_temporary_process_non_windows_is_noop() {
    let pi = [0u8; 24];
    unsafe {
        beacon_inject_temporary_process(pi.as_ptr(), [0u8; 4].as_ptr(), 4, 0, std::ptr::null(), 0);
    }
}

#[cfg(not(windows))]
#[test]
#[allow(unsafe_code)]
fn beacon_cleanup_process_non_windows_is_noop() {
    let mut pi = [0u8; 24];
    unsafe { beacon_cleanup_process(pi.as_mut_ptr()) };
}

#[test]
#[allow(unsafe_code)]
fn beacon_cleanup_process_null_is_noop() {
    unsafe { beacon_cleanup_process(std::ptr::null_mut()) };
}

#[cfg(not(windows))]
#[test]
#[allow(unsafe_code)]
fn beacon_is_admin_non_windows_returns_false() {
    assert_eq!(unsafe { beacon_is_admin() }, 0);
}

#[cfg(not(windows))]
#[test]
#[allow(unsafe_code)]
fn beacon_use_token_non_windows_returns_false() {
    assert_eq!(unsafe { beacon_use_token(0x1234) }, 0);
}

#[cfg(not(windows))]
#[test]
#[allow(unsafe_code)]
fn beacon_revert_token_non_windows_is_noop() {
    unsafe { beacon_revert_token() };
}
