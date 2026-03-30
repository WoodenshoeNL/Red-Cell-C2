//! Fuzz harness for the Demon package and message parsers.
//!
//! Targets:
//! - [`DemonPackage::from_bytes`] — single little-endian command package
//! - [`DemonMessage::from_bytes`] — stream of consecutive packages
//!
//! Invariants checked:
//! 1. Neither parser ever panics on arbitrary input.
//! 2. A successfully parsed package round-trips through `to_bytes` and
//!    re-parses to an identical value.
//! 3. A successfully parsed message round-trips through `to_bytes` and
//!    re-parses to an identical value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use red_cell_common::demon::{DemonMessage, DemonPackage};

fuzz_target!(|data: &[u8]| {
    // Target 1: single-package exact-length parser.
    if let Ok(package) = DemonPackage::from_bytes(data) {
        let reencoded = package.to_bytes().expect("parsed package must re-encode");
        let reparsed = DemonPackage::from_bytes(&reencoded)
            .expect("re-serialized package must parse without error");
        assert_eq!(package, reparsed, "package round-trip produced a different value");
    }

    // Target 2: multi-package stream parser.
    if let Ok(message) = DemonMessage::from_bytes(data) {
        let reencoded = message.to_bytes().expect("parsed message must re-encode");
        let reparsed = DemonMessage::from_bytes(&reencoded)
            .expect("re-serialized message must parse without error");
        assert_eq!(message, reparsed, "message round-trip produced a different value");
    }
});
