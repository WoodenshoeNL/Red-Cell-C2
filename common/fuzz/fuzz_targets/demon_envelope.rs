//! Fuzz harness for the Demon transport envelope and header parsers.
//!
//! Targets:
//! - [`DemonHeader::from_bytes`] — 12-byte big-endian header (size, magic, agent_id)
//! - [`DemonEnvelope::from_bytes`] — full transport frame (header + payload)
//!
//! Invariants checked:
//! 1. Neither parser ever panics on arbitrary input.
//! 2. A successfully parsed envelope round-trips through `to_bytes` and
//!    re-parses to an identical value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use red_cell_common::demon::{DemonEnvelope, DemonHeader};

fuzz_target!(|data: &[u8]| {
    // Target 1: header-only parser.
    let _ = DemonHeader::from_bytes(data);

    // Target 2: full envelope parser.
    if let Ok(envelope) = DemonEnvelope::from_bytes(data) {
        // Round-trip invariant: serialize → re-parse must yield the same value.
        let reencoded = envelope.to_bytes();
        let reparsed = DemonEnvelope::from_bytes(&reencoded)
            .expect("re-serialized envelope must parse without error");
        assert_eq!(
            envelope, reparsed,
            "envelope round-trip produced a different value"
        );
    }
});
