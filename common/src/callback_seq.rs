//! Monotonic callback sequence number validation for replay-attack prevention.
//!
//! Specter and Archon agents prefix every encrypted callback payload with an
//! 8-byte little-endian sequence number.  The teamserver rejects any callback
//! where the incoming sequence number is not strictly greater than the last
//! accepted one, preventing an attacker who captured a callback from replaying
//! it to revert agent metadata.
//!
//! # Known limitation — Demon agents
//!
//! The original Demon agent (C/ASM) is frozen: its wire format cannot be
//! changed.  Demon callbacks carry **no sequence number** and are therefore
//! exempt from this check.  An attacker who captures a Demon CHECKIN frame can
//! replay it to revert hostname/username/IP metadata.  The practical blast
//! radius is limited because the session key rotation guard in
//! `teamserver/src/dispatch/checkin.rs` still prevents cryptographic key
//! substitution.

use thiserror::Error;

/// Maximum allowed gap between the incoming sequence number and the last seen
/// one.  Gaps within this range are accepted to tolerate dropped in-flight
/// packets.  Gaps larger than this are rejected as suspicious (a future-seq
/// replay packet crafted by an attacker).
pub const MAX_SEQ_GAP: u64 = 10;

/// Length in bytes of the sequence number prefix in a seq-protected callback
/// payload.
pub const SEQ_PREFIX_BYTES: usize = 8;

/// Error returned when a callback sequence number is rejected.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CallbackSeqError {
    /// The incoming sequence number is not strictly greater than the last seen
    /// one — this is a replay or an out-of-order delivery.
    #[error(
        "callback replay detected for agent 0x{agent_id:08X}: \
         incoming seq {incoming_seq} <= last_seen_seq {last_seen_seq}"
    )]
    Replay {
        /// Agent for which the replay was detected.
        agent_id: u32,
        /// Sequence number carried in the incoming callback.
        incoming_seq: u64,
        /// Last sequence number accepted for this agent.
        last_seen_seq: u64,
    },

    /// The gap between the incoming and last-seen sequence numbers exceeds
    /// [`MAX_SEQ_GAP`], indicating a suspicious large jump (e.g. a crafted
    /// future-seq packet).
    #[error(
        "callback seq gap too large for agent 0x{agent_id:08X}: \
         incoming seq {incoming_seq}, last_seen_seq {last_seen_seq}, gap {gap} > {MAX_SEQ_GAP}"
    )]
    GapTooLarge {
        /// Agent for which the large gap was detected.
        agent_id: u32,
        /// Sequence number carried in the incoming callback.
        incoming_seq: u64,
        /// Last sequence number accepted for this agent.
        last_seen_seq: u64,
        /// Computed gap (`incoming_seq - last_seen_seq`).
        gap: u64,
    },

    /// The encrypted callback payload is too short to contain the 8-byte
    /// sequence number prefix.
    #[error(
        "seq-protected callback payload for agent 0x{agent_id:08X} is too short: \
         {actual} byte(s) < {SEQ_PREFIX_BYTES} required for seq prefix"
    )]
    PayloadTooShort {
        /// Agent for which the truncated payload was received.
        agent_id: u32,
        /// Actual payload length in bytes.
        actual: usize,
    },
}

/// Parse and validate a sequence number from the start of a seq-protected
/// callback payload.
///
/// Returns `(incoming_seq, remainder)` on success, where `remainder` is the
/// slice of `payload` that follows the 8-byte prefix.
///
/// # Errors
///
/// - [`CallbackSeqError::PayloadTooShort`] if `payload.len() < 8`.
/// - [`CallbackSeqError::Replay`] if `incoming_seq <= last_seen_seq`.
/// - [`CallbackSeqError::GapTooLarge`] if `incoming_seq - last_seen_seq > MAX_SEQ_GAP`.
pub fn extract_and_validate_seq(
    agent_id: u32,
    payload: &[u8],
    last_seen_seq: u64,
) -> Result<(u64, &[u8]), CallbackSeqError> {
    if payload.len() < SEQ_PREFIX_BYTES {
        return Err(CallbackSeqError::PayloadTooShort { agent_id, actual: payload.len() });
    }

    let mut seq_bytes = [0u8; SEQ_PREFIX_BYTES];
    seq_bytes.copy_from_slice(&payload[..SEQ_PREFIX_BYTES]);
    let incoming_seq = u64::from_le_bytes(seq_bytes);
    let remainder = &payload[SEQ_PREFIX_BYTES..];

    validate_seq(agent_id, incoming_seq, last_seen_seq)?;

    Ok((incoming_seq, remainder))
}

/// Validate that `incoming_seq` is acceptable given `last_seen_seq`.
///
/// Rejects replays (`incoming_seq <= last_seen_seq`) and suspiciously large
/// forward jumps (`incoming_seq - last_seen_seq > MAX_SEQ_GAP`).
pub fn validate_seq(
    agent_id: u32,
    incoming_seq: u64,
    last_seen_seq: u64,
) -> Result<(), CallbackSeqError> {
    if incoming_seq <= last_seen_seq {
        return Err(CallbackSeqError::Replay { agent_id, incoming_seq, last_seen_seq });
    }

    let gap = incoming_seq - last_seen_seq;
    if gap > MAX_SEQ_GAP {
        return Err(CallbackSeqError::GapTooLarge { agent_id, incoming_seq, last_seen_seq, gap });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT_ID: u32 = 0xDEAD_BEEF;

    // ── validate_seq ───────────────────────────────────────────────────────────

    #[test]
    fn validate_seq_accepts_next_expected() {
        validate_seq(AGENT_ID, 1, 0).expect("seq 0→1 must be accepted");
        validate_seq(AGENT_ID, 5, 4).expect("seq 4→5 must be accepted");
    }

    #[test]
    fn validate_seq_accepts_gap_at_max_boundary() {
        // gap == MAX_SEQ_GAP should be accepted
        validate_seq(AGENT_ID, MAX_SEQ_GAP, 0).expect("gap equal to MAX_SEQ_GAP must be accepted");
    }

    #[test]
    fn validate_seq_rejects_gap_one_over_max() {
        let err = validate_seq(AGENT_ID, MAX_SEQ_GAP + 1, 0)
            .expect_err("gap of MAX_SEQ_GAP+1 must be rejected");
        match err {
            CallbackSeqError::GapTooLarge { incoming_seq, last_seen_seq, gap, .. } => {
                assert_eq!(incoming_seq, MAX_SEQ_GAP + 1);
                assert_eq!(last_seen_seq, 0);
                assert_eq!(gap, MAX_SEQ_GAP + 1);
            }
            other => panic!("expected GapTooLarge, got: {other:?}"),
        }
    }

    #[test]
    fn validate_seq_rejects_same_seq() {
        let err = validate_seq(AGENT_ID, 5, 5).expect_err("same seq must be rejected as replay");
        match err {
            CallbackSeqError::Replay { incoming_seq, last_seen_seq, .. } => {
                assert_eq!(incoming_seq, 5);
                assert_eq!(last_seen_seq, 5);
            }
            other => panic!("expected Replay, got: {other:?}"),
        }
    }

    #[test]
    fn validate_seq_rejects_lower_seq() {
        let err = validate_seq(AGENT_ID, 3, 7).expect_err("lower seq must be rejected as replay");
        match err {
            CallbackSeqError::Replay { incoming_seq, last_seen_seq, .. } => {
                assert_eq!(incoming_seq, 3);
                assert_eq!(last_seen_seq, 7);
            }
            other => panic!("expected Replay, got: {other:?}"),
        }
    }

    #[test]
    fn validate_seq_rejects_zero_when_last_seen_is_zero() {
        // seq=0 is never valid since last_seen_seq starts at 0
        let err = validate_seq(AGENT_ID, 0, 0).expect_err("seq=0 with last_seen=0 is a replay");
        assert!(matches!(err, CallbackSeqError::Replay { .. }));
    }

    // ── extract_and_validate_seq ───────────────────────────────────────────────

    #[test]
    fn extract_and_validate_seq_accepts_valid_prefix() {
        let seq: u64 = 42;
        let mut payload = seq.to_le_bytes().to_vec();
        payload.extend_from_slice(b"hello");

        let (extracted_seq, remainder) =
            extract_and_validate_seq(AGENT_ID, &payload, 41).expect("valid seq must succeed");
        assert_eq!(extracted_seq, 42);
        assert_eq!(remainder, b"hello");
    }

    #[test]
    fn extract_and_validate_seq_rejects_too_short() {
        let payload = [0u8; 7]; // one byte short
        let err = extract_and_validate_seq(AGENT_ID, &payload, 0)
            .expect_err("payload shorter than 8 bytes must be rejected");
        match err {
            CallbackSeqError::PayloadTooShort { actual, .. } => {
                assert_eq!(actual, 7);
            }
            other => panic!("expected PayloadTooShort, got: {other:?}"),
        }
    }

    #[test]
    fn extract_and_validate_seq_rejects_replay() {
        let seq: u64 = 5;
        let payload = seq.to_le_bytes();
        let err = extract_and_validate_seq(AGENT_ID, &payload, 5)
            .expect_err("replay seq must be rejected");
        assert!(matches!(err, CallbackSeqError::Replay { .. }));
    }

    #[test]
    fn extract_and_validate_seq_rejects_large_gap() {
        let seq: u64 = MAX_SEQ_GAP + 2;
        let payload = seq.to_le_bytes();
        let err = extract_and_validate_seq(AGENT_ID, &payload, 0)
            .expect_err("large gap must be rejected");
        assert!(matches!(err, CallbackSeqError::GapTooLarge { .. }));
    }

    #[test]
    fn extract_and_validate_seq_empty_remainder() {
        // Payload is exactly 8 bytes — remainder should be empty.
        let seq: u64 = 1;
        let payload = seq.to_le_bytes();
        let (extracted_seq, remainder) =
            extract_and_validate_seq(AGENT_ID, &payload, 0).expect("8-byte payload must succeed");
        assert_eq!(extracted_seq, 1);
        assert!(remainder.is_empty(), "remainder should be empty for 8-byte payload");
    }

    // ── little-endian byte-order conformance (C agent interop) ────────────────
    //
    // These tests use hardcoded byte sequences rather than Rust's to_le_bytes() so
    // that a future endianness regression is caught at the byte level, matching
    // what the C Demon/Archon agent actually writes to the wire.

    #[test]
    fn extract_seq_le_byte_order_known_vector() {
        // C agent writes seq=42 as [0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] (little-endian).
        let payload: [u8; 8] = [0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (seq, remainder) =
            extract_and_validate_seq(AGENT_ID, &payload, 41).expect("seq=42 must be accepted");
        assert_eq!(seq, 42, "seq=42 must be parsed from known LE bytes");
        assert!(remainder.is_empty());
    }

    #[test]
    fn extract_seq_le_byte_order_big_value() {
        // C agent writes seq=0x0102_0304_0506_0708 as LE: lowest byte first.
        // Use last_seen one below the expected value so gap=1 and GapTooLarge does not fire.
        const EXPECTED: u64 = 0x0102_0304_0506_0708;
        let payload: [u8; 8] = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let (seq, _) = extract_and_validate_seq(AGENT_ID, &payload, EXPECTED - 1)
            .expect("seq must be accepted");
        assert_eq!(seq, EXPECTED, "multi-byte LE parsing must match C agent byte order");
    }

    #[test]
    fn extract_seq_not_big_endian() {
        // Verify the raw LE byte interpretation without running through the gap check
        // (which would reject a large number relative to last_seen=0 as GapTooLarge).
        // [0x00, ..., 0x2A] in LE = 0x2A00_0000_0000_0000, NOT 0x2A (big-endian).
        let be_42: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A];
        let seq = u64::from_le_bytes(be_42);
        assert_eq!(
            seq, 0x2A00_0000_0000_0000,
            "LE parse of [0x00...0x2A] must yield 0x2A00_0000_0000_0000, not 42 (big-endian)"
        );
        // Confirm the inverse: 42 in LE requires the 0x2A byte at offset 0.
        let le_42: [u8; 8] = [0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(u64::from_le_bytes(le_42), 42);
    }

    // ── u64::MAX wraparound (session exhaustion) ──────────────────────────────
    //
    // When the sequence counter reaches u64::MAX there is no valid next value
    // (u64 cannot exceed MAX). This is a permanent session-death condition.
    // Recovery requires re-registration (reregister_full resets last_seen_seq to 0).
    // These tests document the expected behaviour so a future implementation of
    // counter wraparound or session expiry does not silently regress the invariant.

    #[test]
    fn validate_seq_accepts_u64_max_when_last_seen_is_max_minus_one() {
        // seq=u64::MAX with last_seen=u64::MAX-1: gap=1, must be accepted.
        validate_seq(AGENT_ID, u64::MAX, u64::MAX - 1)
            .expect("seq=u64::MAX must be accepted when last_seen=u64::MAX-1");
    }

    #[test]
    fn validate_seq_rejects_all_values_when_last_seen_is_u64_max() {
        // Once last_seen_seq == u64::MAX, no incoming_seq can be > MAX (u64 overflow).
        // Any attempt must be rejected as Replay (incoming_seq <= last_seen_seq for all u64).
        let err = validate_seq(AGENT_ID, u64::MAX, u64::MAX)
            .expect_err("seq=MAX when last_seen=MAX must be rejected as replay");
        assert!(
            matches!(err, CallbackSeqError::Replay { .. }),
            "expected Replay at u64::MAX boundary, got: {err:?}"
        );

        // Also verify that 0 (which would be a wraparound) is rejected — not silently accepted.
        let err = validate_seq(AGENT_ID, 0, u64::MAX)
            .expect_err("seq=0 when last_seen=u64::MAX must be rejected (no wraparound)");
        assert!(
            matches!(err, CallbackSeqError::Replay { .. }),
            "expected Replay for seq=0 after u64::MAX, got: {err:?}"
        );
    }

    #[test]
    fn validate_seq_near_u64_max_gap_boundary() {
        // last_seen = u64::MAX - MAX_SEQ_GAP: incoming = u64::MAX should be accepted (gap = MAX_SEQ_GAP).
        let last_seen = u64::MAX - MAX_SEQ_GAP;
        validate_seq(AGENT_ID, u64::MAX, last_seen)
            .expect("gap=MAX_SEQ_GAP near u64::MAX must be accepted");

        // one step further back: gap would be MAX_SEQ_GAP + 1, must be rejected.
        let last_seen_one_back = u64::MAX - MAX_SEQ_GAP - 1;
        let err = validate_seq(AGENT_ID, u64::MAX, last_seen_one_back)
            .expect_err("gap=MAX_SEQ_GAP+1 near u64::MAX must be rejected");
        assert!(
            matches!(err, CallbackSeqError::GapTooLarge { .. }),
            "expected GapTooLarge near u64::MAX boundary, got: {err:?}"
        );
    }
}
