//! ECDH session payload parsing helpers.

use red_cell_common::demon::{DemonMessage, DemonPackage};

/// Strip the 8-byte little-endian seq_num prefix from the decrypted session payload.
///
/// Returns `(seq_num, remaining_bytes)`.
pub(crate) fn parse_seq_num_prefix(decrypted: &[u8]) -> Result<(u64, &[u8]), &'static str> {
    if decrypted.len() < 8 {
        return Err("payload too short for seq_num prefix (need ≥ 8 bytes)");
    }
    let seq_num = u64::from_le_bytes([
        decrypted[0],
        decrypted[1],
        decrypted[2],
        decrypted[3],
        decrypted[4],
        decrypted[5],
        decrypted[6],
        decrypted[7],
    ]);
    Ok((seq_num, &decrypted[8..]))
}

pub(crate) fn parse_ecdh_session_payload(bytes: &[u8]) -> Result<Vec<DemonPackage>, String> {
    DemonMessage::from_bytes(bytes)
        .map(|msg| msg.packages)
        .map_err(|e| format!("DemonMessage parse: {e}"))
}
