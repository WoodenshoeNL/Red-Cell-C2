//! Init and reconnect ACK construction for Demon transport.

use super::DemonParserError;
use crate::TeamserverError;

/// Build the encrypted acknowledgement body returned after a Demon init request.
pub async fn build_init_ack(
    registry: &crate::AgentRegistry,
    agent_id: u32,
) -> Result<Vec<u8>, DemonParserError> {
    let payload = agent_id.to_le_bytes();
    registry
        .encrypt_for_agent(agent_id, &payload)
        .await
        .map_err(|e| lift_crypto_encoding_error(agent_id, e))
}

/// Build the encrypted acknowledgement body returned for a reconnect probe.
///
/// # Protocol design intent — reconnect ACK is **not counter-consuming**
///
/// A reconnect probe (`DEMON_INIT` with an empty payload) carries no encrypted data, so the
/// agent does not advance its CTR block counter when sending it.  The reconnect ACK response
/// is the one piece of traffic where server and agent diverge from the usual rule "every
/// encrypted message advances both counters by `ctr_blocks_for_len(len)` blocks":
///
/// - **Server side**: the ACK is encrypted at the *current* stored CTR offset, and that
///   offset is **not advanced** afterwards (hence `encrypt_for_agent_without_advancing`).
/// - **Agent side**: the agent must treat the reconnect ACK as a synchronisation marker and
///   also **not advance** its local counter after receiving it.
///
/// The result is that after a reconnect handshake both parties remain at the same offset
/// they held before the reconnect, and the very next agent callback/response pair continues
/// from that position without any skipped or replayed keystream blocks.
///
/// If an agent implementation incorrectly advances its counter by one block after receiving
/// the reconnect ACK (mirroring the init-ACK handling), its next outbound message will be
/// encrypted at `offset + 1` while the server will attempt to decrypt it at `offset`,
/// causing a permanent session desync.  The end-to-end test
/// `reconnect_then_subsequent_callback_remains_synchronised` in
/// `teamserver/tests/mock_demon_agent_checkin.rs` exercises this contract explicitly.
pub async fn build_reconnect_ack(
    registry: &crate::AgentRegistry,
    agent_id: u32,
) -> Result<Vec<u8>, DemonParserError> {
    let payload = agent_id.to_le_bytes();
    registry
        .encrypt_for_agent_without_advancing(agent_id, &payload)
        .await
        .map_err(|e| lift_crypto_encoding_error(agent_id, e))
}

/// Lift a [`TeamserverError::InvalidPersistedValue`] for AES key/IV fields into the
/// more specific [`DemonParserError::InvalidStoredCryptoEncoding`] variant, preserving
/// the originating agent identifier.  All other errors pass through as
/// [`DemonParserError::Registry`].
pub(crate) fn lift_crypto_encoding_error(
    agent_id: u32,
    error: TeamserverError,
) -> DemonParserError {
    match error {
        TeamserverError::InvalidPersistedValue { field, message }
            if field == "aes_key" || field == "aes_iv" =>
        {
            DemonParserError::InvalidStoredCryptoEncoding { agent_id, field, message }
        }
        other => DemonParserError::Registry(other),
    }
}
