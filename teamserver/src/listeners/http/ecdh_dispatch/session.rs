//! ECDH session packet flow (existing connection_id).

use red_cell_common::crypto::ecdh::{open_session_packet, seal_session_response};
use red_cell_common::demon::DemonPackage;

use crate::database::ecdh::EcdhRepository;
use crate::listeners::ListenerManagerError;
use crate::{CommandDispatcher, DemonCallbackPackage};

use super::parse::{parse_ecdh_session_payload, parse_seq_num_prefix};
use super::types::EcdhResponse;

pub(crate) async fn process_ecdh_session(
    body: &[u8],
    session_key: &[u8; 32],
    agent_id: u32,
    connection_id: &[u8; 16],
    ecdh_db: EcdhRepository,
    dispatcher: &CommandDispatcher,
) -> Result<EcdhResponse, ListenerManagerError> {
    // body = [connection_id: 16] | [nonce: 12] | [ciphertext] | [tag: 16]
    let decrypted = open_session_packet(session_key, &body[16..]).map_err(|e| {
        ListenerManagerError::InvalidConfig { message: format!("ECDH session decrypt failed: {e}") }
    })?;

    let packages: Vec<DemonCallbackPackage> = if decrypted.is_empty() {
        Vec::new()
    } else {
        let (seq_num, payload) =
            parse_seq_num_prefix(&decrypted).map_err(|e| ListenerManagerError::InvalidConfig {
                message: format!("ECDH session seq_num prefix: {e}"),
            })?;

        // Reject replays: seq_num must be strictly greater than the last accepted.
        let accepted = ecdh_db.advance_seq_num(connection_id, seq_num).await.map_err(|e| {
            ListenerManagerError::InvalidConfig {
                message: format!("ECDH seq_num DB update failed: {e}"),
            }
        })?;

        if !accepted {
            return Err(ListenerManagerError::InvalidConfig {
                message: format!("ECDH session replay detected: seq_num {seq_num} already seen"),
            });
        }

        parse_ecdh_session_payload(payload)
            .map_err(|e| ListenerManagerError::InvalidConfig {
                message: format!("ECDH session payload parse failed: {e}"),
            })?
            .into_iter()
            .map(|p: DemonPackage| DemonCallbackPackage {
                command_id: p.command_id,
                request_id: p.request_id,
                payload: p.payload,
            })
            .collect()
    };

    // Packet is authenticated and seq-validated — now it is safe to refresh liveness.
    let _ = ecdh_db.touch_session(connection_id).await;

    let response_bytes = dispatcher
        .dispatch_packages(agent_id, &packages)
        .await
        .map_err(|e| ListenerManagerError::InvalidConfig { message: e.to_string() })?;

    let sealed = seal_session_response(session_key, &response_bytes).map_err(|e| {
        ListenerManagerError::InvalidConfig {
            message: format!("ECDH seal_session_response failed: {e}"),
        }
    })?;

    Ok(EcdhResponse { payload: sealed })
}
