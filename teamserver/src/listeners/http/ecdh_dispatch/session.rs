//! ECDH session packet flow (existing connection_id).

use red_cell_common::crypto::ecdh::{open_session_packet, seal_session_response};
use red_cell_common::demon::DemonPackage;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use crate::AgentRegistry;
use crate::database::ecdh::EcdhRepository;
use crate::events::broadcast_teamserver_line;
use crate::listeners::ListenerManagerError;
use crate::{CommandDispatcher, DemonCallbackPackage, EventBus};

use super::parse::{parse_ecdh_session_payload, parse_seq_num_prefix};
use super::types::EcdhResponse;

/// Infrastructure dependencies for processing an ECDH session packet.
pub(crate) struct EcdhSessionContext<'a> {
    pub(crate) ecdh_db: EcdhRepository,
    pub(crate) registry: &'a AgentRegistry,
    pub(crate) dispatcher: &'a CommandDispatcher,
    pub(crate) events: &'a EventBus,
    pub(crate) listener_name: &'a str,
}

pub(crate) async fn process_ecdh_session(
    body: &[u8],
    session_key: &[u8; 32],
    agent_id: u32,
    connection_id: &[u8; 16],
    ctx: EcdhSessionContext<'_>,
) -> Result<EcdhResponse, ListenerManagerError> {
    let EcdhSessionContext { ecdh_db, registry, dispatcher, events, listener_name } = ctx;

    // body = [connection_id: 16] | [nonce: 12] | [ciphertext] | [tag: 16]
    let decrypted = open_session_packet(session_key, &body[16..]).map_err(|e| {
        let msg = format!("ECDH session decrypt failed: {e}");
        let text = format!("[listener={listener_name}] agent={agent_id:08X} {msg}");
        broadcast_teamserver_line(events, "teamserver", &text);
        warn!(listener = listener_name, agent_id = format_args!("{agent_id:08X}"), %e, "ECDH session decrypt failed");
        ListenerManagerError::InvalidConfig { message: msg }
    })?;

    let packages: Vec<DemonCallbackPackage> = if decrypted.is_empty() {
        Vec::new()
    } else {
        let (seq_num, payload) =
            parse_seq_num_prefix(&decrypted).map_err(|e| {
                let msg = format!("ECDH session seq_num prefix: {e}");
                let text = format!("[listener={listener_name}] agent={agent_id:08X} {msg}");
                broadcast_teamserver_line(events, "teamserver", &text);
                warn!(listener = listener_name, agent_id = format_args!("{agent_id:08X}"), error = %e, "ECDH seq_num prefix parse failed");
                ListenerManagerError::InvalidConfig {
                    message: msg,
                }
            })?;

        // Reject replays: seq_num must be strictly greater than the last accepted.
        let accepted = ecdh_db.advance_seq_num(connection_id, seq_num).await.map_err(|e| {
            let msg = format!("ECDH seq_num DB update failed: {e}");
            let text = format!("[listener={listener_name}] agent={agent_id:08X} {msg}");
            broadcast_teamserver_line(events, "teamserver", &text);
            warn!(listener = listener_name, agent_id = format_args!("{agent_id:08X}"), %e, "ECDH seq_num DB update failed");
            ListenerManagerError::InvalidConfig {
                message: msg,
            }
        })?;

        if !accepted {
            let msg = format!("ECDH session replay detected: seq_num {seq_num} already seen");
            let text = format!("[listener={listener_name}] agent={agent_id:08X} {msg}");
            broadcast_teamserver_line(events, "teamserver", &text);
            warn!(
                listener = listener_name,
                agent_id = format_args!("{agent_id:08X}"),
                seq_num,
                "ECDH session replay rejected"
            );
            return Err(ListenerManagerError::InvalidConfig { message: msg });
        }

        parse_ecdh_session_payload(payload)
            .map_err(|e| {
                let msg = format!("ECDH session payload parse failed: {e}");
                let text = format!("[listener={listener_name}] agent={agent_id:08X} {msg}");
                broadcast_teamserver_line(events, "teamserver", &text);
                warn!(listener = listener_name, agent_id = format_args!("{agent_id:08X}"), error = %e, "ECDH session inner payload parse failed");
                ListenerManagerError::InvalidConfig {
                    message: msg,
                }
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

    // Refresh the agent's last_call_in so the liveness monitor does not mark the
    // agent dead while it is actively communicating via ECDH callback packets
    // (which do not contain CommandCheckin).
    if let Ok(ts) = OffsetDateTime::now_utc().format(&Rfc3339) {
        let _ = registry.set_last_call_in(agent_id, ts).await;
    }

    let response_bytes = match dispatcher.dispatch_packages(agent_id, &packages).await {
        Ok(bytes) => bytes,
        Err(error) => {
            let text = format!(
                "[listener={listener_name}] agent={agent_id:08X} ECDH callback dispatch failed: {error}"
            );
            broadcast_teamserver_line(events, "teamserver", &text);
            warn!(
                listener = listener_name,
                agent_id = format_args!("{agent_id:08X}"),
                %error,
                "ECDH callback dispatch failed"
            );
            return Err(ListenerManagerError::InvalidConfig { message: error.to_string() });
        }
    };

    let sealed = seal_session_response(session_key, &response_bytes).map_err(|e| {
        let msg = format!("ECDH seal_session_response failed: {e}");
        let text = format!("[listener={listener_name}] agent={agent_id:08X} {msg}");
        broadcast_teamserver_line(events, "teamserver", &text);
        warn!(listener = listener_name, agent_id = format_args!("{agent_id:08X}"), %e, "ECDH seal_session_response failed");
        ListenerManagerError::InvalidConfig { message: msg }
    })?;

    Ok(EcdhResponse { payload: sealed })
}
