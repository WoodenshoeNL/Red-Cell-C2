//! ECDH packet processing for Phantom and Specter new-protocol agents.
//!
//! Incoming packets are classified as:
//! - **Registration**: first 16 bytes do NOT match a known `connection_id` in the DB,
//!   and length ≥ `ECDH_REG_MIN_LEN`. The server performs ECDH, registers the agent,
//!   and returns a response containing a new `ConnectionId` + encrypted ack.
//! - **Session**: first 16 bytes match a `connection_id` in the DB. The server decrypts
//!   the payload with the session key, routes to the command dispatcher, and returns
//!   an encrypted response.

use std::net::IpAddr;

use time::OffsetDateTime;
use tracing::{debug, warn};

use red_cell_common::crypto::ecdh::{
    ConnectionId, ECDH_REG_MIN_LEN, ListenerKeypair, build_registration_response,
    extract_connection_id_candidate, open_registration_packet, open_session_packet,
    seal_session_response,
};
use red_cell_common::demon::{DemonMessage, DemonPackage};

use crate::database::ecdh::EcdhRepository;

use crate::demon::parse_ecdh_agent_metadata;
use crate::listeners::ListenerManagerError;
use crate::{
    AgentRegistry, AuditResultStatus, CommandDispatcher, Database, DemonCallbackPackage,
    PluginRuntime, agent_events::agent_new_event, audit_details, events::EventBus,
    parameter_object, record_operator_action, sockets::AgentSocketSnapshot,
};

/// Replay-protection window: registration packets older or newer than this are rejected.
pub(crate) const ECDH_REPLAY_WINDOW_SECS: u64 = 300;

/// Result of processing an ECDH packet.
#[derive(Debug)]
pub(crate) struct EcdhResponse {
    pub(crate) payload: Vec<u8>,
}

/// Process a non-legacy HTTP body as an ECDH new-protocol packet.
///
/// First tries to classify as a session packet (connection_id lookup), then as
/// a registration packet. Returns `None` if the packet is not a valid ECDH packet
/// (caller should fall through to the Archon handler).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn process_ecdh_packet(
    listener_name: &str,
    keypair: Option<&ListenerKeypair>,
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    dispatcher: &CommandDispatcher,
    body: &[u8],
    external_ip: IpAddr,
) -> Result<Option<EcdhResponse>, ListenerManagerError> {
    let ecdh_db = database.ecdh();

    // Try session first: look up the first 16 bytes as a connection_id.
    if let Some(candidate_id) = extract_connection_id_candidate(body) {
        if let Ok(Some((agent_id, session_key))) = ecdh_db.lookup_session(&candidate_id).await {
            // Update last_seen in the background — non-critical.
            let ecdh_db2 = ecdh_db.clone();
            tokio::spawn(async move {
                let _ = ecdh_db2.touch_session(&candidate_id).await;
            });

            return Ok(Some(
                process_ecdh_session(
                    body,
                    &session_key,
                    agent_id,
                    &candidate_id,
                    ecdh_db,
                    dispatcher,
                )
                .await?,
            ));
        }
    }

    // Try registration.
    let Some(kp) = keypair else {
        // Non-legacy listener without a keypair cannot handle ECDH registration.
        return Ok(None);
    };

    if body.len() < ECDH_REG_MIN_LEN {
        return Ok(None);
    }

    let parsed = match open_registration_packet(kp, ECDH_REPLAY_WINDOW_SECS, body) {
        Ok(parsed) => parsed,
        Err(e) => {
            debug!(listener = listener_name, error = %e, "ECDH registration packet failed to decrypt");
            return Ok(None);
        }
    };

    Ok(Some(
        process_ecdh_registration(
            listener_name,
            parsed.session_key,
            &parsed.metadata,
            registry,
            database,
            events,
            external_ip,
        )
        .await?,
    ))
}

async fn process_ecdh_registration(
    listener_name: &str,
    session_key: [u8; 32],
    metadata: &[u8],
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    external_ip: IpAddr,
) -> Result<EcdhResponse, ListenerManagerError> {
    let now = OffsetDateTime::now_utc();
    let external_ip_str = external_ip.to_string();

    let (agent, legacy_ctr, _seq_protected) =
        parse_ecdh_agent_metadata(metadata, &external_ip_str, now).map_err(|e| {
            ListenerManagerError::InvalidConfig {
                message: format!("ECDH metadata parse failed: {e}"),
            }
        })?;

    let agent_id = agent.agent_id;

    // Register in registry + DB.  The ECDH agent has no AES key — use zeros
    // (the session key is stored separately in ts_ecdh_sessions).
    registry.insert_full(agent.clone(), listener_name, 0, legacy_ctr, true).await.map_err(|e| {
        ListenerManagerError::InvalidConfig {
            message: format!("ECDH agent registry insert failed: {e}"),
        }
    })?;

    // Persist ECDH session: connection_id → (agent_id, session_key).
    let connection_id =
        ConnectionId::generate().map_err(|e| ListenerManagerError::InvalidConfig {
            message: format!("ECDH connection_id generation: {e}"),
        })?;

    database.ecdh().store_session(&connection_id, agent_id, &session_key).await.map_err(|e| {
        ListenerManagerError::InvalidConfig { message: format!("ECDH session store failed: {e}") }
    })?;

    // Build the registration response.
    let response =
        build_registration_response(&connection_id, &session_key, agent_id).map_err(|e| {
            ListenerManagerError::InvalidConfig {
                message: format!("ECDH build_registration_response failed: {e}"),
            }
        })?;

    // Emit events and audit.
    let pivots = registry.pivots(agent_id).await;
    events.broadcast(agent_new_event(
        listener_name,
        0, // no plaintext magic for new protocol
        &agent,
        &pivots,
        AgentSocketSnapshot::default(),
    ));

    let listener_name_for_audit = listener_name.to_owned();
    let external_ip_for_audit = external_ip.to_string();
    if let Err(error) = record_operator_action(
        database,
        "teamserver",
        "agent.registered",
        "agent",
        Some(format!("{agent_id:08X}")),
        audit_details(
            AuditResultStatus::Success,
            Some(agent_id),
            Some("registered"),
            Some(parameter_object([
                ("listener", serde_json::Value::String(listener_name_for_audit)),
                ("external_ip", serde_json::Value::String(external_ip_for_audit)),
                ("protocol", serde_json::Value::String("ecdh".into())),
            ])),
        ),
    )
    .await
    {
        warn!(
            listener = listener_name,
            agent_id = format_args!("{agent_id:08X}"),
            %error,
            "failed to persist ECDH agent.registered audit entry"
        );
    }

    if let Ok(Some(plugins)) = PluginRuntime::current() {
        if let Err(error) = plugins.emit_agent_registered(agent_id).await {
            tracing::warn!(
                agent_id = format_args!("{agent_id:08X}"),
                %error,
                "failed to emit python agent_registered event (ECDH)"
            );
        }
    }

    Ok(EcdhResponse { payload: response })
}

async fn process_ecdh_session(
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

/// Strip the 8-byte little-endian seq_num prefix from the decrypted session payload.
///
/// Returns `(seq_num, remaining_bytes)`.
fn parse_seq_num_prefix(decrypted: &[u8]) -> Result<(u64, &[u8]), &'static str> {
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

fn parse_ecdh_session_payload(bytes: &[u8]) -> Result<Vec<DemonPackage>, String> {
    DemonMessage::from_bytes(bytes)
        .map(|msg| msg.packages)
        .map_err(|e| format!("DemonMessage parse: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_seq_num_prefix_round_trips() {
        let seq: u64 = 0xDEAD_BEEF_1234_5678;
        let payload = b"hello world";
        let mut buf = seq.to_le_bytes().to_vec();
        buf.extend_from_slice(payload);

        let (got_seq, got_payload) = parse_seq_num_prefix(&buf).expect("parse");
        assert_eq!(got_seq, seq);
        assert_eq!(got_payload, payload);
    }

    #[test]
    fn parse_seq_num_prefix_zero() {
        let mut buf = 0u64.to_le_bytes().to_vec();
        buf.push(0xAB);
        let (seq, rest) = parse_seq_num_prefix(&buf).expect("parse");
        assert_eq!(seq, 0);
        assert_eq!(rest, &[0xAB]);
    }

    #[test]
    fn parse_seq_num_prefix_exact_8_bytes() {
        let buf = 42u64.to_le_bytes().to_vec();
        let (seq, rest) = parse_seq_num_prefix(&buf).expect("parse");
        assert_eq!(seq, 42);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_seq_num_prefix_too_short_fails() {
        assert!(parse_seq_num_prefix(&[0u8; 7]).is_err());
        assert!(parse_seq_num_prefix(&[]).is_err());
    }
}
