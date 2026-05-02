//! ECDH registration flow (new agent, X25519 + AES-GCM).

use std::net::IpAddr;

use time::OffsetDateTime;
use tracing::warn;

use red_cell_common::crypto::ecdh::{ConnectionId, build_registration_response};

use crate::listeners::ListenerManagerError;
use crate::{
    AgentRegistry, AuditResultStatus, Database, PluginRuntime, agent_events::agent_new_event,
    audit_details, events::EventBus, parameter_object, record_operator_action,
    sockets::AgentSocketSnapshot,
};

use crate::demon::parse_ecdh_agent_metadata;

use super::types::EcdhResponse;

pub(crate) async fn process_ecdh_registration(
    listener_name: &str,
    session_key: [u8; 32],
    metadata: &[u8],
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    external_ip: IpAddr,
    listener_secret_bytes: Option<[u8; 32]>,
) -> Result<EcdhResponse, ListenerManagerError> {
    let now = OffsetDateTime::now_utc();
    let external_ip_str = external_ip.to_string();

    let (agent, legacy_ctr, seq_protected) =
        parse_ecdh_agent_metadata(metadata, &external_ip_str, now).map_err(|e| {
            ListenerManagerError::InvalidConfig {
                message: format!("ECDH metadata parse failed: {e}"),
            }
        })?;

    let agent_id = agent.agent_id;

    // Prepare all failable data before committing any state, so a failure
    // cannot leave a ghost agent row in the registry/database.
    let connection_id =
        ConnectionId::generate().map_err(|e| ListenerManagerError::InvalidConfig {
            message: format!("ECDH connection_id generation: {e}"),
        })?;

    let response =
        build_registration_response(&connection_id, &session_key, agent_id).map_err(|e| {
            ListenerManagerError::InvalidConfig {
                message: format!("ECDH build_registration_response failed: {e}"),
            }
        })?;

    // Persist ECDH session first — no FK on agent_id, so this is safe before
    // the agent row exists.  If the agent insert below fails we roll back.
    database.ecdh().store_session(&connection_id, agent_id, &session_key).await.map_err(|e| {
        ListenerManagerError::InvalidConfig { message: format!("ECDH session store failed: {e}") }
    })?;

    // Register in registry + DB.  The ECDH agent has no AES key — use zeros
    // (the session key is stored separately in ts_ecdh_sessions).
    if let Err(e) =
        registry.insert_full(agent.clone(), listener_name, 0, legacy_ctr, true, seq_protected).await
    {
        if let Err(cleanup_err) = database.ecdh().delete_session(&connection_id).await {
            warn!(
                agent_id = format_args!("{agent_id:08X}"),
                %cleanup_err,
                "failed to roll back ECDH session after agent insert failure"
            );
        }
        return Err(ListenerManagerError::InvalidConfig {
            message: format!("ECDH agent registry insert failed: {e}"),
        });
    }

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

    Ok(EcdhResponse { payload: response, agent_id, session_key, listener_secret_bytes })
}
