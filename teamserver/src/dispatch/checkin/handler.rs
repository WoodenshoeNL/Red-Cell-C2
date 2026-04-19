use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use crate::agent_events::agent_mark_event;
use crate::{AgentRegistry, audit_details, parameter_object, record_operator_action};
use crate::{AuditResultStatus, Database, EventBus, PluginRuntime, TeamserverError};

use super::CommandDispatchError;
use super::parse::parse_checkin_metadata;

/// Handle a `COMMAND_CHECKIN` callback from an agent.
///
/// Parses and validates the payload, updates the agent registry, broadcasts an
/// "Alive" event, writes an audit entry, and notifies any loaded Python plugins.
/// Returns `Ok(None)` — checkin callbacks carry no response payload.
pub(in crate::dispatch) async fn handle_checkin(
    registry: &AgentRegistry,
    events: &EventBus,
    database: &Database,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let existing =
        registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
    let agent = if let Some(mut updated) =
        parse_checkin_metadata(existing.clone(), agent_id, payload, &timestamp)?
    {
        let key_rotation = updated.encryption != existing.encryption;

        if key_rotation {
            // SECURITY: The Demon binary protocol includes no nonce, timestamp, or
            // challenge-response in the COMMAND_CHECKIN payload, so the teamserver cannot
            // distinguish a fresh rotation from a replayed packet carrying a known key.  An
            // adversary who captures a CHECKIN frame can replay it to push the session key to a
            // value they control and then decrypt subsequent traffic or inject spoofed commands.
            //
            // To close the replay window entirely, key rotation is refused for all agents
            // regardless of whether they are direct or pivot-relayed.  Agents that genuinely need
            // new key material must go through a full DEMON_INIT re-registration, which is
            // protected by the mutual-auth handshake.
            let pivot_parent = registry.parent_of(agent_id).await.map(|p| format!("{p:08X}"));
            warn!(
                agent_id = format_args!("{agent_id:08X}"),
                pivot_parent,
                "refused AES session key rotation from CHECKIN payload — \
                 no replay/freshness guarantee in the Demon protocol; \
                 re-init required for legitimate key rotation"
            );
            updated.encryption = existing.encryption.clone();
        }

        // SECURITY: Demon and Archon agents carry no sequence number, timestamp, or
        // nonce in the COMMAND_CHECKIN payload.  Any captured CHECKIN frame can be
        // replayed successfully — AES decryption will pass and metadata will be
        // overwritten with the captured values.  Emit a warning so operators are
        // alerted when metadata is updated without replay protection.
        // Specter/Phantom agents are excluded: they carry a monotonic sequence number
        // (INIT_EXT_SEQ_PROTECTED) and their callbacks are validated by
        // `common::callback_seq`.  See also `common/src/callback_seq.rs` and
        // `docs/operator-security.md`.
        if !registry.is_seq_protected(agent_id).await {
            warn!(
                agent_id = format_args!("{agent_id:08X}"),
                "CHECKIN updated agent metadata without replay protection — \
                 Demon/Archon agents carry no sequence number; a captured CHECKIN \
                 frame can be replayed to overwrite hostname/username/IP/PID metadata. \
                 Migrate to Specter/Phantom to eliminate this risk."
            );
        }
        registry.update_agent(updated).await?;
        registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?
    } else {
        registry.set_last_call_in(agent_id, timestamp).await?
    };
    events.broadcast(agent_mark_event(&agent));
    // Write the audit entry inline so that SQLite write serialisation provides
    // natural backpressure.  A previous version spawned a detached task per
    // callback, which allowed unbounded task accumulation under aggressive
    // check-in rates (see red-cell-c2-3abpv).
    if let Err(error) = record_operator_action(
        database,
        "teamserver",
        "agent.checkin",
        "agent",
        Some(format!("{agent_id:08X}")),
        audit_details(
            AuditResultStatus::Success,
            Some(agent_id),
            Some("checkin"),
            Some(parameter_object([(
                "external_ip",
                serde_json::Value::String(agent.external_ip.clone()),
            )])),
        ),
    )
    .await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to persist agent.checkin audit entry");
    }
    if let Some(plugins) = plugins
        && let Err(error) = plugins.emit_agent_checkin(agent_id).await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python agent_checkin event");
    }
    Ok(None)
}
