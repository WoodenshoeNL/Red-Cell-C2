//! Stale-agent sweep: detection, marking, and side-effect dispatch.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use crate::{
    AgentRegistry, AuditResultStatus, Database, EventBus, PluginRuntime, SocketRelayManager,
    TeamserverError, agent_events::agent_mark_event, audit_details, parameter_object,
    record_operator_action,
};

use super::config::{AgentLivenessConfig, StaleAgent};

pub(super) async fn sweep_dead_agents_at(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    database: &Database,
    config: AgentLivenessConfig,
    now: OffsetDateTime,
) -> Result<Vec<u32>, TeamserverError> {
    let stale_agents = collect_stale_agents(registry, config, now).await;
    let mut dead_agent_ids = Vec::new();

    for stale_agent in stale_agents {
        if mark_stale_agent_if_unchanged(registry, events, database, &stale_agent).await? {
            dead_agent_ids.push(stale_agent.agent_id);
        }
    }

    if !dead_agent_ids.is_empty() {
        sockets.prune_stale_agents().await;
    }

    dead_agent_ids.sort_unstable();
    Ok(dead_agent_ids)
}

pub(super) async fn mark_stale_agent_if_unchanged(
    registry: &AgentRegistry,
    events: &EventBus,
    database: &Database,
    stale_agent: &StaleAgent,
) -> Result<bool, TeamserverError> {
    let Some(current) = registry.get(stale_agent.agent_id).await else {
        return Ok(false);
    };
    if !current.active || current.last_call_in != stale_agent.last_call_in {
        return Ok(false);
    }

    let reason =
        format!("agent timed out after {} seconds without callback", stale_agent.timeout_secs);
    registry.mark_dead(stale_agent.agent_id, reason.clone()).await?;

    if let Some(agent) = registry.get(stale_agent.agent_id).await {
        events.broadcast(agent_mark_event(&agent));

        // Write the audit entry inline so that SQLite write serialisation
        // provides natural backpressure.  A previous version spawned a detached
        // task per dead-agent event, which allowed unbounded task accumulation
        // (same class of bug as red-cell-c2-3abpv in checkin.rs).
        let agent_id = stale_agent.agent_id;
        if let Err(error) = record_operator_action(
            database,
            "teamserver",
            "agent.dead",
            "agent",
            Some(format!("{agent_id:08X}")),
            audit_details(
                AuditResultStatus::Success,
                Some(agent_id),
                Some("dead"),
                Some(parameter_object([
                    ("reason", serde_json::Value::String(reason)),
                    ("external_ip", serde_json::Value::String(agent.external_ip.clone())),
                ])),
            ),
        )
        .await
        {
            warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to persist agent.dead audit entry");
        }
    }

    if let Ok(Some(plugins)) = PluginRuntime::current() {
        if let Err(error) = plugins.emit_agent_dead(stale_agent.agent_id).await {
            warn!(agent_id = format_args!("{:08X}", stale_agent.agent_id), %error, "failed to emit python agent_dead event");
        }
    }

    Ok(true)
}

pub(super) async fn collect_stale_agents(
    registry: &AgentRegistry,
    config: AgentLivenessConfig,
    now: OffsetDateTime,
) -> Vec<StaleAgent> {
    let mut stale_agents = Vec::new();

    for agent in registry.list_active().await {
        let timeout_secs = config.timeout_for(&agent);
        let Some(last_call_in) = parse_timestamp(&agent.last_call_in) else {
            warn!(
                agent_id = format_args!("0x{:08X}", agent.agent_id),
                last_call_in = %agent.last_call_in,
                "skipping liveness timeout because last callback timestamp could not be parsed"
            );
            continue;
        };

        let elapsed_secs = (now - last_call_in).whole_seconds();
        if elapsed_secs >= i64::try_from(timeout_secs).unwrap_or(i64::MAX) {
            stale_agents.push(StaleAgent {
                agent_id: agent.agent_id,
                last_call_in: agent.last_call_in,
                timeout_secs,
            });
        }
    }

    stale_agents
}

pub(super) fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}
