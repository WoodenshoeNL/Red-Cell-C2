//! Per-operator ACL helpers for the operator WebSocket feed.
//!
//! Two concerns live here so the snapshot path and the live broadcast path
//! stay in sync:
//!
//! * [`listener_visible_to`] / [`agent_visible_to`] — shared scope-resolution
//!   primitives used by both the initial snapshot and the live filter.
//! * [`operator_may_see_event`] — decides whether an [`OperatorMessage`]
//!   emitted on the global [`crate::EventBus`] should be forwarded to a
//!   specific operator's socket.
//!
//! Events not bound to a specific listener or agent (chat, build, operator
//! presence, teamserver meta) pass through unchanged — the scoping guarantee
//! only applies to per-listener and per-agent resources.

use red_cell_common::operator::{FlatInfo, OperatorMessage};

use crate::{
    AgentRegistry, AuthorizationError, Database, authorize_agent_group_access,
    authorize_listener_access,
};

/// Return `true` if `username` is permitted to see `event` on their live feed.
pub(super) async fn operator_may_see_event(
    event: &OperatorMessage,
    database: &Database,
    registry: &AgentRegistry,
    username: &str,
) -> bool {
    match event {
        OperatorMessage::ListenerNew(message) | OperatorMessage::ListenerEdit(message) => {
            match message.info.name.as_deref() {
                Some(name) => listener_visible_to(database, username, name).await,
                None => true,
            }
        }
        OperatorMessage::ListenerRemove(message) => {
            listener_visible_to(database, username, &message.info.name).await
        }
        OperatorMessage::ListenerMark(message) => {
            listener_visible_to(database, username, &message.info.name).await
        }
        OperatorMessage::ListenerError(message) => {
            listener_visible_to(database, username, &message.info.name).await
        }
        OperatorMessage::AgentNew(message) | OperatorMessage::AgentReregistered(message) => {
            let Some(agent_id) = parse_hex_agent_id(&message.info.name_id) else {
                tracing::warn!(
                    %username,
                    name_id = %message.info.name_id,
                    "unparseable NameID on agent event; hiding from live feed"
                );
                return false;
            };
            agent_visible_to(database, username, agent_id, Some(&message.info.listener)).await
        }
        OperatorMessage::AgentUpdate(message) => {
            agent_event_visible(database, registry, username, &message.info.agent_id).await
        }
        OperatorMessage::AgentTask(message) => {
            agent_event_visible(database, registry, username, &message.info.demon_id).await
        }
        OperatorMessage::AgentResponse(message) => {
            agent_event_visible(database, registry, username, &message.info.demon_id).await
        }
        OperatorMessage::AgentRemove(message) => match flat_info_agent_id(&message.info) {
            Some(id) => agent_event_visible(database, registry, username, &id).await,
            None => true,
        },
        _ => true,
    }
}

/// Apply the per-operator listener allow-list.
///
/// Mirrors the REST list-endpoint filter so a restricted operator does not
/// learn of listeners outside their scope via the WebSocket.
pub(super) async fn listener_visible_to(
    database: &Database,
    username: &str,
    listener_name: &str,
) -> bool {
    match authorize_listener_access(database, username, listener_name).await {
        Ok(()) => true,
        Err(AuthorizationError::ListenerAccessDenied { .. }) => false,
        Err(err) => {
            tracing::warn!(
                %username,
                %listener_name,
                %err,
                "listener ACL check failed; hiding listener from operator"
            );
            false
        }
    }
}

/// Apply the composite agent-group + listener allow-list.
///
/// Mirrors `api::agents::operator_may_access_agent` so a restricted operator
/// does not learn of agents outside their scope via the WebSocket.
pub(super) async fn agent_visible_to(
    database: &Database,
    username: &str,
    agent_id: u32,
    listener_name: Option<&str>,
) -> bool {
    if let Err(err) = authorize_agent_group_access(database, username, agent_id).await {
        return match err {
            AuthorizationError::AgentGroupDenied { .. } => false,
            other => {
                tracing::warn!(
                    %username,
                    agent_id,
                    err = %other,
                    "agent-group ACL check failed; hiding agent from operator"
                );
                false
            }
        };
    }

    if let Some(listener_name) = listener_name {
        return listener_visible_to(database, username, listener_name).await;
    }

    true
}

async fn agent_event_visible(
    database: &Database,
    registry: &AgentRegistry,
    username: &str,
    agent_id_hex: &str,
) -> bool {
    let Some(agent_id) = parse_hex_agent_id(agent_id_hex) else {
        tracing::warn!(
            %username,
            agent_id_hex,
            "unparseable agent id on live event; hiding from operator"
        );
        return false;
    };
    let listener_name = registry.listener_name(agent_id).await;
    agent_visible_to(database, username, agent_id, listener_name.as_deref()).await
}

fn flat_info_agent_id(info: &FlatInfo) -> Option<String> {
    info.fields
        .get("AgentID")
        .or_else(|| info.fields.get("DemonID"))
        .and_then(|value| value.as_str())
        .map(str::to_owned)
}

fn parse_hex_agent_id(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    let hex = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    u32::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::parse_hex_agent_id;

    #[test]
    fn parse_hex_agent_id_accepts_uppercase_and_lowercase_with_optional_prefix() {
        assert_eq!(parse_hex_agent_id("DEADBEEF"), Some(0xDEAD_BEEF));
        assert_eq!(parse_hex_agent_id("deadbeef"), Some(0xDEAD_BEEF));
        assert_eq!(parse_hex_agent_id("0xDEADBEEF"), Some(0xDEAD_BEEF));
        assert_eq!(parse_hex_agent_id("0XDEADBEEF"), Some(0xDEAD_BEEF));
        assert_eq!(parse_hex_agent_id("  AAAA1111  "), Some(0xAAAA_1111));
    }

    #[test]
    fn parse_hex_agent_id_rejects_invalid_input() {
        assert_eq!(parse_hex_agent_id(""), None);
        assert_eq!(parse_hex_agent_id("not-hex"), None);
        assert_eq!(parse_hex_agent_id("GGGGGGGG"), None);
    }
}
