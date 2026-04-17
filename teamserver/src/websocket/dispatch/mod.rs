//! Operator WebSocket command dispatch.
//!
//! [`dispatch_operator_command`] is the single entry point used by the
//! WebSocket handler; each `OperatorMessage` variant is forwarded to a
//! dedicated submodule (`listeners`, `agents`, `payload`, `chat`) so the
//! per-message logic stays isolated and the dispatcher itself stays small.

use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use thiserror::Error;
use tracing::{debug, warn};

use crate::{
    AgentRegistry, AuditWebhookNotifier, Database, EventBus, ListenerManager,
    PayloadBuilderService, ShutdownController, SocketRelayManager,
};

mod agents;
mod chat;
mod listeners;
mod payload;

pub(crate) use agents::execute_agent_task;

/// Attempt to serialize a value for audit logging, warning on failure instead
/// of silently discarding the error.
pub(super) fn serialize_for_audit<T: serde::Serialize>(value: &T, context: &str) -> Option<Value> {
    match serde_json::to_value(value) {
        Ok(v) => Some(v),
        Err(error) => {
            warn!(%error, context, "failed to serialize audit parameters");
            None
        }
    }
}

pub(super) async fn dispatch_operator_command<S>(
    state: &S,
    session: &crate::OperatorSession,
    message: OperatorMessage,
) where
    S: Clone + Send + Sync + 'static,
    EventBus: axum::extract::FromRef<S>,
    ListenerManager: axum::extract::FromRef<S>,
    AgentRegistry: axum::extract::FromRef<S>,
    SocketRelayManager: axum::extract::FromRef<S>,
    PayloadBuilderService: axum::extract::FromRef<S>,
    AuditWebhookNotifier: axum::extract::FromRef<S>,
    Database: axum::extract::FromRef<S>,
    ShutdownController: axum::extract::FromRef<S>,
{
    use axum::extract::FromRef;

    let events = EventBus::from_ref(state);
    let listeners = ListenerManager::from_ref(state);
    let registry = AgentRegistry::from_ref(state);
    let sockets = SocketRelayManager::from_ref(state);
    let payload_builder = PayloadBuilderService::from_ref(state);
    let webhooks = AuditWebhookNotifier::from_ref(state);
    let database = Database::from_ref(state);

    match message {
        OperatorMessage::ListenerNew(message) => {
            listeners::handle_listener_new(
                &listeners, &events, &database, &webhooks, session, message,
            )
            .await;
        }
        OperatorMessage::ListenerEdit(message) => {
            listeners::handle_listener_edit(
                &listeners, &events, &database, &webhooks, session, message,
            )
            .await;
        }
        OperatorMessage::ListenerRemove(message) => {
            listeners::handle_listener_remove(
                &listeners, &events, &database, &webhooks, session, message,
            )
            .await;
        }
        OperatorMessage::ListenerMark(message) => {
            listeners::handle_listener_mark(
                &listeners, &events, &database, &webhooks, session, message,
            )
            .await;
        }
        OperatorMessage::AgentTask(message) => {
            agents::handle_agent_task_message(
                &registry, &sockets, &events, &database, &webhooks, session, message,
            )
            .await;
        }
        OperatorMessage::AgentRemove(message) => {
            agents::handle_agent_remove_message(
                &registry, &sockets, &events, &database, &webhooks, session, message,
            )
            .await;
        }
        OperatorMessage::BuildPayloadRequest(message) => {
            payload::handle_build_payload_request(
                &listeners,
                &payload_builder,
                &events,
                &database,
                &webhooks,
                session,
                message,
            )
            .await;
        }
        OperatorMessage::ChatMessage(message) => {
            chat::handle_chat_message(&events, &database, &webhooks, session, message).await;
        }
        other => {
            debug!(
                connection_id = %session.connection_id,
                username = %session.username,
                event = ?other.event_code(),
                "operator websocket command has no registered handler yet"
            );
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum AgentCommandError {
    #[error("invalid agent id `{agent_id}`")]
    InvalidAgentId { agent_id: String },
    #[error("agent id is required")]
    MissingAgentId,
    #[error("agent note is required")]
    MissingNote,
    #[error("agent note is too long: {length} bytes (limit {limit})")]
    NoteTooLong { length: usize, limit: usize },
    #[error("unsupported agent remove payload")]
    InvalidRemovePayload,
    #[error("invalid numeric command id `{command_id}`")]
    InvalidCommandId { command_id: String },
    #[error("missing required field `{field}`")]
    MissingField { field: &'static str },
    #[error("invalid boolean field `{field}`: `{value}`")]
    InvalidBooleanField { field: String, value: String },
    #[error("invalid numeric field `{field}`: `{value}`")]
    InvalidNumericField { field: String, value: String },
    #[error("invalid base64 field `{field}`: {message}")]
    InvalidBase64Field { field: String, message: String },
    #[error("unsupported process subcommand `{subcommand}`")]
    UnsupportedProcessSubcommand { subcommand: String },
    #[error("unsupported filesystem subcommand `{subcommand}`")]
    UnsupportedFilesystemSubcommand { subcommand: String },
    #[error("unsupported token subcommand `{subcommand}`")]
    UnsupportedTokenSubcommand { subcommand: String },
    #[error("unsupported socket subcommand `{subcommand}`")]
    UnsupportedSocketSubcommand { subcommand: String },
    #[error("unsupported kerberos subcommand `{subcommand}`")]
    UnsupportedKerberosSubcommand { subcommand: String },
    #[error("invalid hex task id `{task_id}`")]
    InvalidTaskId { task_id: String },
    #[error("unsupported injection way `{way}`")]
    UnsupportedInjectionWay { way: String },
    #[error("unsupported injection technique `{technique}`")]
    UnsupportedInjectionTechnique { technique: String },
    #[error(
        "unsupported command id {command_id}: not a recognized Demon command and no raw payload provided"
    )]
    UnsupportedCommandId { command_id: u32 },
    #[error("unsupported process architecture `{arch}`")]
    UnsupportedArchitecture { arch: String },
    #[error("invalid process create arguments: expected `state;verbose;piped;program;base64_args`")]
    InvalidProcessCreateArguments,
    #[error(transparent)]
    Teamserver(#[from] crate::TeamserverError),
    #[error(transparent)]
    Plugin(#[from] crate::PluginError),
    #[error(transparent)]
    SocketRelay(#[from] crate::SocketRelayError),
    /// Granular RBAC check (group access or listener access) failed.
    #[error(transparent)]
    Authorization(#[from] crate::AuthorizationError),
}
