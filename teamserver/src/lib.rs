//! Red Cell teamserver library components.

mod agent_events;
mod agent_liveness;
pub mod agents;
pub mod api;
pub mod app;
pub mod audit;
pub mod auth;
pub mod database;
pub mod demon;
pub mod dispatch;
pub mod events;
pub mod listeners;
pub mod normalize;
pub mod payload_builder;
pub mod plugins;
pub(crate) mod rate_limiter;
pub mod rbac;
pub mod service;
pub mod shutdown;
pub mod sockets;
pub mod webhook;
pub mod websocket;

pub use agent_liveness::{AgentLivenessMonitor, spawn_agent_liveness_monitor};
pub use agents::{AgentRegistry, DEFAULT_MAX_REGISTERED_AGENTS, Job, PivotInfo};
pub use api::{
    AdminApiAccess, ApiAuthError, ApiErrorBody, ApiErrorDetail, ApiIdentity, ApiPermissionGuard,
    ApiRateLimit, ApiRuntime, ListenerManagementApiAccess, ReadApiAccess, api_routes,
    json_error_response,
};
pub use app::{TeamserverState, build_router};
pub use audit::{
    AuditDetails, AuditPage, AuditQuery, AuditRecord, AuditResultStatus, SessionActivityPage,
    SessionActivityQuery, SessionActivityRecord, audit_details, login_parameters, parameter_object,
    query_audit_log, query_session_activity, record_operator_action,
    record_operator_action_with_notifications,
};
pub use auth::{
    AuthError, AuthService, AuthenticationFailure, AuthenticationResult, AuthenticationSuccess,
    OperatorSession, login_failure_message, login_success_message,
};
pub use database::{
    AgentRepository, AgentResponseRecord, AgentResponseRepository, AuditLogEntry, AuditLogFilter,
    AuditLogRepository, Database, LinkRecord, LinkRepository, ListenerRepository, ListenerStatus,
    LootRecord, LootRepository, OperatorRepository, PayloadBuildRecord, PayloadBuildRepository,
    PayloadBuildSummary, PersistedListener, PersistedListenerState, PersistedOperator,
    TeamserverError,
};
pub use demon::{
    DemonCallbackPackage, DemonPacketParser, DemonParserError, ParsedDemonInit, ParsedDemonPacket,
    build_init_ack, build_reconnect_ack,
};
/// Default maximum bytes allowed for a single agent download.
pub const DEFAULT_MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum bytes for a single agent↔teamserver message in either direction.
///
/// Applied as:
/// - the HTTP body limit in [`listeners`] (agent → teamserver)
/// - the WebSocket chunk size in [`websocket`] (teamserver → operator console)
pub const MAX_AGENT_MESSAGE_LEN: usize = 0x01E0_0000; // 30 MiB

pub use dispatch::{CommandDispatchError, CommandDispatcher};
pub use events::{EventBus, EventReceiver};
pub use listeners::{
    ExternalListenerState, ListenerEventAction, ListenerManager, ListenerManagerError,
    ListenerMarkRequest, ListenerSummary, action_from_mark, handle_external_request,
    listener_config_from_operator, listener_error_event, listener_event_for_action,
    listener_removed_event, operator_requests_start,
};
pub use normalize::NormalizedMakeService;
pub use payload_builder::{
    BuildProgress, PayloadArtifact, PayloadBuildError, PayloadBuilderService, PayloadCache,
};
pub use plugins::{PluginError, PluginEvent, PluginRuntime};
pub use rbac::{
    AdminAccess, AuthenticatedOperator, AuthorizationError, ListenerManagementAccess, Permission,
    ReadAccess, TaskAgentAccess, authorize_permission, authorize_websocket_command,
};
pub use red_cell_common::crypto::hash_password_sha3;
pub use service::{ServiceBridge, ServiceBridgeError, service_routes};
pub use shutdown::ShutdownController;
pub use sockets::{SocketRelayError, SocketRelayManager};
pub use webhook::AuditWebhookNotifier;
#[cfg(feature = "test-helpers")]
pub use webhook::StuckDeliveryGuard;
pub use websocket::{
    LoginRateLimiter, OperatorConnectionManager, routes as websocket_routes, websocket_handler,
};
