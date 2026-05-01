//! Red Cell teamserver library components.

mod agent_events;
mod agent_liveness;
pub mod agents;
pub mod api;
pub mod app;
pub mod audit;
pub mod auth;
pub mod corpus_capture;
pub mod database;
pub mod demon;
pub mod dispatch;
pub mod events;
pub mod listeners;
pub mod metrics;
pub mod normalize;
pub mod payload_builder;
pub mod plugins;
pub(crate) mod rate_limiter;
pub mod rbac;
pub mod service;
mod session_ws;
pub mod shutdown;
pub mod sockets;
pub mod webhook;
pub mod websocket;

pub use agent_liveness::{AgentLivenessMonitor, spawn_agent_liveness_monitor};
pub use agents::{AgentRegistry, DEFAULT_MAX_REGISTERED_AGENTS, Job, PivotInfo};
pub use api::{
    AdminApiAccess, ApiAuthError, ApiErrorBody, ApiErrorDetail, ApiIdentity, ApiPermissionGuard,
    ApiRateLimit, ApiRuntime, AuthMethod, ListenerManagementApiAccess, ReadApiAccess, api_routes,
    json_error_response,
};
pub use app::{TeamserverState, build_router};
pub use audit::{
    AuditDetails, AuditPage, AuditQuery, AuditRecord, AuditResultStatus, AuthVector,
    SessionActivityPage, SessionActivityQuery, SessionActivityRecord, audit_details,
    login_parameters, parameter_object, query_audit_log, query_session_activity,
    record_operator_action, record_operator_action_with_notifications,
};
pub use auth::{
    AuthError, AuthService, AuthenticationFailure, AuthenticationResult, AuthenticationSuccess,
    DEFAULT_IDLE_TIMEOUT, DEFAULT_SESSION_TTL, OperatorSession, SessionActivity,
    SessionExpiryReason, SessionPolicy, login_failure_message, login_success_message,
    session_expired_message,
};
pub use database::{
    AgentGroupRepository, AgentRepository, AgentResponseRecord, AgentResponseRepository,
    AuditLogEntry, AuditLogFilter, AuditLogPruner, AuditLogRepository,
    DEFAULT_AUDIT_PRUNE_INTERVAL_SECS, DEFAULT_AUDIT_RETENTION_DAYS, DEFAULT_BACKUP_INTERVAL_SECS,
    DEFAULT_DEGRADED_THRESHOLD, DEFAULT_PROBE_SECS, DEFAULT_QUERY_TIMEOUT_SECS,
    DEFAULT_WRITE_QUEUE_CAPACITY, Database, DatabaseBackupScheduler, DatabaseHealthMonitor,
    DatabaseHealthState, DbMasterKey, DeferredWrite, LinkRecord, LinkRepository,
    ListenerAccessRepository, ListenerRepository, ListenerStatus, LootRecord, LootRepository,
    OperatorRepository, PayloadBuildRecord, PayloadBuildRepository, PayloadBuildSummary,
    PersistedListener, PersistedListenerState, PersistedOperator, TeamserverError, WriteQueue,
};
pub use demon::{
    DemonCallbackPackage, DemonInitSecretConfig, DemonPacketParser, DemonParserError,
    ParsedDemonInit, ParsedDemonPacket, build_init_ack, build_reconnect_ack,
};
/// Default maximum bytes allowed for a single agent download.
pub const DEFAULT_MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum bytes for a single agent↔teamserver message in either direction.
///
/// Applied as:
/// - the HTTP body limit in [`listeners`] (agent → teamserver)
/// - the WebSocket chunk size in [`websocket`] (teamserver → operator console)
///
/// Set large enough for Demon-style **uncompressed 24-bit BMP screenshots** on
/// wide multi-monitor virtual desktops (payloads can exceed 50 MiB). The former
/// 30 MiB cap caused valid screenshot callbacks to be rejected before dispatch,
/// so operators never saw matching loot rows.
pub const MAX_AGENT_MESSAGE_LEN: usize = 100 * 1024 * 1024; // 100 MiB

pub use corpus_capture::CorpusCapture;
pub use dispatch::{CommandDispatchError, CommandDispatcher};
pub use events::{EventBus, EventReceiver};
pub use listeners::{
    ExternalListenerState, ListenerEventAction, ListenerManager, ListenerManagerError,
    ListenerMarkRequest, ListenerSummary, MAX_DEMON_INIT_ATTEMPTS_PER_IP, action_from_mark,
    handle_external_request, listener_config_from_operator, listener_error_event,
    listener_event_for_action, listener_removed_event, operator_requests_start,
};
pub use metrics::{MetricsHandle, MetricsInitError, install_prometheus_recorder};
pub use normalize::NormalizedMakeService;
pub use payload_builder::{
    BuildProgress, PayloadArtifact, PayloadBuildError, PayloadBuilderService, PayloadCache,
};
pub use plugins::{PluginError, PluginEvent, PluginHealthEntry, PluginRuntime};
pub use rbac::{
    AdminAccess, AuthenticatedOperator, AuthorizationError, ListenerManagementAccess, Permission,
    ReadAccess, TaskAgentAccess, authorize_agent_group_access, authorize_listener_access,
    authorize_permission, authorize_websocket_command,
};
pub use red_cell_common::crypto::hash_password_sha3;
pub use service::{ServiceBridge, ServiceBridgeError, service_routes};
pub use shutdown::{ActiveCallbackGuard, ShutdownController};
pub use sockets::{SocketRelayError, SocketRelayManager};
pub use webhook::AuditWebhookNotifier;
#[cfg(feature = "test-helpers")]
pub use webhook::StuckDeliveryGuard;
pub use websocket::{
    ActiveOperatorInfo, LoginRateLimiter, OperatorConnectionManager, routes as websocket_routes,
    websocket_handler,
};
