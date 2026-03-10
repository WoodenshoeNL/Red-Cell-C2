//! Red Cell teamserver library components.

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
pub mod payload_builder;
pub mod plugins;
pub mod rbac;
pub mod sockets;
pub mod websocket;

pub use agents::{AgentRegistry, Job, PivotInfo};
pub use api::{
    ApiAuthError, ApiErrorBody, ApiErrorDetail, ApiIdentity, ApiPermissionGuard, ApiRateLimit,
    ApiRuntime, ListenerManagementApiAccess, ReadApiAccess, api_routes, json_error_response,
};
pub use app::TeamserverState;
pub use audit::{
    AuditDetails, AuditPage, AuditQuery, AuditRecord, AuditResultStatus, audit_details,
    login_parameters, parameter_object, query_audit_log, record_operator_action,
};
pub use auth::{
    AuthError, AuthService, AuthenticationFailure, AuthenticationResult, AuthenticationSuccess,
    OperatorSession, hash_password, login_failure_message, login_success_message,
};
pub use database::{
    AgentRepository, AuditLogEntry, AuditLogRepository, Database, LinkRecord, LinkRepository,
    ListenerRepository, ListenerStatus, LootRecord, LootRepository, PersistedListener,
    PersistedListenerState, TeamserverError,
};
pub use demon::{
    DemonCallbackPackage, DemonPacketParser, DemonParserError, ParsedDemonInit, ParsedDemonPacket,
    build_init_ack,
};
pub use dispatch::{CommandDispatchError, CommandDispatcher};
pub use events::{EventBus, EventReceiver};
pub use listeners::{
    ListenerEventAction, ListenerManager, ListenerManagerError, ListenerMarkRequest,
    ListenerSummary, action_from_mark, listener_config_from_operator, listener_error_event,
    listener_event_for_action, listener_removed_event, operator_requests_start,
};
pub use payload_builder::{
    BuildProgress, PayloadArtifact, PayloadBuildError, PayloadBuilderService,
};
pub use plugins::{PluginError, PluginEvent, PluginRuntime};
pub use rbac::{
    AdminAccess, AuthenticatedOperator, AuthorizationError, ListenerManagementAccess, Permission,
    ReadAccess, TaskAgentAccess, authorize_permission, authorize_websocket_command,
};
pub use sockets::{SocketRelayError, SocketRelayManager};
pub use websocket::{OperatorConnectionManager, routes as websocket_routes, websocket_handler};
