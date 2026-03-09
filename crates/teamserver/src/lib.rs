//! Red Cell teamserver library components.

pub mod agents;
pub mod auth;
pub mod database;
pub mod demon;
pub mod events;
pub mod listeners;
pub mod rbac;
pub mod websocket;

pub use agents::{AgentRegistry, Job};
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
pub use events::{EventBus, EventReceiver};
pub use listeners::{
    ListenerEventAction, ListenerManager, ListenerManagerError, ListenerMarkRequest,
    ListenerSummary, action_from_mark, listener_config_from_operator, listener_error_event,
    listener_event_for_action, listener_removed_event, operator_requests_start,
};
pub use rbac::{
    AdminAccess, AuthenticatedOperator, AuthorizationError, ListenerManagementAccess, Permission,
    ReadAccess, TaskAgentAccess, authorize_permission, authorize_websocket_command,
};
pub use websocket::{OperatorConnectionManager, routes as websocket_routes, websocket_handler};
