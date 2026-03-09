//! Red Cell teamserver library components.

pub mod agents;
pub mod auth;
pub mod database;
pub mod events;
pub mod rbac;
pub mod websocket;

pub use agents::{AgentRegistry, Job};
pub use auth::{
    AuthError, AuthService, AuthenticationFailure, AuthenticationResult, AuthenticationSuccess,
    OperatorSession, hash_password, login_failure_message, login_success_message,
};
pub use database::{
    AgentRepository, AuditLogEntry, AuditLogRepository, Database, LinkRecord, LinkRepository,
    ListenerRepository, LootRecord, LootRepository, PersistedListener, TeamserverError,
};
pub use events::{EventBus, EventReceiver};
pub use rbac::{
    AdminAccess, AuthenticatedOperator, AuthorizationError, ListenerManagementAccess, Permission,
    ReadAccess, TaskAgentAccess, authorize_permission, authorize_websocket_command,
};
pub use websocket::{OperatorConnectionManager, routes as websocket_routes, websocket_handler};
