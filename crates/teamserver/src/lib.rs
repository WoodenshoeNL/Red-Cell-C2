//! Red Cell teamserver library components.

pub mod agents;
pub mod auth;
pub mod database;
pub mod events;

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
