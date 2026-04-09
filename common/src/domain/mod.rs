//! Shared domain types used across the Red Cell teamserver and client.

mod agents;
mod listeners;
mod serde_helpers;

pub use agents::{AgentEncryptionInfo, AgentRecord, OperatorInfo};
pub use listeners::{
    DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, HttpListenerProxyConfig,
    HttpListenerResponseConfig, ListenerConfig, ListenerProtocol, ListenerTlsConfig,
    SmbListenerConfig, parse_kill_date_to_epoch, validate_kill_date,
};
