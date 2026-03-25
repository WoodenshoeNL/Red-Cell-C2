//! Shared types and protocol primitives for Red Cell C2.

pub mod config;
pub mod crypto;
pub mod demon;
pub mod domain;
pub mod error;
pub mod operator;
pub mod tls;

pub use domain::{
    AgentEncryptionInfo, AgentRecord, DnsListenerConfig, ExternalListenerConfig,
    HttpListenerConfig, HttpListenerProxyConfig, HttpListenerResponseConfig, ListenerConfig,
    ListenerProtocol, ListenerTlsConfig, OperatorInfo, SmbListenerConfig, parse_kill_date_to_epoch,
    validate_kill_date,
};
pub use error::CommonError;
