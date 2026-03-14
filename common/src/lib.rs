//! Shared types and protocol primitives for Red Cell C2.

pub mod config;
pub mod crypto;
pub mod demon;
pub mod domain;
pub mod error;
pub mod operator;
pub mod tls;

pub use domain::{
    AgentEncryptionInfo, AgentRecord, DnsListenerConfig, HttpListenerConfig,
    HttpListenerProxyConfig, HttpListenerResponseConfig, ListenerConfig, ListenerProtocol,
    ListenerTlsConfig, OperatorInfo, SmbListenerConfig,
};
pub use error::CommonError;
