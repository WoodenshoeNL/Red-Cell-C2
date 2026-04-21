//! Listener protocol, configuration, and kill-date types.

mod config;
mod kill_date;
mod protocol;

pub use config::{
    DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, HttpListenerProxyConfig,
    HttpListenerResponseConfig, ListenerTlsConfig, SmbListenerConfig,
};
pub use kill_date::{parse_kill_date_to_epoch, validate_kill_date};
pub use protocol::ListenerProtocol;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Shared listener configuration enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "protocol", content = "config", rename_all = "snake_case")]
pub enum ListenerConfig {
    /// HTTP or HTTPS listener settings.
    Http(Box<HttpListenerConfig>),
    /// SMB pivot listener settings.
    Smb(SmbListenerConfig),
    /// DNS C2 listener settings.
    Dns(DnsListenerConfig),
    /// External C2 bridge listener settings.
    External(ExternalListenerConfig),
}

impl ListenerConfig {
    /// Return the listener display name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Http(config) => &config.name,
            Self::Smb(config) => &config.name,
            Self::Dns(config) => &config.name,
            Self::External(config) => &config.name,
        }
    }

    /// Return the listener protocol family.
    #[must_use]
    pub const fn protocol(&self) -> ListenerProtocol {
        match self {
            Self::Http(_) => ListenerProtocol::Http,
            Self::Smb(_) => ListenerProtocol::Smb,
            Self::Dns(_) => ListenerProtocol::Dns,
            Self::External(_) => ListenerProtocol::External,
        }
    }
}

impl From<HttpListenerConfig> for ListenerConfig {
    fn from(config: HttpListenerConfig) -> Self {
        Self::Http(Box::new(config))
    }
}

impl From<SmbListenerConfig> for ListenerConfig {
    fn from(config: SmbListenerConfig) -> Self {
        Self::Smb(config)
    }
}

impl From<DnsListenerConfig> for ListenerConfig {
    fn from(config: DnsListenerConfig) -> Self {
        Self::Dns(config)
    }
}

impl From<ExternalListenerConfig> for ListenerConfig {
    fn from(config: ExternalListenerConfig) -> Self {
        Self::External(config)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
