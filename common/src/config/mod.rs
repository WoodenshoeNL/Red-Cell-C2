//! Havoc-compatible teamserver profile parsing.

mod serde_helpers;

mod api;
mod demon;
mod listeners;
mod profile;
mod teamserver;

#[cfg(test)]
mod tests;

pub use api::{ApiConfig, ApiKeyConfig, DiscordWebHookConfig, ServiceConfig, WebHookConfig};
pub use demon::{
    BinaryConfig, DemonConfig, HeaderConfig, ProcessInjectionConfig, VersionedInitSecret,
};
pub use listeners::{
    DnsListenerConfig, ExternalListenerConfig, HclHttpListenerProxyConfig,
    HclHttpListenerResponseConfig, HttpListenerCertConfig, ListenersConfig,
    ProfileHttpListenerConfig, SmbListenerConfig,
};
pub use profile::{Profile, ProfileError, ProfileValidationError};
pub use teamserver::{
    BuildConfig, DatabaseConfig, LogFileConfig, LogFormat, LogRotation, LoggingConfig,
    ObservabilityConfig, OperatorConfig, OperatorRole, OperatorsConfig, TeamserverConfig,
};
