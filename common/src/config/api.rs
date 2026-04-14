//! Service bridge, REST API keys, and outbound webhook profile blocks.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

use super::serde_helpers::default_api_rate_limit_per_minute;
use super::teamserver::OperatorRole;

/// Optional service bridge configuration.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct ServiceConfig {
    /// Service endpoint name or address.
    #[serde(rename = "Endpoint")]
    pub endpoint: String,
    /// Service shared secret.
    #[serde(rename = "Password")]
    pub password: String,
}

impl fmt::Debug for ServiceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceConfig")
            .field("endpoint", &self.endpoint)
            .field("password", &"[redacted]")
            .finish()
    }
}

/// Optional REST API configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApiConfig {
    /// API keys keyed by a stable identifier.
    #[serde(rename = "key", default)]
    pub keys: BTreeMap<String, ApiKeyConfig>,
    /// Maximum accepted requests per API key, per minute.
    #[serde(
        rename = "RateLimitPerMinute",
        default = "crate::config::serde_helpers::default_api_rate_limit_per_minute"
    )]
    pub rate_limit_per_minute: u32,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self { keys: BTreeMap::new(), rate_limit_per_minute: default_api_rate_limit_per_minute() }
    }
}

/// A single REST API key definition.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct ApiKeyConfig {
    /// The secret value accepted by the REST API.
    #[serde(rename = "Value")]
    pub value: String,
    /// RBAC role granted to requests using this key.
    #[serde(rename = "Role", default)]
    pub role: OperatorRole,
}

impl fmt::Debug for ApiKeyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKeyConfig")
            .field("value", &"[redacted]")
            .field("role", &self.role)
            .finish()
    }
}

/// Outbound webhook settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WebHookConfig {
    /// Discord webhook integration.
    #[serde(rename = "Discord", default)]
    pub discord: Option<DiscordWebHookConfig>,
}

/// Discord webhook configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DiscordWebHookConfig {
    /// Webhook URL.
    #[serde(rename = "Url")]
    pub url: String,
    /// Optional avatar URL.
    #[serde(rename = "AvatarUrl", default)]
    pub avatar_url: Option<String>,
    /// Optional display name.
    #[serde(rename = "User", default)]
    pub user: Option<String>,
    /// Maximum number of retry attempts after the initial POST fails.
    ///
    /// Defaults to 3.  Set to 0 to disable retries entirely.  Each retry is
    /// preceded by an exponential backoff delay: `RetryBaseDelaySecs * 4^n`
    /// (n = 0 for the first retry).
    #[serde(rename = "MaxRetries", default = "crate::config::serde_helpers::default_max_retries")]
    pub max_retries: u32,
    /// Base delay in seconds for the first retry.
    ///
    /// Each subsequent retry multiplies the previous delay by 4.
    /// Defaults to 1 second (giving delays of 1 s, 4 s, 16 s with the
    /// default `MaxRetries = 3`).
    #[serde(
        rename = "RetryBaseDelaySecs",
        default = "crate::config::serde_helpers::default_retry_base_delay_secs"
    )]
    pub retry_base_delay_secs: u64,
}
