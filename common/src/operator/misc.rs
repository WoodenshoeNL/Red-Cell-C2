//! Chat, login, profile, service, teamserver-log, and database-status payloads.

use serde::{Deserialize, Serialize};

/// Login request payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginInfo {
    /// Operator username.
    #[serde(rename = "User")]
    pub user: String,
    /// SHA3-256 password hash, hex encoded.
    #[serde(rename = "Password", alias = "Password_SHA3")]
    pub password: String,
}

/// Initial profile transfer payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitProfileInfo {
    /// Serialized Demon profile JSON.
    #[serde(rename = "Demon")]
    pub demon: String,
    /// Comma-separated teamserver IP list.
    #[serde(rename = "TeamserverIPs")]
    pub teamserver_ips: String,
}

/// Chat connection payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatUserInfo {
    /// Operator username.
    #[serde(rename = "User")]
    pub user: String,
}

/// Service agent registration payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAgentRegistrationInfo {
    /// Serialized service agent definition.
    #[serde(rename = "Agent")]
    pub agent: String,
}

/// Service listener registration payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceListenerRegistrationInfo {
    /// Serialized listener definition.
    #[serde(rename = "Listener")]
    pub listener: String,
}

/// Teamserver log payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamserverLogInfo {
    /// Log message text.
    #[serde(rename = "Text")]
    pub text: String,
}

/// Teamserver profile payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamserverProfileInfo {
    /// Serialized teamserver profile.
    #[serde(rename = "profile")]
    pub profile: String,
}

/// Database health status change payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseStatusInfo {
    /// Human-readable status message describing the health change.
    #[serde(rename = "Message")]
    pub message: String,
    /// Number of consecutive failures that triggered the degraded transition,
    /// or zero for a recovery event.
    #[serde(rename = "ConsecutiveFailures")]
    pub consecutive_failures: u32,
}
