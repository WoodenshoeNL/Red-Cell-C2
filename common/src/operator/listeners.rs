//! Listener-related payload structs for the operator protocol.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Listener create or edit payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerInfo {
    #[serde(rename = "Name", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "Protocol", default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "Status", default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "Hosts", default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<String>,
    #[serde(rename = "HostBind", default, skip_serializing_if = "Option::is_none")]
    pub host_bind: Option<String>,
    #[serde(rename = "HostRotation", default, skip_serializing_if = "Option::is_none")]
    pub host_rotation: Option<String>,
    #[serde(rename = "PortBind", default, skip_serializing_if = "Option::is_none")]
    pub port_bind: Option<String>,
    #[serde(rename = "PortConn", default, skip_serializing_if = "Option::is_none")]
    pub port_conn: Option<String>,
    #[serde(rename = "Headers", default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<String>,
    #[serde(rename = "Uris", default, skip_serializing_if = "Option::is_none")]
    pub uris: Option<String>,
    #[serde(rename = "UserAgent", default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(rename = "Proxy Enabled", default, skip_serializing_if = "Option::is_none")]
    pub proxy_enabled: Option<String>,
    #[serde(rename = "Proxy Type", default, skip_serializing_if = "Option::is_none")]
    pub proxy_type: Option<String>,
    #[serde(rename = "Proxy Host", default, skip_serializing_if = "Option::is_none")]
    pub proxy_host: Option<String>,
    #[serde(rename = "Proxy Port", default, skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<String>,
    #[serde(rename = "Proxy Username", default, skip_serializing_if = "Option::is_none")]
    pub proxy_username: Option<String>,
    #[serde(rename = "Proxy Password", default, skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<String>,
    #[serde(rename = "Secure", default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<String>,
    #[serde(rename = "Response Headers", default, skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `{ "Name": ... }` payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameInfo {
    /// The named object identifier.
    #[serde(rename = "Name")]
    pub name: String,
}

/// Listener mark payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerMarkInfo {
    /// Listener name.
    #[serde(rename = "Name")]
    pub name: String,
    /// Desired mark.
    #[serde(rename = "Mark")]
    pub mark: String,
}

/// Listener error payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerErrorInfo {
    /// Listener creation or start error.
    #[serde(rename = "Error")]
    pub error: String,
    /// Listener name.
    #[serde(rename = "Name")]
    pub name: String,
}
