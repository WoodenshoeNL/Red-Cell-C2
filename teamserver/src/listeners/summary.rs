//! Public listener-summary payloads used by REST and WebSocket responses.
//!
//! [`ListenerSummary`] is the shape the teamserver hands back to operators
//! when listing or describing configured listeners.  The per-protocol
//! `extra`/typed-field packing used to produce the Havoc-compatible
//! [`ListenerInfo`] shape lives on [`ListenerSummary::to_operator_info`].

use red_cell_common::operator::ListenerInfo;
use red_cell_common::{ListenerConfig, ListenerProtocol};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::config::{
    EXTRA_BEHIND_REDIRECTOR, EXTRA_CERT_PATH, EXTRA_JA3_RANDOMIZE, EXTRA_KEY_PATH, EXTRA_KILL_DATE,
    EXTRA_LEGACY_MODE, EXTRA_METHOD, EXTRA_RESPONSE_BODY, EXTRA_TRUSTED_PROXY_PEERS,
    EXTRA_WORKING_HOURS, insert_optional_extra_string,
};
use super::events::{operator_protocol_name, operator_status};
use crate::{PersistedListener, PersistedListenerState};

/// Runtime state for a configured listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ListenerSummary {
    /// Unique listener name.
    pub name: String,
    /// Listener transport protocol.
    pub protocol: ListenerProtocol,
    /// Persisted runtime state.
    pub state: PersistedListenerState,
    /// Full listener configuration.
    pub config: ListenerConfig,
}

impl From<PersistedListener> for ListenerSummary {
    fn from(value: PersistedListener) -> Self {
        Self {
            name: value.name,
            protocol: value.protocol,
            state: value.state,
            config: value.config,
        }
    }
}

impl ListenerSummary {
    /// Convert the summary into the Havoc-compatible operator payload shape.
    #[must_use]
    pub fn to_operator_info(&self) -> ListenerInfo {
        self.to_operator_info_with_redaction(true)
    }

    #[must_use]
    fn to_operator_info_with_redaction(&self, redact_proxy_password: bool) -> ListenerInfo {
        let mut info = ListenerInfo {
            name: Some(self.name.clone()),
            protocol: Some(operator_protocol_name(&self.config)),
            status: Some(operator_status(self.state.status).to_owned()),
            ..ListenerInfo::default()
        };

        match &self.config {
            ListenerConfig::Http(config) => {
                info.extra
                    .insert("Host".to_owned(), serde_json::Value::String(config.host_bind.clone()));
                info.extra.insert(
                    "Port".to_owned(),
                    serde_json::Value::String(config.port_bind.to_string()),
                );
                info.extra
                    .insert("Info".to_owned(), serde_json::Value::String(config.uris.join(", ")));
                info.extra.insert(
                    "Error".to_owned(),
                    self.state.last_error.clone().map_or_else(
                        || serde_json::Value::String(String::new()),
                        serde_json::Value::String,
                    ),
                );
                info.hosts = Some(config.hosts.join(", "));
                info.host_bind = Some(config.host_bind.clone());
                info.host_rotation = Some(config.host_rotation.clone());
                info.port_bind = Some(config.port_bind.to_string());
                info.port_conn = config.port_conn.map(|value| value.to_string());
                info.headers = Some(config.headers.join(", "));
                info.uris = Some(config.uris.join(", "));
                info.user_agent = config.user_agent.clone();
                if let Some(host_header) = &config.host_header {
                    info.extra.insert(
                        "HostHeader".to_owned(),
                        serde_json::Value::String(host_header.clone()),
                    );
                }
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_METHOD,
                    config.method.as_deref(),
                );
                info.extra.insert(
                    EXTRA_BEHIND_REDIRECTOR.to_owned(),
                    serde_json::Value::String(config.behind_redirector.to_string()),
                );
                if !config.trusted_proxy_peers.is_empty() {
                    info.extra.insert(
                        EXTRA_TRUSTED_PROXY_PEERS.to_owned(),
                        serde_json::Value::String(config.trusted_proxy_peers.join(", ")),
                    );
                }
                info.proxy_enabled =
                    Some(config.proxy.as_ref().is_some_and(|proxy| proxy.enabled).to_string());
                info.proxy_type = config.proxy.as_ref().and_then(|proxy| proxy.proxy_type.clone());
                info.proxy_host = config.proxy.as_ref().map(|proxy| proxy.host.clone());
                info.proxy_port = config.proxy.as_ref().map(|proxy| proxy.port.to_string());
                info.proxy_username =
                    config.proxy.as_ref().and_then(|proxy| proxy.username.clone());
                if !redact_proxy_password {
                    info.proxy_password = config
                        .proxy
                        .as_ref()
                        .and_then(|proxy| proxy.password.as_deref().map(String::from));
                }
                info.secure = Some(config.secure.to_string());
                if let Some(ja3) = config.ja3_randomize {
                    info.extra.insert(
                        EXTRA_JA3_RANDOMIZE.to_owned(),
                        serde_json::Value::String(ja3.to_string()),
                    );
                }
                info.response_headers = config.response.as_ref().and_then(|response| {
                    (!response.headers.is_empty()).then(|| response.headers.join(", "))
                });
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_CERT_PATH,
                    config.cert.as_ref().map(|cert| cert.cert.as_str()),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_KEY_PATH,
                    config.cert.as_ref().map(|cert| cert.key.as_str()),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_RESPONSE_BODY,
                    config.response.as_ref().and_then(|response| response.body.as_deref()),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_KILL_DATE,
                    config.kill_date.as_deref(),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_WORKING_HOURS,
                    config.working_hours.as_deref(),
                );
                info.extra.insert(
                    EXTRA_LEGACY_MODE.to_owned(),
                    serde_json::Value::String(config.legacy_mode.to_string()),
                );
            }
            ListenerConfig::Smb(config) => {
                info.extra.insert("Host".to_owned(), serde_json::Value::String(String::new()));
                info.extra.insert("Port".to_owned(), serde_json::Value::String(String::new()));
                info.extra
                    .insert("Info".to_owned(), serde_json::Value::String(config.pipe_name.clone()));
                info.extra.insert(
                    "Error".to_owned(),
                    self.state.last_error.clone().map_or_else(
                        || serde_json::Value::String(String::new()),
                        serde_json::Value::String,
                    ),
                );
                info.extra.insert(
                    "PipeName".to_owned(),
                    serde_json::Value::String(config.pipe_name.clone()),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_KILL_DATE,
                    config.kill_date.as_deref(),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_WORKING_HOURS,
                    config.working_hours.as_deref(),
                );
            }
            ListenerConfig::Dns(config) => {
                info.extra
                    .insert("Host".to_owned(), serde_json::Value::String(config.host_bind.clone()));
                info.extra.insert(
                    "Port".to_owned(),
                    serde_json::Value::String(config.port_bind.to_string()),
                );
                info.extra
                    .insert("Info".to_owned(), serde_json::Value::String(config.domain.clone()));
                info.extra.insert(
                    "Error".to_owned(),
                    self.state.last_error.clone().map_or_else(
                        || serde_json::Value::String(String::new()),
                        serde_json::Value::String,
                    ),
                );
                info.extra
                    .insert("Domain".to_owned(), serde_json::Value::String(config.domain.clone()));
                info.extra.insert(
                    "RecordTypes".to_owned(),
                    serde_json::Value::String(config.record_types.join(",")),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_KILL_DATE,
                    config.kill_date.as_deref(),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_WORKING_HOURS,
                    config.working_hours.as_deref(),
                );
                info.host_bind = Some(config.host_bind.clone());
                info.port_bind = Some(config.port_bind.to_string());
            }
            ListenerConfig::External(config) => {
                info.extra.insert("Host".to_owned(), serde_json::Value::String(String::new()));
                info.extra.insert("Port".to_owned(), serde_json::Value::String(String::new()));
                info.extra
                    .insert("Info".to_owned(), serde_json::Value::String(config.endpoint.clone()));
                info.extra.insert(
                    "Error".to_owned(),
                    self.state.last_error.clone().map_or_else(
                        || serde_json::Value::String(String::new()),
                        serde_json::Value::String,
                    ),
                );
                info.extra.insert(
                    "Endpoint".to_owned(),
                    serde_json::Value::String(config.endpoint.clone()),
                );
            }
        }

        info
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn to_operator_info_with_secrets(&self) -> ListenerInfo {
        self.to_operator_info_with_redaction(false)
    }
}

/// Request body used by REST listener mark operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ListenerMarkRequest {
    /// Requested mark value such as `start` or `stop`.
    pub mark: String,
}
