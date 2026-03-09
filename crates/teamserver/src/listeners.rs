//! Listener lifecycle management for the teamserver.

use std::collections::BTreeMap;
use std::future::pending;
use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use axum::{Json, http::StatusCode};
use red_cell_common::config::Profile;
use red_cell_common::operator::{
    EventCode, ListenerErrorInfo, ListenerInfo, ListenerMarkInfo, Message, MessageHead, NameInfo,
    OperatorMessage,
};
use red_cell_common::{
    ExternalListenerConfig, HttpListenerConfig, HttpListenerProxyConfig,
    HttpListenerResponseConfig, ListenerConfig, ListenerProtocol, SmbListenerConfig,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::{
    Database, ListenerRepository, ListenerStatus, PersistedListener, PersistedListenerState,
    TeamserverError,
};

/// Runtime state for a configured listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
                info.proxy_enabled =
                    Some(config.proxy.as_ref().is_some_and(|proxy| proxy.enabled).to_string());
                info.proxy_type = config.proxy.as_ref().and_then(|proxy| proxy.proxy_type.clone());
                info.proxy_host = config.proxy.as_ref().map(|proxy| proxy.host.clone());
                info.proxy_port = config.proxy.as_ref().map(|proxy| proxy.port.to_string());
                info.proxy_username =
                    config.proxy.as_ref().and_then(|proxy| proxy.username.clone());
                info.proxy_password =
                    config.proxy.as_ref().and_then(|proxy| proxy.password.clone());
                info.secure = Some(config.secure.to_string());
                info.response_headers =
                    config.response.as_ref().map(|response| response.headers.join(", "));
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
}

/// Request body used by REST listener mark operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerMarkRequest {
    /// Requested mark value such as `start` or `stop`.
    pub mark: String,
}

/// Errors returned by [`ListenerManager`].
#[derive(Debug, thiserror::Error)]
pub enum ListenerManagerError {
    /// Listener persistence failed.
    #[error("{0}")]
    Database(#[from] TeamserverError),
    /// The requested listener already exists.
    #[error("listener `{name}` already exists")]
    DuplicateListener { name: String },
    /// The requested listener could not be found.
    #[error("listener `{name}` not found")]
    ListenerNotFound { name: String },
    /// The listener is already running.
    #[error("listener `{name}` is already running")]
    ListenerAlreadyRunning { name: String },
    /// The listener is not currently running.
    #[error("listener `{name}` is not running")]
    ListenerNotRunning { name: String },
    /// The operator payload could not be converted into a valid listener config.
    #[error("invalid listener configuration: {message}")]
    InvalidConfig { message: String },
    /// A listener runtime could not bind or initialize.
    #[error("failed to start listener `{name}`: {message}")]
    StartFailed { name: String, message: String },
    /// The WebSocket mark command used an unsupported action.
    #[error("unsupported listener mark `{mark}`")]
    UnsupportedMark { mark: String },
}

impl IntoResponse for ListenerManagerError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::DuplicateListener { .. } => StatusCode::CONFLICT,
            Self::ListenerNotFound { .. } => StatusCode::NOT_FOUND,
            Self::ListenerAlreadyRunning { .. } | Self::ListenerNotRunning { .. } => {
                StatusCode::CONFLICT
            }
            Self::InvalidConfig { .. } | Self::UnsupportedMark { .. } => StatusCode::BAD_REQUEST,
            Self::StartFailed { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, Json(serde_json::json!({ "error": self.to_string() }))).into_response()
    }
}

/// Tracks persisted listeners and their active runtime tasks.
#[derive(Clone, Debug)]
pub struct ListenerManager {
    database: Database,
    active_handles: Arc<RwLock<BTreeMap<String, JoinHandle<()>>>>,
    operations: Arc<Mutex<()>>,
}

impl ListenerManager {
    /// Build a listener manager backed by `database`.
    #[must_use]
    pub fn new(database: Database) -> Self {
        Self {
            database,
            active_handles: Arc::new(RwLock::new(BTreeMap::new())),
            operations: Arc::new(Mutex::new(())),
        }
    }

    /// Return the listener persistence repository used by the manager.
    #[must_use]
    pub fn repository(&self) -> ListenerRepository {
        self.database.listeners()
    }

    /// Create a persisted listener configuration in the stopped state.
    pub async fn create(
        &self,
        config: ListenerConfig,
    ) -> Result<ListenerSummary, ListenerManagerError> {
        let _guard = self.operations.lock().await;
        let repository = self.repository();

        if repository.exists(config.name()).await? {
            return Err(ListenerManagerError::DuplicateListener { name: config.name().to_owned() });
        }

        repository.create(&config).await?;
        self.summary(config.name()).await
    }

    /// Replace an existing listener configuration.
    pub async fn update(
        &self,
        config: ListenerConfig,
    ) -> Result<ListenerSummary, ListenerManagerError> {
        let _guard = self.operations.lock().await;
        let repository = self.repository();
        let existing = repository.get(config.name()).await?.ok_or_else(|| {
            ListenerManagerError::ListenerNotFound { name: config.name().to_owned() }
        })?;

        let was_running = existing.state.status == ListenerStatus::Running;
        if was_running {
            self.stop_locked(config.name()).await?;
        }

        repository.update(&config).await?;
        repository.set_state(config.name(), ListenerStatus::Stopped, None).await?;

        if was_running {
            match self.start_locked(config.name()).await {
                Ok(summary) => return Ok(summary),
                Err(error) => return Err(error),
            }
        }

        self.summary(config.name()).await
    }

    /// Start the named listener runtime.
    pub async fn start(&self, name: &str) -> Result<ListenerSummary, ListenerManagerError> {
        let _guard = self.operations.lock().await;
        self.start_locked(name).await
    }

    /// Stop the named listener runtime.
    pub async fn stop(&self, name: &str) -> Result<ListenerSummary, ListenerManagerError> {
        let _guard = self.operations.lock().await;
        self.stop_locked(name).await
    }

    /// Delete the named listener, stopping it first if needed.
    pub async fn delete(&self, name: &str) -> Result<(), ListenerManagerError> {
        let _guard = self.operations.lock().await;
        let repository = self.repository();
        let Some(listener) = repository.get(name).await? else {
            return Err(ListenerManagerError::ListenerNotFound { name: name.to_owned() });
        };

        if listener.state.status == ListenerStatus::Running {
            let _ = self.stop_locked(name).await?;
        }

        repository.delete(name).await?;
        self.active_handles.write().await.remove(name);
        Ok(())
    }

    /// Return the current persisted summary for `name`.
    pub async fn summary(&self, name: &str) -> Result<ListenerSummary, ListenerManagerError> {
        self.repository()
            .get(name)
            .await?
            .map(Into::into)
            .ok_or_else(|| ListenerManagerError::ListenerNotFound { name: name.to_owned() })
    }

    /// Return every persisted listener summary.
    pub async fn list(&self) -> Result<Vec<ListenerSummary>, ListenerManagerError> {
        Ok(self.repository().list().await?.into_iter().map(Into::into).collect())
    }

    /// Ensure listeners declared in the YAOTL profile exist in the database.
    pub async fn sync_profile(&self, profile: &Profile) -> Result<(), ListenerManagerError> {
        for config in profile_listener_configs(profile) {
            match self.create(config.clone()).await {
                Ok(_) => {}
                Err(ListenerManagerError::DuplicateListener { .. }) => {
                    let _ = self.update(config).await?;
                }
                Err(error) => return Err(error),
            }
        }

        Ok(())
    }

    /// Start listeners that were last persisted in the running state.
    pub async fn restore_running(&self) -> Result<(), ListenerManagerError> {
        let listeners = self.repository().list().await?;

        for listener in listeners {
            if listener.state.status == ListenerStatus::Running {
                let _ = self.start(&listener.name).await?;
            }
        }

        Ok(())
    }

    async fn start_locked(&self, name: &str) -> Result<ListenerSummary, ListenerManagerError> {
        let repository = self.repository();
        let listener = repository
            .get(name)
            .await?
            .ok_or_else(|| ListenerManagerError::ListenerNotFound { name: name.to_owned() })?;

        if self.active_handles.read().await.contains_key(name) {
            return Err(ListenerManagerError::ListenerAlreadyRunning { name: name.to_owned() });
        }

        match spawn_listener_runtime(&listener.config).await {
            Ok(handle) => {
                self.active_handles.write().await.insert(name.to_owned(), handle);
                repository.set_state(name, ListenerStatus::Running, None).await?;
                info!(listener = name, protocol = %listener.protocol, "listener started");
                self.summary(name).await
            }
            Err(error) => {
                let error_text = error.to_string();
                repository
                    .set_state(name, ListenerStatus::Error, Some(error_text.as_str()))
                    .await?;
                warn!(listener = name, error = %error_text, "listener failed to start");
                Err(ListenerManagerError::StartFailed {
                    name: name.to_owned(),
                    message: error_text,
                })
            }
        }
    }

    async fn stop_locked(&self, name: &str) -> Result<ListenerSummary, ListenerManagerError> {
        let repository = self.repository();

        if repository.get(name).await?.is_none() {
            return Err(ListenerManagerError::ListenerNotFound { name: name.to_owned() });
        }

        let Some(handle) = self.active_handles.write().await.remove(name) else {
            return Err(ListenerManagerError::ListenerNotRunning { name: name.to_owned() });
        };

        handle.abort();
        let _ = handle.await;
        repository.set_state(name, ListenerStatus::Stopped, None).await?;
        info!(listener = name, "listener stopped");
        self.summary(name).await
    }
}

/// Convert a Havoc operator listener payload into a shared listener config.
pub fn listener_config_from_operator(
    info: &ListenerInfo,
) -> Result<ListenerConfig, ListenerManagerError> {
    let name = required_field("Name", info.name.as_deref())?;
    let protocol = required_field("Protocol", info.protocol.as_deref())?;

    match ListenerProtocol::try_from_str(protocol) {
        Ok(ListenerProtocol::Http) => Ok(ListenerConfig::from(HttpListenerConfig {
            name: name.to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: split_csv(info.hosts.as_deref()),
            host_bind: required_field("HostBind", info.host_bind.as_deref())?.to_owned(),
            host_rotation: required_field("HostRotation", info.host_rotation.as_deref())?
                .to_owned(),
            port_bind: parse_u16("PortBind", info.port_bind.as_deref())?,
            port_conn: parse_optional_u16("PortConn", info.port_conn.as_deref())?,
            method: None,
            behind_redirector: false,
            user_agent: optional_trimmed(info.user_agent.as_deref()),
            headers: split_csv(info.headers.as_deref()),
            uris: split_csv(info.uris.as_deref()),
            host_header: info
                .extra
                .get("HostHeader")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| optional_trimmed(Some(value))),
            secure: parse_bool("Secure", info.secure.as_deref()).unwrap_or(false),
            cert: None,
            response: info
                .response_headers
                .as_deref()
                .map(|headers| HttpListenerResponseConfig { headers: split_csv(Some(headers)) }),
            proxy: proxy_from_operator(info)?,
        })),
        Ok(ListenerProtocol::Smb) => Ok(ListenerConfig::from(SmbListenerConfig {
            name: name.to_owned(),
            pipe_name: required_extra_string(info, "PipeName")?,
            kill_date: None,
            working_hours: None,
        })),
        Ok(ListenerProtocol::External) => Ok(ListenerConfig::from(ExternalListenerConfig {
            name: name.to_owned(),
            endpoint: required_extra_string(info, "Endpoint")?,
        })),
        Err(error) => Err(ListenerManagerError::InvalidConfig { message: error.to_string() }),
    }
}

/// Return `true` when the operator payload requests the listener be started immediately.
#[must_use]
pub fn operator_requests_start(info: &ListenerInfo) -> bool {
    info.status.as_deref().is_some_and(|status| {
        status.eq_ignore_ascii_case("online") || status.eq_ignore_ascii_case("start")
    })
}

/// Convert a listener lifecycle action into a Havoc-compatible event payload.
#[must_use]
pub fn listener_event_for_action(
    user: &str,
    summary: &ListenerSummary,
    action: ListenerEventAction,
) -> OperatorMessage {
    match action {
        ListenerEventAction::Created => OperatorMessage::ListenerNew(Message {
            head: listener_message_head(user),
            info: summary.to_operator_info(),
        }),
        ListenerEventAction::Updated => OperatorMessage::ListenerEdit(Message {
            head: listener_message_head(user),
            info: summary.to_operator_info(),
        }),
        ListenerEventAction::Started => OperatorMessage::ListenerMark(Message {
            head: listener_message_head(user),
            info: ListenerMarkInfo { name: summary.name.clone(), mark: "Online".to_owned() },
        }),
        ListenerEventAction::Stopped => OperatorMessage::ListenerMark(Message {
            head: listener_message_head(user),
            info: ListenerMarkInfo { name: summary.name.clone(), mark: "Offline".to_owned() },
        }),
    }
}

/// Convert a listener error into a Havoc-compatible event payload.
#[must_use]
pub fn listener_error_event(
    user: &str,
    name: &str,
    error: &ListenerManagerError,
) -> OperatorMessage {
    OperatorMessage::ListenerError(Message {
        head: listener_message_head(user),
        info: ListenerErrorInfo { error: error.to_string(), name: name.to_owned() },
    })
}

/// Convert a deletion event into a Havoc-compatible operator payload.
#[must_use]
pub fn listener_removed_event(user: &str, name: &str) -> OperatorMessage {
    OperatorMessage::ListenerRemove(Message {
        head: listener_message_head(user),
        info: NameInfo { name: name.to_owned() },
    })
}

/// The lifecycle action represented by an operator or REST request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerEventAction {
    /// A new listener was created.
    Created,
    /// An existing listener was updated.
    Updated,
    /// A listener was started.
    Started,
    /// A listener was stopped.
    Stopped,
}

/// Parse a WebSocket listener mark value into a lifecycle action.
pub fn action_from_mark(mark: &str) -> Result<ListenerEventAction, ListenerManagerError> {
    if mark.eq_ignore_ascii_case("online")
        || mark.eq_ignore_ascii_case("start")
        || mark.eq_ignore_ascii_case("running")
    {
        Ok(ListenerEventAction::Started)
    } else if mark.eq_ignore_ascii_case("offline")
        || mark.eq_ignore_ascii_case("stop")
        || mark.eq_ignore_ascii_case("stopped")
    {
        Ok(ListenerEventAction::Stopped)
    } else {
        Err(ListenerManagerError::UnsupportedMark { mark: mark.to_owned() })
    }
}

fn listener_message_head(user: &str) -> MessageHead {
    MessageHead {
        event: EventCode::Listener,
        user: user.to_owned(),
        timestamp: String::new(),
        one_time: String::new(),
    }
}

fn operator_status(status: ListenerStatus) -> &'static str {
    match status {
        ListenerStatus::Running => "Online",
        ListenerStatus::Created | ListenerStatus::Stopped | ListenerStatus::Error => "Offline",
    }
}

fn operator_protocol_name(config: &ListenerConfig) -> String {
    match config {
        ListenerConfig::Http(config) if config.secure => "Https".to_owned(),
        _ => config.protocol().as_str().to_owned(),
    }
}

fn profile_listener_configs(profile: &Profile) -> Vec<ListenerConfig> {
    let mut listeners = Vec::new();
    listeners.extend(profile.listeners.http.iter().cloned().map(|config| {
        ListenerConfig::from(HttpListenerConfig {
            name: config.name,
            kill_date: config.kill_date,
            working_hours: config.working_hours,
            hosts: config.hosts,
            host_bind: config.host_bind,
            host_rotation: config.host_rotation,
            port_bind: config.port_bind,
            port_conn: config.port_conn,
            method: config.method,
            behind_redirector: profile.demon.trust_x_forwarded_for,
            user_agent: config.user_agent,
            headers: config.headers,
            uris: config.uris,
            host_header: None,
            secure: config.secure,
            cert: config
                .cert
                .map(|cert| red_cell_common::ListenerTlsConfig { cert: cert.cert, key: cert.key }),
            response: config
                .response
                .map(|response| HttpListenerResponseConfig { headers: response.headers }),
            proxy: config.proxy.map(|proxy| HttpListenerProxyConfig {
                enabled: true,
                proxy_type: Some("http".to_owned()),
                host: proxy.host,
                port: proxy.port,
                username: proxy.username,
                password: proxy.password,
            }),
        })
    }));
    listeners.extend(profile.listeners.smb.iter().cloned().map(|config| {
        ListenerConfig::from(SmbListenerConfig {
            name: config.name,
            pipe_name: config.pipe_name,
            kill_date: config.kill_date,
            working_hours: config.working_hours,
        })
    }));
    listeners.extend(profile.listeners.external.iter().cloned().map(|config| {
        ListenerConfig::from(ExternalListenerConfig {
            name: config.name,
            endpoint: config.endpoint,
        })
    }));
    listeners
}

async fn spawn_listener_runtime(
    config: &ListenerConfig,
) -> Result<JoinHandle<()>, ListenerManagerError> {
    match config {
        ListenerConfig::Http(config) => {
            let address = format!("{}:{}", config.host_bind, config.port_bind);
            let listener = TcpListener::bind(address.as_str()).await.map_err(|error| {
                ListenerManagerError::StartFailed {
                    name: config.name.clone(),
                    message: format!("failed to bind {address}: {error}"),
                }
            })?;

            Ok(tokio::spawn(async move {
                loop {
                    let _ = listener.accept().await;
                }
            }))
        }
        ListenerConfig::Smb(_) | ListenerConfig::External(_) => Ok(tokio::spawn(async move {
            pending::<()>().await;
        })),
    }
}

fn required_field<'a>(
    field: &'static str,
    value: Option<&'a str>,
) -> Result<&'a str, ListenerManagerError> {
    value.map(str::trim).filter(|value| !value.is_empty()).ok_or_else(|| {
        ListenerManagerError::InvalidConfig { message: format!("{field} is required") }
    })
}

fn required_extra_string(
    info: &ListenerInfo,
    field: &'static str,
) -> Result<String, ListenerManagerError> {
    match info.extra.get(field).and_then(serde_json::Value::as_str).map(str::trim) {
        Some(value) if !value.is_empty() => Ok(value.to_owned()),
        _ => Err(ListenerManagerError::InvalidConfig { message: format!("{field} is required") }),
    }
}

fn parse_u16(field: &'static str, value: Option<&str>) -> Result<u16, ListenerManagerError> {
    let value = required_field(field, value)?;
    value.parse::<u16>().map_err(|error| ListenerManagerError::InvalidConfig {
        message: format!("{field} must be a valid port: {error}"),
    })
}

fn parse_optional_u16(
    field: &'static str,
    value: Option<&str>,
) -> Result<Option<u16>, ListenerManagerError> {
    match optional_trimmed(value) {
        Some(value) => {
            value.parse::<u16>().map(Some).map_err(|error| ListenerManagerError::InvalidConfig {
                message: format!("{field} must be a valid port: {error}"),
            })
        }
        None => Ok(None),
    }
}

fn parse_bool(field: &'static str, value: Option<&str>) -> Result<bool, ListenerManagerError> {
    match optional_trimmed(value) {
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Some(value) => Err(ListenerManagerError::InvalidConfig {
            message: format!("{field} must be `true` or `false`, got `{value}`"),
        }),
        None => Ok(false),
    }
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value.map(str::trim).filter(|value| !value.is_empty()).map(ToOwned::to_owned)
}

fn split_csv(value: Option<&str>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn proxy_from_operator(
    info: &ListenerInfo,
) -> Result<Option<HttpListenerProxyConfig>, ListenerManagerError> {
    if !parse_bool("Proxy Enabled", info.proxy_enabled.as_deref())? {
        return Ok(None);
    }

    Ok(Some(HttpListenerProxyConfig {
        enabled: true,
        proxy_type: optional_trimmed(info.proxy_type.as_deref()),
        host: required_field("Proxy Host", info.proxy_host.as_deref())?.to_owned(),
        port: parse_u16("Proxy Port", info.proxy_port.as_deref())?,
        username: optional_trimmed(info.proxy_username.as_deref()),
        password: optional_trimmed(info.proxy_password.as_deref()),
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        ListenerEventAction, ListenerManager, ListenerManagerError, ListenerStatus,
        action_from_mark, listener_config_from_operator, operator_requests_start,
    };
    use crate::Database;
    use red_cell_common::operator::ListenerInfo;
    use red_cell_common::{HttpListenerConfig, ListenerConfig};

    fn http_listener(name: &str, port: u16) -> ListenerConfig {
        ListenerConfig::from(HttpListenerConfig {
            name: name.to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: port,
            port_conn: Some(port),
            method: None,
            behind_redirector: false,
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
        })
    }

    async fn manager() -> Result<ListenerManager, ListenerManagerError> {
        Ok(ListenerManager::new(Database::connect_in_memory().await?))
    }

    #[tokio::test]
    async fn create_and_list_persist_listener_state() -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        let summary = manager.create(http_listener("alpha", 32001)).await?;

        assert_eq!(summary.name, "alpha");
        assert_eq!(summary.state.status, ListenerStatus::Created);
        assert_eq!(manager.list().await?.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn start_stop_and_delete_manage_runtime_handles() -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        manager.create(http_listener("alpha", 32002)).await?;

        let running = manager.start("alpha").await?;
        assert_eq!(running.state.status, ListenerStatus::Running);

        let stopped = manager.stop("alpha").await?;
        assert_eq!(stopped.state.status, ListenerStatus::Stopped);

        manager.delete("alpha").await?;
        assert!(matches!(
            manager.summary("alpha").await,
            Err(ListenerManagerError::ListenerNotFound { .. })
        ));

        Ok(())
    }

    #[tokio::test]
    async fn start_records_bind_errors() -> Result<(), ListenerManagerError> {
        let blocker = tokio::net::TcpListener::bind("127.0.0.1:32003")
            .await
            .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
        let manager = manager().await?;
        manager.create(http_listener("alpha", 32003)).await?;

        let error = manager.start("alpha").await.expect_err("bind should fail");
        let summary = manager.summary("alpha").await?;

        drop(blocker);

        assert!(matches!(error, ListenerManagerError::StartFailed { .. }));
        assert_eq!(summary.state.status, ListenerStatus::Error);
        assert!(summary.state.last_error.is_some());

        Ok(())
    }

    #[test]
    fn operator_payload_maps_to_http_listener_config() -> Result<(), ListenerManagerError> {
        let info = ListenerInfo {
            name: Some("alpha".to_owned()),
            protocol: Some("Https".to_owned()),
            status: Some("Online".to_owned()),
            hosts: Some("a.example, b.example".to_owned()),
            host_bind: Some("0.0.0.0".to_owned()),
            host_rotation: Some("round-robin".to_owned()),
            port_bind: Some("8443".to_owned()),
            port_conn: Some("443".to_owned()),
            headers: Some("X-Test: true".to_owned()),
            uris: Some("/one, /two".to_owned()),
            user_agent: Some("Mozilla/5.0".to_owned()),
            secure: Some("true".to_owned()),
            ..ListenerInfo::default()
        };

        let config = listener_config_from_operator(&info)?;

        assert!(operator_requests_start(&info));
        match config {
            ListenerConfig::Http(config) => {
                assert_eq!(config.name, "alpha");
                assert!(config.secure);
                assert_eq!(config.hosts, vec!["a.example".to_owned(), "b.example".to_owned()]);
            }
            other => panic!("unexpected config: {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn mark_actions_accept_start_and_stop_aliases() -> Result<(), ListenerManagerError> {
        assert_eq!(action_from_mark("online")?, ListenerEventAction::Started);
        assert_eq!(action_from_mark("stop")?, ListenerEventAction::Stopped);
        assert!(matches!(
            action_from_mark("restart"),
            Err(ListenerManagerError::UnsupportedMark { .. })
        ));

        Ok(())
    }
}
