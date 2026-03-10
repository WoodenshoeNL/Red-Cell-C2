use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use eframe::egui;
use futures_util::{SinkExt, StreamExt};
use red_cell_common::OperatorInfo;
use red_cell_common::operator::{
    AgentResponseInfo, ChatUserInfo, FlatInfo, ListenerInfo, ListenerMarkInfo, Message,
    OperatorMessage,
};
use thiserror::Error;
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::SignatureScheme;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{self, aws_lc_rs};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{
        self,
        client::IntoClientRequest,
        protocol::{CloseFrame, Message as WebSocketMessage, frame::coding::CloseCode},
    },
};
use url::Url;

const MAX_CHAT_MESSAGES: usize = 200;
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(1);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

pub(crate) type SharedAppState = Arc<Mutex<AppState>>;

#[derive(Debug)]
pub(crate) struct ClientTransport {
    runtime: Option<Runtime>,
    shutdown_tx: watch::Sender<bool>,
    #[allow(dead_code)]
    outgoing_tx: mpsc::UnboundedSender<OperatorMessage>,
}

impl ClientTransport {
    pub(crate) fn spawn(
        server_url: String,
        app_state: SharedAppState,
        repaint: egui::Context,
    ) -> Result<Self, TransportError> {
        red_cell_common::tls::install_default_crypto_provider();

        let normalized_server_url = normalize_server_url(&server_url)?;
        {
            let mut state = lock_app_state(&app_state);
            state.server_url = normalized_server_url.clone();
        }

        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .thread_name("red-cell-client-ws")
            .build()
            .map_err(TransportError::RuntimeInit)?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        let shared_outgoing_rx = Arc::new(tokio::sync::Mutex::new(outgoing_rx));

        let task_state = app_state.clone();
        runtime.spawn(async move {
            run_connection_manager(
                normalized_server_url,
                task_state,
                shared_outgoing_rx,
                shutdown_rx,
                repaint,
            )
            .await;
        });

        Ok(Self { runtime: Some(runtime), shutdown_tx, outgoing_tx })
    }

    #[allow(dead_code)]
    pub(crate) fn queue_message(&self, message: OperatorMessage) -> Result<(), TransportError> {
        self.outgoing_tx.send(message).map_err(|_| TransportError::OutgoingQueueClosed)
    }

    pub(crate) fn outgoing_sender(&self) -> mpsc::UnboundedSender<OperatorMessage> {
        self.outgoing_tx.clone()
    }
}

impl Drop for ClientTransport {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_millis(250));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Retrying(String),
    Error(String),
}

impl ConnectionStatus {
    pub(crate) fn placeholders() -> [Self; 5] {
        [
            Self::Disconnected,
            Self::Connecting,
            Self::Connected,
            Self::Retrying("Retrying after a dropped connection".to_owned()),
            Self::Error("Awaiting transport initialization".to_owned()),
        ]
    }

    pub(crate) fn label(&self) -> &str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Retrying(_) => "Retrying",
            Self::Error(_) => "Connection Error",
        }
    }

    pub(crate) fn color(&self) -> egui::Color32 {
        match self {
            Self::Disconnected => egui::Color32::from_rgb(130, 138, 145),
            Self::Connecting | Self::Retrying(_) => egui::Color32::from_rgb(232, 182, 83),
            Self::Connected => egui::Color32::from_rgb(110, 199, 141),
            Self::Error(_) => egui::Color32::from_rgb(215, 83, 83),
        }
    }

    pub(crate) fn detail(&self) -> Option<&str> {
        match self {
            Self::Retrying(message) | Self::Error(message) => Some(message.as_str()),
            Self::Disconnected | Self::Connecting | Self::Connected => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LootKind {
    Credential,
    File,
    Screenshot,
    Other,
}

impl LootKind {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Credential => "Credential",
            Self::File => "File",
            Self::Screenshot => "Screenshot",
            Self::Other => "Other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LootItem {
    pub(crate) kind: LootKind,
    pub(crate) name: String,
    pub(crate) agent_id: String,
    pub(crate) source: String,
    pub(crate) collected_at: String,
    pub(crate) file_path: Option<String>,
    pub(crate) size_bytes: Option<u64>,
    pub(crate) content_base64: Option<String>,
    pub(crate) preview: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChatMessage {
    pub(crate) author: String,
    pub(crate) sent_at: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentConsoleEntry {
    pub(crate) command_id: String,
    pub(crate) received_at: String,
    pub(crate) output: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentSummary {
    pub(crate) name_id: String,
    pub(crate) status: String,
    pub(crate) domain_name: String,
    pub(crate) username: String,
    pub(crate) internal_ip: String,
    pub(crate) external_ip: String,
    pub(crate) hostname: String,
    pub(crate) process_arch: String,
    pub(crate) process_name: String,
    pub(crate) process_pid: String,
    pub(crate) elevated: bool,
    pub(crate) os_version: String,
    pub(crate) os_build: String,
    pub(crate) os_arch: String,
    pub(crate) sleep_delay: String,
    pub(crate) sleep_jitter: String,
    pub(crate) last_call_in: String,
    pub(crate) note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListenerSummary {
    pub(crate) name: String,
    pub(crate) protocol: String,
    pub(crate) status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppState {
    pub(crate) server_url: String,
    pub(crate) connection_status: ConnectionStatus,
    pub(crate) operator_info: Option<OperatorInfo>,
    pub(crate) agents: Vec<AgentSummary>,
    pub(crate) agent_consoles: BTreeMap<String, Vec<AgentConsoleEntry>>,
    pub(crate) listeners: Vec<ListenerSummary>,
    pub(crate) loot: Vec<LootItem>,
    pub(crate) chat_messages: Vec<ChatMessage>,
    pub(crate) online_operators: BTreeSet<String>,
}

impl AppState {
    pub(crate) fn new(server_url: String) -> Self {
        Self {
            server_url,
            connection_status: ConnectionStatus::Disconnected,
            operator_info: None,
            agents: Vec::new(),
            agent_consoles: BTreeMap::new(),
            listeners: Vec::new(),
            loot: Vec::new(),
            chat_messages: Vec::new(),
            online_operators: BTreeSet::new(),
        }
    }

    pub(crate) fn apply_operator_message(&mut self, message: OperatorMessage) {
        match message {
            OperatorMessage::InitConnectionSuccess(message) => {
                self.connection_status = ConnectionStatus::Connected;
                if !message.head.user.is_empty() {
                    self.online_operators.insert(message.head.user.clone());
                    self.operator_info = Some(OperatorInfo {
                        username: message.head.user.clone(),
                        password_hash: None,
                        role: None,
                        online: true,
                        last_seen: Some(message.head.timestamp.clone()),
                    });
                }
                self.push_chat_message(
                    "teamserver",
                    message.head.timestamp,
                    sanitize_text(&message.info.message),
                );
            }
            OperatorMessage::InitConnectionError(message) => {
                self.connection_status = ConnectionStatus::Error(message.info.message.clone());
                self.push_chat_message("teamserver", message.head.timestamp, message.info.message);
            }
            OperatorMessage::ListenerNew(message) | OperatorMessage::ListenerEdit(message) => {
                self.upsert_listener(listener_summary_from_info(&message.info));
            }
            OperatorMessage::ListenerRemove(message) => {
                self.listeners.retain(|listener| listener.name != message.info.name);
            }
            OperatorMessage::ListenerMark(message) => {
                self.mark_listener(&message.info);
            }
            OperatorMessage::ListenerError(message) => {
                self.upsert_listener(ListenerSummary {
                    name: message.info.name.clone(),
                    protocol: "unknown".to_owned(),
                    status: format!("Error: {}", message.info.error),
                });
                self.push_chat_message("teamserver", message.head.timestamp, message.info.error);
            }
            OperatorMessage::ChatMessage(message)
            | OperatorMessage::ChatListener(message)
            | OperatorMessage::ChatAgent(message) => {
                self.push_chat_message(
                    flat_info_string(&message.info, &["User", "Name", "DemonID"])
                        .unwrap_or_else(|| "system".to_owned())
                        .as_str(),
                    message.head.timestamp,
                    flat_info_string(&message.info, &["Message", "Text", "Output"])
                        .unwrap_or_else(|| "Received event".to_owned()),
                );
            }
            OperatorMessage::ChatUserConnected(message) => {
                self.handle_chat_user_presence(message.info, true, message.head.timestamp);
            }
            OperatorMessage::ChatUserDisconnected(message) => {
                self.handle_chat_user_presence(message.info, false, message.head.timestamp);
            }
            OperatorMessage::CredentialsAdd(message)
            | OperatorMessage::CredentialsEdit(message) => {
                if let Some(item) = loot_item_from_flat_info(&message.info, LootKind::Credential) {
                    self.upsert_loot(item);
                }
            }
            OperatorMessage::CredentialsRemove(message) => {
                self.remove_loot_matching(&message.info, LootKind::Credential);
            }
            OperatorMessage::HostFileAdd(message) => {
                if let Some(item) = loot_item_from_flat_info(&message.info, LootKind::File) {
                    self.upsert_loot(item);
                }
            }
            OperatorMessage::HostFileRemove(message) => {
                self.remove_loot_matching(&message.info, LootKind::File);
            }
            OperatorMessage::AgentNew(message) => {
                self.upsert_agent(agent_summary_from_message(&message.info));
            }
            OperatorMessage::AgentRemove(message) => {
                if let Some(agent_id) = flat_info_string(&message.info, &["AgentID", "DemonID"]) {
                    self.agents.retain(|agent| agent.name_id != normalize_agent_id(&agent_id));
                }
            }
            OperatorMessage::AgentUpdate(message) => {
                let agent_id = normalize_agent_id(&message.info.agent_id);
                if let Some(agent) = self.agents.iter_mut().find(|agent| agent.name_id == agent_id)
                {
                    agent.status = message.info.marked;
                    agent.last_call_in = message.head.timestamp;
                } else {
                    self.agents.push(AgentSummary {
                        name_id: agent_id,
                        status: message.info.marked,
                        domain_name: String::new(),
                        username: String::new(),
                        internal_ip: String::new(),
                        external_ip: String::new(),
                        hostname: String::new(),
                        process_arch: String::new(),
                        process_name: String::new(),
                        process_pid: String::new(),
                        elevated: false,
                        os_version: String::new(),
                        os_build: String::new(),
                        os_arch: String::new(),
                        sleep_delay: String::new(),
                        sleep_jitter: String::new(),
                        last_call_in: message.head.timestamp,
                        note: String::new(),
                    });
                }
            }
            OperatorMessage::AgentResponse(message) => {
                self.handle_agent_response(message);
            }
            OperatorMessage::TeamserverLog(message) => {
                self.push_chat_message("teamserver", message.head.timestamp, message.info.text);
            }
            OperatorMessage::BuildPayloadMessage(message) => {
                self.push_chat_message(
                    "builder",
                    message.head.timestamp,
                    format!("{}: {}", message.info.message_type, message.info.message),
                );
            }
            OperatorMessage::BuildPayloadResponse(message) => {
                self.push_chat_message(
                    "builder",
                    message.head.timestamp,
                    format!("Built {}", message.info.file_name),
                );
            }
            OperatorMessage::Login(_)
            | OperatorMessage::InitConnectionInfo(_)
            | OperatorMessage::InitConnectionProfile(_)
            | OperatorMessage::BuildPayloadStaged(_)
            | OperatorMessage::BuildPayloadRequest(_)
            | OperatorMessage::BuildPayloadMsOffice(_)
            | OperatorMessage::AgentTask(_)
            | OperatorMessage::ServiceAgentRegister(_)
            | OperatorMessage::ServiceListenerRegister(_)
            | OperatorMessage::TeamserverProfile(_) => {}
        }
    }

    fn push_chat_message(
        &mut self,
        author: impl Into<String>,
        sent_at: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.chat_messages.push(ChatMessage {
            author: author.into(),
            sent_at: sent_at.into(),
            message: message.into(),
        });

        if self.chat_messages.len() > MAX_CHAT_MESSAGES {
            let excess = self.chat_messages.len() - MAX_CHAT_MESSAGES;
            self.chat_messages.drain(0..excess);
        }
    }

    fn upsert_agent(&mut self, agent: AgentSummary) {
        match self.agents.iter_mut().find(|existing| existing.name_id == agent.name_id) {
            Some(existing) => *existing = agent,
            None => self.agents.push(agent),
        }
    }

    pub(crate) fn update_agent_note(&mut self, agent_id: &str, note: String) {
        if let Some(agent) = self.agents.iter_mut().find(|agent| agent.name_id == agent_id) {
            agent.note = note;
        }
    }

    fn upsert_listener(&mut self, listener: ListenerSummary) {
        match self.listeners.iter_mut().find(|existing| existing.name == listener.name) {
            Some(existing) => *existing = listener,
            None => self.listeners.push(listener),
        }
    }

    fn mark_listener(&mut self, mark: &ListenerMarkInfo) {
        let status = mark.mark.clone();
        match self.listeners.iter_mut().find(|listener| listener.name == mark.name) {
            Some(listener) => listener.status = status,
            None => self.listeners.push(ListenerSummary {
                name: mark.name.clone(),
                protocol: "unknown".to_owned(),
                status,
            }),
        }
    }

    fn handle_chat_user_presence(
        &mut self,
        chat_user: ChatUserInfo,
        online: bool,
        timestamp: String,
    ) {
        let action = if online { "connected" } else { "disconnected" };
        if online {
            self.online_operators.insert(chat_user.user.clone());
        } else {
            self.online_operators.remove(&chat_user.user);
        }
        self.push_chat_message(
            "teamserver",
            timestamp.clone(),
            format!("{} {}", chat_user.user, action),
        );

        match &mut self.operator_info {
            Some(operator) if operator.username == chat_user.user => {
                operator.online = online;
                operator.last_seen = Some(timestamp);
            }
            _ if online => {
                self.operator_info = Some(OperatorInfo {
                    username: chat_user.user,
                    password_hash: None,
                    role: None,
                    online,
                    last_seen: Some(timestamp),
                });
            }
            _ => {}
        }
    }

    fn handle_agent_response(&mut self, message: Message<AgentResponseInfo>) {
        if response_is_loot_notification(&message.info) {
            if let Some(loot_item) = loot_item_from_response(&message.info) {
                self.upsert_loot(loot_item);
            }
            return;
        }

        let output = sanitize_output(&message.info.output);
        if output.is_empty() {
            return;
        }

        let agent_id = normalize_agent_id(&message.info.demon_id);
        self.agent_consoles.entry(agent_id).or_default().push(AgentConsoleEntry {
            command_id: message.info.command_id,
            received_at: message.head.timestamp,
            output,
        });
    }

    fn upsert_loot(&mut self, loot_item: LootItem) {
        match self.loot.iter_mut().find(|existing| {
            existing.kind == loot_item.kind
                && existing.agent_id == loot_item.agent_id
                && existing.name == loot_item.name
                && existing.collected_at == loot_item.collected_at
        }) {
            Some(existing) => *existing = loot_item,
            None => self.loot.push(loot_item),
        }
    }

    fn remove_loot_matching(&mut self, info: &FlatInfo, fallback_kind: LootKind) {
        if let Some(item) = loot_item_from_flat_info(info, fallback_kind) {
            self.loot.retain(|existing| {
                !(existing.kind == item.kind
                    && existing.agent_id == item.agent_id
                    && existing.name == item.name)
            });
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum TransportError {
    #[error("failed to initialize Tokio runtime: {0}")]
    RuntimeInit(std::io::Error),
    #[error("invalid teamserver URL `{url}`: {source}")]
    InvalidUrl { url: String, source: url::ParseError },
    #[error("unsupported teamserver URL scheme `{scheme}`")]
    UnsupportedScheme { scheme: String },
    #[error("teamserver URL must include a host")]
    MissingHost,
    #[error("failed to build rustls client config: {0}")]
    Rustls(#[source] Box<tokio_rustls::rustls::Error>),
    #[error("failed to create websocket request: {0}")]
    WebSocketRequest(#[source] Box<tungstenite::Error>),
    #[error("failed to serialize websocket command: {0}")]
    Serialize(#[from] serde_json::Error),
    #[allow(dead_code)]
    #[error("client transport outgoing queue is closed")]
    OutgoingQueueClosed,
}

type ClientWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn run_connection_manager(
    server_url: String,
    app_state: SharedAppState,
    outgoing_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<OperatorMessage>>>,
    mut shutdown_rx: watch::Receiver<bool>,
    repaint: egui::Context,
) {
    let mut reconnect_delay = INITIAL_RECONNECT_DELAY;
    loop {
        if *shutdown_rx.borrow() {
            set_connection_status(&app_state, &repaint, ConnectionStatus::Disconnected);
            return;
        }

        set_connection_status(&app_state, &repaint, ConnectionStatus::Connecting);

        let disconnect_reason = match connect_websocket(&server_url).await {
            Ok(socket) => {
                reconnect_delay = INITIAL_RECONNECT_DELAY;
                set_connection_status(&app_state, &repaint, ConnectionStatus::Connected);

                let (write, read) = socket.split();
                let mut receive_task =
                    tokio::spawn(run_receive_loop(read, app_state.clone(), repaint.clone()));
                let mut send_task = tokio::spawn(run_send_loop(write, outgoing_rx.clone()));

                let reason = tokio::select! {
                    result = &mut receive_task => join_disconnect_reason(result, "receive task stopped"),
                    result = &mut send_task => join_disconnect_reason(result, "send task stopped"),
                    changed = shutdown_rx.changed() => {
                        match changed {
                            Ok(()) if *shutdown_rx.borrow() => {
                                receive_task.abort();
                                send_task.abort();
                                set_connection_status(&app_state, &repaint, ConnectionStatus::Disconnected);
                                return;
                            }
                            Ok(()) | Err(_) => "connection manager stopped".to_owned(),
                        }
                    }
                };

                receive_task.abort();
                send_task.abort();
                reason
            }
            Err(error) => error.to_string(),
        };

        if *shutdown_rx.borrow() {
            set_connection_status(&app_state, &repaint, ConnectionStatus::Disconnected);
            return;
        }

        set_connection_status(
            &app_state,
            &repaint,
            ConnectionStatus::Retrying(format!(
                "{disconnect_reason}. Retrying in {}s",
                reconnect_delay.as_secs()
            )),
        );

        tokio::select! {
            _ = sleep(reconnect_delay) => {}
            changed = shutdown_rx.changed() => {
                match changed {
                    Ok(()) if *shutdown_rx.borrow() => {
                        set_connection_status(&app_state, &repaint, ConnectionStatus::Disconnected);
                        return;
                    }
                    Ok(()) | Err(_) => {
                        set_connection_status(&app_state, &repaint, ConnectionStatus::Disconnected);
                        return;
                    }
                }
            }
        }

        reconnect_delay = std::cmp::min(reconnect_delay.saturating_mul(2), MAX_RECONNECT_DELAY);
    }
}

async fn connect_websocket(server_url: &str) -> Result<ClientWebSocket, TransportError> {
    let request = server_url
        .into_client_request()
        .map_err(|error| TransportError::WebSocketRequest(Box::new(error)))?;
    let connector = build_insecure_tls_connector()?;
    let (stream, _) = connect_async_tls_with_config(request, None, false, Some(connector))
        .await
        .map_err(|error| TransportError::WebSocketRequest(Box::new(error)))?;
    Ok(stream)
}

async fn run_receive_loop(
    mut read: futures_util::stream::SplitStream<ClientWebSocket>,
    app_state: SharedAppState,
    repaint: egui::Context,
) -> Result<(), String> {
    while let Some(frame) = read.next().await {
        match frame {
            Ok(WebSocketMessage::Text(payload)) => {
                match serde_json::from_str::<OperatorMessage>(&payload) {
                    Ok(message) => {
                        {
                            let mut state = lock_app_state(&app_state);
                            state.apply_operator_message(message);
                        }
                        repaint.request_repaint();
                    }
                    Err(error) => {
                        let message = format!("failed to decode operator message: {error}");
                        {
                            let mut state = lock_app_state(&app_state);
                            state.connection_status = ConnectionStatus::Error(message.clone());
                        }
                        repaint.request_repaint();
                    }
                }
            }
            Ok(WebSocketMessage::Ping(_)) | Ok(WebSocketMessage::Pong(_)) => {}
            Ok(WebSocketMessage::Close(frame)) => {
                return Err(close_reason(frame));
            }
            Ok(WebSocketMessage::Binary(_)) | Ok(WebSocketMessage::Frame(_)) => {}
            Err(error) => return Err(error.to_string()),
        }
    }

    Err("teamserver websocket closed".to_owned())
}

async fn run_send_loop(
    mut write: futures_util::stream::SplitSink<ClientWebSocket, WebSocketMessage>,
    outgoing_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<OperatorMessage>>>,
) -> Result<(), String> {
    loop {
        let next_message = {
            let mut receiver = outgoing_rx.lock().await;
            receiver.recv().await
        };

        let Some(message) = next_message else {
            return Ok(());
        };

        let payload = serde_json::to_string(&message).map_err(|error| error.to_string())?;
        write
            .send(WebSocketMessage::Text(payload.into()))
            .await
            .map_err(|error| error.to_string())?;
    }
}

fn build_insecure_tls_connector() -> Result<Connector, TransportError> {
    let provider = aws_lc_rs::default_provider();
    let verifier = Arc::new(DangerousCertificateVerifier { provider: provider.clone() });
    let client_config = ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|error| TransportError::Rustls(Box::new(error)))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok(Connector::Rustls(Arc::new(client_config)))
}

fn normalize_server_url(server_url: &str) -> Result<String, TransportError> {
    let mut url = Url::parse(server_url)
        .map_err(|source| TransportError::InvalidUrl { url: server_url.to_owned(), source })?;

    match url.scheme() {
        "ws" | "wss" => {}
        other => {
            return Err(TransportError::UnsupportedScheme { scheme: other.to_owned() });
        }
    }

    if url.host_str().is_none() {
        return Err(TransportError::MissingHost);
    }

    let normalized_path = match url.path() {
        "" | "/" => "/havoc/",
        "/havoc" => "/havoc/",
        path => path,
    }
    .to_owned();
    url.set_path(&normalized_path);

    Ok(url.to_string())
}

fn set_connection_status(
    app_state: &SharedAppState,
    repaint: &egui::Context,
    status: ConnectionStatus,
) {
    {
        let mut state = lock_app_state(app_state);
        state.connection_status = status;
    }
    repaint.request_repaint();
}

fn lock_app_state(app_state: &SharedAppState) -> MutexGuard<'_, AppState> {
    match app_state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn join_disconnect_reason(
    result: Result<Result<(), String>, tokio::task::JoinError>,
    default_message: &str,
) -> String {
    match result {
        Ok(Ok(())) => default_message.to_owned(),
        Ok(Err(message)) => message,
        Err(error) => error.to_string(),
    }
}

fn close_reason(frame: Option<CloseFrame>) -> String {
    frame
        .map(|close| match close.code {
            CloseCode::Normal => "teamserver websocket closed".to_owned(),
            _ => format!("teamserver closed connection: {}", close.reason),
        })
        .unwrap_or_else(|| "teamserver websocket closed".to_owned())
}

fn listener_summary_from_info(info: &ListenerInfo) -> ListenerSummary {
    ListenerSummary {
        name: info.name.clone().unwrap_or_else(|| "unnamed".to_owned()),
        protocol: info.protocol.clone().unwrap_or_else(|| "unknown".to_owned()),
        status: info.status.clone().unwrap_or_else(|| "Unknown".to_owned()),
    }
}

fn agent_summary_from_message(info: &red_cell_common::operator::AgentInfo) -> AgentSummary {
    AgentSummary {
        name_id: normalize_agent_id(&info.name_id),
        status: if info.active.eq_ignore_ascii_case("true") {
            "Alive".to_owned()
        } else {
            info.active.clone()
        },
        domain_name: info.domain_name.clone(),
        username: info.username.clone(),
        internal_ip: info.internal_ip.clone(),
        external_ip: info.external_ip.clone(),
        hostname: info.hostname.clone(),
        process_arch: info.process_arch.clone(),
        process_name: info.process_name.clone(),
        process_pid: info.process_pid.clone(),
        elevated: info.elevated,
        os_version: info.os_version.clone(),
        os_build: info.os_build.clone(),
        os_arch: info.os_arch.clone(),
        sleep_delay: info.sleep_delay.to_string(),
        sleep_jitter: info.sleep_jitter.to_string(),
        last_call_in: info.last_call_in.clone(),
        note: info.note.clone(),
    }
}

fn normalize_agent_id(agent_id: &str) -> String {
    let trimmed = agent_id.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    if let Ok(value) = u32::from_str_radix(without_prefix, 16) {
        return format!("{value:08X}");
    }

    trimmed.to_ascii_uppercase()
}

fn flat_info_string(info: &FlatInfo, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        info.fields.get(*key).and_then(|value| match value {
            serde_json::Value::String(string) => Some(string.clone()),
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
    })
}

fn sanitize_text(message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.is_empty() { "Connected".to_owned() } else { trimmed.to_owned() }
}

fn sanitize_output(output: &str) -> String {
    output.trim().to_owned()
}

fn response_is_loot_notification(info: &red_cell_common::operator::AgentResponseInfo) -> bool {
    matches!(
        info.extra.get("MiscType"),
        Some(serde_json::Value::String(kind)) if kind == "loot-new"
    )
}

fn loot_item_from_response(
    info: &red_cell_common::operator::AgentResponseInfo,
) -> Option<LootItem> {
    let name = extra_string(&info.extra, "LootName")?;
    let source = extra_string(&info.extra, "LootKind")
        .or_else(|| extra_string(&info.extra, "Operator"))
        .unwrap_or_else(|| "unknown".to_owned());
    let collected_at = extra_string(&info.extra, "CapturedAt").unwrap_or_default();
    let file_path = extra_string(&info.extra, "FilePath");
    let kind = loot_kind_from_strings(
        extra_string(&info.extra, "LootKind").as_deref(),
        Some(name.as_str()),
        file_path.as_deref(),
    );

    Some(LootItem {
        kind,
        name,
        agent_id: normalize_agent_id(&info.demon_id),
        source,
        collected_at,
        file_path,
        size_bytes: extra_u64(&info.extra, "SizeBytes"),
        content_base64: extra_string(&info.extra, "ContentBase64")
            .or_else(|| extra_string(&info.extra, "Data")),
        preview: extra_string(&info.extra, "Preview")
            .or_else(|| extra_string(&info.extra, "Message")),
    })
}

fn extra_string(extra: &BTreeMap<String, serde_json::Value>, key: &str) -> Option<String> {
    extra.get(key).and_then(|value| match value {
        serde_json::Value::String(string) => Some(string.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    })
}

fn extra_u64(extra: &BTreeMap<String, serde_json::Value>, key: &str) -> Option<u64> {
    extra.get(key).and_then(|value| match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(string) => string.parse::<u64>().ok(),
        _ => None,
    })
}

fn loot_item_from_flat_info(info: &FlatInfo, fallback_kind: LootKind) -> Option<LootItem> {
    let name = flat_info_string(info, &["Name", "FileName", "LootName"])?;
    let agent_id = flat_info_string(info, &["DemonID", "AgentID"])
        .map(|id| normalize_agent_id(&id))
        .unwrap_or_default();
    let file_path = flat_info_string(info, &["FilePath", "Path"]);
    let source = flat_info_string(info, &["Operator", "Pattern", "Kind", "Type"])
        .unwrap_or_else(|| fallback_kind.label().to_ascii_lowercase());
    let kind = loot_kind_from_strings(
        flat_info_string(info, &["Kind", "Type", "LootKind"]).as_deref(),
        Some(name.as_str()),
        file_path.as_deref(),
    );

    Some(LootItem {
        kind: if matches!(kind, LootKind::Other) { fallback_kind } else { kind },
        name,
        agent_id,
        source,
        collected_at: flat_info_string(info, &["CapturedAt", "Time", "Timestamp"])
            .unwrap_or_default(),
        file_path,
        size_bytes: flat_info_u64(info, &["SizeBytes", "Size"]),
        content_base64: flat_info_string(info, &["ContentBase64", "Data", "Payload"]),
        preview: flat_info_string(info, &["Credential", "Preview", "Message"]),
    })
}

fn flat_info_u64(info: &FlatInfo, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        info.fields.get(*key).and_then(|value| match value {
            serde_json::Value::Number(number) => number.as_u64(),
            serde_json::Value::String(string) => string.parse::<u64>().ok(),
            _ => None,
        })
    })
}

fn loot_kind_from_strings(
    kind: Option<&str>,
    name: Option<&str>,
    file_path: Option<&str>,
) -> LootKind {
    let mut haystacks = Vec::new();
    if let Some(kind) = kind {
        haystacks.push(kind.to_ascii_lowercase());
    }
    if let Some(name) = name {
        haystacks.push(name.to_ascii_lowercase());
    }
    if let Some(path) = file_path {
        haystacks.push(path.to_ascii_lowercase());
    }

    if haystacks.iter().any(|value| value.contains("credential") || value.contains("password")) {
        LootKind::Credential
    } else if haystacks.iter().any(|value| {
        value.contains("screenshot")
            || value.ends_with(".png")
            || value.ends_with(".jpg")
            || value.ends_with(".jpeg")
    }) {
        LootKind::Screenshot
    } else if haystacks.iter().any(|value| {
        value.contains("file")
            || value.contains("download")
            || value.contains('\\')
            || value.contains('/')
    }) {
        LootKind::File
    } else {
        LootKind::Other
    }
}

#[derive(Debug)]
struct DangerousCertificateVerifier {
    provider: crypto::CryptoProvider,
}

impl ServerCertVerifier for DangerousCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::operator::{
        AgentInfo as OperatorAgentInfo, AgentPivotsInfo, AgentResponseInfo, AgentUpdateInfo,
        BuildPayloadMessageInfo, ChatCode, EventCode, InitConnectionCode, ListenerCode,
        ListenerErrorInfo, LoginInfo, Message, MessageHead, MessageInfo, SessionCode,
        TeamserverLogInfo,
    };
    use red_cell_common::tls::{TlsKeyAlgorithm, generate_self_signed_tls_identity};
    use tokio::net::TcpListener;
    use tokio_tungstenite::{accept_async, tungstenite::Message as TungsteniteMessage};

    fn head(event: EventCode) -> MessageHead {
        MessageHead {
            event,
            user: "operator".to_owned(),
            timestamp: "10/03/2026 12:00:00".to_owned(),
            one_time: String::new(),
        }
    }

    #[test]
    fn normalize_server_url_appends_havoc_path() {
        let normalized = normalize_server_url("wss://127.0.0.1:40056")
            .expect("url normalization should succeed");

        assert_eq!(normalized, "wss://127.0.0.1:40056/havoc/");
    }

    #[test]
    fn app_state_applies_listener_and_agent_updates() {
        let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

        state.apply_operator_message(OperatorMessage::ListenerNew(Message {
            head: head(EventCode::Listener),
            info: ListenerInfo {
                name: Some("http".to_owned()),
                protocol: Some("Https".to_owned()),
                status: Some("Online".to_owned()),
                ..ListenerInfo::default()
            },
        }));
        state.apply_operator_message(OperatorMessage::AgentNew(Box::new(Message {
            head: head(EventCode::Session),
            info: OperatorAgentInfo {
                active: "true".to_owned(),
                background_check: false,
                domain_name: "LAB".to_owned(),
                elevated: true,
                encryption: Default::default(),
                internal_ip: "10.0.0.10".to_owned(),
                external_ip: "203.0.113.10".to_owned(),
                first_call_in: "10/03/2026 11:59:00".to_owned(),
                last_call_in: "10/03/2026 12:00:00".to_owned(),
                hostname: "wkstn-1".to_owned(),
                listener: "http".to_owned(),
                magic_value: "deadbeef".to_owned(),
                name_id: "abcd1234".to_owned(),
                os_arch: "x64".to_owned(),
                os_build: "19045".to_owned(),
                os_version: "Windows 11".to_owned(),
                pivots: AgentPivotsInfo::default(),
                port_fwds: Vec::new(),
                process_arch: "x64".to_owned(),
                process_name: "explorer.exe".to_owned(),
                process_pid: "1234".to_owned(),
                process_ppid: "1111".to_owned(),
                process_path: "C:\\Windows\\explorer.exe".to_owned(),
                reason: "manual".to_owned(),
                note: String::new(),
                sleep_delay: serde_json::Value::from(5),
                sleep_jitter: serde_json::Value::from(10),
                kill_date: serde_json::Value::Null,
                working_hours: serde_json::Value::Null,
                socks_cli: Vec::new(),
                socks_cli_mtx: None,
                socks_svr: Vec::new(),
                tasked_once: false,
                username: "operator".to_owned(),
                pivot_parent: String::new(),
            },
        })));
        state.apply_operator_message(OperatorMessage::AgentUpdate(Message {
            head: head(EventCode::Session),
            info: AgentUpdateInfo { agent_id: "ABCD1234".to_owned(), marked: "Alive".to_owned() },
        }));

        assert_eq!(state.listeners.len(), 1);
        assert_eq!(state.listeners[0].name, "http");
        assert_eq!(state.agents.len(), 1);
        assert_eq!(state.agents[0].name_id, "ABCD1234");
        assert_eq!(state.agents[0].status, "Alive");
    }

    #[test]
    fn agent_response_appends_console_output() {
        let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

        state.apply_operator_message(OperatorMessage::AgentResponse(Message {
            head: head(EventCode::Session),
            info: AgentResponseInfo {
                demon_id: "abcd1234".to_owned(),
                command_id: "42".to_owned(),
                output: "whoami".to_owned(),
                command_line: Some("shell whoami".to_owned()),
                extra: BTreeMap::new(),
            },
        }));

        let entries = state
            .agent_consoles
            .get("ABCD1234")
            .unwrap_or_else(|| panic!("console output should be stored"));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].command_id, "42");
        assert_eq!(entries[0].output, "whoami");
    }

    #[test]
    fn loot_notifications_update_loot_panel_state() {
        let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        let mut extra = BTreeMap::new();
        extra.insert("MiscType".to_owned(), serde_json::Value::String("loot-new".to_owned()));
        extra.insert("LootName".to_owned(), serde_json::Value::String("passwords.txt".to_owned()));
        extra.insert("LootKind".to_owned(), serde_json::Value::String("download".to_owned()));
        extra.insert(
            "CapturedAt".to_owned(),
            serde_json::Value::String("2026-03-10T12:00:00Z".to_owned()),
        );

        state.apply_operator_message(OperatorMessage::AgentResponse(Message {
            head: head(EventCode::Session),
            info: AgentResponseInfo {
                demon_id: "abcd1234".to_owned(),
                command_id: "99".to_owned(),
                output: String::new(),
                command_line: None,
                extra,
            },
        }));

        assert_eq!(state.loot.len(), 1);
        assert_eq!(state.loot[0].name, "passwords.txt");
        assert_eq!(state.loot[0].agent_id, "ABCD1234");
        assert_eq!(state.loot[0].source, "download");
        assert_eq!(state.loot[0].collected_at, "2026-03-10T12:00:00Z");
        assert!(!state.agent_consoles.contains_key("ABCD1234"));
    }

    #[test]
    fn credential_events_update_loot_state() {
        let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        let info = FlatInfo {
            fields: BTreeMap::from([
                ("DemonID".to_owned(), serde_json::Value::String("abcd1234".to_owned())),
                ("Name".to_owned(), serde_json::Value::String("password-hash".to_owned())),
                ("Credential".to_owned(), serde_json::Value::String("alice:hash".to_owned())),
                ("Pattern".to_owned(), serde_json::Value::String("pwdump-hash".to_owned())),
                (
                    "Timestamp".to_owned(),
                    serde_json::Value::String("2026-03-10T12:00:00Z".to_owned()),
                ),
            ]),
        };

        state.apply_operator_message(OperatorMessage::CredentialsAdd(Message {
            head: head(EventCode::Credentials),
            info: info.clone(),
        }));
        assert_eq!(state.loot.len(), 1);
        assert_eq!(state.loot[0].kind, LootKind::Credential);
        assert_eq!(state.loot[0].preview.as_deref(), Some("alice:hash"));

        state.apply_operator_message(OperatorMessage::CredentialsRemove(Message {
            head: head(EventCode::Credentials),
            info,
        }));
        assert!(state.loot.is_empty());
    }

    #[test]
    fn host_file_events_capture_screenshot_loot() {
        let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        state.apply_operator_message(OperatorMessage::HostFileAdd(Message {
            head: head(EventCode::HostFile),
            info: FlatInfo {
                fields: BTreeMap::from([
                    ("DemonID".to_owned(), serde_json::Value::String("abcd1234".to_owned())),
                    ("FileName".to_owned(), serde_json::Value::String("desktop.png".to_owned())),
                    (
                        "FilePath".to_owned(),
                        serde_json::Value::String("C:/Temp/desktop.png".to_owned()),
                    ),
                    ("Type".to_owned(), serde_json::Value::String("screenshot".to_owned())),
                    ("SizeBytes".to_owned(), serde_json::Value::from(512_u64)),
                    (
                        "Timestamp".to_owned(),
                        serde_json::Value::String("2026-03-10T12:00:00Z".to_owned()),
                    ),
                ]),
            },
        }));

        assert_eq!(state.loot.len(), 1);
        assert_eq!(state.loot[0].kind, LootKind::Screenshot);
        assert_eq!(state.loot[0].size_bytes, Some(512));
    }

    #[test]
    fn app_state_caps_chat_history() {
        let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

        for index in 0..(MAX_CHAT_MESSAGES + 5) {
            state.push_chat_message("teamserver", index.to_string(), format!("message-{index}"));
        }

        assert_eq!(state.chat_messages.len(), MAX_CHAT_MESSAGES);
        assert_eq!(state.chat_messages[0].message, "message-5");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn websocket_connection_accepts_self_signed_certificates() {
        red_cell_common::tls::install_default_crypto_provider();
        let identity = generate_self_signed_tls_identity(
            &["127.0.0.1".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity generation should succeed");
        let tls_acceptor = identity.tls_acceptor().expect("tls acceptor should build");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
        let address = listener.local_addr().expect("listener should have local address");

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("client should connect");
            let tls_stream =
                tls_acceptor.accept(stream).await.expect("tls handshake should succeed");
            let mut websocket =
                accept_async(tls_stream).await.expect("websocket upgrade should succeed");
            let payload = serde_json::to_string(&OperatorMessage::TeamserverLog(Message {
                head: MessageHead {
                    event: EventCode::Teamserver,
                    user: "teamserver".to_owned(),
                    timestamp: "10/03/2026 12:00:00".to_owned(),
                    one_time: String::new(),
                },
                info: TeamserverLogInfo { text: "hello".to_owned() },
            }))
            .expect("message should serialize");
            websocket
                .send(TungsteniteMessage::Text(payload.into()))
                .await
                .expect("server should send log event");
        });

        let mut socket = connect_websocket(&format!("wss://{address}/havoc/"))
            .await
            .expect("client should accept self-signed cert");
        let frame = socket
            .next()
            .await
            .expect("server frame should arrive")
            .expect("frame should be valid");

        match frame {
            WebSocketMessage::Text(payload) => {
                let message: OperatorMessage =
                    serde_json::from_str(&payload).expect("payload should deserialize");
                assert!(matches!(message, OperatorMessage::TeamserverLog(_)));
            }
            other => panic!("unexpected websocket frame: {other:?}"),
        }
    }

    #[test]
    fn message_variants_used_by_transport_state_reducer_are_constructible() {
        let _ = (
            InitConnectionCode::Success,
            ListenerCode::New,
            SessionCode::AgentNew,
            ChatCode::Message,
        );
        let _ = BuildPayloadMessageInfo {
            message_type: "info".to_owned(),
            message: "built".to_owned(),
        };
        let _ = MessageInfo { message: "ok".to_owned() };
        let _ = ListenerErrorInfo { error: "failed".to_owned(), name: "http".to_owned() };
    }

    #[test]
    fn queue_message_forwards_commands_to_sender_task() {
        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, _) = watch::channel(false);
        let transport = ClientTransport { runtime: None, shutdown_tx, outgoing_tx };

        let message = OperatorMessage::Login(Message {
            head: head(EventCode::InitConnection),
            info: LoginInfo { user: "operator".to_owned(), password: "hash".to_owned() },
        });

        transport
            .queue_message(message.clone())
            .unwrap_or_else(|error| panic!("queue_message should succeed: {error}"));

        let queued_message = outgoing_rx
            .try_recv()
            .unwrap_or_else(|error| panic!("queued message should be available: {error}"));
        assert_eq!(queued_message, message);
    }

    #[test]
    fn queue_message_returns_error_when_sender_is_closed() {
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        drop(outgoing_rx);
        let (shutdown_tx, _) = watch::channel(false);
        let transport = ClientTransport { runtime: None, shutdown_tx, outgoing_tx };

        let result = transport.queue_message(OperatorMessage::Login(Message {
            head: head(EventCode::InitConnection),
            info: LoginInfo { user: "operator".to_owned(), password: "hash".to_owned() },
        }));

        assert!(matches!(result, Err(TransportError::OutgoingQueueClosed)));
    }
}
