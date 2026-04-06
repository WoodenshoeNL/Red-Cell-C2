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
mod harvest;
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
/// Maximum number of simultaneous in-progress downloads tracked per agent.
/// A compromised agent can send unlimited Download mode=0 (start) packets, each consuming heap
/// memory before any byte-level cap activates. This count cap closes that gap.
const MAX_CONCURRENT_DOWNLOADS_PER_AGENT: usize = 32;
const DOTNET_INFO_PATCHED: u32 = 0x1;
const DOTNET_INFO_NET_VERSION: u32 = 0x2;
const DOTNET_INFO_ENTRYPOINT_EXECUTED: u32 = 0x3;
const DOTNET_INFO_FINISHED: u32 = 0x4;
const DOTNET_INFO_FAILED: u32 = 0x5;

#[derive(Clone, Debug)]
pub(crate) struct DownloadTracker {
    max_download_bytes: usize,
    max_total_download_bytes: usize,
    max_concurrent_downloads_per_agent: usize,
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
    /// Current pivot dispatch nesting depth — incremented each time a pivot
    /// command callback is recursively dispatched through a child agent.
    pivot_dispatch_depth: usize,
    /// Whether to accept pivot-child DEMON_INIT packets that use legacy AES-CTR
    /// (no `INIT_EXT_MONOTONIC_CTR` flag).  Mirrors `DemonConfig::allow_legacy_ctr`.
    allow_legacy_ctr: bool,
}

#[derive(Clone)]
struct BuiltinHandlerDependencies {
    registry: AgentRegistry,
    events: EventBus,
    database: Database,
    sockets: SocketRelayManager,
    downloads: DownloadTracker,
    plugins: Option<PluginRuntime>,
    /// Pivot dispatch nesting depth captured at handler-registration time.
    pivot_dispatch_depth: usize,
    /// Mirrors `DemonConfig::allow_legacy_ctr` — controls whether child-agent
    /// pivot registrations may use legacy (non-monotonic) AES-CTR.
    allow_legacy_ctr: bool,
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
    /// A new download start was rejected because the per-agent concurrent-download cap was reached.
    #[error(
        "agent 0x{agent_id:08X} already has {max_concurrent} concurrent downloads in progress; rejecting new download 0x{file_id:08X}"
    )]
    DownloadConcurrentLimitExceeded {
        /// Agent that attempted to open a new download.
        agent_id: u32,
        /// File identifier from the rejected start request.
        file_id: u32,
        /// Configured maximum number of concurrent in-progress downloads allowed per agent.
        max_concurrent: usize,
    },
    /// A pivot command callback was nested deeper than `MAX_PIVOT_CHAIN_DEPTH`.
    #[error(
        "pivot dispatch depth {depth} exceeds maximum ({max_depth}); possible recursive envelope attack"
    )]
    PivotDispatchDepthExceeded {
        /// The depth that was rejected.
        depth: usize,
        /// The configured maximum allowed depth.
        max_depth: usize,
    },
    /// No handler is registered for the command identifier carried by the callback.
    #[error(
        "no handler registered for command 0x{command_id:08X} from agent 0x{agent_id:08X} (request 0x{request_id:08X})"
    )]
    UnknownCommand {
        /// Agent that sent the callback.
        agent_id: u32,
        /// Unrecognised command identifier.
        command_id: u32,
        /// Request identifier from the callback header.
        request_id: u32,
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
        let BuiltinHandlerDependencies {
            registry,
            events,
            database,
            sockets,
            downloads,
            plugins,
            pivot_dispatch_depth,
            allow_legacy_ctr,
        } = dependencies;

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

        let ps_import_events = events.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandPsImport),
            move |agent_id, request_id, payload| {
                let events = ps_import_events.clone();
                Box::pin(async move {
                    assembly::handle_ps_import_callback(&events, agent_id, request_id, &payload)
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

        let harvest_database = database.clone();
        let harvest_events = events.clone();
        let harvest_registry = registry.clone();
        let harvest_plugins = plugins.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandHarvest),
            move |agent_id, request_id, payload| {
                let registry = harvest_registry.clone();
                let database = harvest_database.clone();
                let events = harvest_events.clone();
                let plugins = harvest_plugins.clone();
                Box::pin(async move {
                    harvest::handle_harvest_callback(
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
                        pivot_dispatch_depth,
                        allow_legacy_ctr,
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
            false,
        )
    }

    pub(crate) fn with_builtin_handlers_and_downloads(
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
        downloads: DownloadTracker,
        allow_legacy_ctr: bool,
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
                pivot_dispatch_depth: 0,
                allow_legacy_ctr,
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
            return Err(CommandDispatchError::UnknownCommand { agent_id, command_id, request_id });
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
            max_concurrent_downloads_per_agent: MAX_CONCURRENT_DOWNLOADS_PER_AGENT,
            inner: Arc::new(RwLock::new(DownloadTrackerState::default())),
        }
    }

    /// Override the per-agent concurrent download limit.
    ///
    /// Must be called before any downloads are tracked.
    #[must_use]
    pub(crate) fn with_max_concurrent_per_agent(mut self, limit: usize) -> Self {
        self.max_concurrent_downloads_per_agent = limit;
        self
    }

    /// Override the aggregate in-memory cap across all active downloads.
    ///
    /// The value is clamped to at least `max_download_bytes` so a single
    /// download can always make progress up to its per-download limit.
    /// Must be called before any downloads are tracked.
    #[must_use]
    pub(crate) fn with_max_aggregate_bytes(mut self, limit: usize) -> Self {
        self.max_total_download_bytes = limit.max(self.max_download_bytes);
        self
    }

    async fn start(
        &self,
        agent_id: u32,
        file_id: u32,
        state: DownloadState,
    ) -> Result<(), CommandDispatchError> {
        let mut tracker = self.inner.write().await;
        // Replacing an existing entry for the same (agent, file) pair does not count against the
        // cap — remove it first so the count below reflects truly new slots being consumed.
        self.remove_locked(&mut tracker, agent_id, file_id);
        let active = tracker.downloads.keys().filter(|(aid, _)| *aid == agent_id).count();
        if active >= self.max_concurrent_downloads_per_agent {
            return Err(CommandDispatchError::DownloadConcurrentLimitExceeded {
                agent_id,
                file_id,
                max_concurrent: self.max_concurrent_downloads_per_agent,
            });
        }
        tracker.downloads.insert((agent_id, file_id), TrackedDownload { state });
        Ok(())
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
                command_id: 0,
                message: format!(
                    "download 0x{file_id:08X} for agent 0x{agent_id:08X} was not opened"
                ),
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
                command_id: 0,
                message: format!(
                    "download 0x{file_id:08X} for agent 0x{agent_id:08X} was not opened"
                ),
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
mod tests;
