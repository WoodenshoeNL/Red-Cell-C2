//! Command routing for parsed Demon callback packages.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use red_cell_common::demon::{DemonCommand, DemonMessage, DemonPackage, DemonProtocolError};

use crate::DEFAULT_MAX_DOWNLOAD_BYTES;
use crate::{
    AgentRegistry, Database, DemonCallbackPackage, DemonInitSecretConfig, EventBus, PluginRuntime,
    SocketRelayManager,
};

mod assembly;
mod checkin;
mod context;
mod download;
mod error;
mod filesystem;
mod harvest;
mod kerberos;
mod network;
mod output;
mod pivot;
mod process;
mod response;
mod screenshot;
mod socket;
mod token;
mod transfer;
pub(crate) mod util;

pub use error::CommandDispatchError;

// `DownloadTracker` is also used from `listeners/`, so it needs crate-level visibility.
pub(crate) use download::DownloadTracker;

pub(crate) use context::DEFAULT_MAX_PIVOT_CHAIN_DEPTH;

// Flatten the context types and constants into this module's namespace so submodules
// can reach them via `super::Foo`.
#[allow(unused_imports)]
use context::{
    BuiltinDispatchContext, BuiltinHandlerDependencies, DOTNET_INFO_ENTRYPOINT_EXECUTED,
    DOTNET_INFO_FAILED, DOTNET_INFO_FINISHED, DOTNET_INFO_NET_VERSION, DOTNET_INFO_PATCHED,
};

// Bring all remaining shared types into this module's namespace so submodules can
// reach them via `super::Foo`.  These imports are not used directly within mod.rs
// itself — they exist to flatten the namespace for child modules.
#[allow(unused_imports)]
use download::{DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER, DownloadState};
#[allow(unused_imports)]
use response::{
    AgentResponseEntry, CredentialCapture, LootContext, agent_response_event,
    agent_response_event_with_extra, agent_response_event_with_extra_and_context,
    agent_response_extra, bool_string, broadcast_and_persist_agent_response,
    broadcast_credential_event, extract_credentials, insert_loot_record, job_state_name,
    job_type_name, looks_like_credential_line, looks_like_inline_secret, looks_like_pwdump_hash,
    loot_context, loot_new_event, metadata_with_context, non_empty_option,
    parse_optional_kill_date, persist_agent_response_record, persist_credentials_from_output,
};
#[allow(unused_imports)]
use util::CallbackParser;

type HandlerFuture =
    Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, CommandDispatchError>> + Send>>;
type Handler = dyn Fn(u32, u32, Vec<u8>) -> HandlerFuture + Send + Sync + 'static;

/// Central registry of Demon command handlers keyed by command identifier.
#[derive(Clone)]
pub struct CommandDispatcher {
    handlers: Arc<HashMap<u32, Arc<Handler>>>,
    pub(in crate::dispatch) downloads: DownloadTracker,
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
            max_pivot_chain_depth,
            allow_legacy_ctr,
            init_secret_config,
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
        let pivot_init_secret_config = init_secret_config;
        self.register_handler(
            u32::from(DemonCommand::CommandPivot),
            move |agent_id, request_id, payload| {
                let registry = pivot_registry.clone();
                let events = pivot_events.clone();
                let database = pivot_database.clone();
                let sockets = pivot_sockets.clone();
                let downloads = pivot_downloads.clone();
                let plugins = pivot_plugins.clone();
                let init_secret_config = pivot_init_secret_config.clone();
                Box::pin(async move {
                    let context = BuiltinDispatchContext {
                        registry: &registry,
                        events: &events,
                        database: &database,
                        sockets: &sockets,
                        downloads: &downloads,
                        plugins: plugins.as_ref(),
                        pivot_dispatch_depth,
                        max_pivot_chain_depth,
                        allow_legacy_ctr,
                        init_secret_config,
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
            DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
            false,
            DemonInitSecretConfig::None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_builtin_handlers_and_downloads(
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
        downloads: DownloadTracker,
        max_pivot_chain_depth: usize,
        allow_legacy_ctr: bool,
        init_secret_config: DemonInitSecretConfig,
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
                max_pivot_chain_depth,
                allow_legacy_ctr,
                init_secret_config,
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
    #[tracing::instrument(skip(self, payload), fields(agent_id = format_args!("0x{:08X}", agent_id), command_id = format_args!("0x{:04X}", command_id), request_id))]
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

        let cmd_label = format!("0x{command_id:04X}");
        crate::metrics::inc_callbacks_total(&cmd_label);
        let start = std::time::Instant::now();
        let result = handler(agent_id, request_id, payload.to_vec()).await;
        crate::metrics::observe_callback_latency(&cmd_label, start.elapsed().as_secs_f64());
        result
    }

    /// Dispatch multiple parsed callback packages and concatenate any response packages.
    #[tracing::instrument(skip(self, packages), fields(agent_id = format_args!("0x{:08X}", agent_id), package_count = packages.len()))]
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

    // ECDH agents have no AES session key — the outer AES-256-GCM seal in
    // `process_ecdh_session` provides confidentiality, so job payloads must
    // be returned as plaintext (no inner AES-CTR layer).
    let skip_aes = registry.is_ecdh_transport(agent_id).await;

    let mut packages = Vec::with_capacity(jobs.len());

    for job in jobs {
        let payload = if job.payload.is_empty() || skip_aes {
            job.payload
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

#[cfg(test)]
mod tests;
