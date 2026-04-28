use red_cell_common::demon::DemonCommand;

use super::{
    AgentRegistry, CommandDispatcher, DownloadTracker, EventBus, PluginRuntime, assembly, network,
    output, process, token, transfer,
};
use crate::Database;

impl CommandDispatcher {
    /// Register handlers for process/injection commands: Proc, PsImport, ProcPpidSpoof,
    /// InjectShellcode, InjectDll, SpawnDll.
    pub(in crate::dispatch) fn register_process_handlers(
        &mut self,
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
    ) {
        let proc_registry = registry.clone();
        let proc_events = events.clone();
        let proc_database = database.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandProc),
            move |agent_id, request_id, payload| {
                let registry = proc_registry.clone();
                let events = proc_events.clone();
                let database = proc_database.clone();
                Box::pin(async move {
                    process::handle_process_command_callback(
                        &registry, &database, &events, agent_id, request_id, &payload,
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
        let proc_ppid_database = database.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandProcPpidSpoof),
            move |agent_id, request_id, payload| {
                let registry = proc_ppid_registry.clone();
                let events = proc_ppid_events.clone();
                let database = proc_ppid_database.clone();
                Box::pin(async move {
                    process::handle_proc_ppid_spoof_callback(
                        &registry, &database, &events, agent_id, request_id, &payload,
                    )
                    .await
                })
            },
        );

        let inject_registry = registry.clone();
        let inject_events = events.clone();
        let inject_database = database.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandInjectShellcode),
            move |agent_id, request_id, payload| {
                let registry = inject_registry.clone();
                let events = inject_events.clone();
                let database = inject_database.clone();
                Box::pin(async move {
                    process::handle_inject_shellcode_callback(
                        &registry, &database, &events, agent_id, request_id, &payload,
                    )
                    .await
                })
            },
        );

        let inject_dll_registry = registry.clone();
        let inject_dll_events = events.clone();
        let inject_dll_database = database.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandInjectDll),
            move |agent_id, request_id, payload| {
                let registry = inject_dll_registry.clone();
                let events = inject_dll_events.clone();
                let database = inject_dll_database.clone();
                Box::pin(async move {
                    process::handle_inject_dll_callback(
                        &registry, &database, &events, agent_id, request_id, &payload,
                    )
                    .await
                })
            },
        );

        let spawn_dll_registry = registry.clone();
        let spawn_dll_events = events.clone();
        let spawn_dll_database = database.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandSpawnDll),
            move |agent_id, request_id, payload| {
                let registry = spawn_dll_registry.clone();
                let events = spawn_dll_events.clone();
                let database = spawn_dll_database.clone();
                Box::pin(async move {
                    process::handle_spawn_dll_callback(
                        &registry, &database, &events, agent_id, request_id, &payload,
                    )
                    .await
                })
            },
        );
    }

    /// Register handlers for output/text-result commands: Output, Error, BeaconOutput, Token,
    /// InlineExecute, AssemblyInlineExecute, AssemblyListVersions, Job, Net, Config.
    pub(in crate::dispatch) fn register_output_handlers(
        &mut self,
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        plugins: Option<PluginRuntime>,
        downloads: DownloadTracker,
    ) {
        let command_output_registry = registry.clone();
        let command_output_events = events.clone();
        let command_output_database = database.clone();
        let command_output_plugins = plugins.clone();
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

        let error_registry = registry.clone();
        let error_events = events.clone();
        let error_database = database.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandError),
            move |agent_id, request_id, payload| {
                let registry = error_registry.clone();
                let events = error_events.clone();
                let database = error_database.clone();
                Box::pin(async move {
                    output::handle_command_error_callback(
                        &registry, &database, &events, agent_id, request_id, &payload,
                    )
                    .await
                })
            },
        );

        let beacon_registry = registry.clone();
        let beacon_events = events.clone();
        let beacon_database = database.clone();
        let beacon_downloads = downloads.clone();
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
    }
}
