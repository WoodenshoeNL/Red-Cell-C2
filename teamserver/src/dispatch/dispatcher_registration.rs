use red_cell_common::demon::DemonCommand;

use super::{
    AgentRegistry, BuiltinHandlerDependencies, CommandDispatcher, EventBus, PluginRuntime,
    SocketRelayManager, checkin, output, process,
};
use crate::Database;

impl CommandDispatcher {
    /// Wire every built-in Demon command handler onto this dispatcher.
    ///
    /// Delegates to focused helpers grouped by command family:
    /// - system (checkin, sleep, lifecycle)
    /// - process/injection
    /// - output/text-result
    /// - I/O and network (filesystem, transfer, sockets, pivot)
    pub(in crate::dispatch) fn register_builtin_handlers(
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

        self.register_system_handlers(
            registry.clone(),
            events.clone(),
            database.clone(),
            plugins.clone(),
            sockets.clone(),
            include_get_job,
        );
        self.register_process_handlers(registry.clone(), events.clone(), database.clone());
        self.register_output_handlers(
            registry.clone(),
            events.clone(),
            database.clone(),
            plugins.clone(),
            downloads.clone(),
        );
        self.register_io_handlers(
            registry,
            events,
            database,
            plugins,
            downloads,
            sockets,
            pivot_dispatch_depth,
            max_pivot_chain_depth,
            allow_legacy_ctr,
            init_secret_config,
        );
    }

    /// Register system/lifecycle handlers: GetJob, Checkin, ProcList, Sleep, DemonInfo,
    /// Exit, KillDate.
    fn register_system_handlers(
        &mut self,
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        plugins: Option<PluginRuntime>,
        sockets: SocketRelayManager,
        include_get_job: bool,
    ) {
        if include_get_job {
            let get_job_registry = registry.clone();
            self.register_handler(
                u32::from(DemonCommand::CommandGetJob),
                move |agent_id, request_id, _| {
                    let registry = get_job_registry.clone();
                    Box::pin(async move {
                        super::dispatcher_runtime::handle_get_job(&registry, agent_id, request_id)
                            .await
                    })
                },
            );
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

        let proc_list_registry = registry.clone();
        let proc_list_events = events.clone();
        let proc_list_database = database.clone();
        self.register_handler(
            u32::from(DemonCommand::CommandProcList),
            move |agent_id, request_id, payload| {
                let registry = proc_list_registry.clone();
                let events = proc_list_events.clone();
                let database = proc_list_database.clone();
                Box::pin(async move {
                    process::handle_process_list_callback(
                        &registry, &database, &events, agent_id, request_id, &payload,
                    )
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
    }
}
