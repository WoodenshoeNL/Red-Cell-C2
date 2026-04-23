use red_cell_common::demon::DemonCommand;

use super::{
    AgentRegistry, BuiltinDispatchContext, CommandDispatcher, DemonInitSecretConfig,
    DownloadTracker, EventBus, PluginRuntime, SocketRelayManager, filesystem, harvest, kerberos,
    pivot, screenshot, socket, transfer,
};
use crate::Database;

impl CommandDispatcher {
    /// Register handlers for I/O commands: Fs, Screenshot, Harvest, Transfer, Kerberos,
    /// MemFile, PackageDropped.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::dispatch) fn register_io_handlers(
        &mut self,
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        plugins: Option<PluginRuntime>,
        downloads: DownloadTracker,
        sockets: SocketRelayManager,
        pivot_dispatch_depth: usize,
        max_pivot_chain_depth: usize,
        allow_legacy_ctr: bool,
        init_secret_config: DemonInitSecretConfig,
    ) {
        let fs_registry = registry.clone();
        let fs_events = events.clone();
        let fs_database = database.clone();
        let fs_downloads = downloads.clone();
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

        let screenshot_registry = registry.clone();
        let screenshot_events = events.clone();
        let screenshot_database = database.clone();
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

        let harvest_registry = registry.clone();
        let harvest_events = events.clone();
        let harvest_database = database.clone();
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
}
