use std::collections::HashMap;
use std::sync::Arc;

use super::{
    AgentRegistry, BuiltinHandlerDependencies, CommandDispatcher, DEFAULT_MAX_DOWNLOAD_BYTES,
    DEFAULT_MAX_PIVOT_CHAIN_DEPTH, DemonInitSecretConfig, DownloadTracker, EventBus, PluginRuntime,
    SocketRelayManager,
};
use crate::Database;

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
    pub(in crate::dispatch) fn with_max_download_bytes(max_download_bytes: usize) -> Self {
        Self {
            handlers: Arc::new(HashMap::new()),
            downloads: DownloadTracker::new(max_download_bytes),
        }
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
        F: Fn(u32, u32, Vec<u8>) -> super::HandlerFuture + Send + Sync + 'static,
    {
        Arc::make_mut(&mut self.handlers).insert(command_id, Arc::new(handler));
    }

    /// Return `true` when a handler is registered for `command_id`.
    #[must_use]
    pub fn handles_command(&self, command_id: u32) -> bool {
        self.handlers.contains_key(&command_id)
    }
}
