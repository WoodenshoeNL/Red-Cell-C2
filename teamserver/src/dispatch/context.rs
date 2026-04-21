use crate::{
    AgentRegistry, Database, DemonInitSecretConfig, EventBus, PluginRuntime, SocketRelayManager,
};

use super::download::DownloadTracker;

/// Default maximum pivot-chain dispatch depth used when no profile override is present.
pub(crate) const DEFAULT_MAX_PIVOT_CHAIN_DEPTH: usize = 10;

pub(super) const DOTNET_INFO_PATCHED: u32 = 0x1;
pub(super) const DOTNET_INFO_NET_VERSION: u32 = 0x2;
pub(super) const DOTNET_INFO_ENTRYPOINT_EXECUTED: u32 = 0x3;
pub(super) const DOTNET_INFO_FINISHED: u32 = 0x4;
pub(super) const DOTNET_INFO_FAILED: u32 = 0x5;

#[derive(Clone)]
pub(super) struct BuiltinDispatchContext<'a> {
    pub(super) registry: &'a AgentRegistry,
    pub(super) events: &'a EventBus,
    pub(super) database: &'a Database,
    pub(super) sockets: &'a SocketRelayManager,
    pub(super) downloads: &'a DownloadTracker,
    pub(super) plugins: Option<&'a PluginRuntime>,
    /// Current pivot dispatch nesting depth — incremented each time a pivot
    /// command callback is recursively dispatched through a child agent.
    pub(super) pivot_dispatch_depth: usize,
    /// Configured maximum allowed pivot dispatch nesting depth.
    ///
    /// When `pivot_dispatch_depth` reaches this value the dispatch is rejected,
    /// an audit log entry is written, and an error event is broadcast to
    /// operators. Sourced from the profile `Teamserver.MaxPivotChainDepth`
    /// field; defaults to [`DEFAULT_MAX_PIVOT_CHAIN_DEPTH`] when absent.
    pub(super) max_pivot_chain_depth: usize,
    /// Whether to accept pivot-child DEMON_INIT packets that use legacy AES-CTR
    /// (no `INIT_EXT_MONOTONIC_CTR` flag).  Mirrors `DemonConfig::allow_legacy_ctr`.
    pub(super) allow_legacy_ctr: bool,
    /// HKDF init-secret configuration to enforce on pivot-child DEMON_INIT packets.
    /// Mirrors the listener's `DemonInitSecretConfig` so SMB pivot registration is
    /// subject to the same server-secret check as direct HTTP/DNS/SMB connections.
    pub(super) init_secret_config: DemonInitSecretConfig,
}

#[derive(Clone)]
pub(super) struct BuiltinHandlerDependencies {
    pub(super) registry: AgentRegistry,
    pub(super) events: EventBus,
    pub(super) database: Database,
    pub(super) sockets: SocketRelayManager,
    pub(super) downloads: DownloadTracker,
    pub(super) plugins: Option<PluginRuntime>,
    /// Pivot dispatch nesting depth captured at handler-registration time.
    pub(super) pivot_dispatch_depth: usize,
    /// Configured maximum allowed pivot dispatch nesting depth.
    pub(super) max_pivot_chain_depth: usize,
    /// Mirrors `DemonConfig::allow_legacy_ctr` — controls whether child-agent
    /// pivot registrations may use legacy (non-monotonic) AES-CTR.
    pub(super) allow_legacy_ctr: bool,
    /// HKDF init-secret configuration for pivot-child DEMON_INIT packets.
    pub(super) init_secret_config: DemonInitSecretConfig,
}
