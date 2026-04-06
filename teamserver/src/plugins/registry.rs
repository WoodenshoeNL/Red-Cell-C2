//! Plugin registry types: registered callbacks, commands, health tracking, and the
//! shared inner state carried by every [`super::PluginRuntime`] clone.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use tokio::runtime::Handle;
use tokio::sync::RwLock;

use crate::{AgentRegistry, Database, EventBus, ListenerManager, SocketRelayManager};

/// Default number of consecutive callback failures before a plugin is disabled.
pub(super) const DEFAULT_MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// A Python event-callback together with the name of the plugin that registered it.
///
/// The plugin name is used for per-plugin health tracking and auto-disable logic.
#[derive(Clone, Debug)]
pub(super) struct NamedCallback {
    /// Name of the `.py` module that registered this callback (e.g. `"my_plugin"`).
    pub(super) plugin_name: String,
    /// The Python callable.
    pub(super) callback: Arc<Py<PyAny>>,
}

#[derive(Clone, Debug)]
pub(super) struct RegisteredCommand {
    pub(super) description: String,
    pub(super) callback: Arc<Py<PyAny>>,
    /// Plugin name that registered this command, for health tracking.
    pub(super) plugin_name: String,
}

/// Health snapshot for a single plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHealthEntry {
    /// Name of the `.py` module (without extension).
    pub plugin_name: String,
    /// Number of consecutive callback failures since the last success.
    pub consecutive_failures: u32,
    /// Whether the plugin has been automatically disabled.
    pub disabled: bool,
}

#[derive(Debug)]
pub(super) struct PluginRuntimeInner {
    pub(super) database: Database,
    pub(super) agents: AgentRegistry,
    pub(super) events: EventBus,
    pub(super) _sockets: SocketRelayManager,
    pub(super) plugins_dir: Option<PathBuf>,
    pub(super) runtime_handle: Handle,
    pub(super) listeners: RwLock<Option<ListenerManager>>,
    pub(super) callbacks: RwLock<BTreeMap<&'static str, Vec<NamedCallback>>>,
    pub(super) commands: RwLock<BTreeMap<String, RegisteredCommand>>,
    /// Per-plugin consecutive failure counts (plugin_name → count).
    pub(super) failure_counts: Mutex<BTreeMap<String, u32>>,
    /// Plugins that have been auto-disabled after exceeding `max_consecutive_failures`.
    pub(super) disabled_plugins: Mutex<BTreeSet<String>>,
    /// Maximum number of consecutive failures before a plugin is auto-disabled.
    pub(super) max_consecutive_failures: u32,
    /// When true, `invoke_callbacks` returns `Err` immediately — test-only fault injection.
    #[cfg(test)]
    pub(super) force_emit_failure: std::sync::atomic::AtomicBool,
}
