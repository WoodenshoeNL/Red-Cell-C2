//! Plugin registry types and operations: callback/command registration, health
//! tracking, auto-disable accounting, and the shared inner state carried by
//! every [`super::PluginRuntime`] clone.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use tokio::runtime::Handle;
use tokio::sync::RwLock;
use tracing::error;

use super::{PluginError, PluginEvent, PluginRuntime};
use crate::{AgentRegistry, Database, EventBus, ListenerManager, SocketRelayManager};

/// Default number of consecutive callback failures before a plugin is disabled.
pub(super) const DEFAULT_MAX_CONSECUTIVE_FAILURES: u32 = 5;

thread_local! {
    /// Plugin name set during `load_plugins_blocking` while loading each `.py`
    /// module. Callbacks registered during module initialisation use this to
    /// attach their plugin name for health-tracking purposes.
    pub(super) static LOADING_PLUGIN: RefCell<Option<String>> = const { RefCell::new(None) };
}

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

impl PluginRuntime {
    pub(super) async fn register_callback(
        &self,
        event: PluginEvent,
        callback: Py<PyAny>,
    ) -> Result<(), PluginError> {
        let plugin_name = LOADING_PLUGIN
            .with(|cell| cell.borrow().clone())
            .unwrap_or_else(|| "<unknown>".to_owned());
        self.inner
            .callbacks
            .write()
            .await
            .entry(event.as_str())
            .or_default()
            .push(NamedCallback { plugin_name, callback: Arc::new(callback) });
        Ok(())
    }

    pub(super) async fn register_command(
        &self,
        name: String,
        description: String,
        callback: Py<PyAny>,
    ) -> Result<(), PluginError> {
        let plugin_name = LOADING_PLUGIN
            .with(|cell| cell.borrow().clone())
            .unwrap_or_else(|| "<unknown>".to_owned());
        self.inner.commands.write().await.insert(
            name,
            RegisteredCommand { description, callback: Arc::new(callback), plugin_name },
        );
        Ok(())
    }

    /// Record a successful callback invocation for a plugin, resetting its consecutive failure count.
    pub(super) fn record_callback_success(&self, plugin_name: &str) {
        if let Ok(mut counts) = self.inner.failure_counts.lock() {
            counts.remove(plugin_name);
        }
    }

    /// Record a failed callback invocation. Returns `true` when the plugin was just disabled.
    pub(super) fn record_callback_failure(&self, plugin_name: &str) -> bool {
        let threshold = self.inner.max_consecutive_failures;
        let new_count = {
            let mut counts = match self.inner.failure_counts.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let entry = counts.entry(plugin_name.to_owned()).or_insert(0);
            *entry += 1;
            *entry
        };

        if new_count >= threshold {
            let mut disabled = match self.inner.disabled_plugins.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            if disabled.insert(plugin_name.to_owned()) {
                error!(
                    plugin = plugin_name,
                    consecutive_failures = new_count,
                    "plugin disabled after too many consecutive failures"
                );
                return true;
            }
        }
        false
    }

    /// Returns `true` if the given plugin has been auto-disabled.
    pub(super) fn is_plugin_disabled(&self, plugin_name: &str) -> bool {
        match self.inner.disabled_plugins.lock() {
            Ok(g) => g.contains(plugin_name),
            Err(e) => e.into_inner().contains(plugin_name),
        }
    }

    /// Return a health snapshot for every plugin that has registered at least one callback
    /// or command, including those that have never failed.
    pub fn plugin_health_summary(&self) -> Vec<PluginHealthEntry> {
        let mut plugin_names: BTreeSet<String> = BTreeSet::new();
        if let Ok(callbacks) = self.inner.callbacks.try_read() {
            for entries in callbacks.values() {
                for cb in entries {
                    plugin_names.insert(cb.plugin_name.clone());
                }
            }
        }
        if let Ok(commands) = self.inner.commands.try_read() {
            for cmd in commands.values() {
                plugin_names.insert(cmd.plugin_name.clone());
            }
        }

        let counts = self.inner.failure_counts.lock().unwrap_or_else(|e| e.into_inner());
        let disabled = self.inner.disabled_plugins.lock().unwrap_or_else(|e| e.into_inner());

        plugin_names
            .into_iter()
            .map(|name| {
                let consecutive_failures = *counts.get(&name).unwrap_or(&0);
                let is_disabled = disabled.contains(&name);
                PluginHealthEntry { plugin_name: name, consecutive_failures, disabled: is_disabled }
            })
            .collect()
    }
}
