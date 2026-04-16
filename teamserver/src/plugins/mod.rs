//! Embedded Python plugin runtime for the teamserver.

mod events;
mod python;
mod registry;

pub use events::PluginEvent;
use python::{PyAgent, PyEvent, populate_api_module};
pub use registry::PluginHealthEntry;
use registry::{DEFAULT_MAX_CONSECUTIVE_FAILURES, LOADING_PLUGIN, PluginRuntimeInner};

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyModule, PyTuple};
use red_cell_common::AgentRecord;
use red_cell_common::config::OperatorRole;
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::runtime::Handle;
use tokio::sync::RwLock;
use tracing::{error, instrument, warn};

use crate::{
    AgentRegistry, Database, EventBus, Job, ListenerManager, ListenerManagerError, LootRecord,
    PersistedListener, SocketRelayManager, TeamserverError,
};

static RUNTIME: OnceLock<Mutex<Option<PluginRuntime>>> = OnceLock::new();
static NEXT_REQUEST_ID: AtomicU32 = AtomicU32::new(1);

// Thread-local runtime set during Python callback dispatch so that re-entrant
// calls from Python into the Rust API bypass the global `RUNTIME` mutex
// entirely, eliminating the deadlock window.
thread_local! {
    static CALLBACK_RUNTIME: RefCell<Option<PluginRuntime>> = const { RefCell::new(None) };
}

/// RAII guard that sets the [`CALLBACK_RUNTIME`] thread-local for the current
/// scope and clears it on drop, ensuring callbacks always have a lock-free path
/// to the active runtime.
struct CallbackRuntimeGuard;

impl CallbackRuntimeGuard {
    fn enter(runtime: &PluginRuntime) -> Self {
        CALLBACK_RUNTIME.with(|cell| {
            *cell.borrow_mut() = Some(runtime.clone());
        });
        Self
    }
}

impl Drop for CallbackRuntimeGuard {
    fn drop(&mut self) {
        CALLBACK_RUNTIME.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
}

// Thread-local caller role set during `invoke_registered_command` so that Python
// API functions can enforce RBAC without needing to pass the role through Python.
// When `None`, the caller is the system (e.g. event callbacks at startup) and
// all permissions are granted.
thread_local! {
    static CALLER_ROLE: RefCell<Option<OperatorRole>> = const { RefCell::new(None) };
}

/// RAII guard that sets the [`CALLER_ROLE`] thread-local for the current scope
/// and clears it on drop.
struct CallerRoleGuard;

impl CallerRoleGuard {
    fn enter(role: OperatorRole) -> Self {
        CALLER_ROLE.with(|cell| {
            *cell.borrow_mut() = Some(role);
        });
        Self
    }
}

impl Drop for CallerRoleGuard {
    fn drop(&mut self) {
        CALLER_ROLE.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
}

fn runtime_slot() -> &'static Mutex<Option<PluginRuntime>> {
    RUNTIME.get_or_init(|| Mutex::new(None))
}

fn next_request_id() -> u32 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

/// Errors returned by the embedded Python plugin host.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// Python execution failed.
    #[error("python error: {0}")]
    Python(#[from] PyErr),
    /// Teamserver state could not be queried while serving the Python API.
    #[error("{0}")]
    Teamserver(#[from] TeamserverError),
    /// Listener lifecycle management failed while serving the Python API.
    #[error("{0}")]
    ListenerManager(#[from] ListenerManagerError),
    /// JSON serialization failed while marshalling data into Python.
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// The configured plugin directory is invalid.
    #[error("plugin directory `{path}` does not exist or is not a directory")]
    InvalidPluginDirectory {
        /// The invalid filesystem path.
        path: PathBuf,
    },
    /// A plugin path or module name contains unsupported interior NUL bytes.
    #[error("plugin path contains an interior NUL byte: {path}")]
    InvalidCStringPath {
        /// The offending path.
        path: String,
    },
    /// A tokio task failed while dispatching plugin work.
    #[error("plugin task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    /// A plugin requested listener control before the manager was attached.
    #[error("listener manager is not available")]
    ListenerManagerUnavailable,
    /// A plugin command could not be routed through the teamserver tasking pipeline.
    #[error("{message}")]
    AgentCommand {
        /// Human-readable tasking failure.
        message: String,
    },
    /// The caller's RBAC role does not grant the required permission.
    #[error("plugin permission denied: role `{role:?}` lacks `{permission}` permission")]
    PermissionDenied {
        /// The caller's RBAC role.
        role: OperatorRole,
        /// The permission that was required.
        permission: &'static str,
    },
    /// The global plugin runtime mutex was poisoned by a panic in another thread.
    #[error("plugin runtime mutex poisoned: a thread panicked while holding the lock")]
    MutexPoisoned,
}

/// Shared embedded Python runtime state.
#[derive(Clone, Debug)]
pub struct PluginRuntime {
    inner: Arc<PluginRuntimeInner>,
}

impl PluginRuntime {
    /// Initialize the embedded Python runtime and install the `red_cell` and `havoc` API modules.
    #[instrument(skip(database, agents, events, sockets))]
    pub async fn initialize(
        database: Database,
        agents: AgentRegistry,
        events: EventBus,
        sockets: SocketRelayManager,
        plugins_dir: Option<PathBuf>,
    ) -> Result<Self, PluginError> {
        let runtime = Self {
            inner: Arc::new(PluginRuntimeInner {
                database,
                agents,
                events,
                _sockets: sockets,
                plugins_dir,
                runtime_handle: Handle::current(),
                listeners: RwLock::new(None),
                callbacks: RwLock::new(BTreeMap::new()),
                commands: RwLock::new(BTreeMap::new()),
                failure_counts: Mutex::new(BTreeMap::new()),
                disabled_plugins: Mutex::new(BTreeSet::new()),
                max_consecutive_failures: DEFAULT_MAX_CONSECUTIVE_FAILURES,
                #[cfg(test)]
                force_emit_failure: std::sync::atomic::AtomicBool::new(false),
            }),
        };

        runtime.install_as_active()?;
        let runtime_for_python = runtime.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = CallbackRuntimeGuard::enter(&runtime_for_python);
            pyo3::prepare_freethreaded_python();
            Python::with_gil(|py| -> PyResult<()> {
                runtime_for_python.install_api_module(py)?;
                Ok(())
            })
        })
        .await
        .map_err(PluginError::from)?
        .map_err(PluginError::from)?;

        Ok(runtime)
    }

    /// Load all `.py` modules from the configured plugins directory.
    #[instrument(skip(self))]
    pub async fn load_plugins(&self) -> Result<Vec<String>, PluginError> {
        let Some(directory) = self.inner.plugins_dir.clone() else {
            return Ok(Vec::new());
        };

        if !directory.is_dir() {
            return Err(PluginError::InvalidPluginDirectory { path: directory });
        }

        let runtime = self.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = CallbackRuntimeGuard::enter(&runtime);
            runtime.load_plugins_blocking(&directory)
        })
        .await?
    }

    /// Return the configured plugin directory, if one was provided.
    #[must_use]
    pub fn plugins_dir(&self) -> Option<&Path> {
        self.inner.plugins_dir.as_deref()
    }

    /// Attach the listener manager once the application has finished bootstrapping.
    #[instrument(skip(self, listeners))]
    pub async fn attach_listener_manager(&self, listeners: ListenerManager) {
        *self.inner.listeners.write().await = Some(listeners);
    }

    /// Return the registered Python command names in sorted order.
    #[instrument(skip(self))]
    pub async fn command_names(&self) -> Vec<String> {
        self.inner.commands.read().await.keys().cloned().collect()
    }

    /// Return the registered Python command descriptions keyed by command name.
    #[instrument(skip(self))]
    pub async fn command_descriptions(&self) -> BTreeMap<String, String> {
        self.inner
            .commands
            .read()
            .await
            .iter()
            .map(|(name, command)| (name.clone(), command.description.clone()))
            .collect()
    }

    /// Dispatch an agent check-in event to subscribed Python callbacks.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn emit_agent_checkin(&self, agent_id: u32) -> Result<(), PluginError> {
        let Some(agent) = self.inner.agents.get(agent_id).await else {
            return Ok(());
        };
        let payload = serde_json::to_value(agent)?;
        self.invoke_callbacks(PluginEvent::AgentCheckin, payload).await
    }

    /// Dispatch a command output event to subscribed Python callbacks.
    #[instrument(skip(self, output), fields(agent_id = format_args!("0x{:08X}", agent_id), command_id, request_id))]
    pub async fn emit_command_output(
        &self,
        agent_id: u32,
        command_id: u32,
        request_id: u32,
        output: &str,
    ) -> Result<(), PluginError> {
        let payload = json!({
            "agent_id": agent_id,
            "command_id": command_id,
            "request_id": request_id,
            "output": output,
        });
        self.invoke_callbacks(PluginEvent::CommandOutput, payload).await
    }

    /// Dispatch an agent registration (DemonInit) event to subscribed Python callbacks.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn emit_agent_registered(&self, agent_id: u32) -> Result<(), PluginError> {
        let Some(agent) = self.inner.agents.get(agent_id).await else {
            return Ok(());
        };
        let payload = serde_json::to_value(agent)?;
        self.invoke_callbacks(PluginEvent::AgentRegistered, payload).await
    }

    /// Dispatch an agent death/timeout event to subscribed Python callbacks.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn emit_agent_dead(&self, agent_id: u32) -> Result<(), PluginError> {
        let Some(agent) = self.inner.agents.get(agent_id).await else {
            return Ok(());
        };
        let payload = serde_json::to_value(agent)?;
        self.invoke_callbacks(PluginEvent::AgentDead, payload).await
    }

    /// Dispatch a loot-captured event to subscribed Python callbacks.
    ///
    /// Binary `data` is omitted from the payload to avoid serialising large blobs.
    #[instrument(skip(self, loot), fields(agent_id = format_args!("0x{:08X}", loot.agent_id), kind = %loot.kind))]
    pub async fn emit_loot_captured(&self, loot: &LootRecord) -> Result<(), PluginError> {
        let payload = json!({
            "agent_id": loot.agent_id,
            "id": loot.id,
            "kind": loot.kind,
            "name": loot.name,
            "file_path": loot.file_path,
            "size_bytes": loot.size_bytes,
            "captured_at": loot.captured_at,
        });
        self.invoke_callbacks(PluginEvent::LootCaptured, payload).await
    }

    /// Dispatch a task-created event to subscribed Python callbacks.
    #[instrument(skip(self, job), fields(agent_id = format_args!("0x{:08X}", agent_id), request_id = job.request_id))]
    pub async fn emit_task_created(&self, agent_id: u32, job: &Job) -> Result<(), PluginError> {
        let payload = json!({
            "agent_id": agent_id,
            "request_id": job.request_id,
            "command": job.command,
            "command_line": job.command_line,
            "task_id": job.task_id,
            "created_at": job.created_at,
            "operator": job.operator,
        });
        self.invoke_callbacks(PluginEvent::TaskCreated, payload).await
    }

    /// Return the active process-wide plugin runtime when initialized.
    pub fn current() -> Result<Option<Self>, PluginError> {
        let lock = runtime_slot();
        let guard = lock.lock().map_err(|_| PluginError::MutexPoisoned)?;
        Ok(guard.clone())
    }

    fn install_as_active(&self) -> Result<(), PluginError> {
        let lock = runtime_slot();
        let mut guard = lock.lock().map_err(|_| PluginError::MutexPoisoned)?;
        *guard = Some(self.clone());
        Ok(())
    }

    /// Replace the process-wide active plugin runtime, returning the previous value.
    ///
    /// This is a low-level escape hatch for tests that need to install a known runtime
    /// and restore the previous state afterwards. Do not call from production code.
    #[cfg(test)]
    pub(crate) fn swap_active(runtime: Option<Self>) -> Result<Option<Self>, PluginError> {
        let mut guard = runtime_slot().lock().map_err(|_| PluginError::MutexPoisoned)?;
        Ok(std::mem::replace(&mut *guard, runtime))
    }

    /// Create a `PluginRuntime` whose `emit_*` methods succeed (no-op).
    ///
    /// This avoids Python initialization entirely — useful for testing the
    /// `plugins = Some(runtime)` happy path in callers like `handle_checkin`.
    #[cfg(test)]
    pub(crate) fn stub_succeeding(
        database: Database,
        agents: AgentRegistry,
        events: EventBus,
        sockets: SocketRelayManager,
    ) -> Self {
        Self {
            inner: Arc::new(PluginRuntimeInner {
                database,
                agents,
                events,
                _sockets: sockets,
                plugins_dir: None,
                runtime_handle: Handle::current(),
                listeners: RwLock::new(None),
                callbacks: RwLock::new(BTreeMap::new()),
                commands: RwLock::new(BTreeMap::new()),
                failure_counts: Mutex::new(BTreeMap::new()),
                disabled_plugins: Mutex::new(BTreeSet::new()),
                max_consecutive_failures: DEFAULT_MAX_CONSECUTIVE_FAILURES,
                force_emit_failure: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    /// Create a `PluginRuntime` whose `emit_*` methods always return `Err`.
    ///
    /// This avoids Python initialization entirely — useful for testing error
    /// suppression in callers like `handle_screenshot_callback`.
    #[cfg(test)]
    pub(crate) fn stub_failing(
        database: Database,
        agents: AgentRegistry,
        events: EventBus,
        sockets: SocketRelayManager,
    ) -> Self {
        Self {
            inner: Arc::new(PluginRuntimeInner {
                database,
                agents,
                events,
                _sockets: sockets,
                plugins_dir: None,
                runtime_handle: Handle::current(),
                listeners: RwLock::new(None),
                callbacks: RwLock::new(BTreeMap::new()),
                commands: RwLock::new(BTreeMap::new()),
                failure_counts: Mutex::new(BTreeMap::new()),
                disabled_plugins: Mutex::new(BTreeSet::new()),
                max_consecutive_failures: DEFAULT_MAX_CONSECUTIVE_FAILURES,
                force_emit_failure: std::sync::atomic::AtomicBool::new(true),
            }),
        }
    }

    /// Register a Python callback for the given event.
    ///
    /// Exposed for wiring tests in other modules that need to register callbacks
    /// without going through the Python `register_callback` API function.
    #[cfg(test)]
    pub(crate) async fn register_callback_for_test(
        &self,
        event: PluginEvent,
        callback: Py<PyAny>,
    ) -> Result<(), PluginError> {
        self.register_callback(event, callback).await
    }

    /// Install the `red_cell`/`havoc` API module into the Python interpreter.
    ///
    /// Exposed for wiring tests in other modules that construct tracker callbacks.
    #[cfg(test)]
    pub(crate) fn install_api_module_for_test(&self, py: Python<'_>) -> PyResult<()> {
        self.install_api_module(py)
    }

    /// Return the active runtime, preferring the thread-local set during callback
    /// dispatch to avoid re-entering the global [`RUNTIME`] mutex.
    fn active() -> PyResult<Self> {
        // Fast path: if we are inside a callback dispatch, the thread-local is set
        // and we can avoid touching the global mutex entirely.
        if let Some(runtime) = CALLBACK_RUNTIME.with(|cell| cell.borrow().clone()) {
            return Ok(runtime);
        }

        #[cfg(debug_assertions)]
        {
            // In debug builds, detect if the global mutex is already held by this
            // thread — a sign that a callback is re-entering without the thread-local
            // guard.  `try_lock` returns Err(TryLockError::WouldBlock) if held.
            if let Err(std::sync::TryLockError::WouldBlock) = runtime_slot().try_lock() {
                tracing::error!(
                    "deadlock detected: RUNTIME mutex already held on this thread; \
                     callback dispatch should set CALLBACK_RUNTIME thread-local"
                );
            }
        }

        Self::current()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?
            .ok_or_else(|| PyRuntimeError::new_err("red_cell Python runtime is not initialized"))
    }

    fn install_api_module(&self, py: Python<'_>) -> PyResult<()> {
        let sys = py.import("sys")?;
        let modules = sys.getattr("modules")?;

        for module_name in ["red_cell", "havoc"] {
            let module = PyModule::new(py, module_name)?;
            populate_api_module(&module)?;
            modules.set_item(module_name, module)?;
        }

        Ok(())
    }

    fn load_plugins_blocking(&self, directory: &Path) -> Result<Vec<String>, PluginError> {
        let mut entries = std::fs::read_dir(directory)
            .map_err(|_| PluginError::InvalidPluginDirectory { path: directory.to_path_buf() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PluginError::InvalidPluginDirectory { path: directory.to_path_buf() })?;
        entries.sort_by_key(|entry| entry.path());

        Python::with_gil(|py| -> Result<Vec<String>, PluginError> {
            self.install_api_module(py)?;

            let sys = py.import("sys")?;
            let path = sys.getattr("path")?;
            path.call_method1("insert", (0, directory.display().to_string()))?;

            let mut loaded = Vec::new();
            for entry in entries {
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("py") {
                    continue;
                }

                let module_name = match path.file_stem().and_then(|stem| stem.to_str()) {
                    Some(name) => name.to_owned(),
                    None => {
                        warn!(path = %path.display(), "skipping plugin with invalid module name");
                        continue;
                    }
                };
                let code = match std::fs::read_to_string(&path) {
                    Ok(code) => code,
                    Err(err) => {
                        warn!(path = %path.display(), %err, "skipping plugin that could not be read");
                        continue;
                    }
                };

                let code = match CString::new(code) {
                    Ok(code) => code,
                    Err(_) => {
                        warn!(path = %path.display(), "skipping plugin with interior NUL byte in source");
                        continue;
                    }
                };
                let filename = match CString::new(path.display().to_string()) {
                    Ok(filename) => filename,
                    Err(_) => {
                        warn!(path = %path.display(), "skipping plugin with interior NUL byte in path");
                        continue;
                    }
                };
                let module_name_cstr = match CString::new(module_name.clone()) {
                    Ok(cstr) => cstr,
                    Err(_) => {
                        warn!(path = %path.display(), "skipping plugin with interior NUL byte in module name");
                        continue;
                    }
                };

                // Set the loading-plugin thread-local so that any register_callback /
                // register_command calls made during module initialisation are tagged
                // with this plugin's name for health-tracking purposes.
                LOADING_PLUGIN.with(|cell| {
                    *cell.borrow_mut() = Some(module_name.clone());
                });
                let load_result = PyModule::from_code(py, &code, &filename, &module_name_cstr);
                LOADING_PLUGIN.with(|cell| {
                    *cell.borrow_mut() = None;
                });

                match load_result {
                    Ok(module) => {
                        if let Err(err) = py
                            .import("sys")
                            .and_then(|sys| sys.getattr("modules"))
                            .and_then(|modules| modules.set_item(module_name.as_str(), module))
                        {
                            warn!(plugin = %module_name, %err, "failed to register plugin module in sys.modules");
                            continue;
                        }
                        loaded.push(module_name);
                    }
                    Err(err) => {
                        warn!(plugin = %module_name, %err, "skipping plugin that failed to load");
                        continue;
                    }
                }
            }

            Ok(loaded)
        })
    }

    fn block_on<F, T>(&self, fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        self.inner.runtime_handle.block_on(fut)
    }

    async fn invoke_callbacks(
        &self,
        event: PluginEvent,
        payload: Value,
    ) -> Result<(), PluginError> {
        #[cfg(test)]
        if self.inner.force_emit_failure.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(PluginError::MutexPoisoned);
        }

        let callbacks = {
            let callbacks = self.inner.callbacks.read().await;
            callbacks.get(event.as_str()).cloned().unwrap_or_default()
        };
        if callbacks.is_empty() {
            return Ok(());
        }

        let runtime = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            // Set the thread-local so re-entrant calls from Python into the Rust
            // API bypass the global RUNTIME mutex.
            let _guard = CallbackRuntimeGuard::enter(&runtime);

            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;

                let agent_id = match event {
                    PluginEvent::AgentCheckin
                    | PluginEvent::AgentRegistered
                    | PluginEvent::AgentDead => payload
                        .get("AgentID")
                        .and_then(Value::as_u64)
                        .and_then(|value| u32::try_from(value).ok()),
                    PluginEvent::CommandOutput
                    | PluginEvent::LootCaptured
                    | PluginEvent::TaskCreated => payload
                        .get("agent_id")
                        .and_then(Value::as_u64)
                        .and_then(|value| u32::try_from(value).ok()),
                };
                let event_object = Py::new(
                    py,
                    PyEvent { event_type: event.as_str().to_owned(), agent_id, data: payload },
                )?
                .into_any();
                let py_args = PyTuple::new(py, [event_object])?;

                for named_cb in &callbacks {
                    if runtime.is_plugin_disabled(&named_cb.plugin_name) {
                        continue;
                    }

                    // Wrap each invocation in catch_unwind to prevent a Rust panic
                    // inside a callback from aborting the entire dispatch task.
                    let call_result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            named_cb.callback.bind(py).call1(py_args.clone())
                        }));

                    match call_result {
                        Ok(Ok(_)) => {
                            runtime.record_callback_success(&named_cb.plugin_name);
                        }
                        Ok(Err(py_err)) => {
                            error!(
                                event = event.as_str(),
                                plugin = %named_cb.plugin_name,
                                error = %py_err,
                                "python plugin callback raised an exception"
                            );
                            runtime.record_callback_failure(&named_cb.plugin_name);
                        }
                        Err(panic_payload) => {
                            let msg = panic_payload
                                .downcast_ref::<String>()
                                .map(String::as_str)
                                .or_else(|| panic_payload.downcast_ref::<&str>().copied())
                                .unwrap_or("<non-string panic payload>");
                            error!(
                                event = event.as_str(),
                                plugin = %named_cb.plugin_name,
                                panic_message = msg,
                                "python plugin callback panicked"
                            );
                            runtime.record_callback_failure(&named_cb.plugin_name);
                        }
                    }
                }

                Ok(())
            })
        })
        .await;

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(py_err)) => Err(PluginError::Python(py_err)),
            Err(join_err) => {
                if join_err.is_panic() {
                    error!(
                        event = event.as_str(),
                        "plugin dispatch task panicked — all callbacks for this event were skipped"
                    );
                    // Do not propagate the panic; the dispatch task is isolated on a
                    // blocking thread and the agent can still receive a response.
                    Ok(())
                } else {
                    Err(PluginError::Join(join_err))
                }
            }
        }
    }

    async fn get_agent(&self, agent_id: u32) -> Result<Option<AgentRecord>, TeamserverError> {
        Ok(self.inner.agents.get(agent_id).await)
    }

    async fn list_agents(&self) -> Vec<AgentRecord> {
        self.inner.agents.list().await
    }

    async fn get_listener(&self, name: &str) -> Result<Option<PersistedListener>, TeamserverError> {
        self.inner.database.listeners().get(name).await
    }

    async fn list_listeners(&self) -> Result<Vec<PersistedListener>, TeamserverError> {
        self.inner.database.listeners().list().await
    }

    async fn listener_manager(&self) -> Result<ListenerManager, PluginError> {
        self.inner.listeners.read().await.clone().ok_or(PluginError::ListenerManagerUnavailable)
    }

    async fn start_listener(&self, name: &str) -> Result<PersistedListener, PluginError> {
        self.listener_manager().await?.start(name).await?;
        self.inner
            .database
            .listeners()
            .get(name)
            .await?
            .ok_or_else(|| TeamserverError::InvalidPersistedValue {
                field: "listener",
                message: format!("listener `{name}` disappeared after start"),
            })
            .map_err(PluginError::from)
    }

    async fn stop_listener(&self, name: &str) -> Result<PersistedListener, PluginError> {
        self.listener_manager().await?.stop(name).await?;
        self.inner
            .database
            .listeners()
            .get(name)
            .await?
            .ok_or_else(|| TeamserverError::InvalidPersistedValue {
                field: "listener",
                message: format!("listener `{name}` disappeared after stop"),
            })
            .map_err(PluginError::from)
    }

    async fn queue_raw_agent_task(
        &self,
        agent_id: u32,
        command: u32,
        payload: Vec<u8>,
    ) -> Result<String, PluginError> {
        let id = next_request_id();
        let task_id = format!("{id:08X}");
        self.inner
            .agents
            .enqueue_job(
                agent_id,
                Job {
                    command,
                    request_id: id,
                    payload,
                    command_line: format!("python:{command}"),
                    task_id: task_id.clone(),
                    created_at: OffsetDateTime::now_utc().unix_timestamp().to_string(),
                    operator: String::new(),
                },
            )
            .await?;
        Ok(task_id)
    }

    pub(crate) async fn invoke_registered_command(
        &self,
        name: &str,
        actor: &str,
        role: OperatorRole,
        agent_id: u32,
        args: Vec<String>,
    ) -> Result<bool, PluginError> {
        let command = {
            let commands = self.inner.commands.read().await;
            commands.get(name).cloned()
        };
        let Some(command) = command else {
            return Ok(false);
        };

        if self.is_plugin_disabled(&command.plugin_name) {
            error!(
                command = name,
                plugin = %command.plugin_name,
                "python command skipped — plugin is disabled due to repeated failures"
            );
            return Ok(false);
        }

        let runtime = self.clone();
        let plugin_name = command.plugin_name.clone();
        let callback_args = args.clone();
        let joined_args = args.join(" ");
        let captured_task_id: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let task_id_for_callback = captured_task_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            // Set the thread-local so re-entrant calls from Python into the Rust
            // API bypass the global RUNTIME mutex.
            let _guard = CallbackRuntimeGuard::enter(&runtime);
            // Set the caller's RBAC role so Python API functions can enforce
            // permission checks against the invoking operator's role.
            let _role_guard = CallerRoleGuard::enter(role);

            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Python::with_gil(|py| -> PyResult<()> {
                    runtime.install_api_module(py)?;
                    let agent =
                        Py::new(py, PyAgent { agent_id, last_task_id: task_id_for_callback })?
                            .into_any();
                    let list = PyList::new(py, callback_args)?.into_any().unbind();
                    let py_args = PyTuple::new(py, [agent, list])?;
                    command.callback.bind(py).call1(py_args)?;
                    Ok(())
                })
            }))
        })
        .await;

        match result {
            Ok(Ok(Ok(()))) => {
                self.record_callback_success(&plugin_name);
            }
            Ok(Ok(Err(py_err))) => {
                error!(
                    command = name,
                    plugin = %plugin_name,
                    error = %py_err,
                    "python plugin command raised an exception"
                );
                self.record_callback_failure(&plugin_name);
                return Err(PluginError::Python(py_err));
            }
            Ok(Err(panic_payload)) => {
                let msg = panic_payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| panic_payload.downcast_ref::<&str>().copied())
                    .unwrap_or("<non-string panic payload>");
                error!(
                    command = name,
                    plugin = %plugin_name,
                    panic_message = msg,
                    "python plugin command panicked"
                );
                self.record_callback_failure(&plugin_name);
                return Err(PluginError::MutexPoisoned);
            }
            Err(join_err) => {
                error!(
                    command = name,
                    plugin = %plugin_name,
                    "python plugin command task failed to join"
                );
                self.record_callback_failure(&plugin_name);
                return Err(PluginError::Join(join_err));
            }
        }

        let task_id = captured_task_id.lock().map_err(|_| PluginError::MutexPoisoned)?.clone();

        if let Some(task_id) = task_id {
            self.inner.events.broadcast(OperatorMessage::AgentTask(Message {
                head: MessageHead {
                    event: EventCode::Session,
                    user: actor.to_owned(),
                    timestamp: String::new(),
                    one_time: String::new(),
                },
                info: AgentTaskInfo {
                    task_id,
                    command_line: format!("{name} {joined_args}").trim().to_owned(),
                    demon_id: format!("{agent_id:08X}"),
                    command_id: "Python".to_owned(),
                    command: Some(name.to_owned()),
                    arguments: Some(joined_args),
                    task_message: Some("python plugin command executed".to_owned()),
                    ..AgentTaskInfo::default()
                },
            }));
        }
        Ok(true)
    }

    pub(crate) async fn match_registered_command(
        &self,
        info: &AgentTaskInfo,
    ) -> Option<(String, Vec<String>)> {
        let commands = self.inner.commands.read().await;
        if commands.is_empty() {
            return None;
        }

        if let Some(command) =
            info.command.as_deref().map(str::trim).filter(|value| !value.is_empty())
            && commands.contains_key(command)
        {
            let args = info
                .arguments
                .as_deref()
                .unwrap_or_default()
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect();
            return Some((command.to_owned(), args));
        }

        let command_line = info.command_line.trim();
        if command_line.is_empty() {
            return None;
        }

        let mut matches = commands
            .keys()
            .filter(|command| {
                command_line == command.as_str() || command_line.starts_with(&format!("{command} "))
            })
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by_key(|command| usize::MAX - command.len());
        let command = matches.into_iter().next()?;
        let remainder = command_line.strip_prefix(command.as_str()).unwrap_or_default().trim();
        let args = if remainder.is_empty() {
            Vec::new()
        } else {
            remainder.split_whitespace().map(ToOwned::to_owned).collect()
        };
        Some((command, args))
    }
}

/// Check that the current caller (set via [`CallerRoleGuard`]) has the required
/// permission.  When no caller role is set (system/event context), all
/// permissions are granted.
fn check_plugin_permission(permission: crate::rbac::Permission) -> PyResult<()> {
    let role = CALLER_ROLE.with(|cell| *cell.borrow());
    let Some(role) = role else {
        // System context — no restriction.
        return Ok(());
    };
    if crate::rbac::role_grants(role, permission) {
        Ok(())
    } else {
        Err(pyo3::exceptions::PyPermissionError::new_err(format!(
            "plugin permission denied: role `{role:?}` lacks `{}` permission",
            permission.as_str(),
        )))
    }
}

/// Process-wide serialisation lock for tests that install a `PluginRuntime` as the
/// active global.  Tests in other modules that call `PluginRuntime::swap_active` must
/// hold this lock for the duration of the test to prevent races with the plugin unit
/// tests that share the same global slot.
#[cfg(test)]
pub(crate) static PLUGIN_RUNTIME_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests;
