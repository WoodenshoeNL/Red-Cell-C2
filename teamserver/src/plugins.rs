//! Embedded Python plugin runtime for the teamserver.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule, PyTuple};
use red_cell_common::AgentRecord;
use red_cell_common::config::OperatorRole;
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::runtime::Handle;
use tokio::sync::RwLock;
use tracing::{instrument, warn};

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

/// Events exposed to Python callbacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PluginEvent {
    /// Agent check-in callback notifications.
    AgentCheckin,
    /// Agent registration (DemonInit) callback notifications.
    AgentRegistered,
    /// Agent death or stale timeout callback notifications.
    AgentDead,
    /// Agent command output callback notifications.
    CommandOutput,
    /// Loot (download, screenshot, credential) captured callback notifications.
    LootCaptured,
    /// Task queued for an agent callback notifications.
    TaskCreated,
}

impl PluginEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::AgentCheckin => "agent_checkin",
            Self::AgentRegistered => "agent_registered",
            Self::AgentDead => "agent_dead",
            Self::CommandOutput => "command_output",
            Self::LootCaptured => "loot_captured",
            Self::TaskCreated => "task_created",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "agent_checkin" => Some(Self::AgentCheckin),
            "agent_registered" => Some(Self::AgentRegistered),
            "agent_dead" => Some(Self::AgentDead),
            "command_output" => Some(Self::CommandOutput),
            "loot_captured" => Some(Self::LootCaptured),
            "task_created" => Some(Self::TaskCreated),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct RegisteredCommand {
    description: String,
    callback: Arc<Py<PyAny>>,
}

#[derive(Debug)]
struct PluginRuntimeInner {
    database: Database,
    agents: AgentRegistry,
    events: EventBus,
    _sockets: SocketRelayManager,
    plugins_dir: Option<PathBuf>,
    runtime_handle: Handle,
    listeners: RwLock<Option<ListenerManager>>,
    callbacks: RwLock<BTreeMap<&'static str, Vec<Arc<Py<PyAny>>>>>,
    commands: RwLock<BTreeMap<String, RegisteredCommand>>,
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

                match PyModule::from_code(py, &code, &filename, &module_name_cstr) {
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

    async fn register_callback(
        &self,
        event: PluginEvent,
        callback: Py<PyAny>,
    ) -> Result<(), PluginError> {
        self.inner
            .callbacks
            .write()
            .await
            .entry(event.as_str())
            .or_default()
            .push(Arc::new(callback));
        Ok(())
    }

    async fn register_command(
        &self,
        name: String,
        description: String,
        callback: Py<PyAny>,
    ) -> Result<(), PluginError> {
        self.inner
            .commands
            .write()
            .await
            .insert(name, RegisteredCommand { description, callback: Arc::new(callback) });
        Ok(())
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
        let callbacks = {
            let callbacks = self.inner.callbacks.read().await;
            callbacks.get(event.as_str()).cloned().unwrap_or_default()
        };
        if callbacks.is_empty() {
            return Ok(());
        }

        let runtime = self.clone();
        tokio::task::spawn_blocking(move || {
            // Set the thread-local so re-entrant calls from Python into the Rust
            // API bypass the global RUNTIME mutex.
            let _guard = CallbackRuntimeGuard::enter(&runtime);

            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;

                let agent_id = match event {
                    PluginEvent::AgentCheckin | PluginEvent::AgentRegistered | PluginEvent::AgentDead => payload
                        .get("AgentID")
                        .and_then(Value::as_u64)
                        .and_then(|value| u32::try_from(value).ok()),
                    PluginEvent::CommandOutput | PluginEvent::LootCaptured | PluginEvent::TaskCreated => payload
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

                for callback in callbacks {
                    if let Err(error) = callback.bind(py).call1(py_args.clone()) {
                        warn!(event = event.as_str(), error = %error, "python plugin callback failed");
                    }
                }

                Ok(())
            })
        })
        .await??;

        Ok(())
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

        let runtime = self.clone();
        let callback_args = args.clone();
        let joined_args = args.join(" ");
        let captured_task_id: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let task_id_for_callback = captured_task_id.clone();
        tokio::task::spawn_blocking(move || {
            // Set the thread-local so re-entrant calls from Python into the Rust
            // API bypass the global RUNTIME mutex.
            let _guard = CallbackRuntimeGuard::enter(&runtime);
            // Set the caller's RBAC role so Python API functions can enforce
            // permission checks against the invoking operator's role.
            let _role_guard = CallerRoleGuard::enter(role);

            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let agent = Py::new(py, PyAgent { agent_id, last_task_id: task_id_for_callback })?
                    .into_any();
                let list = PyList::new(py, callback_args)?.into_any().unbind();
                let py_args = PyTuple::new(py, [agent, list])?;
                command.callback.bind(py).call1(py_args)?;
                Ok(())
            })
        })
        .await??;

        let task_id = captured_task_id
            .lock()
            .map_err(|_| PluginError::MutexPoisoned)?
            .clone()
            .unwrap_or_else(|| format!("{:08X}", next_request_id()));

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

fn json_value_to_object(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let json_module = py.import("json")?;
    let serialized =
        serde_json::to_string(value).map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(json_module.call_method1("loads", (serialized,))?.unbind())
}

fn ensure_callable(callback: &Bound<'_, PyAny>) -> PyResult<()> {
    if callback.is_callable() {
        Ok(())
    } else {
        Err(PyValueError::new_err("callback must be callable"))
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

#[derive(Debug)]
struct RegisterCommandRequest {
    name: String,
    description: String,
    callback: Py<PyAny>,
}

fn optional_kwarg<'py>(
    kwargs: Option<&Bound<'py, PyDict>>,
    key: &str,
) -> PyResult<Option<Bound<'py, PyAny>>> {
    match kwargs {
        Some(kwargs) => kwargs.get_item(key),
        None => Ok(None),
    }
}

fn extract_string_argument(
    kwargs: Option<&Bound<'_, PyDict>>,
    key: &str,
    positional: Option<&Bound<'_, PyAny>>,
) -> PyResult<Option<String>> {
    if let Some(value) = optional_kwarg(kwargs, key)? {
        return value.extract::<String>().map(Some);
    }

    positional.map(Bound::extract::<String>).transpose()
}

fn parse_register_command_request(
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<RegisterCommandRequest> {
    let positional = args.iter().collect::<Vec<_>>();
    let havoc_style = optional_kwarg(kwargs, "function")?.is_some()
        || positional.first().is_some_and(Bound::is_callable);

    if havoc_style {
        let callback = if let Some(value) = optional_kwarg(kwargs, "function")? {
            value
        } else {
            positional
                .first()
                .cloned()
                .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a callable"))?
        };
        ensure_callable(&callback)?;

        let module = extract_string_argument(kwargs, "module", positional.get(1))?
            .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a module name"))?;
        let command = extract_string_argument(kwargs, "command", positional.get(2))?
            .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a command name"))?;
        let description = extract_string_argument(kwargs, "description", positional.get(3))?
            .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a description"))?;

        let name = if module.trim().is_empty() { command } else { format!("{module} {command}") };

        return Ok(RegisterCommandRequest { name, description, callback: callback.unbind() });
    }

    let callback = if let Some(value) = optional_kwarg(kwargs, "callback")? {
        value
    } else {
        positional
            .get(2)
            .cloned()
            .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a callback"))?
    };
    ensure_callable(&callback)?;

    let name = extract_string_argument(kwargs, "name", positional.first())?
        .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a command name"))?;
    let description = extract_string_argument(kwargs, "description", positional.get(1))?
        .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a description"))?;

    Ok(RegisterCommandRequest { name, description, callback: callback.unbind() })
}

#[pyclass(name = "Agent")]
#[derive(Clone, Debug)]
struct PyAgent {
    agent_id: u32,
    /// Captures the task_id assigned during the most recent `task()` call so callers
    /// (e.g. `invoke_registered_command`) can correlate the broadcast with the queued job.
    last_task_id: Arc<Mutex<Option<String>>>,
}

#[pymethods]
impl PyAgent {
    #[new]
    fn new(agent_id: &str) -> PyResult<Self> {
        let trimmed = agent_id.trim().trim_start_matches("0x").trim_start_matches("0X");
        let agent_id = u32::from_str_radix(trimmed, 16)
            .map_err(|_| PyValueError::new_err(format!("invalid agent id `{agent_id}`")))?;
        Ok(Self { agent_id, last_task_id: Arc::new(Mutex::new(None)) })
    }

    #[getter]
    fn id(&self) -> String {
        format!("{:08X}", self.agent_id)
    }

    #[getter]
    fn info(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        check_plugin_permission(crate::rbac::Permission::Read)?;
        let runtime = PluginRuntime::active()?;
        let agent = py.allow_threads(|| runtime.block_on(runtime.get_agent(self.agent_id)));
        match agent {
            Ok(Some(agent)) => json_value_to_object(
                py,
                &serde_json::to_value(agent)
                    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
            ),
            Ok(None) => {
                Err(PyValueError::new_err(format!("agent {:08X} no longer exists", self.agent_id)))
            }
            Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
        }
    }

    #[pyo3(signature = (command, args=None))]
    fn task(&self, py: Python<'_>, command: u32, args: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        check_plugin_permission(crate::rbac::Permission::TaskAgents)?;
        let runtime = PluginRuntime::active()?;
        let payload = match args {
            None => Vec::new(),
            Some(value) if value.is_none() => Vec::new(),
            Some(value) => {
                if let Ok(bytes) = value.extract::<Vec<u8>>() {
                    bytes
                } else if let Ok(text) = value.extract::<String>() {
                    text.into_bytes()
                } else {
                    return Err(PyValueError::new_err(
                        "args must be bytes, bytearray, str, or None",
                    ));
                }
            }
        };

        let agent_id = self.agent_id;
        let task_id = py
            .allow_threads(move || {
                runtime.block_on(runtime.queue_raw_agent_task(agent_id, command, payload))
            })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        if let Ok(mut guard) = self.last_task_id.lock() {
            *guard = Some(task_id);
        }
        Ok(())
    }
}

#[pyclass(name = "Listener")]
#[derive(Clone, Debug)]
struct PyListener {
    name: String,
}

#[pymethods]
impl PyListener {
    #[new]
    fn new(name: String) -> Self {
        Self { name }
    }

    #[getter]
    fn info(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        check_plugin_permission(crate::rbac::Permission::Read)?;
        let runtime = PluginRuntime::active()?;
        let listener = py.allow_threads(|| runtime.block_on(runtime.get_listener(&self.name)));
        match listener {
            Ok(Some(listener)) => json_value_to_object(
                py,
                &serde_json::to_value(listener)
                    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
            ),
            Ok(None) => Err(PyValueError::new_err(format!("listener `{}` not found", self.name))),
            Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
        }
    }

    fn start(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        check_plugin_permission(crate::rbac::Permission::ManageListeners)?;
        let runtime = PluginRuntime::active()?;
        let listener = py.allow_threads(|| runtime.block_on(runtime.start_listener(&self.name)));
        match listener {
            Ok(listener) => json_value_to_object(
                py,
                &serde_json::to_value(listener)
                    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
            ),
            Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
        }
    }

    fn stop(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        check_plugin_permission(crate::rbac::Permission::ManageListeners)?;
        let runtime = PluginRuntime::active()?;
        let listener = py.allow_threads(|| runtime.block_on(runtime.stop_listener(&self.name)));
        match listener {
            Ok(listener) => json_value_to_object(
                py,
                &serde_json::to_value(listener)
                    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
            ),
            Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
        }
    }
}

#[pyclass(name = "Event")]
#[derive(Clone, Debug)]
struct PyEvent {
    event_type: String,
    agent_id: Option<u32>,
    data: Value,
}

#[pymethods]
impl PyEvent {
    #[getter]
    fn event_type(&self) -> String {
        self.event_type.clone()
    }

    #[getter]
    fn agent(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        self.agent_id
            .map(|agent_id| {
                Py::new(py, PyAgent { agent_id, last_task_id: Arc::new(Mutex::new(None)) })
                    .map(|agent| agent.into_any())
            })
            .transpose()
    }

    #[getter]
    fn data(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_object(py, &self.data)
    }
}

#[pyfunction]
fn get_agent(py: Python<'_>, agent_id: u32) -> PyResult<Py<PyAny>> {
    check_plugin_permission(crate::rbac::Permission::Read)?;
    let runtime = PluginRuntime::active()?;
    let agent = py.allow_threads(|| runtime.block_on(runtime.get_agent(agent_id)));

    match agent {
        Ok(Some(agent)) => json_value_to_object(
            py,
            &serde_json::to_value(agent)
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
        ),
        Ok(None) => Ok(py.None().into_bound(py).unbind()),
        Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
    }
}

#[pyfunction]
fn list_agents(py: Python<'_>) -> PyResult<Py<PyAny>> {
    check_plugin_permission(crate::rbac::Permission::Read)?;
    let runtime = PluginRuntime::active()?;
    let agents = py.allow_threads(|| runtime.block_on(runtime.list_agents()));
    json_value_to_object(
        py,
        &serde_json::to_value(agents)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
    )
}

#[pyfunction]
fn get_agents(py: Python<'_>) -> PyResult<Py<PyAny>> {
    list_agents(py)
}

#[pyfunction]
fn get_listener(py: Python<'_>, name: String) -> PyResult<Py<PyAny>> {
    check_plugin_permission(crate::rbac::Permission::Read)?;
    let runtime = PluginRuntime::active()?;
    let listener = py.allow_threads(|| runtime.block_on(runtime.get_listener(&name)));

    match listener {
        Ok(Some(listener)) => json_value_to_object(
            py,
            &serde_json::to_value(listener)
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
        ),
        Ok(None) => Ok(py.None().into_bound(py).unbind()),
        Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
    }
}

#[pyfunction]
fn list_listeners(py: Python<'_>) -> PyResult<Py<PyAny>> {
    check_plugin_permission(crate::rbac::Permission::Read)?;
    let runtime = PluginRuntime::active()?;
    let listeners = py.allow_threads(|| runtime.block_on(runtime.list_listeners()));
    let listeners = listeners.map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    json_value_to_object(
        py,
        &serde_json::to_value(listeners)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
    )
}

#[pyfunction]
fn get_listeners(py: Python<'_>) -> PyResult<Py<PyAny>> {
    list_listeners(py)
}

#[pyfunction]
fn on_agent_checkin(py: Python<'_>, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || {
        runtime.block_on(runtime.register_callback(PluginEvent::AgentCheckin, callback))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
fn on_command_output(py: Python<'_>, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || {
        runtime.block_on(runtime.register_callback(PluginEvent::CommandOutput, callback))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
fn on_agent_registered(py: Python<'_>, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || {
        runtime.block_on(runtime.register_callback(PluginEvent::AgentRegistered, callback))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
fn on_agent_dead(py: Python<'_>, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || {
        runtime.block_on(runtime.register_callback(PluginEvent::AgentDead, callback))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
fn on_loot_captured(py: Python<'_>, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || {
        runtime.block_on(runtime.register_callback(PluginEvent::LootCaptured, callback))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
fn on_task_created(py: Python<'_>, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || {
        runtime.block_on(runtime.register_callback(PluginEvent::TaskCreated, callback))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
fn register_callback(
    py: Python<'_>,
    event_type: String,
    callback: Bound<'_, PyAny>,
) -> PyResult<()> {
    ensure_callable(&callback)?;
    let event = PluginEvent::parse(&event_type)
        .ok_or_else(|| PyValueError::new_err(format!("unsupported event type `{event_type}`")))?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || runtime.block_on(runtime.register_callback(event, callback)))
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (*args, **kwargs))]
fn register_command(
    py: Python<'_>,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<()> {
    let request = parse_register_command_request(args, kwargs)?;
    let runtime = PluginRuntime::active()?;
    py.allow_threads(move || {
        runtime.block_on(runtime.register_command(
            request.name,
            request.description,
            request.callback,
        ))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

fn populate_api_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(get_agent, module)?)?;
    module.add_function(wrap_pyfunction!(list_agents, module)?)?;
    module.add_function(wrap_pyfunction!(get_agents, module)?)?;
    module.add_function(wrap_pyfunction!(get_listener, module)?)?;
    module.add_function(wrap_pyfunction!(list_listeners, module)?)?;
    module.add_function(wrap_pyfunction!(get_listeners, module)?)?;
    module.add_function(wrap_pyfunction!(on_agent_checkin, module)?)?;
    module.add_function(wrap_pyfunction!(on_agent_registered, module)?)?;
    module.add_function(wrap_pyfunction!(on_agent_dead, module)?)?;
    module.add_function(wrap_pyfunction!(on_command_output, module)?)?;
    module.add_function(wrap_pyfunction!(on_loot_captured, module)?)?;
    module.add_function(wrap_pyfunction!(on_task_created, module)?)?;
    module.add_function(wrap_pyfunction!(register_callback, module)?)?;
    module.add_function(wrap_pyfunction!(register_command, module)?)?;
    module.add_class::<PyAgent>()?;
    module.add_class::<PyListener>()?;
    module.add_class::<PyEvent>()?;

    module.add("GetAgent", module.getattr("get_agent")?)?;
    module.add("GetAgents", module.getattr("get_agents")?)?;
    module.add("GetListener", module.getattr("get_listener")?)?;
    module.add("GetListeners", module.getattr("get_listeners")?)?;
    module.add("RegisterCallback", module.getattr("register_callback")?)?;
    module.add("RegisterCommand", module.getattr("register_command")?)?;
    Ok(())
}

/// Process-wide serialisation lock for tests that install a `PluginRuntime` as the
/// active global.  Tests in other modules that call `PluginRuntime::swap_active` must
/// hold this lock for the duration of the test to prevent races with the plugin unit
/// tests that share the same global slot.
#[cfg(test)]
pub(crate) static PLUGIN_RUNTIME_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use red_cell_common::{AgentEncryptionInfo, HttpListenerConfig, ListenerConfig};
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use super::*;

    // Tests that install a `PluginRuntime` as the active global must hold
    // `super::PLUGIN_RUNTIME_TEST_MUTEX` so that wiring tests in other modules that
    // call `PluginRuntime::swap_active` are serialised with us.
    //
    // We use `unwrap_or_else(|e| e.into_inner())` to tolerate a poisoned mutex — if a
    // prior test panicked while holding the lock, the data inside is still valid (it is
    // just `()`), so we recover and continue rather than cascading failures.
    fn lock_test_guard() -> std::sync::MutexGuard<'static, ()> {
        super::PLUGIN_RUNTIME_TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    const POISON_CURRENT_ENV: &str = "RED_CELL_POISON_PLUGIN_RUNTIME_CURRENT";

    fn unique_test_dir(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("red-cell-{label}-{suffix}"))
    }

    fn sample_agent(agent_id: u32) -> AgentRecord {
        AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: "note".to_owned(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(b"aes-key".to_vec()),
                aes_iv: Zeroizing::new(b"aes-iv".to_vec()),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 15,
            sleep_jitter: 20,
            kill_date: Some(1_893_456_000),
            working_hours: Some(0b101010),
            first_call_in: "2026-03-09T18:45:00Z".to_owned(),
            last_call_in: "2026-03-09T18:46:00Z".to_owned(),
        }
    }

    fn sample_listener() -> ListenerConfig {
        ListenerConfig::from(HttpListenerConfig {
            name: "http-main".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 8443,
            port_conn: Some(443),
            method: Some("POST".to_owned()),
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: Some("Mozilla/5.0".to_owned()),
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
        })
    }

    async fn runtime_fixture(
        label: &str,
    ) -> Result<(Database, AgentRegistry, EventBus, SocketRelayManager, PluginRuntime), PluginError>
    {
        let database = Database::connect(unique_test_dir(label)).await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime = PluginRuntime::initialize(
            database.clone(),
            registry.clone(),
            events.clone(),
            sockets.clone(),
            None,
        )
        .await?;
        Ok((database, registry, events, sockets, runtime))
    }

    fn replace_active_runtime(
        runtime: Option<PluginRuntime>,
    ) -> Result<Option<PluginRuntime>, PluginError> {
        let mut guard = runtime_slot().lock().map_err(|_| PluginError::MutexPoisoned)?;
        Ok(std::mem::replace(&mut *guard, runtime))
    }

    struct ActiveRuntimeReset {
        previous: Option<PluginRuntime>,
    }

    impl ActiveRuntimeReset {
        fn clear() -> Result<Self, PluginError> {
            Ok(Self { previous: replace_active_runtime(None)? })
        }
    }

    impl Drop for ActiveRuntimeReset {
        fn drop(&mut self) {
            let _ = replace_active_runtime(self.previous.take());
        }
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn current_is_none_before_initialization_and_plugins_dir_is_optional()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let _reset = ActiveRuntimeReset::clear()?;

        assert!(PluginRuntime::current()?.is_none());

        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-optional-dir").await?;

        assert!(runtime.plugins_dir().is_none());

        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn initialize_sets_current_runtime_and_exposes_plugins_dir()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let _reset = ActiveRuntimeReset::clear()?;
        let temp_dir = TempDir::new()?;
        let plugins_dir = temp_dir.path().to_path_buf();
        let database = Database::connect(unique_test_dir("plugins-current-state")).await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());

        let runtime = PluginRuntime::initialize(
            database,
            registry,
            events,
            sockets,
            Some(plugins_dir.clone()),
        )
        .await?;

        assert_eq!(runtime.plugins_dir(), Some(plugins_dir.as_path()));

        let current = PluginRuntime::current()?;
        let Some(current) = current else {
            return Err("expected active plugin runtime".into());
        };
        assert!(Arc::ptr_eq(&runtime.inner, &current.inner));
        assert_eq!(current.plugins_dir(), Some(plugins_dir.as_path()));

        Ok(())
    }

    #[test]
    fn current_reports_mutex_poisoned_in_isolated_process() -> Result<(), Box<dyn std::error::Error>>
    {
        if std::env::var_os(POISON_CURRENT_ENV).is_some() {
            let child = std::thread::spawn(|| {
                let _guard = runtime_slot().lock().unwrap_or_else(|error| error.into_inner());
                panic!("poison plugin runtime mutex");
            });
            assert!(child.join().is_err(), "child thread must panic to poison the mutex");
            assert!(matches!(PluginRuntime::current(), Err(PluginError::MutexPoisoned)));
            return Ok(());
        }

        let status = Command::new(std::env::current_exe()?)
            .arg("current_reports_mutex_poisoned_in_isolated_process")
            .arg("--nocapture")
            .env(POISON_CURRENT_ENV, "1")
            .status()?;

        assert!(status.success(), "isolated poison harness failed");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn initialize_exposes_agent_and_listener_accessors()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (database, registry, events, sockets, runtime) =
            runtime_fixture("plugins-access").await?;
        database.listeners().create(&sample_listener()).await?;
        registry.insert(sample_agent(0x00AB_CDEF)).await?;
        let listeners = ListenerManager::new(
            database.clone(),
            registry.clone(),
            events,
            sockets,
            Some(runtime.clone()),
        );
        runtime.attach_listener_manager(listeners).await;

        let handle = std::thread::spawn(move || {
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;

                let module = py.import("havoc")?;
                let agent = module.getattr("Agent")?.call1(("00ABCDEF",))?;
                let agent_info = agent.getattr("info")?;
                let listener = module.getattr("Listener")?.call1(("http-main",))?;
                let listener_info = listener.getattr("info")?;

                assert_eq!(agent_info.get_item("Hostname")?.extract::<String>()?, "wkstn-01");
                assert_eq!(listener_info.get_item("name")?.extract::<String>()?, "http-main");
                Ok(())
            })
        });
        handle.join().map_err(|_| "python test thread panicked")??;
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn load_plugins_registers_callbacks_and_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let temp_dir = TempDir::new()?;
        let plugin_path = temp_dir.path().join("sample_plugin.py");
        std::fs::write(
            &plugin_path,
            r#"
import havoc

def handle_event(event):
    if event.event_type == "agent_checkin":
        _ = event.agent.info["Hostname"]
    else:
        _ = event.data["output"]

def run(agent, args):
    agent.task(0x63, "hello-from-python")

havoc.RegisterCallback("agent_checkin", handle_event)
havoc.RegisterCallback("command_output", handle_event)
havoc.RegisterCommand("demo", "demo command", run)
"#,
        )?;

        let database = Database::connect(unique_test_dir("plugins-load")).await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime = PluginRuntime::initialize(
            database,
            registry,
            events,
            sockets,
            Some(temp_dir.path().to_path_buf()),
        )
        .await?;

        let loaded = runtime.load_plugins().await?;

        assert_eq!(loaded, vec!["sample_plugin".to_owned()]);
        assert_eq!(runtime.command_names().await, vec!["demo".to_owned()]);
        assert_eq!(
            runtime.command_descriptions().await.get("demo"),
            Some(&"demo command".to_owned())
        );
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn load_plugins_skips_plugin_with_syntax_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let _guard = lock_test_guard();
        let temp_dir = TempDir::new()?;
        let plugin_path = temp_dir.path().join("bad_plugin.py");
        // Deliberate Python syntax error: unmatched parenthesis.
        std::fs::write(&plugin_path, "def broken(\n    pass\n")?;

        let database = Database::connect(unique_test_dir("plugins-syntax-error")).await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime = PluginRuntime::initialize(
            database,
            registry,
            events,
            sockets,
            Some(temp_dir.path().to_path_buf()),
        )
        .await?;

        let loaded = runtime.load_plugins().await?;
        assert!(loaded.is_empty(), "broken plugin should be skipped, got {loaded:?}");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn load_plugins_multiple_with_broken_plugin_isolation()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let temp_dir = TempDir::new()?;

        // alpha.py — registers a command
        std::fs::write(
            temp_dir.path().join("alpha.py"),
            r#"
import havoc
def run_alpha(agent, args):
    agent.task(0x10, "alpha-payload")
havoc.RegisterCommand("alpha_cmd", "alpha command", run_alpha)
"#,
        )?;

        // beta.py — has a syntax error (should be skipped)
        std::fs::write(temp_dir.path().join("beta.py"), "def broken(\n    pass\n")?;

        // gamma.py — registers a callback
        std::fs::write(
            temp_dir.path().join("gamma.py"),
            r#"
import havoc
def on_checkin(event):
    _ = event.agent.info["Hostname"]
havoc.RegisterCallback("agent_checkin", on_checkin)
"#,
        )?;

        let database = Database::connect(unique_test_dir("plugins-multi-isolation")).await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime = PluginRuntime::initialize(
            database,
            registry,
            events,
            sockets,
            Some(temp_dir.path().to_path_buf()),
        )
        .await?;

        let loaded = runtime.load_plugins().await?;

        // alpha and gamma should load; beta (syntax error) should be skipped.
        assert_eq!(loaded, vec!["alpha".to_owned(), "gamma".to_owned()]);

        // alpha's command should be registered.
        assert_eq!(runtime.command_names().await, vec!["alpha_cmd".to_owned()]);
        assert_eq!(
            runtime.command_descriptions().await.get("alpha_cmd"),
            Some(&"alpha command".to_owned()),
        );

        // gamma's callback should be registered (agent_checkin event).
        let callbacks = runtime.inner.callbacks.read().await;
        let checkin_callbacks = callbacks.get("agent_checkin");
        assert!(
            checkin_callbacks.is_some_and(|cbs| cbs.len() == 1),
            "expected exactly 1 agent_checkin callback from gamma plugin",
        );
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn registered_command_callbacks_can_queue_agent_jobs()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-command-exec").await?;
        registry.insert(sample_agent(0x00AB_CDEF)).await?;

        let handle = std::thread::spawn({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<()> {
                    runtime.install_api_module(py)?;
                    let module = py.import("red_cell")?;
                    let callback = py.eval(
                        pyo3::ffi::c_str!("lambda agent, args: agent.task(99, ' '.join(args))"),
                        None,
                        None,
                    )?;
                    module.call_method1("register_command", ("demo", "demo command", callback))?;
                    Ok(())
                })
            }
        });
        handle.join().map_err(|_| "python test thread panicked")??;

        assert_eq!(
            runtime
                .match_registered_command(&AgentTaskInfo {
                    command_line: "demo alpha beta".to_owned(),
                    ..AgentTaskInfo::default()
                })
                .await,
            Some(("demo".to_owned(), vec!["alpha".to_owned(), "beta".to_owned()]))
        );

        assert!(
            runtime
                .invoke_registered_command(
                    "demo",
                    "operator",
                    OperatorRole::Admin,
                    0x00AB_CDEF,
                    vec!["alpha".to_owned(), "beta".to_owned()],
                )
                .await?
        );

        let queued = registry.dequeue_jobs(0x00AB_CDEF).await?;
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].command, 99);
        assert_eq!(queued[0].payload, b"alpha beta");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn register_command_accepts_havoc_keyword_signature()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-havoc-register-command").await?;
        registry.insert(sample_agent(0x00AB_CDEF)).await?;

        let handle = std::thread::spawn({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<()> {
                    runtime.install_api_module(py)?;
                    let helper = PyModule::from_code(
                        py,
                        pyo3::ffi::c_str!(
                            "import havoc\n\
\n\
def run(agent, args):\n\
\tagent.task(100, ' '.join(args))\n\
\n\
havoc.RegisterCommand(\n\
\tfunction=run,\n\
\tmodule='situational_awareness',\n\
\tcommand='whoami',\n\
\tdescription='demo command',\n\
\tbehavior=0,\n\
\tusage='',\n\
\texample=''\n\
)\n"
                        ),
                        pyo3::ffi::c_str!("test_havoc_register_command.py"),
                        pyo3::ffi::c_str!("test_havoc_register_command"),
                    )?;
                    let _ = helper;
                    Ok(())
                })
            }
        });
        handle.join().map_err(|_| "python test thread panicked")??;

        assert_eq!(runtime.command_names().await, vec!["situational_awareness whoami".to_owned()]);
        assert_eq!(
            runtime
                .match_registered_command(&AgentTaskInfo {
                    command_line: "situational_awareness whoami /all".to_owned(),
                    ..AgentTaskInfo::default()
                })
                .await,
            Some(("situational_awareness whoami".to_owned(), vec!["/all".to_owned()],))
        );

        runtime
            .invoke_registered_command(
                "situational_awareness whoami",
                "operator",
                OperatorRole::Admin,
                0x00AB_CDEF,
                vec!["/all".to_owned()],
            )
            .await?;

        let queued = registry.dequeue_jobs(0x00AB_CDEF).await?;
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].command, 100);
        assert_eq!(queued[0].payload, b"/all");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn invoke_registered_command_broadcast_task_id_matches_queued_job()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, registry, events, _sockets, runtime) =
            runtime_fixture("plugins-task-id-match").await?;
        registry.insert(sample_agent(0x00AB_CDEF)).await?;

        let handle = std::thread::spawn({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<()> {
                    runtime.install_api_module(py)?;
                    let module = py.import("red_cell")?;
                    let callback = py.eval(
                        pyo3::ffi::c_str!("lambda agent, args: agent.task(99, ' '.join(args))"),
                        None,
                        None,
                    )?;
                    module.call_method1("register_command", ("sync_cmd", "sync test", callback))?;
                    Ok(())
                })
            }
        });
        handle.join().map_err(|_| "python test thread panicked")??;

        let mut receiver = events.subscribe();

        runtime
            .invoke_registered_command(
                "sync_cmd",
                "operator",
                OperatorRole::Admin,
                0x00AB_CDEF,
                vec!["arg1".to_owned()],
            )
            .await?;

        let queued = registry.dequeue_jobs(0x00AB_CDEF).await?;
        assert_eq!(queued.len(), 1);
        let queued_task_id = &queued[0].task_id;

        let broadcast_msg =
            tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv())
                .await?
                .expect("expected a broadcast message");

        match broadcast_msg {
            OperatorMessage::AgentTask(msg) => {
                assert_eq!(
                    &msg.info.task_id, queued_task_id,
                    "broadcast task_id must match the queued job's task_id"
                );
            }
            other => panic!("expected AgentTask broadcast, got {other:?}"),
        }
        Ok(())
    }

    fn make_tracker_and_callback(
        runtime: &PluginRuntime,
        py: Python<'_>,
        append_expr: &std::ffi::CStr,
    ) -> PyResult<(Py<PyList>, Py<PyAny>)> {
        runtime.install_api_module(py)?;
        let tracker = PyList::empty(py);
        let locals = pyo3::types::PyDict::new(py);
        locals.set_item("_tracker", tracker.clone())?;
        let cb = py.eval(append_expr, None, Some(&locals))?;
        Ok((tracker.unbind(), cb.unbind()))
    }

    fn tracker_len(tracker: Py<PyList>) -> usize {
        Python::with_gil(|py| tracker.bind(py).len())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_agent_checkin_invokes_registered_callbacks()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("emit-checkin").await?;
        registry.insert(sample_agent(0x00AB_CDEF)).await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append(event.event_type))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::AgentCheckin, callback).await?;
        runtime.emit_agent_checkin(0x00AB_CDEF).await?;

        let (count, event_type) = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<(usize, String)> {
                let list = tracker.bind(py);
                let count = list.len();
                let first = list.get_item(0)?.extract::<String>()?;
                Ok((count, first))
            })
        })
        .await??;
        assert_eq!(count, 1);
        assert_eq!(event_type, "agent_checkin");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_command_output_invokes_registered_callbacks()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("emit-output").await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append(event.data['output']))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::CommandOutput, callback).await?;
        runtime.emit_command_output(0x00AB_CDEF, 42, 1, "hello world").await?;

        let (count, output) = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<(usize, String)> {
                let list = tracker.bind(py);
                let count = list.len();
                let first = list.get_item(0)?.extract::<String>()?;
                Ok((count, first))
            })
        })
        .await??;
        assert_eq!(count, 1);
        assert_eq!(output, "hello world");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_agent_checkin_skips_unknown_agent() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("emit-checkin-unknown").await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!("(lambda t: lambda event: t.append(1))(_tracker)"),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::AgentCheckin, callback).await?;
        runtime.emit_agent_checkin(0xDEAD).await?;

        let count = tokio::task::spawn_blocking(move || tracker_len(tracker)).await?;
        assert_eq!(count, 0, "callback must not fire when agent is unknown");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_callback_exception_does_not_propagate() -> Result<(), Box<dyn std::error::Error>>
    {
        let _guard = lock_test_guard();
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("emit-exception").await?;
        registry.insert(sample_agent(0x00AB_CDEF)).await?;

        let (tracker, bad_cb, good_cb) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<(Py<PyList>, Py<PyAny>, Py<PyAny>)> {
                    runtime.install_api_module(py)?;
                    let helper = PyModule::from_code(
                        py,
                        pyo3::ffi::c_str!("def raise_error(event):\n    raise Exception('boom')"),
                        pyo3::ffi::c_str!("test_raiser.py"),
                        pyo3::ffi::c_str!("test_raiser"),
                    )?;
                    let bad_cb = helper.getattr("raise_error")?.unbind();

                    let tracker = PyList::empty(py);
                    let locals = pyo3::types::PyDict::new(py);
                    locals.set_item("_tracker", tracker.clone())?;
                    let good_cb = py.eval(
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append(event.event_type))(_tracker)"
                        ),
                        None,
                        Some(&locals),
                    )?;
                    Ok((tracker.unbind(), bad_cb, good_cb.unbind()))
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::AgentCheckin, bad_cb).await?;
        runtime.register_callback(PluginEvent::AgentCheckin, good_cb).await?;

        runtime.emit_agent_checkin(0x00AB_CDEF).await?;

        let count = tokio::task::spawn_blocking(move || tracker_len(tracker)).await?;
        assert_eq!(count, 1, "good callback must still fire after bad callback raises");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_agent_registered_invokes_registered_callbacks()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("emit-registered").await?;
        registry.insert(sample_agent(0x00AB_CDEF)).await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append(event.event_type))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::AgentRegistered, callback).await?;
        runtime.emit_agent_registered(0x00AB_CDEF).await?;

        let (count, event_type) = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<(usize, String)> {
                let list = tracker.bind(py);
                let count = list.len();
                let first = list.get_item(0)?.extract::<String>()?;
                Ok((count, first))
            })
        })
        .await??;
        assert_eq!(count, 1);
        assert_eq!(event_type, "agent_registered");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_agent_dead_invokes_registered_callbacks() -> Result<(), Box<dyn std::error::Error>>
    {
        let _guard = lock_test_guard();
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("emit-dead").await?;
        registry.insert(sample_agent(0x00AB_CDEF)).await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append(event.event_type))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::AgentDead, callback).await?;
        runtime.emit_agent_dead(0x00AB_CDEF).await?;

        let (count, event_type) = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<(usize, String)> {
                let list = tracker.bind(py);
                let count = list.len();
                let first = list.get_item(0)?.extract::<String>()?;
                Ok((count, first))
            })
        })
        .await??;
        assert_eq!(count, 1);
        assert_eq!(event_type, "agent_dead");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_loot_captured_invokes_registered_callbacks()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("emit-loot").await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append(event.data['kind']))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::LootCaptured, callback).await?;
        let loot = LootRecord {
            id: Some(1),
            agent_id: 0x00AB_CDEF,
            kind: "screenshot".to_owned(),
            name: "Desktop_01.01.2026.png".to_owned(),
            file_path: None,
            size_bytes: Some(12345),
            captured_at: "2026-03-15T00:00:00Z".to_owned(),
            data: None,
            metadata: None,
        };
        runtime.emit_loot_captured(&loot).await?;

        let (count, kind) = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<(usize, String)> {
                let list = tracker.bind(py);
                let count = list.len();
                let first = list.get_item(0)?.extract::<String>()?;
                Ok((count, first))
            })
        })
        .await??;
        assert_eq!(count, 1);
        assert_eq!(kind, "screenshot");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_task_created_invokes_registered_callbacks()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("emit-task").await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append(event.data['command_line']))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::TaskCreated, callback).await?;
        let job = Job {
            command: 10,
            request_id: 42,
            payload: vec![],
            command_line: "shell whoami".to_owned(),
            task_id: "task-001".to_owned(),
            created_at: "2026-03-15T00:00:00Z".to_owned(),
            operator: "admin".to_owned(),
        };
        runtime.emit_task_created(0x00AB_CDEF, &job).await?;

        let (count, cmd_line) = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<(usize, String)> {
                let list = tracker.bind(py);
                let count = list.len();
                let first = list.get_item(0)?.extract::<String>()?;
                Ok((count, first))
            })
        })
        .await??;
        assert_eq!(count, 1);
        assert_eq!(cmd_line, "shell whoami");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn listener_start_fails_before_manager_attached() -> Result<(), Box<dyn std::error::Error>>
    {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-listener-unavailable-start").await?;

        // Do NOT call attach_listener_manager — the manager stays None.
        let handle = std::thread::spawn({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<String> {
                    runtime.install_api_module(py)?;
                    let module = py.import("havoc")?;
                    let listener = module.getattr("Listener")?.call1(("nonexistent",))?;
                    match listener.call_method0("start") {
                        Ok(_) => Ok("unexpected success".to_owned()),
                        Err(err) => Ok(err.to_string()),
                    }
                })
            }
        });
        let error_message = handle.join().map_err(|_| "python test thread panicked")??;
        assert!(
            error_message.contains("listener manager is not available"),
            "expected ListenerManagerUnavailable error, got: {error_message}",
        );
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn listener_stop_fails_before_manager_attached() -> Result<(), Box<dyn std::error::Error>>
    {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-listener-unavailable-stop").await?;

        let handle = std::thread::spawn({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<String> {
                    runtime.install_api_module(py)?;
                    let module = py.import("havoc")?;
                    let listener = module.getattr("Listener")?.call1(("nonexistent",))?;
                    match listener.call_method0("stop") {
                        Ok(_) => Ok("unexpected success".to_owned()),
                        Err(err) => Ok(err.to_string()),
                    }
                })
            }
        });
        let error_message = handle.join().map_err(|_| "python test thread panicked")??;
        assert!(
            error_message.contains("listener manager is not available"),
            "expected ListenerManagerUnavailable error, got: {error_message}",
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_plugins_rejects_nonexistent_plugin_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let bogus_path = unique_test_dir("plugins-no-such-dir");
        // Ensure the directory really doesn't exist.
        assert!(!bogus_path.exists());

        let database = Database::connect(unique_test_dir("plugins-invalid-dir-db")).await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime = PluginRuntime::initialize(
            database,
            registry,
            events,
            sockets,
            Some(bogus_path.clone()),
        )
        .await?;

        let result = runtime.load_plugins().await;
        match result {
            Err(PluginError::InvalidPluginDirectory { path }) => {
                assert_eq!(path, bogus_path);
            }
            other => panic!("expected Err(InvalidPluginDirectory), got {other:?}"),
        }
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn load_plugins_skips_plugin_with_interior_nul_in_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let temp_dir = TempDir::new()?;
        let plugin_path = temp_dir.path().join("nul_plugin.py");
        // Write a plugin whose source contains an interior NUL byte — this must
        // trigger the CString conversion guard and skip the plugin.
        std::fs::write(&plugin_path, b"x = 1\0\ny = 2\n")?;

        let database = Database::connect(unique_test_dir("plugins-nul-source")).await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime = PluginRuntime::initialize(
            database,
            registry,
            events,
            sockets,
            Some(temp_dir.path().to_path_buf()),
        )
        .await?;

        let loaded = runtime.load_plugins().await?;
        assert!(loaded.is_empty(), "plugin with interior NUL should be skipped, got {loaded:?}",);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_plugins_rejects_regular_file_as_plugin_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("not_a_dir.txt");
        std::fs::write(&file_path, "hello")?;

        let database = Database::connect(unique_test_dir("plugins-file-not-dir-db")).await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime =
            PluginRuntime::initialize(database, registry, events, sockets, Some(file_path.clone()))
                .await?;

        let result = runtime.load_plugins().await;
        match result {
            Err(PluginError::InvalidPluginDirectory { path }) => {
                assert_eq!(path, file_path);
            }
            other => panic!("expected Err(InvalidPluginDirectory), got {other:?}"),
        }
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn invoke_command_against_unknown_agent_returns_error_and_no_broadcast()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        // Do NOT insert any agent into the registry — the agent ID will be unknown.
        let (_database, _registry, events, _sockets, runtime) =
            runtime_fixture("plugins-unknown-agent-task").await?;

        // Register a command that calls agent.task() inside its callback.
        let handle = std::thread::spawn({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<()> {
                    runtime.install_api_module(py)?;
                    let module = py.import("red_cell")?;
                    let callback = py.eval(
                        pyo3::ffi::c_str!("lambda agent, args: agent.task(99, 'payload')"),
                        None,
                        None,
                    )?;
                    module.call_method1(
                        "register_command",
                        ("fail_cmd", "command that will fail", callback),
                    )?;
                    Ok(())
                })
            }
        });
        handle.join().map_err(|_| "python test thread panicked")??;

        let mut receiver = events.subscribe();

        // Invoke against a non-existent agent.
        let result = runtime
            .invoke_registered_command(
                "fail_cmd",
                "operator",
                OperatorRole::Admin,
                0xDEAD_BEEF,
                vec!["arg1".to_owned()],
            )
            .await;

        // The call must return an error (propagated from enqueue_job → AgentNotFound).
        assert!(result.is_err(), "expected error for unknown agent, got {result:?}");

        // No AgentTask broadcast should have been emitted.
        let recv_result =
            tokio::time::timeout(std::time::Duration::from_millis(100), receiver.recv()).await;
        assert!(
            recv_result.is_err(),
            "expected no broadcast, but received a message: {recv_result:?}",
        );
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn load_plugins_returns_empty_when_no_dir_configured()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-no-dir").await?;

        let loaded = runtime.load_plugins().await?;
        assert!(loaded.is_empty(), "expected empty vec when no plugins_dir configured");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn load_plugins_skips_non_py_files() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let temp_dir = TempDir::new()?;
        std::fs::write(temp_dir.path().join("readme.txt"), "not a plugin")?;
        std::fs::write(temp_dir.path().join("data.json"), "{}")?;
        std::fs::write(temp_dir.path().join("real_plugin.py"), "x = 42\n")?;

        let database = Database::connect(unique_test_dir("plugins-skip-non-py")).await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime = PluginRuntime::initialize(
            database,
            registry,
            events,
            sockets,
            Some(temp_dir.path().to_path_buf()),
        )
        .await?;

        let loaded = runtime.load_plugins().await?;
        assert_eq!(loaded, vec!["real_plugin".to_owned()]);
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_agent_registered_skips_unknown_agent() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("emit-registered-unknown").await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!("(lambda t: lambda event: t.append(1))(_tracker)"),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::AgentRegistered, callback).await?;
        runtime.emit_agent_registered(0xDEAD).await?;

        let count = tokio::task::spawn_blocking(move || tracker_len(tracker)).await?;
        assert_eq!(count, 0, "callback must not fire when agent is unknown");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_agent_dead_skips_unknown_agent() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("emit-dead-unknown").await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!("(lambda t: lambda event: t.append(1))(_tracker)"),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::AgentDead, callback).await?;
        runtime.emit_agent_dead(0xDEAD).await?;

        let count = tokio::task::spawn_blocking(move || tracker_len(tracker)).await?;
        assert_eq!(count, 0, "callback must not fire when agent is unknown");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_events_succeed_silently_with_no_callbacks()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("emit-no-callbacks").await?;
        registry.insert(sample_agent(0x00AB_CDEF)).await?;

        // All emit_* methods must succeed when no callbacks are registered.
        runtime.emit_agent_checkin(0x00AB_CDEF).await?;
        runtime.emit_agent_registered(0x00AB_CDEF).await?;
        runtime.emit_agent_dead(0x00AB_CDEF).await?;
        runtime.emit_command_output(0x00AB_CDEF, 1, 1, "output").await?;
        runtime
            .emit_loot_captured(&LootRecord {
                id: Some(1),
                agent_id: 0x00AB_CDEF,
                kind: "screenshot".to_owned(),
                name: "test.png".to_owned(),
                file_path: None,
                size_bytes: Some(100),
                captured_at: "2026-03-15T00:00:00Z".to_owned(),
                data: None,
                metadata: None,
            })
            .await?;
        runtime
            .emit_task_created(
                0x00AB_CDEF,
                &Job {
                    command: 1,
                    request_id: 1,
                    payload: vec![],
                    command_line: "test".to_owned(),
                    task_id: "001".to_owned(),
                    created_at: "2026-03-15T00:00:00Z".to_owned(),
                    operator: "admin".to_owned(),
                },
            )
            .await?;
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn command_names_and_descriptions_empty_by_default()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-empty-commands").await?;

        assert!(runtime.command_names().await.is_empty());
        assert!(runtime.command_descriptions().await.is_empty());
        Ok(())
    }

    /// Multiple plugins registering different commands should produce a merged
    /// result from `command_names()` and `command_descriptions()`.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn command_names_and_descriptions_merge_across_plugins()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let temp_dir = TempDir::new()?;

        // Plugin A registers "recon" command.
        std::fs::write(
            temp_dir.path().join("plugin_a.py"),
            r#"
import havoc

def run_recon(agent, args):
    agent.task(0x10, "recon")

havoc.RegisterCommand("recon", "run reconnaissance", run_recon)
"#,
        )?;

        // Plugin B registers "exfil" command.
        std::fs::write(
            temp_dir.path().join("plugin_b.py"),
            r#"
import havoc

def run_exfil(agent, args):
    agent.task(0x20, "exfil")

havoc.RegisterCommand("exfil", "exfiltrate data", run_exfil)
"#,
        )?;

        let database = Database::connect(unique_test_dir("plugins-merge-commands")).await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime = PluginRuntime::initialize(
            database,
            registry,
            events,
            sockets,
            Some(temp_dir.path().to_path_buf()),
        )
        .await?;

        let loaded = runtime.load_plugins().await?;
        assert_eq!(loaded.len(), 2);

        // command_names returns sorted keys from BTreeMap.
        let names = runtime.command_names().await;
        assert_eq!(names, vec!["exfil".to_owned(), "recon".to_owned()]);

        let descriptions = runtime.command_descriptions().await;
        assert_eq!(descriptions.len(), 2);
        assert_eq!(descriptions.get("recon"), Some(&"run reconnaissance".to_owned()),);
        assert_eq!(descriptions.get("exfil"), Some(&"exfiltrate data".to_owned()),);
        Ok(())
    }

    /// When two plugins register a command with the same name, the last one
    /// loaded wins (alphabetical filename order). The description in
    /// `command_descriptions()` should reflect the overwriting plugin.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn command_names_last_write_wins_on_duplicate_name()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let temp_dir = TempDir::new()?;

        // aaa_first.py registers "scan" with description "first scan".
        std::fs::write(
            temp_dir.path().join("aaa_first.py"),
            r#"
import havoc

def run_scan(agent, args):
    agent.task(0x30, "first")

havoc.RegisterCommand("scan", "first scan", run_scan)
"#,
        )?;

        // zzz_second.py registers "scan" with description "second scan".
        std::fs::write(
            temp_dir.path().join("zzz_second.py"),
            r#"
import havoc

def run_scan(agent, args):
    agent.task(0x30, "second")

havoc.RegisterCommand("scan", "second scan", run_scan)
"#,
        )?;

        let database = Database::connect(unique_test_dir("plugins-duplicate-command")).await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime = PluginRuntime::initialize(
            database,
            registry,
            events,
            sockets,
            Some(temp_dir.path().to_path_buf()),
        )
        .await?;

        let loaded = runtime.load_plugins().await?;
        assert_eq!(loaded.len(), 2);

        // Only one "scan" entry should exist (BTreeMap key deduplication).
        let names = runtime.command_names().await;
        assert_eq!(names, vec!["scan".to_owned()]);

        // zzz_second.py loads after aaa_first.py, so its description wins.
        let descriptions = runtime.command_descriptions().await;
        assert_eq!(descriptions.get("scan"), Some(&"second scan".to_owned()),);
        Ok(())
    }

    /// Verify that the thread-local [`CallbackRuntimeGuard`] allows `active()` to
    /// succeed even when the global `RUNTIME` mutex is held by another thread,
    /// proving the re-entrancy fix for the callback deadlock (red-cell-c2-ss50).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn callback_runtime_guard_bypasses_global_mutex() -> Result<(), Box<dyn std::error::Error>>
    {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-callback-guard").await?;

        let runtime_for_thread = runtime.clone();
        let result = tokio::task::spawn_blocking(move || {
            // Set the thread-local guard (simulating callback dispatch).
            let _guard = CallbackRuntimeGuard::enter(&runtime_for_thread);
            // active() should resolve via the thread-local, never touching the
            // global mutex.
            PluginRuntime::active()
        })
        .await?;

        assert!(result.is_ok(), "active() should succeed via thread-local guard");
        Ok(())
    }

    /// Verify that `active()` returns the thread-local runtime (not the global)
    /// when the callback guard is set, and that the thread-local is cleared on
    /// guard drop.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn callback_runtime_guard_clears_on_drop() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-callback-guard-drop").await?;

        let result = tokio::task::spawn_blocking(move || {
            // Verify thread-local is empty before guard.
            let before = CALLBACK_RUNTIME.with(|cell| cell.borrow().is_some());
            assert!(!before, "thread-local should be None before guard");

            {
                let _guard = CallbackRuntimeGuard::enter(&runtime);
                let during = CALLBACK_RUNTIME.with(|cell| cell.borrow().is_some());
                assert!(during, "thread-local should be Some while guard is active");
            }

            // After guard drops, thread-local should be cleared.
            let after = CALLBACK_RUNTIME.with(|cell| cell.borrow().is_some());
            assert!(!after, "thread-local should be None after guard drops");
        })
        .await;

        assert!(result.is_ok());
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn attach_listener_manager_makes_manager_available()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (database, registry, events, sockets, runtime) =
            runtime_fixture("plugins-attach-manager").await?;
        database.listeners().create(&sample_listener()).await?;

        // Before attaching, listener operations should fail.
        let result = runtime.listener_manager().await;
        assert!(
            matches!(result, Err(PluginError::ListenerManagerUnavailable)),
            "expected ListenerManagerUnavailable before attach",
        );

        let listeners =
            ListenerManager::new(database, registry, events, sockets, Some(runtime.clone()));
        runtime.attach_listener_manager(listeners).await;

        // After attaching, listener_manager() should succeed.
        let manager = runtime.listener_manager().await;
        assert!(manager.is_ok(), "expected listener manager to be available after attach");
        Ok(())
    }

    /// Regression test for red-cell-c2-ss50: a Python callback that calls back
    /// into the Rust API (e.g. `havoc.Agent(...).info`) must not deadlock on the
    /// global `RUNTIME` mutex.  The `CallbackRuntimeGuard` thread-local bypass
    /// makes this safe.  Without it, `invoke_callbacks` holds the mutex while
    /// Python calls `PluginRuntime::active()`, which tries to acquire it again
    /// on the same thread — classic re-entrant deadlock.
    ///
    /// We use `tokio::time::timeout` so the test fails fast rather than hanging
    /// forever if the deadlock regresses.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn callback_reentrant_rust_api_does_not_deadlock()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-reentrant-deadlock").await?;
        let agent_id: u32 = 0x00DE_AD01;
        registry.insert(sample_agent(agent_id)).await?;

        // Build a Python callback that calls back into the Rust API via
        // `havoc.Agent("00DEAD01").info`, which internally calls
        // `PluginRuntime::active()`.  If the thread-local guard is not set,
        // this will deadlock because `invoke_callbacks` already holds the
        // global RUNTIME mutex on this thread.
        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<_> {
                    runtime.install_api_module(py)?;
                    let havoc = py.import("havoc")?;
                    let locals = pyo3::types::PyDict::new(py);
                    let tracker = PyList::empty(py);
                    locals.set_item("_tracker", tracker.clone())?;
                    locals.set_item("havoc", havoc)?;
                    let cb = py.eval(
                        pyo3::ffi::c_str!(
                            "(lambda t, h: lambda event: t.append(h.Agent('00DEAD01').info['Hostname']))(_tracker, havoc)"
                        ),
                        None,
                        Some(&locals),
                    )?;
                    Ok((tracker.unbind(), cb.unbind()))
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::AgentCheckin, callback).await?;

        // The callback re-enters Rust via havoc.Agent().info — if the
        // thread-local bypass is missing, this will hang forever.  A 10-second
        // timeout gives plenty of margin for CI while still catching a
        // deadlock quickly.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            runtime.emit_agent_checkin(agent_id),
        )
        .await;

        let emit_result = result.expect("timed out — likely deadlock in re-entrant callback");
        emit_result?;

        // Verify the callback actually ran and read the agent info successfully.
        let (count, hostname) = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<(usize, String)> {
                let list = tracker.bind(py);
                let count = list.len();
                let first = list.get_item(0)?.extract::<String>()?;
                Ok((count, first))
            })
        })
        .await??;
        assert_eq!(count, 1, "callback should have been invoked exactly once");
        assert_eq!(hostname, "wkstn-01", "callback should have read the agent hostname");
        Ok(())
    }

    // ---- RBAC enforcement tests ----

    #[test]
    fn caller_role_guard_sets_and_clears_thread_local() {
        // Initially no role is set.
        let role = CALLER_ROLE.with(|cell| *cell.borrow());
        assert!(role.is_none(), "caller role should be None before guard");

        {
            let _guard = CallerRoleGuard::enter(OperatorRole::Analyst);
            let role = CALLER_ROLE.with(|cell| *cell.borrow());
            assert_eq!(role, Some(OperatorRole::Analyst));
        }

        let role = CALLER_ROLE.with(|cell| *cell.borrow());
        assert!(role.is_none(), "caller role should be None after guard drops");
    }

    #[test]
    fn check_plugin_permission_allows_all_in_system_context() {
        // Ensure no caller role is set (system context).
        CALLER_ROLE.with(|cell| *cell.borrow_mut() = None);

        for permission in [
            crate::rbac::Permission::Read,
            crate::rbac::Permission::TaskAgents,
            crate::rbac::Permission::ManageListeners,
            crate::rbac::Permission::Admin,
        ] {
            assert!(
                check_plugin_permission(permission).is_ok(),
                "system context should allow {}",
                permission.as_str(),
            );
        }
    }

    #[test]
    fn check_plugin_permission_admin_allows_everything() {
        let _guard = CallerRoleGuard::enter(OperatorRole::Admin);
        for permission in [
            crate::rbac::Permission::Read,
            crate::rbac::Permission::TaskAgents,
            crate::rbac::Permission::ManageListeners,
            crate::rbac::Permission::Admin,
        ] {
            assert!(
                check_plugin_permission(permission).is_ok(),
                "Admin should have {} permission",
                permission.as_str(),
            );
        }
    }

    #[test]
    fn check_plugin_permission_operator_denied_admin() {
        let _guard = CallerRoleGuard::enter(OperatorRole::Operator);

        assert!(check_plugin_permission(crate::rbac::Permission::Read).is_ok());
        assert!(check_plugin_permission(crate::rbac::Permission::TaskAgents).is_ok());
        assert!(check_plugin_permission(crate::rbac::Permission::ManageListeners).is_ok());
        assert!(
            check_plugin_permission(crate::rbac::Permission::Admin).is_err(),
            "Operator should be denied Admin permission",
        );
    }

    #[test]
    fn check_plugin_permission_analyst_denied_write_operations() {
        let _guard = CallerRoleGuard::enter(OperatorRole::Analyst);

        assert!(check_plugin_permission(crate::rbac::Permission::Read).is_ok());
        assert!(
            check_plugin_permission(crate::rbac::Permission::TaskAgents).is_err(),
            "Analyst should be denied TaskAgents permission",
        );
        assert!(
            check_plugin_permission(crate::rbac::Permission::ManageListeners).is_err(),
            "Analyst should be denied ManageListeners permission",
        );
        assert!(
            check_plugin_permission(crate::rbac::Permission::Admin).is_err(),
            "Analyst should be denied Admin permission",
        );
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn invoke_registered_command_enforces_caller_role_in_python()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let _reset = ActiveRuntimeReset::clear()?;
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-rbac-invoke").await?;

        // Register an agent so the command can reference it.
        let agent = sample_agent(0xBEEF_0001);
        registry.insert(agent.clone()).await?;

        // Register a Python command that tries to call list_agents() (requires Read).
        let command_runtime = runtime.clone();
        let handle = std::thread::spawn(move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&command_runtime);
            Python::with_gil(|py| -> PyResult<()> {
                command_runtime.install_api_module(py)?;
                let module = PyModule::from_code(
                    py,
                    pyo3::ffi::c_str!(
                        "import red_cell\n\
                         \n\
                         def my_command(agent, args):\n\
                         \tagents = red_cell.list_agents()\n"
                    ),
                    pyo3::ffi::c_str!("test_rbac_read.py"),
                    pyo3::ffi::c_str!("test_rbac_read"),
                )?;
                let callback = module.getattr("my_command")?.unbind();
                command_runtime
                    .block_on(command_runtime.register_command(
                        "test_rbac_cmd".to_owned(),
                        "test command for RBAC".to_owned(),
                        callback,
                    ))
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                Ok(())
            })
        });
        handle.join().map_err(|_| "python test thread panicked")??;

        // Admin should succeed.
        let result = runtime
            .invoke_registered_command(
                "test_rbac_cmd",
                "admin_user",
                OperatorRole::Admin,
                0xBEEF_0001,
                vec![],
            )
            .await;
        assert!(result.is_ok(), "Admin should be able to invoke the command");

        // Analyst should also succeed because list_agents requires Read.
        let result = runtime
            .invoke_registered_command(
                "test_rbac_cmd",
                "analyst_user",
                OperatorRole::Analyst,
                0xBEEF_0001,
                vec![],
            )
            .await;
        assert!(result.is_ok(), "Analyst should be able to invoke read-only command");

        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn invoke_registered_command_denies_analyst_task_agents()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let _reset = ActiveRuntimeReset::clear()?;
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-rbac-deny-task").await?;

        let agent = sample_agent(0xBEEF_0002);
        registry.insert(agent.clone()).await?;

        // Register a command that tries to task an agent (requires TaskAgents).
        let command_runtime = runtime.clone();
        let handle = std::thread::spawn(move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&command_runtime);
            Python::with_gil(|py| -> PyResult<()> {
                command_runtime.install_api_module(py)?;
                let module = PyModule::from_code(
                    py,
                    pyo3::ffi::c_str!(
                        "import red_cell\n\
                         \n\
                         def task_command(agent, args):\n\
                         \tagent.task(99)\n"
                    ),
                    pyo3::ffi::c_str!("test_rbac_task.py"),
                    pyo3::ffi::c_str!("test_rbac_task"),
                )?;
                let callback = module.getattr("task_command")?.unbind();
                command_runtime
                    .block_on(command_runtime.register_command(
                        "test_task_cmd".to_owned(),
                        "test task command".to_owned(),
                        callback,
                    ))
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                Ok(())
            })
        });
        handle.join().map_err(|_| "python test thread panicked")??;

        // Analyst should be denied because task() requires TaskAgents.
        let result = runtime
            .invoke_registered_command(
                "test_task_cmd",
                "analyst_user",
                OperatorRole::Analyst,
                0xBEEF_0002,
                vec![],
            )
            .await;
        assert!(result.is_err(), "Analyst should be denied agent tasking via plugin");

        // Operator should succeed.
        let result = runtime
            .invoke_registered_command(
                "test_task_cmd",
                "operator_user",
                OperatorRole::Operator,
                0xBEEF_0002,
                vec![],
            )
            .await;
        assert!(result.is_ok(), "Operator should be able to task agents via plugin");

        Ok(())
    }

    #[test]
    fn plugin_event_round_trip_all_variants() {
        let variants = [
            PluginEvent::AgentCheckin,
            PluginEvent::AgentRegistered,
            PluginEvent::AgentDead,
            PluginEvent::CommandOutput,
            PluginEvent::LootCaptured,
            PluginEvent::TaskCreated,
        ];
        for event in variants {
            let s = event.as_str();
            let parsed = PluginEvent::parse(s);
            assert_eq!(parsed, Some(event), "round-trip failed for {s:?}");
        }
    }

    #[test]
    fn plugin_event_parse_unknown_returns_none() {
        for input in ["nonexistent_event", "foo", "", "agent_checkin_extra", "UNKNOWN"] {
            assert_eq!(
                PluginEvent::parse(input),
                None,
                "expected None for unknown input {input:?}"
            );
        }
    }

    #[test]
    fn plugin_event_parse_case_insensitive() {
        assert_eq!(PluginEvent::parse("AGENT_CHECKIN"), Some(PluginEvent::AgentCheckin));
        assert_eq!(PluginEvent::parse("Agent_Registered"), Some(PluginEvent::AgentRegistered));
        assert_eq!(PluginEvent::parse("COMMAND_OUTPUT"), Some(PluginEvent::CommandOutput));
        assert_eq!(PluginEvent::parse("Loot_Captured"), Some(PluginEvent::LootCaptured));
        assert_eq!(PluginEvent::parse("TASK_CREATED"), Some(PluginEvent::TaskCreated));
        assert_eq!(PluginEvent::parse("AGENT_DEAD"), Some(PluginEvent::AgentDead));
    }

    #[test]
    fn plugin_event_parse_trims_whitespace() {
        assert_eq!(PluginEvent::parse("  agent_checkin  "), Some(PluginEvent::AgentCheckin));
        assert_eq!(PluginEvent::parse("\tagent_dead\n"), Some(PluginEvent::AgentDead));
        assert_eq!(PluginEvent::parse("   "), None);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn match_registered_command_resolves_ambiguous_prefix_to_longest()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("plugins-ambiguous-prefix").await?;

        let handle = std::thread::spawn({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<()> {
                    runtime.install_api_module(py)?;
                    let module = py.import("red_cell")?;
                    let noop =
                        py.eval(pyo3::ffi::c_str!("lambda agent, args: None"), None, None)?;
                    module.call_method1("register_command", ("scan", "short scan", &noop))?;
                    module.call_method1("register_command", ("scan_deep", "deep scan", &noop))?;
                    Ok(())
                })
            }
        });
        handle.join().map_err(|_| "python test thread panicked")??;

        // "scan_deep target" must match "scan_deep", not "scan"
        assert_eq!(
            runtime
                .match_registered_command(&AgentTaskInfo {
                    command_line: "scan_deep target".to_owned(),
                    ..AgentTaskInfo::default()
                })
                .await,
            Some(("scan_deep".to_owned(), vec!["target".to_owned()]))
        );

        // "scan host1" must still match "scan"
        assert_eq!(
            runtime
                .match_registered_command(&AgentTaskInfo {
                    command_line: "scan host1".to_owned(),
                    ..AgentTaskInfo::default()
                })
                .await,
            Some(("scan".to_owned(), vec!["host1".to_owned()]))
        );

        // exact "scan_deep" with no args must match "scan_deep"
        assert_eq!(
            runtime
                .match_registered_command(&AgentTaskInfo {
                    command_line: "scan_deep".to_owned(),
                    ..AgentTaskInfo::default()
                })
                .await,
            Some(("scan_deep".to_owned(), vec![]))
        );

        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_agent_checkin_passes_full_agent_data() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("emit-checkin-full").await?;
        registry.insert(sample_agent(0x00AB_CDEF)).await?;

        // Capture event.data fields and event.agent.id (hex string) via Python.
        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append((event.event_type, event.agent.id if event.agent else None, event.data.get('Hostname'), event.data.get('Username'), event.data.get('ExternalIP'), event.data.get('ProcessName'), event.data.get('Elevated'))))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::AgentCheckin, callback).await?;
        runtime.emit_agent_checkin(0x00AB_CDEF).await?;

        let result = tokio::task::spawn_blocking(move || {
            Python::with_gil(
                |py| -> PyResult<(String, String, String, String, String, String, bool)> {
                    let list = tracker.bind(py);
                    let tuple = list.get_item(0)?;
                    Ok((
                        tuple.get_item(0)?.extract()?,
                        tuple.get_item(1)?.extract()?,
                        tuple.get_item(2)?.extract()?,
                        tuple.get_item(3)?.extract()?,
                        tuple.get_item(4)?.extract()?,
                        tuple.get_item(5)?.extract()?,
                        tuple.get_item(6)?.extract()?,
                    ))
                },
            )
        })
        .await??;
        assert_eq!(result.0, "agent_checkin");
        assert_eq!(result.1, "00ABCDEF");
        assert_eq!(result.2, "wkstn-01");
        assert_eq!(result.3, "operator");
        assert_eq!(result.4, "203.0.113.10");
        assert_eq!(result.5, "explorer.exe");
        assert!(result.6, "Elevated must be true");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_command_output_passes_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("emit-output-full").await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append((event.event_type, event.data['agent_id'], event.data['command_id'], event.data['request_id'], event.data['output'])))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::CommandOutput, callback).await?;
        runtime.emit_command_output(0x00AB_CDEF, 42, 7, "test output").await?;

        let result = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<(String, u32, u32, u32, String)> {
                let list = tracker.bind(py);
                let tuple = list.get_item(0)?;
                Ok((
                    tuple.get_item(0)?.extract()?,
                    tuple.get_item(1)?.extract()?,
                    tuple.get_item(2)?.extract()?,
                    tuple.get_item(3)?.extract()?,
                    tuple.get_item(4)?.extract()?,
                ))
            })
        })
        .await??;
        assert_eq!(result.0, "command_output");
        assert_eq!(result.1, 0x00AB_CDEF, "agent_id");
        assert_eq!(result.2, 42, "command_id");
        assert_eq!(result.3, 7, "request_id");
        assert_eq!(result.4, "test output");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_agent_dead_passes_full_agent_data() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, registry, _events, _sockets, runtime) =
            runtime_fixture("emit-dead-full").await?;
        registry.insert(sample_agent(0x00AB_CDEF)).await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append((event.event_type, event.agent.id if event.agent else None, event.data.get('Hostname'), event.data.get('DomainName'))))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::AgentDead, callback).await?;
        runtime.emit_agent_dead(0x00AB_CDEF).await?;

        let result = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<(String, String, String, String)> {
                let list = tracker.bind(py);
                let tuple = list.get_item(0)?;
                Ok((
                    tuple.get_item(0)?.extract()?,
                    tuple.get_item(1)?.extract()?,
                    tuple.get_item(2)?.extract()?,
                    tuple.get_item(3)?.extract()?,
                ))
            })
        })
        .await??;
        assert_eq!(result.0, "agent_dead");
        assert_eq!(result.1, "00ABCDEF");
        assert_eq!(result.2, "wkstn-01");
        assert_eq!(result.3, "REDCELL");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_loot_captured_passes_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("emit-loot-full").await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append((event.event_type, event.data['agent_id'], event.data['id'], event.data['kind'], event.data['name'], event.data['size_bytes'], event.data['captured_at'], event.data.get('file_path'))))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::LootCaptured, callback).await?;
        let loot = LootRecord {
            id: Some(99),
            agent_id: 0x00AB_CDEF,
            kind: "credential".to_owned(),
            name: "admin_creds.txt".to_owned(),
            file_path: Some("/loot/admin_creds.txt".to_owned()),
            size_bytes: Some(256),
            captured_at: "2026-03-15T12:00:00Z".to_owned(),
            data: None,
            metadata: None,
        };
        runtime.emit_loot_captured(&loot).await?;

        let result = tokio::task::spawn_blocking(move || {
            Python::with_gil(
                |py| -> PyResult<(String, u32, u64, String, String, u64, String, String)> {
                    let list = tracker.bind(py);
                    let tuple = list.get_item(0)?;
                    Ok((
                        tuple.get_item(0)?.extract()?,
                        tuple.get_item(1)?.extract()?,
                        tuple.get_item(2)?.extract()?,
                        tuple.get_item(3)?.extract()?,
                        tuple.get_item(4)?.extract()?,
                        tuple.get_item(5)?.extract()?,
                        tuple.get_item(6)?.extract()?,
                        tuple.get_item(7)?.extract()?,
                    ))
                },
            )
        })
        .await??;
        assert_eq!(result.0, "loot_captured");
        assert_eq!(result.1, 0x00AB_CDEF, "agent_id");
        assert_eq!(result.2, 99, "loot id");
        assert_eq!(result.3, "credential", "kind");
        assert_eq!(result.4, "admin_creds.txt", "name");
        assert_eq!(result.5, 256, "size_bytes");
        assert_eq!(result.6, "2026-03-15T12:00:00Z", "captured_at");
        assert_eq!(result.7, "/loot/admin_creds.txt", "file_path");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_task_created_passes_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("emit-task-full").await?;

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append((event.event_type, event.data['agent_id'], event.data['request_id'], event.data['command'], event.data['command_line'], event.data['task_id'], event.data['created_at'], event.data['operator'])))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::TaskCreated, callback).await?;
        let job = Job {
            command: 15,
            request_id: 99,
            payload: vec![],
            command_line: "upload /tmp/payload.bin".to_owned(),
            task_id: "task-042".to_owned(),
            created_at: "2026-03-15T08:30:00Z".to_owned(),
            operator: "admin".to_owned(),
        };
        runtime.emit_task_created(0x00AB_CDEF, &job).await?;

        let result = tokio::task::spawn_blocking(move || {
            Python::with_gil(
                |py| -> PyResult<(String, u32, u32, u32, String, String, String, String)> {
                    let list = tracker.bind(py);
                    let tuple = list.get_item(0)?;
                    Ok((
                        tuple.get_item(0)?.extract()?,
                        tuple.get_item(1)?.extract()?,
                        tuple.get_item(2)?.extract()?,
                        tuple.get_item(3)?.extract()?,
                        tuple.get_item(4)?.extract()?,
                        tuple.get_item(5)?.extract()?,
                        tuple.get_item(6)?.extract()?,
                        tuple.get_item(7)?.extract()?,
                    ))
                },
            )
        })
        .await??;
        assert_eq!(result.0, "task_created");
        assert_eq!(result.1, 0x00AB_CDEF, "agent_id");
        assert_eq!(result.2, 99, "request_id");
        assert_eq!(result.3, 15, "command");
        assert_eq!(result.4, "upload /tmp/payload.bin", "command_line");
        assert_eq!(result.5, "task-042", "task_id");
        assert_eq!(result.6, "2026-03-15T08:30:00Z", "created_at");
        assert_eq!(result.7, "admin", "operator");
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn emit_loot_captured_exception_does_not_block_subsequent_callbacks()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = lock_test_guard();
        let (_database, _registry, _events, _sockets, runtime) =
            runtime_fixture("emit-loot-exception").await?;

        let (tracker, bad_cb, good_cb) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<(Py<PyList>, Py<PyAny>, Py<PyAny>)> {
                    runtime.install_api_module(py)?;
                    let helper = PyModule::from_code(
                        py,
                        pyo3::ffi::c_str!(
                            "def raise_error(event):\n    raise ValueError('loot boom')"
                        ),
                        pyo3::ffi::c_str!("test_loot_raiser.py"),
                        pyo3::ffi::c_str!("test_loot_raiser"),
                    )?;
                    let bad_cb = helper.getattr("raise_error")?.unbind();

                    let tracker = PyList::empty(py);
                    let locals = PyDict::new(py);
                    locals.set_item("_tracker", tracker.clone())?;
                    let good_cb = py.eval(
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append(event.data['kind']))(_tracker)"
                        ),
                        None,
                        Some(&locals),
                    )?;
                    Ok((tracker.unbind(), bad_cb, good_cb.unbind()))
                })
            }
        })
        .await??;

        runtime.register_callback(PluginEvent::LootCaptured, bad_cb).await?;
        runtime.register_callback(PluginEvent::LootCaptured, good_cb).await?;

        let loot = LootRecord {
            id: Some(1),
            agent_id: 0x00AB_CDEF,
            kind: "download".to_owned(),
            name: "flag.txt".to_owned(),
            file_path: None,
            size_bytes: Some(42),
            captured_at: "2026-03-15T00:00:00Z".to_owned(),
            data: None,
            metadata: None,
        };
        runtime.emit_loot_captured(&loot).await?;

        let (count, kind) = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<(usize, String)> {
                let list = tracker.bind(py);
                let count = list.len();
                let first = list.get_item(0)?.extract::<String>()?;
                Ok((count, first))
            })
        })
        .await??;
        assert_eq!(count, 1, "good callback must fire after bad callback raises");
        assert_eq!(kind, "download");
        Ok(())
    }
}
