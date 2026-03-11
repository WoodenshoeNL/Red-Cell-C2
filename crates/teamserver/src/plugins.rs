//! Embedded Python plugin runtime for the teamserver.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule, PyTuple};
use red_cell_common::AgentInfo;
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::runtime::Handle;
use tokio::sync::RwLock;
use tracing::{instrument, warn};

use crate::{
    AgentRegistry, Database, EventBus, Job, ListenerManager, ListenerManagerError,
    PersistedListener, SocketRelayManager, TeamserverError,
};

static RUNTIME: OnceLock<Mutex<Option<PluginRuntime>>> = OnceLock::new();
static NEXT_REQUEST_ID: AtomicU32 = AtomicU32::new(1);

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
    /// The global plugin runtime mutex was poisoned by a panic in another thread.
    #[error("plugin runtime mutex poisoned: a thread panicked while holding the lock")]
    MutexPoisoned,
}

/// Events exposed to Python callbacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PluginEvent {
    /// Agent check-in callback notifications.
    AgentCheckin,
    /// Agent command output callback notifications.
    CommandOutput,
}

impl PluginEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::AgentCheckin => "agent_checkin",
            Self::CommandOutput => "command_output",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "agent_checkin" => Some(Self::AgentCheckin),
            "command_output" => Some(Self::CommandOutput),
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
        tokio::task::spawn_blocking(move || runtime.load_plugins_blocking(&directory)).await?
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

    fn active() -> PyResult<Self> {
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

                let module_name = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .ok_or_else(|| PluginError::InvalidCStringPath {
                        path: path.display().to_string(),
                    })?
                    .to_owned();
                let code = std::fs::read_to_string(&path).map_err(|_| {
                    PluginError::InvalidPluginDirectory { path: directory.to_path_buf() }
                })?;

                let code = CString::new(code).map_err(|_| PluginError::InvalidCStringPath {
                    path: path.display().to_string(),
                })?;
                let filename = CString::new(path.display().to_string()).map_err(|_| {
                    PluginError::InvalidCStringPath { path: path.display().to_string() }
                })?;
                let module_name_cstr = CString::new(module_name.clone()).map_err(|_| {
                    PluginError::InvalidCStringPath { path: path.display().to_string() }
                })?;

                let module = PyModule::from_code(py, &code, &filename, &module_name_cstr)?;
                py.import("sys")?.getattr("modules")?.set_item(module_name.as_str(), module)?;
                loaded.push(module_name);
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
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;

                let agent_id = match event {
                    PluginEvent::AgentCheckin => payload
                        .get("AgentID")
                        .and_then(Value::as_u64)
                        .and_then(|value| u32::try_from(value).ok()),
                    PluginEvent::CommandOutput => payload
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

    async fn get_agent(&self, agent_id: u32) -> Result<Option<AgentInfo>, TeamserverError> {
        Ok(self.inner.agents.get(agent_id).await)
    }

    async fn list_agents(&self) -> Vec<AgentInfo> {
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
    module.add_function(wrap_pyfunction!(on_command_output, module)?)?;
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use red_cell_common::{AgentEncryptionInfo, HttpListenerConfig, ListenerConfig};
    use tempfile::TempDir;

    use super::*;

    static TEST_GUARD: Mutex<()> = Mutex::new(());

    fn unique_test_dir(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("red-cell-{label}-{suffix}"))
    }

    fn sample_agent(agent_id: u32) -> AgentInfo {
        AgentInfo {
            agent_id,
            active: true,
            reason: String::new(),
            note: "note".to_owned(),
            encryption: AgentEncryptionInfo {
                aes_key: "YWVzLWtleQ==".to_owned(),
                aes_iv: "YWVzLWl2".to_owned(),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
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

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn initialize_exposes_agent_and_listener_accessors()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = TEST_GUARD.lock().map_err(|_| "plugin test mutex poisoned")?;
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
        let _guard = TEST_GUARD.lock().map_err(|_| "plugin test mutex poisoned")?;
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
    async fn registered_command_callbacks_can_queue_agent_jobs()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = TEST_GUARD.lock().map_err(|_| "plugin test mutex poisoned")?;
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
        let _guard = TEST_GUARD.lock().map_err(|_| "plugin test mutex poisoned")?;
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
        let _guard = TEST_GUARD.lock().map_err(|_| "plugin test mutex poisoned")?;
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
            .invoke_registered_command("sync_cmd", "operator", 0x00AB_CDEF, vec!["arg1".to_owned()])
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
        let _guard = TEST_GUARD.lock().map_err(|_| "plugin test mutex poisoned")?;
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
        let _guard = TEST_GUARD.lock().map_err(|_| "plugin test mutex poisoned")?;
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
        let _guard = TEST_GUARD.lock().map_err(|_| "plugin test mutex poisoned")?;
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
        let _guard = TEST_GUARD.lock().map_err(|_| "plugin test mutex poisoned")?;
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
}
