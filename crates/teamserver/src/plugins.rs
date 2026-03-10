//! Embedded Python plugin runtime for the teamserver.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyModule, PyTuple};
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use red_cell_common::AgentInfo;
use serde_json::{Value, json};
use tokio::runtime::Handle;
use tokio::sync::RwLock;
use tracing::warn;

use crate::{
    AgentRegistry, Database, EventBus, Job, ListenerManager, PersistedListener,
    SocketRelayManager, TeamserverError,
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
    /// A Python plugin requested listener control before the manager was attached.
    #[error("listener manager is not available")]
    ListenerManagerUnavailable,
    /// A plugin command could not be routed through the teamserver tasking pipeline.
    #[error("{0}")]
    AgentCommand(#[from] crate::websocket::AgentCommandError),
    /// Listener lifecycle control failed.
    #[error("{0}")]
    ListenerManager(#[from] crate::ListenerManagerError),
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
}

#[derive(Debug)]
struct PluginRuntimeInner {
    database: Database,
    agents: AgentRegistry,
    events: EventBus,
    sockets: SocketRelayManager,
    plugins_dir: Option<PathBuf>,
    runtime_handle: Handle,
    listeners: RwLock<Option<ListenerManager>>,
    callbacks: RwLock<BTreeMap<&'static str, Vec<Arc<Py<PyAny>>>>>,
    commands: RwLock<BTreeMap<String, RegisteredCommand>>,
}

#[derive(Clone, Debug)]
struct RegisteredCommand {
    description: String,
    callback: Arc<Py<PyAny>>,
}

/// Shared embedded Python runtime state.
#[derive(Clone, Debug)]
pub struct PluginRuntime {
    inner: Arc<PluginRuntimeInner>,
}

impl PluginRuntime {
    /// Initialize the embedded Python runtime and install the `red_cell` API module.
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
                sockets,
                plugins_dir,
                runtime_handle: Handle::current(),
                listeners: RwLock::new(None),
                callbacks: RwLock::new(BTreeMap::new()),
                commands: RwLock::new(BTreeMap::new()),
            }),
        };

        runtime.install_as_active();
        let runtime_for_python = runtime.clone();
        tokio::task::spawn_blocking(move || {
            pyo3::prepare_freethreaded_python();
            Python::with_gil(|py| -> PyResult<()> {
                runtime_for_python.install_api_module(py)?;
                Ok(())
            })
        })
        .await??;

        Ok(runtime)
    }

    /// Load all `.py` modules from the configured plugins directory.
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
    pub async fn attach_listener_manager(&self, listeners: ListenerManager) {
        *self.inner.listeners.write().await = Some(listeners);
    }

    /// Return the registered Python command names in sorted order.
    pub async fn command_names(&self) -> Vec<String> {
        self.inner.commands.read().await.keys().cloned().collect()
    }

    /// Return the registered Python command descriptions keyed by command name.
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
    pub async fn emit_agent_checkin(&self, agent_id: u32) -> Result<(), PluginError> {
        let Some(agent) = self.inner.agents.get(agent_id).await else {
            return Ok(());
        };
        let payload = serde_json::to_value(agent)?;
        self.invoke_callbacks(PluginEvent::AgentCheckin, vec![payload]).await
    }

    /// Dispatch a command output event to subscribed Python callbacks.
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
        self.invoke_callbacks(PluginEvent::CommandOutput, vec![payload]).await
    }

    fn install_as_active(&self) {
        let lock = runtime_slot();
        let mut guard = match lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some(self.clone());
    }

    fn active() -> PyResult<Self> {
        let lock = runtime_slot();
        let guard = match lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .clone()
            .ok_or_else(|| PyRuntimeError::new_err("red_cell Python runtime is not initialized"))
    }

    /// Return the process-wide active plugin runtime when initialized.
    #[must_use]
    pub fn current() -> Option<Self> {
        let lock = runtime_slot();
        let guard = match lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.clone()
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
        let mut callbacks = self.inner.callbacks.write().await;
        callbacks.entry(event.as_str()).or_default().push(Arc::new(callback));
        Ok(())
    }

    async fn register_command(
        &self,
        name: String,
        description: String,
        callback: Py<PyAny>,
    ) -> Result<(), PluginError> {
        self.inner.commands.write().await.insert(
            name,
            RegisteredCommand { description, callback: Arc::new(callback) },
        );
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
        args: Vec<Value>,
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

                for callback in callbacks {
                    let py_args = match event {
                        PluginEvent::AgentCheckin => {
                            let agent_id = args
                                .first()
                                .and_then(|value| value.get("AgentID"))
                                .and_then(Value::as_u64)
                                .and_then(|value| u32::try_from(value).ok());
                            let event = PyEvent {
                                event_type: event.as_str().to_owned(),
                                agent_id,
                                data: args.first().cloned().unwrap_or(Value::Null),
                            };
                            PyTuple::new(py, [Py::new(py, event)?.into_any()])?
                        }
                        PluginEvent::CommandOutput => {
                            let payload = args.first().cloned().unwrap_or(Value::Null);
                            let agent_id = payload
                                .get("agent_id")
                                .and_then(Value::as_u64)
                                .and_then(|value| u32::try_from(value).ok());
                            let event = PyEvent {
                                event_type: event.as_str().to_owned(),
                                agent_id,
                                data: payload,
                            };
                            PyTuple::new(py, [Py::new(py, event)?.into_any()])?
                        }
                    };
                    let bound = callback.bind(py);
                    if let Err(error) = bound.call1(py_args) {
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
        self.inner
            .listeners
            .read()
            .await
            .clone()
            .ok_or(PluginError::ListenerManagerUnavailable)
    }

    async fn start_listener(&self, name: &str) -> Result<PersistedListener, PluginError> {
        let manager = self.listener_manager().await?;
        manager.start(name).await?;
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
        let manager = self.listener_manager().await?;
        manager.stop(name).await?;
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
    ) -> Result<(), PluginError> {
        self.inner
            .agents
            .enqueue_job(
                agent_id,
                Job {
                    command,
                    request_id: next_request_id(),
                    payload,
                    command_line: format!("python:{command}"),
                    task_id: format!("{:08X}", next_request_id()),
                    created_at: "0".to_owned(),
                },
            )
            .await?;
        Ok(())
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
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let agent = Py::new(py, PyAgent { agent_id })?;
                let py_args = PyTuple::new(
                    py,
                    [
                        agent.into_any(),
                        pyo3::types::PyList::new(py, args.clone())?.into_any().unbind(),
                    ],
                )?;
                command.callback.bind(py).call1(py_args)?;
                Ok(())
            })
        })
        .await??;

        self.inner.events.broadcast(OperatorMessage::AgentTask(Message {
            head: MessageHead {
                event: EventCode::Session,
                user: actor.to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: AgentTaskInfo {
                task_id: format!("{:08X}", next_request_id()),
                command_line: format!("{name} {}", args.join(" ")).trim().to_owned(),
                demon_id: format!("{agent_id:08X}"),
                command_id: "Python".to_owned(),
                command: Some(name),
                arguments: Some(args.join(" ")),
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

        if let Some(command) = info.command.as_deref().map(str::trim).filter(|value| !value.is_empty())
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

        let line = info.command_line.trim();
        if line.is_empty() {
            return None;
        }

        let mut matches = commands
            .keys()
            .filter(|command| line == command.as_str() || line.starts_with(&format!("{command} ")))
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by_key(|command| usize::MAX - command.len());
        let command = matches.into_iter().next()?;
        let rest = line.strip_prefix(command.as_str()).unwrap_or_default().trim();
        let args = if rest.is_empty() {
            Vec::new()
        } else {
            rest.split_whitespace().map(ToOwned::to_owned).collect()
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

#[pyclass(name = "Agent", module = "havoc")]
#[derive(Clone, Debug)]
struct PyAgent {
    agent_id: u32,
}

#[pymethods]
impl PyAgent {
    #[new]
    fn new(agent_id: &str) -> PyResult<Self> {
        let trimmed = agent_id.trim().trim_start_matches("0x").trim_start_matches("0X");
        let agent_id = u32::from_str_radix(trimmed, 16)
            .map_err(|_| PyValueError::new_err(format!("invalid agent id `{agent_id}`")))?;
        Ok(Self { agent_id })
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
            Ok(None) => Err(PyValueError::new_err(format!(
                "agent {:08X} no longer exists",
                self.agent_id
            ))),
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
        py.allow_threads(move || runtime.block_on(runtime.queue_raw_agent_task(self.agent_id, command, payload)))
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(())
    }

    #[pyo3(name = "Command")]
    fn command_alias(
        &self,
        py: Python<'_>,
        task_id: &str,
        command: &str,
        args: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let runtime = PluginRuntime::active()?;
        let payload = args
            .extract::<Vec<u8>>()
            .or_else(|_| args.extract::<String>().map(String::into_bytes))
            .map_err(|_| PyValueError::new_err("Command args must be bytes or str"))?;
        let info = AgentTaskInfo {
            task_id: task_id.to_owned(),
            command_line: command.to_owned(),
            demon_id: format!("{:08X}", self.agent_id),
            command_id: "0".to_owned(),
            command: Some(command.to_owned()),
            extra: BTreeMap::from([(
                "Payload".to_owned(),
                Value::String(String::from_utf8_lossy(&payload).into_owned()),
            )]),
            ..AgentTaskInfo::default()
        };
        py.allow_threads(move || {
            runtime.block_on(crate::websocket::execute_agent_task(
                &runtime.inner.agents,
                &runtime.inner.sockets,
                &runtime.inner.events,
                "python-plugin",
                Message {
                    head: MessageHead {
                        event: EventCode::Session,
                        user: "python-plugin".to_owned(),
                        timestamp: String::new(),
                        one_time: String::new(),
                    },
                    info,
                },
            ))
        })
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(())
    }
}

#[pyclass(name = "Listener", module = "havoc")]
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
        listener
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
            .and_then(|listener| {
                json_value_to_object(
                    py,
                    &serde_json::to_value(listener)
                        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
                )
            })
    }

    fn stop(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let runtime = PluginRuntime::active()?;
        let listener = py.allow_threads(|| runtime.block_on(runtime.stop_listener(&self.name)));
        listener
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
            .and_then(|listener| {
                json_value_to_object(
                    py,
                    &serde_json::to_value(listener)
                        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
                )
            })
    }
}

#[pyclass(name = "Event", module = "havoc")]
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
            .map(|agent_id| Py::new(py, PyAgent { agent_id }).map(|agent| agent.into_any()))
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
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    let event = match event_type.trim().to_ascii_lowercase().as_str() {
        "agent_checkin" => PluginEvent::AgentCheckin,
        "command_output" => PluginEvent::CommandOutput,
        other => return Err(PyValueError::new_err(format!("unsupported event type `{other}`"))),
    };
    py.allow_threads(move || runtime.block_on(runtime.register_callback(event, callback)))
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (name, description, callback))]
fn register_command(
    py: Python<'_>,
    name: String,
    description: String,
    callback: Bound<'_, PyAny>,
) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || runtime.block_on(runtime.register_command(name, description, callback)))
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

fn populate_api_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(get_agent, module)?)?;
    module.add_function(wrap_pyfunction!(get_agents, module)?)?;
    module.add_function(wrap_pyfunction!(list_agents, module)?)?;
    module.add_function(wrap_pyfunction!(get_listener, module)?)?;
    module.add_function(wrap_pyfunction!(get_listeners, module)?)?;
    module.add_function(wrap_pyfunction!(list_listeners, module)?)?;
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

    use red_cell_common::{AgentEncryptionInfo, AgentInfo, HttpListenerConfig, ListenerConfig};
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

    #[tokio::test]
    async fn initialize_exposes_agent_and_listener_accessors()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = TEST_GUARD.lock().map_err(|_| "plugin test mutex poisoned")?;
        let database = Database::connect(unique_test_dir("plugins-access")).await?;
        database.listeners().create(&sample_listener()).await?;
        let registry = AgentRegistry::new(database.clone());
        registry.insert(sample_agent(0x00AB_CDEF)).await?;

        let runtime = PluginRuntime::initialize(database, registry, None).await?;
        let handle = std::thread::spawn(move || {
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let module = py.import("red_cell")?;
                let agent = module.call_method1("get_agent", (0x00AB_CDEF_u32,))?;
                let listener = module.call_method1("get_listener", ("http-main",))?;

                assert_eq!(agent.get_item("Hostname")?.extract::<String>()?, "wkstn-01");
                assert_eq!(listener.get_item("name")?.extract::<String>()?, "http-main");
                Ok(())
            })
        });
        handle.join().map_err(|_| "python test thread panicked")??;
        Ok(())
    }

    #[tokio::test]
    async fn load_plugins_registers_callbacks_and_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = TEST_GUARD.lock().map_err(|_| "plugin test mutex poisoned")?;
        let temp_dir = TempDir::new()?;
        let plugin_path = temp_dir.path().join("sample_plugin.py");
        std::fs::write(
            &plugin_path,
            r#"
import red_cell

def handle_checkin(agent):
    _ = agent["hostname"]

def handle_output(event):
    _ = event["output"]

def run_command():
    return "ok"

red_cell.on_agent_checkin(handle_checkin)
red_cell.on_command_output(handle_output)
red_cell.register_command("demo", run_command)
"#,
        )?;

        let directory = temp_dir.path().to_path_buf();
        let database = Database::connect(unique_test_dir("plugins-load")).await?;
        let registry = AgentRegistry::new(database.clone());
        let runtime = PluginRuntime::initialize(database, registry, Some(directory)).await?;

        let loaded = runtime.load_plugins().await?;

        assert_eq!(loaded, vec!["sample_plugin".to_owned()]);
        assert_eq!(runtime.command_names().await, vec!["demo".to_owned()]);
        Ok(())
    }
}
