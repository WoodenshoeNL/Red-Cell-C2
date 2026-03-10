//! Embedded Python plugin runtime for the teamserver.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyModule, PyTuple};
use red_cell_common::AgentInfo;
use serde_json::{Value, json};
use tokio::runtime::Handle;
use tokio::sync::RwLock;
use tracing::warn;

use crate::{AgentRegistry, Database, PersistedListener, TeamserverError};

static RUNTIME: OnceLock<Mutex<Option<PluginRuntime>>> = OnceLock::new();

fn runtime_slot() -> &'static Mutex<Option<PluginRuntime>> {
    RUNTIME.get_or_init(|| Mutex::new(None))
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
    plugins_dir: Option<PathBuf>,
    runtime_handle: Handle,
    callbacks: RwLock<BTreeMap<&'static str, Vec<Arc<Py<PyAny>>>>>,
    commands: RwLock<BTreeMap<String, Arc<Py<PyAny>>>>,
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
        plugins_dir: Option<PathBuf>,
    ) -> Result<Self, PluginError> {
        let runtime = Self {
            inner: Arc::new(PluginRuntimeInner {
                database,
                agents,
                plugins_dir,
                runtime_handle: Handle::current(),
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

    /// Return the registered Python command names in sorted order.
    pub async fn command_names(&self) -> Vec<String> {
        self.inner.commands.read().await.keys().cloned().collect()
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

    fn install_api_module(&self, py: Python<'_>) -> PyResult<()> {
        let module = PyModule::new(py, "red_cell")?;
        red_cell(py, &module)?;
        let sys = py.import("sys")?;
        let modules = sys.getattr("modules")?;
        modules.set_item("red_cell", module)?;
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

    async fn register_command(&self, name: String, callback: Py<PyAny>) -> Result<(), PluginError> {
        self.inner.commands.write().await.insert(name, Arc::new(callback));
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
                    let py_args = args
                        .iter()
                        .map(|value| json_value_to_object(py, value))
                        .collect::<PyResult<Vec<_>>>()?;
                    let py_args = PyTuple::new(py, py_args)?;
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
fn register_command(py: Python<'_>, name: String, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || runtime.block_on(runtime.register_command(name, callback)))
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pymodule]
fn red_cell(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(get_agent, module)?)?;
    module.add_function(wrap_pyfunction!(list_agents, module)?)?;
    module.add_function(wrap_pyfunction!(get_listener, module)?)?;
    module.add_function(wrap_pyfunction!(list_listeners, module)?)?;
    module.add_function(wrap_pyfunction!(on_agent_checkin, module)?)?;
    module.add_function(wrap_pyfunction!(on_command_output, module)?)?;
    module.add_function(wrap_pyfunction!(register_command, module)?)?;
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
