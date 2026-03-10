//! Embedded Python runtime for client-side automation.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde_json::{Value, json};
use tracing::warn;

use crate::transport::{AgentSummary, AppState, SharedAppState};

static ACTIVE_RUNTIME: OnceLock<Mutex<Option<Arc<PythonApiState>>>> = OnceLock::new();

fn active_runtime_slot() -> &'static Mutex<Option<Arc<PythonApiState>>> {
    ACTIVE_RUNTIME.get_or_init(|| Mutex::new(None))
}

#[derive(Debug)]
struct RegisteredCommand {
    _callback: Arc<Py<PyAny>>,
}

#[derive(Debug)]
struct PythonApiState {
    app_state: SharedAppState,
    commands: Mutex<BTreeMap<String, RegisteredCommand>>,
    agent_checkin_callbacks: Mutex<Vec<Arc<Py<PyAny>>>>,
    script_errors: Mutex<BTreeMap<String, String>>,
}

impl PythonApiState {
    fn register_command(&self, name: String, callback: Py<PyAny>) {
        let mut commands = lock_mutex(&self.commands);
        commands.insert(name, RegisteredCommand { _callback: Arc::new(callback) });
    }

    fn register_agent_checkin_callback(&self, callback: Py<PyAny>) {
        lock_mutex(&self.agent_checkin_callbacks).push(Arc::new(callback));
    }

    #[cfg(test)]
    fn command_names(&self) -> Vec<String> {
        lock_mutex(&self.commands).keys().cloned().collect()
    }

    #[cfg(test)]
    fn script_errors(&self) -> BTreeMap<String, String> {
        lock_mutex(&self.script_errors).clone()
    }

    fn record_script_error(&self, script_name: String, error: impl Into<String>) {
        lock_mutex(&self.script_errors).insert(script_name, error.into());
    }

    fn clear_script_error(&self, script_name: &str) {
        lock_mutex(&self.script_errors).remove(script_name);
    }

    fn agent_snapshot(&self, agent_id: &str) -> Option<AgentSummary> {
        let normalized = normalize_agent_id(agent_id);
        let state = lock_app_state(&self.app_state);
        state.agents.iter().find(|agent| agent.name_id == normalized).cloned()
    }

    fn invoke_agent_checkin_callbacks(&self, py: Python<'_>, agent_id: &str) {
        let callbacks = lock_mutex(&self.agent_checkin_callbacks).clone();
        if callbacks.is_empty() {
            return;
        }

        match Py::new(py, PyAgent { agent_id: normalize_agent_id(agent_id) }) {
            Ok(agent) => {
                for callback in callbacks {
                    let bound = callback.bind(py);
                    if let Err(error) = bound.call1((agent.clone_ref(py),)) {
                        warn!(agent_id, error = %error, "python agent checkin callback failed");
                    }
                }
            }
            Err(error) => {
                warn!(agent_id, error = %error, "failed to construct python agent proxy");
            }
        }
    }
}

#[derive(Debug)]
enum PythonThreadCommand {
    EmitAgentCheckin(String),
    Shutdown,
}

/// Errors returned by the client-side Python runtime.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PythonRuntimeError {
    #[error("failed to spawn python runtime thread: {0}")]
    ThreadSpawn(#[source] std::io::Error),
    #[error("python runtime initialization did not complete")]
    InitializationChannelClosed,
    #[error("python runtime initialization failed: {0}")]
    Initialization(String),
    #[error("python runtime thread is not available")]
    ThreadUnavailable,
}

/// Handle to the embedded client-side Python runtime.
#[derive(Clone, Debug)]
pub(crate) struct PythonRuntime {
    inner: Arc<PythonRuntimeInner>,
}

#[derive(Debug)]
struct PythonRuntimeInner {
    #[cfg_attr(not(test), allow(dead_code))]
    api_state: Arc<PythonApiState>,
    command_tx: Sender<PythonThreadCommand>,
    join_handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for PythonRuntimeInner {
    fn drop(&mut self) {
        let _ = self.command_tx.send(PythonThreadCommand::Shutdown);

        if let Some(handle) = lock_mutex(&self.join_handle).take() {
            if handle.join().is_err() {
                warn!("python runtime thread panicked during shutdown");
            }
        }

        *lock_mutex(active_runtime_slot()) = None;
    }
}

impl PythonRuntime {
    /// Start the embedded Python runtime and load scripts from the configured directory.
    pub(crate) fn initialize(
        app_state: SharedAppState,
        scripts_dir: PathBuf,
    ) -> Result<Self, PythonRuntimeError> {
        let api_state = Arc::new(PythonApiState {
            app_state,
            commands: Mutex::new(BTreeMap::new()),
            agent_checkin_callbacks: Mutex::new(Vec::new()),
            script_errors: Mutex::new(BTreeMap::new()),
        });
        *lock_mutex(active_runtime_slot()) = Some(api_state.clone());

        let (command_tx, command_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread_api_state = api_state.clone();
        let handle = thread::Builder::new()
            .name("red-cell-client-python".to_owned())
            .spawn(move || {
                if let Err(error) =
                    python_thread_main(thread_api_state, scripts_dir, command_rx, ready_tx)
                {
                    warn!(error = %error, "client python runtime exited");
                }
            })
            .map_err(PythonRuntimeError::ThreadSpawn)?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                inner: Arc::new(PythonRuntimeInner {
                    api_state,
                    command_tx,
                    join_handle: Mutex::new(Some(handle)),
                }),
            }),
            Ok(Err(error)) => Err(PythonRuntimeError::Initialization(error)),
            Err(_) => Err(PythonRuntimeError::InitializationChannelClosed),
        }
    }

    /// Queue an agent check-in callback dispatch on the Python thread.
    pub(crate) fn emit_agent_checkin(&self, agent_id: String) -> Result<(), PythonRuntimeError> {
        self.inner
            .command_tx
            .send(PythonThreadCommand::EmitAgentCheckin(agent_id))
            .map_err(|_| PythonRuntimeError::ThreadUnavailable)
    }

    #[cfg(test)]
    fn command_names(&self) -> Vec<String> {
        self.inner.api_state.command_names()
    }

    #[cfg(test)]
    fn script_errors(&self) -> BTreeMap<String, String> {
        self.inner.api_state.script_errors()
    }
}

fn python_thread_main(
    api_state: Arc<PythonApiState>,
    scripts_dir: PathBuf,
    command_rx: Receiver<PythonThreadCommand>,
    ready_tx: SyncSender<Result<(), String>>,
) -> Result<(), String> {
    pyo3::prepare_freethreaded_python();
    if let Err(error) = std::fs::create_dir_all(&scripts_dir) {
        let message =
            format!("failed to create scripts directory {}: {error}", scripts_dir.display());
        let _ = ready_tx.send(Err(message.clone()));
        return Err(message);
    }

    let init_result = Python::with_gil(|py| -> PyResult<()> {
        install_api_module(py)?;
        load_scripts(py, api_state.as_ref(), &scripts_dir);
        Ok(())
    })
    .map_err(|error| error.to_string());
    match init_result {
        Ok(()) => {
            let _ = ready_tx.send(Ok(()));
        }
        Err(error) => {
            let _ = ready_tx.send(Err(error.clone()));
            return Err(error);
        }
    }

    while let Ok(command) = command_rx.recv() {
        match command {
            PythonThreadCommand::EmitAgentCheckin(agent_id) => {
                Python::with_gil(|py| api_state.invoke_agent_checkin_callbacks(py, &agent_id));
            }
            PythonThreadCommand::Shutdown => break,
        }
    }

    Ok(())
}

fn install_api_module(py: Python<'_>) -> PyResult<()> {
    let sys = py.import("sys")?;
    let modules = sys.getattr("modules")?;
    let module = PyModule::new(py, "red_cell")?;
    populate_api_module(&module)?;
    modules.set_item("red_cell", module)?;
    Ok(())
}

fn load_scripts(py: Python<'_>, api_state: &PythonApiState, scripts_dir: &Path) {
    let mut entries = match std::fs::read_dir(scripts_dir) {
        Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
        Err(error) => {
            warn!(path = %scripts_dir.display(), error = %error, "failed to enumerate client python scripts");
            return;
        }
    };
    entries.sort_by_key(|entry| entry.path());

    if let Ok(sys) = py.import("sys")
        && let Ok(path) = sys.getattr("path")
    {
        let _ = path.call_method1("insert", (0, scripts_dir.display().to_string()));
    }

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("py") {
            continue;
        }

        let script_name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_owned)
            .unwrap_or_else(|| path.display().to_string());

        match load_script(py, &path, &script_name) {
            Ok(()) => api_state.clear_script_error(&script_name),
            Err(error) => {
                warn!(script = %path.display(), error = %error, "failed to load client python script");
                api_state.record_script_error(script_name, error.to_string());
            }
        }
    }
}

fn load_script(py: Python<'_>, path: &Path, script_name: &str) -> PyResult<()> {
    let code = std::fs::read_to_string(path).map_err(|error| {
        PyRuntimeError::new_err(format!("failed to read {}: {error}", path.display()))
    })?;
    let code = CString::new(code).map_err(|_| {
        PyValueError::new_err(format!("script contains interior NUL: {}", path.display()))
    })?;
    let filename = CString::new(path.display().to_string())
        .map_err(|_| PyValueError::new_err(format!("invalid script path: {}", path.display())))?;
    let module_name = CString::new(script_name)
        .map_err(|_| PyValueError::new_err(format!("invalid script module name: {script_name}")))?;

    let module = PyModule::from_code(py, &code, &filename, &module_name)?;
    py.import("sys")?.getattr("modules")?.set_item(script_name, module)?;
    Ok(())
}

fn active_api_state() -> PyResult<Arc<PythonApiState>> {
    lock_mutex(active_runtime_slot())
        .clone()
        .ok_or_else(|| PyRuntimeError::new_err("red_cell Python runtime is not initialized"))
}

fn populate_api_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(register_command, module)?)?;
    module.add_function(wrap_pyfunction!(on_agent_checkin, module)?)?;
    module.add_function(wrap_pyfunction!(agent, module)?)?;
    module.add_class::<PyAgent>()?;
    Ok(())
}

fn ensure_callable(callback: &Bound<'_, PyAny>) -> PyResult<()> {
    if callback.is_callable() {
        Ok(())
    } else {
        Err(PyValueError::new_err("callback must be callable"))
    }
}

fn json_value_to_object(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let json_module = py.import("json")?;
    let serialized =
        serde_json::to_string(value).map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(json_module.call_method1("loads", (serialized,))?.unbind())
}

fn normalize_agent_id(agent_id: &str) -> String {
    let trimmed = agent_id.trim();
    let without_prefix =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);

    if let Ok(value) = u32::from_str_radix(without_prefix, 16) {
        format!("{value:08X}")
    } else {
        trimmed.to_ascii_uppercase()
    }
}

fn agent_summary_to_json(agent: &AgentSummary) -> Value {
    json!({
        "name_id": agent.name_id,
        "status": agent.status,
        "domain_name": agent.domain_name,
        "username": agent.username,
        "internal_ip": agent.internal_ip,
        "external_ip": agent.external_ip,
        "hostname": agent.hostname,
        "process_arch": agent.process_arch,
        "process_name": agent.process_name,
        "process_pid": agent.process_pid,
        "elevated": agent.elevated,
        "os_version": agent.os_version,
        "os_build": agent.os_build,
        "os_arch": agent.os_arch,
        "sleep_delay": agent.sleep_delay,
        "sleep_jitter": agent.sleep_jitter,
        "last_call_in": agent.last_call_in,
        "note": agent.note,
        "pivot_parent": agent.pivot_parent,
        "pivot_links": agent.pivot_links,
    })
}

#[pyclass(name = "Agent")]
#[derive(Clone, Debug)]
struct PyAgent {
    agent_id: String,
}

#[pymethods]
impl PyAgent {
    #[new]
    fn new(agent_id: &Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(value) = agent_id.extract::<String>() {
            return Ok(Self { agent_id: normalize_agent_id(&value) });
        }
        if let Ok(value) = agent_id.extract::<u32>() {
            return Ok(Self { agent_id: format!("{value:08X}") });
        }
        Err(PyValueError::new_err("agent id must be a hex string or integer"))
    }

    #[getter]
    fn id(&self) -> String {
        self.agent_id.clone()
    }

    #[getter]
    fn info(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let api_state = active_api_state()?;
        match api_state.agent_snapshot(&self.agent_id) {
            Some(agent) => json_value_to_object(py, &agent_summary_to_json(&agent)),
            None => Ok(py.None().into_bound(py).unbind()),
        }
    }
}

#[pyfunction]
fn register_command(name: String, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let api_state = active_api_state()?;
    api_state.register_command(name, callback.unbind());
    Ok(())
}

#[pyfunction]
fn on_agent_checkin(callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let api_state = active_api_state()?;
    api_state.register_agent_checkin_callback(callback.unbind());
    Ok(())
}

#[pyfunction]
fn agent(py: Python<'_>, agent_id: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    Py::new(py, PyAgent::new(agent_id)?).map(|agent| agent.into_any())
}

fn lock_mutex<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn lock_app_state(app_state: &SharedAppState) -> std::sync::MutexGuard<'_, AppState> {
    match app_state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::*;

    static TEST_GUARD: Mutex<()> = Mutex::new(());

    fn sample_agent(agent_id: &str) -> AgentSummary {
        AgentSummary {
            name_id: agent_id.to_owned(),
            status: "Alive".to_owned(),
            domain_name: "REDCELL".to_owned(),
            username: "operator".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            hostname: "wkstn-01".to_owned(),
            process_arch: "x64".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_pid: "1337".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: "22631".to_owned(),
            os_arch: "x64".to_owned(),
            sleep_delay: "15".to_owned(),
            sleep_jitter: "20".to_owned(),
            last_call_in: "2026-03-10T10:00:00Z".to_owned(),
            note: "test".to_owned(),
            pivot_parent: None,
            pivot_links: Vec::new(),
        }
    }

    fn write_script(path: &Path, body: &str) {
        if let Err(error) = std::fs::write(path, body) {
            panic!("script write should succeed: {error}");
        }
    }

    fn wait_for_file_contents(path: &Path) -> Option<String> {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if let Ok(contents) = std::fs::read_to_string(path) {
                return Some(contents);
            }
            thread::sleep(Duration::from_millis(25));
        }
        None
    }

    #[test]
    fn runtime_loads_scripts_and_registers_commands() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("sample.py"),
            "import red_cell\nred_cell.register_command('demo', lambda: None)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert_eq!(runtime.command_names(), vec!["demo".to_owned()]);
        assert!(runtime.script_errors().is_empty());
    }

    #[test]
    fn runtime_isolates_bad_scripts() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("good.py"),
            "import red_cell\nred_cell.register_command('good', lambda: None)\n",
        );
        write_script(&temp_dir.path().join("bad.py"), "raise RuntimeError('boom')\n");
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert_eq!(runtime.command_names(), vec!["good".to_owned()]);
        assert!(runtime.script_errors().get("bad").is_some_and(|error| error.contains("boom")));
    }

    #[test]
    fn runtime_dispatches_agent_checkin_callbacks() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("checkin.txt");
        let script = format!(
            "import pathlib\nimport red_cell\n\
def on_checkin(agent):\n    pathlib.Path({output:?}).write_text(agent.info['hostname'])\n\
red_cell.on_agent_checkin(on_checkin)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("checkin.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        runtime
            .emit_agent_checkin("00ABCDEF".to_owned())
            .unwrap_or_else(|error| panic!("agent checkin dispatch should succeed: {error}"));

        assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("wkstn-01"));
    }

    #[test]
    fn agent_proxy_returns_live_agent_info() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(&temp_dir.path().join("noop.py"), "import red_cell\n");
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }
        let _runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let result = Python::with_gil(|py| -> PyResult<String> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            let agent = module.call_method1("agent", ("00ABCDEF",))?;
            Ok(agent.getattr("info")?.get_item("hostname")?.extract::<String>()?)
        })
        .unwrap_or_else(|error| panic!("python agent lookup should succeed: {error}"));

        assert_eq!(result, "wkstn-01");
    }
}
