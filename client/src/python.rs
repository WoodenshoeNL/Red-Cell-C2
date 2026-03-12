//! Embedded Python runtime for client-side automation.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};

use base64::Engine;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedSender;
use tracing::warn;

use crate::transport::{AgentSummary, AppState, ListenerSummary, SharedAppState};

static ACTIVE_RUNTIME: OnceLock<Mutex<Option<Arc<PythonApiState>>>> = OnceLock::new();
const MAX_SCRIPT_OUTPUT_ENTRIES: usize = 512;

fn active_runtime_slot() -> &'static Mutex<Option<Arc<PythonApiState>>> {
    ACTIVE_RUNTIME.get_or_init(|| Mutex::new(None))
}

#[derive(Clone, Debug)]
struct RegisteredCommand {
    script_name: String,
    description: Option<String>,
    callback: Arc<Py<PyAny>>,
}

#[derive(Clone, Debug)]
struct RegisteredAgentCheckinCallback {
    script_name: String,
    mode: AgentCheckinCallbackMode,
    callback: Arc<Py<PyAny>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MatchedCommand {
    name: String,
    command_line: String,
    arguments: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentCheckinCallbackMode {
    Agent,
    Identifier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ScriptRecord {
    path: PathBuf,
    status: ScriptLoadStatus,
    error: Option<String>,
    registered_commands: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ScriptTabRecord {
    title: String,
    script_name: String,
    layout: String,
    has_callback: bool,
}

#[derive(Debug)]
struct PythonApiState {
    app_state: SharedAppState,
    commands: Mutex<BTreeMap<String, RegisteredCommand>>,
    agent_checkin_callbacks: Mutex<Vec<RegisteredAgentCheckinCallback>>,
    script_tabs: Mutex<BTreeMap<String, ScriptTabRecord>>,
    current_script: Mutex<Option<String>>,
    output_entries: Mutex<Vec<ScriptOutputEntry>>,
    script_records: Mutex<BTreeMap<String, ScriptRecord>>,
    outgoing_tx: Mutex<Option<UnboundedSender<OperatorMessage>>>,
}

impl PythonApiState {
    fn begin_script_execution(&self, script_name: &str) {
        *lock_mutex(&self.current_script) = Some(script_name.to_owned());
    }

    fn end_script_execution(&self) {
        *lock_mutex(&self.current_script) = None;
    }

    fn current_script_name(&self) -> Option<String> {
        lock_mutex(&self.current_script).clone()
    }

    fn ensure_script_record(&self, script_name: &str, path: PathBuf) {
        lock_mutex(&self.script_records)
            .entry(script_name.to_owned())
            .and_modify(|record| record.path = path.clone())
            .or_insert(ScriptRecord {
                path,
                status: ScriptLoadStatus::Unloaded,
                error: None,
                registered_commands: BTreeSet::new(),
            });
    }

    fn mark_script_loaded(&self, script_name: &str) {
        if let Some(record) = lock_mutex(&self.script_records).get_mut(script_name) {
            record.status = ScriptLoadStatus::Loaded;
            record.error = None;
        }
    }

    fn mark_script_error(&self, script_name: &str, error: String) {
        if let Some(record) = lock_mutex(&self.script_records).get_mut(script_name) {
            record.status = ScriptLoadStatus::Error;
            record.error = Some(error);
        }
    }

    fn mark_script_unloaded(&self, script_name: &str) {
        if let Some(record) = lock_mutex(&self.script_records).get_mut(script_name) {
            record.status = ScriptLoadStatus::Unloaded;
            record.error = None;
            record.registered_commands.clear();
        }
    }

    fn register_command(
        &self,
        name: String,
        description: Option<String>,
        callback: Py<PyAny>,
    ) -> PyResult<()> {
        let script_name = self.current_script_name().ok_or_else(|| {
            PyRuntimeError::new_err("red_cell.register_command must be called while a script loads")
        })?;
        let normalized_name = normalize_command_name(&name);

        lock_mutex(&self.commands).insert(
            normalized_name.clone(),
            RegisteredCommand {
                script_name: script_name.clone(),
                description,
                callback: Arc::new(callback),
            },
        );
        if let Some(record) = lock_mutex(&self.script_records).get_mut(&script_name) {
            record.registered_commands.insert(normalized_name);
        }
        Ok(())
    }

    fn register_agent_checkin_callback(
        &self,
        callback: Py<PyAny>,
        mode: AgentCheckinCallbackMode,
    ) -> PyResult<()> {
        let script_name = self.current_script_name().ok_or_else(|| {
            PyRuntimeError::new_err("red_cell.on_agent_checkin must be called while a script loads")
        })?;
        lock_mutex(&self.agent_checkin_callbacks).push(RegisteredAgentCheckinCallback {
            script_name,
            mode,
            callback: Arc::new(callback),
        });
        Ok(())
    }

    fn register_tab(&self, title: String, callback: Option<Py<PyAny>>) -> PyResult<()> {
        let script_name = self.current_script_name().ok_or_else(|| {
            PyRuntimeError::new_err("havocui.CreateTab must be called while a script loads")
        })?;
        let normalized_title = normalize_tab_title(&title)?;
        lock_mutex(&self.script_tabs).insert(
            normalized_title.clone(),
            ScriptTabRecord {
                title: normalized_title,
                script_name,
                layout: String::new(),
                has_callback: callback.is_some(),
            },
        );
        if let Some(callback) = callback {
            self.register_command(format!("__tab__ {title}"), None, callback)?;
        }
        Ok(())
    }

    fn set_tab_layout(&self, title: &str, layout: String) -> PyResult<()> {
        let normalized_title = normalize_tab_title(title)?;
        let script_name = self.current_script_name();
        let mut tabs = lock_mutex(&self.script_tabs);
        let Some(record) = tabs.get_mut(&normalized_title) else {
            return Err(PyValueError::new_err(format!(
                "havocui tab `{normalized_title}` has not been created"
            )));
        };
        if let Some(script_name) = script_name
            && record.script_name != script_name
        {
            return Err(PyValueError::new_err(format!(
                "havocui tab `{normalized_title}` belongs to a different script"
            )));
        }
        record.layout = layout;
        Ok(())
    }

    fn clear_script_bindings(&self, script_name: &str) {
        lock_mutex(&self.commands).retain(|_, command| command.script_name != script_name);
        lock_mutex(&self.agent_checkin_callbacks)
            .retain(|callback| callback.script_name != script_name);
        lock_mutex(&self.script_tabs).retain(|_, tab| tab.script_name != script_name);
        if let Some(record) = lock_mutex(&self.script_records).get_mut(script_name) {
            record.registered_commands.clear();
        }
    }

    fn script_descriptors(&self) -> Vec<ScriptDescriptor> {
        lock_mutex(&self.script_records)
            .iter()
            .map(|(name, record)| ScriptDescriptor {
                name: name.clone(),
                path: record.path.clone(),
                status: record.status,
                error: record.error.clone(),
                registered_commands: record.registered_commands.iter().cloned().collect(),
                registered_command_count: record.registered_commands.len(),
            })
            .collect()
    }

    fn output_entries(&self) -> Vec<ScriptOutputEntry> {
        lock_mutex(&self.output_entries).clone()
    }

    fn tab_descriptors(&self) -> Vec<ScriptTabDescriptor> {
        lock_mutex(&self.script_tabs)
            .values()
            .map(|tab| ScriptTabDescriptor {
                title: tab.title.clone(),
                script_name: tab.script_name.clone(),
                layout: tab.layout.clone(),
                has_callback: tab.has_callback,
            })
            .collect()
    }

    fn push_runtime_note(&self, script_name: Option<&str>, text: &str) {
        let mut rendered = text.to_owned();
        if !rendered.ends_with('\n') {
            rendered.push('\n');
        }
        let _ = self.push_output(script_name, ScriptOutputStream::Stdout, &rendered);
    }

    fn push_output(
        &self,
        script_name: Option<&str>,
        stream: ScriptOutputStream,
        text: &str,
    ) -> PyResult<usize> {
        if text.is_empty() {
            return Ok(0);
        }

        let script_name = script_name
            .map(ToOwned::to_owned)
            .or_else(|| self.current_script_name())
            .unwrap_or_else(|| "runtime".to_owned());
        let mut output_entries = lock_mutex(&self.output_entries);
        if let Some(last) = output_entries.last_mut()
            && last.script_name == script_name
            && last.stream == stream
        {
            last.text.push_str(text);
        } else {
            output_entries.push(ScriptOutputEntry { script_name, stream, text: text.to_owned() });
        }
        if output_entries.len() > MAX_SCRIPT_OUTPUT_ENTRIES {
            let overflow = output_entries.len() - MAX_SCRIPT_OUTPUT_ENTRIES;
            output_entries.drain(0..overflow);
        }
        Ok(text.len())
    }

    #[cfg(test)]
    fn command_names(&self) -> Vec<String> {
        lock_mutex(&self.commands).keys().cloned().collect()
    }

    fn match_registered_command(&self, input: &str) -> Option<MatchedCommand> {
        let trimmed_input = input.trim();
        if trimmed_input.is_empty() {
            return None;
        }
        let input_parts = trimmed_input.split_whitespace().collect::<Vec<_>>();

        let commands = lock_mutex(&self.commands);
        let matched_name = commands
            .keys()
            .filter_map(|name| {
                let command_parts = name.split_whitespace().collect::<Vec<_>>();
                (input_parts.len() >= command_parts.len()
                    && input_parts.iter().zip(command_parts.iter()).all(
                        |(input_part, command_part)| input_part.eq_ignore_ascii_case(command_part),
                    ))
                .then_some((name, command_parts.len()))
            })
            .max_by_key(|(_, part_count)| *part_count)?;
        let arguments =
            input_parts[matched_name.1..].iter().map(|argument| (*argument).to_owned()).collect();
        Some(MatchedCommand {
            name: matched_name.0.clone(),
            command_line: trimmed_input.to_owned(),
            arguments,
        })
    }

    fn agent_snapshot(&self, agent_id: &str) -> Option<AgentSummary> {
        let normalized = normalize_agent_id(agent_id);
        let state = lock_app_state(&self.app_state);
        state.agents.iter().find(|agent| agent.name_id == normalized).cloned()
    }

    fn agent_snapshots(&self) -> Vec<AgentSummary> {
        let state = lock_app_state(&self.app_state);
        state.agents.clone()
    }

    fn listener_snapshot(&self, name: &str) -> Option<ListenerSummary> {
        let normalized = normalize_listener_name(name);
        let state = lock_app_state(&self.app_state);
        state.listeners.iter().find(|listener| listener.name == normalized).cloned()
    }

    fn listener_snapshots(&self) -> Vec<ListenerSummary> {
        let state = lock_app_state(&self.app_state);
        state.listeners.clone()
    }

    fn set_outgoing_sender(&self, sender: UnboundedSender<OperatorMessage>) {
        *lock_mutex(&self.outgoing_tx) = Some(sender);
    }

    fn queue_task_message(&self, message: OperatorMessage) -> PyResult<()> {
        let Some(sender) = lock_mutex(&self.outgoing_tx).clone() else {
            return Err(PyRuntimeError::new_err(
                "client transport is not connected for Python tasking",
            ));
        };
        sender
            .send(message)
            .map_err(|_| PyRuntimeError::new_err("client transport task queue is closed"))
    }

    fn invoke_agent_checkin_callbacks(&self, py: Python<'_>, agent_id: &str) {
        let callbacks = lock_mutex(&self.agent_checkin_callbacks).clone();
        if callbacks.is_empty() {
            return;
        }

        match Py::new(py, PyAgent { agent_id: normalize_agent_id(agent_id) }) {
            Ok(agent) => {
                for callback in callbacks {
                    self.begin_script_execution(&callback.script_name);
                    let bound = callback.callback.bind(py);
                    let call_result = match callback.mode {
                        AgentCheckinCallbackMode::Agent => bound.call1((agent.clone_ref(py),)),
                        AgentCheckinCallbackMode::Identifier => bound.call1((agent_id,)),
                    };
                    if let Err(error) = call_result {
                        let message = format!("agent checkin callback failed: {error}\n");
                        let _ = self.push_output(
                            Some(&callback.script_name),
                            ScriptOutputStream::Stderr,
                            &message,
                        );
                        warn!(agent_id, error = %error, "python agent checkin callback failed");
                    }
                    self.end_script_execution();
                }
            }
            Err(error) => {
                warn!(agent_id, error = %error, "failed to construct python agent proxy");
            }
        }
    }

    fn execute_registered_command(
        &self,
        py: Python<'_>,
        command_name: &str,
        agent_id: &str,
        command_line: &str,
        arguments: &[String],
    ) -> Result<bool, String> {
        let registered = {
            let commands = lock_mutex(&self.commands);
            commands.get(command_name).cloned()
        };
        let Some(registered) = registered else {
            return Ok(false);
        };

        let agent = Py::new(py, PyAgent { agent_id: normalize_agent_id(agent_id) })
            .map_err(|error| error.to_string())?;
        let command_context = Py::new(
            py,
            PyCommandContext {
                command: command_name.to_owned(),
                command_line: command_line.to_owned(),
                arguments: arguments.to_vec(),
                description: registered.description.clone(),
                agent: agent.clone_ref(py),
            },
        )
        .map_err(|error| error.to_string())?;
        self.begin_script_execution(&registered.script_name);
        let bound = registered.callback.bind(py);
        let result = invoke_registered_command_callback(
            self,
            py,
            &registered.script_name,
            bound,
            agent,
            command_context,
            arguments,
        );
        self.end_script_execution();
        result
    }

    fn activate_tab(&self, py: Python<'_>, title: &str) -> Result<(), String> {
        let normalized_title = normalize_tab_title(title).map_err(|error| error.to_string())?;
        let tab = {
            let tabs = lock_mutex(&self.script_tabs);
            tabs.get(&normalized_title).cloned()
        }
        .ok_or_else(|| format!("havocui tab `{normalized_title}` is not registered"))?;
        if !tab.has_callback {
            return Ok(());
        }

        let command_name = normalize_command_name(&format!("__tab__ {normalized_title}"));
        self.execute_registered_command(py, &command_name, "", &normalized_title, &[])?;
        Ok(())
    }
}

#[derive(Debug)]
enum PythonThreadCommand {
    EmitAgentCheckin(String),
    ActivateTab {
        title: String,
        response_tx: SyncSender<Result<(), String>>,
    },
    ExecuteRegisteredCommand {
        command_name: String,
        command_line: String,
        agent_id: String,
        arguments: Vec<String>,
        response_tx: SyncSender<Result<bool, String>>,
    },
    LoadScript(PathBuf, SyncSender<Result<(), String>>),
    ReloadScript(String, SyncSender<Result<(), String>>),
    UnloadScript(String, SyncSender<Result<(), String>>),
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
    #[error("python runtime command failed: {0}")]
    CommandFailed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScriptLoadStatus {
    Loaded,
    Error,
    Unloaded,
}

/// Snapshot of a client script known to the runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScriptDescriptor {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) status: ScriptLoadStatus,
    pub(crate) error: Option<String>,
    pub(crate) registered_commands: Vec<String>,
    pub(crate) registered_command_count: usize,
}

/// Snapshot of a custom `havocui` tab exposed by a client-side Python script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScriptTabDescriptor {
    pub(crate) title: String,
    pub(crate) script_name: String,
    pub(crate) layout: String,
    pub(crate) has_callback: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScriptOutputStream {
    Stdout,
    Stderr,
}

/// Captured stdout/stderr emitted by client-side Python scripts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScriptOutputEntry {
    pub(crate) script_name: String,
    pub(crate) stream: ScriptOutputStream,
    pub(crate) text: String,
}

/// Handle to the embedded client-side Python runtime.
#[derive(Clone, Debug)]
pub(crate) struct PythonRuntime {
    inner: Arc<PythonRuntimeInner>,
}

#[derive(Debug)]
struct PythonRuntimeInner {
    api_state: Arc<PythonApiState>,
    command_tx: Sender<PythonThreadCommand>,
    join_handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for PythonRuntimeInner {
    fn drop(&mut self) {
        let _ = self.command_tx.send(PythonThreadCommand::Shutdown);

        if let Some(handle) = lock_mutex(&self.join_handle).take()
            && handle.join().is_err()
        {
            warn!("python runtime thread panicked during shutdown");
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
            script_tabs: Mutex::new(BTreeMap::new()),
            current_script: Mutex::new(None),
            output_entries: Mutex::new(Vec::new()),
            script_records: Mutex::new(BTreeMap::new()),
            outgoing_tx: Mutex::new(None),
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

    /// Return a snapshot of the scripts known to the runtime.
    pub(crate) fn script_descriptors(&self) -> Vec<ScriptDescriptor> {
        self.inner.api_state.script_descriptors()
    }

    /// Return captured stdout/stderr from Python scripts.
    pub(crate) fn script_output(&self) -> Vec<ScriptOutputEntry> {
        self.inner.api_state.output_entries()
    }

    /// Return the active `havocui` tabs registered by client scripts.
    pub(crate) fn script_tabs(&self) -> Vec<ScriptTabDescriptor> {
        self.inner.api_state.tab_descriptors()
    }

    /// Attach the current client transport sender so Python shims can queue tasks.
    pub(crate) fn set_outgoing_sender(&self, sender: UnboundedSender<OperatorMessage>) {
        self.inner.api_state.set_outgoing_sender(sender);
    }

    /// Run a registered `havocui` tab callback and refresh the tab layout.
    pub(crate) fn activate_tab(&self, title: &str) -> Result<(), PythonRuntimeError> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        self.inner
            .command_tx
            .send(PythonThreadCommand::ActivateTab { title: title.to_owned(), response_tx })
            .map_err(|_| PythonRuntimeError::ThreadUnavailable)?;
        match response_rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(PythonRuntimeError::CommandFailed(error)),
            Err(_) => Err(PythonRuntimeError::ThreadUnavailable),
        }
    }

    /// Load a Python script from the provided path.
    pub(crate) fn load_script(&self, path: PathBuf) -> Result<(), PythonRuntimeError> {
        self.send_script_command(|response| PythonThreadCommand::LoadScript(path, response))
    }

    /// Reload a previously known script by its module name.
    pub(crate) fn reload_script(&self, script_name: &str) -> Result<(), PythonRuntimeError> {
        self.send_script_command(|response| {
            PythonThreadCommand::ReloadScript(script_name.to_owned(), response)
        })
    }

    /// Unload a previously known script by its module name.
    pub(crate) fn unload_script(&self, script_name: &str) -> Result<(), PythonRuntimeError> {
        self.send_script_command(|response| {
            PythonThreadCommand::UnloadScript(script_name.to_owned(), response)
        })
    }

    /// Queue an agent check-in callback dispatch on the Python thread.
    pub(crate) fn emit_agent_checkin(&self, agent_id: String) -> Result<(), PythonRuntimeError> {
        self.inner
            .command_tx
            .send(PythonThreadCommand::EmitAgentCheckin(agent_id))
            .map_err(|_| PythonRuntimeError::ThreadUnavailable)
    }

    /// Execute a script-registered command if the console input matches one.
    pub(crate) fn execute_registered_command(
        &self,
        agent_id: &str,
        input: &str,
    ) -> Result<bool, PythonRuntimeError> {
        let Some(matched_command) = self.inner.api_state.match_registered_command(input) else {
            return Ok(false);
        };
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        self.inner
            .command_tx
            .send(PythonThreadCommand::ExecuteRegisteredCommand {
                command_name: matched_command.name,
                command_line: matched_command.command_line,
                agent_id: agent_id.to_owned(),
                arguments: matched_command.arguments,
                response_tx,
            })
            .map_err(|_| PythonRuntimeError::ThreadUnavailable)?;
        match response_rx.recv() {
            Ok(Ok(executed)) => Ok(executed),
            Ok(Err(error)) => Err(PythonRuntimeError::CommandFailed(error)),
            Err(_) => Err(PythonRuntimeError::ThreadUnavailable),
        }
    }

    fn send_script_command<F>(&self, build: F) -> Result<(), PythonRuntimeError>
    where
        F: FnOnce(SyncSender<Result<(), String>>) -> PythonThreadCommand,
    {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        self.inner
            .command_tx
            .send(build(response_tx))
            .map_err(|_| PythonRuntimeError::ThreadUnavailable)?;
        match response_rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(PythonRuntimeError::CommandFailed(error)),
            Err(_) => Err(PythonRuntimeError::ThreadUnavailable),
        }
    }

    #[cfg(test)]
    fn command_names(&self) -> Vec<String> {
        self.inner.api_state.command_names()
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
        install_output_capture(py)?;
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
            PythonThreadCommand::ActivateTab { title, response_tx } => {
                let result = Python::with_gil(|py| api_state.activate_tab(py, &title));
                let _ = response_tx.send(result);
            }
            PythonThreadCommand::ExecuteRegisteredCommand {
                command_name,
                command_line,
                agent_id,
                arguments,
                response_tx,
            } => {
                let result = Python::with_gil(|py| {
                    api_state.execute_registered_command(
                        py,
                        &command_name,
                        &agent_id,
                        &command_line,
                        &arguments,
                    )
                });
                let _ = response_tx.send(result);
            }
            PythonThreadCommand::LoadScript(path, response_tx) => {
                let result =
                    Python::with_gil(|py| load_script_at_path(py, api_state.as_ref(), &path));
                let _ = response_tx.send(result);
            }
            PythonThreadCommand::ReloadScript(script_name, response_tx) => {
                let result = Python::with_gil(|py| {
                    reload_script_by_name(py, api_state.as_ref(), &script_name)
                });
                let _ = response_tx.send(result);
            }
            PythonThreadCommand::UnloadScript(script_name, response_tx) => {
                let result = Python::with_gil(|py| {
                    unload_script_by_name(py, api_state.as_ref(), &script_name)
                });
                let _ = response_tx.send(result);
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
    modules.set_item("havoc", modules.get_item("red_cell")?)?;
    let havocui = PyModule::new(py, "havocui")?;
    populate_havocui_module(&havocui)?;
    modules.set_item("havocui", havocui)?;
    Ok(())
}

fn install_output_capture(py: Python<'_>) -> PyResult<()> {
    let sys = py.import("sys")?;
    sys.setattr("stdout", Py::new(py, PyOutputSink { stream: ScriptOutputStream::Stdout })?)?;
    sys.setattr("stderr", Py::new(py, PyOutputSink { stream: ScriptOutputStream::Stderr })?)?;
    Ok(())
}

fn load_scripts(py: Python<'_>, api_state: &PythonApiState, scripts_dir: &Path) {
    let mut entries = match std::fs::read_dir(scripts_dir) {
        Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
        Err(error) => {
            warn!(
                path = %scripts_dir.display(),
                error = %error,
                "failed to enumerate client python scripts"
            );
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

        if let Err(error) = load_script_at_path(py, api_state, &path) {
            warn!(script = %path.display(), error = %error, "failed to load client python script");
        }
    }
}

fn load_script_at_path(
    py: Python<'_>,
    api_state: &PythonApiState,
    path: &Path,
) -> Result<(), String> {
    let script_name = script_name_from_path(path)?;
    api_state.ensure_script_record(&script_name, path.to_path_buf());
    unload_script_bindings(py, api_state, &script_name)?;

    api_state.begin_script_execution(&script_name);
    let result = load_script(py, path, &script_name).map_err(|error| error.to_string());
    api_state.end_script_execution();

    match result {
        Ok(()) => {
            api_state.mark_script_loaded(&script_name);
            Ok(())
        }
        Err(error) => {
            api_state.mark_script_error(&script_name, error.clone());
            Err(error)
        }
    }
}

fn reload_script_by_name(
    py: Python<'_>,
    api_state: &PythonApiState,
    script_name: &str,
) -> Result<(), String> {
    let path = lock_mutex(&api_state.script_records)
        .get(script_name)
        .map(|record| record.path.clone())
        .ok_or_else(|| format!("script `{script_name}` is not known to the runtime"))?;
    load_script_at_path(py, api_state, &path)
}

fn unload_script_by_name(
    py: Python<'_>,
    api_state: &PythonApiState,
    script_name: &str,
) -> Result<(), String> {
    if !lock_mutex(&api_state.script_records).contains_key(script_name) {
        return Err(format!("script `{script_name}` is not known to the runtime"));
    }
    unload_script_bindings(py, api_state, script_name)?;
    api_state.mark_script_unloaded(script_name);
    Ok(())
}

fn unload_script_bindings(
    py: Python<'_>,
    api_state: &PythonApiState,
    script_name: &str,
) -> Result<(), String> {
    api_state.clear_script_bindings(script_name);
    let sys = py.import("sys").map_err(|error| error.to_string())?;
    let modules = sys.getattr("modules").map_err(|error| error.to_string())?;
    if modules.contains(script_name).map_err(|error| error.to_string())? {
        modules.del_item(script_name).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn script_name_from_path(path: &Path) -> Result<String, String> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("py") {
        return Err(format!("script path must end with .py: {}", path.display()));
    }
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("unable to derive script name from {}", path.display()))
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
    module.add_function(wrap_pyfunction!(register_callback, module)?)?;
    module.add_function(wrap_pyfunction!(on_agent_checkin, module)?)?;
    module.add_function(wrap_pyfunction!(agent, module)?)?;
    module.add_function(wrap_pyfunction!(agents, module)?)?;
    module.add_function(wrap_pyfunction!(listener, module)?)?;
    module.add_function(wrap_pyfunction!(listeners, module)?)?;
    module.add_class::<PyAgent>()?;
    module.add_class::<PyCommandContext>()?;
    module.add_class::<PyEventRegistrar>()?;
    module.add_class::<PyListener>()?;
    module.add("RegisterCommand", module.getattr("register_command")?)?;
    module.add("RegisterCallback", module.getattr("register_callback")?)?;
    module.add("GetAgent", module.getattr("agent")?)?;
    module.add("GetAgents", module.getattr("agents")?)?;
    module.add("GetListener", module.getattr("listener")?)?;
    module.add("GetListeners", module.getattr("listeners")?)?;
    module.add("Demon", module.getattr("Agent")?)?;
    module.add("Event", module.getattr("Event")?)?;
    Ok(())
}

fn populate_havocui_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(messagebox, module)?)?;
    module.add_function(wrap_pyfunction!(errormessage, module)?)?;
    module.add_function(wrap_pyfunction!(infomessage, module)?)?;
    module.add_function(wrap_pyfunction!(successmessage, module)?)?;
    module.add_function(wrap_pyfunction!(createtab, module)?)?;
    module.add_function(wrap_pyfunction!(settablayout, module)?)?;
    module.add_class::<PyLogger>()?;
    module.add("MessageBox", module.getattr("messagebox")?)?;
    module.add("ErrorMessage", module.getattr("errormessage")?)?;
    module.add("InfoMessage", module.getattr("infomessage")?)?;
    module.add("SuccessMessage", module.getattr("successmessage")?)?;
    module.add("CreateTab", module.getattr("createtab")?)?;
    module.add("SetTabLayout", module.getattr("settablayout")?)?;
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

fn normalize_command_name(name: &str) -> String {
    name.split_whitespace().map(|part| part.to_ascii_lowercase()).collect::<Vec<_>>().join(" ")
}

fn normalize_listener_name(name: &str) -> String {
    name.trim().to_owned()
}

fn normalize_tab_title(title: &str) -> PyResult<String> {
    let normalized = title.trim().to_owned();
    if normalized.is_empty() {
        return Err(PyValueError::new_err("tab title cannot be empty"));
    }
    Ok(normalized)
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

fn listener_summary_to_json(listener: &ListenerSummary) -> Value {
    json!({
        "name": listener.name,
        "protocol": listener.protocol,
        "status": listener.status,
    })
}

fn write_callback_result(
    api_state: &PythonApiState,
    script_name: &str,
    value: &Bound<'_, PyAny>,
) -> Result<(), String> {
    if value.is_none() {
        return Ok(());
    }

    let mut rendered = value
        .str()
        .and_then(|text| text.to_str().map(str::to_owned))
        .map_err(|error| error.to_string())?;
    if rendered.trim().is_empty() {
        return Ok(());
    }
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    let _ = api_state.push_output(Some(script_name), ScriptOutputStream::Stdout, &rendered);
    Ok(())
}

fn invoke_registered_command_callback(
    api_state: &PythonApiState,
    py: Python<'_>,
    script_name: &str,
    callback: &Bound<'_, PyAny>,
    agent: Py<PyAgent>,
    context: Py<PyCommandContext>,
    arguments: &[String],
) -> Result<bool, String> {
    let attempts = [
        PyCallShape::AgentArgsContext,
        PyCallShape::AgentArgs,
        PyCallShape::ContextOnly,
        PyCallShape::AgentOnly,
        PyCallShape::NoArgs,
    ];

    for shape in attempts {
        if !callback_accepts_shape(py, callback, shape)? {
            continue;
        }
        let result = match shape {
            PyCallShape::AgentArgsContext => {
                callback.call1((agent.clone_ref(py), arguments.to_vec(), context.clone_ref(py)))
            }
            PyCallShape::AgentArgs => callback.call1((agent.clone_ref(py), arguments.to_vec())),
            PyCallShape::ContextOnly => callback.call1((context.clone_ref(py),)),
            PyCallShape::AgentOnly => callback.call1((agent.clone_ref(py),)),
            PyCallShape::NoArgs => callback.call0(),
        };
        let value = result.map_err(|error| error.to_string())?;
        write_callback_result(api_state, script_name, &value)?;
        return Ok(true);
    }

    let _ = agent;
    Err("registered command callback does not accept any supported signature".to_owned())
}

#[derive(Clone, Copy)]
enum PyCallShape {
    AgentArgsContext,
    AgentArgs,
    ContextOnly,
    AgentOnly,
    NoArgs,
}

fn callback_accepts_shape(
    py: Python<'_>,
    callback: &Bound<'_, PyAny>,
    shape: PyCallShape,
) -> Result<bool, String> {
    let inspect = py.import("inspect").map_err(|error| error.to_string())?;
    let signature = match inspect.call_method1("signature", (callback,)) {
        Ok(signature) => signature,
        Err(_) => return Ok(true),
    };

    let args = match shape {
        PyCallShape::AgentArgsContext => 3_usize,
        PyCallShape::AgentArgs => 2,
        PyCallShape::ContextOnly | PyCallShape::AgentOnly => 1,
        PyCallShape::NoArgs => 0,
    };
    let probe =
        PyTuple::new(py, (0..args).map(|_| py.None())).map_err(|error| error.to_string())?;
    Ok(signature.call_method1("bind_partial", probe).is_ok())
}

#[pyclass(name = "Agent")]
#[derive(Clone, Debug)]
struct PyAgent {
    agent_id: String,
}

#[pymethods]
impl PyAgent {
    #[classattr]
    const CONSOLE_INFO: u32 = 1;

    #[classattr]
    const CONSOLE_ERROR: u32 = 2;

    #[classattr]
    const CONSOLE_TASK: u32 = 3;

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

    #[pyo3(name = "ConsoleWrite", signature = (*args))]
    fn console_write(&self, args: &Bound<'_, PyTuple>) -> PyResult<Option<String>> {
        let api_state = active_api_state()?;
        match args.len() {
            1 => {
                let text = args.get_item(0)?.extract::<String>()?;
                api_state.push_runtime_note(None, &format!("[INFO] {}: {text}", self.agent_id));
                Ok(None)
            }
            2 => {
                if let Ok(kind) = args.get_item(0)?.extract::<u32>() {
                    let text = args.get_item(1)?.extract::<String>()?;
                    return match kind {
                        Self::CONSOLE_INFO => {
                            api_state.push_runtime_note(
                                None,
                                &format!("[INFO] {}: {text}", self.agent_id),
                            );
                            Ok(None)
                        }
                        Self::CONSOLE_ERROR => {
                            let rendered = format!("[ERROR] {}: {text}\n", self.agent_id);
                            let _ = api_state.push_output(
                                None,
                                ScriptOutputStream::Stderr,
                                &rendered,
                            )?;
                            Ok(None)
                        }
                        Self::CONSOLE_TASK => Ok(Some(next_task_id_string())),
                        _ => Err(PyValueError::new_err(format!(
                            "unsupported ConsoleWrite kind `{kind}`"
                        ))),
                    };
                }

                let text = args.get_item(0)?.extract::<String>()?;
                let level = args.get_item(1)?.extract::<String>()?;
                api_state.push_runtime_note(
                    None,
                    &format!("[{}] {}: {text}", level.to_ascii_uppercase(), self.agent_id),
                );
                Ok(None)
            }
            _ => Err(PyValueError::new_err(
                "ConsoleWrite expects either (text), (text, level), or (kind, text)",
            )),
        }
    }

    #[pyo3(name = "Command", signature = (*args))]
    fn command(&self, args: &Bound<'_, PyTuple>) -> PyResult<()> {
        let api_state = active_api_state()?;
        match args.len() {
            2 => {
                let task_id = args.get_item(0)?.extract::<String>()?;
                let command_line = args.get_item(1)?.extract::<String>()?;
                let operator = current_operator_username(&api_state.app_state);
                let message =
                    build_console_task_message(&self.agent_id, &task_id, &command_line, &operator)
                        .map_err(PyValueError::new_err)?;
                api_state.queue_task_message(message)
            }
            3 => {
                let task_id = args.get_item(0)?.extract::<String>()?;
                let command = args.get_item(1)?.extract::<String>()?;
                let command_arg = args.get_item(2)?.extract::<Vec<u8>>()?;
                let operator = current_operator_username(&api_state.app_state);
                let message = build_agent_command_message(
                    &self.agent_id,
                    &task_id,
                    &command,
                    &command_arg,
                    &operator,
                );
                api_state.queue_task_message(message)
            }
            _ => Err(PyValueError::new_err(
                "Command expects either (task_id, command_line) or (task_id, name, bytes)",
            )),
        }
    }
}

#[pyclass(name = "CommandContext")]
#[derive(Debug)]
struct PyCommandContext {
    command: String,
    command_line: String,
    arguments: Vec<String>,
    description: Option<String>,
    agent: Py<PyAgent>,
}

#[pymethods]
impl PyCommandContext {
    #[getter]
    fn command(&self) -> String {
        self.command.clone()
    }

    #[getter]
    fn command_line(&self) -> String {
        self.command_line.clone()
    }

    #[getter]
    fn args(&self) -> Vec<String> {
        self.arguments.clone()
    }

    #[getter]
    fn description(&self) -> Option<String> {
        self.description.clone()
    }

    #[getter]
    fn agent(&self, py: Python<'_>) -> Py<PyAgent> {
        self.agent.clone_ref(py)
    }
}

#[pyclass(name = "Event")]
#[derive(Clone, Debug)]
struct PyEventRegistrar {
    namespace: String,
}

#[pymethods]
impl PyEventRegistrar {
    #[new]
    fn new(namespace: String) -> Self {
        Self { namespace }
    }

    #[pyo3(name = "OnNewSession")]
    fn on_new_session(&self, callback: Bound<'_, PyAny>) -> PyResult<()> {
        ensure_callable(&callback)?;
        let _ = &self.namespace;
        active_api_state()?.register_agent_checkin_callback(
            callback.unbind(),
            AgentCheckinCallbackMode::Identifier,
        )
    }

    #[pyo3(name = "OnAgentCheckin")]
    fn on_agent_checkin(&self, callback: Bound<'_, PyAny>) -> PyResult<()> {
        self.on_new_session(callback)
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
    fn new(name: String) -> PyResult<Self> {
        let normalized = normalize_listener_name(&name);
        if normalized.is_empty() {
            return Err(PyValueError::new_err("listener name cannot be empty"));
        }
        Ok(Self { name: normalized })
    }

    #[getter]
    fn name(&self) -> String {
        self.name.clone()
    }

    #[getter]
    fn info(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let api_state = active_api_state()?;
        match api_state.listener_snapshot(&self.name) {
            Some(listener) => json_value_to_object(py, &listener_summary_to_json(&listener)),
            None => Ok(py.None().into_bound(py).unbind()),
        }
    }
}

#[pyclass]
struct PyOutputSink {
    stream: ScriptOutputStream,
}

#[pyclass(name = "Logger")]
struct PyLogger {
    name: Option<String>,
}

#[pymethods]
impl PyLogger {
    #[new]
    #[pyo3(signature = (name=None))]
    fn new(name: Option<String>) -> Self {
        Self { name }
    }

    fn write(&self, text: &str) -> PyResult<usize> {
        let api_state = active_api_state()?;
        let prefix = self.name.as_deref().unwrap_or("havocui");
        api_state.push_output(None, ScriptOutputStream::Stdout, &format!("[{prefix}] {text}"))
    }

    fn info(&self, text: &str) -> PyResult<usize> {
        self.write(text)
    }

    fn error(&self, text: &str) -> PyResult<usize> {
        let api_state = active_api_state()?;
        let prefix = self.name.as_deref().unwrap_or("havocui");
        api_state.push_output(None, ScriptOutputStream::Stderr, &format!("[{prefix}] {text}"))
    }
}

#[pymethods]
impl PyOutputSink {
    fn write(&self, text: &str) -> PyResult<usize> {
        active_api_state()?.push_output(None, self.stream, text)
    }

    fn flush(&self) {}
}

struct RegisterCommandRequest {
    name: String,
    description: Option<String>,
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
        let description = extract_string_argument(kwargs, "description", positional.get(3))?;
        let name = if module.trim().is_empty() { command } else { format!("{module} {command}") };
        return Ok(RegisterCommandRequest { name, description, callback: callback.unbind() });
    }

    let callback = if let Some(value) = optional_kwarg(kwargs, "callback")? {
        value
    } else {
        positional
            .get(1)
            .cloned()
            .ok_or_else(|| PyValueError::new_err("register_command requires a callback"))?
    };
    ensure_callable(&callback)?;
    let name = extract_string_argument(kwargs, "name", positional.first())?
        .ok_or_else(|| PyValueError::new_err("register_command requires a command name"))?;
    let description = extract_string_argument(kwargs, "description", positional.get(2))?;
    Ok(RegisterCommandRequest { name, description, callback: callback.unbind() })
}

#[pyfunction]
#[pyo3(signature = (*args, **kwargs))]
fn register_command(args: &Bound<'_, PyTuple>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<()> {
    let request = parse_register_command_request(args, kwargs)?;
    let api_state = active_api_state()?;
    api_state.register_command(request.name, request.description, request.callback)
}

#[pyfunction]
fn register_callback(event_type: String, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let mode = match event_type.trim().to_ascii_lowercase().as_str() {
        "agent_checkin" | "new_session" => AgentCheckinCallbackMode::Identifier,
        _ => {
            return Err(PyValueError::new_err(format!(
                "unsupported client callback `{event_type}`"
            )));
        }
    };
    active_api_state()?.register_agent_checkin_callback(callback.unbind(), mode)
}

#[pyfunction]
fn on_agent_checkin(callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let api_state = active_api_state()?;
    api_state.register_agent_checkin_callback(callback.unbind(), AgentCheckinCallbackMode::Agent)
}

#[pyfunction]
fn agent(py: Python<'_>, agent_id: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    Py::new(py, PyAgent::new(agent_id)?).map(|agent| agent.into_any())
}

#[pyfunction]
fn agents(py: Python<'_>) -> PyResult<Vec<Py<PyAgent>>> {
    let api_state = active_api_state()?;
    api_state
        .agent_snapshots()
        .into_iter()
        .map(|agent| Py::new(py, PyAgent { agent_id: agent.name_id }))
        .collect()
}

#[pyfunction]
fn listener(py: Python<'_>, name: String) -> PyResult<Py<PyAny>> {
    Py::new(py, PyListener::new(name)?).map(|listener| listener.into_any())
}

#[pyfunction]
fn listeners(py: Python<'_>) -> PyResult<Vec<Py<PyListener>>> {
    let api_state = active_api_state()?;
    api_state
        .listener_snapshots()
        .into_iter()
        .map(|listener| Py::new(py, PyListener { name: listener.name }))
        .collect()
}

#[pyfunction]
#[pyo3(signature = (text, title=None))]
fn messagebox(text: String, title: Option<String>) -> PyResult<()> {
    let api_state = active_api_state()?;
    let label = title.unwrap_or_else(|| "Message".to_owned());
    api_state.push_runtime_note(None, &format!("[havocui:{label}] {text}"));
    Ok(())
}

#[pyfunction]
fn errormessage(text: String) -> PyResult<()> {
    let api_state = active_api_state()?;
    let rendered = format!("[havocui:error] {text}\n");
    let _ = api_state.push_output(None, ScriptOutputStream::Stderr, &rendered)?;
    Ok(())
}

#[pyfunction]
fn infomessage(text: String) -> PyResult<()> {
    messagebox(text, Some("Info".to_owned()))
}

#[pyfunction]
fn successmessage(text: String) -> PyResult<()> {
    messagebox(text, Some("Success".to_owned()))
}

#[pyfunction]
#[pyo3(signature = (title, callback=None))]
fn createtab(title: String, callback: Option<Bound<'_, PyAny>>) -> PyResult<()> {
    let callback = if let Some(callback) = callback {
        ensure_callable(&callback)?;
        Some(callback.unbind())
    } else {
        None
    };
    let api_state = active_api_state()?;
    api_state.register_tab(title, callback)
}

#[pyfunction]
fn settablayout(title: String, layout: String) -> PyResult<()> {
    let api_state = active_api_state()?;
    api_state.set_tab_layout(&title, layout)
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

fn current_operator_username(app_state: &SharedAppState) -> String {
    let state = lock_app_state(app_state);
    state.operator_info.as_ref().map(|operator| operator.username.clone()).unwrap_or_default()
}

fn build_agent_task(operator: &str, info: AgentTaskInfo) -> OperatorMessage {
    OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info,
    })
}

fn next_task_id_string() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};

    static TASK_COUNTER: AtomicU32 = AtomicU32::new(1);
    format!("{:08X}", TASK_COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn build_console_task_message(
    agent_id: &str,
    task_id: &str,
    input: &str,
    operator: &str,
) -> Result<OperatorMessage, String> {
    let trimmed = input.trim();
    let mut parts = trimmed.split_whitespace();
    let Some(command) = parts.next() else {
        return Err("Command input is empty.".to_owned());
    };
    let command = command.to_ascii_lowercase();

    let info = match command.as_str() {
        "checkin" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: task_id.to_owned(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("checkin".to_owned()),
            ..AgentTaskInfo::default()
        },
        "kill" | "exit" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: task_id.to_owned(),
            command_id: u32::from(DemonCommand::CommandExit).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("kill".to_owned()),
            arguments: parts.next().map(ToOwned::to_owned),
            ..AgentTaskInfo::default()
        },
        "ps" | "proclist" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: task_id.to_owned(),
            command_id: u32::from(DemonCommand::CommandProcList).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("ps".to_owned()),
            ..AgentTaskInfo::default()
        },
        "screenshot" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: task_id.to_owned(),
            command_id: u32::from(DemonCommand::CommandScreenshot).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("screenshot".to_owned()),
            ..AgentTaskInfo::default()
        },
        "pwd" => filesystem_task(agent_id, task_id, trimmed, "pwd", None),
        "cd" => filesystem_task(agent_id, task_id, trimmed, "cd", Some(rest_after_word(trimmed)?)),
        "mkdir" => {
            filesystem_task(agent_id, task_id, trimmed, "mkdir", Some(rest_after_word(trimmed)?))
        }
        "rm" | "del" | "remove" => {
            filesystem_task(agent_id, task_id, trimmed, "remove", Some(rest_after_word(trimmed)?))
        }
        "download" => filesystem_transfer_task(
            agent_id,
            task_id,
            trimmed,
            "download",
            &rest_after_word(trimmed)?,
        ),
        "cat" | "type" => {
            filesystem_transfer_task(agent_id, task_id, trimmed, "cat", &rest_after_word(trimmed)?)
        }
        "proc" => process_task(agent_id, task_id, trimmed)?,
        _ => return Err(format!("Unsupported console command `{command}`.")),
    };

    Ok(build_agent_task(operator, info))
}

fn build_agent_command_message(
    agent_id: &str,
    task_id: &str,
    command: &str,
    command_arg: &[u8],
    operator: &str,
) -> OperatorMessage {
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: task_id.to_owned(),
            command_id: "0".to_owned(),
            command_line: String::new(),
            command: Some(command.to_owned()),
            arguments: Some(base64::engine::general_purpose::STANDARD.encode(command_arg)),
            extra: BTreeMap::from([(
                "CommandArg".to_owned(),
                Value::String(base64::engine::general_purpose::STANDARD.encode(command_arg)),
            )]),
            ..AgentTaskInfo::default()
        },
    )
}

fn filesystem_task(
    agent_id: &str,
    task_id: &str,
    command_line: &str,
    sub_command: &str,
    arguments: Option<String>,
) -> AgentTaskInfo {
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: task_id.to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command_line: command_line.to_owned(),
        command: Some("fs".to_owned()),
        sub_command: Some(sub_command.to_owned()),
        arguments,
        ..AgentTaskInfo::default()
    }
}

fn filesystem_transfer_task(
    agent_id: &str,
    task_id: &str,
    command_line: &str,
    sub_command: &str,
    path: &str,
) -> AgentTaskInfo {
    let encoded = Some(base64::engine::general_purpose::STANDARD.encode(path.as_bytes()));
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: task_id.to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command_line: command_line.to_owned(),
        command: Some("fs".to_owned()),
        sub_command: Some(sub_command.to_owned()),
        arguments: encoded,
        ..AgentTaskInfo::default()
    }
}

fn process_task(
    agent_id: &str,
    task_id: &str,
    command_line: &str,
) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub_command = parts.next().ok_or_else(|| "Usage: proc kill <pid>".to_owned())?;
    match sub_command.to_ascii_lowercase().as_str() {
        "kill" => {
            let pid = parts.next().ok_or_else(|| "Usage: proc kill <pid>".to_owned())?;
            if parts.next().is_some() {
                return Err("Usage: proc kill <pid>".to_owned());
            }
            let pid = pid.parse::<u32>().map_err(|_| format!("Invalid PID `{pid}`."))?;
            Ok(AgentTaskInfo {
                demon_id: agent_id.to_owned(),
                task_id: task_id.to_owned(),
                command_id: u32::from(DemonCommand::CommandProc).to_string(),
                command_line: format!("proc kill {pid}"),
                command: Some("proc".to_owned()),
                sub_command: Some("kill".to_owned()),
                arguments: Some(pid.to_string()),
                extra: BTreeMap::from([("Args".to_owned(), Value::String(pid.to_string()))]),
                ..AgentTaskInfo::default()
            })
        }
        _ => Err("Usage: proc kill <pid>".to_owned()),
    }
}

fn rest_after_word(input: &str) -> Result<String, String> {
    let mut parts = input.trim().splitn(2, char::is_whitespace);
    let _ = parts.next();
    let rest = parts.next().map(str::trim).unwrap_or_default();
    if rest.is_empty() {
        Err("This command requires an argument.".to_owned())
    } else {
        Ok(rest.to_owned())
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

    fn sample_listener(name: &str) -> ListenerSummary {
        ListenerSummary {
            name: name.to_owned(),
            protocol: "https".to_owned(),
            status: "Online".to_owned(),
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

    fn wait_for_output(runtime: &PythonRuntime, needle: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if runtime.script_output().iter().any(|entry| entry.text.contains(needle)) {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        false
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
        assert_eq!(
            runtime.script_descriptors(),
            vec![ScriptDescriptor {
                name: "sample".to_owned(),
                path: temp_dir.path().join("sample.py"),
                status: ScriptLoadStatus::Loaded,
                error: None,
                registered_commands: vec!["demo".to_owned()],
                registered_command_count: 1,
            }]
        );
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
        assert_eq!(runtime.script_descriptors().len(), 2);
        assert!(
            runtime
                .script_descriptors()
                .iter()
                .find(|script| script.name == "bad")
                .and_then(|script| script.error.as_ref())
                .is_some_and(|error| error.contains("boom"))
        );
    }

    #[test]
    fn runtime_can_reload_and_unload_scripts() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let script_path = temp_dir.path().join("sample.py");
        write_script(
            &script_path,
            "import red_cell\nred_cell.register_command('demo', lambda: None)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));
        assert_eq!(runtime.command_names(), vec!["demo".to_owned()]);

        write_script(
            &script_path,
            "import red_cell\nred_cell.register_command('updated', lambda: None)\n",
        );
        runtime
            .reload_script("sample")
            .unwrap_or_else(|error| panic!("reload should succeed: {error}"));
        assert_eq!(runtime.command_names(), vec!["updated".to_owned()]);

        runtime
            .unload_script("sample")
            .unwrap_or_else(|error| panic!("unload should succeed: {error}"));
        assert!(runtime.command_names().is_empty());
        assert!(
            runtime
                .script_descriptors()
                .iter()
                .find(|script| script.name == "sample")
                .is_some_and(|script| script.status == ScriptLoadStatus::Unloaded)
        );
    }

    #[test]
    fn runtime_captures_script_output() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("chatty.py"),
            "import sys\nprint('hello from stdout')\nprint('hello from stderr', file=sys.stderr)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert!(wait_for_output(&runtime, "hello from stdout"));
        assert!(wait_for_output(&runtime, "hello from stderr"));
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
    fn runtime_executes_registered_commands() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("command.txt");
        let script = format!(
            "import pathlib\nimport red_cell\n\
def demo(agent, args):\n    pathlib.Path({output:?}).write_text(agent.id + ':' + ','.join(args))\n    return 'handled ' + agent.info['hostname']\n\
red_cell.register_command('demo', demo)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("demo.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let executed = runtime
            .execute_registered_command("00ABCDEF", "demo alpha bravo")
            .unwrap_or_else(|error| panic!("registered command should run: {error}"));

        assert!(executed);
        assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("00ABCDEF:alpha,bravo"));
        assert!(wait_for_output(&runtime, "handled wkstn-01"));
    }

    #[test]
    fn runtime_accepts_havoc_style_command_registration_and_context_callbacks() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("context.txt");
        let script = format!(
            "import pathlib\nimport havoc\n\
def run(context):\n    pathlib.Path({output:?}).write_text(context.command_line + '|' + context.agent.id)\n    return context.description or ''\n\
havoc.RegisterCommand(function=run, module='situational_awareness', command='whoami', description='demo command')\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("compat.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert_eq!(runtime.command_names(), vec!["situational_awareness whoami".to_owned()]);

        let executed = runtime
            .execute_registered_command("00ABCDEF", "situational_awareness whoami /all")
            .unwrap_or_else(|error| panic!("havoc-style command should run: {error}"));

        assert!(executed);
        assert_eq!(
            wait_for_file_contents(&output_path).as_deref(),
            Some("situational_awareness whoami /all|00ABCDEF")
        );
        assert!(wait_for_output(&runtime, "demo command"));
    }

    #[test]
    fn runtime_preserves_original_argument_casing_for_registered_commands() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("preserved_case.txt");
        let script = format!(
            "import json\nimport pathlib\nimport red_cell\n\
def demo(context):\n    payload = {{'command_line': context.command_line, 'args': context.args}}\n    pathlib.Path({output:?}).write_text(json.dumps(payload))\n\
red_cell.register_command('demo', demo)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("preserve.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let executed = runtime
            .execute_registered_command("00ABCDEF", "DeMo C:\\Temp\\Foo.txt MiXeDCaseToken")
            .unwrap_or_else(|error| panic!("registered command should run: {error}"));

        assert!(executed);
        assert_eq!(
            wait_for_file_contents(&output_path).as_deref(),
            Some(
                "{\"command_line\": \"DeMo C:\\\\Temp\\\\Foo.txt MiXeDCaseToken\", \
\"args\": [\"C:\\\\Temp\\\\Foo.txt\", \"MiXeDCaseToken\"]}"
            )
        );
    }

    #[test]
    fn havoc_event_and_havocui_modules_are_compatible() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("event.txt");
        let script = format!(
            "import pathlib\nimport havoc\nimport havocui\n\
event = havoc.Event('events')\n\
def on_new_session(identifier):\n    pathlib.Path({output:?}).write_text(identifier)\n    havocui.MessageBox('new session for ' + identifier)\n\
event.OnNewSession(on_new_session)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("havoc_ui.py"), &script);

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
            .unwrap_or_else(|error| panic!("havoc event dispatch should succeed: {error}"));

        assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("00ABCDEF"));
        assert!(wait_for_output(&runtime, "new session for 00ABCDEF"));
    }

    #[test]
    fn havocui_tabs_are_registered_and_can_refresh_layouts() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let script = "import havocui\n\
def render():\n    havocui.SetTabLayout('Status', 'operator layout')\n\
havocui.CreateTab('Status', render)\n";
        write_script(&temp_dir.path().join("tabbed.py"), script);
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert_eq!(
            runtime.script_tabs(),
            vec![ScriptTabDescriptor {
                title: "Status".to_owned(),
                script_name: "tabbed".to_owned(),
                layout: String::new(),
                has_callback: true,
            }]
        );

        runtime
            .activate_tab("Status")
            .unwrap_or_else(|error| panic!("tab activation should succeed: {error}"));

        assert_eq!(
            runtime.script_tabs(),
            vec![ScriptTabDescriptor {
                title: "Status".to_owned(),
                script_name: "tabbed".to_owned(),
                layout: "operator layout".to_owned(),
                has_callback: true,
            }]
        );
    }

    #[test]
    fn demon_command_queues_agent_task_messages() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let script = "import havoc\n\
def queue(agent, args):\n    demon = havoc.Demon(agent.id)\n    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, 'queued pwd')\n    demon.Command(task_id, 'pwd')\n\
havoc.RegisterCommand(function=queue, module='ops', command='pwd', description='queue pwd')\n";
        write_script(&temp_dir.path().join("queue_task.py"), script);
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
            state.operator_info = Some(red_cell_common::OperatorInfo {
                username: "operator".to_owned(),
                password_hash: None,
                role: None,
                online: true,
                last_seen: None,
            });
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));
        let (outgoing_tx, mut outgoing_rx) = tokio::sync::mpsc::unbounded_channel();
        runtime.set_outgoing_sender(outgoing_tx);

        let executed = runtime
            .execute_registered_command("00ABCDEF", "ops pwd")
            .unwrap_or_else(|error| panic!("registered command should run: {error}"));
        assert!(executed);

        let Some(OperatorMessage::AgentTask(message)) = outgoing_rx.blocking_recv() else {
            panic!("expected queued agent task");
        };
        assert_eq!(message.head.user, "operator");
        assert_eq!(message.info.demon_id, "00ABCDEF");
        assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(message.info.sub_command.as_deref(), Some("pwd"));
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
            agent.getattr("info")?.get_item("hostname")?.extract::<String>()
        })
        .unwrap_or_else(|error| panic!("python agent lookup should succeed: {error}"));

        assert_eq!(result, "wkstn-01");
    }

    #[test]
    fn havoc_alias_exposes_agent_and_listener_accessors() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(&temp_dir.path().join("noop.py"), "import red_cell\n");
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
            state.listeners.push(sample_listener("https"));
        }
        let _runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let result = Python::with_gil(|py| -> PyResult<(String, usize, String, usize)> {
            install_api_module(py)?;
            let module = py.import("havoc")?;
            let agent_name = module
                .call_method0("agents")?
                .get_item(0)?
                .getattr("info")?
                .get_item("hostname")?
                .extract::<String>()?;
            let agent_count = module.call_method0("agents")?.len()?;
            let listener_status = module
                .call_method1("listener", ("https",))?
                .getattr("info")?
                .get_item("status")?
                .extract::<String>()?;
            let listener_count = module.call_method0("listeners")?.len()?;
            Ok((agent_name, agent_count, listener_status, listener_count))
        })
        .unwrap_or_else(|error| panic!("havoc alias lookup should succeed: {error}"));

        assert_eq!(result, ("wkstn-01".to_owned(), 1, "Online".to_owned(), 1));
    }
}
