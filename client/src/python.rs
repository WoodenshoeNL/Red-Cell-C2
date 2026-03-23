//! Embedded Python runtime for client-side automation.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::Engine;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedSender;
use tracing::warn;

use crate::transport::{AgentSummary, AppState, ListenerSummary, LootItem, SharedAppState};

static ACTIVE_RUNTIME: OnceLock<Mutex<Option<Arc<PythonApiState>>>> = OnceLock::new();
const MAX_SCRIPT_OUTPUT_ENTRIES: usize = 512;
const MAX_COMMAND_HISTORY: usize = 100;

fn active_runtime_slot() -> &'static Mutex<Option<Arc<PythonApiState>>> {
    ACTIVE_RUNTIME.get_or_init(|| Mutex::new(None))
}

#[derive(Clone, Debug)]
struct RegisteredCommand {
    script_name: String,
    description: Option<String>,
    options: Vec<CommandOption>,
    callback: Arc<Py<PyAny>>,
}

#[derive(Clone, Debug)]
struct RegisteredAgentCheckinCallback {
    script_name: String,
    mode: AgentCheckinCallbackMode,
    callback: Arc<Py<PyAny>>,
}

/// Generic callback record used for event callbacks with no variant-specific metadata.
#[derive(Clone, Debug)]
struct EventCallback {
    script_name: String,
    callback: Arc<Py<PyAny>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MatchedCommand {
    name: String,
    command_line: String,
    arguments: Vec<String>,
}

/// The data type of a command option parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandOptionType {
    String,
    Int,
    Bool,
    File,
}

impl CommandOptionType {
    fn from_str(s: &str) -> pyo3::PyResult<Self> {
        match s.to_ascii_lowercase().as_str() {
            "string" | "str" => Ok(Self::String),
            "int" | "integer" => Ok(Self::Int),
            "bool" | "boolean" => Ok(Self::Bool),
            "file" => Ok(Self::File),
            _ => Err(pyo3::exceptions::PyValueError::new_err(format!("unknown option type `{s}`"))),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Int => "int",
            Self::Bool => "bool",
            Self::File => "file",
        }
    }
}

/// A declared parameter for a registered command.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommandOption {
    name: String,
    option_type: CommandOptionType,
    required: bool,
    default: Option<String>,
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
    command_response_callbacks: Mutex<Vec<EventCallback>>,
    loot_captured_callbacks: Mutex<Vec<EventCallback>>,
    listener_changed_callbacks: Mutex<Vec<EventCallback>>,
    script_tabs: Mutex<BTreeMap<String, ScriptTabRecord>>,
    current_script: Mutex<Option<String>>,
    output_entries: Mutex<Vec<ScriptOutputEntry>>,
    script_records: Mutex<BTreeMap<String, ScriptRecord>>,
    outgoing_tx: Mutex<Option<UnboundedSender<OperatorMessage>>>,
    /// Sender half of pending task result channels, keyed by task_id.
    task_result_senders: Mutex<HashMap<String, SyncSender<TaskResult>>>,
    /// Receiver half of pending task result channels, keyed by task_id.
    task_result_receivers: Mutex<HashMap<String, Receiver<TaskResult>>>,
    /// Per-agent command history, keyed by (agent_id, command_name).
    command_history: Mutex<HashMap<(String, String), VecDeque<String>>>,
}

/// Result delivered to a `get_task_result` waiter.
#[derive(Debug, Clone)]
struct TaskResult {
    agent_id: String,
    output: String,
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
        options: Vec<CommandOption>,
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
                options,
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

    fn register_command_response_callback(&self, callback: Py<PyAny>) -> PyResult<()> {
        let script_name = self.current_script_name().ok_or_else(|| {
            PyRuntimeError::new_err(
                "red_cell.on_command_response must be called while a script loads",
            )
        })?;
        lock_mutex(&self.command_response_callbacks)
            .push(EventCallback { script_name, callback: Arc::new(callback) });
        Ok(())
    }

    fn register_loot_captured_callback(&self, callback: Py<PyAny>) -> PyResult<()> {
        let script_name = self.current_script_name().ok_or_else(|| {
            PyRuntimeError::new_err("red_cell.on_loot_captured must be called while a script loads")
        })?;
        lock_mutex(&self.loot_captured_callbacks)
            .push(EventCallback { script_name, callback: Arc::new(callback) });
        Ok(())
    }

    fn register_listener_changed_callback(&self, callback: Py<PyAny>) -> PyResult<()> {
        let script_name = self.current_script_name().ok_or_else(|| {
            PyRuntimeError::new_err(
                "red_cell.on_listener_changed must be called while a script loads",
            )
        })?;
        lock_mutex(&self.listener_changed_callbacks)
            .push(EventCallback { script_name, callback: Arc::new(callback) });
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
            self.register_command(format!("__tab__ {title}"), None, Vec::new(), callback)?;
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
        lock_mutex(&self.command_response_callbacks)
            .retain(|callback| callback.script_name != script_name);
        lock_mutex(&self.loot_captured_callbacks)
            .retain(|callback| callback.script_name != script_name);
        lock_mutex(&self.listener_changed_callbacks)
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

    fn loot_snapshots(
        &self,
        agent_id: Option<&str>,
        loot_type: Option<&str>,
    ) -> Vec<crate::transport::LootItem> {
        let state = lock_app_state(&self.app_state);
        state
            .loot
            .iter()
            .filter(|item| {
                if let Some(id) = agent_id {
                    if item.agent_id != normalize_agent_id(id) {
                        return false;
                    }
                }
                if let Some(ty) = loot_type {
                    if !item.kind.label().eq_ignore_ascii_case(ty) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
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

    /// Register a one-shot channel for `task_id` and store both halves.
    ///
    /// The receiver is retrieved later by `take_task_receiver`.
    fn register_task_waiter(&self, task_id: String) {
        let (tx, rx) = mpsc::sync_channel(1);
        lock_mutex(&self.task_result_senders).insert(task_id.clone(), tx);
        lock_mutex(&self.task_result_receivers).insert(task_id, rx);
    }

    /// Remove and return the receiver registered for `task_id`, if any.
    ///
    /// The sender is intentionally left in `task_result_senders` so that
    /// `deliver_task_result` can still write the result into the channel even
    /// when it fires after `take_task_receiver` has already been called.
    fn take_task_receiver(&self, task_id: &str) -> Option<Receiver<TaskResult>> {
        lock_mutex(&self.task_result_receivers).remove(task_id)
    }

    /// Deliver a task result to any waiting `get_task_result` call.
    fn deliver_task_result(&self, task_id: &str, agent_id: String, output: String) {
        if let Some(tx) = lock_mutex(&self.task_result_senders).remove(task_id) {
            // Ignore errors: waiter may have timed out and dropped its receiver.
            let _ = tx.send(TaskResult { agent_id, output });
        }
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

    fn invoke_command_response_callbacks(
        &self,
        py: Python<'_>,
        agent_id: &str,
        task_id: &str,
        output: &str,
    ) {
        let callbacks = lock_mutex(&self.command_response_callbacks).clone();
        for callback in callbacks {
            self.begin_script_execution(&callback.script_name);
            let call_result = callback.callback.bind(py).call1((agent_id, task_id, output));
            if let Err(error) = call_result {
                let message = format!("command response callback failed: {error}\n");
                let _ = self.push_output(
                    Some(&callback.script_name),
                    ScriptOutputStream::Stderr,
                    &message,
                );
                warn!(agent_id, task_id, error = %error, "python command response callback failed");
            }
            self.end_script_execution();
        }
    }

    fn invoke_loot_captured_callbacks(
        &self,
        py: Python<'_>,
        loot_item: &crate::transport::LootItem,
    ) {
        let callbacks = lock_mutex(&self.loot_captured_callbacks).clone();
        if callbacks.is_empty() {
            return;
        }
        let py_loot = match Py::new(py, PyLootItem::from_loot_item(loot_item)) {
            Ok(item) => item,
            Err(error) => {
                warn!(error = %error, "failed to construct python loot item proxy");
                return;
            }
        };
        for callback in callbacks {
            self.begin_script_execution(&callback.script_name);
            let call_result =
                callback.callback.bind(py).call1((&loot_item.agent_id, py_loot.clone_ref(py)));
            if let Err(error) = call_result {
                let message = format!("loot captured callback failed: {error}\n");
                let _ = self.push_output(
                    Some(&callback.script_name),
                    ScriptOutputStream::Stderr,
                    &message,
                );
                warn!(error = %error, "python loot captured callback failed");
            }
            self.end_script_execution();
        }
    }

    fn invoke_listener_changed_callbacks(&self, py: Python<'_>, listener_name: &str, action: &str) {
        let callbacks = lock_mutex(&self.listener_changed_callbacks).clone();
        for callback in callbacks {
            self.begin_script_execution(&callback.script_name);
            let call_result = callback.callback.bind(py).call1((listener_name, action));
            if let Err(error) = call_result {
                let message = format!("listener changed callback failed: {error}\n");
                let _ = self.push_output(
                    Some(&callback.script_name),
                    ScriptOutputStream::Stderr,
                    &message,
                );
                warn!(listener_name, action, error = %error, "python listener changed callback failed");
            }
            self.end_script_execution();
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

        // Snapshot prior history, then record this invocation.
        let history_snapshot = {
            let key = (normalize_agent_id(agent_id), command_name.to_owned());
            let mut history = lock_mutex(&self.command_history);
            let agent_history = history.entry(key).or_default();
            let snapshot: Vec<String> = agent_history.iter().cloned().collect();
            agent_history.push_back(command_line.to_owned());
            while agent_history.len() > MAX_COMMAND_HISTORY {
                agent_history.pop_front();
            }
            snapshot
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
                options: registered.options.clone(),
                history: history_snapshot,
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
    EmitCommandResponse {
        agent_id: String,
        task_id: String,
        output: String,
    },
    EmitLootCaptured(crate::transport::LootItem),
    EmitListenerChanged {
        name: String,
        action: String,
    },
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
            command_response_callbacks: Mutex::new(Vec::new()),
            loot_captured_callbacks: Mutex::new(Vec::new()),
            listener_changed_callbacks: Mutex::new(Vec::new()),
            script_tabs: Mutex::new(BTreeMap::new()),
            current_script: Mutex::new(None),
            output_entries: Mutex::new(Vec::new()),
            script_records: Mutex::new(BTreeMap::new()),
            outgoing_tx: Mutex::new(None),
            task_result_senders: Mutex::new(HashMap::new()),
            task_result_receivers: Mutex::new(HashMap::new()),
            command_history: Mutex::new(HashMap::new()),
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

    /// Deliver a task result to any Python script blocked in `get_task_result`.
    pub(crate) fn notify_task_result(&self, task_id: String, agent_id: String, output: String) {
        self.inner.api_state.deliver_task_result(&task_id, agent_id, output);
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

    /// Queue a command-response callback dispatch on the Python thread.
    pub(crate) fn emit_command_response(
        &self,
        agent_id: String,
        task_id: String,
        output: String,
    ) -> Result<(), PythonRuntimeError> {
        self.inner
            .command_tx
            .send(PythonThreadCommand::EmitCommandResponse { agent_id, task_id, output })
            .map_err(|_| PythonRuntimeError::ThreadUnavailable)
    }

    /// Queue a loot-captured callback dispatch on the Python thread.
    pub(crate) fn emit_loot_captured(
        &self,
        loot_item: crate::transport::LootItem,
    ) -> Result<(), PythonRuntimeError> {
        self.inner
            .command_tx
            .send(PythonThreadCommand::EmitLootCaptured(loot_item))
            .map_err(|_| PythonRuntimeError::ThreadUnavailable)
    }

    /// Queue a listener-changed callback dispatch on the Python thread.
    pub(crate) fn emit_listener_changed(
        &self,
        name: String,
        action: String,
    ) -> Result<(), PythonRuntimeError> {
        self.inner
            .command_tx
            .send(PythonThreadCommand::EmitListenerChanged { name, action })
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

    #[cfg(test)]
    fn new_zombie_for_test() -> Self {
        // Ensure the Python interpreter is ready before acquiring the GIL.
        // This is idempotent — safe to call multiple times and from multiple threads.
        pyo3::prepare_freethreaded_python();
        let api_state = Arc::new(PythonApiState {
            app_state: Arc::new(Mutex::new(AppState::new(
                "wss://127.0.0.1:40056/havoc/".to_owned(),
            ))),
            commands: Mutex::new(BTreeMap::new()),
            agent_checkin_callbacks: Mutex::new(Vec::new()),
            command_response_callbacks: Mutex::new(Vec::new()),
            loot_captured_callbacks: Mutex::new(Vec::new()),
            listener_changed_callbacks: Mutex::new(Vec::new()),
            script_tabs: Mutex::new(BTreeMap::new()),
            current_script: Mutex::new(None),
            output_entries: Mutex::new(Vec::new()),
            script_records: Mutex::new(BTreeMap::new()),
            outgoing_tx: Mutex::new(None),
            task_result_senders: Mutex::new(HashMap::new()),
            task_result_receivers: Mutex::new(HashMap::new()),
            command_history: Mutex::new(HashMap::new()),
        });
        let (command_tx, command_rx) = mpsc::channel();
        drop(command_rx);

        Python::with_gil(|py| {
            lock_mutex(&api_state.commands).insert(
                "zombie".to_owned(),
                RegisteredCommand {
                    script_name: "zombie".to_owned(),
                    description: None,
                    options: Vec::new(),
                    callback: Arc::new(py.None()),
                },
            );
        });

        Self {
            inner: Arc::new(PythonRuntimeInner {
                api_state,
                command_tx,
                join_handle: Mutex::new(None),
            }),
        }
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
            PythonThreadCommand::EmitCommandResponse { agent_id, task_id, output } => {
                Python::with_gil(|py| {
                    api_state.invoke_command_response_callbacks(py, &agent_id, &task_id, &output);
                });
            }
            PythonThreadCommand::EmitLootCaptured(loot_item) => {
                Python::with_gil(|py| {
                    api_state.invoke_loot_captured_callbacks(py, &loot_item);
                });
            }
            PythonThreadCommand::EmitListenerChanged { name, action } => {
                Python::with_gil(|py| {
                    api_state.invoke_listener_changed_callbacks(py, &name, &action);
                });
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
    module.add_function(wrap_pyfunction!(on_command_response, module)?)?;
    module.add_function(wrap_pyfunction!(on_loot_captured, module)?)?;
    module.add_function(wrap_pyfunction!(on_listener_changed, module)?)?;
    module.add_function(wrap_pyfunction!(agent, module)?)?;
    module.add_function(wrap_pyfunction!(agents, module)?)?;
    module.add_function(wrap_pyfunction!(listener, module)?)?;
    module.add_function(wrap_pyfunction!(listeners, module)?)?;
    module.add_function(wrap_pyfunction!(get_loot, module)?)?;
    module.add_function(wrap_pyfunction!(task_agent, module)?)?;
    module.add_function(wrap_pyfunction!(get_task_result, module)?)?;
    module.add_class::<PyAgent>()?;
    module.add_class::<PyCommandContext>()?;
    module.add_class::<PyCommandOption>()?;
    module.add_class::<PyEventRegistrar>()?;
    module.add_class::<PyListener>()?;
    module.add_class::<PyLootItem>()?;
    module.add("RegisterCommand", module.getattr("register_command")?)?;
    module.add("RegisterCallback", module.getattr("register_callback")?)?;
    module.add("GetAgent", module.getattr("agent")?)?;
    module.add("GetAgents", module.getattr("agents")?)?;
    module.add("GetListener", module.getattr("listener")?)?;
    module.add("GetListeners", module.getattr("listeners")?)?;
    module.add("GetLoot", module.getattr("get_loot")?)?;
    module.add("TaskAgent", module.getattr("task_agent")?)?;
    module.add("GetTaskResult", module.getattr("get_task_result")?)?;
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
    module.add_function(wrap_pyfunction!(havocui_register_command, module)?)?;
    module.add_class::<PyLogger>()?;
    module.add("MessageBox", module.getattr("messagebox")?)?;
    module.add("ErrorMessage", module.getattr("errormessage")?)?;
    module.add("InfoMessage", module.getattr("infomessage")?)?;
    module.add("SuccessMessage", module.getattr("successmessage")?)?;
    module.add("CreateTab", module.getattr("createtab")?)?;
    module.add("SetTabLayout", module.getattr("settablayout")?)?;
    module.add("RegisterCommand", module.getattr("register_command")?)?;
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
        "host": listener.host,
        "port_bind": listener.port_bind,
        "port_conn": listener.port_conn,
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
    options: Vec<CommandOption>,
    history: Vec<String>,
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

    /// The declared options for this command.
    #[getter]
    fn options(&self, py: Python<'_>) -> PyResult<Vec<Py<PyCommandOption>>> {
        self.options
            .iter()
            .map(|opt| {
                Py::new(
                    py,
                    PyCommandOption {
                        name: opt.name.clone(),
                        option_type: opt.option_type,
                        required: opt.required,
                        default: opt.default.clone(),
                    },
                )
            })
            .collect::<PyResult<Vec<_>>>()
    }

    /// Previous invocations of this command for the same agent, oldest first.
    #[getter]
    fn history(&self) -> Vec<String> {
        self.history.clone()
    }

    #[getter]
    fn agent(&self, py: Python<'_>) -> Py<PyAgent> {
        self.agent.clone_ref(py)
    }
}

/// A declared parameter exposed by a registered command.
#[pyclass(name = "CommandOption", frozen)]
#[derive(Clone, Debug)]
struct PyCommandOption {
    name: String,
    option_type: CommandOptionType,
    required: bool,
    default: Option<String>,
}

#[pymethods]
impl PyCommandOption {
    /// The parameter name.
    #[getter]
    fn name(&self) -> String {
        self.name.clone()
    }

    /// The parameter type label: `"string"`, `"int"`, `"bool"`, or `"file"`.
    #[getter(r#type)]
    fn option_type(&self) -> &'static str {
        self.option_type.label()
    }

    /// Whether this parameter must be supplied.
    #[getter]
    fn required(&self) -> bool {
        self.required
    }

    /// Default value string, or `None` if no default was declared.
    #[getter]
    fn default(&self) -> Option<String> {
        self.default.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "CommandOption(name={:?}, type={:?}, required={}, default={:?})",
            self.name,
            self.option_type.label(),
            self.required,
            self.default,
        )
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

    #[pyo3(name = "OnCommandResponse")]
    fn on_command_response(&self, callback: Bound<'_, PyAny>) -> PyResult<()> {
        ensure_callable(&callback)?;
        active_api_state()?.register_command_response_callback(callback.unbind())
    }

    #[pyo3(name = "OnLootCaptured")]
    fn on_loot_captured(&self, callback: Bound<'_, PyAny>) -> PyResult<()> {
        ensure_callable(&callback)?;
        active_api_state()?.register_loot_captured_callback(callback.unbind())
    }

    #[pyo3(name = "OnListenerChanged")]
    fn on_listener_changed(&self, callback: Bound<'_, PyAny>) -> PyResult<()> {
        ensure_callable(&callback)?;
        active_api_state()?.register_listener_changed_callback(callback.unbind())
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

/// A single loot item returned by `red_cell.get_loot()`.
#[pyclass(name = "LootItem", frozen)]
#[derive(Clone, Debug)]
struct PyLootItem {
    id: Option<i64>,
    agent_id: String,
    loot_type: String,
    data: Option<String>,
    timestamp: String,
    name: String,
}

impl PyLootItem {
    fn from_loot_item(item: &LootItem) -> Self {
        Self {
            id: item.id,
            agent_id: item.agent_id.clone(),
            loot_type: item.kind.label().to_owned(),
            data: item.content_base64.clone().or_else(|| item.preview.clone()),
            timestamp: item.collected_at.clone(),
            name: item.name.clone(),
        }
    }
}

#[pymethods]
impl PyLootItem {
    /// The database ID of this loot item, or `None` if not yet known.
    #[getter]
    fn id(&self) -> Option<i64> {
        self.id
    }

    /// The hex identifier of the agent that captured this loot.
    #[getter]
    fn agent_id(&self) -> String {
        self.agent_id.clone()
    }

    /// The loot type label: `"Credential"`, `"File"`, `"Screenshot"`, or `"Other"`.
    #[getter(r#type)]
    fn loot_type(&self) -> String {
        self.loot_type.clone()
    }

    /// The loot content: base64-encoded bytes for files, plain text for credentials.
    #[getter]
    fn data(&self) -> Option<String> {
        self.data.clone()
    }

    /// ISO-8601 timestamp when the loot was captured.
    #[getter]
    fn timestamp(&self) -> String {
        self.timestamp.clone()
    }

    /// Human-readable name of this loot item.
    #[getter]
    fn name(&self) -> String {
        self.name.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "LootItem(id={:?}, agent_id={:?}, type={:?}, name={:?}, timestamp={:?})",
            self.id, self.agent_id, self.loot_type, self.name, self.timestamp,
        )
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
    options: Vec<CommandOption>,
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

/// Parse a Python value (list of dicts) into a `Vec<CommandOption>`.
fn parse_options(value: &Bound<'_, PyAny>) -> PyResult<Vec<CommandOption>> {
    if value.is_none() {
        return Ok(Vec::new());
    }
    let list = value.try_iter().map_err(|_| {
        PyValueError::new_err(
            "options must be a list of dicts with 'name', 'type', 'required', 'default'",
        )
    })?;
    let mut options = Vec::new();
    for item in list {
        let item = item?;
        let dict = item.downcast::<PyDict>().map_err(|_| {
            PyValueError::new_err(
                "each option must be a dict with 'name', 'type', 'required', 'default'",
            )
        })?;
        let name = dict
            .get_item("name")?
            .ok_or_else(|| PyValueError::new_err("option is missing 'name'"))?
            .extract::<String>()?;
        let type_str = match dict.get_item("type")? {
            Some(v) => v.extract::<String>()?,
            None => "string".to_owned(),
        };
        let option_type = CommandOptionType::from_str(&type_str)?;
        let required = match dict.get_item("required")? {
            Some(v) => v.extract::<bool>()?,
            None => false,
        };
        let default = match dict.get_item("default")? {
            Some(v) if !v.is_none() => Some(v.extract::<String>()?),
            _ => None,
        };
        options.push(CommandOption { name, option_type, required, default });
    }
    Ok(options)
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
        let options = optional_kwarg(kwargs, "options")?
            .as_ref()
            .map(parse_options)
            .transpose()?
            .unwrap_or_default();
        let name = if module.trim().is_empty() { command } else { format!("{module} {command}") };
        return Ok(RegisterCommandRequest {
            name,
            description,
            options,
            callback: callback.unbind(),
        });
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
    let options = if let Some(value) = optional_kwarg(kwargs, "options")? {
        parse_options(&value)?
    } else {
        positional.get(3).map(parse_options).transpose()?.unwrap_or_default()
    };
    Ok(RegisterCommandRequest { name, description, options, callback: callback.unbind() })
}

#[pyfunction]
#[pyo3(signature = (*args, **kwargs))]
fn register_command(args: &Bound<'_, PyTuple>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<()> {
    let request = parse_register_command_request(args, kwargs)?;
    let api_state = active_api_state()?;
    api_state.register_command(request.name, request.description, request.options, request.callback)
}

/// Parse a `havocui.RegisterCommand` call.
///
/// Supported forms:
/// - `(name, callback)` — 2-arg backward-compatible
/// - `(name, description, options, callback)` — full 4-arg form
/// - keyword arguments: `name=`, `description=`, `options=`, `callback=`
fn parse_havocui_register_command_request(
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<RegisterCommandRequest> {
    let positional = args.iter().collect::<Vec<_>>();

    // Prefer explicit keyword form for any argument.
    let callback = if let Some(value) = optional_kwarg(kwargs, "callback")? {
        value
    } else if let Some(cb) = positional.last().filter(|v| v.is_callable()) {
        cb.clone()
    } else {
        return Err(PyValueError::new_err(
            "havocui.RegisterCommand requires a callable as the last positional argument or `callback=`",
        ));
    };
    ensure_callable(&callback)?;

    let name = extract_string_argument(kwargs, "name", positional.first())?
        .ok_or_else(|| PyValueError::new_err("havocui.RegisterCommand requires a command name"))?;

    // 2-arg form: (name, callback) — no description or options.
    // 4-arg form: (name, description, options, callback).
    let (description, options) = if positional.len() == 4 {
        let desc = extract_string_argument(kwargs, "description", positional.get(1))?;
        let opts = match positional.get(2) {
            Some(v) => parse_options(v)?,
            None => Vec::new(),
        };
        (desc, opts)
    } else {
        let desc = extract_string_argument(kwargs, "description", None)?;
        let opts = optional_kwarg(kwargs, "options")?
            .as_ref()
            .map(parse_options)
            .transpose()?
            .unwrap_or_default();
        (desc, opts)
    };

    Ok(RegisterCommandRequest { name, description, options, callback: callback.unbind() })
}

/// Register a command via the `havocui` module.
///
/// Supported forms:
/// - `havocui.RegisterCommand(name, callback)` — backward-compatible 2-arg form
/// - `havocui.RegisterCommand(name, description, options, callback)` — full form
/// - keyword arguments: `name=`, `description=`, `options=`, `callback=`
#[pyfunction]
#[pyo3(name = "register_command")]
#[pyo3(signature = (*args, **kwargs))]
fn havocui_register_command(
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<()> {
    let request = parse_havocui_register_command_request(args, kwargs)?;
    let api_state = active_api_state()?;
    api_state.register_command(request.name, request.description, request.options, request.callback)
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

/// Register a callback that fires whenever any command output arrives from an agent.
///
/// The callback receives `(agent_id: str, task_id: str, output: str)`.
/// `task_id` is empty when the response does not belong to a tracked task.
#[pyfunction]
fn on_command_response(callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    active_api_state()?.register_command_response_callback(callback.unbind())
}

/// Register a callback that fires when a loot item (credential, file, etc.) is captured.
///
/// The callback receives `(agent_id: str, loot: LootItem)`.
#[pyfunction]
fn on_loot_captured(callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    active_api_state()?.register_loot_captured_callback(callback.unbind())
}

/// Register a callback that fires when a listener is started, stopped, or edited.
///
/// The callback receives `(listener_id: str, action: str)` where `action` is one of
/// `"start"`, `"stop"`, or `"edit"`.
#[pyfunction]
fn on_listener_changed(callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    active_api_state()?.register_listener_changed_callback(callback.unbind())
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

/// Return loot items from the client's local cache, optionally filtered.
///
/// # Arguments
/// * `agent_id`  – hex agent identifier; omit or pass `None` to return loot from all agents.
/// * `loot_type` – one of `"Credential"`, `"File"`, `"Screenshot"`, `"Other"`;
///                 omit or pass `None` to return all types (case-insensitive).
#[pyfunction]
#[pyo3(signature = (agent_id=None, loot_type=None))]
fn get_loot(
    py: Python<'_>,
    agent_id: Option<String>,
    loot_type: Option<String>,
) -> PyResult<Vec<Py<PyLootItem>>> {
    let api_state = active_api_state()?;
    api_state
        .loot_snapshots(agent_id.as_deref(), loot_type.as_deref())
        .iter()
        .map(|item| Py::new(py, PyLootItem::from_loot_item(item)))
        .collect()
}

/// Send a command to an agent and return the allocated task ID.
///
/// The returned task ID can be passed to `get_task_result` to block until the
/// teamserver delivers the agent's response.
///
/// # Arguments
/// * `agent_id` – hex agent identifier (string or integer).
/// * `command`  – full command line, e.g. `"shell whoami"` or `"ps"`.
/// * `args`     – optional raw argument bytes. When provided `command` is used
///               as the command name and `args` as the binary payload.
///
/// # Returns
/// A task ID string (`"XXXXXXXX"`) that can be passed to `get_task_result`.
///
/// # Errors
/// Returns a `RuntimeError` if the transport is not connected.
#[pyfunction]
#[pyo3(signature = (agent_id, command, args=None))]
fn task_agent(
    agent_id: &Bound<'_, PyAny>,
    command: String,
    args: Option<Vec<u8>>,
) -> PyResult<String> {
    let agent = PyAgent::new(agent_id)?;
    let api_state = active_api_state()?;
    let task_id = next_task_id_string();
    // Register the waiter before sending so no result can arrive unnoticed.
    api_state.register_task_waiter(task_id.clone());
    let operator = current_operator_username(&api_state.app_state);
    let message = if let Some(raw) = args {
        build_agent_command_message(&agent.agent_id, &task_id, &command, &raw, &operator)
    } else {
        build_console_task_message(&agent.agent_id, &task_id, &command, &operator)
            .map_err(PyValueError::new_err)?
    };
    if let Err(err) = api_state.queue_task_message(message) {
        // Clean up both channel halves since we failed to enqueue.
        lock_mutex(&api_state.task_result_senders).remove(&task_id);
        lock_mutex(&api_state.task_result_receivers).remove(&task_id);
        return Err(err);
    }
    Ok(task_id)
}

/// Block until the result for `task_id` arrives or `timeout` seconds elapse.
///
/// Must be called after `task_agent` using the task ID it returned.
///
/// # Arguments
/// * `task_id` – the string returned by `task_agent`.
/// * `timeout` – maximum seconds to wait (default `30.0`).
///
/// # Returns
/// A dict `{"agent_id": str, "output": str}` on success, or `None` on timeout.
///
/// # Errors
/// Returns a `ValueError` if `task_id` has no registered waiter (i.e. was not
/// produced by `task_agent`).
#[pyfunction]
#[pyo3(signature = (task_id, timeout = 30.0))]
fn get_task_result(py: Python<'_>, task_id: String, timeout: f64) -> PyResult<Py<PyAny>> {
    let api_state = active_api_state()?;
    let rx = api_state.take_task_receiver(&task_id).ok_or_else(|| {
        PyValueError::new_err(format!("no pending task with id `{task_id}`; call task_agent first"))
    })?;
    let timeout_dur = Duration::from_secs_f64(timeout.max(0.0));
    // Release the GIL while blocking so other Python threads can continue.
    let result = py.allow_threads(move || rx.recv_timeout(timeout_dur).ok());
    match result {
        Some(task_result) => {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("agent_id", task_result.agent_id)?;
            dict.set_item("output", task_result.output)?;
            Ok(dict.into_any().unbind())
        }
        None => {
            // Timeout: the agent never replied. Remove the stale sender so it does not
            // accumulate indefinitely (deliver_task_result is the only other caller that
            // would remove it, but it will never fire for an orphaned task).
            lock_mutex(&api_state.task_result_senders).remove(&task_id);
            Ok(py.None())
        }
    }
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
        Err(poisoned) => {
            warn!("mutex poisoned in python runtime — recovering with potentially corrupted state");
            poisoned.into_inner()
        }
    }
}

fn lock_app_state(app_state: &SharedAppState) -> std::sync::MutexGuard<'_, AppState> {
    match app_state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!(
                "app state mutex poisoned in python module — recovering with potentially corrupted state"
            );
            poisoned.into_inner()
        }
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

    use pyo3::types::IntoPyDict;
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
            host: "0.0.0.0".to_owned(),
            port_bind: "443".to_owned(),
            port_conn: "443".to_owned(),
            status: "Online".to_owned(),
        }
    }

    fn sample_loot_item(
        agent_id: &str,
        kind: crate::transport::LootKind,
        name: &str,
        content: Option<&str>,
    ) -> LootItem {
        LootItem {
            id: Some(42),
            kind,
            name: name.to_owned(),
            agent_id: agent_id.to_owned(),
            source: "operator".to_owned(),
            collected_at: "2026-03-15T12:00:00Z".to_owned(),
            file_path: None,
            size_bytes: None,
            content_base64: content.map(ToOwned::to_owned),
            preview: None,
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

    fn output_occurrences(runtime: &PythonRuntime, needle: &str) -> usize {
        runtime.script_output().iter().map(|entry| entry.text.matches(needle).count()).sum()
    }

    fn wait_for_output_occurrences(runtime: &PythonRuntime, needle: &str, expected: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if output_occurrences(runtime, needle) >= expected {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        false
    }

    #[test]
    fn zombie_runtime_emit_agent_checkin_returns_thread_unavailable() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();

        let result = runtime.emit_agent_checkin("DEADBEEF".to_owned());

        assert!(matches!(result, Err(PythonRuntimeError::ThreadUnavailable)));
    }

    #[test]
    fn zombie_runtime_emit_loot_captured_returns_thread_unavailable() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();

        let result = runtime.emit_loot_captured(sample_loot_item(
            "DEADBEEF",
            crate::transport::LootKind::Other,
            "notes.txt",
            Some("c2FtcGxl"),
        ));

        assert!(matches!(result, Err(PythonRuntimeError::ThreadUnavailable)));
    }

    #[test]
    fn zombie_runtime_execute_registered_command_returns_thread_unavailable() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();

        let result = runtime.execute_registered_command("DEADBEEF", "zombie");

        assert!(matches!(result, Err(PythonRuntimeError::ThreadUnavailable)));
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
            "import havocui\nimport red_cell\n\
def on_checkin(agent):\n    print('checkin:' + agent.id)\n\
def render():\n    havocui.SetTabLayout('Status', 'operator layout')\n\
red_cell.register_command('demo', lambda: None)\n\
red_cell.on_agent_checkin(on_checkin)\n\
havocui.CreateTab('Status', render)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));
        assert_eq!(runtime.command_names(), vec!["__tab__ status".to_owned(), "demo".to_owned()]);
        assert_eq!(
            runtime.script_tabs(),
            vec![ScriptTabDescriptor {
                title: "Status".to_owned(),
                script_name: "sample".to_owned(),
                layout: String::new(),
                has_callback: true,
            }]
        );

        runtime
            .emit_agent_checkin("00ABCDEF".to_owned())
            .unwrap_or_else(|error| panic!("agent checkin dispatch should succeed: {error}"));
        assert!(wait_for_output_occurrences(&runtime, "checkin:00ABCDEF", 1));

        write_script(
            &script_path,
            "import havocui\nimport red_cell\n\
def on_checkin(agent):\n    print('checkin:' + agent.id)\n\
def render():\n    havocui.SetTabLayout('Status', 'reloaded layout')\n\
red_cell.register_command('updated', lambda: None)\n\
red_cell.on_agent_checkin(on_checkin)\n\
havocui.CreateTab('Status', render)\n",
        );
        runtime
            .reload_script("sample")
            .unwrap_or_else(|error| panic!("reload should succeed: {error}"));
        assert_eq!(
            runtime.command_names(),
            vec!["__tab__ status".to_owned(), "updated".to_owned()]
        );
        assert_eq!(
            runtime.script_tabs(),
            vec![ScriptTabDescriptor {
                title: "Status".to_owned(),
                script_name: "sample".to_owned(),
                layout: String::new(),
                has_callback: true,
            }]
        );
        runtime
            .emit_agent_checkin("00ABCDEF".to_owned())
            .unwrap_or_else(|error| panic!("agent checkin dispatch should succeed: {error}"));
        assert!(
            wait_for_output_occurrences(&runtime, "checkin:00ABCDEF", 2),
            "reload should register exactly one active callback"
        );

        runtime
            .unload_script("sample")
            .unwrap_or_else(|error| panic!("unload should succeed: {error}"));
        assert!(runtime.command_names().is_empty());
        assert!(runtime.script_tabs().is_empty(), "unload should remove script tabs");

        let output_count_before_unload_emit = output_occurrences(&runtime, "checkin:00ABCDEF");
        runtime
            .emit_agent_checkin("00ABCDEF".to_owned())
            .unwrap_or_else(|error| panic!("agent checkin dispatch should succeed: {error}"));
        thread::sleep(Duration::from_millis(150));
        assert_eq!(
            output_occurrences(&runtime, "checkin:00ABCDEF"),
            output_count_before_unload_emit,
            "unload should remove agent checkin callbacks"
        );
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
    fn execute_registered_command_returns_false_for_unknown_command() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("demo.py"),
            "import red_cell\nred_cell.register_command('demo', lambda agent, args: 'ok')\n",
        );

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let executed = runtime
            .execute_registered_command("00ABCDEF", "unknown_command")
            .unwrap_or_else(|error| panic!("execute_registered_command should not error: {error}"));

        assert!(!executed, "unknown command should return false");
        assert!(
            runtime.script_output().is_empty(),
            "no output should be generated for an unknown command"
        );
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

    #[test]
    fn get_loot_returns_all_items_when_no_filter() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(&temp_dir.path().join("noop.py"), "import red_cell\n");
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.loot.push(sample_loot_item(
                "00AABBCC",
                crate::transport::LootKind::Credential,
                "cred-1",
                Some("dXNlcjpwYXNz"),
            ));
            state.loot.push(sample_loot_item(
                "00DDEEFF",
                crate::transport::LootKind::File,
                "file-1",
                Some("ZmlsZWNvbnRlbnQ="),
            ));
        }
        let _runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let (count, first_agent_id, first_type, first_id, first_timestamp) =
            Python::with_gil(|py| -> PyResult<(usize, String, String, Option<i64>, String)> {
                install_api_module(py)?;
                let module = py.import("red_cell")?;
                let items = module.call_method0("get_loot")?;
                let count = items.len()?;
                let first = items.get_item(0)?;
                let agent_id = first.getattr("agent_id")?.extract::<String>()?;
                let loot_type = first.getattr("type")?.extract::<String>()?;
                let id = first.getattr("id")?.extract::<Option<i64>>()?;
                let timestamp = first.getattr("timestamp")?.extract::<String>()?;
                Ok((count, agent_id, loot_type, id, timestamp))
            })
            .unwrap_or_else(|error| panic!("get_loot should succeed: {error}"));

        assert_eq!(count, 2);
        assert_eq!(first_agent_id, "00AABBCC");
        assert_eq!(first_type, "Credential");
        assert_eq!(first_id, Some(42));
        assert_eq!(first_timestamp, "2026-03-15T12:00:00Z");
    }

    #[test]
    fn get_loot_filters_by_agent_id_and_type() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(&temp_dir.path().join("noop.py"), "import red_cell\n");
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.loot.push(sample_loot_item(
                "00AABBCC",
                crate::transport::LootKind::Credential,
                "cred-1",
                Some("dXNlcjpwYXNz"),
            ));
            state.loot.push(sample_loot_item(
                "00AABBCC",
                crate::transport::LootKind::File,
                "file-1",
                Some("ZmlsZWNvbnRlbnQ="),
            ));
            state.loot.push(sample_loot_item(
                "00DDEEFF",
                crate::transport::LootKind::Credential,
                "cred-2",
                None,
            ));
        }
        let _runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // Filter by agent_id only.
        let agent_filtered_count = Python::with_gil(|py| -> PyResult<usize> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            module
                .call_method("get_loot", (), Some(&[("agent_id", "00AABBCC")].into_py_dict(py)?))?
                .len()
        })
        .unwrap_or_else(|error| panic!("get_loot with agent_id filter should succeed: {error}"));
        assert_eq!(agent_filtered_count, 2);

        // Filter by loot_type only.
        let type_filtered_count = Python::with_gil(|py| -> PyResult<usize> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            module
                .call_method(
                    "get_loot",
                    (),
                    Some(&[("loot_type", "credential")].into_py_dict(py)?),
                )?
                .len()
        })
        .unwrap_or_else(|error| panic!("get_loot with type filter should succeed: {error}"));
        assert_eq!(type_filtered_count, 2);

        // Filter by both agent_id and loot_type.
        let both_filtered = Python::with_gil(|py| -> PyResult<(usize, Option<String>)> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            let items = module.call_method(
                "get_loot",
                (),
                Some(&[("agent_id", "00AABBCC"), ("loot_type", "Credential")].into_py_dict(py)?),
            )?;
            let count = items.len()?;
            let data = items.get_item(0)?.getattr("data")?.extract::<Option<String>>()?;
            Ok((count, data))
        })
        .unwrap_or_else(|error| panic!("get_loot with both filters should succeed: {error}"));
        assert_eq!(both_filtered.0, 1);
        assert_eq!(both_filtered.1.as_deref(), Some("dXNlcjpwYXNz"));
    }

    // ── task_agent / get_task_result ────────────────────────────────────────

    #[test]
    fn task_agent_returns_task_id_and_queues_message() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_mutex(&app_state);
            state.agents.push(sample_agent("AABBCCDD"));
        }

        let runtime = PythonRuntime::initialize(app_state.clone(), temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // Attach a channel so queue_task_message succeeds.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OperatorMessage>();
        runtime.set_outgoing_sender(tx);

        let task_id = Python::with_gil(|py| -> PyResult<String> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            module.call_method("task_agent", ("AABBCCDD", "ps"), None)?.extract::<String>()
        })
        .unwrap_or_else(|error| panic!("task_agent should succeed: {error}"));

        assert_eq!(task_id.len(), 8, "task_id should be an 8-character hex string");
        rx.try_recv().unwrap_or_else(|error| panic!("a message should have been queued: {error}"));
    }

    #[test]
    fn get_task_result_fails_without_prior_task_agent() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        let _runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let result = Python::with_gil(|py| -> PyResult<()> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            module.call_method("get_task_result", ("DEADBEEF",), None)?;
            Ok(())
        });

        assert!(result.is_err(), "get_task_result with unknown task_id should fail");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("DEADBEEF"), "error should mention the task id");
    }

    #[test]
    fn notify_task_result_unblocks_get_task_result() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_mutex(&app_state);
            state.agents.push(sample_agent("11223344"));
        }

        let runtime = PythonRuntime::initialize(app_state.clone(), temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<OperatorMessage>();
        runtime.set_outgoing_sender(tx);

        // Allocate a task and get the task_id.
        let task_id = Python::with_gil(|py| -> PyResult<String> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            module.call_method("task_agent", ("11223344", "screenshot"), None)?.extract::<String>()
        })
        .unwrap_or_else(|error| panic!("task_agent should succeed: {error}"));

        // Deliver the result from a separate thread before get_task_result is called.
        let runtime_clone = runtime.clone();
        let task_id_clone = task_id.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            runtime_clone.notify_task_result(
                task_id_clone,
                "11223344".to_owned(),
                "screenshot saved".to_owned(),
            );
        });

        let result = Python::with_gil(|py| -> PyResult<(String, String)> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            let res = module.call_method("get_task_result", (&task_id,), None)?;
            let agent_id = res.get_item("agent_id")?.extract::<String>()?;
            let output = res.get_item("output")?.extract::<String>()?;
            Ok((agent_id, output))
        })
        .unwrap_or_else(|error| panic!("get_task_result should succeed: {error}"));

        assert_eq!(result.0, "11223344");
        assert_eq!(result.1, "screenshot saved");
    }

    #[test]
    fn get_task_result_times_out_and_returns_none() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_mutex(&app_state);
            state.agents.push(sample_agent("DEADBEEF"));
        }

        let runtime = PythonRuntime::initialize(app_state.clone(), temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<OperatorMessage>();
        runtime.set_outgoing_sender(tx);

        let task_id = Python::with_gil(|py| -> PyResult<String> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            module.call_method("task_agent", ("DEADBEEF", "screenshot"), None)?.extract::<String>()
        })
        .unwrap_or_else(|error| panic!("task_agent should succeed: {error}"));

        // get_task_result with a tiny timeout; nobody will deliver the result.
        let is_none = Python::with_gil(|py| -> PyResult<bool> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            let res = module.call_method(
                "get_task_result",
                (&task_id,),
                Some(&[("timeout", 0.01f64)].into_py_dict(py)?),
            )?;
            Ok(res.is_none())
        })
        .unwrap_or_else(|error| panic!("get_task_result should not error: {error}"));

        assert!(is_none, "get_task_result should return None on timeout");

        // After timeout the sender must be removed from the map so it does not leak.
        let api_state = Python::with_gil(|py| -> PyResult<Arc<PythonApiState>> {
            install_api_module(py)?;
            active_api_state()
        })
        .unwrap_or_else(|error| panic!("active_api_state should be available: {error}"));
        assert!(
            !lock_mutex(&api_state.task_result_senders).contains_key(&task_id),
            "sender for timed-out task should have been removed from task_result_senders",
        );
    }

    #[test]
    fn runtime_dispatches_command_response_callbacks() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("response.txt");
        let script = format!(
            "import pathlib\nimport red_cell\n\
def on_resp(agent_id, task_id, output):\n    pathlib.Path({output:?}).write_text(agent_id + ':' + task_id + ':' + output)\n\
red_cell.on_command_response(on_resp)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("resp.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        runtime
            .emit_command_response(
                "AABBCCDD".to_owned(),
                "TASKID01".to_owned(),
                "whoami output".to_owned(),
            )
            .unwrap_or_else(|error| panic!("emit_command_response should succeed: {error}"));

        assert_eq!(
            wait_for_file_contents(&output_path).as_deref(),
            Some("AABBCCDD:TASKID01:whoami output")
        );
    }

    #[test]
    fn runtime_dispatches_loot_captured_callbacks() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("loot.txt");
        let script = format!(
            "import pathlib\nimport red_cell\n\
def on_loot(agent_id, loot):\n    pathlib.Path({output:?}).write_text(agent_id + ':' + loot.type + ':' + loot.name)\n\
red_cell.on_loot_captured(on_loot)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("loot.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let loot_item = sample_loot_item(
            "AABBCCDD",
            crate::transport::LootKind::Credential,
            "domain\\user:pass",
            Some("dXNlcjpwYXNz"),
        );
        runtime
            .emit_loot_captured(loot_item)
            .unwrap_or_else(|error| panic!("emit_loot_captured should succeed: {error}"));

        assert_eq!(
            wait_for_file_contents(&output_path).as_deref(),
            Some("AABBCCDD:Credential:domain\\user:pass")
        );
    }

    #[test]
    fn runtime_dispatches_listener_changed_callbacks() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("listener.txt");
        let script = format!(
            "import pathlib\nimport red_cell\n\
def on_listener(listener_id, action):\n    pathlib.Path({output:?}).write_text(listener_id + ':' + action)\n\
red_cell.on_listener_changed(on_listener)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("listener_cb.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        runtime
            .emit_listener_changed("https-listener".to_owned(), "start".to_owned())
            .unwrap_or_else(|error| panic!("emit_listener_changed should succeed: {error}"));

        assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("https-listener:start"));
    }

    #[test]
    fn event_registrar_exposes_new_event_methods() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("event_registrar.txt");
        let script = format!(
            "import pathlib\nimport havoc\n\
event = havoc.Event('test')\n\
def on_resp(agent_id, task_id, output):\n    pathlib.Path({output:?}).write_text('resp:' + agent_id)\n\
event.OnCommandResponse(on_resp)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("event_reg.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        runtime
            .emit_command_response("DEADBEEF".to_owned(), String::new(), "output".to_owned())
            .unwrap_or_else(|error| panic!("emit_command_response should succeed: {error}"));

        assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("resp:DEADBEEF"));
    }

    // ── options & history ────────────────────────────────────────────────────

    #[test]
    fn register_command_accepts_options_and_exposes_them_via_context() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("opts.txt");
        let script = format!(
            "import json\nimport pathlib\nimport red_cell\n\
def cmd(context):\n    opts = [dict(name=o.name, type=o.type, required=o.required, default=o.default) for o in context.options]\n    pathlib.Path({output:?}).write_text(json.dumps(opts))\n\
options = [\n    {{'name': 'target', 'type': 'string', 'required': True}},\n    {{'name': 'timeout', 'type': 'int', 'required': False, 'default': '30'}},\n    {{'name': 'verbose', 'type': 'bool', 'required': False}},\n    {{'name': 'output', 'type': 'file', 'required': False}},\n]\n\
red_cell.register_command('demo', cmd, options=options)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("opts.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let executed = runtime
            .execute_registered_command("00ABCDEF", "demo localhost")
            .unwrap_or_else(|error| panic!("registered command should run: {error}"));

        assert!(executed);
        let contents = wait_for_file_contents(&output_path)
            .unwrap_or_else(|| panic!("output file should be written"));
        let opts: Vec<serde_json::Value> =
            serde_json::from_str(&contents).expect("output should be valid JSON");
        assert_eq!(opts.len(), 4);
        assert_eq!(opts[0]["name"], "target");
        assert_eq!(opts[0]["type"], "string");
        assert_eq!(opts[0]["required"], true);
        assert_eq!(opts[0]["default"], serde_json::Value::Null);
        assert_eq!(opts[1]["name"], "timeout");
        assert_eq!(opts[1]["type"], "int");
        assert_eq!(opts[1]["required"], false);
        assert_eq!(opts[1]["default"], "30");
        assert_eq!(opts[2]["type"], "bool");
        assert_eq!(opts[3]["type"], "file");
    }

    #[test]
    fn command_history_is_empty_on_first_invocation_and_grows_on_subsequent() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("history.txt");
        let script = format!(
            "import json\nimport pathlib\nimport red_cell\n\
def cmd(context):\n    pathlib.Path({output:?}).write_text(json.dumps(context.history))\n\
red_cell.register_command('hist', cmd)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("hist.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // First invocation — history must be empty.
        runtime
            .execute_registered_command("00ABCDEF", "hist alpha")
            .unwrap_or_else(|e| panic!("should run: {e}"));
        let first = wait_for_file_contents(&output_path)
            .unwrap_or_else(|| panic!("output should be written"));
        let hist: Vec<String> = serde_json::from_str(&first).expect("valid JSON");
        assert!(hist.is_empty(), "history should be empty on first invocation");

        // Second invocation — history must contain the first command.
        std::fs::remove_file(&output_path).ok();
        runtime
            .execute_registered_command("00ABCDEF", "hist beta")
            .unwrap_or_else(|e| panic!("should run: {e}"));
        let second = wait_for_file_contents(&output_path)
            .unwrap_or_else(|| panic!("output should be written"));
        let hist: Vec<String> = serde_json::from_str(&second).expect("valid JSON");
        assert_eq!(hist, vec!["hist alpha".to_owned()]);

        // Third invocation — history contains both prior commands in order.
        std::fs::remove_file(&output_path).ok();
        runtime
            .execute_registered_command("00ABCDEF", "hist gamma")
            .unwrap_or_else(|e| panic!("should run: {e}"));
        let third = wait_for_file_contents(&output_path)
            .unwrap_or_else(|| panic!("output should be written"));
        let hist: Vec<String> = serde_json::from_str(&third).expect("valid JSON");
        assert_eq!(hist, vec!["hist alpha".to_owned(), "hist beta".to_owned()]);
    }

    #[test]
    fn command_history_is_scoped_per_agent() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("scoped_hist.txt");
        let script = format!(
            "import json\nimport pathlib\nimport red_cell\n\
def cmd(context):\n    pathlib.Path({output:?}).write_text(json.dumps(context.history))\n\
red_cell.register_command('scoped', cmd)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("scoped.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("AABBCCDD"));
            state.agents.push(sample_agent("11223344"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // Invoke on agent A.
        runtime
            .execute_registered_command("AABBCCDD", "scoped from_a")
            .unwrap_or_else(|e| panic!("should run: {e}"));
        let _ = wait_for_file_contents(&output_path);

        // Invoke on agent B — history must be empty (different agent).
        std::fs::remove_file(&output_path).ok();
        runtime
            .execute_registered_command("11223344", "scoped from_b")
            .unwrap_or_else(|e| panic!("should run: {e}"));
        let contents = wait_for_file_contents(&output_path)
            .unwrap_or_else(|| panic!("output should be written"));
        let hist: Vec<String> = serde_json::from_str(&contents).expect("valid JSON");
        assert!(hist.is_empty(), "agent B should start with empty history");
    }

    #[test]
    fn havocui_register_command_two_arg_form_is_backward_compatible() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("ui_cmd.txt");
        let script = format!(
            "import pathlib\nimport havocui\n\
def run(context):\n    pathlib.Path({output:?}).write_text('ok:' + context.command_line)\n\
havocui.RegisterCommand('ui cmd', run)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("ui_cmd.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let executed = runtime
            .execute_registered_command("00ABCDEF", "ui cmd")
            .unwrap_or_else(|e| panic!("should run: {e}"));
        assert!(executed);
        assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("ok:ui cmd"));
    }

    #[test]
    fn havocui_register_command_four_arg_form_exposes_description_and_options() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("ui_full.txt");
        let script = format!(
            "import json\nimport pathlib\nimport havocui\n\
def run(context):\n    payload = {{'description': context.description, 'options': [o.name for o in context.options]}}\n    pathlib.Path({output:?}).write_text(json.dumps(payload))\n\
havocui.RegisterCommand('recon scan', 'Run a recon scan', [{{'name': 'target', 'type': 'string', 'required': True}}], run)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("ui_full.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let executed = runtime
            .execute_registered_command("00ABCDEF", "recon scan 10.0.0.1")
            .unwrap_or_else(|e| panic!("should run: {e}"));
        assert!(executed);
        let contents = wait_for_file_contents(&output_path)
            .unwrap_or_else(|| panic!("output should be written"));
        let payload: serde_json::Value = serde_json::from_str(&contents).expect("valid JSON");
        assert_eq!(payload["description"], "Run a recon scan");
        assert_eq!(payload["options"], serde_json::json!(["target"]));
    }

    #[test]
    fn havocui_create_tab_rejects_empty_title() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

        // Script tries to create a tab with a whitespace-only title.
        let script = "import havocui\n\
            try:\n\
            \x20   havocui.CreateTab('   ')\n\
            except ValueError as e:\n\
            \x20   print(f'caught: {e}')\n";
        write_script(&temp_dir.path().join("empty_tab.py"), script);
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // The tab set must remain empty — the create call was rejected.
        assert!(runtime.script_tabs().is_empty(), "empty-title tab should not be registered");
        // The script should have caught the ValueError.
        assert!(
            wait_for_output(&runtime, "caught: tab title cannot be empty"),
            "script should log the caught ValueError"
        );
    }

    #[test]
    fn havocui_set_tab_layout_rejects_uncreated_tab() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

        // Script calls SetTabLayout on a tab that was never created.
        let script = "import havocui\n\
            try:\n\
            \x20   havocui.SetTabLayout('Ghost', '<html></html>')\n\
            except ValueError as e:\n\
            \x20   print(f'caught: {e}')\n";
        write_script(&temp_dir.path().join("layout_no_tab.py"), script);
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert!(runtime.script_tabs().is_empty(), "no tabs should be registered");
        assert!(
            wait_for_output(&runtime, "caught: havocui tab `Ghost` has not been created"),
            "script should log the caught ValueError for uncreated tab"
        );
    }

    #[test]
    fn havocui_set_tab_layout_rejects_cross_script_mutation() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

        // First script (alpha) creates a tab named "Dashboard".
        let script_alpha = "import havocui\n\
            havocui.CreateTab('Dashboard')\n";
        write_script(&temp_dir.path().join("alpha.py"), script_alpha);

        // Second script (beta) tries to mutate alpha's tab layout.
        let script_beta = "import havocui\n\
            try:\n\
            \x20   havocui.SetTabLayout('Dashboard', 'evil layout')\n\
            except ValueError as e:\n\
            \x20   print(f'caught: {e}')\n";
        write_script(&temp_dir.path().join("beta.py"), script_beta);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // Alpha's tab should still exist with an empty layout (never mutated).
        let tabs = runtime.script_tabs();
        assert_eq!(tabs.len(), 1, "only alpha's tab should be registered");
        assert_eq!(tabs[0].title, "Dashboard");
        assert_eq!(tabs[0].script_name, "alpha");
        assert_eq!(
            tabs[0].layout, "",
            "layout must remain empty — beta's mutation should have been rejected"
        );

        // Beta should have caught the cross-script error.
        assert!(
            wait_for_output(
                &runtime,
                "caught: havocui tab `Dashboard` belongs to a different script"
            ),
            "script should log the caught ValueError for cross-script mutation"
        );
    }

    // ── task_agent cleanup on enqueue failure ─────────────────────────────

    #[test]
    fn task_agent_cleans_up_waiter_when_no_sender_configured() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_mutex(&app_state);
            state.agents.push(sample_agent("AABB0001"));
        }

        let _runtime = PythonRuntime::initialize(app_state.clone(), temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // Do NOT attach an outgoing sender — queue_task_message should fail.
        let result = Python::with_gil(|py| -> PyResult<String> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            module.call_method("task_agent", ("AABB0001", "ps"), None)?.extract::<String>()
        });

        assert!(result.is_err(), "task_agent should fail when no sender is configured");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not connected"),
            "error should mention transport not connected, got: {err_msg}"
        );

        // Verify no stale waiter state was left behind.
        let api_state = Python::with_gil(|py| -> PyResult<Arc<PythonApiState>> {
            install_api_module(py)?;
            active_api_state()
        })
        .unwrap_or_else(|error| panic!("active_api_state should be available: {error}"));
        assert!(
            lock_mutex(&api_state.task_result_senders).is_empty(),
            "task_result_senders should be empty after enqueue failure"
        );
        assert!(
            lock_mutex(&api_state.task_result_receivers).is_empty(),
            "task_result_receivers should be empty after enqueue failure"
        );
    }

    #[test]
    fn task_agent_cleans_up_waiter_when_sender_is_closed() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_mutex(&app_state);
            state.agents.push(sample_agent("AABB0002"));
        }

        let runtime = PythonRuntime::initialize(app_state.clone(), temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // Attach a sender then immediately close it by dropping the receiver.
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<OperatorMessage>();
        runtime.set_outgoing_sender(tx);
        drop(rx);

        let result = Python::with_gil(|py| -> PyResult<String> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            module.call_method("task_agent", ("AABB0002", "ps"), None)?.extract::<String>()
        });

        assert!(result.is_err(), "task_agent should fail when the sender channel is closed");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("closed"),
            "error should mention the queue being closed, got: {err_msg}"
        );

        // Verify no stale waiter state was left behind.
        let api_state = Python::with_gil(|py| -> PyResult<Arc<PythonApiState>> {
            install_api_module(py)?;
            active_api_state()
        })
        .unwrap_or_else(|error| panic!("active_api_state should be available: {error}"));
        assert!(
            lock_mutex(&api_state.task_result_senders).is_empty(),
            "task_result_senders should be empty after closed-sender enqueue failure"
        );
        assert!(
            lock_mutex(&api_state.task_result_receivers).is_empty(),
            "task_result_receivers should be empty after closed-sender enqueue failure"
        );
    }

    // ---------------------------------------------------------------
    // Error-path tests: invalid callbacks and option-schema failures
    // ---------------------------------------------------------------

    #[test]
    fn register_command_rejects_non_callable_callback() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("bad_cb.py"),
            "import red_cell\nred_cell.register_command('oops', 'not_a_function')\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert!(
            runtime.command_names().is_empty(),
            "no command should be registered when the callback is not callable"
        );
        let descriptor = runtime
            .script_descriptors()
            .into_iter()
            .find(|s| s.name == "bad_cb")
            .expect("script descriptor should exist");
        assert_eq!(descriptor.status, ScriptLoadStatus::Error);
        assert!(
            descriptor.error.as_ref().is_some_and(|e| e.contains("callback must be callable")),
            "error should mention non-callable callback, got: {:?}",
            descriptor.error,
        );
    }

    #[test]
    fn havocui_register_command_rejects_non_callable_callback() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("bad_ui_cb.py"),
            "import havocui\nhavocui.RegisterCommand('oops', 42)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert!(
            runtime.command_names().is_empty(),
            "no command should be registered when havocui callback is not callable"
        );
        let descriptor = runtime
            .script_descriptors()
            .into_iter()
            .find(|s| s.name == "bad_ui_cb")
            .expect("script descriptor should exist");
        assert_eq!(descriptor.status, ScriptLoadStatus::Error);
        assert!(
            descriptor
                .error
                .as_ref()
                .is_some_and(|e| { e.contains("callable") || e.contains("callback") }),
            "error should mention callable requirement, got: {:?}",
            descriptor.error,
        );
    }

    #[test]
    fn register_callback_rejects_non_callable() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("bad_event.py"),
            "import red_cell\nred_cell.register_callback('agent_checkin', 'not_callable')\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let descriptor = runtime
            .script_descriptors()
            .into_iter()
            .find(|s| s.name == "bad_event")
            .expect("script descriptor should exist");
        assert_eq!(descriptor.status, ScriptLoadStatus::Error);
        assert!(
            descriptor.error.as_ref().is_some_and(|e| e.contains("callback must be callable")),
            "error should mention non-callable callback, got: {:?}",
            descriptor.error,
        );
    }

    #[test]
    fn register_callback_rejects_unsupported_event_type() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("bad_event_type.py"),
            "import red_cell\nred_cell.register_callback('no_such_event', lambda: None)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let descriptor = runtime
            .script_descriptors()
            .into_iter()
            .find(|s| s.name == "bad_event_type")
            .expect("script descriptor should exist");
        assert_eq!(descriptor.status, ScriptLoadStatus::Error);
        assert!(
            descriptor.error.as_ref().is_some_and(|e| e.contains("unsupported client callback")),
            "error should mention unsupported event type, got: {:?}",
            descriptor.error,
        );
    }

    #[test]
    fn register_command_rejects_malformed_options_item() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        // Options list contains a string instead of a dict.
        write_script(
            &temp_dir.path().join("bad_opts.py"),
            "import red_cell\nred_cell.register_command('oops', lambda a, b: None, options=['not_a_dict'])\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert!(
            runtime.command_names().is_empty(),
            "no command should be registered with a malformed options list"
        );
        let descriptor = runtime
            .script_descriptors()
            .into_iter()
            .find(|s| s.name == "bad_opts")
            .expect("script descriptor should exist");
        assert_eq!(descriptor.status, ScriptLoadStatus::Error);
        assert!(
            descriptor.error.as_ref().is_some_and(|e| e.contains("each option must be a dict")),
            "error should mention dict requirement, got: {:?}",
            descriptor.error,
        );
    }

    #[test]
    fn register_command_rejects_unknown_option_type() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("bad_type.py"),
            "import red_cell\nred_cell.register_command(\n    'oops', lambda a, b: None,\n    options=[{'name': 'x', 'type': 'quaternion'}]\n)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert!(
            runtime.command_names().is_empty(),
            "no command should be registered with an unknown option type"
        );
        let descriptor = runtime
            .script_descriptors()
            .into_iter()
            .find(|s| s.name == "bad_type")
            .expect("script descriptor should exist");
        assert_eq!(descriptor.status, ScriptLoadStatus::Error);
        assert!(
            descriptor
                .error
                .as_ref()
                .is_some_and(|e| e.contains("unknown option type `quaternion`")),
            "error should mention unknown option type, got: {:?}",
            descriptor.error,
        );
    }

    #[test]
    fn register_command_rejects_option_missing_name() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("no_name.py"),
            "import red_cell\nred_cell.register_command(\n    'oops', lambda a, b: None,\n    options=[{'type': 'string'}]\n)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert!(
            runtime.command_names().is_empty(),
            "no command should be registered when option name is missing"
        );
        let descriptor = runtime
            .script_descriptors()
            .into_iter()
            .find(|s| s.name == "no_name")
            .expect("script descriptor should exist");
        assert_eq!(descriptor.status, ScriptLoadStatus::Error);
        assert!(
            descriptor.error.as_ref().is_some_and(|e| e.contains("option is missing 'name'")),
            "error should mention missing name, got: {:?}",
            descriptor.error,
        );
    }

    #[test]
    fn havocui_register_command_rejects_unknown_option_type() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("ui_bad_type.py"),
            "import havocui\nhavocui.RegisterCommand(\n    'oops', 'desc',\n    [{'name': 'x', 'type': 'imaginary'}],\n    lambda: None\n)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert!(
            runtime.command_names().is_empty(),
            "no command should be registered with an unknown option type via havocui"
        );
        let descriptor = runtime
            .script_descriptors()
            .into_iter()
            .find(|s| s.name == "ui_bad_type")
            .expect("script descriptor should exist");
        assert_eq!(descriptor.status, ScriptLoadStatus::Error);
        assert!(
            descriptor
                .error
                .as_ref()
                .is_some_and(|e| e.contains("unknown option type `imaginary`")),
            "error should mention unknown option type, got: {:?}",
            descriptor.error,
        );
    }

    #[test]
    fn register_command_rejects_non_iterable_options() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("opts_int.py"),
            "import red_cell\nred_cell.register_command('oops', lambda a, b: None, options=999)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert!(
            runtime.command_names().is_empty(),
            "no command should be registered when options is not iterable"
        );
        let descriptor = runtime
            .script_descriptors()
            .into_iter()
            .find(|s| s.name == "opts_int")
            .expect("script descriptor should exist");
        assert_eq!(descriptor.status, ScriptLoadStatus::Error);
        assert!(
            descriptor.error.as_ref().is_some_and(|e| e.contains("options must be a list")),
            "error should mention list requirement, got: {:?}",
            descriptor.error,
        );
    }

    #[test]
    fn script_output_evicts_oldest_entries_at_capacity() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

        // Generate a script that creates 520 distinct output entries by alternating
        // between stdout and stderr (preventing coalescing of consecutive entries).
        let total_entries = MAX_SCRIPT_OUTPUT_ENTRIES + 8; // 520
        let script = format!(
            "import sys\nfor i in range({total_entries}):\n\
             \x20   if i % 2 == 0:\n\
             \x20       sys.stdout.write(f'out-{{i}}\\n')\n\
             \x20       sys.stdout.flush()\n\
             \x20   else:\n\
             \x20       sys.stderr.write(f'err-{{i}}\\n')\n\
             \x20       sys.stderr.flush()\n",
        );
        write_script(&temp_dir.path().join("flood.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // Wait until the last entry appears in the output log.
        let last_marker = format!("err-{}", total_entries - 1);
        assert!(wait_for_output(&runtime, &last_marker), "last output entry should appear",);

        let output = runtime.script_output();
        assert!(
            output.len() <= MAX_SCRIPT_OUTPUT_ENTRIES,
            "output log should be capped at {MAX_SCRIPT_OUTPUT_ENTRIES}, got {}",
            output.len(),
        );

        // The oldest entries (indices 0..8) should have been evicted.
        let has_evicted_entry = output.iter().any(|e| e.text.contains("out-0\n"));
        assert!(!has_evicted_entry, "oldest entry (out-0) should have been evicted",);

        // The newest entries should still be present.
        let has_newest = output.iter().any(|e| e.text.contains(&last_marker));
        assert!(has_newest, "newest entry should still be present");
    }

    #[test]
    fn command_history_evicts_oldest_entries_at_capacity() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let output_path = temp_dir.path().join("hist_cap.txt");

        // Register a command that writes the history snapshot to a file.
        let script = format!(
            "import json\nimport pathlib\nimport red_cell\n\
            def cmd(context):\n    pathlib.Path({output:?}).write_text(json.dumps(context.history))\n\
            red_cell.register_command('hcap', cmd)\n",
            output = output_path.display().to_string()
        );
        write_script(&temp_dir.path().join("hcap.py"), &script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("DEADBEEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let total_invocations = MAX_COMMAND_HISTORY + 5; // 105

        // Invoke the command 105 times to overflow the history buffer.
        for i in 0..total_invocations {
            std::fs::remove_file(&output_path).ok();
            runtime
                .execute_registered_command("DEADBEEF", &format!("hcap call-{i}"))
                .unwrap_or_else(|e| panic!("invocation {i} should run: {e}"));
            let _ = wait_for_file_contents(&output_path)
                .unwrap_or_else(|| panic!("output should be written for invocation {i}"));
        }

        // Invoke once more (the 106th call) — the snapshot should contain exactly
        // MAX_COMMAND_HISTORY entries, with the oldest 5 evicted.
        std::fs::remove_file(&output_path).ok();
        runtime
            .execute_registered_command("DEADBEEF", "hcap final")
            .unwrap_or_else(|e| panic!("final invocation should run: {e}"));
        let final_output = wait_for_file_contents(&output_path)
            .unwrap_or_else(|| panic!("output should be written for final invocation"));
        let history: Vec<String> = serde_json::from_str(&final_output)
            .unwrap_or_else(|e| panic!("history should be valid JSON: {e}"));

        assert_eq!(
            history.len(),
            MAX_COMMAND_HISTORY,
            "history should be capped at {MAX_COMMAND_HISTORY}, got {}",
            history.len(),
        );

        // The oldest entries (call-0 through call-4) should have been evicted.
        for evicted_idx in 0..5 {
            let evicted = format!("hcap call-{evicted_idx}");
            assert!(
                !history.iter().any(|h| *h == evicted),
                "entry {evicted} should have been evicted",
            );
        }

        // The first entry in the snapshot should be call-5 (the 6th invocation).
        assert_eq!(
            history[0], "hcap call-5",
            "first history entry should be call-5 after eviction",
        );

        // The last entry should be the 105th invocation (call-104).
        assert_eq!(
            history[MAX_COMMAND_HISTORY - 1],
            format!("hcap call-{}", total_invocations - 1),
            "last history entry should be the most recent invocation before the final call",
        );
    }

    #[test]
    fn execute_registered_command_captures_callback_exception() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let script = "import red_cell\n\
def boom(agent, args):\n    raise RuntimeError('plugin exploded')\n\
red_cell.register_command('boom', boom)\n";
        write_script(&temp_dir.path().join("boom.py"), script);

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            state.agents.push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let result = runtime.execute_registered_command("00ABCDEF", "boom");
        assert!(
            result.is_err(),
            "execute_registered_command should return an error when the callback raises"
        );
        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains("plugin exploded"),
            "error should contain the exception message, got: {error_message}"
        );

        // The runtime should still be functional after the exception.
        let second = runtime.execute_registered_command("00ABCDEF", "boom");
        assert!(second.is_err(), "callback should still raise on second invocation");
    }

    #[test]
    fn reload_script_returns_error_for_unknown_script() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let result = runtime.reload_script("nonexistent_plugin");
        assert!(result.is_err(), "reload_script should return an error for an unknown script name");
        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains("nonexistent_plugin"),
            "error should mention the script name, got: {error_message}"
        );
    }

    #[test]
    fn unload_script_twice_is_idempotent() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("ephemeral.py"),
            "import red_cell\nred_cell.register_command('temp', lambda: None)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert_eq!(runtime.command_names(), vec!["temp".to_owned()]);

        runtime
            .unload_script("ephemeral")
            .unwrap_or_else(|error| panic!("first unload should succeed: {error}"));
        assert!(runtime.command_names().is_empty());
        assert!(
            runtime
                .script_descriptors()
                .iter()
                .find(|s| s.name == "ephemeral")
                .is_some_and(|s| s.status == ScriptLoadStatus::Unloaded)
        );

        // Second unload of the same script should also succeed.
        runtime
            .unload_script("ephemeral")
            .unwrap_or_else(|error| panic!("second unload should succeed (idempotent): {error}"));
        assert!(
            runtime
                .script_descriptors()
                .iter()
                .find(|s| s.name == "ephemeral")
                .is_some_and(|s| s.status == ScriptLoadStatus::Unloaded)
        );
    }

    #[test]
    fn load_script_registers_command_and_descriptor() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        // Initialize runtime with an empty directory — no scripts loaded yet.
        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));
        assert!(runtime.command_names().is_empty(), "no commands before load");
        assert!(runtime.script_descriptors().is_empty(), "no descriptors before load");

        // Write a script and load it via load_script.
        let script_path = temp_dir.path().join("plugin.py");
        write_script(
            &script_path,
            "import red_cell\nred_cell.register_command('greet', lambda: None)\n",
        );
        runtime
            .load_script(script_path.clone())
            .unwrap_or_else(|error| panic!("load_script should succeed: {error}"));

        assert_eq!(runtime.command_names(), vec!["greet".to_owned()]);
        assert_eq!(
            runtime.script_descriptors(),
            vec![ScriptDescriptor {
                name: "plugin".to_owned(),
                path: script_path,
                status: ScriptLoadStatus::Loaded,
                error: None,
                registered_commands: vec!["greet".to_owned()],
                registered_command_count: 1,
            }]
        );
    }

    #[test]
    fn load_script_nonexistent_path_returns_error() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let result = runtime.load_script(temp_dir.path().join("nonexistent.py"));
        assert!(result.is_err(), "load_script with a nonexistent path should return an error");
        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains("nonexistent"),
            "error should reference the missing file, got: {error_message}"
        );
    }

    #[test]
    fn load_script_twice_is_idempotent() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        let script_path = temp_dir.path().join("twice.py");
        write_script(
            &script_path,
            "import red_cell\nred_cell.register_command('cmd', lambda: None)\n",
        );

        runtime
            .load_script(script_path.clone())
            .unwrap_or_else(|error| panic!("first load should succeed: {error}"));
        runtime
            .load_script(script_path.clone())
            .unwrap_or_else(|error| panic!("second load should succeed: {error}"));

        // Command should appear exactly once — not duplicated.
        assert_eq!(runtime.command_names(), vec!["cmd".to_owned()]);
        assert_eq!(
            runtime.script_descriptors().len(),
            1,
            "only one script descriptor should exist after loading twice"
        );
        assert_eq!(runtime.script_descriptors()[0].registered_command_count, 1);
    }

    // --- ThreadUnavailable regression tests ---
    // These tests verify that every dispatch method returns
    // Err(PythonRuntimeError::ThreadUnavailable) when the internal command
    // channel is closed (e.g. Python thread crashed or was dropped).
    //
    // Each test acquires TEST_GUARD to serialize with other Python tests and
    // avoid concurrent GIL / ACTIVE_RUNTIME state races.

    #[test]
    fn emit_agent_checkin_returns_thread_unavailable_on_zombie_runtime() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();
        let result = runtime.emit_agent_checkin("dead-agent-id".to_owned());
        assert!(
            matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
            "expected ThreadUnavailable, got: {result:?}"
        );
    }

    #[test]
    fn emit_command_response_returns_thread_unavailable_on_zombie_runtime() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();
        let result = runtime.emit_command_response(
            "dead-agent".to_owned(),
            "task-1".to_owned(),
            "output".to_owned(),
        );
        assert!(
            matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
            "expected ThreadUnavailable, got: {result:?}"
        );
    }

    #[test]
    fn emit_loot_captured_returns_thread_unavailable_on_zombie_runtime() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();
        let loot =
            sample_loot_item("dead-agent", crate::transport::LootKind::Credential, "hash", None);
        let result = runtime.emit_loot_captured(loot);
        assert!(
            matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
            "expected ThreadUnavailable, got: {result:?}"
        );
    }

    #[test]
    fn emit_listener_changed_returns_thread_unavailable_on_zombie_runtime() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();
        let result = runtime.emit_listener_changed("https-443".to_owned(), "started".to_owned());
        assert!(
            matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
            "expected ThreadUnavailable, got: {result:?}"
        );
    }

    #[test]
    fn execute_registered_command_returns_thread_unavailable_on_zombie_runtime() {
        let _guard = lock_mutex(&TEST_GUARD);
        // new_zombie_for_test registers a "zombie" command so match_registered_command
        // succeeds and the send path is exercised.
        let runtime = PythonRuntime::new_zombie_for_test();
        let result = runtime.execute_registered_command("dead-agent", "zombie");
        assert!(
            matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
            "expected ThreadUnavailable, got: {result:?}"
        );
    }

    #[test]
    fn activate_tab_returns_thread_unavailable_on_zombie_runtime() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();
        let result = runtime.activate_tab("some-tab");
        assert!(
            matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
            "expected ThreadUnavailable, got: {result:?}"
        );
    }

    #[test]
    fn load_script_returns_thread_unavailable_on_zombie_runtime() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();
        let result = runtime.load_script("/tmp/nonexistent.py".into());
        assert!(
            matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
            "expected ThreadUnavailable, got: {result:?}"
        );
    }

    #[test]
    fn reload_script_returns_thread_unavailable_on_zombie_runtime() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();
        let result = runtime.reload_script("some_script");
        assert!(
            matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
            "expected ThreadUnavailable, got: {result:?}"
        );
    }

    #[test]
    fn unload_script_returns_thread_unavailable_on_zombie_runtime() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();
        let result = runtime.unload_script("some_script");
        assert!(
            matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
            "expected ThreadUnavailable, got: {result:?}"
        );
    }
}
