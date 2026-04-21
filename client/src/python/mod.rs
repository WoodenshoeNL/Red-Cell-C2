//! Embedded Python runtime for client-side automation.

mod callbacks;
mod plugin;
mod runtime;
mod script;

use callbacks::{EventCallback, RegisteredAgentCheckinCallback};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use red_cell_common::operator::OperatorMessage;
use tokio::sync::mpsc::UnboundedSender;
use tracing::error;

use crate::transport::{AgentSummary, AppState, ListenerSummary, SharedAppState};

pub(crate) use plugin::{PyAgent, PyLootItem, ensure_callable, normalize_agent_id};
pub(crate) use runtime::PythonRuntime;
use runtime::PythonThreadCommand;

thread_local! {
    /// When set, a Python callback or script entrypoint is active on this thread (used for mutex
    /// poison diagnostics).
    static PYTHON_CALLBACK_CONTEXT: RefCell<Option<(String, &'static str)>> = const { RefCell::new(None) };
}

static ACTIVE_RUNTIME: OnceLock<Mutex<Option<Arc<PythonApiState>>>> = OnceLock::new();
const MAX_SCRIPT_OUTPUT_ENTRIES: usize = 512;
const MAX_COMMAND_HISTORY: usize = 100;
/// Default per-invocation timeout for Python script callbacks (seconds).
const DEFAULT_SCRIPT_TIMEOUT_SECS: u64 = 10;

fn active_runtime_slot() -> &'static Mutex<Option<Arc<PythonApiState>>> {
    ACTIVE_RUNTIME.get_or_init(|| Mutex::new(None))
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
    commands: Mutex<BTreeMap<String, plugin::RegisteredCommand>>,
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
    /// Per-invocation timeout for Python script callbacks (seconds).
    ///
    /// A watchdog injects `KeyboardInterrupt` if a callback does not return
    /// within this many seconds.  Updated atomically so the GUI can adjust it
    /// without restarting the runtime.
    script_timeout_secs: AtomicU64,
    /// `threading.get_ident()` value of the dedicated Python thread.
    ///
    /// Stored at thread startup and used by watchdog threads to target
    /// `ctypes.pythonapi.PyThreadState_SetAsyncExc`.  Zero means the thread
    /// has not yet stored its identity.
    python_thread_id: AtomicU64,
}

/// Result delivered to a `get_task_result` waiter.
#[derive(Debug, Clone)]
struct TaskResult {
    agent_id: String,
    output: String,
}

impl PythonApiState {
    /// `callback_kind`, when set, is included in ERROR logs if a mutex is poisoned while this
    /// script runs.
    pub(super) fn begin_script_execution(
        &self,
        script_name: &str,
        callback_kind: Option<&'static str>,
    ) {
        *lock_mutex(&self.current_script) = Some(script_name.to_owned());
        PYTHON_CALLBACK_CONTEXT.with(|c| {
            *c.borrow_mut() = callback_kind.map(|k| (script_name.to_owned(), k));
        });
    }

    fn end_script_execution(&self) {
        *lock_mutex(&self.current_script) = None;
        PYTHON_CALLBACK_CONTEXT.with(|c| {
            *c.borrow_mut() = None;
        });
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

    fn register_tab(&self, title: String, callback: Option<Py<PyAny>>) -> PyResult<()> {
        let script_name = self.current_script_name().ok_or_else(|| {
            PyRuntimeError::new_err("havocui.CreateTab must be called while a script loads")
        })?;
        let normalized_title = plugin::normalize_tab_title(&title)?;
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
        let normalized_title = plugin::normalize_tab_title(title)?;
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

    fn agent_snapshot(&self, agent_id: &str) -> Option<AgentSummary> {
        let normalized = plugin::normalize_agent_id(agent_id);
        let state = lock_app_state(&self.app_state);
        state.agents.iter().find(|agent| agent.name_id == normalized).cloned()
    }

    fn agent_snapshots(&self) -> Arc<Vec<AgentSummary>> {
        let state = lock_app_state(&self.app_state);
        Arc::clone(&state.agents)
    }

    fn listener_snapshot(&self, name: &str) -> Option<ListenerSummary> {
        let normalized = plugin::normalize_listener_name(name);
        let state = lock_app_state(&self.app_state);
        state.listeners.iter().find(|listener| listener.name == normalized).cloned()
    }

    fn listener_snapshots(&self) -> Arc<Vec<ListenerSummary>> {
        let state = lock_app_state(&self.app_state);
        Arc::clone(&state.listeners)
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
                    if item.agent_id != plugin::normalize_agent_id(id) {
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

    fn activate_tab(&self, py: Python<'_>, title: &str) -> Result<(), String> {
        let normalized_title =
            plugin::normalize_tab_title(title).map_err(|error| error.to_string())?;
        let tab = {
            let tabs = lock_mutex(&self.script_tabs);
            tabs.get(&normalized_title).cloned()
        }
        .ok_or_else(|| format!("havocui tab `{normalized_title}` is not registered"))?;
        if !tab.has_callback {
            return Ok(());
        }

        let command_name = plugin::normalize_command_name(&format!("__tab__ {normalized_title}"));
        self.execute_registered_command(py, &command_name, "", &normalized_title, &[])?;
        Ok(())
    }
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

fn install_api_module(py: Python<'_>) -> PyResult<()> {
    let sys = py.import("sys")?;
    let modules = sys.getattr("modules")?;
    let module = PyModule::new(py, "red_cell")?;
    plugin::populate_api_module(&module)?;
    modules.set_item("red_cell", module)?;
    modules.set_item("havoc", modules.get_item("red_cell")?)?;
    let havocui = PyModule::new(py, "havocui")?;
    plugin::populate_havocui_module(&havocui)?;
    modules.set_item("havocui", havocui)?;
    Ok(())
}

fn install_output_capture(py: Python<'_>) -> PyResult<()> {
    let sys = py.import("sys")?;
    sys.setattr(
        "stdout",
        Py::new(py, plugin::PyOutputSink { stream: ScriptOutputStream::Stdout })?,
    )?;
    sys.setattr(
        "stderr",
        Py::new(py, plugin::PyOutputSink { stream: ScriptOutputStream::Stderr })?,
    )?;
    Ok(())
}

fn active_api_state() -> PyResult<Arc<PythonApiState>> {
    lock_mutex(active_runtime_slot())
        .clone()
        .ok_or_else(|| PyRuntimeError::new_err("red_cell Python runtime is not initialized"))
}

fn python_callback_context_for_log() -> Option<String> {
    PYTHON_CALLBACK_CONTEXT
        .with(|c| c.borrow().as_ref().map(|(script, kind)| format!("{kind} (script `{script}`)")))
}

fn lock_mutex<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        let callback_context = python_callback_context_for_log();
        error!(
            target: "red_cell_client::python",
            callback_context = callback_context.as_deref().unwrap_or("(unknown)"),
            "python runtime mutex poisoned — recovering inner state; previous holder panicked (state may be inconsistent)"
        );
        poisoned.into_inner()
    })
}

fn lock_app_state(app_state: &SharedAppState) -> std::sync::MutexGuard<'_, AppState> {
    app_state.lock().unwrap_or_else(|poisoned| {
        let callback_context = python_callback_context_for_log();
        error!(
            target: "red_cell_client::python",
            callback_context = callback_context.as_deref().unwrap_or("(unknown)"),
            "app state mutex poisoned while in python module — recovering inner state; previous holder panicked (state may be inconsistent)"
        );
        poisoned.into_inner()
    })
}

fn current_operator_username(app_state: &SharedAppState) -> String {
    let state = lock_app_state(app_state);
    state.operator_info.as_ref().map(|operator| operator.username.clone()).unwrap_or_default()
}

#[cfg(test)]
mod tests;
