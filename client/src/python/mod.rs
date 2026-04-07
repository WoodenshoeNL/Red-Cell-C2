//! Embedded Python runtime for client-side automation.

mod callbacks;
mod plugin;
mod script;

use callbacks::{EventCallback, RegisteredAgentCheckinCallback};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use red_cell_common::operator::OperatorMessage;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, warn};

use crate::transport::{AgentSummary, AppState, ListenerSummary, SharedAppState};

pub(crate) use plugin::{PyAgent, PyLootItem, ensure_callable, normalize_agent_id};

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
            script_timeout_secs: AtomicU64::new(DEFAULT_SCRIPT_TIMEOUT_SECS),
            python_thread_id: AtomicU64::new(0),
        });
        *lock_mutex(active_runtime_slot()) = Some(api_state.clone());

        let (command_tx, command_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread_api_state = api_state.clone();
        let handle = thread::Builder::new()
            .name("red-cell-client-python".to_owned())
            .spawn(move || {
                if let Err(error) =
                    script::python_thread_main(thread_api_state, scripts_dir, command_rx, ready_tx)
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

    /// Override the per-invocation timeout for Python script callbacks.
    ///
    /// Any callback that does not return within `secs` seconds will receive a
    /// `KeyboardInterrupt` and an `ERROR`-level log message will be emitted.
    /// The default is [`DEFAULT_SCRIPT_TIMEOUT_SECS`] (10 seconds).
    pub(crate) fn set_script_timeout(&self, secs: u64) {
        self.inner.api_state.script_timeout_secs.store(secs, Ordering::Relaxed);
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
            script_timeout_secs: AtomicU64::new(DEFAULT_SCRIPT_TIMEOUT_SECS),
            python_thread_id: AtomicU64::new(0),
        });
        let (command_tx, command_rx) = mpsc::channel();
        drop(command_rx);

        Python::with_gil(|py| {
            lock_mutex(&api_state.commands).insert(
                "zombie".to_owned(),
                plugin::RegisteredCommand {
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
mod tests {
    use std::path::Path;
    use std::time::{Duration, Instant};

    use pyo3::types::IntoPyDict;
    use red_cell_common::demon::DemonCommand;
    use tempfile::TempDir;

    use super::*;
    use crate::transport::LootItem;

    static TEST_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn lock_mutex_recovers_from_poison() {
        let m = Mutex::new(42u32);
        let _ = std::panic::catch_unwind(|| {
            let _g = m.lock().expect("lock for poison test");
            panic!("intentional test poison");
        });
        assert!(m.is_poisoned());
        let guard = lock_mutex(&m);
        assert_eq!(*guard, 42);
    }

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
                if !contents.is_empty() {
                    return Some(contents);
                }
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
            Arc::make_mut(&mut state.listeners).push(sample_listener("https"));
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
            Arc::make_mut(&mut state.loot).push(sample_loot_item(
                "00AABBCC",
                crate::transport::LootKind::Credential,
                "cred-1",
                Some("dXNlcjpwYXNz"),
            ));
            Arc::make_mut(&mut state.loot).push(sample_loot_item(
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
            Arc::make_mut(&mut state.loot).push(sample_loot_item(
                "00AABBCC",
                crate::transport::LootKind::Credential,
                "cred-1",
                Some("dXNlcjpwYXNz"),
            ));
            Arc::make_mut(&mut state.loot).push(sample_loot_item(
                "00AABBCC",
                crate::transport::LootKind::File,
                "file-1",
                Some("ZmlsZWNvbnRlbnQ="),
            ));
            Arc::make_mut(&mut state.loot).push(sample_loot_item(
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
            Arc::make_mut(&mut state.agents).push(sample_agent("AABBCCDD"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("11223344"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("DEADBEEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("AABBCCDD"));
            Arc::make_mut(&mut state.agents).push(sample_agent("11223344"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("AABB0001"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("AABB0002"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("DEADBEEF"));
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
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
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

    #[test]
    fn script_output_returns_empty_before_any_output() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();
        assert!(
            runtime.script_output().is_empty(),
            "script_output should be empty before any script emits"
        );
    }

    #[test]
    fn script_output_captures_correct_stream_and_text() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("streams.py"),
            "import sys\nprint('out-marker')\nprint('err-marker', file=sys.stderr)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert!(wait_for_output(&runtime, "out-marker"), "stdout entry should appear");
        assert!(wait_for_output(&runtime, "err-marker"), "stderr entry should appear");

        let entries = runtime.script_output();
        let stdout_entry =
            entries.iter().find(|e| e.text.contains("out-marker")).expect("stdout entry missing");
        assert_eq!(stdout_entry.stream, ScriptOutputStream::Stdout);
        assert_eq!(stdout_entry.script_name, "streams");

        let stderr_entry =
            entries.iter().find(|e| e.text.contains("err-marker")).expect("stderr entry missing");
        assert_eq!(stderr_entry.stream, ScriptOutputStream::Stderr);
        assert_eq!(stderr_entry.script_name, "streams");
    }

    #[test]
    fn script_tabs_returns_empty_before_any_createtab_call() {
        let _guard = lock_mutex(&TEST_GUARD);
        let runtime = PythonRuntime::new_zombie_for_test();
        assert!(
            runtime.script_tabs().is_empty(),
            "script_tabs should be empty before any CreateTab"
        );
    }

    #[test]
    fn script_tabs_is_empty_after_unloading_registering_script() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("tabscript.py"),
            "import havocui\ndef render(): pass\nhavocui.CreateTab('Panel', render)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        assert_eq!(
            runtime.script_tabs(),
            vec![ScriptTabDescriptor {
                title: "Panel".to_owned(),
                script_name: "tabscript".to_owned(),
                layout: String::new(),
                has_callback: true,
            }],
            "tab should be present after script load"
        );

        runtime
            .unload_script("tabscript")
            .unwrap_or_else(|error| panic!("unload should succeed: {error}"));

        assert!(
            runtime.script_tabs().is_empty(),
            "script_tabs should be empty after unloading the registering script"
        );
    }

    #[test]
    fn script_output_collects_from_two_concurrent_scripts() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        write_script(
            &temp_dir.path().join("alpha.py"),
            "import red_cell\ndef on_checkin(agent):\n    print('alpha:' + agent.id)\nred_cell.on_agent_checkin(on_checkin)\n",
        );
        write_script(
            &temp_dir.path().join("beta.py"),
            "import red_cell\ndef on_checkin(agent):\n    print('beta:' + agent.id)\nred_cell.on_agent_checkin(on_checkin)\n",
        );
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        {
            let mut state = lock_app_state(&app_state);
            Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
        }

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // Fire two checkin events from separate threads to exercise concurrent output writes.
        let r1 = runtime.clone();
        let r2 = runtime.clone();
        let t1 = thread::spawn(move || {
            r1.emit_agent_checkin("00ABCDEF".to_owned())
                .unwrap_or_else(|error| panic!("checkin dispatch should succeed: {error}"));
        });
        let t2 = thread::spawn(move || {
            r2.emit_agent_checkin("00ABCDEF".to_owned())
                .unwrap_or_else(|error| panic!("checkin dispatch should succeed: {error}"));
        });
        t1.join().unwrap_or_else(|_| panic!("thread 1 should not panic"));
        t2.join().unwrap_or_else(|_| panic!("thread 2 should not panic"));

        // Each script fires once per emit call, and we fired two; expect at least one from each.
        assert!(
            wait_for_output_occurrences(&runtime, "alpha:00ABCDEF", 1),
            "alpha script output should appear"
        );
        assert!(
            wait_for_output_occurrences(&runtime, "beta:00ABCDEF", 1),
            "beta script output should appear"
        );
    }

    #[test]
    fn set_script_timeout_updates_stored_value() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // Default is 10 s.
        assert_eq!(
            runtime.inner.api_state.script_timeout_secs.load(std::sync::atomic::Ordering::Relaxed),
            DEFAULT_SCRIPT_TIMEOUT_SECS,
        );

        runtime.set_script_timeout(30);
        assert_eq!(
            runtime.inner.api_state.script_timeout_secs.load(std::sync::atomic::Ordering::Relaxed),
            30,
        );
    }

    /// A script containing an infinite loop must be interrupted via
    /// `KeyboardInterrupt` within the watchdog timeout window.
    ///
    /// We set a very short timeout (1 s) so the test finishes quickly.
    /// The script prints "before" before entering the loop and must NOT
    /// print "after" (which it would only reach if the loop returned normally).
    #[test]
    fn timeout_interrupts_infinite_loop_in_registered_command() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

        write_script(
            &temp_dir.path().join("loopy.py"),
            "import red_cell, sys\ndef loopy():\n    sys.stdout.write('before\\n')\n    sys.stdout.flush()\n    while True:\n        pass\n    sys.stdout.write('after\\n')\nred_cell.register_command('loopy', loopy)\n",
        );

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // Set a 1-second timeout so the test is fast.
        runtime.set_script_timeout(1);

        // Dispatch the command — it should return (interrupted) rather than hang.
        let started = Instant::now();
        let result = runtime.execute_registered_command("agent-0", "loopy");
        let elapsed = started.elapsed();

        // The command must complete well within 5 s (generous upper bound).
        assert!(
            elapsed < Duration::from_secs(5),
            "command dispatch blocked for {elapsed:?}; expected interrupt within 5 s"
        );

        // The callback raised KeyboardInterrupt so execute_registered_command
        // returns Err (CommandFailed) — not Ok.
        assert!(result.is_err(), "expected Err from timed-out callback, got Ok");

        // "before" must have been written; "after" must not.
        assert!(wait_for_output(&runtime, "before"), "'before' should appear before the loop");
        let any_after = runtime.script_output().iter().any(|e| e.text.contains("after"));
        assert!(!any_after, "'after' should not appear — loop must have been interrupted");
    }

    /// After an agent-checkin callback with an infinite loop is interrupted by
    /// the watchdog, the Python thread must remain responsive and able to
    /// process the next event.
    #[test]
    fn timeout_interrupts_infinite_loop_in_agent_checkin_callback() {
        let _guard = lock_mutex(&TEST_GUARD);
        let temp_dir =
            TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

        // Script 1: loops indefinitely in the checkin callback.
        write_script(
            &temp_dir.path().join("hang_checkin.py"),
            "import red_cell, sys\ndef on_checkin(agent_id):\n    sys.stdout.write('checkin_before\\n')\n    sys.stdout.flush()\n    while True:\n        pass\nred_cell.on_agent_checkin(on_checkin)\n",
        );
        // Script 2: registers a fast command so we can verify the thread recovers.
        write_script(
            &temp_dir.path().join("recover.py"),
            "import red_cell, sys\ndef ping():\n    sys.stdout.write('pong\\n')\nred_cell.register_command('ping', ping)\n",
        );

        let app_state =
            Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
        let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
            .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

        // 1-second watchdog so this test finishes quickly.
        runtime.set_script_timeout(1);

        // Dispatch the looping checkin callback (fire-and-forget).
        runtime
            .emit_agent_checkin("DEADBEEF".to_owned())
            .unwrap_or_else(|error| panic!("emit should succeed: {error}"));

        // Wait until the callback has started (written its marker).
        assert!(
            wait_for_output(&runtime, "checkin_before"),
            "'checkin_before' should appear before the loop"
        );

        // Give the watchdog time to fire (timeout is 1 s; allow 3 s total slack).
        thread::sleep(Duration::from_millis(1500));

        // The Python thread must now be unblocked — execute a fast command.
        let result = runtime.execute_registered_command("agent-0", "ping");
        assert!(
            result.is_ok(),
            "Python thread should be responsive after watchdog interrupt; got {result:?}"
        );
        assert!(wait_for_output(&runtime, "pong"), "'pong' should appear from recovery command");
    }
}
