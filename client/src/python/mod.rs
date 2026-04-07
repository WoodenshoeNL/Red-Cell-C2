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
mod tests;
