//! `PythonRuntime` handle and the dedicated Python-thread command channel.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use red_cell_common::operator::OperatorMessage;
use tokio::sync::mpsc::UnboundedSender;
use tracing::warn;

#[cfg(test)]
use super::plugin;
use super::{
    DEFAULT_SCRIPT_TIMEOUT_SECS, PythonApiState, ScriptDescriptor, ScriptOutputEntry,
    ScriptTabDescriptor, active_runtime_slot, lock_mutex, script,
};
#[cfg(test)]
use crate::transport::AppState;
use crate::transport::SharedAppState;
#[cfg(test)]
use pyo3::prelude::*;

#[derive(Debug)]
pub(super) enum PythonThreadCommand {
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
    pub(super) fn script_timeout_secs_raw(&self) -> u64 {
        self.inner.api_state.script_timeout_secs.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn command_names(&self) -> Vec<String> {
        self.inner.api_state.command_names()
    }

    #[cfg(test)]
    pub(super) fn new_zombie_for_test() -> Self {
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
