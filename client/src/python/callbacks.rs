//! Python callback registration and event dispatch for the embedded runtime.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use tracing::warn;

use super::script;
use super::{
    PyAgent, PyLootItem, PythonApiState, ScriptOutputStream, active_api_state, ensure_callable,
    lock_mutex, normalize_agent_id,
};

#[derive(Clone, Debug)]
pub(crate) struct RegisteredAgentCheckinCallback {
    pub(super) script_name: String,
    pub(super) mode: AgentCheckinCallbackMode,
    pub(super) callback: Arc<Py<PyAny>>,
}

/// Generic callback record used for event callbacks with no variant-specific metadata.
#[derive(Clone, Debug)]
pub(crate) struct EventCallback {
    pub(super) script_name: String,
    pub(super) callback: Arc<Py<PyAny>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AgentCheckinCallbackMode {
    Agent,
    Identifier,
}

impl PythonApiState {
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

    pub(super) fn invoke_agent_checkin_callbacks(&self, py: Python<'_>, agent_id: &str) {
        let timeout = Duration::from_secs(self.script_timeout_secs.load(Ordering::Relaxed));
        let thread_id = self.python_thread_id.load(Ordering::Relaxed);
        let callbacks = lock_mutex(&self.agent_checkin_callbacks).clone();
        if callbacks.is_empty() {
            return;
        }

        match Py::new(py, PyAgent { agent_id: normalize_agent_id(agent_id) }) {
            Ok(agent) => {
                for callback in callbacks {
                    self.begin_script_execution(&callback.script_name, Some("agent_checkin"));
                    let bound = callback.callback.bind(py);
                    let watchdog = script::spawn_script_watchdog(
                        timeout,
                        callback.script_name.clone(),
                        "agent_checkin",
                        thread_id,
                    );
                    let call_result = match callback.mode {
                        AgentCheckinCallbackMode::Agent => bound.call1((agent.clone_ref(py),)),
                        AgentCheckinCallbackMode::Identifier => bound.call1((agent_id,)),
                    };
                    drop(watchdog); // callback completed — cancel the watchdog
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

    pub(super) fn invoke_command_response_callbacks(
        &self,
        py: Python<'_>,
        agent_id: &str,
        task_id: &str,
        output: &str,
    ) {
        let timeout = Duration::from_secs(self.script_timeout_secs.load(Ordering::Relaxed));
        let thread_id = self.python_thread_id.load(Ordering::Relaxed);
        let callbacks = lock_mutex(&self.command_response_callbacks).clone();
        for callback in callbacks {
            self.begin_script_execution(&callback.script_name, Some("command_response"));
            let watchdog = script::spawn_script_watchdog(
                timeout,
                callback.script_name.clone(),
                "command_response",
                thread_id,
            );
            let call_result = callback.callback.bind(py).call1((agent_id, task_id, output));
            drop(watchdog); // callback completed — cancel the watchdog
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

    pub(super) fn invoke_loot_captured_callbacks(
        &self,
        py: Python<'_>,
        loot_item: &crate::transport::LootItem,
    ) {
        let timeout = Duration::from_secs(self.script_timeout_secs.load(Ordering::Relaxed));
        let thread_id = self.python_thread_id.load(Ordering::Relaxed);
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
            self.begin_script_execution(&callback.script_name, Some("loot_captured"));
            let watchdog = script::spawn_script_watchdog(
                timeout,
                callback.script_name.clone(),
                "loot_captured",
                thread_id,
            );
            let call_result =
                callback.callback.bind(py).call1((&loot_item.agent_id, py_loot.clone_ref(py)));
            drop(watchdog); // callback completed — cancel the watchdog
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

    pub(super) fn invoke_listener_changed_callbacks(
        &self,
        py: Python<'_>,
        listener_name: &str,
        action: &str,
    ) {
        let timeout = Duration::from_secs(self.script_timeout_secs.load(Ordering::Relaxed));
        let thread_id = self.python_thread_id.load(Ordering::Relaxed);
        let callbacks = lock_mutex(&self.listener_changed_callbacks).clone();
        for callback in callbacks {
            self.begin_script_execution(&callback.script_name, Some("listener_changed"));
            let watchdog = script::spawn_script_watchdog(
                timeout,
                callback.script_name.clone(),
                "listener_changed",
                thread_id,
            );
            let call_result = callback.callback.bind(py).call1((listener_name, action));
            drop(watchdog); // callback completed — cancel the watchdog
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
}

#[pyclass(name = "Event")]
#[derive(Clone, Debug)]
pub(crate) struct PyEventRegistrar {
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

#[pyfunction]
pub(crate) fn register_callback(event_type: String, callback: Bound<'_, PyAny>) -> PyResult<()> {
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
pub(crate) fn on_agent_checkin(callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let api_state = active_api_state()?;
    api_state.register_agent_checkin_callback(callback.unbind(), AgentCheckinCallbackMode::Agent)
}

/// Register a callback that fires whenever any command output arrives from an agent.
///
/// The callback receives `(agent_id: str, task_id: str, output: str)`.
/// `task_id` is empty when the response does not belong to a tracked task.
#[pyfunction]
pub(crate) fn on_command_response(callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    active_api_state()?.register_command_response_callback(callback.unbind())
}

/// Register a callback that fires when a loot item (credential, file, etc.) is captured.
///
/// The callback receives `(agent_id: str, loot: LootItem)`.
#[pyfunction]
pub(crate) fn on_loot_captured(callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    active_api_state()?.register_loot_captured_callback(callback.unbind())
}

/// Register a callback that fires when a listener is started, stopped, or edited.
///
/// The callback receives `(listener_id: str, action: str)` where `action` is one of
/// `"start"`, `"stop"`, or `"edit"`.
#[pyfunction]
pub(crate) fn on_listener_changed(callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    active_api_state()?.register_listener_changed_callback(callback.unbind())
}
