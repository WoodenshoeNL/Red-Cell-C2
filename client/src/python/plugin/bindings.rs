//! PyO3 query/data bindings: agent, listener, loot, task, and havocui UI functions.

use std::time::Duration;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use super::helpers::ensure_callable;
use super::types::{PyAgent, PyListener, PyLootItem};
use super::{ScriptOutputStream, active_api_state, current_operator_username};
use crate::python::lock_mutex;
use crate::python::plugin::tasks::{
    build_agent_command_message, build_console_task_message, next_task_id_string,
};

#[pyfunction]
pub(super) fn agent(py: Python<'_>, agent_id: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    Py::new(py, PyAgent::new(agent_id)?).map(|agent| agent.into_any())
}

#[pyfunction]
pub(super) fn agents(py: Python<'_>) -> PyResult<Vec<Py<PyAgent>>> {
    let api_state = active_api_state()?;
    api_state
        .agent_snapshots()
        .iter()
        .map(|agent| Py::new(py, PyAgent { agent_id: agent.name_id.clone() }))
        .collect()
}

#[pyfunction]
pub(super) fn listener(py: Python<'_>, name: String) -> PyResult<Py<PyAny>> {
    Py::new(py, PyListener::new(name)?).map(|listener| listener.into_any())
}

#[pyfunction]
pub(super) fn listeners(py: Python<'_>) -> PyResult<Vec<Py<PyListener>>> {
    let api_state = active_api_state()?;
    api_state
        .listener_snapshots()
        .iter()
        .map(|listener| Py::new(py, PyListener { name: listener.name.clone() }))
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
pub(super) fn get_loot(
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
pub(super) fn task_agent(
    agent_id: &Bound<'_, PyAny>,
    command: String,
    args: Option<Vec<u8>>,
) -> PyResult<String> {
    let agent = PyAgent::new(agent_id)?;
    let api_state = active_api_state()?;
    let task_id = next_task_id_string();
    api_state.register_task_waiter(task_id.clone());
    let operator = current_operator_username(&api_state.app_state);
    let message = if let Some(raw) = args {
        build_agent_command_message(&agent.agent_id, &task_id, &command, &raw, &operator)
    } else {
        build_console_task_message(&agent.agent_id, &task_id, &command, &operator)
            .map_err(PyValueError::new_err)?
    };
    if let Err(err) = api_state.queue_task_message(message) {
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
pub(super) fn get_task_result(
    py: Python<'_>,
    task_id: String,
    timeout: f64,
) -> PyResult<Py<PyAny>> {
    let api_state = active_api_state()?;
    let rx = api_state.take_task_receiver(&task_id).ok_or_else(|| {
        PyValueError::new_err(format!("no pending task with id `{task_id}`; call task_agent first"))
    })?;
    let timeout_dur = Duration::from_secs_f64(timeout.max(0.0));
    let result = py.allow_threads(move || rx.recv_timeout(timeout_dur).ok());
    match result {
        Some(task_result) => {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("agent_id", task_result.agent_id)?;
            dict.set_item("output", task_result.output)?;
            Ok(dict.into_any().unbind())
        }
        None => {
            lock_mutex(&api_state.task_result_senders).remove(&task_id);
            Ok(py.None())
        }
    }
}

#[pyfunction]
#[pyo3(signature = (text, title=None))]
pub(super) fn messagebox(text: String, title: Option<String>) -> PyResult<()> {
    let api_state = active_api_state()?;
    let label = title.unwrap_or_else(|| "Message".to_owned());
    api_state.push_runtime_note(None, &format!("[havocui:{label}] {text}"));
    Ok(())
}

#[pyfunction]
pub(super) fn errormessage(text: String) -> PyResult<()> {
    let api_state = active_api_state()?;
    let rendered = format!("[havocui:error] {text}\n");
    let _ = api_state.push_output(None, ScriptOutputStream::Stderr, &rendered)?;
    Ok(())
}

#[pyfunction]
pub(super) fn infomessage(text: String) -> PyResult<()> {
    messagebox(text, Some("Info".to_owned()))
}

#[pyfunction]
pub(super) fn successmessage(text: String) -> PyResult<()> {
    messagebox(text, Some("Success".to_owned()))
}

#[pyfunction]
#[pyo3(signature = (title, callback=None))]
pub(super) fn createtab(title: String, callback: Option<Bound<'_, PyAny>>) -> PyResult<()> {
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
pub(super) fn settablayout(title: String, layout: String) -> PyResult<()> {
    let api_state = active_api_state()?;
    api_state.set_tab_layout(&title, layout)
}
