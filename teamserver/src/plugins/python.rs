//! PyO3 embedding and Python event bridge.
//!
//! Defines the `red_cell` / `havoc` Python API module exposed to plugins:
//! `PyAgent`, `PyListener`, `PyEvent` proxy classes, and the module-level
//! functions (`get_agent`, `register_command`, `on_*`, …).

use std::sync::{Arc, Mutex};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule, PyTuple};
use serde_json::Value;

use super::PluginRuntime;
use super::check_plugin_permission;
use super::events::PluginEvent;

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

#[derive(Debug)]
pub(super) struct RegisterCommandRequest {
    pub(super) name: String,
    pub(super) description: String,
    pub(super) callback: Py<PyAny>,
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

pub(super) fn parse_register_command_request(
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
        let description = extract_string_argument(kwargs, "description", positional.get(3))?
            .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a description"))?;

        let name = if module.trim().is_empty() { command } else { format!("{module} {command}") };

        return Ok(RegisterCommandRequest { name, description, callback: callback.unbind() });
    }

    let callback = if let Some(value) = optional_kwarg(kwargs, "callback")? {
        value
    } else {
        positional
            .get(2)
            .cloned()
            .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a callback"))?
    };
    ensure_callable(&callback)?;

    let name = extract_string_argument(kwargs, "name", positional.first())?
        .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a command name"))?;
    let description = extract_string_argument(kwargs, "description", positional.get(1))?
        .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a description"))?;

    Ok(RegisterCommandRequest { name, description, callback: callback.unbind() })
}

#[pyclass(name = "Agent")]
#[derive(Clone, Debug)]
pub(super) struct PyAgent {
    pub(super) agent_id: u32,
    /// Captures the task_id assigned during the most recent `task()` call so callers
    /// (e.g. `invoke_registered_command`) can correlate the broadcast with the queued job.
    pub(super) last_task_id: Arc<Mutex<Option<String>>>,
}

#[pymethods]
impl PyAgent {
    #[new]
    fn new(agent_id: &str) -> PyResult<Self> {
        let trimmed = agent_id.trim().trim_start_matches("0x").trim_start_matches("0X");
        let agent_id = u32::from_str_radix(trimmed, 16)
            .map_err(|_| PyValueError::new_err(format!("invalid agent id `{agent_id}`")))?;
        Ok(Self { agent_id, last_task_id: Arc::new(Mutex::new(None)) })
    }

    #[getter]
    fn id(&self) -> String {
        format!("{:08X}", self.agent_id)
    }

    #[getter]
    fn info(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        check_plugin_permission(crate::rbac::Permission::Read)?;
        let runtime = PluginRuntime::active()?;
        let agent = py.allow_threads(|| runtime.block_on(runtime.get_agent(self.agent_id)));
        match agent {
            Ok(Some(agent)) => json_value_to_object(
                py,
                &serde_json::to_value(agent)
                    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
            ),
            Ok(None) => {
                Err(PyValueError::new_err(format!("agent {:08X} no longer exists", self.agent_id)))
            }
            Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
        }
    }

    #[pyo3(signature = (command, args=None))]
    fn task(&self, py: Python<'_>, command: u32, args: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        check_plugin_permission(crate::rbac::Permission::TaskAgents)?;
        let runtime = PluginRuntime::active()?;
        let payload = match args {
            None => Vec::new(),
            Some(value) if value.is_none() => Vec::new(),
            Some(value) => {
                if let Ok(bytes) = value.extract::<Vec<u8>>() {
                    bytes
                } else if let Ok(text) = value.extract::<String>() {
                    text.into_bytes()
                } else {
                    return Err(PyValueError::new_err(
                        "args must be bytes, bytearray, str, or None",
                    ));
                }
            }
        };

        let agent_id = self.agent_id;
        let task_id = py
            .allow_threads(move || {
                runtime.block_on(runtime.queue_raw_agent_task(agent_id, command, payload))
            })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        self.last_task_id
            .lock()
            .map_err(|_| {
                PyRuntimeError::new_err(
                    "last_task_id mutex poisoned: task was queued but id not captured",
                )
            })?
            .replace(task_id);
        Ok(())
    }
}

#[pyclass(name = "Listener")]
#[derive(Clone, Debug)]
pub(super) struct PyListener {
    name: String,
}

#[pymethods]
impl PyListener {
    #[new]
    fn new(name: String) -> Self {
        Self { name }
    }

    #[getter]
    fn info(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        check_plugin_permission(crate::rbac::Permission::Read)?;
        let runtime = PluginRuntime::active()?;
        let listener = py.allow_threads(|| runtime.block_on(runtime.get_listener(&self.name)));
        match listener {
            Ok(Some(listener)) => json_value_to_object(
                py,
                &serde_json::to_value(listener)
                    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
            ),
            Ok(None) => Err(PyValueError::new_err(format!("listener `{}` not found", self.name))),
            Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
        }
    }

    fn start(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        check_plugin_permission(crate::rbac::Permission::ManageListeners)?;
        let runtime = PluginRuntime::active()?;
        let listener = py.allow_threads(|| runtime.block_on(runtime.start_listener(&self.name)));
        match listener {
            Ok(listener) => json_value_to_object(
                py,
                &serde_json::to_value(listener)
                    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
            ),
            Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
        }
    }

    fn stop(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        check_plugin_permission(crate::rbac::Permission::ManageListeners)?;
        let runtime = PluginRuntime::active()?;
        let listener = py.allow_threads(|| runtime.block_on(runtime.stop_listener(&self.name)));
        match listener {
            Ok(listener) => json_value_to_object(
                py,
                &serde_json::to_value(listener)
                    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
            ),
            Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
        }
    }
}

#[pyclass(name = "Event")]
#[derive(Clone, Debug)]
pub(super) struct PyEvent {
    pub(super) event_type: String,
    pub(super) agent_id: Option<u32>,
    pub(super) data: Value,
}

#[pymethods]
impl PyEvent {
    #[getter]
    fn event_type(&self) -> String {
        self.event_type.clone()
    }

    #[getter]
    fn agent(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        self.agent_id
            .map(|agent_id| {
                Py::new(py, PyAgent { agent_id, last_task_id: Arc::new(Mutex::new(None)) })
                    .map(|agent| agent.into_any())
            })
            .transpose()
    }

    #[getter]
    fn data(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_object(py, &self.data)
    }
}

#[pyfunction]
fn get_agent(py: Python<'_>, agent_id: u32) -> PyResult<Py<PyAny>> {
    check_plugin_permission(crate::rbac::Permission::Read)?;
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
    check_plugin_permission(crate::rbac::Permission::Read)?;
    let runtime = PluginRuntime::active()?;
    let agents = py.allow_threads(|| runtime.block_on(runtime.list_agents()));
    json_value_to_object(
        py,
        &serde_json::to_value(agents)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
    )
}

#[pyfunction]
fn get_agents(py: Python<'_>) -> PyResult<Py<PyAny>> {
    list_agents(py)
}

#[pyfunction]
fn get_listener(py: Python<'_>, name: String) -> PyResult<Py<PyAny>> {
    check_plugin_permission(crate::rbac::Permission::Read)?;
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
    check_plugin_permission(crate::rbac::Permission::Read)?;
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
fn get_listeners(py: Python<'_>) -> PyResult<Py<PyAny>> {
    list_listeners(py)
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
fn on_agent_registered(py: Python<'_>, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || {
        runtime.block_on(runtime.register_callback(PluginEvent::AgentRegistered, callback))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
fn on_agent_dead(py: Python<'_>, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || {
        runtime.block_on(runtime.register_callback(PluginEvent::AgentDead, callback))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
fn on_loot_captured(py: Python<'_>, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || {
        runtime.block_on(runtime.register_callback(PluginEvent::LootCaptured, callback))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
fn on_task_created(py: Python<'_>, callback: Bound<'_, PyAny>) -> PyResult<()> {
    ensure_callable(&callback)?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || {
        runtime.block_on(runtime.register_callback(PluginEvent::TaskCreated, callback))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
fn register_callback(
    py: Python<'_>,
    event_type: String,
    callback: Bound<'_, PyAny>,
) -> PyResult<()> {
    ensure_callable(&callback)?;
    let event = PluginEvent::parse(&event_type)
        .ok_or_else(|| PyValueError::new_err(format!("unsupported event type `{event_type}`")))?;
    let runtime = PluginRuntime::active()?;
    let callback = callback.unbind();
    py.allow_threads(move || runtime.block_on(runtime.register_callback(event, callback)))
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (*args, **kwargs))]
fn register_command(
    py: Python<'_>,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<()> {
    let request = parse_register_command_request(args, kwargs)?;
    let runtime = PluginRuntime::active()?;
    py.allow_threads(move || {
        runtime.block_on(runtime.register_command(
            request.name,
            request.description,
            request.callback,
        ))
    })
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(())
}

pub(super) fn populate_api_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(get_agent, module)?)?;
    module.add_function(wrap_pyfunction!(list_agents, module)?)?;
    module.add_function(wrap_pyfunction!(get_agents, module)?)?;
    module.add_function(wrap_pyfunction!(get_listener, module)?)?;
    module.add_function(wrap_pyfunction!(list_listeners, module)?)?;
    module.add_function(wrap_pyfunction!(get_listeners, module)?)?;
    module.add_function(wrap_pyfunction!(on_agent_checkin, module)?)?;
    module.add_function(wrap_pyfunction!(on_agent_registered, module)?)?;
    module.add_function(wrap_pyfunction!(on_agent_dead, module)?)?;
    module.add_function(wrap_pyfunction!(on_command_output, module)?)?;
    module.add_function(wrap_pyfunction!(on_loot_captured, module)?)?;
    module.add_function(wrap_pyfunction!(on_task_created, module)?)?;
    module.add_function(wrap_pyfunction!(register_callback, module)?)?;
    module.add_function(wrap_pyfunction!(register_command, module)?)?;
    module.add_class::<PyAgent>()?;
    module.add_class::<PyListener>()?;
    module.add_class::<PyEvent>()?;

    module.add("GetAgent", module.getattr("get_agent")?)?;
    module.add("GetAgents", module.getattr("get_agents")?)?;
    module.add("GetListener", module.getattr("get_listener")?)?;
    module.add("GetListeners", module.getattr("get_listeners")?)?;
    module.add("RegisterCallback", module.getattr("register_callback")?)?;
    module.add("RegisterCommand", module.getattr("register_command")?)?;
    Ok(())
}
