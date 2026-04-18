//! PyO3 Python binding types: `PyAgent`, `PyCommandContext`, `PyCommandOption`,
//! `PyListener`, `PyLootItem`, `PyLogger`, and `PyOutputSink`.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyTuple;

use crate::python::{ScriptOutputStream, active_api_state, current_operator_username};
use crate::transport::LootItem;

use super::{
    CommandOption, CommandOptionType, agent_summary_to_json, build_agent_command_message,
    build_console_task_message, json_value_to_object, listener_summary_to_json,
    next_task_id_string, normalize_agent_id, normalize_listener_name,
};

// ── PyAgent ──────────────────────────────────────────────────────────────────

#[pyclass(name = "Agent")]
#[derive(Clone, Debug)]
pub(crate) struct PyAgent {
    pub(crate) agent_id: String,
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
    pub(super) fn new(agent_id: &Bound<'_, PyAny>) -> PyResult<Self> {
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

// ── PyCommandContext ──────────────────────────────────────────────────────────

#[pyclass(name = "CommandContext")]
#[derive(Debug)]
pub(super) struct PyCommandContext {
    pub(super) command: String,
    pub(super) command_line: String,
    pub(super) arguments: Vec<String>,
    pub(super) description: Option<String>,
    pub(super) options: Vec<CommandOption>,
    pub(super) history: Vec<String>,
    pub(super) agent: Py<PyAgent>,
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

// ── PyCommandOption ───────────────────────────────────────────────────────────

/// A declared parameter exposed by a registered command.
#[pyclass(name = "CommandOption", frozen)]
#[derive(Clone, Debug)]
pub(super) struct PyCommandOption {
    pub(super) name: String,
    pub(super) option_type: CommandOptionType,
    pub(super) required: bool,
    pub(super) default: Option<String>,
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

// ── PyListener ────────────────────────────────────────────────────────────────

#[pyclass(name = "Listener")]
#[derive(Clone, Debug)]
pub(super) struct PyListener {
    pub(super) name: String,
}

#[pymethods]
impl PyListener {
    #[new]
    pub(super) fn new(name: String) -> PyResult<Self> {
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

// ── PyLootItem ────────────────────────────────────────────────────────────────

/// A single loot item returned by `red_cell.get_loot()`.
#[pyclass(name = "LootItem", frozen)]
#[derive(Clone, Debug)]
pub(crate) struct PyLootItem {
    id: Option<i64>,
    agent_id: String,
    loot_type: String,
    data: Option<String>,
    timestamp: String,
    name: String,
}

impl PyLootItem {
    pub(crate) fn from_loot_item(item: &LootItem) -> Self {
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

// ── PyOutputSink ──────────────────────────────────────────────────────────────

#[pyclass]
pub(crate) struct PyOutputSink {
    pub(crate) stream: ScriptOutputStream,
}

#[pymethods]
impl PyOutputSink {
    fn write(&self, text: &str) -> PyResult<usize> {
        active_api_state()?.push_output(None, self.stream, text)
    }

    fn flush(&self) {}
}

// ── PyLogger ──────────────────────────────────────────────────────────────────

#[pyclass(name = "Logger")]
pub(super) struct PyLogger {
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
