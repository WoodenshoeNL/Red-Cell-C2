//! PyO3 plugin API: command registration, Havoc-compatible bindings, and helpers.
//!
//! This module holds Havoc-style `red_cell` / `havocui` surface area: registered commands,
//! agent/listener wrappers, and console task message builders.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use base64::Engine;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use serde_json::{Value, json};

use super::script;
use super::{
    MAX_COMMAND_HISTORY, PythonApiState, ScriptOutputStream, active_api_state,
    current_operator_username, lock_mutex,
};
use crate::transport::{AgentSummary, ListenerSummary, LootItem};

#[derive(Clone, Debug)]
pub(super) struct RegisteredCommand {
    pub(super) script_name: String,
    pub(super) description: Option<String>,
    pub(super) options: Vec<CommandOption>,
    pub(super) callback: Arc<Py<PyAny>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MatchedCommand {
    pub(super) name: String,
    pub(super) command_line: String,
    pub(super) arguments: Vec<String>,
}

/// The data type of a command option parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CommandOptionType {
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
pub(super) struct CommandOption {
    name: String,
    option_type: CommandOptionType,
    required: bool,
    default: Option<String>,
}

impl PythonApiState {
    pub(super) fn register_command(
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
    #[cfg(test)]
    pub(super) fn command_names(&self) -> Vec<String> {
        lock_mutex(&self.commands).keys().cloned().collect()
    }
    pub(super) fn match_registered_command(&self, input: &str) -> Option<MatchedCommand> {
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
    pub(super) fn execute_registered_command(
        &self,
        py: Python<'_>,
        command_name: &str,
        agent_id: &str,
        command_line: &str,
        arguments: &[String],
    ) -> Result<bool, String> {
        let timeout = Duration::from_secs(self.script_timeout_secs.load(Ordering::Relaxed));
        let thread_id = self.python_thread_id.load(Ordering::Relaxed);
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
        self.begin_script_execution(&registered.script_name, Some("registered_command"));
        let bound = registered.callback.bind(py);
        let watchdog = script::spawn_script_watchdog(
            timeout,
            registered.script_name.clone(),
            "command",
            thread_id,
        );
        let result = invoke_registered_command_callback(
            self,
            py,
            &registered.script_name,
            bound,
            agent,
            command_context,
            arguments,
        );
        drop(watchdog); // callback completed — cancel the watchdog
        self.end_script_execution();
        result
    }
}

pub(super) fn populate_api_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(register_command, module)?)?;
    module.add_function(wrap_pyfunction!(crate::python::callbacks::register_callback, module)?)?;
    module.add_function(wrap_pyfunction!(crate::python::callbacks::on_agent_checkin, module)?)?;
    module
        .add_function(wrap_pyfunction!(crate::python::callbacks::on_command_response, module)?)?;
    module.add_function(wrap_pyfunction!(crate::python::callbacks::on_loot_captured, module)?)?;
    module
        .add_function(wrap_pyfunction!(crate::python::callbacks::on_listener_changed, module)?)?;
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
    module.add_class::<crate::python::callbacks::PyEventRegistrar>()?;
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

pub(super) fn populate_havocui_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
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

pub(crate) fn ensure_callable(callback: &Bound<'_, PyAny>) -> PyResult<()> {
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

pub(crate) fn normalize_agent_id(agent_id: &str) -> String {
    let trimmed = agent_id.trim();
    let without_prefix =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);

    if let Ok(value) = u32::from_str_radix(without_prefix, 16) {
        format!("{value:08X}")
    } else {
        trimmed.to_ascii_uppercase()
    }
}

pub(super) fn normalize_command_name(name: &str) -> String {
    name.split_whitespace().map(|part| part.to_ascii_lowercase()).collect::<Vec<_>>().join(" ")
}

pub(super) fn normalize_listener_name(name: &str) -> String {
    name.trim().to_owned()
}

pub(super) fn normalize_tab_title(title: &str) -> PyResult<String> {
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
pub(super) enum PyCallShape {
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
pub(super) struct PyCommandContext {
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
pub(super) struct PyCommandOption {
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

#[pyclass(name = "Listener")]
#[derive(Clone, Debug)]
pub(super) struct PyListener {
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

#[pyclass]
pub(super) struct PyOutputSink {
    pub(super) stream: ScriptOutputStream,
}

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

#[pymethods]
impl PyOutputSink {
    fn write(&self, text: &str) -> PyResult<usize> {
        active_api_state()?.push_output(None, self.stream, text)
    }

    fn flush(&self) {}
}

pub(super) struct RegisterCommandRequest {
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
fn agent(py: Python<'_>, agent_id: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    Py::new(py, PyAgent::new(agent_id)?).map(|agent| agent.into_any())
}

#[pyfunction]
fn agents(py: Python<'_>) -> PyResult<Vec<Py<PyAgent>>> {
    let api_state = active_api_state()?;
    api_state
        .agent_snapshots()
        .iter()
        .map(|agent| Py::new(py, PyAgent { agent_id: agent.name_id.clone() }))
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
