//! PyO3 plugin API: command registration, Havoc-compatible bindings, and helpers.
//!
//! This module holds Havoc-style `red_cell` / `havocui` surface area: registered commands,
//! agent/listener wrappers, and console task message builders.

mod bindings;
mod commands;
mod helpers;
mod tasks;
mod types;

pub(crate) use helpers::{ensure_callable, normalize_agent_id};
pub(super) use helpers::{normalize_command_name, normalize_listener_name, normalize_tab_title};
pub(crate) use types::{PyAgent, PyLootItem, PyOutputSink};

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use pyo3::prelude::*;

use commands::invoke_registered_command_callback;
use types::{PyCommandContext, PyCommandOption, PyListener, PyLogger};

use super::script;
use super::{
    MAX_COMMAND_HISTORY, PythonApiState, ScriptOutputStream, active_api_state,
    current_operator_username, lock_mutex,
};

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

    pub(super) fn label(self) -> &'static str {
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
    pub(super) name: String,
    pub(super) option_type: CommandOptionType,
    pub(super) required: bool,
    pub(super) default: Option<String>,
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
            pyo3::exceptions::PyRuntimeError::new_err(
                "red_cell.register_command must be called while a script loads",
            )
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

        let history_snapshot = {
            let key = (helpers::normalize_agent_id(agent_id), command_name.to_owned());
            let mut history = lock_mutex(&self.command_history);
            let agent_history = history.entry(key).or_default();
            let snapshot: Vec<String> = agent_history.iter().cloned().collect();
            agent_history.push_back(command_line.to_owned());
            while agent_history.len() > MAX_COMMAND_HISTORY {
                agent_history.pop_front();
            }
            snapshot
        };

        let agent = Py::new(py, types::PyAgent { agent_id: helpers::normalize_agent_id(agent_id) })
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
        drop(watchdog);
        self.end_script_execution();
        result
    }
}

pub(super) fn populate_api_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(commands::register_command, module)?)?;
    module.add_function(wrap_pyfunction!(crate::python::callbacks::register_callback, module)?)?;
    module.add_function(wrap_pyfunction!(crate::python::callbacks::on_agent_checkin, module)?)?;
    module
        .add_function(wrap_pyfunction!(crate::python::callbacks::on_command_response, module)?)?;
    module.add_function(wrap_pyfunction!(crate::python::callbacks::on_loot_captured, module)?)?;
    module
        .add_function(wrap_pyfunction!(crate::python::callbacks::on_listener_changed, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::agent, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::agents, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::listener, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::listeners, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::get_loot, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::task_agent, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::get_task_result, module)?)?;
    module.add_class::<types::PyAgent>()?;
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
    module.add_function(wrap_pyfunction!(bindings::messagebox, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::errormessage, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::infomessage, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::successmessage, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::createtab, module)?)?;
    module.add_function(wrap_pyfunction!(bindings::settablayout, module)?)?;
    module.add_function(wrap_pyfunction!(commands::havocui_register_command, module)?)?;
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
