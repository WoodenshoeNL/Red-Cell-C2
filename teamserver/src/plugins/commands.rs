//! Python plugin command registration and dispatch.
//!
//! This module holds the [`PluginRuntime`] methods that deal with the command
//! lifecycle: listing registered commands, routing an incoming [`AgentTaskInfo`]
//! to a plugin handler, and invoking a named command on behalf of an operator.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use pyo3::types::{PyList, PyTuple};
use red_cell_common::config::OperatorRole;
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use tracing::error;

use super::{CallbackRuntimeGuard, CallerRoleGuard, PluginError, PluginRuntime};

impl PluginRuntime {
    /// Return the registered Python command names in sorted order.
    #[tracing::instrument(skip(self))]
    pub async fn command_names(&self) -> Vec<String> {
        self.inner.commands.read().await.keys().cloned().collect()
    }

    /// Return the registered Python command descriptions keyed by command name.
    #[tracing::instrument(skip(self))]
    pub async fn command_descriptions(&self) -> BTreeMap<String, String> {
        self.inner
            .commands
            .read()
            .await
            .iter()
            .map(|(name, command)| (name.clone(), command.description.clone()))
            .collect()
    }

    pub(crate) async fn invoke_registered_command(
        &self,
        name: &str,
        actor: &str,
        role: OperatorRole,
        agent_id: u32,
        args: Vec<String>,
    ) -> Result<bool, PluginError> {
        let command = {
            let commands = self.inner.commands.read().await;
            commands.get(name).cloned()
        };
        let Some(command) = command else {
            return Ok(false);
        };

        if self.is_plugin_disabled(&command.plugin_name) {
            error!(
                command = name,
                plugin = %command.plugin_name,
                "python command skipped — plugin is disabled due to repeated failures"
            );
            return Ok(false);
        }

        let runtime = self.clone();
        let plugin_name = command.plugin_name.clone();
        let callback_args = args.clone();
        let joined_args = args.join(" ");
        let captured_task_id: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let task_id_for_callback = captured_task_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            // Set the thread-local so re-entrant calls from Python into the Rust
            // API bypass the global RUNTIME mutex.
            let _guard = CallbackRuntimeGuard::enter(&runtime);
            // Set the caller's RBAC role so Python API functions can enforce
            // permission checks against the invoking operator's role.
            let _role_guard = CallerRoleGuard::enter(role);

            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Python::with_gil(|py| -> PyResult<()> {
                    runtime.install_api_module(py)?;
                    let agent = Py::new(
                        py,
                        super::python::PyAgent { agent_id, last_task_id: task_id_for_callback },
                    )?
                    .into_any();
                    let list = PyList::new(py, callback_args)?.into_any().unbind();
                    let py_args = PyTuple::new(py, [agent, list])?;
                    command.callback.bind(py).call1(py_args)?;
                    Ok(())
                })
            }))
        })
        .await;

        match result {
            Ok(Ok(Ok(()))) => {
                self.record_callback_success(&plugin_name);
            }
            Ok(Ok(Err(py_err))) => {
                error!(
                    command = name,
                    plugin = %plugin_name,
                    error = %py_err,
                    "python plugin command raised an exception"
                );
                self.record_callback_failure(&plugin_name);
                return Err(PluginError::Python(py_err));
            }
            Ok(Err(panic_payload)) => {
                let msg = panic_payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| panic_payload.downcast_ref::<&str>().copied())
                    .unwrap_or("<non-string panic payload>");
                error!(
                    command = name,
                    plugin = %plugin_name,
                    panic_message = msg,
                    "python plugin command panicked"
                );
                self.record_callback_failure(&plugin_name);
                return Err(PluginError::MutexPoisoned);
            }
            Err(join_err) => {
                error!(
                    command = name,
                    plugin = %plugin_name,
                    "python plugin command task failed to join"
                );
                self.record_callback_failure(&plugin_name);
                return Err(PluginError::Join(join_err));
            }
        }

        let task_id = captured_task_id.lock().map_err(|_| PluginError::MutexPoisoned)?.clone();

        if let Some(task_id) = task_id {
            self.inner.events.broadcast(OperatorMessage::AgentTask(Message {
                head: MessageHead {
                    event: EventCode::Session,
                    user: actor.to_owned(),
                    timestamp: String::new(),
                    one_time: String::new(),
                },
                info: AgentTaskInfo {
                    task_id,
                    command_line: format!("{name} {joined_args}").trim().to_owned(),
                    demon_id: format!("{agent_id:08X}"),
                    command_id: "Python".to_owned(),
                    command: Some(name.to_owned()),
                    arguments: Some(joined_args),
                    task_message: Some("python plugin command executed".to_owned()),
                    ..AgentTaskInfo::default()
                },
            }));
        }
        Ok(true)
    }

    pub(crate) async fn match_registered_command(
        &self,
        info: &AgentTaskInfo,
    ) -> Option<(String, Vec<String>)> {
        let commands = self.inner.commands.read().await;
        if commands.is_empty() {
            return None;
        }

        if let Some(command) =
            info.command.as_deref().map(str::trim).filter(|value| !value.is_empty())
            && commands.contains_key(command)
        {
            let args = info
                .arguments
                .as_deref()
                .unwrap_or_default()
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect();
            return Some((command.to_owned(), args));
        }

        let command_line = info.command_line.trim();
        if command_line.is_empty() {
            return None;
        }

        let mut matches = commands
            .keys()
            .filter(|command| {
                command_line == command.as_str() || command_line.starts_with(&format!("{command} "))
            })
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by_key(|command| usize::MAX - command.len());
        let command = matches.into_iter().next()?;
        let remainder = command_line.strip_prefix(command.as_str()).unwrap_or_default().trim();
        let args = if remainder.is_empty() {
            Vec::new()
        } else {
            remainder.split_whitespace().map(ToOwned::to_owned).collect()
        };
        Some((command, args))
    }
}
