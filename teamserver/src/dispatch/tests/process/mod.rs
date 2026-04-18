//! Tests for process, job, inject, exit, and related dispatch command handlers.

mod assembly;
mod cmd;
mod integration;
mod job;

pub(super) use super::super::process::{
    GrepRow, MemoryRow, ModuleRow, ProcessRow, format_grep_table, format_memory_protect,
    format_memory_state, format_memory_table, format_memory_type, format_module_table,
    format_process_table, handle_inject_dll_callback, handle_inject_shellcode_callback,
    handle_proc_ppid_spoof_callback, handle_process_command_callback, handle_process_list_callback,
    handle_spawn_dll_callback, process_rows_json, win32_error_code_name,
};
pub(super) use super::super::{CommandDispatchError, CommandDispatcher};
pub(super) use super::common::*;
pub(super) use crate::{AgentRegistry, Database, EventBus, SocketRelayManager, TeamserverError};
pub(super) use red_cell_common::demon::{
    DemonCallbackError, DemonCommand, DemonInfoClass, DemonInjectError, DemonJobCommand,
    DemonProcessCommand, DemonTokenCommand,
};
pub(super) use red_cell_common::operator::OperatorMessage;
pub(super) use serde_json::Value;
pub(super) use tokio::time::{Duration, timeout};

/// Extract the `Type` and `Message` extra fields from an `AgentResponse`.
pub(super) fn extract_response_kind_and_message(msg: &OperatorMessage) -> (String, String) {
    let OperatorMessage::AgentResponse(m) = msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let kind = m.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("").to_owned();
    let message = m.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("").to_owned();
    (kind, message)
}
