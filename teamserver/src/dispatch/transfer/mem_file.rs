//! Handlers for the `CommandMemFile` and `CommandPackageDropped` callbacks.
//!
//! Both commands are fire-and-forget status notifications from the agent:
//! `CommandMemFile` reports whether a memory-backed file was registered
//! successfully, and `CommandPackageDropped` reports that the agent discarded
//! an oversize outbound package. Each emits a single `AgentResponse` event and
//! never produces a reply packet.

use red_cell_common::demon::DemonCommand;

use super::super::{CallbackParser, CommandDispatchError, agent_response_event};
use crate::EventBus;

pub(in crate::dispatch) async fn handle_mem_file_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandMemFile));
    let mem_file_id = parser.read_u32("mem file id")?;
    let success = parser.read_bool("mem file success")?;
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandMemFile),
        request_id,
        if success { "Good" } else { "Error" },
        &format!(
            "Memory file {:x} {}",
            mem_file_id,
            if success { "registered successfully" } else { "failed to register" }
        ),
        None,
    )?);
    Ok(None)
}

pub(in crate::dispatch) async fn handle_package_dropped_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandPackageDropped));
    let package_length = parser.read_u32("dropped package length")?;
    let max_length = parser.read_u32("dropped package max length")?;
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandPackageDropped),
        request_id,
        "Error",
        &format!(
            "A package was discarded by demon for being larger than PIPE_BUFFER_MAX ({package_length} > {max_length})"
        ),
        None,
    )?);
    Ok(None)
}
