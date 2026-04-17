//! Upload subcommand handler for `CommandFs` callbacks.
//!
//! Invoked by `handle_filesystem_callback` in `mod.rs` with an already-
//! positioned `CallbackParser` (subcommand byte consumed).

use red_cell_common::demon::DemonCommand;

use crate::EventBus;

use super::super::{CallbackParser, CommandDispatchError, agent_response_event};

pub(super) fn handle_upload(
    events: &EventBus,
    parser: &mut CallbackParser<'_>,
    agent_id: u32,
    request_id: u32,
) -> Result<(), CommandDispatchError> {
    let size = parser.read_u32("filesystem upload size")?;
    let path = parser.read_utf16("filesystem upload path")?;
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandFs),
        request_id,
        "Info",
        &format!("Uploaded file: {path} ({size} bytes)"),
        None,
    )?);
    Ok(())
}
