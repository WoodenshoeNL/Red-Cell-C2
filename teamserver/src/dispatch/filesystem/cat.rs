//! Cat subcommand handler for `CommandFs` callbacks.
//!
//! Invoked by `handle_filesystem_callback` in `mod.rs` with an already-
//! positioned `CallbackParser` (subcommand byte consumed).

use red_cell_common::demon::DemonCommand;

use crate::EventBus;

use super::super::{CallbackParser, CommandDispatchError, agent_response_event};

pub(super) fn handle_cat(
    events: &EventBus,
    parser: &mut CallbackParser<'_>,
    agent_id: u32,
    request_id: u32,
) -> Result<(), CommandDispatchError> {
    let path = parser.read_utf16("filesystem cat path")?;
    let success = parser.read_bool("filesystem cat success")?;
    let output = parser.read_string("filesystem cat output")?;
    let (kind, message) = if success {
        ("Info", format!("File content of {path} ({}):", output.len()))
    } else {
        ("Error", format!("Failed to read file: {path}"))
    };
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandFs),
        request_id,
        kind,
        &message,
        if success { Some(output) } else { None },
    )?);
    Ok(())
}
