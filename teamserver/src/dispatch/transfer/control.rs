//! Handlers for the `Stop`, `Resume`, and `Remove` subcommands of
//! `DemonTransferCommand`.
//!
//! All three subcommands share an identical on-the-wire payload
//! (`found: bool`, `file_id: u32`) and emit a single `AgentResponse` event
//! describing the outcome, so they are dispatched together.

use red_cell_common::demon::{DemonCommand, DemonTransferCommand};
use tracing::warn;

use super::super::{CallbackParser, CommandDispatchError, DownloadTracker, agent_response_event};
use crate::EventBus;

/// Handle the `Stop`, `Resume`, or `Remove` subcommand.
///
/// The subcommand byte has already been consumed from `parser`; the caller
/// passes the decoded variant so this function can dispatch on it.
pub(super) async fn handle_control(
    events: &EventBus,
    downloads: &DownloadTracker,
    agent_id: u32,
    request_id: u32,
    subcommand: DemonTransferCommand,
    parser: &mut CallbackParser<'_>,
) -> Result<(), CommandDispatchError> {
    let found = parser.read_bool("transfer found")?;
    let file_id = parser.read_u32("transfer file id")?;
    let exists = downloads
        .active_for_agent(agent_id)
        .await
        .iter()
        .any(|(active_file_id, _)| *active_file_id == file_id);
    let (kind, message) = match subcommand {
        DemonTransferCommand::Stop => {
            if found && exists {
                ("Good", format!("Successfully found and stopped download: {file_id:x}"))
            } else if found {
                ("Error", format!("Couldn't stop download {file_id:x}: Download does not exist"))
            } else {
                ("Error", format!("Couldn't stop download {file_id:x}: FileID not found"))
            }
        }
        DemonTransferCommand::Resume => {
            if found && exists {
                ("Good", format!("Successfully found and resumed download: {file_id:x}"))
            } else if found {
                ("Error", format!("Couldn't resume download {file_id:x}: Download does not exist"))
            } else {
                ("Error", format!("Couldn't resume download {file_id:x}: FileID not found"))
            }
        }
        DemonTransferCommand::Remove => {
            if found && exists {
                if downloads.finish(agent_id, file_id).await.is_none() {
                    warn!(
                        agent_id = format_args!("{agent_id:08X}"),
                        file_id = format_args!("{file_id:08X}"),
                        "download remove: finish returned None — in-memory state was absent despite exists check"
                    );
                }
                ("Good", format!("Successfully found and removed download: {file_id:x}"))
            } else if found {
                ("Error", format!("Couldn't remove download {file_id:x}: Download does not exist"))
            } else {
                ("Error", format!("Couldn't remove download {file_id:x}: FileID not found"))
            }
        }
        DemonTransferCommand::List => unreachable!(),
    };
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandTransfer),
        request_id,
        kind,
        &message,
        None,
    )?);

    Ok(())
}
