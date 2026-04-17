//! Handler for the `DemonTransferCommand::List` subcommand.

use red_cell_common::demon::DemonCommand;

use super::super::{CallbackParser, CommandDispatchError, DownloadTracker, agent_response_event};
use super::helpers::{byte_count, transfer_progress_text, transfer_state_name};
use crate::EventBus;

/// Handle the `List` subcommand: render the active download table for the operator.
///
/// The subcommand byte has already been consumed from `parser`.
pub(super) async fn handle_list(
    events: &EventBus,
    downloads: &DownloadTracker,
    agent_id: u32,
    request_id: u32,
    parser: &mut CallbackParser<'_>,
) -> Result<(), CommandDispatchError> {
    let active = downloads.active_for_agent(agent_id).await;
    let mut output = String::from(
        " File ID   Size      Progress  State     File\n -------   ----      --------  -----     ----\n",
    );
    let mut count = 0_usize;

    while !parser.is_empty() {
        let file_id = parser.read_u32("transfer list file id")?;
        let progress = u64::from(parser.read_u32("transfer list progress")?);
        let state = parser.read_u32("transfer list state")?;
        if let Some((_, download)) =
            active.iter().find(|(active_file_id, _)| *active_file_id == file_id)
        {
            output.push_str(&format!(
                " {file_id:<7x}   {:<8}  {:<8}  {:<8}  {}\n",
                byte_count(download.expected_size),
                transfer_progress_text(progress, download.expected_size),
                transfer_state_name(state),
                download.remote_path
            ));
            count += 1;
        }
    }

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandTransfer),
        request_id,
        "Info",
        &format!("List downloads [{count} current downloads]:"),
        Some(output.trim_end().to_owned()),
    )?);

    Ok(())
}
