//! Dispatch handlers for `CommandTransfer`, `CommandMemFile`, `CommandPackageDropped`,
//! and `BeaconOutput` callbacks.

use red_cell_common::demon::{DemonCommand, DemonTransferCommand};

use crate::EventBus;

use super::{CallbackParser, CommandDispatchError, DownloadTracker};

mod beacon_output;
mod control;
mod helpers;
mod list;
mod mem_file;

// Re-exported for sibling dispatch submodules (e.g. `filesystem`) that format
// byte sizes in operator-facing output.
pub(super) use helpers::byte_count;

// The `BeaconOutput` callback handler lives in its own submodule; expose it
// under the historical name so the outer dispatch module call site is
// unaffected by the extraction.
pub(super) use beacon_output::handle_beacon_output as handle_beacon_output_callback;

// The `CommandMemFile` and `CommandPackageDropped` callback handlers live in
// their own submodule; re-export them so the outer dispatch module call sites
// are unaffected by the extraction.
pub(super) use mem_file::{handle_mem_file_callback, handle_package_dropped_callback};

#[cfg(test)]
mod tests;

pub(super) async fn handle_transfer_callback(
    events: &EventBus,
    downloads: &DownloadTracker,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandTransfer));
    let subcommand = parser.read_u32("transfer subcommand")?;
    let subcommand = DemonTransferCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandTransfer),
            message: error.to_string(),
        }
    })?;

    match subcommand {
        DemonTransferCommand::List => {
            list::handle_list(events, downloads, agent_id, request_id, &mut parser).await?;
        }
        DemonTransferCommand::Stop
        | DemonTransferCommand::Resume
        | DemonTransferCommand::Remove => {
            control::handle_control(
                events,
                downloads,
                agent_id,
                request_id,
                subcommand,
                &mut parser,
            )
            .await?;
        }
    }

    Ok(None)
}
