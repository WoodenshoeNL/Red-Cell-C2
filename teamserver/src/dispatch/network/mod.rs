//! Dispatch handlers for `CommandNet` callbacks.
//!
//! Routes the net subcommand u32 to per-operation handlers. Domain membership,
//! computer, and DC listing live in `domain`; logon, session, and user
//! enumeration in `sessions`; share and group enumeration in `groups`.
//! The `int_to_ipv4` utility is re-exported for use by the sibling `socket`
//! module.

use red_cell_common::demon::{DemonCommand, DemonNetCommand};

use crate::EventBus;

use super::{CallbackParser, CommandDispatchError, agent_response_event};

mod domain;
mod groups;
mod sessions;
mod util;

// Re-export for sibling `socket` module: `use super::network::int_to_ipv4`.
pub(super) use util::int_to_ipv4;

#[cfg(test)]
mod tests;

pub(super) async fn handle_net_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandNet));
    let subcommand = parser.read_u32("net subcommand")?;
    let subcommand = DemonNetCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandNet),
            message: error.to_string(),
        }
    })?;

    let (kind, message, output) = match subcommand {
        DemonNetCommand::Domain => domain::handle_domain(&mut parser)?,
        DemonNetCommand::Logons => sessions::handle_logons(&mut parser)?,
        DemonNetCommand::Sessions => sessions::handle_sessions(&mut parser)?,
        DemonNetCommand::Computer => domain::handle_computer(&mut parser)?,
        DemonNetCommand::DcList => domain::handle_dc_list(&mut parser)?,
        DemonNetCommand::Share => groups::handle_share(&mut parser)?,
        DemonNetCommand::LocalGroup => groups::handle_local_group(&mut parser)?,
        DemonNetCommand::Group => groups::handle_group(&mut parser)?,
        DemonNetCommand::Users => sessions::handle_users(&mut parser)?,
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandNet),
        request_id,
        kind,
        &message,
        output,
    )?);
    Ok(None)
}
