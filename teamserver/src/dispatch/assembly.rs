use red_cell_common::demon::DemonCommand;

use crate::EventBus;

use super::{
    CallbackParser, CommandDispatchError, DOTNET_INFO_ENTRYPOINT_EXECUTED, DOTNET_INFO_FAILED,
    DOTNET_INFO_FINISHED, DOTNET_INFO_NET_VERSION, DOTNET_INFO_PATCHED, agent_response_event,
};

pub(super) async fn handle_assembly_inline_execute_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser =
        CallbackParser::new(payload, u32::from(DemonCommand::CommandAssemblyInlineExecute));
    let info_id = parser.read_u32("assembly inline execute info id")?;

    let (kind, message) = match info_id {
        DOTNET_INFO_PATCHED => {
            ("Info", "[HwBpEngine] Amsi/Etw has been hooked & patched".to_owned())
        }
        DOTNET_INFO_NET_VERSION => {
            ("Info", format!("Using CLR Version: {}", parser.read_utf16("assembly clr version")?))
        }
        DOTNET_INFO_ENTRYPOINT_EXECUTED => (
            "Good",
            format!(
                "Assembly has been executed [Thread: {}]",
                parser.read_u32("assembly entrypoint thread id")?
            ),
        ),
        DOTNET_INFO_FINISHED => ("Good", "Finished executing assembly.".to_owned()),
        DOTNET_INFO_FAILED => {
            ("Error", "Failed to execute assembly or initialize the clr".to_owned())
        }
        _ => return Ok(None),
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute),
        request_id,
        kind,
        &message,
        None,
    )?);
    Ok(None)
}

pub(super) async fn handle_assembly_list_versions_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser =
        CallbackParser::new(payload, u32::from(DemonCommand::CommandAssemblyListVersions));
    let mut output = String::new();
    while !parser.is_empty() {
        output.push_str(&format!("   - {}\n", parser.read_utf16("assembly version")?));
    }

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandAssemblyListVersions),
        request_id,
        "Info",
        "List available assembly versions:",
        Some(output.trim_end().to_owned()),
    )?);
    Ok(None)
}
