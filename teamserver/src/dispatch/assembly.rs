use red_cell_common::demon::DemonCommand;

use crate::EventBus;

use super::{
    CallbackParser, CommandDispatchError, DOTNET_INFO_ENTRYPOINT_EXECUTED, DOTNET_INFO_FAILED,
    DOTNET_INFO_FINISHED, DOTNET_INFO_NET_VERSION, DOTNET_INFO_PATCHED, agent_response_event,
};

/// Havoc BOF/CoffeeLdr callback sub-type: standard output from the BOF.
const BOF_CALLBACK_OUTPUT: u32 = 0x00;
/// Havoc BOF/CoffeeLdr callback sub-type: error output from the BOF.
const BOF_CALLBACK_ERROR: u32 = 0x0d;
/// Havoc `COMMAND_INLINEEXECUTE_EXCEPTION` — an exception was thrown during BOF execution.
const BOF_EXCEPTION: u32 = 1;
/// Havoc `COMMAND_INLINEEXECUTE_SYMBOL_NOT_FOUND` — a required DLL export was not resolved.
const BOF_SYMBOL_NOT_FOUND: u32 = 2;
/// Havoc `COMMAND_INLINEEXECUTE_RAN_OK` — the BOF ran to completion successfully.
const BOF_RAN_OK: u32 = 3;
/// Havoc `COMMAND_INLINEEXECUTE_COULD_NO_RUN` — the loader could not start the BOF at all.
const BOF_COULD_NOT_RUN: u32 = 4;

/// Handle a `COMMAND_INLINEEXECUTE` (BOF/CoffeeLdr) callback from a Demon agent.
///
/// Parses the Havoc BOF callback sub-type and emits an operator event describing
/// the outcome.  Sub-types are:
///
/// | Value  | Meaning |
/// |--------|---------|
/// | `0x00` | Standard output text produced by the BOF |
/// | `0x0d` | Error output text produced by the BOF |
/// | `1`    | An exception occurred during BOF execution |
/// | `2`    | A required symbol (DLL export) was not found |
/// | `3`    | BOF ran to completion (`COMMAND_INLINEEXECUTE_RAN_OK`) |
/// | `4`    | BOF could not be started (`COMMAND_INLINEEXECUTE_COULD_NO_RUN`) |
pub(super) async fn handle_inline_execute_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandInlineExecute));
    let callback_type = parser.read_u32("bof callback type")?;

    let (kind, message) = match callback_type {
        BOF_CALLBACK_OUTPUT => ("Output", parser.read_string("bof output")?),
        BOF_CALLBACK_ERROR => ("Error", parser.read_string("bof error output")?),
        BOF_EXCEPTION => {
            let exception = parser.read_u32("bof exception code")?;
            let address = parser.read_u64("bof exception address")?;
            (
                "Error",
                format!(
                    "Exception 0x{exception:08X} occurred while executing BOF at address \
                     0x{address:016X}"
                ),
            )
        }
        BOF_SYMBOL_NOT_FOUND => {
            let symbol = parser.read_string("bof missing symbol")?;
            ("Error", format!("Symbol not found: {symbol}"))
        }
        BOF_RAN_OK => ("Good", "BOF execution completed".to_owned()),
        BOF_COULD_NOT_RUN => ("Error", "Failed to execute object file".to_owned()),
        _ => return Ok(None),
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandInlineExecute),
        request_id,
        kind,
        &message,
        None,
    )?);
    Ok(None)
}

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
