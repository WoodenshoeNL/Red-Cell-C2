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

/// Handle a `CommandPsImport` (0x1011) callback from a Demon agent.
///
/// When the agent finishes importing a PowerShell script into memory it sends
/// back a callback with a single UTF-8 output string describing the result.
/// This handler reads the output and broadcasts it to connected operators.
pub(super) async fn handle_ps_import_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandPsImport));
    let output = parser.read_string("ps import output")?;

    let message = if output.is_empty() {
        "PowerShell script imported successfully".to_owned()
    } else {
        output
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandPsImport),
        request_id,
        "Good",
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

#[cfg(test)]
mod tests {
    use red_cell_common::demon::DemonCommand;
    use red_cell_common::operator::OperatorMessage;

    use super::*;

    const AGENT_ID: u32 = 0xCAFE_BABE;
    const REQUEST_ID: u32 = 42;

    fn add_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn add_u64(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn add_bytes(buf: &mut Vec<u8>, value: &[u8]) {
        add_u32(buf, u32::try_from(value.len()).unwrap_or_default());
        buf.extend_from_slice(value);
    }

    fn add_utf16(buf: &mut Vec<u8>, value: &str) {
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.extend_from_slice(&[0, 0]);
        add_bytes(buf, &encoded);
    }

    // --- handle_inline_execute_callback ---

    #[tokio::test]
    async fn inline_execute_empty_payload_returns_error() {
        let events = EventBus::new(8);
        let result = handle_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &[]).await;

        match result {
            Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
                assert_eq!(command_id, u32::from(DemonCommand::CommandInlineExecute));
            }
            other => panic!("expected InvalidCallbackPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inline_execute_unknown_callback_type_returns_ok_none() {
        let events = EventBus::new(8);
        let mut payload = Vec::new();
        add_u32(&mut payload, 0xDEAD);

        let result = handle_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn inline_execute_truncated_after_callback_type_returns_error() {
        let events = EventBus::new(8);
        // BOF_CALLBACK_OUTPUT requires a subsequent read_string; give only the type.
        let mut payload = Vec::new();
        add_u32(&mut payload, BOF_CALLBACK_OUTPUT);

        let result = handle_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;

        match result {
            Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
                assert_eq!(command_id, u32::from(DemonCommand::CommandInlineExecute));
            }
            other => panic!("expected InvalidCallbackPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inline_execute_bof_callback_error_broadcasts_error_event() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_u32(&mut payload, BOF_CALLBACK_ERROR);
        add_bytes(&mut payload, b"something went wrong in BOF");

        let result = handle_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                let extra = &resp.info.extra;
                assert_eq!(
                    extra.get("Type"),
                    Some(&serde_json::Value::String("Error".to_owned())),
                    "BOF_CALLBACK_ERROR should produce Type=Error"
                );
                assert_eq!(
                    extra.get("Message"),
                    Some(&serde_json::Value::String("something went wrong in BOF".to_owned())),
                    "BOF_CALLBACK_ERROR should forward the error string as Message"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inline_execute_bof_callback_error_truncated_returns_error() {
        let events = EventBus::new(8);
        // BOF_CALLBACK_ERROR requires a subsequent read_string; give only the type.
        let mut payload = Vec::new();
        add_u32(&mut payload, BOF_CALLBACK_ERROR);

        let result = handle_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;

        match result {
            Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
                assert_eq!(command_id, u32::from(DemonCommand::CommandInlineExecute));
            }
            other => panic!("expected InvalidCallbackPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inline_execute_bof_ran_ok_broadcasts_event() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_u32(&mut payload, BOF_RAN_OK);

        let result = handle_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                assert!(resp.info.output.is_empty() || resp.info.output.contains("BOF"));
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inline_execute_bof_exception_broadcasts_hex_codes() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_u32(&mut payload, BOF_EXCEPTION);
        add_u32(&mut payload, 0xC000_0005); // exception code
        add_u64(&mut payload, 0x00007FFA_DEADBEEF); // exception address

        let result = handle_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                let extra = &resp.info.extra;
                assert_eq!(
                    extra.get("Type"),
                    Some(&serde_json::Value::String("Error".to_owned())),
                    "BOF_EXCEPTION should produce Type=Error"
                );
                let message = extra.get("Message").unwrap().as_str().unwrap();
                assert!(
                    message.contains("C0000005"),
                    "expected exception code 0xC0000005 in message, got {message:?}"
                );
                assert!(
                    message.contains("00007FFADEADBEEF"),
                    "expected exception address in message, got {message:?}"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inline_execute_bof_exception_truncated_returns_error() {
        let events = EventBus::new(8);
        // BOF_EXCEPTION needs u32 + u64; give only the type + exception code (no address).
        let mut payload = Vec::new();
        add_u32(&mut payload, BOF_EXCEPTION);
        add_u32(&mut payload, 0xC000_0005);

        let result = handle_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;

        match result {
            Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
                assert_eq!(command_id, u32::from(DemonCommand::CommandInlineExecute));
            }
            other => panic!("expected InvalidCallbackPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inline_execute_bof_symbol_not_found_broadcasts_symbol_name() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_u32(&mut payload, BOF_SYMBOL_NOT_FOUND);
        add_bytes(&mut payload, b"kernel32.dll!SomeExport");

        let result = handle_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                let extra = &resp.info.extra;
                assert_eq!(
                    extra.get("Type"),
                    Some(&serde_json::Value::String("Error".to_owned())),
                    "BOF_SYMBOL_NOT_FOUND should produce Type=Error"
                );
                let message = extra.get("Message").unwrap().as_str().unwrap();
                assert!(
                    message.contains("kernel32.dll!SomeExport"),
                    "expected symbol name in message, got {message:?}"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inline_execute_bof_symbol_not_found_truncated_returns_error() {
        let events = EventBus::new(8);
        // BOF_SYMBOL_NOT_FOUND needs a string; give only the type.
        let mut payload = Vec::new();
        add_u32(&mut payload, BOF_SYMBOL_NOT_FOUND);

        let result = handle_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;

        match result {
            Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
                assert_eq!(command_id, u32::from(DemonCommand::CommandInlineExecute));
            }
            other => panic!("expected InvalidCallbackPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inline_execute_bof_could_not_run_broadcasts_error() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_u32(&mut payload, BOF_COULD_NOT_RUN);

        let result = handle_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                let extra = &resp.info.extra;
                assert_eq!(
                    extra.get("Type"),
                    Some(&serde_json::Value::String("Error".to_owned())),
                    "BOF_COULD_NOT_RUN should produce Type=Error"
                );
                let message = extra.get("Message").unwrap().as_str().unwrap();
                assert!(
                    message.contains("Failed"),
                    "expected 'Failed' in message, got {message:?}"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    // --- handle_assembly_inline_execute_callback ---

    #[tokio::test]
    async fn assembly_inline_execute_empty_payload_returns_error() {
        let events = EventBus::new(8);
        let result =
            handle_assembly_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &[]).await;

        match result {
            Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
                assert_eq!(command_id, u32::from(DemonCommand::CommandAssemblyInlineExecute));
            }
            other => panic!("expected InvalidCallbackPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn assembly_inline_execute_unknown_info_id_returns_ok_none() {
        let events = EventBus::new(8);
        let mut payload = Vec::new();
        add_u32(&mut payload, 0xDEAD);

        let result =
            handle_assembly_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn assembly_inline_execute_truncated_clr_version_returns_error() {
        let events = EventBus::new(8);
        // DOTNET_INFO_NET_VERSION requires a subsequent read_utf16; give only the info id.
        let mut payload = Vec::new();
        add_u32(&mut payload, DOTNET_INFO_NET_VERSION);

        let result =
            handle_assembly_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;

        match result {
            Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
                assert_eq!(command_id, u32::from(DemonCommand::CommandAssemblyInlineExecute));
            }
            other => panic!("expected InvalidCallbackPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn assembly_inline_execute_patched_broadcasts_info() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_u32(&mut payload, DOTNET_INFO_PATCHED);

        let result =
            handle_assembly_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                let extra = &resp.info.extra;
                assert_eq!(extra.get("Type"), Some(&serde_json::Value::String("Info".to_owned())),);
                let message = extra.get("Message").unwrap().as_str().unwrap();
                assert!(
                    message.contains("Amsi/Etw"),
                    "expected patched message to mention Amsi/Etw, got {message:?}"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn assembly_inline_execute_net_version_broadcasts_clr_version() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_u32(&mut payload, DOTNET_INFO_NET_VERSION);
        add_utf16(&mut payload, "v4.0.30319");

        let result =
            handle_assembly_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                let extra = &resp.info.extra;
                assert_eq!(extra.get("Type"), Some(&serde_json::Value::String("Info".to_owned())),);
                let message = extra.get("Message").unwrap().as_str().unwrap();
                assert!(
                    message.contains("v4.0.30319"),
                    "expected CLR version in message, got {message:?}"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn assembly_inline_execute_entrypoint_executed_broadcasts_thread_id() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_u32(&mut payload, DOTNET_INFO_ENTRYPOINT_EXECUTED);
        add_u32(&mut payload, 1337); // thread id

        let result =
            handle_assembly_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                let extra = &resp.info.extra;
                assert_eq!(extra.get("Type"), Some(&serde_json::Value::String("Good".to_owned())),);
                let message = extra.get("Message").unwrap().as_str().unwrap();
                assert!(
                    message.contains("1337"),
                    "expected thread id 1337 in message, got {message:?}"
                );
                assert!(
                    message.contains("Thread"),
                    "expected 'Thread' label in message, got {message:?}"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn assembly_inline_execute_entrypoint_truncated_returns_error() {
        let events = EventBus::new(8);
        // DOTNET_INFO_ENTRYPOINT_EXECUTED requires a subsequent read_u32 for thread id.
        let mut payload = Vec::new();
        add_u32(&mut payload, DOTNET_INFO_ENTRYPOINT_EXECUTED);

        let result =
            handle_assembly_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;

        match result {
            Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
                assert_eq!(command_id, u32::from(DemonCommand::CommandAssemblyInlineExecute));
            }
            other => panic!("expected InvalidCallbackPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn assembly_inline_execute_finished_broadcasts_good() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_u32(&mut payload, DOTNET_INFO_FINISHED);

        let result =
            handle_assembly_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                let extra = &resp.info.extra;
                assert_eq!(extra.get("Type"), Some(&serde_json::Value::String("Good".to_owned())),);
                let message = extra.get("Message").unwrap().as_str().unwrap();
                assert!(
                    message.contains("Finished"),
                    "expected 'Finished' in message, got {message:?}"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn assembly_inline_execute_failed_broadcasts_error() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_u32(&mut payload, DOTNET_INFO_FAILED);

        let result =
            handle_assembly_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                let extra = &resp.info.extra;
                assert_eq!(extra.get("Type"), Some(&serde_json::Value::String("Error".to_owned())),);
                let message = extra.get("Message").unwrap().as_str().unwrap();
                assert!(
                    message.contains("Failed"),
                    "expected 'Failed' in message, got {message:?}"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    // --- handle_ps_import_callback ---

    #[tokio::test]
    async fn ps_import_empty_payload_returns_error() {
        let events = EventBus::new(8);
        let result = handle_ps_import_callback(&events, AGENT_ID, REQUEST_ID, &[]).await;

        match result {
            Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
                assert_eq!(command_id, u32::from(DemonCommand::CommandPsImport));
            }
            other => panic!("expected InvalidCallbackPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ps_import_with_output_broadcasts_message() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_bytes(&mut payload, b"Script loaded: Invoke-Mimikatz.ps1");

        let result = handle_ps_import_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                let extra = &resp.info.extra;
                assert_eq!(extra.get("Type"), Some(&serde_json::Value::String("Good".to_owned())));
                let message = extra.get("Message").unwrap().as_str().unwrap();
                assert!(
                    message.contains("Invoke-Mimikatz.ps1"),
                    "expected output text in message, got {message:?}"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ps_import_empty_output_broadcasts_default_message() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_bytes(&mut payload, b"");

        let result = handle_ps_import_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                let extra = &resp.info.extra;
                assert_eq!(extra.get("Type"), Some(&serde_json::Value::String("Good".to_owned())));
                let message = extra.get("Message").unwrap().as_str().unwrap();
                assert!(
                    message.contains("PowerShell"),
                    "expected default PowerShell message, got {message:?}"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    // --- handle_assembly_list_versions_callback ---

    #[tokio::test]
    async fn list_versions_empty_payload_broadcasts_empty_output() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();

        let result =
            handle_assembly_list_versions_callback(&events, AGENT_ID, REQUEST_ID, &[]).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                assert!(
                    resp.info.output.is_empty(),
                    "expected empty output for zero versions, got {:?}",
                    resp.info.output,
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_versions_truncated_utf16_returns_error() {
        let events = EventBus::new(8);
        // Provide a length prefix that claims more bytes than available.
        let mut payload = Vec::new();
        add_u32(&mut payload, 100); // claim 100 bytes of UTF-16 data
        payload.push(0x41); // only 1 byte present

        let result =
            handle_assembly_list_versions_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;

        match result {
            Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
                assert_eq!(command_id, u32::from(DemonCommand::CommandAssemblyListVersions));
            }
            other => panic!("expected InvalidCallbackPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_versions_odd_byte_utf16_returns_error() {
        let events = EventBus::new(8);
        // Provide an odd number of bytes as UTF-16 data — must be rejected.
        let mut payload = Vec::new();
        add_u32(&mut payload, 3); // 3 bytes — not even
        payload.extend_from_slice(&[0x41, 0x00, 0x42]);

        let result =
            handle_assembly_list_versions_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;

        match result {
            Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
                assert_eq!(command_id, u32::from(DemonCommand::CommandAssemblyListVersions));
            }
            other => panic!("expected InvalidCallbackPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_versions_valid_single_version_broadcasts_output() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();
        let mut payload = Vec::new();
        add_utf16(&mut payload, "v4.0.30319");

        let result =
            handle_assembly_list_versions_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                assert!(
                    resp.info.output.contains("v4.0.30319"),
                    "expected output to contain version string, got {:?}",
                    resp.info.output,
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }
}
