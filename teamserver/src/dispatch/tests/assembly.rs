//! Unit tests for the assembly dispatch handlers (BOF, .NET inline execute,
//! PS import, and assembly list versions).

use super::common::*;

use super::super::CommandDispatchError;
use super::super::assembly::{
    BOF_CALLBACK_ERROR, BOF_CALLBACK_OUTPUT, BOF_COULD_NOT_RUN, BOF_EXCEPTION, BOF_RAN_OK,
    BOF_SYMBOL_NOT_FOUND, handle_assembly_inline_execute_callback,
    handle_assembly_list_versions_callback, handle_inline_execute_callback,
    handle_ps_import_callback,
};
use super::super::context::{
    DOTNET_INFO_ENTRYPOINT_EXECUTED, DOTNET_INFO_FAILED, DOTNET_INFO_FINISHED,
    DOTNET_INFO_NET_VERSION, DOTNET_INFO_PATCHED,
};
use crate::EventBus;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;

const AGENT_ID: u32 = 0xCAFE_BABE;
const REQUEST_ID: u32 = 42;

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
            let extra = &resp.info.extra;
            assert_eq!(
                extra.get("Type"),
                Some(&serde_json::Value::String("Good".to_owned())),
                "BOF_RAN_OK should produce Type=Good"
            );
            assert_eq!(
                extra.get("Message"),
                Some(&serde_json::Value::String("BOF execution completed".to_owned())),
                "BOF_RAN_OK should produce Message='BOF execution completed'"
            );
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
            let message = extra.get("Message").expect("unwrap").as_str().expect("unwrap");
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
            let message = extra.get("Message").expect("unwrap").as_str().expect("unwrap");
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
            let message = extra.get("Message").expect("unwrap").as_str().expect("unwrap");
            assert!(message.contains("Failed"), "expected 'Failed' in message, got {message:?}");
        }
        other => panic!("expected AgentResponse, got {other:?}"),
    }
}

// --- handle_assembly_inline_execute_callback ---

#[tokio::test]
async fn assembly_inline_execute_empty_payload_returns_error() {
    let events = EventBus::new(8);
    let result = handle_assembly_inline_execute_callback(&events, AGENT_ID, REQUEST_ID, &[]).await;

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
            let message = extra.get("Message").expect("unwrap").as_str().expect("unwrap");
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
            let message = extra.get("Message").expect("unwrap").as_str().expect("unwrap");
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
            let message = extra.get("Message").expect("unwrap").as_str().expect("unwrap");
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
            let message = extra.get("Message").expect("unwrap").as_str().expect("unwrap");
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
            let message = extra.get("Message").expect("unwrap").as_str().expect("unwrap");
            assert!(message.contains("Failed"), "expected 'Failed' in message, got {message:?}");
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
            let message = extra.get("Message").expect("unwrap").as_str().expect("unwrap");
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
            let message = extra.get("Message").expect("unwrap").as_str().expect("unwrap");
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

    let result = handle_assembly_list_versions_callback(&events, AGENT_ID, REQUEST_ID, &[]).await;
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
