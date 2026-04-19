//! Tests for error paths in `handle_net_callback`.

use super::super::super::CommandDispatchError;
use super::super::handle_net_callback;
use super::common::{AGENT_ID, REQUEST_ID, encode_u32};
use crate::EventBus;

#[tokio::test]
async fn invalid_subcommand_returns_invalid_callback_payload() {
    let payload = encode_u32(0xFF);
    let events = EventBus::default();
    let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload, got {result:?}"
    );
}

#[tokio::test]
async fn empty_payload_returns_invalid_callback_payload() {
    let events = EventBus::default();
    let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &[]).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for empty payload, got {result:?}"
    );
}
