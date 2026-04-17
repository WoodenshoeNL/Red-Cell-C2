//! Tests for the transfer dispatch module.
//!
//! Per-command tests are split into submodules; shared helpers live here so that
//! every submodule can reach them via `super::`.

use super::super::{CommandDispatchError, DownloadTracker};
use super::handle_transfer_callback;
use crate::EventBus;

mod beacon_output;
mod control;
mod list;
mod mem_file;

// `assert_no_events_broadcast` is defined in the `mem_file` submodule; re-export
// it at the tests-module level so sibling submodules can continue to reach it
// via `super::assert_no_events_broadcast`.
pub(super) use mem_file::assert_no_events_broadcast;

fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn length_prefixed(data: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(data.len()).expect("test data fits in u32").to_le_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

// ------------------------------------------------------------------
// Malformed-payload tests — CommandTransfer
// ------------------------------------------------------------------

#[tokio::test]
async fn transfer_callback_invalid_subcommand_returns_error() {
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);

    // Subcommand 0xFF is not a valid DemonTransferCommand.
    let payload = le32(0xFF);

    let result = handle_transfer_callback(&events, &downloads, 0x1111_0001, 1, &payload).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "invalid subcommand must yield InvalidCallbackPayload; got: {result:?}"
    );
    assert_no_events_broadcast(events).await;
}

// ------------------------------------------------------------------
// Existing truncated-transfer test also asserts no events
// ------------------------------------------------------------------

#[tokio::test]
async fn transfer_callback_truncated_returns_error_no_events() {
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);

    let result = handle_transfer_callback(&events, &downloads, 0x1111_1111, 1, &[]).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "empty payload must yield InvalidCallbackPayload; got: {result:?}"
    );
    assert_no_events_broadcast(events).await;
}
