use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonPackage};

use super::super::{DispatchResult, dispatch};
use super::le_u32_pair;
use crate::config::SpecterConfig;
use crate::download::DownloadTracker;
use crate::job::JobStore;
use crate::token::TokenVault;

// ── handle_sleep ─────────────────────────────────────────────────────────

#[test]
fn handle_sleep_updates_config_and_echoes_values() {
    let mut config = SpecterConfig::default();
    let payload = le_u32_pair(3000, 25);
    let package = DemonPackage::new(DemonCommand::CommandSleep, 42, payload);
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

    assert_eq!(config.sleep_delay_ms, 3000);
    assert_eq!(config.sleep_jitter, 25);

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandSleep));
    let expected_delay = 3000u32.to_le_bytes();
    let expected_jitter = 25u32.to_le_bytes();
    assert_eq!(&resp.payload[0..4], &expected_delay);
    assert_eq!(&resp.payload[4..8], &expected_jitter);
}

#[test]
fn handle_sleep_clamps_jitter_to_100() {
    let mut config = SpecterConfig::default();
    let payload = le_u32_pair(1000, 150); // jitter > 100
    let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
    dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert_eq!(config.sleep_jitter, 100);
}

#[test]
fn handle_sleep_short_payload_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandSleep, 1, vec![0x01]); // too short
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
    assert!(matches!(result, DispatchResult::Ignore));
}

// ── dispatch routing ──────────────────────────────────────────────────────

#[test]
fn dispatch_routes_command_sleep() {
    let mut config = SpecterConfig::default();
    let payload = le_u32_pair(500, 10);
    let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
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

// ── edge cases ────────────────────────────────────────────────────────────

#[test]
fn handle_sleep_zero_delay_and_zero_jitter() {
    let mut config = SpecterConfig::default();
    config.sleep_delay_ms = 1000;
    config.sleep_jitter = 50;
    let payload = le_u32_pair(0, 0);
    let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
    dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert_eq!(config.sleep_delay_ms, 0);
    assert_eq!(config.sleep_jitter, 0);
}

#[test]
fn handle_sleep_max_u32_delay() {
    let mut config = SpecterConfig::default();
    let payload = le_u32_pair(u32::MAX, 100);
    let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
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
    assert_eq!(config.sleep_delay_ms, u32::MAX);
    assert_eq!(config.sleep_jitter, 100);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    let echoed_delay = u32::from_le_bytes(resp.payload[0..4].try_into().expect("delay"));
    assert_eq!(echoed_delay, u32::MAX);
}
