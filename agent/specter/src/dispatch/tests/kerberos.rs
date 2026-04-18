use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonPackage};

use super::super::kerberos::{
    handle_kerberos, handle_kerberos_klist, handle_kerberos_luid, handle_kerberos_ptt,
    handle_kerberos_purge,
};
use super::super::{DispatchResult, MemFileStore, dispatch};
use super::le_subcmd;
use crate::config::SpecterConfig;
use crate::download::DownloadTracker;
use crate::job::JobStore;
use crate::token::TokenVault;

// ── Kerberos tests ─────────────────────────────────────────────────────

/// Build a Kerberos task payload with the given subcommand and extra args.
fn kerberos_payload(subcmd: u32, extra: &[u8]) -> Vec<u8> {
    let mut v = subcmd.to_le_bytes().to_vec();
    v.extend_from_slice(extra);
    v
}

#[test]
fn kerberos_dispatch_routes_to_handler() {
    let payload = kerberos_payload(0, &[]); // Luid subcommand
    let pkg = DemonPackage {
        command_id: u32::from(DemonCommand::CommandKerberos),
        request_id: 1,
        payload,
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
    // On non-Windows, get_luid returns error → success=FALSE.
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandKerberos));
    // Parse: [subcmd=0][success=0]
    assert!(resp.payload.len() >= 8);
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 0); // subcmd
    // On non-Windows, success is 0 (FALSE)
    #[cfg(not(windows))]
    assert_eq!(u32::from_le_bytes(resp.payload[4..8].try_into().unwrap()), 0);
}

#[test]
fn kerberos_luid_response_format() {
    let result = handle_kerberos_luid(0);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandKerberos));
    // Subcmd should be 0.
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 0);
    // On non-Windows: [subcmd=0][success=0] → 8 bytes
    #[cfg(not(windows))]
    assert_eq!(resp.payload.len(), 8);
}

#[test]
fn kerberos_klist_all_response_format() {
    // type=0 means /all
    let mut rest = Vec::new();
    rest.extend_from_slice(&0u32.to_le_bytes()); // type = 0 (/all)
    let result = handle_kerberos_klist(1, &rest);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandKerberos));
    // [subcmd=1][success=0] on non-Windows → 8 bytes
    #[cfg(not(windows))]
    assert_eq!(resp.payload.len(), 8);
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 1); // subcmd
}

#[test]
fn kerberos_klist_by_luid_response_format() {
    // type=1 means /luid, then a LUID value
    let mut rest = Vec::new();
    rest.extend_from_slice(&1u32.to_le_bytes()); // type = 1 (/luid)
    rest.extend_from_slice(&0x1234u32.to_le_bytes()); // target LUID
    let result = handle_kerberos_klist(1, &rest);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 1);
}

#[test]
fn kerberos_klist_missing_luid_ignored() {
    // type=1 but no LUID value → parse error → Ignore
    let rest = 1u32.to_le_bytes().to_vec(); // type = 1 (/luid), no LUID
    let result = handle_kerberos_klist(1, &rest);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn kerberos_purge_response_format() {
    let rest = 0xABCDu32.to_le_bytes().to_vec();
    let result = handle_kerberos_purge(2, &rest);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 2); // subcmd
    // On non-Windows: success = 0
    #[cfg(not(windows))]
    assert_eq!(u32::from_le_bytes(resp.payload[4..8].try_into().unwrap()), 0);
}

#[test]
fn kerberos_purge_missing_luid_ignored() {
    let result = handle_kerberos_purge(2, &[]);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn kerberos_ptt_response_format() {
    let ticket = vec![0x61, 0x82, 0x03, 0x00];
    let luid: u32 = 0x5678;
    let mut rest = Vec::new();
    // Length-prefixed ticket bytes.
    rest.extend_from_slice(&(ticket.len() as u32).to_le_bytes());
    rest.extend_from_slice(&ticket);
    rest.extend_from_slice(&luid.to_le_bytes());
    let result = handle_kerberos_ptt(3, &rest);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 3); // subcmd
    // On non-Windows: success = 0
    #[cfg(not(windows))]
    assert_eq!(u32::from_le_bytes(resp.payload[4..8].try_into().unwrap()), 0);
}

#[test]
fn kerberos_ptt_missing_ticket_ignored() {
    let result = handle_kerberos_ptt(3, &[]);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn kerberos_ptt_missing_luid_after_ticket_ignored() {
    // Valid ticket but no LUID after it.
    let mut rest = Vec::new();
    rest.extend_from_slice(&2u32.to_le_bytes()); // ticket length = 2
    rest.extend_from_slice(&[0xAA, 0xBB]); // ticket data
    // No LUID following → parse error.
    let result = handle_kerberos_ptt(3, &rest);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn kerberos_unknown_subcommand_ignored() {
    let payload = kerberos_payload(99, &[]); // invalid subcmd
    let result = handle_kerberos(&payload);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn kerberos_empty_payload_ignored() {
    let result = handle_kerberos(&[]);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn dispatch_routes_command_kerberos() {
    let mut config = SpecterConfig::default();
    // Kerberos subcommand 0 = Luid
    let payload = le_subcmd(0);
    let package = DemonPackage::new(DemonCommand::CommandKerberos, 1, payload);
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
