use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonPackage, DemonTokenCommand};

use super::super::{DispatchResult, dispatch};
use super::{decode_utf16le_null, le_subcmd};
use super::{parse_bytes_le, parse_u32_le};
use crate::config::SpecterConfig;
use crate::download::DownloadTracker;
use crate::job::JobStore;
use crate::token::TokenVault;

// ── CommandToken helpers ────────────────────────────────────────────────

/// Build a CommandToken package with the given subcommand and args.
fn token_package(subcmd: DemonTokenCommand, args: &[u8]) -> DemonPackage {
    let mut payload = (u32::from(subcmd)).to_le_bytes().to_vec();
    payload.extend_from_slice(args);
    DemonPackage::new(DemonCommand::CommandToken, 1, payload)
}

// ── Token::Impersonate ──────────────────────────────────────────────────

#[test]
fn token_impersonate_nonexistent_returns_failure() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    // Token ID 99 doesn't exist.
    let args = 99u32.to_le_bytes().to_vec();
    let package = token_package(DemonTokenCommand::Impersonate, &args);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandToken));
    // Parse: [subcmd: u32][success: u32]
    let mut off = 0;
    let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
    assert_eq!(subcmd, u32::from(DemonTokenCommand::Impersonate));
    let success = parse_u32_le(&resp.payload, &mut off).expect("success");
    assert_eq!(success, 0); // FALSE — token not found
}

// ── Token::List ─────────────────────────────────────────────────────────

#[test]
fn token_list_empty_vault() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let package = token_package(DemonTokenCommand::List, &[]);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandToken));
    // Only the subcmd header, no entries.
    let mut off = 0;
    let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
    assert_eq!(subcmd, u32::from(DemonTokenCommand::List));
    assert_eq!(off, resp.payload.len()); // no more data
}

#[test]
fn token_list_with_entries() {
    use crate::token::{TokenEntry, TokenType};

    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    vault.add(TokenEntry {
        handle: 0xAA,
        domain_user: "DOM\\user1".to_string(),
        process_id: 100,
        token_type: TokenType::Stolen,
        credentials: None,
    });
    vault.add(TokenEntry {
        handle: 0xBB,
        domain_user: "DOM\\user2".to_string(),
        process_id: 200,
        token_type: TokenType::MakeNetwork,
        credentials: None,
    });

    let package = token_package(DemonTokenCommand::List, &[]);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };

    let mut off = 0;
    let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
    assert_eq!(subcmd, u32::from(DemonTokenCommand::List));

    // Entry 0
    let idx0 = parse_u32_le(&resp.payload, &mut off).expect("idx0");
    assert_eq!(idx0, 0);
    let handle0 = parse_u32_le(&resp.payload, &mut off).expect("handle0");
    assert_eq!(handle0, 0xAA);
    let user0_bytes = parse_bytes_le(&resp.payload, &mut off).expect("user0");
    let user0 = decode_utf16le_null(&user0_bytes);
    assert_eq!(user0, "DOM\\user1");
    let pid0 = parse_u32_le(&resp.payload, &mut off).expect("pid0");
    assert_eq!(pid0, 100);
    let type0 = parse_u32_le(&resp.payload, &mut off).expect("type0");
    assert_eq!(type0, TokenType::Stolen as u32);
    let imp0 = parse_u32_le(&resp.payload, &mut off).expect("imp0");
    assert_eq!(imp0, 0); // not impersonating

    // Entry 1
    let idx1 = parse_u32_le(&resp.payload, &mut off).expect("idx1");
    assert_eq!(idx1, 1);
    let _handle1 = parse_u32_le(&resp.payload, &mut off).expect("handle1");
    let _user1_bytes = parse_bytes_le(&resp.payload, &mut off).expect("user1");
    let pid1 = parse_u32_le(&resp.payload, &mut off).expect("pid1");
    assert_eq!(pid1, 200);
    let type1 = parse_u32_le(&resp.payload, &mut off).expect("type1");
    assert_eq!(type1, TokenType::MakeNetwork as u32);
}

// ── Token::GetUid ───────────────────────────────────────────────────────

#[test]
fn token_getuid_returns_respond() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let package = token_package(DemonTokenCommand::GetUid, &[]);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandToken));
    let mut off = 0;
    let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
    assert_eq!(subcmd, u32::from(DemonTokenCommand::GetUid));
    // elevated: u32
    let _elevated = parse_u32_le(&resp.payload, &mut off).expect("elevated");
    // user: wbytes (length-prefixed)
    let user_bytes = parse_bytes_le(&resp.payload, &mut off).expect("user");
    let user = decode_utf16le_null(&user_bytes);
    assert!(!user.is_empty(), "user string should not be empty");
}

// ── Token::Revert ───────────────────────────────────────────────────────

#[test]
fn token_revert_returns_respond() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let package = token_package(DemonTokenCommand::Revert, &[]);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    let mut off = 0;
    let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
    assert_eq!(subcmd, u32::from(DemonTokenCommand::Revert));
    // On non-Windows: revert_to_self returns Err, so success = 0.
    // On Windows: success depends on thread state.
    let _success = parse_u32_le(&resp.payload, &mut off).expect("success");
}

// ── Token::Remove ───────────────────────────────────────────────────────

#[test]
fn token_remove_nonexistent_returns_failure() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let args = 42u32.to_le_bytes().to_vec();
    let package = token_package(DemonTokenCommand::Remove, &args);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    let mut off = 0;
    let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
    assert_eq!(subcmd, u32::from(DemonTokenCommand::Remove));
    let success = parse_u32_le(&resp.payload, &mut off).expect("success");
    assert_eq!(success, 0); // FALSE — no such token
    let returned_id = parse_u32_le(&resp.payload, &mut off).expect("token_id");
    assert_eq!(returned_id, 42);
}

#[test]
fn token_remove_existing_returns_success() {
    use crate::token::{TokenEntry, TokenType};

    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let id = vault.add(TokenEntry {
        handle: 0,
        domain_user: "D\\U".to_string(),
        process_id: 1,
        token_type: TokenType::Stolen,
        credentials: None,
    });

    let args = id.to_le_bytes().to_vec();
    let package = token_package(DemonTokenCommand::Remove, &args);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    let mut off = 0;
    let _subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
    let success = parse_u32_le(&resp.payload, &mut off).expect("success");
    assert_eq!(success, 1); // TRUE
    assert!(vault.get(id).is_none());
}

// ── Token::Clear ────────────────────────────────────────────────────────

#[test]
fn token_clear_empties_vault() {
    use crate::token::{TokenEntry, TokenType};

    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    vault.add(TokenEntry {
        handle: 0,
        domain_user: "D\\U".to_string(),
        process_id: 1,
        token_type: TokenType::Stolen,
        credentials: None,
    });

    let package = token_package(DemonTokenCommand::Clear, &[]);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    let mut off = 0;
    let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
    assert_eq!(subcmd, u32::from(DemonTokenCommand::Clear));
    assert!(vault.is_empty());
}

// ── Token::FindTokens ───────────────────────────────────────────────────

#[test]
fn token_find_returns_success_with_empty_list_on_non_windows() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let package = token_package(DemonTokenCommand::FindTokens, &[]);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    let mut off = 0;
    let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
    assert_eq!(subcmd, u32::from(DemonTokenCommand::FindTokens));
    // On non-Windows the stub returns success=TRUE with count=0.
    let success = parse_u32_le(&resp.payload, &mut off).expect("success");
    assert_eq!(success, 1);
    let count = parse_u32_le(&resp.payload, &mut off).expect("count");
    assert_eq!(count, 0);
}

// ── Token::PrivsGetOrList ───────────────────────────────────────────────

#[test]
fn token_privs_list_returns_respond() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    // list_privs = 1 (list mode)
    let args = 1u32.to_le_bytes().to_vec();
    let package = token_package(DemonTokenCommand::PrivsGetOrList, &args);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    let mut off = 0;
    let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
    assert_eq!(subcmd, u32::from(DemonTokenCommand::PrivsGetOrList));
    let list_flag = parse_u32_le(&resp.payload, &mut off).expect("list_privs");
    assert_eq!(list_flag, 1);
}

// ── Token::Steal ────────────────────────────────────────────────────────

#[test]
fn token_steal_invalid_pid_returns_ignore() {
    // On non-Windows, steal always fails; on Windows, PID 0 is invalid.
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let mut args = Vec::new();
    args.extend_from_slice(&0u32.to_le_bytes()); // pid = 0
    args.extend_from_slice(&0u32.to_le_bytes()); // handle = 0
    let package = token_package(DemonTokenCommand::Steal, &args);
    // On non-Windows stubs, steal returns Err → DispatchResult::Ignore.
    let result = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Ignore));
}

// ── Token::Make ─────────────────────────────────────────────────────────

#[test]
fn token_make_returns_respond_on_non_windows() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();

    // Build args: [domain: wbytes][user: wbytes][password: wbytes][logon_type: u32]
    let mut args = Vec::new();
    let to_wbytes = |s: &str| -> Vec<u8> {
        let utf16: Vec<u8> =
            s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
        let mut b = (utf16.len() as u32).to_le_bytes().to_vec();
        b.extend_from_slice(&utf16);
        b
    };
    args.extend_from_slice(&to_wbytes("DOMAIN"));
    args.extend_from_slice(&to_wbytes("user"));
    args.extend_from_slice(&to_wbytes("pass"));
    args.extend_from_slice(&9u32.to_le_bytes()); // LOGON32_LOGON_NEW_CREDENTIALS

    let package = token_package(DemonTokenCommand::Make, &args);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    // On non-Windows: make_token fails, so response has subcmd but no domain_user.
    let mut off = 0;
    let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
    assert_eq!(subcmd, u32::from(DemonTokenCommand::Make));
    // Vault should remain empty on failure.
    assert!(vault.is_empty());
}

// ── Token dispatch: unknown subcommand ──────────────────────────────────

#[test]
fn token_unknown_subcommand_returns_ignore() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    // Subcommand 255 is not defined.
    let payload = 255u32.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandToken, 1, payload);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

#[test]
fn token_empty_payload_returns_ignore() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let package = DemonPackage::new(DemonCommand::CommandToken, 1, vec![]);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

#[test]
fn dispatch_routes_command_token_getuid() {
    let mut config = SpecterConfig::default();
    let payload = le_subcmd(6); // GetUid = 6
    let package = DemonPackage::new(DemonCommand::CommandToken, 1, payload);
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
// ── handle_token edge cases ──────────────────────────────────────────────

#[test]
fn token_impersonate_valid_id_on_non_windows_returns_failure() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    // Add a token entry manually (on non-Windows it's a stub).
    use crate::token::{TokenEntry, TokenType};
    vault.add(TokenEntry {
        handle: 0,
        domain_user: "DOMAIN\\user".into(),
        process_id: 0,
        token_type: TokenType::Stolen,
        credentials: None,
    });

    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes()); // subcommand = Impersonate (= 1)
    payload.extend_from_slice(&0u32.to_le_bytes()); // vault index = 0
    let package = DemonPackage::new(DemonCommand::CommandToken, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    // On non-Windows, impersonation fails because there's no real handle.
    assert!(matches!(result, DispatchResult::Respond(_)));
}
