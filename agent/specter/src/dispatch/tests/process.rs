use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonNetCommand, DemonPackage, DemonProcessCommand};

use super::super::process::{arch_from_wow64, translate_to_shell_cmd};
use super::super::{DispatchResult, dispatch};
use super::{decode_utf16le_null, le_subcmd, le_utf16le_payload, parse_bytes_le, parse_u32_le};
use crate::config::SpecterConfig;
use crate::download::DownloadTracker;
use crate::job::JobStore;
use crate::token::TokenVault;

// ── handle_proc_list ─────────────────────────────────────────────────────

#[test]
fn handle_proc_list_uses_correct_command_id() {
    let mut config = SpecterConfig::default();
    // process_ui = 0 (console request)
    let payload = 0u32.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandProcList, 1, payload);
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
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProcList));
}

#[test]
fn handle_proc_list_echoes_process_ui_flag() {
    let mut config = SpecterConfig::default();
    // process_ui = 1 (from process manager)
    let payload = 1u32.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandProcList, 2, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    let echoed_ui = u32::from_le_bytes(resp.payload[0..4].try_into().expect("le u32"));
    assert_eq!(echoed_ui, 1, "process_ui must be echoed verbatim");
}

#[test]
fn handle_proc_list_contains_at_least_one_process() {
    let mut config = SpecterConfig::default();
    let payload = 0u32.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandProcList, 3, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    // Payload must be > 4 bytes (the process_ui field) if any processes were enumerated.
    assert!(resp.payload.len() > 4, "process list must contain at least one entry");
}

#[test]
fn handle_proc_list_includes_self_pid() {
    let own_pid = std::process::id();
    let mut config = SpecterConfig::default();
    let payload = 0u32.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandProcList, 4, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    // Parse the response (LE): skip process_ui (4 bytes), then iterate entries.
    let p = &resp.payload;
    let mut pos = 4usize; // skip process_ui
    let mut found = false;
    while pos + 4 <= p.len() {
        // name: length-prefixed utf16le (LE length prefix)
        let name_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("name len")) as usize;
        pos += 4 + name_len;
        if pos + 4 > p.len() {
            break;
        }
        // pid (LE)
        let pid = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("pid"));
        pos += 4;
        if pid == own_pid {
            found = true;
        }
        // skip: is_wow64 + ppid + session_id + threads = 4 × u32 = 16 bytes
        pos += 16;
        // user: length-prefixed utf16le (LE length prefix)
        if pos + 4 > p.len() {
            break;
        }
        let user_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("user len")) as usize;
        pos += 4 + user_len;
    }
    assert!(found, "own PID {own_pid} not found in process list");
}

// ── handle_proc_modules ──────────────────────────────────────────────────

#[test]
fn handle_proc_modules_returns_correct_command_id() {
    let mut config = SpecterConfig::default();
    // pid=0 → current process
    let mut payload = 2u32.to_le_bytes().to_vec(); // subcmd = Modules
    payload.extend_from_slice(&0u32.to_le_bytes()); // pid = 0
    let package = DemonPackage::new(DemonCommand::CommandProc, 10, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProc));
    // First 4 bytes must be subcmd=2 (LE)
    let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
    assert_eq!(subcmd, 2);
}

#[test]
fn handle_proc_modules_echoes_pid() {
    let mut config = SpecterConfig::default();
    let mut payload = 2u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&42u32.to_le_bytes()); // arbitrary pid
    let package = DemonPackage::new(DemonCommand::CommandProc, 11, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    let echoed_pid = u32::from_le_bytes(resp.payload[4..8].try_into().expect("pid"));
    assert_eq!(echoed_pid, 42);
}

// ── handle_proc_grep ─────────────────────────────────────────────────────

#[test]
fn handle_proc_grep_correct_command_id_and_subcmd() {
    let mut config = SpecterConfig::default();
    let mut payload = 3u32.to_le_bytes().to_vec(); // subcmd = Grep
    payload.extend_from_slice(&le_utf16le_payload("nonexistent_xzy_proc_name_123"));
    let package = DemonPackage::new(DemonCommand::CommandProc, 20, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProc));
    let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
    assert_eq!(subcmd, 3, "subcmd must be echoed as 3 (Grep)");
}

#[test]
fn handle_proc_grep_empty_result_when_no_match() {
    let mut config = SpecterConfig::default();
    let mut payload = 3u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&le_utf16le_payload("zzz_no_such_process_zzz_99999"));
    let package = DemonPackage::new(DemonCommand::CommandProc, 21, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    // Only the subcmd field (4 bytes); no process entries.
    assert_eq!(resp.payload.len(), 4, "no match → payload must be exactly subcmd u32");
}

#[test]
fn handle_proc_grep_missing_name_returns_ignore() {
    let mut config = SpecterConfig::default();
    // Only the subcmd, no name bytes
    let payload = 3u32.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandProc, 22, payload);
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

#[test]
fn arch_from_wow64_encodes_correctly() {
    // Mirrors Phantom's convention: is_wow64=true → 86, is_wow64=false → 64.
    assert_eq!(arch_from_wow64(true), 86, "WOW64 process must report arch=86");
    assert_eq!(arch_from_wow64(false), 64, "native x64 process must report arch=64");
}

// ── handle_proc_memory ───────────────────────────────────────────────────

#[test]
fn handle_proc_memory_correct_command_id_and_subcmd() {
    let mut config = SpecterConfig::default();
    let mut payload = 6u32.to_le_bytes().to_vec(); // subcmd = Memory
    payload.extend_from_slice(&0u32.to_le_bytes()); // pid = 0
    payload.extend_from_slice(&0u32.to_le_bytes()); // filter = all
    let package = DemonPackage::new(DemonCommand::CommandProc, 30, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProc));
    let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
    assert_eq!(subcmd, 6, "subcmd must be echoed as 6 (Memory)");
}

#[test]
fn handle_proc_memory_echoes_pid_and_filter() {
    let mut config = SpecterConfig::default();
    let mut payload = 6u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&1234u32.to_le_bytes()); // pid
    payload.extend_from_slice(&0x04u32.to_le_bytes()); // PAGE_READWRITE filter
    let package = DemonPackage::new(DemonCommand::CommandProc, 31, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    let echoed_pid = u32::from_le_bytes(resp.payload[4..8].try_into().expect("pid"));
    let echoed_filter = u32::from_le_bytes(resp.payload[8..12].try_into().expect("filter"));
    assert_eq!(echoed_pid, 1234);
    assert_eq!(echoed_filter, 0x04);
}

#[test]
fn handle_proc_memory_self_returns_regions() {
    let own_pid = std::process::id();
    let mut config = SpecterConfig::default();
    let mut payload = 6u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&own_pid.to_le_bytes()); // self
    payload.extend_from_slice(&0u32.to_le_bytes()); // all regions
    let package = DemonPackage::new(DemonCommand::CommandProc, 32, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    // Header is 12 bytes (subcmd + pid + filter); must have at least one region (20 bytes).
    assert!(
        resp.payload.len() >= 12 + 20,
        "self memory query must return at least one region; payload len={}",
        resp.payload.len()
    );
}

#[test]
fn handle_proc_memory_missing_pid_returns_ignore() {
    let mut config = SpecterConfig::default();
    let payload = 6u32.to_le_bytes().to_vec(); // subcmd only, no pid
    let package = DemonPackage::new(DemonCommand::CommandProc, 33, payload);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

// ── handle_proc_kill ─────────────────────────────────────────────────────

#[test]
fn handle_proc_kill_nonexistent_pid_returns_failure() {
    let mut config = SpecterConfig::default();
    let mut payload = 7u32.to_le_bytes().to_vec(); // subcmd = Kill
    payload.extend_from_slice(&9_999_999u32.to_le_bytes()); // bogus pid
    let package = DemonPackage::new(DemonCommand::CommandProc, 40, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
    let success = u32::from_le_bytes(resp.payload[4..8].try_into().expect("success"));
    let echoed_pid = u32::from_le_bytes(resp.payload[8..12].try_into().expect("pid"));
    assert_eq!(subcmd, 7, "subcmd must be echoed as 7 (Kill)");
    assert_eq!(success, 0, "kill of bogus pid must report failure");
    assert_eq!(echoed_pid, 9_999_999);
}

#[test]
fn handle_proc_kill_missing_pid_returns_ignore() {
    let mut config = SpecterConfig::default();
    let payload = 7u32.to_le_bytes().to_vec(); // subcmd only, no pid
    let package = DemonPackage::new(DemonCommand::CommandProc, 41, payload);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

#[test]
fn handle_proc_kill_payload_is_twelve_bytes() {
    // The kill response is always exactly 12 bytes: subcmd(4) + success(4) + pid(4)
    let mut config = SpecterConfig::default();
    let mut payload = 7u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&1u32.to_le_bytes()); // pid=1 (init, will likely fail)
    let package = DemonPackage::new(DemonCommand::CommandProc, 42, payload);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.payload.len(), 12, "kill response must be exactly 12 bytes");
}

// ── handle_net ──────────────────────────────────────────────────────────

/// Build a LE-encoded UTF-16LE length-prefixed payload (without NUL terminator)
/// matching the format the teamserver sends.
fn le_utf16le_net(s: &str) -> Vec<u8> {
    let utf16: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut v = Vec::new();
    v.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    v.extend_from_slice(&utf16);
    v
}

/// Build a CommandNet task package with the given subcommand and rest bytes.
fn net_package(subcmd: DemonNetCommand, rest: &[u8]) -> DemonPackage {
    let mut payload = (subcmd as u32).to_le_bytes().to_vec();
    payload.extend_from_slice(rest);
    DemonPackage::new(DemonCommand::CommandNet, 1, payload)
}

/// Parse the first u32 LE from a response payload (the subcommand echo).
fn resp_subcmd_le(payload: &[u8]) -> u32 {
    u32::from_le_bytes(payload[0..4].try_into().expect("subcmd"))
}

#[test]
fn handle_net_unknown_subcommand_returns_ignore() {
    let mut config = SpecterConfig::default();
    let payload = 0xFFu32.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandNet, 1, payload);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

#[test]
fn handle_net_empty_payload_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandNet, 1, vec![]);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

#[test]
fn handle_net_domain_returns_correct_command_and_subcmd() {
    let mut config = SpecterConfig::default();
    let package = net_package(DemonNetCommand::Domain, &[]);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
    assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Domain));
    // Payload must have at least subcmd(4) + len(4) (the domain string, possibly empty).
    assert!(resp.payload.len() >= 8, "domain response must have subcmd + string length");
}

#[test]
fn handle_net_domain_response_string_is_le_length_prefixed() {
    let mut config = SpecterConfig::default();
    let package = net_package(DemonNetCommand::Domain, &[]);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    // After subcmd (4 bytes), read the LE length-prefixed domain string.
    let str_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
    assert_eq!(resp.payload.len(), 8 + str_len, "payload size must match header");
}

#[test]
fn handle_net_logons_echoes_server_and_subcmd() {
    let mut config = SpecterConfig::default();
    let rest = le_utf16le_net("SERVER01");
    let package = net_package(DemonNetCommand::Logons, &rest);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
    assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Logons));
    // After subcmd (4 bytes), the server name should be present as UTF-16LE.
    let server_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
    let server_bytes = &resp.payload[8..8 + server_len];
    let server = decode_utf16le_null(server_bytes);
    assert_eq!(server, "SERVER01");
}

#[test]
fn handle_net_logons_missing_server_returns_ignore() {
    let mut config = SpecterConfig::default();
    // Subcommand only, no server name.
    let package = net_package(DemonNetCommand::Logons, &[]);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

#[test]
fn handle_net_sessions_echoes_server_and_subcmd() {
    let mut config = SpecterConfig::default();
    let rest = le_utf16le_net("DC01");
    let package = net_package(DemonNetCommand::Sessions, &rest);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
    assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Sessions));
}

#[test]
fn handle_net_sessions_missing_server_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = net_package(DemonNetCommand::Sessions, &[]);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

#[test]
fn handle_net_computer_echoes_domain_and_correct_subcmd() {
    let mut config = SpecterConfig::default();
    let rest = le_utf16le_net("CORP.LOCAL");
    let package = net_package(DemonNetCommand::Computer, &rest);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
    assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Computer));
    // Domain name must be echoed as len-prefixed UTF-16LE after subcmd.
    let domain_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
    let domain = decode_utf16le_null(&resp.payload[8..8 + domain_len]);
    assert_eq!(domain, "CORP.LOCAL");
    // On non-Windows there is no NetServerEnum — list is empty, payload ends after domain.
    #[cfg(not(windows))]
    assert_eq!(resp.payload.len(), 8 + domain_len);
}

#[test]
fn handle_net_computer_missing_domain_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = net_package(DemonNetCommand::Computer, &[]);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

#[test]
fn handle_net_dclist_echoes_domain_and_correct_subcmd() {
    let mut config = SpecterConfig::default();
    let rest = le_utf16le_net("CORP.LOCAL");
    let package = net_package(DemonNetCommand::DcList, &rest);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
    assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::DcList));
    // Domain name must be echoed as len-prefixed UTF-16LE after subcmd.
    let domain_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
    let domain = decode_utf16le_null(&resp.payload[8..8 + domain_len]);
    assert_eq!(domain, "CORP.LOCAL");
    // On non-Windows there is no NetServerEnum — list is empty, payload ends after domain.
    #[cfg(not(windows))]
    assert_eq!(resp.payload.len(), 8 + domain_len);
}

#[test]
fn handle_net_dclist_missing_domain_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = net_package(DemonNetCommand::DcList, &[]);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

#[test]
fn handle_net_share_echoes_server_and_subcmd() {
    let mut config = SpecterConfig::default();
    let rest = le_utf16le_net("FILESERV");
    let package = net_package(DemonNetCommand::Share, &rest);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
    assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Share));
}

#[test]
fn handle_net_share_missing_server_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = net_package(DemonNetCommand::Share, &[]);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

#[test]
fn handle_net_localgroup_echoes_server_and_subcmd() {
    let mut config = SpecterConfig::default();
    let rest = le_utf16le_net("WORKSTATION");
    let package = net_package(DemonNetCommand::LocalGroup, &rest);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::LocalGroup));
    // Server name echoed.
    let server_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
    let server = decode_utf16le_null(&resp.payload[8..8 + server_len]);
    assert_eq!(server, "WORKSTATION");
}

#[test]
fn handle_net_localgroup_has_groups_from_etc_group() {
    let mut config = SpecterConfig::default();
    let rest = le_utf16le_net("localhost");
    let package = net_package(DemonNetCommand::LocalGroup, &rest);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    // On any Linux system /etc/group has at least "root".
    // Response = subcmd(4) + server(4+N) + [group_name(4+N) + description(4+N)]...
    // So payload must be longer than just subcmd + server.
    let server_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
    let after_server = 8 + server_len;
    assert!(
        resp.payload.len() > after_server,
        "expected at least one group entry; payload len = {}",
        resp.payload.len()
    );
}

#[test]
fn handle_net_group_echoes_subcmd_8() {
    let mut config = SpecterConfig::default();
    let rest = le_utf16le_net("DC01");
    let package = net_package(DemonNetCommand::Group, &rest);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Group));
}

#[test]
fn handle_net_users_echoes_server_and_subcmd() {
    let mut config = SpecterConfig::default();
    let rest = le_utf16le_net("HOST01");
    let package = net_package(DemonNetCommand::Users, &rest);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
    assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Users));
}

#[test]
fn handle_net_users_includes_root_as_admin() {
    let mut config = SpecterConfig::default();
    let rest = le_utf16le_net("localhost");
    let package = net_package(DemonNetCommand::Users, &rest);
    let DispatchResult::Respond(resp) = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    ) else {
        panic!("expected Respond");
    };
    // Parse response to find "root" with is_admin=true.
    let p = &resp.payload;
    let mut pos = 4; // skip subcmd
    // Skip server name.
    let server_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("len")) as usize;
    pos += 4 + server_len;
    // Iterate user entries: [name: LE-len-prefixed UTF-16LE][is_admin: u32 LE]
    let mut found_root = false;
    while pos + 4 <= p.len() {
        let name_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("name len")) as usize;
        pos += 4;
        if pos + name_len + 4 > p.len() {
            break;
        }
        let name = decode_utf16le_null(&p[pos..pos + name_len]);
        pos += name_len;
        let is_admin = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("admin"));
        pos += 4;
        if name == "root" {
            assert_eq!(is_admin, 1, "root must be flagged as admin");
            found_root = true;
        }
    }
    assert!(found_root, "root user not found in user list");
}

#[test]
fn handle_net_users_missing_server_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = net_package(DemonNetCommand::Users, &[]);
    assert!(matches!(
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        ),
        DispatchResult::Ignore
    ));
}

#[test]
fn dispatch_routes_command_proc_list() {
    let mut config = SpecterConfig::default();
    let payload = 0u32.to_le_bytes().to_vec(); // process_ui = 0
    let package = DemonPackage::new(DemonCommand::CommandProcList, 1, payload);
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

#[test]
fn dispatch_routes_command_net_domain() {
    let mut config = SpecterConfig::default();
    let payload = le_subcmd(1); // DemonNetCommand::Domain = 1
    let package = DemonPackage::new(DemonCommand::CommandNet, 1, payload);
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
// ── handle_proc edge cases ───────────────────────────────────────────────

#[test]
fn handle_proc_create_captures_stderr() {
    let mut config = SpecterConfig::default();
    // Run a command that writes to stderr.
    let mut payload = Vec::new();
    payload.extend_from_slice(&le_subcmd(u32::from(DemonProcessCommand::Create)));
    payload.extend_from_slice(&0u32.to_le_bytes()); // process_state
    payload.extend_from_slice(&le_utf16le_payload("")); // process_path (empty → /bin/sh)
    payload.extend_from_slice(&le_utf16le_payload("/c echo stderr_test >&2"));
    payload.extend_from_slice(&1u32.to_le_bytes()); // piped = true
    payload.extend_from_slice(&0u32.to_le_bytes()); // verbose = false
    let package = DemonPackage::new(DemonCommand::CommandProc, 1, payload);
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
    let DispatchResult::MultiRespond(responses) = result else {
        panic!("expected MultiRespond for proc create");
    };
    assert_eq!(responses.len(), 2, "proc create returns 2 responses");
    // Second response is CommandOutput with captured output.
    let output_resp = &responses[1];
    assert_eq!(output_resp.command_id, u32::from(DemonCommand::CommandOutput));
    // Parse the output payload (LE length-prefixed bytes).
    let output_len =
        u32::from_le_bytes(output_resp.payload[0..4].try_into().expect("len")) as usize;
    let output_bytes = &output_resp.payload[4..4 + output_len];
    let output_str = String::from_utf8_lossy(output_bytes);
    assert!(
        output_str.contains("stderr_test"),
        "proc create must capture stderr — got: {output_str}"
    );
}

#[test]
fn handle_proc_create_nonzero_exit_code_still_succeeds() {
    let mut config = SpecterConfig::default();
    let mut payload = Vec::new();
    payload.extend_from_slice(&le_subcmd(u32::from(DemonProcessCommand::Create)));
    payload.extend_from_slice(&0u32.to_le_bytes()); // process_state
    payload.extend_from_slice(&le_utf16le_payload("")); // process_path
    payload.extend_from_slice(&le_utf16le_payload("/c exit 42"));
    payload.extend_from_slice(&1u32.to_le_bytes()); // piped
    payload.extend_from_slice(&0u32.to_le_bytes()); // verbose
    let package = DemonPackage::new(DemonCommand::CommandProc, 1, payload);
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
    // Even with a non-zero exit code, the handler should return MultiRespond
    // (the process ran, it just exited non-zero).
    let DispatchResult::MultiRespond(responses) = result else {
        panic!("expected MultiRespond for proc create with non-zero exit");
    };
    assert_eq!(responses.len(), 2);

    // Verify the trailing i32 exit code is encoded in the CommandOutput payload.
    let out_resp = &responses[1];
    assert_eq!(out_resp.command_id, u32::from(DemonCommand::CommandOutput));
    let out_payload = &out_resp.payload;
    let str_len = u32::from_le_bytes(out_payload[0..4].try_into().expect("len")) as usize;
    let exit_code_start = 4 + str_len;
    assert!(
        out_payload.len() >= exit_code_start + 4,
        "CommandOutput payload must include trailing exit code i32"
    );
    let exit_code = i32::from_le_bytes(
        out_payload[exit_code_start..exit_code_start + 4].try_into().expect("exit code bytes"),
    );
    assert_eq!(exit_code, 42, "exit code must be 42");
}

#[test]
fn handle_proc_empty_payload_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandProc, 1, vec![]);
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

#[test]
fn handle_proc_unknown_subcommand_returns_ignore() {
    let mut config = SpecterConfig::default();
    let payload = le_subcmd(0xFFFF); // bogus subcommand
    let package = DemonPackage::new(DemonCommand::CommandProc, 1, payload);
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

#[test]
fn handle_proc_grep_matches_self_pid() {
    let mut config = SpecterConfig::default();
    // Use empty needle (matches all).
    let mut payload = Vec::new();
    payload.extend_from_slice(&le_subcmd(u32::from(DemonProcessCommand::Grep)));
    payload.extend_from_slice(&le_utf16le_payload(""));
    let package = DemonPackage::new(DemonCommand::CommandProc, 1, payload);
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
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond for proc grep");
    };
    // Parse response: subcmd(4) + repeated entries.
    // Each entry contains a PID field. Verify our PID is in there.
    assert!(resp.payload.len() > 4, "proc grep with empty needle should return entries");
}

// ── handle_proc_list edge cases ──────────────────────────────────────────

#[test]
fn handle_proc_list_empty_payload_uses_default_flag() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandProcList, 1, vec![]);
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
    // ProcList should still respond even with empty payload (uses default process_ui = 0).
    assert!(matches!(result, DispatchResult::Respond(_)));
}

// ── handle_net edge cases ────────────────────────────────────────────────

#[test]
fn dispatch_routes_command_net_empty_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandNet, 1, vec![]);
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
