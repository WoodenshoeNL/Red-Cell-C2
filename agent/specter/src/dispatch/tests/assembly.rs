use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonPackage};

use super::super::assembly::{
    handle_assembly_inline_execute, handle_assembly_list_versions, handle_inline_execute,
    handle_job, handle_ps_import,
};
use super::super::{DispatchResult, MemFile, MemFileStore, PsScriptStore, dispatch};
use super::le_u32_pair;
use crate::config::SpecterConfig;
use crate::download::{DownloadState, DownloadTracker};
use crate::job::JobStore;
use crate::token::TokenVault;
use crate::{coffeeldr, dotnet};

// ── CommandInlineExecute (20) ───────────────────────────────────────────

#[test]
fn inline_execute_short_payload_returns_could_not_run() {
    let result = handle_inline_execute(
        &[],
        1,
        &SpecterConfig::default(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInlineExecute));
    // Payload should start with BOF_COULD_NOT_RUN (4)
    let cb_type = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(cb_type, coffeeldr::BOF_COULD_NOT_RUN);
}

#[test]
fn inline_execute_missing_memfile_returns_could_not_run() {
    // Valid payload structure but memfile IDs don't exist
    let mut payload = Vec::new();
    // function_name: "go"
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    // bof_file_id
    payload.extend_from_slice(&99u32.to_le_bytes());
    // params_file_id
    payload.extend_from_slice(&100u32.to_le_bytes());
    // flags
    payload.extend_from_slice(&0u32.to_le_bytes());

    let result = handle_inline_execute(
        &payload,
        1,
        &SpecterConfig::default(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInlineExecute));
    let cb_type = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(cb_type, coffeeldr::BOF_COULD_NOT_RUN);
}

#[test]
fn inline_execute_incomplete_memfile_returns_could_not_run() {
    let mut mem_files = MemFileStore::new();
    // Insert an incomplete memfile
    mem_files.insert(1, MemFile { expected_size: 100, data: vec![0u8; 50] });

    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&1u32.to_le_bytes()); // bof_file_id
    payload.extend_from_slice(&2u32.to_le_bytes()); // params_file_id
    payload.extend_from_slice(&0u32.to_le_bytes()); // flags

    let result = handle_inline_execute(
        &payload,
        1,
        &SpecterConfig::default(),
        &mut mem_files,
        &mut JobStore::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    let cb_type = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(cb_type, coffeeldr::BOF_COULD_NOT_RUN);
    // Memfiles should be cleaned up
    assert!(!mem_files.contains_key(&1));
}

#[test]
fn inline_execute_with_valid_memfiles_attempts_execution() {
    let mut mem_files = MemFileStore::new();
    // Insert complete memfiles (garbage COFF data — execution will fail)
    mem_files.insert(1, MemFile { expected_size: 4, data: vec![0xDE, 0xAD, 0xBE, 0xEF] });
    mem_files.insert(2, MemFile { expected_size: 0, data: Vec::new() });

    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&2u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());

    let result = handle_inline_execute(
        &payload,
        1,
        &SpecterConfig::default(),
        &mut mem_files,
        &mut JobStore::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    // Should get some kind of response (BOF_COULD_NOT_RUN on invalid COFF)
    match result {
        DispatchResult::Respond(resp) => {
            assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInlineExecute));
        }
        DispatchResult::MultiRespond(resps) => {
            assert!(!resps.is_empty());
            assert_eq!(resps[0].command_id, u32::from(DemonCommand::CommandInlineExecute));
        }
        _ => panic!("expected Respond or MultiRespond"),
    }
    // Memfiles should be cleaned up
    assert!(!mem_files.contains_key(&1));
    assert!(!mem_files.contains_key(&2));
}

// ── CommandJob (21) ─────────────────────────────────────────────────────

#[test]
fn job_list_empty_store_returns_header_only() {
    let mut store = JobStore::new();
    let payload = 1u32.to_le_bytes().to_vec(); // List = 1
    let result = handle_job(&payload, &mut store);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandJob));
    // Payload: [1: u32 LE] — just the subcommand, no jobs
    assert_eq!(resp.payload.len(), 4);
    let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(subcmd, 1);
}

#[test]
fn job_list_with_jobs_includes_all_entries() {
    let mut store = JobStore::new();
    store.add(crate::job::JOB_TYPE_THREAD, 0, 0);
    store.add(crate::job::JOB_TYPE_PROCESS, 0, 0);

    let payload = 1u32.to_le_bytes().to_vec();
    let result = handle_job(&payload, &mut store);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    // Payload: [1: u32] + 2 * [job_id: u32, type: u32, state: u32] = 4 + 24 = 28
    assert_eq!(resp.payload.len(), 28);
}

#[test]
fn job_suspend_nonexistent_returns_failure() {
    let mut store = JobStore::new();
    let mut payload = Vec::new();
    payload.extend_from_slice(&2u32.to_le_bytes()); // Suspend = 2
    payload.extend_from_slice(&999u32.to_le_bytes()); // nonexistent job
    let result = handle_job(&payload, &mut store);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    // [2: u32][999: u32][0: u32 (false)]
    assert_eq!(resp.payload.len(), 12);
    let success = u32::from_le_bytes(resp.payload[8..12].try_into().expect("u32"));
    assert_eq!(success, 0);
}

#[test]
fn job_kill_existing_returns_success() {
    let mut store = JobStore::new();
    let id = store.add(crate::job::JOB_TYPE_THREAD, 0, 0);
    let mut payload = Vec::new();
    payload.extend_from_slice(&4u32.to_le_bytes()); // KillRemove = 4
    payload.extend_from_slice(&id.to_le_bytes());
    let result = handle_job(&payload, &mut store);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    let success = u32::from_le_bytes(resp.payload[8..12].try_into().expect("u32"));
    assert_eq!(success, 1);
}

#[test]
fn job_unknown_subcommand_returns_ignore() {
    let mut store = JobStore::new();
    let payload = 99u32.to_le_bytes().to_vec();
    let result = handle_job(&payload, &mut store);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn job_short_payload_returns_ignore() {
    let mut store = JobStore::new();
    let result = handle_job(&[0x01], &mut store);
    assert!(matches!(result, DispatchResult::Ignore));
}

// ── CommandPsImport (0x1011) ────────────────────────────────────────────

#[test]
fn ps_import_stores_script_and_responds_success() {
    let mut ps_scripts = PsScriptStore::new();
    let mut mem_files = MemFileStore::new();

    // Stage script in memfile
    let script = b"Write-Host 'Hello'";
    mem_files.insert(42, MemFile { expected_size: script.len(), data: script.to_vec() });

    let payload = 42u32.to_le_bytes().to_vec(); // memfile ID
    let result = handle_ps_import(&payload, &mut ps_scripts, &mut mem_files);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandPsImport));
    assert_eq!(ps_scripts, script.to_vec());
    // Response should contain empty string (success)
    let out_len = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(out_len, 0);
}

#[test]
fn ps_import_missing_memfile_uses_raw_payload() {
    let mut ps_scripts = PsScriptStore::new();
    let mut mem_files = MemFileStore::new();

    // Payload: [memfile_id: u32][raw script bytes]
    let mut payload = Vec::new();
    payload.extend_from_slice(&99u32.to_le_bytes()); // nonexistent memfile
    payload.extend_from_slice(b"Get-Process");

    let result = handle_ps_import(&payload, &mut ps_scripts, &mut mem_files);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandPsImport));
    assert_eq!(ps_scripts, b"Get-Process".to_vec());
}

#[test]
fn ps_import_empty_script_returns_error() {
    let mut ps_scripts = PsScriptStore::new();
    let mut mem_files = MemFileStore::new();
    mem_files.insert(1, MemFile { expected_size: 0, data: Vec::new() });

    let payload = 1u32.to_le_bytes().to_vec();
    let result = handle_ps_import(&payload, &mut ps_scripts, &mut mem_files);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    // Should contain non-empty error message
    let out_len = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert!(out_len > 0);
}

// ── CommandAssemblyInlineExecute (0x2001) ───────────────────────────────

#[test]
fn assembly_inline_execute_short_payload_returns_failed() {
    let result = handle_assembly_inline_execute(&[], &mut HashMap::new());
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandAssemblyInlineExecute));
    let info_id = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(info_id, dotnet::DOTNET_INFO_FAILED);
}

#[test]
fn assembly_inline_execute_missing_memfile_returns_failed() {
    let mut mem_files = MemFileStore::new();

    // Build payload with valid wstrings but nonexistent memfile
    let mut payload = Vec::new();
    // pipe_name
    let pipe_utf16: Vec<u8> =
        "pipe".encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    payload.extend_from_slice(&(pipe_utf16.len() as u32).to_le_bytes());
    payload.extend_from_slice(&pipe_utf16);
    // app_domain
    let domain_utf16: Vec<u8> =
        "dom".encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    payload.extend_from_slice(&(domain_utf16.len() as u32).to_le_bytes());
    payload.extend_from_slice(&domain_utf16);
    // net_version
    let ver_utf16: Vec<u8> =
        "v4.0".encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    payload.extend_from_slice(&(ver_utf16.len() as u32).to_le_bytes());
    payload.extend_from_slice(&ver_utf16);
    // memfile_id (nonexistent)
    payload.extend_from_slice(&999u32.to_le_bytes());

    let result = handle_assembly_inline_execute(&payload, &mut mem_files);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    let info_id = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(info_id, dotnet::DOTNET_INFO_FAILED);
}

// ── CommandAssemblyListVersions (0x2003) ────────────────────────────────

#[test]
fn assembly_list_versions_returns_respond() {
    let result = handle_assembly_list_versions();
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandAssemblyListVersions));
    // On non-Windows, payload will be empty (no CLR versions)
    #[cfg(not(windows))]
    assert_eq!(resp.payload.len(), 0);
}

// ── Full dispatch routing tests for new commands ────────────────────────

#[test]
fn dispatch_routes_command_job() {
    let mut config = SpecterConfig::default();
    let payload = 1u32.to_le_bytes().to_vec(); // List
    let package = DemonPackage::new(DemonCommand::CommandJob, 1, payload);
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
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandJob));
}

#[test]
fn dispatch_routes_command_assembly_list_versions() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandAssemblyListVersions, 1, Vec::new());
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
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandAssemblyListVersions));
}

// ── CommandPackageDropped ────────────────────────────────────────────────

#[test]
fn dispatch_routes_package_dropped_returns_ignore() {
    let mut config = SpecterConfig::default();
    let payload = le_u32_pair(0x20000, 0x10000); // dropped=128KB, max=64KB
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 42, payload);
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
fn package_dropped_marks_matching_downloads_for_removal() {
    let mut config = SpecterConfig::default();
    let mut downloads = DownloadTracker::new();

    // Create a temp file to register as a download.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("specter_pkg_drop_{}", rand::random::<u32>()));
    std::fs::write(&path, b"data").expect("write temp");
    let file = std::fs::File::open(&path).expect("open temp");
    let file_id = downloads.add(file, 99, 4); // request_id=99

    let payload = le_u32_pair(0x20000, 0x10000);
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Ignore));

    // The download should now be marked for removal.
    let entry = downloads.get(file_id).expect("entry should still exist before push");
    assert_eq!(entry.state, DownloadState::Remove);
    let _ = std::fs::remove_file(path);
}

#[test]
fn package_dropped_removes_matching_memfile() {
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();
    mem_files.insert(55, MemFile { expected_size: 1024, data: vec![0u8; 512] });

    let payload = le_u32_pair(0x20000, 0x10000);
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 55, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Ignore));
    assert!(mem_files.get(&55).is_none(), "mem-file should have been removed");
}

#[test]
fn package_dropped_ignores_short_payload() {
    let mut config = SpecterConfig::default();
    let payload = vec![0x00, 0x01, 0x00]; // only 3 bytes, not enough for two u32s
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 1, payload);
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
fn package_dropped_does_not_affect_unrelated_downloads() {
    let mut config = SpecterConfig::default();
    let mut downloads = DownloadTracker::new();

    let dir = std::env::temp_dir();
    let path = dir.join(format!("specter_pkg_drop_unrel_{}", rand::random::<u32>()));
    std::fs::write(&path, b"data").expect("write temp");
    let file = std::fs::File::open(&path).expect("open temp");
    let file_id = downloads.add(file, 100, 4); // request_id=100

    // Package dropped for request_id=99 — should NOT affect download with request_id=100.
    let payload = le_u32_pair(0x20000, 0x10000);
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);
    dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );

    let entry = downloads.get(file_id).expect("entry should exist");
    assert_eq!(entry.state, DownloadState::Running);
    let _ = std::fs::remove_file(path);
}

// ── handle_ps_import edge cases ──────────────────────────────────────────

#[test]
fn ps_import_accumulates_across_multiple_imports() {
    let mut config = SpecterConfig::default();
    let mut ps_scripts = Vec::new();
    let mut mem_files: MemFileStore = HashMap::new();

    // First import
    let script1 = b"function Get-Foo { 'foo' }\n";
    let mut payload1 = (script1.len() as u32).to_le_bytes().to_vec();
    payload1.extend_from_slice(script1);
    let package1 = DemonPackage::new(DemonCommand::CommandPsImport, 1, payload1);
    let _ = dispatch(
        &package1,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut JobStore::new(),
        &mut ps_scripts,
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert_eq!(ps_scripts.len(), script1.len());

    // Second import — should replace (not accumulate).
    let script2 = b"function Get-Bar { 'bar' }\n";
    let mut payload2 = (script2.len() as u32).to_le_bytes().to_vec();
    payload2.extend_from_slice(script2);
    let package2 = DemonPackage::new(DemonCommand::CommandPsImport, 2, payload2);
    let _ = dispatch(
        &package2,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut JobStore::new(),
        &mut ps_scripts,
        &crate::coffeeldr::new_bof_output_queue(),
    );
    // After second import, the stored script should be the second one.
    assert_eq!(ps_scripts.len(), script2.len());
}
// ── handle_inline_execute edge cases ─────────────────────────────────────

#[test]
fn dispatch_routes_command_inline_execute() {
    let mut config = SpecterConfig::default();
    // Minimal payload that will fail parsing (too short).
    let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, vec![0x00]);
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
    // Short payload → returns CouldNotRun response.
    assert!(matches!(result, DispatchResult::Respond(_)));
}

/// Build a minimal InlineExecute payload with the given `flags` value.
///
/// Does NOT insert a BOF memfile — the handler will return CouldNotRun
/// when the memfile is missing.  Used to test error-path behaviour.
fn inline_execute_payload_no_memfile(flags: i32) -> Vec<u8> {
    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&1u32.to_le_bytes()); // bof_file_id = 1 (absent)
    payload.extend_from_slice(&2u32.to_le_bytes()); // params_file_id = 2
    payload.extend_from_slice(&flags.to_le_bytes());
    payload
}

/// Insert a complete BOF memfile into `mem_files` by dispatching a
/// `CommandMemFile` packet.
fn insert_complete_memfile(mem_files: &mut MemFileStore, file_id: u32, data: Vec<u8>) {
    let mut config = SpecterConfig::default();
    let mut payload = Vec::new();
    payload.extend_from_slice(&file_id.to_le_bytes());
    payload.extend_from_slice(&(data.len() as u64).to_le_bytes());
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(&data);
    let pkg = DemonPackage::new(DemonCommand::CommandMemFile, 1, payload);
    let _ = dispatch(
        &pkg,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
}

#[test]
fn inline_execute_threaded_missing_bof_returns_could_not_run() {
    // When the BOF memfile is absent, threaded mode still returns an error
    // and registers no job in the store.
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();
    let mut job_store = JobStore::new();

    let package = DemonPackage::new(
        DemonCommand::CommandInlineExecute,
        1,
        inline_execute_payload_no_memfile(1), // flags=1 → threaded
    );
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut job_store,
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
    assert_eq!(job_store.list().count(), 0, "no job should be registered on error");
}

#[test]
fn inline_execute_nonthreaded_does_not_register_job() {
    // flags=0 (sync) with a garbage BOF: runs sync, returns BOF_COULD_NOT_RUN,
    // and leaves the job store empty.
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();
    let mut job_store = JobStore::new();

    insert_complete_memfile(&mut mem_files, 10, vec![0xDE, 0xAD]); // garbage COFF

    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&10u32.to_le_bytes()); // bof_file_id = 10
    payload.extend_from_slice(&11u32.to_le_bytes()); // params_file_id = 11 (absent → empty)
    payload.extend_from_slice(&0i32.to_le_bytes()); // flags = 0 → non-threaded

    let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut job_store,
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
    assert_eq!(job_store.list().count(), 0, "sync BOF must not register a job");
}

#[cfg(not(windows))]
#[test]
fn inline_execute_threaded_non_windows_falls_back_to_sync() {
    // On non-Windows the threaded path is a no-op stub; execution falls
    // back to sync, returns BOF_COULD_NOT_RUN, and no job is registered.
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();
    let mut job_store = JobStore::new();

    insert_complete_memfile(&mut mem_files, 20, vec![0xDE, 0xAD]); // garbage COFF

    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&20u32.to_le_bytes()); // bof_file_id = 20
    payload.extend_from_slice(&21u32.to_le_bytes()); // params_file_id = 21 (absent → empty)
    payload.extend_from_slice(&1i32.to_le_bytes()); // flags = 1 → threaded

    let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut job_store,
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    // Non-Windows sync fallback → returns BOF_COULD_NOT_RUN response
    assert!(matches!(result, DispatchResult::Respond(_)));
    // No job registered — threaded BOF unsupported on non-Windows
    assert_eq!(job_store.list().count(), 0);
}

#[cfg(not(windows))]
#[test]
fn inline_execute_threaded_non_windows_output_queue_stays_empty() {
    // On non-Windows the threaded stub returns None, so no callbacks should
    // appear in the output queue — the sync fallback produces an immediate
    // response instead.
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();
    let mut job_store = JobStore::new();
    let queue = crate::coffeeldr::new_bof_output_queue();

    insert_complete_memfile(&mut mem_files, 30, vec![0xDE, 0xAD]);

    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&30u32.to_le_bytes());
    payload.extend_from_slice(&31u32.to_le_bytes());
    payload.extend_from_slice(&1i32.to_le_bytes()); // flags = 1 → threaded

    let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut job_store,
        &mut Vec::new(),
        &queue,
    );
    // Sync fallback returns a response
    assert!(matches!(result, DispatchResult::Respond(_)));
    // Queue must remain empty — no threaded execution occurred
    assert!(queue.lock().expect("lock").is_empty());
}

#[test]
fn dispatch_routes_command_ps_import() {
    let mut config = SpecterConfig::default();
    // Empty script (0-length).
    let payload = 0u32.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandPsImport, 1, payload);
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
    // Empty script returns error response.
    assert!(matches!(result, DispatchResult::Respond(_)));
}

#[test]
fn dispatch_routes_command_assembly_inline_execute() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandAssemblyInlineExecute, 1, vec![0x00]);
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
    // Short payload → returns error response.
    assert!(matches!(result, DispatchResult::Respond(_)));
}
