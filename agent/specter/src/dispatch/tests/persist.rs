use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonPackage, PhantomPersistOp};

use super::super::persist::{
    SPECTER_PERSIST_MARKER, SPECTER_RUN_VALUE_NAME, SPECTER_STARTUP_FILE_NAME, TestPersistGuard,
    write_text_file,
};
use super::super::{DispatchResult, dispatch};
use super::{
    decode_command_output_text, decode_error_text, make_test_persist_dir, persist_payload,
};
use crate::config::SpecterConfig;
use crate::download::DownloadTracker;
use crate::job::JobStore;
use crate::token::TokenVault;

// ── CommandPersist ───────────────────────────────────────────────────────

#[test]
fn command_persist_registry_install_routes_to_command_output() {
    let persist_dir = make_test_persist_dir("specter_persist_registry");
    let _guard = TestPersistGuard::install(&persist_dir);

    let mut config = SpecterConfig::default();
    let payload = persist_payload(1, u32::from(PhantomPersistOp::Install), "cmd.exe /c whoami");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 77, payload);
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
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));
    let text = decode_command_output_text(&resp.payload);
    assert!(text.contains("registry run key persistence installed"), "unexpected text: {text}");

    let persisted =
        std::fs::read_to_string(persist_dir.join("registry").join(SPECTER_RUN_VALUE_NAME))
            .expect("read persisted registry stub");
    assert_eq!(persisted, "cmd.exe /c whoami");
    let _ = std::fs::remove_dir_all(&persist_dir);
}

#[test]
fn command_persist_startup_remove_deletes_script_and_reports_success() {
    let persist_dir = make_test_persist_dir("specter_persist_startup");
    let _guard = TestPersistGuard::install(&persist_dir);
    let startup_path = persist_dir.join("startup").join(SPECTER_STARTUP_FILE_NAME);
    write_text_file(&startup_path, "@echo off\r\ncalc.exe\r\n").expect("seed startup script");

    let mut config = SpecterConfig::default();
    let payload = persist_payload(2, u32::from(PhantomPersistOp::Remove), "");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 78, payload);
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
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));
    let text = decode_command_output_text(&resp.payload);
    assert!(text.contains("startup folder persistence removed"), "unexpected text: {text}");
    assert!(!startup_path.exists(), "startup script should be removed");
    let _ = std::fs::remove_dir_all(&persist_dir);
}

#[test]
fn command_persist_powershell_profile_install_is_idempotent() {
    let persist_dir = make_test_persist_dir("specter_persist_psprofile");
    let _guard = TestPersistGuard::install(&persist_dir);

    let mut config = SpecterConfig::default();
    let payload =
        persist_payload(3, u32::from(PhantomPersistOp::Install), "Start-Process notepad.exe");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 79, payload.clone());

    let first = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = first else {
        panic!("expected Respond, got {first:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));

    let second_package = DemonPackage::new(DemonCommand::CommandPersist, 80, payload);
    let second = dispatch(
        &second_package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = second else {
        panic!("expected Respond, got {second:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));
    let text = decode_command_output_text(&resp.payload);
    assert!(text.contains("already present"), "unexpected text: {text}");

    let profile_path = persist_dir.join("powershell").join("Microsoft.PowerShell_profile.ps1");
    let profile = std::fs::read_to_string(&profile_path).expect("read powershell profile");
    assert_eq!(
        profile.matches(SPECTER_PERSIST_MARKER).count(),
        2,
        "profile should contain exactly one BEGIN/END marker pair"
    );
    let _ = std::fs::remove_dir_all(&persist_dir);
}

#[test]
fn command_persist_powershell_profile_install_updates_changed_command() {
    let persist_dir = make_test_persist_dir("specter_persist_psprofile_update");
    let _guard = TestPersistGuard::install(&persist_dir);

    let mut config = SpecterConfig::default();

    let payload_a =
        persist_payload(3, u32::from(PhantomPersistOp::Install), "Start-Process notepad.exe");
    let pkg_a = DemonPackage::new(DemonCommand::CommandPersist, 82, payload_a);
    let first = dispatch(
        &pkg_a,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = first else {
        panic!("expected Respond, got {first:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));

    let payload_b =
        persist_payload(3, u32::from(PhantomPersistOp::Install), "Start-Process calc.exe");
    let pkg_b = DemonPackage::new(DemonCommand::CommandPersist, 83, payload_b);
    let second = dispatch(
        &pkg_b,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = second else {
        panic!("expected Respond, got {second:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));
    let text = decode_command_output_text(&resp.payload);
    assert!(text.contains("updated"), "expected 'updated' in response, got: {text}");

    let profile_path = persist_dir.join("powershell").join("Microsoft.PowerShell_profile.ps1");
    let profile = std::fs::read_to_string(&profile_path).expect("read powershell profile");
    assert_eq!(
        profile.matches(SPECTER_PERSIST_MARKER).count(),
        2,
        "profile should contain exactly one BEGIN/END marker pair after update"
    );
    assert!(profile.contains("Start-Process calc.exe"), "new command not found in profile");
    assert!(
        !profile.contains("Start-Process notepad.exe"),
        "old command still present in profile after update"
    );

    let _ = std::fs::remove_dir_all(&persist_dir);
}

#[test]
fn command_persist_unknown_method_returns_error_callback() {
    let mut config = SpecterConfig::default();
    let payload = persist_payload(99, u32::from(PhantomPersistOp::Install), "cmd.exe /c exit 0");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 81, payload);
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
    assert_eq!(resp.command_id, u32::from(DemonCommand::BeaconOutput));
    let text = decode_error_text(&resp.payload);
    assert!(text.contains("unknown Specter persist method 99"), "unexpected text: {text}");
}
