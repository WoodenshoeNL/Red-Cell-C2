use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand, DemonPackage};

use super::super::filesystem::unix_secs_to_ymd_hm;
use super::super::process::translate_to_shell_cmd;
use super::super::{DispatchResult, dispatch};
use super::{decode_utf16le_null, dir_request_payload, le_subcmd, le_utf16le_payload};
use super::{write_ptr_be, write_ptr_le};
use crate::config::SpecterConfig;
use crate::download::DownloadTracker;
use crate::job::JobStore;
use crate::token::TokenVault;

// ── handle_fs pwd ────────────────────────────────────────────────────────

#[test]
fn handle_fs_pwd_returns_non_empty_path() {
    let mut config = SpecterConfig::default();
    let payload = le_subcmd(9); // GetPwd = 9
    let package = DemonPackage::new(DemonCommand::CommandFs, 7, payload);
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
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));

    // First 4 bytes LE = subcommand (9)
    let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
    assert_eq!(subcmd, 9);

    // Remaining = length-prefixed UTF-16LE path
    assert!(resp.payload.len() > 8, "payload should contain a path");
}

// ── handle_fs cd ─────────────────────────────────────────────────────────

#[test]
fn handle_fs_cd_changes_directory_and_echoes_path() {
    let tmp = std::env::temp_dir();
    let tmp_str = tmp.display().to_string();

    let mut config = SpecterConfig::default();
    let mut payload = le_subcmd(4); // Cd = 4
    payload.extend_from_slice(&le_utf16le_payload(&tmp_str));
    let package = DemonPackage::new(DemonCommand::CommandFs, 8, payload);

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
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));
    let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
    assert_eq!(subcmd, 4);

    // Decode echoed path from response
    let path_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
    let decoded = decode_utf16le_null(&resp.payload[8..8 + path_len]);
    assert_eq!(decoded, tmp_str);
}

#[test]
fn handle_fs_cd_missing_path_returns_ignore() {
    let mut config = SpecterConfig::default();
    let payload = le_subcmd(4); // Cd = 4, but no path bytes follow
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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

// ── handle_fs dir ────────────────────────────────────────────────────────

#[test]
fn handle_fs_dir_returns_non_empty_listing() {
    let tmp = std::env::temp_dir();
    let tmp_str = tmp.display().to_string();

    let mut config = SpecterConfig::default();
    let payload = dir_request_payload(&tmp_str, false, false, false, false, "", "", "");
    let package = DemonPackage::new(DemonCommand::CommandFs, 9, payload);

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
fn handle_fs_dir_list_only_omits_size_and_timestamps() {
    // In list_only mode the response must NOT include is_dir/size/timestamps per entry
    // and must NOT include total_size per dir group.
    let tmp = std::env::temp_dir();
    // Create a known file so we always have at least one entry.
    let test_file = tmp.join("specter_list_only_test.tmp");
    let _ = std::fs::write(&test_file, b"x");

    let mut config = SpecterConfig::default();
    let payload =
        dir_request_payload(&tmp.display().to_string(), false, false, false, true, "", "", "");
    let package = DemonPackage::new(DemonCommand::CommandFs, 11, payload);
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

    // Parse the response header.
    let p = &resp.payload;
    let mut pos = 0usize;
    let _subcmd = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("subcmd"));
    pos += 4;
    let _file_explorer = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("fe"));
    pos += 4;
    let list_only_flag = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("lo"));
    pos += 4;
    assert_eq!(list_only_flag, 1, "list_only must be echoed as 1");

    // Skip root_path (LE length-prefixed utf16le).
    let path_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("plen")) as usize;
    pos += 4 + path_len;
    let success = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("success"));
    assert_eq!(success, 1);
    pos += 4;

    // Dir group: dir_path, num_files, num_dirs — but NO total_size.
    let gpath_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("gpath")) as usize;
    pos += 4 + gpath_len;
    let _num_files = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("nf"));
    pos += 4;
    let _num_dirs = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("nd"));
    pos += 4;
    // In list_only mode the next field should be the first entry name, NOT a u64 total_size.
    // The remaining bytes must all be name-only entries (no is_dir/size/timestamps).
    // Just verify we can parse all remaining entries as utf16le strings without going OOB.
    while pos < p.len() {
        let name_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("name len")) as usize;
        pos += 4 + name_len;
    }
    assert_eq!(pos, p.len(), "no trailing bytes; each entry must be exactly a name");

    let _ = std::fs::remove_file(test_file);
}

#[test]
fn handle_fs_dir_timestamps_are_not_placeholder_epoch() {
    // Write a temp file and verify its modification time is encoded, not 1970-01-01 00:00.
    let tmp = std::env::temp_dir();
    let test_file = tmp.join("specter_ts_test.tmp");
    std::fs::write(&test_file, b"ts test").expect("write test file");

    let mut config = SpecterConfig::default();
    let payload =
        dir_request_payload(&tmp.display().to_string(), false, false, false, false, "", "", "");
    let package = DemonPackage::new(DemonCommand::CommandFs, 12, payload);
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

    // Parse to the first entry and check the year field.
    let p = &resp.payload;
    let mut pos = 4 + 4 + 4; // subcmd + file_explorer + list_only
    let root_path_len = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4 + root_path_len + 4; // skip root_path + success
    let gpath_len = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4 + gpath_len + 4 + 4 + 8; // skip group path + num_files + num_dirs + total_size

    // Find the entry for our test file and read its year (offset 4+2+4+8+4+4 from name start).
    let test_name = "specter_ts_test.tmp";
    let mut found = false;
    while pos < p.len() {
        let name_len = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let name_utf16: Vec<u16> = p[pos..pos + name_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name: String =
            char::decode_utf16(name_utf16).filter_map(|r| r.ok()).filter(|&c| c != '\0').collect();
        pos += name_len;
        // is_dir(4) + size(8) + day(4) + month(4) + year(4) + minute(4) + hour(4) = 32
        let _is_dir = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap());
        let _size = u64::from_le_bytes(p[pos + 4..pos + 12].try_into().unwrap());
        let _day = u32::from_le_bytes(p[pos + 12..pos + 16].try_into().unwrap());
        let _month = u32::from_le_bytes(p[pos + 16..pos + 20].try_into().unwrap());
        let year = u32::from_le_bytes(p[pos + 20..pos + 24].try_into().unwrap());
        pos += 32;
        if name == test_name {
            // The year must be >= 2024 (the file was just created).
            assert!(year >= 2024, "year should be current, got {year}");
            found = true;
        }
    }
    assert!(found, "test file entry not found in Dir listing");
    let _ = std::fs::remove_file(test_file);
}

#[test]
fn unix_secs_to_ymd_hm_known_value() {
    // 1743162600 = 2025-03-28T11:50:00Z (verified against algorithm output)
    let (d, m, y, min, h) = unix_secs_to_ymd_hm(1_743_162_600);
    assert_eq!((d, m, y, min, h), (28, 3, 2025, 50, 11));
}

#[test]
fn unix_secs_to_ymd_hm_epoch() {
    let (d, m, y, min, h) = unix_secs_to_ymd_hm(0);
    assert_eq!((d, m, y, min, h), (1, 1, 1970, 0, 0));
}

// ── handle_proc create / shell ────────────────────────────────────────────

#[test]
fn handle_proc_create_shell_returns_two_responses() {
    let cmd = "echo hello";
    let mut config = SpecterConfig::default();

    // Build the payload for CommandProc / ProcCreate (subcommand=4)
    let mut payload = 4u32.to_le_bytes().to_vec(); // subcmd = Create
    payload.extend_from_slice(&0u32.to_le_bytes()); // state
    payload.extend_from_slice(&le_utf16le_payload("c:\\windows\\system32\\cmd.exe")); // path
    payload.extend_from_slice(&le_utf16le_payload(&format!("/c {cmd}"))); // args
    payload.extend_from_slice(&1u32.to_le_bytes()); // piped = true
    payload.extend_from_slice(&0u32.to_le_bytes()); // verbose = false

    let package = DemonPackage::new(DemonCommand::CommandProc, 99, payload);
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

    let DispatchResult::MultiRespond(resps) = result else {
        panic!("expected MultiRespond, got {result:?}");
    };
    assert_eq!(resps.len(), 2);
    assert_eq!(resps[0].command_id, u32::from(DemonCommand::CommandProc));
    assert_eq!(resps[1].command_id, u32::from(DemonCommand::CommandOutput));

    // The output payload should contain "hello"
    // payload[0..4] = LE length, payload[4..] = output bytes
    let out_payload = &resps[1].payload;
    let out_len = u32::from_le_bytes(out_payload[0..4].try_into().expect("len")) as usize;
    let out_str =
        std::str::from_utf8(&out_payload[4..4 + out_len]).expect("utf8 output").trim().to_string();
    assert_eq!(out_str, "hello");
}

#[test]
fn handle_proc_create_reports_child_pid_not_agent_pid() {
    // The proc-create callback must carry the spawned child's PID, not std::process::id().
    let mut config = SpecterConfig::default();
    let mut payload = 4u32.to_le_bytes().to_vec(); // subcmd = Create
    payload.extend_from_slice(&0u32.to_le_bytes()); // state
    payload.extend_from_slice(&le_utf16le_payload("c:\\windows\\system32\\cmd.exe"));
    payload.extend_from_slice(&le_utf16le_payload("/c echo pid_test"));
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

    let DispatchResult::MultiRespond(resps) = result else {
        panic!("expected MultiRespond, got {result:?}");
    };

    // Parse the proc payload to extract the PID field.
    // Format: [subcmd: u32 LE][path: u32 LE len + utf16le bytes][pid: u32 LE][...]
    let proc_payload = &resps[0].payload;
    // Skip subcmd (4 bytes), then read the path length to skip the path.
    let path_len = u32::from_le_bytes(proc_payload[4..8].try_into().expect("path len")) as usize;
    let pid_offset = 4 + 4 + path_len;
    let reported_pid =
        u32::from_le_bytes(proc_payload[pid_offset..pid_offset + 4].try_into().expect("pid bytes"));

    // The reported PID must be non-zero (child was spawned) and must NOT be our own PID.
    assert_ne!(reported_pid, 0, "child PID must not be zero");
    assert_ne!(reported_pid, std::process::id(), "child PID must not equal the agent's own PID");
}

#[test]
fn translate_to_shell_cmd_strips_cmd_exe_prefix() {
    assert_eq!(translate_to_shell_cmd("c:\\windows\\system32\\cmd.exe", "/c whoami"), "whoami");
    assert_eq!(translate_to_shell_cmd("c:\\windows\\system32\\cmd.exe", "/C ls -la"), "ls -la");
}

#[test]
fn translate_to_shell_cmd_strips_quoted_cmd_path_prefix() {
    assert_eq!(
        translate_to_shell_cmd(
            r"c:\windows\system32\cmd.exe",
            r#""c:\windows\system32\cmd.exe" /c whoami"#
        ),
        "whoami"
    );
}

#[test]
fn translate_to_shell_cmd_non_cmd_exe_uses_path_and_args() {
    assert_eq!(translate_to_shell_cmd("/usr/bin/ls", "-la /tmp"), "/usr/bin/ls -la /tmp");
}

#[test]
fn translate_to_shell_cmd_empty_args_returns_path() {
    assert_eq!(translate_to_shell_cmd("/usr/bin/id", ""), "/usr/bin/id");
}

// ── unknown/unhandled commands ────────────────────────────────────────────

#[test]
fn dispatch_unknown_command_id_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage { command_id: 0xDEAD_0000, request_id: 0, payload: vec![] };
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
fn dispatch_no_job_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandNoJob, 0, vec![]);
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
fn dispatch_exit_returns_exit() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandExit, 0, vec![]);
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
        DispatchResult::Exit
    ));
}

// ── write_ptr_be ─────────────────────────────────────────────────────────

#[test]
fn write_ptr_be_encodes_eight_bytes_big_endian() {
    let mut buf = Vec::new();
    write_ptr_be(&mut buf, 0x0011_2233_4455_6677);
    assert_eq!(buf, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
}

// ── write_ptr_le ─────────────────────────────────────────────────────────

#[test]
fn write_ptr_le_encodes_eight_bytes_little_endian() {
    let mut buf = Vec::new();
    write_ptr_le(&mut buf, 0x0011_2233_4455_6677);
    assert_eq!(buf, [0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]);
}

#[test]
fn dispatch_routes_command_fs_pwd() {
    let mut config = SpecterConfig::default();
    let payload = le_subcmd(u32::from(DemonFilesystemCommand::GetPwd));
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
// ── handle_fs_cd edge cases ──────────────────────────────────────────────

#[test]
fn handle_fs_cd_nonexistent_directory_returns_ignore() {
    let mut config = SpecterConfig::default();
    let mut payload = le_subcmd(4); // Cd = 4
    payload.extend_from_slice(&le_utf16le_payload("/nonexistent_dir_xyz_99999"));
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
    assert!(
        matches!(result, DispatchResult::Ignore),
        "cd to nonexistent directory must return Ignore"
    );
}

// ── handle_fs_dir edge cases ─────────────────────────────────────────────

#[test]
fn handle_fs_dir_nonexistent_path_returns_ignore() {
    let payload =
        dir_request_payload("/nonexistent_dir_xyz_99999", false, false, false, false, "", "", "");
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
    assert!(matches!(result, DispatchResult::Ignore), "dir on nonexistent path must return Ignore");
}

#[test]
fn handle_fs_dir_files_only_excludes_directories() {
    let dir = std::env::temp_dir();
    let base = dir.join(format!("specter_dir_fonly_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&base).expect("create base dir");
    // Create a file and a subdirectory.
    std::fs::write(base.join("file.txt"), b"hello").expect("write file");
    std::fs::create_dir(base.join("subdir")).expect("create subdir");

    let payload = dir_request_payload(
        &base.display().to_string(),
        false,
        true, // files_only
        false,
        true, // list_only (simpler output)
        "",
        "",
        "",
    );
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
        panic!("expected Respond for dir listing");
    };
    // Verify the response payload doesn't contain "subdir".
    // The response uses UTF-16LE encoding, so search for "subdir" encoded.
    let subdir_utf16: Vec<u8> = "subdir".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    assert!(
        !resp.payload.windows(subdir_utf16.len()).any(|w| w == subdir_utf16.as_slice()),
        "files_only must exclude directory entries"
    );
    let file_utf16: Vec<u8> = "file.txt".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    assert!(
        resp.payload.windows(file_utf16.len()).any(|w| w == file_utf16.as_slice()),
        "files_only must include file entries"
    );
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn handle_fs_dir_dirs_only_excludes_files() {
    let dir = std::env::temp_dir();
    let base = dir.join(format!("specter_dir_donly_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&base).expect("create base dir");
    std::fs::write(base.join("file.txt"), b"hello").expect("write file");
    std::fs::create_dir(base.join("subdir")).expect("create subdir");

    let payload = dir_request_payload(
        &base.display().to_string(),
        false,
        false,
        true, // dirs_only
        true, // list_only
        "",
        "",
        "",
    );
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
        panic!("expected Respond for dir listing");
    };
    let file_utf16: Vec<u8> = "file.txt".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    assert!(
        !resp.payload.windows(file_utf16.len()).any(|w| w == file_utf16.as_slice()),
        "dirs_only must exclude file entries"
    );
    let subdir_utf16: Vec<u8> = "subdir".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    assert!(
        resp.payload.windows(subdir_utf16.len()).any(|w| w == subdir_utf16.as_slice()),
        "dirs_only must include directory entries"
    );
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn handle_fs_dir_name_filter_starts_with() {
    let dir = std::env::temp_dir();
    let base = dir.join(format!("specter_dir_filter_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&base).expect("create base dir");
    std::fs::write(base.join("alpha.txt"), b"a").expect("write alpha");
    std::fs::write(base.join("beta.txt"), b"b").expect("write beta");

    let payload = dir_request_payload(
        &base.display().to_string(),
        false,
        false,
        false,
        true, // list_only
        "alpha",
        "",
        "",
    );
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
        panic!("expected Respond for dir listing");
    };
    let alpha_utf16: Vec<u8> = "alpha.txt".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    assert!(
        resp.payload.windows(alpha_utf16.len()).any(|w| w == alpha_utf16.as_slice()),
        "starts_with filter must include matching entries"
    );
    let beta_utf16: Vec<u8> = "beta.txt".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    assert!(
        !resp.payload.windows(beta_utf16.len()).any(|w| w == beta_utf16.as_slice()),
        "starts_with filter must exclude non-matching entries"
    );
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn handle_fs_unknown_subcommand_returns_ignore() {
    let mut config = SpecterConfig::default();
    let payload = le_subcmd(0xFF_FF); // bogus subcommand
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
fn handle_fs_empty_payload_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, vec![]);
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

// ── handle_fs cat ─────────────────────────────────────────────────────────

#[test]
fn handle_fs_cat_reads_file_contents() {
    let tmp = std::env::temp_dir();
    let file = tmp.join(format!("specter_cat_{}.txt", rand::random::<u32>()));
    std::fs::write(&file, b"hello specter").expect("write test file");

    let mut config = SpecterConfig::default();
    let mut payload = le_subcmd(u32::from(DemonFilesystemCommand::Cat));
    payload.extend_from_slice(&le_utf16le_payload(&file.display().to_string()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));
    let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
    assert_eq!(subcmd, u32::from(DemonFilesystemCommand::Cat));
    // Verify "hello specter" appears in the payload.
    assert!(
        resp.payload.windows(b"hello specter".len()).any(|w| w == b"hello specter"),
        "Cat response must contain file contents"
    );
    let _ = std::fs::remove_file(file);
}

#[test]
fn handle_fs_cat_missing_file_returns_ignore() {
    let mut config = SpecterConfig::default();
    let mut payload = le_subcmd(u32::from(DemonFilesystemCommand::Cat));
    payload.extend_from_slice(&le_utf16le_payload("/nonexistent_specter_cat_xyz.txt"));
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
    assert!(matches!(result, DispatchResult::Ignore), "Cat of nonexistent file must return Ignore");
}

// ── handle_fs remove ──────────────────────────────────────────────────────

#[test]
fn handle_fs_remove_deletes_file() {
    let tmp = std::env::temp_dir();
    let file = tmp.join(format!("specter_rm_{}.txt", rand::random::<u32>()));
    std::fs::write(&file, b"delete me").expect("write file");
    assert!(file.exists());

    let mut config = SpecterConfig::default();
    let mut payload = le_subcmd(u32::from(DemonFilesystemCommand::Remove));
    payload.extend_from_slice(&le_utf16le_payload(&file.display().to_string()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
    assert!(matches!(result, DispatchResult::Respond(_)), "Remove must respond");
    assert!(!file.exists(), "file must be deleted");
}

#[test]
fn handle_fs_remove_deletes_empty_directory() {
    let tmp = std::env::temp_dir();
    let dir = tmp.join(format!("specter_rmdir_{}", rand::random::<u32>()));
    std::fs::create_dir(&dir).expect("create dir");
    assert!(dir.exists());

    let mut config = SpecterConfig::default();
    let mut payload = le_subcmd(u32::from(DemonFilesystemCommand::Remove));
    payload.extend_from_slice(&le_utf16le_payload(&dir.display().to_string()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
    assert!(matches!(result, DispatchResult::Respond(_)), "Remove dir must respond");
    assert!(!dir.exists(), "directory must be deleted");
}

// ── handle_fs mkdir ───────────────────────────────────────────────────────

#[test]
fn handle_fs_mkdir_creates_directory() {
    let tmp = std::env::temp_dir();
    let dir = tmp.join(format!("specter_mkdir_{}", rand::random::<u32>()));
    assert!(!dir.exists());

    let mut config = SpecterConfig::default();
    let mut payload = le_subcmd(u32::from(DemonFilesystemCommand::Mkdir));
    payload.extend_from_slice(&le_utf16le_payload(&dir.display().to_string()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
    assert!(matches!(result, DispatchResult::Respond(_)), "Mkdir must respond");
    assert!(dir.exists() && dir.is_dir(), "directory must exist after Mkdir");
    let _ = std::fs::remove_dir(dir);
}

// ── handle_fs copy ────────────────────────────────────────────────────────

#[test]
fn handle_fs_copy_copies_file() {
    let tmp = std::env::temp_dir();
    let from = tmp.join(format!("specter_cp_src_{}.txt", rand::random::<u32>()));
    let to = tmp.join(format!("specter_cp_dst_{}.txt", rand::random::<u32>()));
    std::fs::write(&from, b"copy content").expect("write src");

    let mut config = SpecterConfig::default();
    let mut payload = le_subcmd(u32::from(DemonFilesystemCommand::Copy));
    payload.extend_from_slice(&le_utf16le_payload(&from.display().to_string()));
    payload.extend_from_slice(&le_utf16le_payload(&to.display().to_string()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
    assert!(matches!(result, DispatchResult::Respond(_)), "Copy must respond");
    assert!(from.exists(), "source must still exist after Copy");
    assert!(to.exists(), "destination must exist after Copy");
    assert_eq!(std::fs::read(&to).expect("read dst"), b"copy content");
    let _ = std::fs::remove_file(from);
    let _ = std::fs::remove_file(to);
}

// ── handle_fs move ────────────────────────────────────────────────────────

#[test]
fn handle_fs_move_renames_file() {
    let tmp = std::env::temp_dir();
    let from = tmp.join(format!("specter_mv_src_{}.txt", rand::random::<u32>()));
    let to = tmp.join(format!("specter_mv_dst_{}.txt", rand::random::<u32>()));
    std::fs::write(&from, b"move content").expect("write src");

    let mut config = SpecterConfig::default();
    let mut payload = le_subcmd(u32::from(DemonFilesystemCommand::Move));
    payload.extend_from_slice(&le_utf16le_payload(&from.display().to_string()));
    payload.extend_from_slice(&le_utf16le_payload(&to.display().to_string()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
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
    assert!(matches!(result, DispatchResult::Respond(_)), "Move must respond");
    assert!(!from.exists(), "source must not exist after Move");
    assert!(to.exists(), "destination must exist after Move");
    assert_eq!(std::fs::read(&to).expect("read dst"), b"move content");
    let _ = std::fs::remove_file(to);
}
