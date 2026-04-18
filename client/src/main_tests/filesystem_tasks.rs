use super::*;

/// Helper to extract the `AgentTaskInfo` from an `OperatorMessage::AgentTask`.
fn unwrap_agent_task(msg: OperatorMessage) -> (MessageHead, AgentTaskInfo) {
    match msg {
        OperatorMessage::AgentTask(m) => (m.head, m.info),
        other => panic!("expected AgentTask, got {other:?}"),
    }
}

// -- filesystem_task helper --

#[test]
fn filesystem_task_sets_command_fs_and_sub_command() {
    let info = filesystem_task("DEAD0001", "pwd", "pwd", None);
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(info.command.as_deref(), Some("fs"));
    assert_eq!(info.sub_command.as_deref(), Some("pwd"));
    assert_eq!(info.demon_id, "DEAD0001");
    assert_eq!(info.command_line, "pwd");
    assert!(info.arguments.is_none());
}

#[test]
fn filesystem_task_with_arguments_passes_them_through() {
    let info = filesystem_task("DEAD0002", "cd /tmp", "cd", Some("/tmp".to_owned()));
    assert_eq!(info.arguments.as_deref(), Some("/tmp"));
    assert_eq!(info.command_line, "cd /tmp");
}

#[test]
fn filesystem_task_generates_eight_hex_digit_task_id() {
    let info = filesystem_task("DEAD0003", "pwd", "pwd", None);
    assert_eq!(info.task_id.len(), 8);
    assert!(
        u32::from_str_radix(&info.task_id, 16).is_ok(),
        "task_id should be valid hex: {}",
        info.task_id
    );
}

// -- filesystem_transfer_task helper --

#[test]
fn filesystem_transfer_task_base64_encodes_path() {
    let info =
        filesystem_transfer_task("DEAD0004", "download /etc/passwd", "download", "/etc/passwd");
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(info.command.as_deref(), Some("fs"));
    assert_eq!(info.sub_command.as_deref(), Some("download"));
    let expected = base64::engine::general_purpose::STANDARD.encode(b"/etc/passwd");
    assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
}

#[test]
fn filesystem_transfer_task_encodes_windows_path() {
    let path = r"C:\Users\admin\Desktop\secrets.txt";
    let info = filesystem_transfer_task("DEAD0005", &format!("download {path}"), "download", path);
    let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
    assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
}

#[test]
fn filesystem_transfer_task_encodes_unicode_path() {
    let path = "/home/用户/文件.txt";
    let info = filesystem_transfer_task("DEAD0006", &format!("cat {path}"), "cat", path);
    let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
    assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
}

// -- build_transfer_stop_task --

#[test]
fn build_transfer_stop_task_encodes_correct_payload() {
    let msg = build_transfer_stop_task("DEAD0007", "0000002A", "operator")
        .expect("should build for valid hex");
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(
        info.command_id,
        u32::from(red_cell_common::demon::DemonCommand::CommandTransfer).to_string()
    );
    assert_eq!(info.command_line, "transfer stop 0000002A");

    // Verify the binary payload: [1u32_le, 0x2Au32_le]
    let b64 = info
        .extra
        .get("PayloadBase64")
        .and_then(|v| v.as_str())
        .expect("PayloadBase64 must be present");
    let payload = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    assert_eq!(payload.len(), 8);
    assert_eq!(&payload[..4], &1u32.to_le_bytes()); // stop subcommand
    assert_eq!(&payload[4..], &0x0000_002Au32.to_le_bytes()); // file_id
}

#[test]
fn build_transfer_stop_task_rejects_invalid_hex() {
    assert!(build_transfer_stop_task("DEAD0008", "not_hex", "operator").is_none());
}

#[test]
fn build_transfer_stop_task_handles_8digit_hex() {
    let msg = build_transfer_stop_task("DEAD0009", "DEADBEEF", "operator")
        .expect("should parse 8-digit hex");
    let (_, info) = unwrap_agent_task(msg);
    let b64 = info.extra["PayloadBase64"].as_str().unwrap();
    let payload = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    assert_eq!(&payload[4..], &0xDEADBEEFu32.to_le_bytes());
}

// -- build_file_browser_pwd_task --

#[test]
fn build_file_browser_pwd_task_produces_correct_shape() {
    let (head, info) = unwrap_agent_task(build_file_browser_pwd_task("BEEF0001", "alice"));
    assert_eq!(head.user, "alice");
    assert_eq!(info.demon_id, "BEEF0001");
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(info.command.as_deref(), Some("fs"));
    assert_eq!(info.sub_command.as_deref(), Some("pwd"));
    assert_eq!(info.command_line, "pwd");
    assert!(info.arguments.is_none());
}

// -- build_file_browser_cd_task --

#[test]
fn build_file_browser_cd_task_produces_correct_shape() {
    let (head, info) = unwrap_agent_task(build_file_browser_cd_task("BEEF0002", "/var/log", "bob"));
    assert_eq!(head.user, "bob");
    assert_eq!(info.demon_id, "BEEF0002");
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(info.sub_command.as_deref(), Some("cd"));
    assert_eq!(info.command_line, "cd /var/log");
    assert_eq!(info.arguments.as_deref(), Some("/var/log"));
}

#[test]
fn build_file_browser_cd_task_handles_path_with_spaces() {
    let (_, info) =
        unwrap_agent_task(build_file_browser_cd_task("BEEF0003", "C:\\Program Files\\App", "op"));
    assert_eq!(info.arguments.as_deref(), Some("C:\\Program Files\\App"));
    assert_eq!(info.command_line, "cd C:\\Program Files\\App");
}

#[test]
fn build_file_browser_cd_task_handles_unicode_path() {
    let (_, info) = unwrap_agent_task(build_file_browser_cd_task("BEEF0004", "/home/用户", "op"));
    assert_eq!(info.arguments.as_deref(), Some("/home/用户"));
}

// -- build_file_browser_download_task --

#[test]
fn build_file_browser_download_task_produces_correct_shape() {
    let (head, info) =
        unwrap_agent_task(build_file_browser_download_task("CAFE0001", "/tmp/data.bin", "charlie"));
    assert_eq!(head.user, "charlie");
    assert_eq!(info.demon_id, "CAFE0001");
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(info.sub_command.as_deref(), Some("download"));
    assert_eq!(info.command_line, "download /tmp/data.bin");
    let expected = base64::engine::general_purpose::STANDARD.encode(b"/tmp/data.bin");
    assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
}

#[test]
fn build_file_browser_download_task_encodes_windows_backslash_path() {
    let path = r"C:\Users\admin\Documents\report.docx";
    let (_, info) = unwrap_agent_task(build_file_browser_download_task("CAFE0002", path, "op"));
    let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
    assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
}

#[test]
fn build_file_browser_download_task_encodes_unicode_path() {
    let path = "/données/résumé.pdf";
    let (_, info) = unwrap_agent_task(build_file_browser_download_task("CAFE0003", path, "op"));
    let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
    assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
}

// -- build_file_browser_delete_task --

#[test]
fn build_file_browser_delete_task_produces_correct_shape() {
    let (head, info) =
        unwrap_agent_task(build_file_browser_delete_task("F00D0001", "/tmp/junk.log", "dave"));
    assert_eq!(head.user, "dave");
    assert_eq!(info.demon_id, "F00D0001");
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(info.sub_command.as_deref(), Some("remove"));
    assert_eq!(info.command_line, "rm /tmp/junk.log");
    assert_eq!(info.arguments.as_deref(), Some("/tmp/junk.log"));
}

#[test]
fn build_file_browser_delete_task_handles_path_with_spaces() {
    let path = "C:\\Program Files\\Old App\\config.ini";
    let (_, info) = unwrap_agent_task(build_file_browser_delete_task("F00D0002", path, "op"));
    assert_eq!(info.arguments.as_deref(), Some(path));
    assert_eq!(info.command_line, format!("rm {path}"));
}

#[test]
fn build_file_browser_delete_task_handles_unicode_path() {
    let path = "/home/用户/临时文件.tmp";
    let (_, info) = unwrap_agent_task(build_file_browser_delete_task("F00D0003", path, "op"));
    assert_eq!(info.arguments.as_deref(), Some(path));
}

// -- cross-builder structural checks --

#[test]
fn all_file_browser_builders_set_session_event_code() {
    let builders: Vec<OperatorMessage> = vec![
        build_file_browser_pwd_task("A0000001", "op"),
        build_file_browser_cd_task("A0000002", "/tmp", "op"),
        build_file_browser_download_task("A0000003", "/tmp/f", "op"),
        build_file_browser_delete_task("A0000004", "/tmp/f", "op"),
    ];
    for msg in builders {
        let (head, _) = unwrap_agent_task(msg);
        assert_eq!(
            head.event,
            EventCode::Session,
            "file browser tasks must use Session event code"
        );
    }
}

#[test]
fn all_file_browser_builders_produce_unique_task_ids() {
    let msgs: Vec<OperatorMessage> = vec![
        build_file_browser_pwd_task("B0000001", "op"),
        build_file_browser_cd_task("B0000002", "/a", "op"),
        build_file_browser_download_task("B0000003", "/b", "op"),
        build_file_browser_delete_task("B0000004", "/c", "op"),
    ];
    let mut ids: Vec<String> = msgs
        .into_iter()
        .map(|m| {
            let (_, info) = unwrap_agent_task(m);
            info.task_id
        })
        .collect();
    let count_before = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), count_before, "task IDs should all be unique");
}
