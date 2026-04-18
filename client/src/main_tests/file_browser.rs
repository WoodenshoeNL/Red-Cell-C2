use super::*;

#[test]
fn build_console_task_encodes_filesystem_download() {
    let OperatorMessage::AgentTask(message) =
        build_console_task("ABCD1234", "download C:\\Temp\\report.txt", "operator")
            .unwrap_or_else(|error| panic!("console task should build: {error}"))
    else {
        panic!("expected agent task");
    };

    assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(message.info.sub_command.as_deref(), Some("download"));
    assert_eq!(message.info.arguments.as_deref(), Some("QzpcVGVtcFxyZXBvcnQudHh0"));
}

#[test]
fn file_browser_list_task_uses_explorer_arguments() {
    let OperatorMessage::AgentTask(message) =
        build_file_browser_list_task("ABCD1234", "C:\\Temp", "operator")
    else {
        panic!("expected agent task");
    };

    assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(message.info.sub_command.as_deref(), Some("dir"));
    assert_eq!(message.info.arguments.as_deref(), Some("C:\\Temp;true;false;false;false;;;"));
}

#[test]
fn file_browser_upload_task_encodes_remote_path_and_content() {
    let OperatorMessage::AgentTask(message) =
        build_file_browser_upload_task("ABCD1234", "C:\\Temp\\report.txt", b"hello", "operator")
    else {
        panic!("expected agent task");
    };

    assert_eq!(message.info.sub_command.as_deref(), Some("upload"));
    assert_eq!(message.info.arguments.as_deref(), Some("QzpcVGVtcFxyZXBvcnQudHh0;aGVsbG8="));
}

#[test]
fn build_console_task_rejects_missing_process_kill_pid() {
    let error = build_console_task("ABCD1234", "proc kill", "operator")
        .expect_err("missing pid should fail");
    assert_eq!(error, "Usage: proc kill <pid>");
}

#[test]
fn parent_remote_path_returns_windows_parent() {
    assert_eq!(parent_remote_path("C:\\Temp\\report.txt").as_deref(), Some("C:\\Temp\\"));
}

#[test]
fn upload_destination_prefers_selected_directory() {
    let browser = AgentFileBrowserState {
        current_dir: Some("C:\\Temp".to_owned()),
        directories: BTreeMap::from([(
            "C:\\Temp".to_owned(),
            vec![FileBrowserEntry {
                name: "Logs".to_owned(),
                path: "C:\\Temp\\Logs".to_owned(),
                is_dir: true,
                size_label: String::new(),
                size_bytes: None,
                modified_at: String::new(),
                permissions: String::new(),
            }],
        )]),
        ..AgentFileBrowserState::default()
    };

    assert_eq!(
        upload_destination(Some(&browser), Some("C:\\Temp\\Logs")).as_deref(),
        Some("C:\\Temp\\Logs")
    );
}

#[test]
fn selected_remote_directory_uses_parent_for_selected_file() {
    let browser = AgentFileBrowserState {
        current_dir: Some("C:\\Temp".to_owned()),
        directories: BTreeMap::from([(
            "C:\\Temp".to_owned(),
            vec![FileBrowserEntry {
                name: "report.txt".to_owned(),
                path: "C:\\Temp\\report.txt".to_owned(),
                is_dir: false,
                size_label: "5 B".to_owned(),
                size_bytes: Some(5),
                modified_at: String::new(),
                permissions: String::new(),
            }],
        )]),
        ..AgentFileBrowserState::default()
    };

    assert_eq!(
        selected_remote_directory(Some(&browser), Some("C:\\Temp\\report.txt")).as_deref(),
        Some("C:\\Temp\\")
    );
}

#[test]
fn selected_remote_directory_returns_none_without_matching_entry() {
    let browser = AgentFileBrowserState::default();
    assert!(selected_remote_directory(Some(&browser), Some("C:\\Missing")).is_none());
}

// ── join_remote_path ──────────────────────────────────────────────

#[test]
fn join_remote_path_windows_backslash_base() {
    assert_eq!(join_remote_path("C:\\Users\\admin", "Documents"), "C:\\Users\\admin\\Documents");
}

#[test]
fn join_remote_path_unix_slash_base() {
    assert_eq!(join_remote_path("/home/user", "file.txt"), "/home/user/file.txt");
}

#[test]
fn join_remote_path_trailing_backslash() {
    assert_eq!(join_remote_path("C:\\Users\\", "admin"), "C:\\Users\\admin");
}

#[test]
fn join_remote_path_trailing_slash() {
    assert_eq!(join_remote_path("/home/user/", "file.txt"), "/home/user/file.txt");
}

#[test]
fn join_remote_path_empty_base() {
    assert_eq!(join_remote_path("", "file.txt"), "file.txt");
}

#[test]
fn join_remote_path_root_unix() {
    assert_eq!(join_remote_path("/", "etc"), "/etc");
}

// ── DockTab::FileBrowser ────────────────────────────────────────

#[test]
fn dock_tab_file_browser_label() {
    let tab = DockTab::FileBrowser("DEADBEEF".to_owned());
    assert_eq!(tab.label(), "[DEADBEEF] File Explorer");
}

#[test]
fn dock_tab_file_browser_is_closeable() {
    let tab = DockTab::FileBrowser("DEADBEEF".to_owned());
    assert!(tab.closeable());
}

#[test]
fn dock_tab_file_browser_accent_is_teal() {
    let tab = DockTab::FileBrowser("DEADBEEF".to_owned());
    assert_eq!(tab.accent_color(), Color32::from_rgb(80, 180, 140));
}

#[test]
fn dock_state_open_file_browser_tab() {
    let mut dock = DockState::default();
    dock.open_tab(DockTab::FileBrowser("AGENT1".to_owned()));
    assert!(dock.open_tabs.contains(&DockTab::FileBrowser("AGENT1".to_owned())));
    assert_eq!(dock.selected, Some(DockTab::FileBrowser("AGENT1".to_owned())));
}

#[test]
fn dock_state_close_file_browser_tab() {
    let mut dock = DockState::default();
    dock.open_tab(DockTab::FileBrowser("AGENT1".to_owned()));
    dock.close_tab(&DockTab::FileBrowser("AGENT1".to_owned()));
    assert!(!dock.open_tabs.contains(&DockTab::FileBrowser("AGENT1".to_owned())));
}

// ── DockTab::ProcessList ──────────────────────────────────────────

#[test]
fn dock_tab_process_list_label() {
    let tab = DockTab::ProcessList("DEADBEEF".to_owned());
    assert_eq!(tab.label(), "Process: [DEADBEEF]");
}

#[test]
fn dock_tab_process_list_is_closeable() {
    let tab = DockTab::ProcessList("DEADBEEF".to_owned());
    assert!(tab.closeable());
}

#[test]
fn dock_tab_process_list_accent_is_red() {
    let tab = DockTab::ProcessList("DEADBEEF".to_owned());
    assert_eq!(tab.accent_color(), Color32::from_rgb(255, 85, 85));
}

#[test]
fn dock_state_open_process_list_tab() {
    let mut dock = DockState::default();
    dock.open_tab(DockTab::ProcessList("AGENT1".to_owned()));
    assert!(dock.open_tabs.contains(&DockTab::ProcessList("AGENT1".to_owned())));
    assert_eq!(dock.selected, Some(DockTab::ProcessList("AGENT1".to_owned())));
}

#[test]
fn dock_state_close_process_list_tab() {
    let mut dock = DockState::default();
    dock.open_tab(DockTab::ProcessList("AGENT1".to_owned()));
    dock.close_tab(&DockTab::ProcessList("AGENT1".to_owned()));
    assert!(!dock.open_tabs.contains(&DockTab::ProcessList("AGENT1".to_owned())));
}

#[test]
fn ensure_process_list_open_creates_tab() {
    let mut panel = SessionPanelState::default();
    panel.ensure_process_list_open("ABCD1234");
    assert!(panel.dock.open_tabs.contains(&DockTab::ProcessList("ABCD1234".to_owned())));
    assert_eq!(panel.dock.selected, Some(DockTab::ProcessList("ABCD1234".to_owned())));
}

#[test]
fn ensure_process_list_open_idempotent() {
    let mut panel = SessionPanelState::default();
    panel.ensure_process_list_open("ABCD1234");
    panel.ensure_process_list_open("ABCD1234");
    let count = panel
        .dock
        .open_tabs
        .iter()
        .filter(|t| **t == DockTab::ProcessList("ABCD1234".to_owned()))
        .count();
    assert_eq!(count, 1);
}

// ── breadcrumb_segments ──────────────────────────────────────────

#[test]
fn breadcrumb_segments_windows_path() {
    let segments = breadcrumb_segments("C:\\Users\\admin\\Documents");
    assert_eq!(
        segments,
        vec![
            ("C:\\".to_owned(), "C:\\".to_owned()),
            ("Users".to_owned(), "C:\\Users\\".to_owned()),
            ("admin".to_owned(), "C:\\Users\\admin\\".to_owned()),
            ("Documents".to_owned(), "C:\\Users\\admin\\Documents\\".to_owned()),
        ]
    );
}

#[test]
fn breadcrumb_segments_unix_path() {
    let segments = breadcrumb_segments("/home/user/docs");
    assert_eq!(
        segments,
        vec![
            ("/".to_owned(), "/".to_owned()),
            ("home".to_owned(), "/home/".to_owned()),
            ("user".to_owned(), "/home/user/".to_owned()),
            ("docs".to_owned(), "/home/user/docs/".to_owned()),
        ]
    );
}

#[test]
fn breadcrumb_segments_root_only() {
    let segments = breadcrumb_segments("/");
    assert_eq!(segments, vec![("/".to_owned(), "/".to_owned())]);
}

#[test]
fn breadcrumb_segments_windows_drive_root() {
    let segments = breadcrumb_segments("C:\\");
    assert_eq!(segments, vec![("C:\\".to_owned(), "C:\\".to_owned())]);
}

#[test]
fn breadcrumb_segments_relative_path() {
    let segments = breadcrumb_segments("Documents/Stuff");
    assert_eq!(
        segments,
        vec![
            ("Documents".to_owned(), "Documents/".to_owned()),
            ("Stuff".to_owned(), "Documents/Stuff/".to_owned()),
        ]
    );
}

// ── directory_label ───────────────────────────────────────────────

#[test]
fn directory_label_extracts_leaf() {
    assert_eq!(directory_label("/home/user/Documents"), "Documents");
}

#[test]
fn directory_label_windows_leaf() {
    // On Linux, std::path::Path does not split on backslashes, so the full
    // string is returned as the "file_name". This matches the current
    // implementation which delegates to Path::file_name().
    let result = directory_label("C:\\Users\\admin\\Desktop");
    assert!(
        result == "Desktop" || result == "C:\\Users\\admin\\Desktop",
        "unexpected result: {result}"
    );
}

#[test]
fn directory_label_trailing_separator() {
    assert_eq!(directory_label("/home/user/Downloads/"), "Downloads");
}

#[test]
fn directory_label_drive_root_backslash() {
    assert_eq!(directory_label("C:\\"), "C:\\");
}

#[test]
fn directory_label_drive_root_slash() {
    assert_eq!(directory_label("C:/"), "C:/");
}

#[test]
fn directory_label_drive_letter_colon() {
    assert_eq!(directory_label("C:"), "C:");
}

// ── file_entry_label ──────────────────────────────────────────────

fn make_file_browser_entry(
    name: &str,
    size_label: &str,
    modified: &str,
    perms: &str,
) -> FileBrowserEntry {
    FileBrowserEntry {
        name: name.to_owned(),
        path: String::new(),
        is_dir: false,
        size_label: size_label.to_owned(),
        size_bytes: None,
        modified_at: modified.to_owned(),
        permissions: perms.to_owned(),
    }
}

#[test]
fn file_entry_label_all_fields() {
    let entry = make_file_browser_entry("readme.txt", "1.5 KB", "2026-01-15", "rwxr-xr-x");
    assert_eq!(file_entry_label(&entry), "readme.txt  [1.5 KB | 2026-01-15 | rwxr-xr-x]");
}

#[test]
fn file_entry_label_empty_size() {
    let entry = make_file_browser_entry("dir", "", "2026-01-15", "drwxr-xr-x");
    assert_eq!(file_entry_label(&entry), "dir  [- | 2026-01-15 | drwxr-xr-x]");
}

#[test]
fn file_entry_label_all_empty_metadata() {
    let entry = make_file_browser_entry("file.bin", " ", "", "");
    assert_eq!(file_entry_label(&entry), "file.bin  [- | - | -]");
}

// ── human_size ────────────────────────────────────────────────────

#[test]
fn human_size_zero_bytes() {
    assert_eq!(human_size(0), "0 B");
}

#[test]
fn human_size_below_kb() {
    assert_eq!(human_size(1023), "1023 B");
}

#[test]
fn human_size_exactly_1kb() {
    assert_eq!(human_size(1024), "1.0 KB");
}

#[test]
fn human_size_megabyte_range() {
    assert_eq!(human_size(1_048_576), "1.0 MB");
}

#[test]
fn human_size_gigabyte_range() {
    assert_eq!(human_size(1_073_741_824), "1.0 GB");
}

#[test]
fn human_size_large_gb_value() {
    assert_eq!(human_size(5_905_580_032), "5.5 GB");
}

#[test]
fn human_size_one_byte() {
    assert_eq!(human_size(1), "1 B");
}

// ── find_file_entry ───────────────────────────────────────────────

fn browser_with_entries(entries: Vec<FileBrowserEntry>) -> AgentFileBrowserState {
    let mut dirs = std::collections::BTreeMap::new();
    dirs.insert("/home".to_owned(), entries);
    AgentFileBrowserState {
        current_dir: Some("/home".to_owned()),
        directories: dirs,
        ..AgentFileBrowserState::default()
    }
}

#[test]
fn find_file_entry_found() {
    let entry = FileBrowserEntry {
        name: "test.txt".to_owned(),
        path: "/home/test.txt".to_owned(),
        is_dir: false,
        size_label: "100 B".to_owned(),
        size_bytes: Some(100),
        modified_at: String::new(),
        permissions: String::new(),
    };
    let browser = browser_with_entries(vec![entry]);
    let found = find_file_entry(&browser, "/home/test.txt");
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "test.txt");
}

#[test]
fn find_file_entry_not_found() {
    let browser = browser_with_entries(vec![]);
    assert!(find_file_entry(&browser, "/nonexistent").is_none());
}

// ── parent_remote_path ────────────────────────────────────────────

#[test]
fn parent_remote_path_unix() {
    assert_eq!(parent_remote_path("/home/user/file.txt"), Some("/home/user/".to_owned()));
}

#[test]
fn parent_remote_path_windows() {
    assert_eq!(
        parent_remote_path("C:\\Users\\admin\\file.txt"),
        Some("C:\\Users\\admin\\".to_owned())
    );
}

#[test]
fn parent_remote_path_trailing_slash() {
    assert_eq!(parent_remote_path("/home/user/"), Some("/home/".to_owned()));
}

#[test]
fn parent_remote_path_root() {
    assert_eq!(parent_remote_path("/"), None);
}

#[test]
fn parent_remote_path_empty() {
    assert_eq!(parent_remote_path(""), None);
}

#[test]
fn parent_remote_path_no_separator() {
    assert_eq!(parent_remote_path("file.txt"), None);
}

// ── json_str ─────────────────────────────────────────────────────────

#[test]
fn json_str_plain_string() {
    assert_eq!(json_str("hello"), "\"hello\"");
}

#[test]
fn json_str_embedded_quotes() {
    assert_eq!(json_str(r#"say "hi""#), r#""say \"hi\"""#);
}

#[test]
fn json_str_backslashes() {
    assert_eq!(json_str(r"C:\Users\admin"), r#""C:\\Users\\admin""#);
}

#[test]
fn json_str_newlines_and_tabs() {
    assert_eq!(json_str("line1\nline2\ttab"), r#""line1\nline2\ttab""#);
}

#[test]
fn json_str_carriage_return() {
    assert_eq!(json_str("a\rb"), r#""a\rb""#);
}

#[test]
fn json_str_empty_string() {
    assert_eq!(json_str(""), "\"\"");
}

#[test]
fn json_str_combined_escapes() {
    assert_eq!(json_str("\\\"\n\r\t"), r#""\\\"\n\r\t""#);
}

#[test]
fn json_str_null_bytes_passed_through() {
    // Null bytes are not escaped by json_str — they pass through as-is.
    let result = json_str("a\0b");
    assert!(result.starts_with('"') && result.ends_with('"'));
    assert!(result.contains('\0'));
}

// ── contains_ascii_case_insensitive ──────────────────────────────────

#[test]
fn case_insensitive_match() {
    assert!(contains_ascii_case_insensitive("Hello World", "hello"));
}

#[test]
fn case_insensitive_no_match() {
    assert!(!contains_ascii_case_insensitive("Hello World", "goodbye"));
}

#[test]
fn case_insensitive_empty_needle_matches_all() {
    assert!(contains_ascii_case_insensitive("anything", ""));
    assert!(contains_ascii_case_insensitive("", ""));
}

#[test]
fn case_insensitive_whitespace_only_needle_matches_all() {
    assert!(contains_ascii_case_insensitive("anything", "   "));
}

#[test]
fn case_insensitive_mixed_case() {
    assert!(contains_ascii_case_insensitive("NtLmHash", "ntlm"));
}

#[test]
fn case_insensitive_needle_with_surrounding_whitespace() {
    assert!(contains_ascii_case_insensitive("foobar", "  bar  "));
}
