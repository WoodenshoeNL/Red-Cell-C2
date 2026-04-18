use super::*;

#[test]
fn filtered_process_rows_matches_name_and_pid() {
    let rows = vec![
        ProcessEntry {
            pid: 1010,
            ppid: 4,
            name: "explorer.exe".to_owned(),
            arch: "x64".to_owned(),
            user: "LAB\\operator".to_owned(),
            session: 1,
        },
        ProcessEntry {
            pid: 2020,
            ppid: 4,
            name: "svchost.exe".to_owned(),
            arch: "x64".to_owned(),
            user: "SYSTEM".to_owned(),
            session: 0,
        },
    ];

    assert_eq!(filtered_process_rows(&rows, "explorer").len(), 1);
    assert_eq!(filtered_process_rows(&rows, "2020").len(), 1);
    assert_eq!(filtered_process_rows(&rows, "missing").len(), 0);
}

#[test]
fn normalized_process_arch_maps_unknown_values_to_x64() {
    assert_eq!(normalized_process_arch("x86"), "x86");
    assert_eq!(normalized_process_arch("WOW64"), "x64");
}

#[test]
fn history_navigation_walks_commands_and_resets() {
    let mut console = AgentConsoleState::default();
    push_history_entry(&mut console, "ps");
    push_history_entry(&mut console, "pwd");

    apply_history_step(&mut console, HistoryDirection::Older);
    assert_eq!(console.input, "pwd");

    apply_history_step(&mut console, HistoryDirection::Older);
    assert_eq!(console.input, "ps");

    apply_history_step(&mut console, HistoryDirection::Newer);
    assert_eq!(console.input, "pwd");

    apply_history_step(&mut console, HistoryDirection::Newer);
    assert!(console.input.is_empty());
}

#[test]
fn completion_cycles_supported_commands() {
    let mut console = AgentConsoleState { input: "p".to_owned(), ..AgentConsoleState::default() };

    apply_completion(&mut console);
    assert_eq!(console.input, "ps");

    apply_completion(&mut console);
    assert_eq!(console.input, "pwd");

    apply_completion(&mut console);
    assert_eq!(console.input, "proc");
}

#[test]
fn split_console_selection_prefers_selected_agent() {
    let open = vec!["A".to_owned(), "B".to_owned(), "C".to_owned()];
    let visible = split_console_selection(&open, Some("C"));
    assert_eq!(visible, vec!["C", "A"]);
}

// ── process_task tests ──────────────────────────────────────────────

#[test]
fn process_task_valid_kill() {
    let info = process_task("DEAD0001", "proc kill 1234").unwrap();
    assert_eq!(info.demon_id, "DEAD0001");
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandProc).to_string());
    assert_eq!(info.command.as_deref(), Some("proc"));
    assert_eq!(info.sub_command.as_deref(), Some("kill"));
    assert_eq!(info.arguments.as_deref(), Some("1234"));
    assert_eq!(info.command_line, "proc kill 1234");
    assert_eq!(info.extra.get("Args"), Some(&serde_json::Value::String("1234".to_owned())));
}

#[test]
fn process_task_missing_subcommand() {
    let err = process_task("DEAD0001", "proc").unwrap_err();
    assert!(err.contains("Usage"), "unexpected error: {err}");
}

#[test]
fn process_task_missing_pid() {
    let err = process_task("DEAD0001", "proc kill").unwrap_err();
    assert!(err.contains("Usage"), "unexpected error: {err}");
}

#[test]
fn process_task_non_numeric_pid() {
    let err = process_task("DEAD0001", "proc kill abc").unwrap_err();
    assert!(err.contains("Invalid PID"), "unexpected error: {err}");
}

#[test]
fn process_task_extra_trailing_args() {
    let err = process_task("DEAD0001", "proc kill 1234 extra").unwrap_err();
    assert!(err.contains("Usage"), "unexpected error: {err}");
}

#[test]
fn process_task_unknown_subcommand() {
    let err = process_task("DEAD0001", "proc list").unwrap_err();
    assert!(err.contains("Usage"), "unexpected error: {err}");
}

#[test]
fn process_task_kill_case_insensitive() {
    let info = process_task("DEAD0001", "proc KILL 42").unwrap();
    assert_eq!(info.sub_command.as_deref(), Some("kill"));
    assert_eq!(info.arguments.as_deref(), Some("42"));
}

// ── rest_after_word tests ───────────────────────────────────────────

#[test]
fn rest_after_word_two_words() {
    assert_eq!(rest_after_word("cmd argument").unwrap(), "argument");
}

#[test]
fn rest_after_word_multiple_words() {
    assert_eq!(rest_after_word("shell whoami /all").unwrap(), "whoami /all");
}

#[test]
fn rest_after_word_single_word_errors() {
    let err = rest_after_word("cmd").unwrap_err();
    assert!(err.contains("requires an argument"), "unexpected error: {err}");
}

#[test]
fn rest_after_word_leading_trailing_whitespace() {
    assert_eq!(rest_after_word("  cmd   argument  ").unwrap(), "argument");
}

#[test]
fn rest_after_word_empty_string_errors() {
    assert!(rest_after_word("").is_err());
}

#[test]
fn rest_after_word_only_whitespace_errors() {
    assert!(rest_after_word("   ").is_err());
}
