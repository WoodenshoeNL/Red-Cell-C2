use super::*;

/// Helper to extract the `AgentTaskInfo` from an `OperatorMessage::AgentTask`.
fn unwrap_agent_task(msg: OperatorMessage) -> (MessageHead, AgentTaskInfo) {
    match msg {
        OperatorMessage::AgentTask(m) => (m.head, m.info),
        other => panic!("expected AgentTask, got {other:?}"),
    }
}

#[test]
fn build_console_message_color_mapping() {
    assert_eq!(build_console_message_color("Good"), Color32::from_rgb(85, 255, 85));
    assert_eq!(build_console_message_color("Error"), Color32::from_rgb(255, 85, 85));
    assert_eq!(build_console_message_color("Warning"), Color32::from_rgb(255, 200, 50));
    assert_eq!(build_console_message_color("Info"), Color32::from_rgb(180, 180, 220));
    assert_eq!(build_console_message_color("unknown"), Color32::from_rgb(180, 180, 220));
}

#[test]
fn build_console_message_prefix_mapping() {
    assert_eq!(build_console_message_prefix("Good"), "[+]");
    assert_eq!(build_console_message_prefix("Error"), "[-]");
    assert_eq!(build_console_message_prefix("Warning"), "[!]");
    assert_eq!(build_console_message_prefix("Info"), "[*]");
    assert_eq!(build_console_message_prefix("other"), "[*]");
}

// ---- console prompt format tests ----

#[test]
fn format_console_prompt_includes_operator_and_agent_id() {
    let prompt = format_console_prompt("alice", "DEAD1234");
    assert_eq!(prompt, "[alice/DEAD1234] demon.x64 >> ");
}

#[test]
fn format_console_prompt_uses_fallback_when_operator_empty() {
    let prompt = format_console_prompt("", "DEAD1234");
    assert_eq!(prompt, "[operator/DEAD1234] demon.x64 >> ");
}

// ---- help command tests ----

#[test]
fn handle_local_command_help_returns_command_table() {
    let output = handle_local_command("help").expect("help should be handled locally");
    assert!(output.contains("Demon Commands"));
    assert!(output.contains("Command"));
    assert!(output.contains("Type"));
    assert!(output.contains("Description"));
    // Verify a sample of commands appear in the table.
    assert!(output.contains("shell"));
    assert!(output.contains("sleep"));
    assert!(output.contains("token"));
    assert!(output.contains("inline-execute"));
}

#[test]
fn handle_local_command_help_specific_command() {
    let output = handle_local_command("help shell").expect("help shell should be handled");
    assert!(output.contains("shell"));
    assert!(output.contains("Usage:"));
    assert!(output.contains("Description:"));
}

#[test]
fn handle_local_command_help_unknown_topic() {
    let output = handle_local_command("help nonexistent").expect("should still return output");
    assert!(output.contains("Unknown command"));
}

#[test]
fn handle_local_command_question_mark_alias() {
    let output = handle_local_command("?").expect("? should work as help alias");
    assert!(output.contains("Demon Commands"));
}

#[test]
fn handle_local_command_returns_none_for_remote_commands() {
    assert!(handle_local_command("ps").is_none());
    assert!(handle_local_command("shell whoami").is_none());
    assert!(handle_local_command("sleep 10").is_none());
}

// ---- new command dispatch tests ----

#[test]
fn build_console_task_shell_command() {
    let result = build_console_task("ABCD1234", "shell whoami", "operator");
    let msg = result.unwrap_or_else(|e| panic!("shell task should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandInlineExecute).to_string());
    assert_eq!(info.arguments.as_deref(), Some("whoami"));
}

#[test]
fn build_console_task_sleep_with_jitter() {
    let result = build_console_task("ABCD1234", "sleep 30 50%", "operator");
    let msg = result.unwrap_or_else(|e| panic!("sleep task should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandSleep).to_string());
    assert_eq!(info.arguments.as_deref(), Some("30;50"));
}

#[test]
fn build_console_task_sleep_without_jitter() {
    let result = build_console_task("ABCD1234", "sleep 10", "operator");
    let msg = result.unwrap_or_else(|e| panic!("sleep task should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.arguments.as_deref(), Some("10;0"));
}

#[test]
fn build_console_task_sleep_rejects_missing_delay() {
    let result = build_console_task("ABCD1234", "sleep", "operator");
    assert!(result.is_err());
}

#[test]
fn build_console_task_dir_uses_explorer_format() {
    let result = build_console_task("ABCD1234", "dir C:\\Temp", "operator");
    let msg = result.unwrap_or_else(|e| panic!("dir task should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(info.sub_command.as_deref(), Some("dir"));
    assert!(info.arguments.as_deref().unwrap_or_default().contains("C:\\Temp"));
}

#[test]
fn build_console_task_cp_requires_two_args() {
    let result = build_console_task("ABCD1234", "cp /tmp/a", "operator");
    assert!(result.is_err());
}

#[test]
fn build_console_task_cp_sends_both_paths() {
    let result = build_console_task("ABCD1234", "cp /tmp/a /tmp/b", "operator");
    let msg = result.unwrap_or_else(|e| panic!("cp task should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.sub_command.as_deref(), Some("cp"));
    assert_eq!(info.arguments.as_deref(), Some("/tmp/a;/tmp/b"));
}

#[test]
fn build_console_task_mv_sends_both_paths() {
    let result = build_console_task("ABCD1234", "mv /tmp/a /tmp/b", "operator");
    let msg = result.unwrap_or_else(|e| panic!("mv task should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.sub_command.as_deref(), Some("move"));
}

#[test]
fn build_console_task_token_list() {
    let result = build_console_task("ABCD1234", "token list", "operator");
    let msg = result.unwrap_or_else(|e| panic!("token task should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandToken).to_string());
    assert_eq!(info.sub_command.as_deref(), Some("list"));
}

#[test]
fn build_console_task_token_requires_subcommand() {
    let result = build_console_task("ABCD1234", "token", "operator");
    assert!(result.is_err());
}

#[test]
fn build_console_task_net_domain() {
    let result = build_console_task("ABCD1234", "net domain", "operator");
    let msg = result.unwrap_or_else(|e| panic!("net task should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandNet).to_string());
    assert_eq!(info.sub_command.as_deref(), Some("domain"));
}

#[test]
fn build_console_task_config_sets_subcommand() {
    let result = build_console_task("ABCD1234", "config sleep-obf true", "operator");
    let msg = result.unwrap_or_else(|e| panic!("config task should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(info.sub_command.as_deref(), Some("sleep-obf"));
    assert_eq!(info.arguments.as_deref(), Some("true"));
}

#[test]
fn build_console_task_pivot_requires_subcommand() {
    let result = build_console_task("ABCD1234", "pivot", "operator");
    assert!(result.is_err());
}

#[test]
fn build_console_task_kerberos_luid() {
    let result = build_console_task("ABCD1234", "kerberos luid", "operator");
    let msg = result.unwrap_or_else(|e| panic!("kerberos task should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandKerberos).to_string());
    assert_eq!(info.sub_command.as_deref(), Some("luid"));
}

#[test]
fn build_console_task_rportfwd_list() {
    let result = build_console_task("ABCD1234", "rportfwd list", "operator");
    let msg = result.unwrap_or_else(|e| panic!("rportfwd task should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandSocket).to_string());
    assert_eq!(info.sub_command.as_deref(), Some("rportfwd list"));
}

#[test]
fn build_console_task_proc_modules() {
    let result = build_console_task("ABCD1234", "proc modules", "operator");
    let msg = result.unwrap_or_else(|e| panic!("proc modules should build: {e}"));
    let (_, info) = unwrap_agent_task(msg);
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandProc).to_string());
    assert_eq!(info.sub_command.as_deref(), Some("modules"));
}

#[test]
fn build_console_task_proc_invalid_subcommand() {
    let result = build_console_task("ABCD1234", "proc bogus", "operator");
    assert!(result.is_err());
}

#[test]
fn build_console_task_help_is_not_dispatched_remotely() {
    let result = build_console_task("ABCD1234", "help", "operator");
    assert!(result.is_err(), "help should not produce a remote task");
}

#[test]
fn build_help_output_full_table_lists_all_commands() {
    let output = build_help_output(None);
    for spec in &CONSOLE_COMMANDS {
        assert!(output.contains(spec.name), "help table should contain `{}`", spec.name);
    }
}

#[test]
fn build_help_output_specific_command_shows_details() {
    let output = build_help_output(Some("token"));
    assert!(output.contains("token"));
    assert!(output.contains("Usage:"));
    assert!(output.contains("Type:"));
    assert!(output.contains("Description:"));
}

#[test]
fn build_help_output_alias_resolves() {
    let output = build_help_output(Some("bof"));
    assert!(output.contains("inline-execute"));
}

#[test]
fn console_commands_all_have_descriptions() {
    for spec in &CONSOLE_COMMANDS {
        assert!(!spec.description.is_empty(), "command `{}` missing description", spec.name);
        assert!(!spec.cmd_type.is_empty(), "command `{}` missing type", spec.name);
        assert!(!spec.usage.is_empty(), "command `{}` missing usage", spec.name);
    }
}

#[test]
fn console_commands_names_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for spec in &CONSOLE_COMMANDS {
        assert!(seen.insert(spec.name), "duplicate command name: {}", spec.name);
    }
}

#[test]
fn completion_includes_new_commands() {
    let all = console_completion_candidates("");
    assert!(all.contains(&"shell"));
    assert!(all.contains(&"sleep"));
    assert!(all.contains(&"token"));
    assert!(all.contains(&"inline-execute"));
    assert!(all.contains(&"net"));
    assert!(all.contains(&"config"));
    assert!(all.contains(&"help"));
}

#[test]
fn completion_pivot_matches_p_prefix() {
    let matches = console_completion_candidates("pi");
    assert!(matches.contains(&"pivot"));
}
