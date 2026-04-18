use super::*;

#[test]
fn agent_filter_matches_multiple_columns() {
    let agent = sample_agent("ABCD1234", "wkstn-1", "operator", true, "10/03/2026 12:00:00");
    assert!(agent_matches_filter(&agent, "wkstn"));
    assert!(agent_matches_filter(&agent, "primary"));
    assert!(agent_matches_filter(&agent, "10.0.0.10"));
    assert!(!agent_matches_filter(&agent, "sqlservr"));
}

#[test]
fn sort_agents_orders_by_last_checkin_descending() {
    let mut agents = vec![
        sample_agent("AAAA0001", "wkstn-1", "alice", false, "10/03/2026 11:00:00"),
        sample_agent("BBBB0002", "wkstn-2", "bob", true, "10/03/2026 12:00:00"),
    ];

    sort_agents(&mut agents, AgentSortColumn::LastCheckin, true);

    assert_eq!(agents[0].name_id, "BBBB0002");
    assert_eq!(agents[1].name_id, "AAAA0001");
}

#[test]
fn sort_button_label_marks_active_column() {
    assert_eq!(
        sort_button_label(Some(AgentSortColumn::Hostname), false, AgentSortColumn::Hostname),
        "Hostname ^"
    );
    assert_eq!(sort_button_label(Some(AgentSortColumn::Hostname), true, AgentSortColumn::Id), "ID");
}

#[test]
fn build_kill_task_uses_exit_command_shape() {
    let OperatorMessage::AgentTask(message) = build_kill_task("ABCD1234", "operator") else {
        panic!("expected agent task");
    };

    assert_eq!(message.info.demon_id, "ABCD1234");
    assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandExit).to_string());
    assert_eq!(message.info.command.as_deref(), Some("kill"));
}

#[test]
fn build_process_list_task_marks_process_manager_origin() {
    let OperatorMessage::AgentTask(message) = build_process_list_task("ABCD1234", "operator")
    else {
        panic!("expected agent task");
    };

    assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandProcList).to_string());
    assert_eq!(message.info.extra.get("FromProcessManager"), Some(&serde_json::Value::Bool(true)));
}

#[test]
fn build_process_injection_task_encodes_shellcode_payload() {
    let OperatorMessage::AgentTask(message) = build_process_injection_task(
        "ABCD1234",
        4444,
        "x64",
        InjectionTechnique::NtCreateThreadEx,
        &[0x90, 0x90, 0xCC],
        "--flag",
        InjectionTargetAction::Inject,
        "operator",
    ) else {
        panic!("expected agent task");
    };

    assert_eq!(
        message.info.command_id,
        u32::from(DemonCommand::CommandInjectShellcode).to_string()
    );
    assert_eq!(
        message.info.extra.get("Technique"),
        Some(&serde_json::Value::String("ntcreatethreadex".to_owned()))
    );
    assert_eq!(
        message.info.extra.get("Binary"),
        Some(&serde_json::Value::String("kJDM".to_owned()))
    );
    assert_eq!(
        message.info.extra.get("Arguments"),
        Some(&serde_json::Value::String("LS1mbGFn".to_owned()))
    );
}

#[test]
fn build_note_task_uses_teamserver_note_shape() {
    let OperatorMessage::AgentTask(message) = build_note_task("ABCD1234", "triaged", "operator")
    else {
        panic!("expected agent task");
    };

    assert_eq!(message.head.user, "operator");
    assert_eq!(message.info.demon_id, "ABCD1234");
    assert_eq!(message.info.command_id, "Teamserver");
    assert_eq!(message.info.command.as_deref(), Some("note"));
    assert_eq!(message.info.arguments.as_deref(), Some("triaged"));
}

#[test]
fn build_chat_message_uses_chat_wire_shape() {
    let Some(OperatorMessage::ChatMessage(message)) =
        build_chat_message(Some("operator"), " hello team ")
    else {
        panic!("expected chat message");
    };

    assert_eq!(message.head.event, EventCode::Chat);
    assert_eq!(
        message.info.fields.get("Message"),
        Some(&serde_json::Value::String("hello team".to_owned()))
    );
}
