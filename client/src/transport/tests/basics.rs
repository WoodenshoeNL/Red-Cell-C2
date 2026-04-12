use super::super::*;

#[test]
fn agent_console_entry_kind_from_command_id_classifies_error_and_output() {
    assert_eq!(AgentConsoleEntryKind::from_command_id("91"), AgentConsoleEntryKind::Error);
    assert_eq!(AgentConsoleEntryKind::from_command_id("100"), AgentConsoleEntryKind::Output);
    assert_eq!(
        AgentConsoleEntryKind::from_command_id("not-a-number"),
        AgentConsoleEntryKind::Output
    );
    assert_eq!(AgentConsoleEntryKind::from_command_id(""), AgentConsoleEntryKind::Output);
    assert_eq!(AgentConsoleEntryKind::from_command_id(" 91 "), AgentConsoleEntryKind::Error);
}

#[test]
fn normalize_server_url_appends_havoc_path() {
    let normalized =
        normalize_server_url("wss://127.0.0.1:40056").expect("url normalization should succeed");

    assert_eq!(normalized, "wss://127.0.0.1:40056/havoc/");
}

#[test]
fn normalize_server_url_rejects_http_scheme() {
    let result = normalize_server_url("http://127.0.0.1:40056");
    assert!(
        matches!(result, Err(TransportError::UnsupportedScheme { ref scheme }) if scheme == "http"),
        "expected UnsupportedScheme for http://, got {result:?}",
    );
}

#[test]
fn normalize_server_url_rejects_https_scheme() {
    let result = normalize_server_url("https://127.0.0.1:40056");
    assert!(
        matches!(result, Err(TransportError::UnsupportedScheme { ref scheme }) if scheme == "https"),
        "expected UnsupportedScheme for https://, got {result:?}",
    );
}

#[test]
fn normalize_server_url_rejects_malformed_url() {
    let result = normalize_server_url("not a url");
    assert!(
        matches!(result, Err(TransportError::InvalidUrl { .. })),
        "expected InvalidUrl for malformed input, got {result:?}",
    );
}

#[test]
fn normalize_server_url_appends_slash_to_havoc_path() {
    let normalized = normalize_server_url("wss://127.0.0.1:40056/havoc")
        .expect("url normalization should succeed");

    assert_eq!(normalized, "wss://127.0.0.1:40056/havoc/");
}

#[test]
fn normalize_server_url_preserves_custom_path() {
    let normalized = normalize_server_url("wss://127.0.0.1:40056/custom/path")
        .expect("url normalization should succeed");

    assert_eq!(normalized, "wss://127.0.0.1:40056/custom/path");
}

#[test]
fn connection_status_label_matches_expected_text() {
    assert_eq!(ConnectionStatus::Connected.label(), "Connected");
    assert_eq!(ConnectionStatus::Disconnected.label(), "Disconnected");
    assert_eq!(ConnectionStatus::Connecting.label(), "Connecting");
    assert_eq!(ConnectionStatus::Retrying("later".to_owned()).label(), "Retrying");
    assert_eq!(ConnectionStatus::Error("failed".to_owned()).label(), "Connection Error");
}

#[test]
fn connection_status_detail_returns_message_only_for_retrying_and_error() {
    let retrying = ConnectionStatus::Retrying("x".to_owned());
    let error = ConnectionStatus::Error("boom".to_owned());

    assert_eq!(retrying.detail(), Some("x"));
    assert_eq!(error.detail(), Some("boom"));
    assert_eq!(ConnectionStatus::Connected.detail(), None);
    assert_eq!(ConnectionStatus::Connecting.detail(), None);
    assert_eq!(ConnectionStatus::Disconnected.detail(), None);
}

#[test]
fn connection_status_placeholders_cover_all_variants() {
    let placeholders = ConnectionStatus::placeholders();

    assert_eq!(placeholders.len(), 5);
    assert!(placeholders.contains(&ConnectionStatus::Disconnected));
    assert!(placeholders.contains(&ConnectionStatus::Connecting));
    assert!(placeholders.contains(&ConnectionStatus::Connected));
    assert!(placeholders.iter().any(|status| matches!(status, ConnectionStatus::Retrying(_))));
    assert!(placeholders.iter().any(|status| matches!(status, ConnectionStatus::Error(_))));
}

#[test]
fn connection_status_color_distinguishes_status_groups() {
    let disconnected = ConnectionStatus::Disconnected.color();
    let connecting = ConnectionStatus::Connecting.color();
    let connected = ConnectionStatus::Connected.color();
    let retrying = ConnectionStatus::Retrying("x".to_owned()).color();
    let error = ConnectionStatus::Error("boom".to_owned()).color();

    assert_ne!(connected, disconnected);
    assert_eq!(connecting, retrying);
    assert_ne!(connected, connecting);
    assert_ne!(error, connected);
    assert_ne!(error, disconnected);
}

#[test]
fn loot_kind_label_matches_expected_text() {
    assert_eq!(LootKind::Credential.label(), "Credential");
    assert_eq!(LootKind::Screenshot.label(), "Screenshot");
    assert_eq!(LootKind::File.label(), "File");
    assert_eq!(LootKind::Other.label(), "Other");
}

#[test]
fn event_kind_label_is_distinct_and_non_empty() {
    let agent = EventKind::Agent.label();
    let operator = EventKind::Operator.label();
    let system = EventKind::System.label();

    assert!(!agent.is_empty());
    assert!(!operator.is_empty());
    assert!(!system.is_empty());
    assert_ne!(agent, operator);
    assert_ne!(agent, system);
    assert_ne!(operator, system);
}
