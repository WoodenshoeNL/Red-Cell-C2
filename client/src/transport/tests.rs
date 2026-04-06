use super::operator_msg::{
    flat_info_string, loot_item_from_flat_info, loot_item_from_response, loot_kind_from_strings,
    normalize_agent_id, sanitize_text,
};
use super::*;
use std::collections::BTreeMap;
use std::sync::Mutex;

use base64::Engine as _;
use futures_util::SinkExt;
use red_cell_common::OperatorInfo;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentInfo as OperatorAgentInfo, AgentPivotsInfo, AgentResponseInfo, AgentUpdateInfo,
    BuildPayloadMessageInfo, BuildPayloadResponseInfo, ChatCode, EventCode, FlatInfo,
    InitConnectionCode, ListenerCode, ListenerErrorInfo, ListenerInfo, ListenerMarkInfo, LoginInfo,
    Message, MessageHead, MessageInfo, NameInfo, SessionCode, TeamserverLogInfo,
};
use red_cell_common::tls::{TlsKeyAlgorithm, generate_self_signed_tls_identity};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message as TungsteniteMessage};

fn head(event: EventCode) -> MessageHead {
    MessageHead {
        event,
        user: "operator".to_owned(),
        timestamp: "10/03/2026 12:00:00".to_owned(),
        one_time: String::new(),
    }
}

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

#[test]
fn app_state_applies_listener_and_agent_updates() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let listener_events = state.apply_operator_message(OperatorMessage::ListenerNew(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("http".to_owned()),
            protocol: Some("Https".to_owned()),
            status: Some("Online".to_owned()),
            ..ListenerInfo::default()
        },
    }));
    let new_events = state.apply_operator_message(OperatorMessage::AgentNew(Box::new(Message {
        head: head(EventCode::Session),
        info: OperatorAgentInfo {
            active: "true".to_owned(),
            background_check: false,
            domain_name: "LAB".to_owned(),
            elevated: true,
            internal_ip: "10.0.0.10".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            first_call_in: "10/03/2026 11:59:00".to_owned(),
            last_call_in: "10/03/2026 12:00:00".to_owned(),
            hostname: "wkstn-1".to_owned(),
            listener: "http".to_owned(),
            magic_value: "deadbeef".to_owned(),
            name_id: "abcd1234".to_owned(),
            os_arch: "x64".to_owned(),
            os_build: "19045".to_owned(),
            os_version: "Windows 11".to_owned(),
            pivots: AgentPivotsInfo::default(),
            port_fwds: Vec::new(),
            process_arch: "x64".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_pid: "1234".to_owned(),
            process_ppid: "1111".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            reason: "manual".to_owned(),
            note: String::new(),
            sleep_delay: serde_json::Value::from(5),
            sleep_jitter: serde_json::Value::from(10),
            kill_date: serde_json::Value::Null,
            working_hours: serde_json::Value::Null,
            socks_cli: Vec::new(),
            socks_cli_mtx: None,
            socks_svr: Vec::new(),
            tasked_once: false,
            username: "operator".to_owned(),
            pivot_parent: String::new(),
        },
    })));
    let update_events = state.apply_operator_message(OperatorMessage::AgentUpdate(Message {
        head: head(EventCode::Session),
        info: AgentUpdateInfo { agent_id: "ABCD1234".to_owned(), marked: "Alive".to_owned() },
    }));

    assert_eq!(state.listeners.len(), 1);
    assert_eq!(state.listeners[0].name, "http");
    assert_eq!(state.agents.len(), 1);
    assert_eq!(state.agents[0].name_id, "ABCD1234");
    assert_eq!(state.agents[0].status, "Alive");
    assert!(state.agents[0].pivot_parent.is_none());
    assert!(state.agents[0].pivot_links.is_empty());
    assert_eq!(
        listener_events,
        vec![AppEvent::ListenerChanged { name: "http".to_owned(), action: "start".to_owned() }]
    );
    assert_eq!(new_events, vec![AppEvent::AgentCheckin("ABCD1234".to_owned())]);
    assert_eq!(update_events, vec![AppEvent::AgentCheckin("ABCD1234".to_owned())]);
}

#[test]
fn agent_reregistered_logs_reregistered_not_new() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // First register the agent via AgentNew.
    state.apply_operator_message(OperatorMessage::AgentNew(Box::new(Message {
        head: head(EventCode::Session),
        info: OperatorAgentInfo {
            active: "true".to_owned(),
            background_check: false,
            domain_name: "LAB".to_owned(),
            elevated: true,
            internal_ip: "10.0.0.10".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            first_call_in: "10/03/2026 11:59:00".to_owned(),
            last_call_in: "10/03/2026 12:00:00".to_owned(),
            hostname: "wkstn-1".to_owned(),
            listener: "http".to_owned(),
            magic_value: "deadbeef".to_owned(),
            name_id: "abcd1234".to_owned(),
            os_arch: "x64".to_owned(),
            os_build: "19045".to_owned(),
            os_version: "Windows 11".to_owned(),
            pivots: AgentPivotsInfo::default(),
            port_fwds: Vec::new(),
            process_arch: "x64".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_pid: "1234".to_owned(),
            process_ppid: "1111".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            reason: "manual".to_owned(),
            note: String::new(),
            sleep_delay: serde_json::Value::from(5),
            sleep_jitter: serde_json::Value::from(10),
            kill_date: serde_json::Value::Null,
            working_hours: serde_json::Value::Null,
            socks_cli: Vec::new(),
            socks_cli_mtx: None,
            socks_svr: Vec::new(),
            tasked_once: false,
            username: "operator".to_owned(),
            pivot_parent: String::new(),
        },
    })));

    // Now re-register via AgentReregistered.
    let events =
        state.apply_operator_message(OperatorMessage::AgentReregistered(Box::new(Message {
            head: head(EventCode::Session),
            info: OperatorAgentInfo {
                active: "true".to_owned(),
                background_check: false,
                domain_name: "LAB".to_owned(),
                elevated: true,
                internal_ip: "10.0.0.10".to_owned(),
                external_ip: "203.0.113.10".to_owned(),
                first_call_in: "10/03/2026 11:59:00".to_owned(),
                last_call_in: "10/03/2026 12:05:00".to_owned(),
                hostname: "wkstn-1".to_owned(),
                listener: "http".to_owned(),
                magic_value: "deadbeef".to_owned(),
                name_id: "abcd1234".to_owned(),
                os_arch: "x64".to_owned(),
                os_build: "19045".to_owned(),
                os_version: "Windows 11".to_owned(),
                pivots: AgentPivotsInfo::default(),
                port_fwds: Vec::new(),
                process_arch: "x64".to_owned(),
                process_name: "explorer.exe".to_owned(),
                process_pid: "1234".to_owned(),
                process_ppid: "1111".to_owned(),
                process_path: "C:\\Windows\\explorer.exe".to_owned(),
                reason: "manual".to_owned(),
                note: String::new(),
                sleep_delay: serde_json::Value::from(5),
                sleep_jitter: serde_json::Value::from(10),
                kill_date: serde_json::Value::Null,
                working_hours: serde_json::Value::Null,
                socks_cli: Vec::new(),
                socks_cli_mtx: None,
                socks_svr: Vec::new(),
                tasked_once: false,
                username: "operator".to_owned(),
                pivot_parent: String::new(),
            },
        })));

    // Must emit AgentCheckin and not duplicate the agent.
    assert_eq!(events, vec![AppEvent::AgentCheckin("ABCD1234".to_owned())]);
    assert_eq!(state.agents.len(), 1, "re-registration must not duplicate the agent");

    // The event log must say "re-registered", not "checked in (new)".
    let rereg_events: Vec<_> =
        state.event_log.entries.iter().filter(|e| e.message.contains("re-registered")).collect();
    assert_eq!(rereg_events.len(), 1, "expected exactly one re-registered event");
    assert!(!rereg_events[0].message.contains("(new)"), "re-registration must not say 'new'");
}

#[test]
fn update_agent_note_updates_matching_agent_and_ignores_unknown_ids() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    state.agents.push(AgentSummary {
        name_id: "ABCD1234".to_owned(),
        status: "Alive".to_owned(),
        domain_name: "LAB".to_owned(),
        username: "operator".to_owned(),
        internal_ip: "10.0.0.10".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        hostname: "wkstn-1".to_owned(),
        process_arch: "x64".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_pid: "1234".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: "19045".to_owned(),
        os_arch: "x64".to_owned(),
        sleep_delay: "5".to_owned(),
        sleep_jitter: "10".to_owned(),
        last_call_in: "10/03/2026 12:00:00".to_owned(),
        note: String::new(),
        pivot_parent: None,
        pivot_links: Vec::new(),
    });

    state.update_agent_note("ABCD1234", "my note".to_owned());
    assert_eq!(state.agents[0].note, "my note");

    state.update_agent_note("ABCD1234", "updated note".to_owned());
    assert_eq!(state.agents[0].note, "updated note");

    let agents_before_unknown_update = state.agents.clone();
    state.update_agent_note("BEEF5678", "ignored".to_owned());
    assert_eq!(state.agents, agents_before_unknown_update);
}

#[test]
fn agent_update_for_unknown_agent_creates_stub_entry() {
    // AgentUpdate arrives before AgentNew (e.g. after reconnect before snapshot).
    // The fallback path must create a minimal stub with a normalised name_id and
    // correct status, and emit an AgentCheckin event.
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    assert!(state.agents.is_empty());

    let events = state.apply_operator_message(OperatorMessage::AgentUpdate(Message {
        head: head(EventCode::Session),
        info: AgentUpdateInfo {
            agent_id: "abcd1234".to_owned(), // lowercase / un-normalised
            marked: "Dead".to_owned(),
        },
    }));

    assert_eq!(state.agents.len(), 1, "stub agent should be created");
    assert_eq!(
        state.agents[0].name_id, "ABCD1234",
        "name_id must be the normalised (uppercase) agent ID"
    );
    assert_eq!(state.agents[0].status, "Dead", "stub status must match the marked field");
    assert_eq!(
        events,
        vec![AppEvent::AgentCheckin("ABCD1234".to_owned())],
        "AgentCheckin event must be emitted for the normalised ID"
    );
}

#[test]
fn agent_remove_drops_matching_agent() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    state.agents.push(AgentSummary {
        name_id: "ABCD1234".to_owned(),
        status: "Alive".to_owned(),
        domain_name: "LAB".to_owned(),
        username: "operator".to_owned(),
        internal_ip: "10.0.0.10".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        hostname: "wkstn-1".to_owned(),
        process_arch: "x64".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_pid: "1234".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: "19045".to_owned(),
        os_arch: "x64".to_owned(),
        sleep_delay: "5".to_owned(),
        sleep_jitter: "10".to_owned(),
        last_call_in: "10/03/2026 12:00:00".to_owned(),
        note: String::new(),
        pivot_parent: None,
        pivot_links: Vec::new(),
    });

    let events = state.apply_operator_message(OperatorMessage::AgentRemove(Message {
        head: head(EventCode::Session),
        info: FlatInfo {
            fields: BTreeMap::from([(
                "AgentID".to_owned(),
                serde_json::Value::String("abcd1234".to_owned()),
            )]),
        },
    }));

    assert!(events.is_empty());
    assert!(state.agents.is_empty());
}

#[test]
fn agent_remove_ignores_unknown_agent_id() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    state.agents.push(AgentSummary {
        name_id: "ABCD1234".to_owned(),
        status: "Alive".to_owned(),
        domain_name: "LAB".to_owned(),
        username: "operator".to_owned(),
        internal_ip: "10.0.0.10".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        hostname: "wkstn-1".to_owned(),
        process_arch: "x64".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_pid: "1234".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: "19045".to_owned(),
        os_arch: "x64".to_owned(),
        sleep_delay: "5".to_owned(),
        sleep_jitter: "10".to_owned(),
        last_call_in: "10/03/2026 12:00:00".to_owned(),
        note: String::new(),
        pivot_parent: None,
        pivot_links: Vec::new(),
    });

    let events = state.apply_operator_message(OperatorMessage::AgentRemove(Message {
        head: head(EventCode::Session),
        info: FlatInfo {
            fields: BTreeMap::from([(
                "AgentID".to_owned(),
                serde_json::Value::String("beef5678".to_owned()),
            )]),
        },
    }));

    assert!(events.is_empty());
    assert_eq!(state.agents.len(), 1);
    assert_eq!(state.agents[0].name_id, "ABCD1234");
}

#[test]
fn operator_snapshot_updates_online_users_and_current_operator_metadata() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    state.operator_info = Some(OperatorInfo {
        username: "operator".to_owned(),
        password_hash: None,
        role: None,
        online: true,
        last_seen: None,
    });

    state.apply_operator_message(OperatorMessage::InitConnectionInfo(Message {
        head: head(EventCode::InitConnection),
        info: FlatInfo {
            fields: BTreeMap::from([(
                "Operators".to_owned(),
                serde_json::json!([
                    {
                        "Username": "operator",
                        "PasswordHash": null,
                        "Role": "Operator",
                        "Online": true,
                        "LastSeen": "2026-03-10T12:00:00Z"
                    },
                    {
                        "Username": "analyst",
                        "PasswordHash": null,
                        "Role": "Analyst",
                        "Online": true,
                        "LastSeen": "2026-03-10T12:00:00Z"
                    },
                    {
                        "Username": "admin",
                        "PasswordHash": null,
                        "Role": "Admin",
                        "Online": false,
                        "LastSeen": null
                    }
                ]),
            )]),
        },
    }));

    assert_eq!(
        state.online_operators.iter().cloned().collect::<Vec<_>>(),
        vec!["analyst".to_owned(), "operator".to_owned()]
    );
    assert_eq!(
        state.operator_info,
        Some(OperatorInfo {
            username: "operator".to_owned(),
            password_hash: None,
            role: Some("Operator".to_owned()),
            online: true,
            last_seen: Some("2026-03-10T12:00:00Z".to_owned()),
        })
    );
}

#[test]
fn agent_new_normalizes_pivot_relationships() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let events = state.apply_operator_message(OperatorMessage::AgentNew(Box::new(Message {
        head: head(EventCode::Session),
        info: OperatorAgentInfo {
            active: "true".to_owned(),
            background_check: false,
            domain_name: "LAB".to_owned(),
            elevated: false,
            internal_ip: "10.0.0.11".to_owned(),
            external_ip: "203.0.113.11".to_owned(),
            first_call_in: "10/03/2026 11:59:00".to_owned(),
            last_call_in: "10/03/2026 12:00:00".to_owned(),
            hostname: "wkstn-2".to_owned(),
            listener: "smb".to_owned(),
            magic_value: "deadbeef".to_owned(),
            name_id: "beef5678".to_owned(),
            os_arch: "x64".to_owned(),
            os_build: "19045".to_owned(),
            os_version: "Windows 11".to_owned(),
            pivots: AgentPivotsInfo {
                parent: Some("abcd1234".to_owned()),
                links: vec!["0xC0FFEE01".to_owned()],
            },
            port_fwds: Vec::new(),
            process_arch: "x64".to_owned(),
            process_name: "cmd.exe".to_owned(),
            process_pid: "2222".to_owned(),
            process_ppid: "1234".to_owned(),
            process_path: "C:\\Windows\\System32\\cmd.exe".to_owned(),
            reason: "pivot".to_owned(),
            note: String::new(),
            sleep_delay: serde_json::Value::from(5),
            sleep_jitter: serde_json::Value::from(10),
            kill_date: serde_json::Value::Null,
            working_hours: serde_json::Value::Null,
            socks_cli: Vec::new(),
            socks_cli_mtx: None,
            socks_svr: Vec::new(),
            tasked_once: false,
            username: "operator".to_owned(),
            pivot_parent: String::new(),
        },
    })));

    assert_eq!(state.agents[0].pivot_parent.as_deref(), Some("ABCD1234"));
    assert_eq!(state.agents[0].pivot_links, vec!["C0FFEE01"]);
    assert_eq!(events, vec![AppEvent::AgentCheckin("BEEF5678".to_owned())]);
}

#[test]
fn agent_response_appends_console_output() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::AgentResponse(Message {
        head: head(EventCode::Session),
        info: AgentResponseInfo {
            demon_id: "abcd1234".to_owned(),
            command_id: "42".to_owned(),
            output: "whoami".to_owned(),
            command_line: Some("shell whoami".to_owned()),
            extra: BTreeMap::new(),
        },
    }));

    let entries = state
        .agent_consoles
        .get("ABCD1234")
        .unwrap_or_else(|| panic!("console output should be stored"));
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].command_id, "42");
    assert_eq!(entries[0].command_line.as_deref(), Some("shell whoami"));
    assert_eq!(entries[0].kind, AgentConsoleEntryKind::Output);
    assert_eq!(entries[0].output, "whoami");
}

#[test]
fn error_response_marks_console_entry_as_error() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::AgentResponse(Message {
        head: head(EventCode::Session),
        info: AgentResponseInfo {
            demon_id: "abcd1234".to_owned(),
            command_id: u32::from(DemonCommand::CommandError).to_string(),
            output: "access denied".to_owned(),
            command_line: Some("token impersonate 4".to_owned()),
            extra: BTreeMap::new(),
        },
    }));

    let entries = state
        .agent_consoles
        .get("ABCD1234")
        .unwrap_or_else(|| panic!("console output should be stored"));
    assert_eq!(entries[0].kind, AgentConsoleEntryKind::Error);
}

#[test]
fn process_list_response_updates_process_panel_state() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let mut extra = BTreeMap::new();
    extra.insert(
        "ProcessListRows".to_owned(),
        serde_json::json!([
            {
                "Name": "explorer.exe",
                "PID": 1234,
                "PPID": 1111,
                "Session": 1,
                "Arch": "x64",
                "User": "LAB\\operator"
            }
        ]),
    );

    state.apply_operator_message(OperatorMessage::AgentResponse(Message {
        head: head(EventCode::Session),
        info: AgentResponseInfo {
            demon_id: "abcd1234".to_owned(),
            command_id: u32::from(DemonCommand::CommandProcList).to_string(),
            output: "process table".to_owned(),
            command_line: Some("ps".to_owned()),
            extra,
        },
    }));

    let processes = state
        .process_lists
        .get("ABCD1234")
        .unwrap_or_else(|| panic!("process list should be stored"));
    assert_eq!(processes.rows.len(), 1);
    assert_eq!(processes.rows[0].pid, 1234);
    assert_eq!(processes.rows[0].name, "explorer.exe");
    assert_eq!(processes.updated_at.as_deref(), Some("10/03/2026 12:00:00"));
}

#[test]
fn loot_notifications_update_loot_panel_state() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let mut extra = BTreeMap::new();
    extra.insert("MiscType".to_owned(), serde_json::Value::String("loot-new".to_owned()));
    extra.insert("LootName".to_owned(), serde_json::Value::String("passwords.txt".to_owned()));
    extra.insert("LootKind".to_owned(), serde_json::Value::String("download".to_owned()));
    extra.insert(
        "CapturedAt".to_owned(),
        serde_json::Value::String("2026-03-10T12:00:00Z".to_owned()),
    );

    state.apply_operator_message(OperatorMessage::AgentResponse(Message {
        head: head(EventCode::Session),
        info: AgentResponseInfo {
            demon_id: "abcd1234".to_owned(),
            command_id: "99".to_owned(),
            output: String::new(),
            command_line: None,
            extra,
        },
    }));

    assert_eq!(state.loot.len(), 1);
    assert_eq!(state.loot[0].name, "passwords.txt");
    assert_eq!(state.loot[0].agent_id, "ABCD1234");
    assert_eq!(state.loot[0].source, "download");
    assert_eq!(state.loot[0].collected_at, "2026-03-10T12:00:00Z");
    assert!(!state.agent_consoles.contains_key("ABCD1234"));
}

#[test]
fn loot_item_from_response_sanitizes_control_chars_and_large_fields() {
    let large_name = "a".repeat(MAX_LOOT_NAME_CHARS + 32);
    let info = AgentResponseInfo {
        demon_id: "abcd1234".to_owned(),
        command_id: "99".to_owned(),
        output: String::new(),
        command_line: None,
        extra: BTreeMap::from([
            ("LootName".to_owned(), serde_json::Value::String(format!("\t{large_name}\n"))),
            ("LootKind".to_owned(), serde_json::Value::String("download\tbatch".to_owned())),
            (
                "FilePath".to_owned(),
                serde_json::Value::String("C:\\Temp\\loot.txt\r\nnext".to_owned()),
            ),
            ("Preview".to_owned(), serde_json::Value::String("alice\tadmin\nhash".to_owned())),
        ]),
    };

    let item = loot_item_from_response(&info).unwrap_or_else(|| panic!("loot item expected"));

    assert_eq!(item.agent_id, "ABCD1234");
    assert_eq!(item.name.len(), MAX_LOOT_NAME_CHARS);
    assert!(item.name.chars().all(|ch| !ch.is_control()));
    assert_eq!(item.source, "download batch");
    assert_eq!(item.file_path.as_deref(), Some("C:\\Temp\\loot.txt  next"));
    assert_eq!(item.preview.as_deref(), Some("alice admin hash"));
}

#[test]
fn loot_item_from_response_uses_transport_agent_id_not_agent_metadata() {
    let info = AgentResponseInfo {
        demon_id: "0xface1234".to_owned(),
        command_id: "99".to_owned(),
        output: String::new(),
        command_line: None,
        extra: BTreeMap::from([
            ("LootName".to_owned(), serde_json::Value::String("hashdump".to_owned())),
            ("AgentID".to_owned(), serde_json::Value::String("deadbeef".to_owned())),
            ("DemonID".to_owned(), serde_json::Value::String("cafebabe".to_owned())),
        ]),
    };

    let item = loot_item_from_response(&info).unwrap_or_else(|| panic!("loot item expected"));
    assert_eq!(item.agent_id, "FACE1234");
}

#[test]
fn credential_events_update_loot_state() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let info = FlatInfo {
        fields: BTreeMap::from([
            ("DemonID".to_owned(), serde_json::Value::String("abcd1234".to_owned())),
            ("Name".to_owned(), serde_json::Value::String("password-hash".to_owned())),
            ("Credential".to_owned(), serde_json::Value::String("alice:hash".to_owned())),
            ("Pattern".to_owned(), serde_json::Value::String("pwdump-hash".to_owned())),
            ("Timestamp".to_owned(), serde_json::Value::String("2026-03-10T12:00:00Z".to_owned())),
        ]),
    };

    state.apply_operator_message(OperatorMessage::CredentialsAdd(Message {
        head: head(EventCode::Credentials),
        info: info.clone(),
    }));
    assert_eq!(state.loot.len(), 1);
    assert_eq!(state.loot[0].kind, LootKind::Credential);
    assert_eq!(state.loot[0].preview.as_deref(), Some("alice:hash"));

    state.apply_operator_message(OperatorMessage::CredentialsRemove(Message {
        head: head(EventCode::Credentials),
        info,
    }));
    assert!(state.loot.is_empty());
}

#[test]
fn host_file_events_capture_screenshot_loot() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    state.apply_operator_message(OperatorMessage::HostFileAdd(Message {
        head: head(EventCode::HostFile),
        info: FlatInfo {
            fields: BTreeMap::from([
                ("DemonID".to_owned(), serde_json::Value::String("abcd1234".to_owned())),
                ("FileName".to_owned(), serde_json::Value::String("desktop.png".to_owned())),
                (
                    "FilePath".to_owned(),
                    serde_json::Value::String("C:/Temp/desktop.png".to_owned()),
                ),
                ("Type".to_owned(), serde_json::Value::String("screenshot".to_owned())),
                ("SizeBytes".to_owned(), serde_json::Value::from(512_u64)),
                (
                    "Timestamp".to_owned(),
                    serde_json::Value::String("2026-03-10T12:00:00Z".to_owned()),
                ),
            ]),
        },
    }));

    assert_eq!(state.loot.len(), 1);
    assert_eq!(state.loot[0].kind, LootKind::Screenshot);
    assert_eq!(state.loot[0].size_bytes, Some(512));
}

#[test]
fn file_explorer_events_update_file_browser_state() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let payload = serde_json::json!({
        "Path": "C:\\Temp",
        "Files": [
            {
                "Type": "dir",
                "Size": "",
                "Modified": "10/03/2026  12:00",
                "Name": "Logs",
                "Permissions": "rwx"
            },
            {
                "Type": "",
                "Size": "1.5 KB",
                "Modified": "10/03/2026  12:01",
                "Name": "report.txt"
            }
        ]
    });
    let mut extra = BTreeMap::new();
    extra.insert("MiscType".to_owned(), serde_json::Value::String("FileExplorer".to_owned()));
    extra.insert(
        "MiscData".to_owned(),
        serde_json::Value::String(
            base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&payload).unwrap_or_default()),
        ),
    );

    state.apply_operator_message(OperatorMessage::AgentResponse(Message {
        head: head(EventCode::Session),
        info: AgentResponseInfo {
            demon_id: "abcd1234".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            output: "Directory listing completed".to_owned(),
            command_line: Some("ls C:\\Temp".to_owned()),
            extra,
        },
    }));

    let browser = state.file_browsers.get("ABCD1234").unwrap_or_else(|| panic!("browser state"));
    assert_eq!(browser.current_dir.as_deref(), Some("C:\\Temp"));
    assert_eq!(browser.directories["C:\\Temp"].len(), 2);
    assert_eq!(browser.directories["C:\\Temp"][0].path, "C:\\Temp\\Logs");
    assert_eq!(browser.directories["C:\\Temp"][1].size_bytes, Some(1536));
}

#[test]
fn download_progress_updates_file_browser_state() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let mut extra = BTreeMap::new();
    extra.insert("MiscType".to_owned(), serde_json::Value::String("download-progress".to_owned()));
    extra.insert("FileID".to_owned(), serde_json::Value::String("0000002A".to_owned()));
    extra.insert(
        "FileName".to_owned(),
        serde_json::Value::String("C:\\Temp\\report.txt".to_owned()),
    );
    extra.insert("CurrentSize".to_owned(), serde_json::Value::String("512".to_owned()));
    extra.insert("ExpectedSize".to_owned(), serde_json::Value::String("1024".to_owned()));
    extra.insert("State".to_owned(), serde_json::Value::String("InProgress".to_owned()));

    state.apply_operator_message(OperatorMessage::AgentResponse(Message {
        head: head(EventCode::Session),
        info: AgentResponseInfo {
            demon_id: "abcd1234".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            output: String::new(),
            command_line: Some("download C:\\Temp\\report.txt".to_owned()),
            extra,
        },
    }));

    let browser = state.file_browsers.get("ABCD1234").unwrap_or_else(|| panic!("browser state"));
    assert_eq!(browser.downloads.len(), 1);
    assert_eq!(browser.downloads["0000002A"].current_size, 512);
}

#[test]
fn completed_download_stores_data_and_removes_in_progress_entry() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // Seed an in-progress download entry.
    let mut progress_extra = BTreeMap::new();
    progress_extra
        .insert("MiscType".to_owned(), serde_json::Value::String("download-progress".to_owned()));
    progress_extra.insert("FileID".to_owned(), serde_json::Value::String("DEADBEEF".to_owned()));
    progress_extra
        .insert("FileName".to_owned(), serde_json::Value::String("C:\\secret.txt".to_owned()));
    progress_extra.insert("CurrentSize".to_owned(), serde_json::Value::String("4".to_owned()));
    progress_extra.insert("ExpectedSize".to_owned(), serde_json::Value::String("4".to_owned()));
    progress_extra.insert("State".to_owned(), serde_json::Value::String("InProgress".to_owned()));
    state.apply_operator_message(OperatorMessage::AgentResponse(Message {
        head: head(EventCode::Session),
        info: AgentResponseInfo {
            demon_id: "abcd1234".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            output: String::new(),
            command_line: Some("download C:\\secret.txt".to_owned()),
            extra: progress_extra,
        },
    }));

    // Now send the completion event (MiscType = "download") with file content.
    let content_bytes = b"data";
    let content_b64 = base64::engine::general_purpose::STANDARD.encode(content_bytes);
    let mut done_extra = BTreeMap::new();
    done_extra.insert("MiscType".to_owned(), serde_json::Value::String("download".to_owned()));
    done_extra.insert("FileID".to_owned(), serde_json::Value::String("DEADBEEF".to_owned()));
    done_extra
        .insert("FileName".to_owned(), serde_json::Value::String("C:\\secret.txt".to_owned()));
    done_extra.insert("MiscData".to_owned(), serde_json::Value::String(content_b64.clone()));
    state.apply_operator_message(OperatorMessage::AgentResponse(Message {
        head: head(EventCode::Session),
        info: AgentResponseInfo {
            demon_id: "abcd1234".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            output: String::new(),
            command_line: None,
            extra: done_extra,
        },
    }));

    let browser = state.file_browsers.get("ABCD1234").expect("browser state should exist");
    // In-progress entry must be removed.
    assert!(browser.downloads.is_empty(), "in-progress entry should be removed on completion");
    // Completed download must be stored.
    let completed = browser.completed_downloads.get("DEADBEEF").expect("completed download");
    assert_eq!(completed.remote_path, "C:\\secret.txt");
    assert_eq!(completed.data, content_bytes);
}

#[test]
fn current_directory_output_updates_file_browser_state() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::AgentResponse(Message {
        head: head(EventCode::Session),
        info: AgentResponseInfo {
            demon_id: "abcd1234".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            output: "Current directory: C:\\Windows".to_owned(),
            command_line: Some("pwd".to_owned()),
            extra: BTreeMap::new(),
        },
    }));

    let browser = state.file_browsers.get("ABCD1234").unwrap_or_else(|| panic!("browser state"));
    assert_eq!(browser.current_dir.as_deref(), Some("C:\\Windows"));
}

#[test]
fn event_log_mark_all_read_clears_unread_count() {
    let mut log = EventLog::new(10);
    log.push(EventKind::System, "a", "t", "msg1");
    log.push(EventKind::Operator, "b", "t", "msg2");
    assert_eq!(log.unread_count, 2);

    log.mark_all_read();
    assert_eq!(log.unread_count, 0);
    assert!(log.entries.iter().all(|e| e.read));
}

#[test]
fn event_log_unread_by_kind_counts_correctly() {
    let mut log = EventLog::new(10);
    log.push(EventKind::Agent, "a", "t", "agent1");
    log.push(EventKind::Agent, "a", "t", "agent2");
    log.push(EventKind::Operator, "b", "t", "op1");
    log.push(EventKind::System, "c", "t", "sys1");

    assert_eq!(log.unread_by_kind(EventKind::Agent), 2);
    assert_eq!(log.unread_by_kind(EventKind::Operator), 1);
    assert_eq!(log.unread_by_kind(EventKind::System), 1);

    // mark one agent entry read
    log.entries.front_mut().unwrap().read = true;
    log.unread_count -= 1;
    assert_eq!(log.unread_by_kind(EventKind::Agent), 1);
}

#[test]
fn event_log_eviction_adjusts_unread_count() {
    let mut log = EventLog::new(2);
    log.push(EventKind::System, "a", "t", "first");
    log.push(EventKind::System, "a", "t", "second");
    assert_eq!(log.unread_count, 2);

    // Evict the oldest unread entry.
    log.push(EventKind::System, "a", "t", "third");
    assert_eq!(log.len(), 2);
    assert_eq!(log.unread_count, 2, "evicted unread should decrement count");
}

#[test]
fn event_log_caps_history_at_max_size() {
    let max = DEFAULT_EVENT_LOG_MAX;
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    for index in 0..(max + 5) {
        state.event_log.push(
            EventKind::System,
            "teamserver",
            index.to_string(),
            format!("message-{index}"),
        );
    }

    assert_eq!(state.event_log.len(), max);
    assert_eq!(state.event_log.entries.front().map(|e| e.message.as_str()), Some("message-5"),);
}

async fn spawn_tls_echo_server(
    identity: &red_cell_common::tls::TlsIdentity,
) -> std::net::SocketAddr {
    let tls_acceptor = identity.tls_acceptor().expect("tls acceptor should build");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
    let address = listener.local_addr().expect("listener should have local address");

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("client should connect");
        let tls_stream = tls_acceptor.accept(stream).await.expect("tls handshake should succeed");
        let mut websocket =
            accept_async(tls_stream).await.expect("websocket upgrade should succeed");
        let payload = serde_json::to_string(&OperatorMessage::TeamserverLog(Message {
            head: MessageHead {
                event: EventCode::Teamserver,
                user: "teamserver".to_owned(),
                timestamp: "10/03/2026 12:00:00".to_owned(),
                one_time: String::new(),
            },
            info: TeamserverLogInfo { text: "hello".to_owned() },
        }))
        .expect("message should serialize");
        websocket
            .send(TungsteniteMessage::Text(payload.into()))
            .await
            .expect("server should send log event");
    });

    address
}

async fn assert_websocket_receives_log(mut socket: ClientWebSocket) {
    let frame =
        socket.next().await.expect("server frame should arrive").expect("frame should be valid");

    match frame {
        WebSocketMessage::Text(payload) => {
            let message: OperatorMessage =
                serde_json::from_str(&payload).expect("payload should deserialize");
            assert!(matches!(message, OperatorMessage::TeamserverLog(_)));
        }
        other => panic!("unexpected websocket frame: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dangerous_skip_verify_accepts_self_signed_certificates() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["127.0.0.1".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");
    let address = spawn_tls_echo_server(&identity).await;

    let sink = Arc::new(std::sync::Mutex::new(None));
    let socket = connect_websocket(
        &format!("wss://{address}/havoc/"),
        &TlsVerification::DangerousSkipVerify,
        &sink,
    )
    .await
    .expect("client should accept self-signed cert with skip-verify");
    assert_websocket_receives_log(socket).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fingerprint_verification_accepts_matching_certificate() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["127.0.0.1".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let cert_der = {
        let mut reader = std::io::BufReader::new(identity.certificate_pem());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("cert PEM should parse");
        certs.into_iter().next().expect("should have one cert")
    };
    let fingerprint = certificate_fingerprint(cert_der.as_ref());
    let address = spawn_tls_echo_server(&identity).await;

    let sink = Arc::new(std::sync::Mutex::new(None));
    let socket = connect_websocket(
        &format!("wss://{address}/havoc/"),
        &TlsVerification::Fingerprint(fingerprint),
        &sink,
    )
    .await
    .expect("client should accept cert with matching fingerprint");
    assert_websocket_receives_log(socket).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fingerprint_verification_rejects_mismatched_certificate() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["127.0.0.1".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");
    let address = spawn_tls_echo_server(&identity).await;

    let wrong_fingerprint = "00".repeat(32);
    let sink = Arc::new(std::sync::Mutex::new(None));
    let result = connect_websocket(
        &format!("wss://{address}/havoc/"),
        &TlsVerification::Fingerprint(wrong_fingerprint),
        &sink,
    )
    .await;

    assert!(result.is_err(), "mismatched fingerprint should be rejected");
    assert!(
        sink.lock().unwrap().is_some(),
        "fingerprint sink should be populated even on mismatch"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_ca_verification_accepts_certificate_signed_by_ca() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["127.0.0.1".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let ca_dir = tempfile::tempdir().expect("tempdir should be created");
    let ca_path = ca_dir.path().join("ca.pem");
    std::fs::write(&ca_path, identity.certificate_pem()).expect("CA cert should be written");

    let address = spawn_tls_echo_server(&identity).await;

    let sink = Arc::new(std::sync::Mutex::new(None));
    let socket = connect_websocket(
        &format!("wss://{address}/havoc/"),
        &TlsVerification::CustomCa(ca_path),
        &sink,
    )
    .await
    .expect("client should accept cert signed by custom CA");
    assert_websocket_receives_log(socket).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ca_verification_rejects_self_signed_certificate() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["127.0.0.1".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");
    let address = spawn_tls_echo_server(&identity).await;

    let sink = Arc::new(std::sync::Mutex::new(None));
    let result = connect_websocket(
        &format!("wss://{address}/havoc/"),
        &TlsVerification::CertificateAuthority,
        &sink,
    )
    .await;

    assert!(result.is_err(), "self-signed cert should be rejected by default CA verification");
    assert!(
        sink.lock().unwrap().is_some(),
        "fingerprint sink should be populated even when CA verification fails"
    );
}

#[test]
fn certificate_fingerprint_produces_hex_sha256() {
    let identity =
        generate_self_signed_tls_identity(&["test.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let cert_der = {
        let mut reader = std::io::BufReader::new(identity.certificate_pem());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("cert PEM should parse");
        certs.into_iter().next().expect("should have one cert")
    };

    let fingerprint = certificate_fingerprint(cert_der.as_ref());
    assert_eq!(fingerprint.len(), 64, "SHA-256 hex should be 64 chars");
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()), "fingerprint should be hex-only");
}

#[test]
fn listener_error_updates_existing_listener_status_and_pushes_chat() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    // Pre-populate a listener so we can verify it is updated in-place.
    state.listeners.push(ListenerSummary {
        name: "http".to_owned(),
        protocol: "Https".to_owned(),
        host: "0.0.0.0".to_owned(),
        port_bind: "443".to_owned(),
        port_conn: "443".to_owned(),
        status: "Online".to_owned(),
    });
    let log_before = state.event_log.len();

    state.apply_operator_message(OperatorMessage::ListenerError(Message {
        head: head(EventCode::Listener),
        info: ListenerErrorInfo { name: "http".to_owned(), error: "port in use".to_owned() },
    }));

    assert_eq!(state.listeners.len(), 1, "upsert should not create a duplicate");
    let listener = &state.listeners[0];
    assert!(
        listener.status.starts_with("Error:"),
        "status should start with 'Error:' but was: {:?}",
        listener.status
    );
    assert!(
        listener.status.contains("port in use"),
        "status should contain the error text but was: {:?}",
        listener.status
    );
    assert_eq!(
        state.event_log.len(),
        log_before + 1,
        "an event notification should have been appended"
    );
    let entry = state.event_log.entries.back().expect("entry should exist");
    assert!(
        entry.message.contains("port in use"),
        "event message should echo the error text but was: {:?}",
        entry.message
    );
}

#[test]
fn listener_error_creates_new_listener_entry_when_none_exists() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    assert!(state.listeners.is_empty());

    state.apply_operator_message(OperatorMessage::ListenerError(Message {
        head: head(EventCode::Listener),
        info: ListenerErrorInfo { name: "smb".to_owned(), error: "bind failed".to_owned() },
    }));

    assert_eq!(state.listeners.len(), 1, "upsert should create a new entry");
    let listener = &state.listeners[0];
    assert_eq!(listener.name, "smb");
    assert!(
        listener.status.starts_with("Error:"),
        "status should start with 'Error:' but was: {:?}",
        listener.status
    );
    assert_eq!(state.event_log.len(), 1, "event notification should be appended");
}

#[test]
fn message_variants_used_by_transport_state_reducer_are_constructible() {
    let _ =
        (InitConnectionCode::Success, ListenerCode::New, SessionCode::AgentNew, ChatCode::Message);
    let _ =
        BuildPayloadMessageInfo { message_type: "info".to_owned(), message: "built".to_owned() };
    let _ = MessageInfo { message: "ok".to_owned() };
    let _ = ListenerErrorInfo { error: "failed".to_owned(), name: "http".to_owned() };
}

#[test]
fn queue_message_forwards_commands_to_sender_task() {
    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, _) = watch::channel(false);
    let transport = ClientTransport { runtime: None, shutdown_tx, outgoing_tx };

    let message = OperatorMessage::Login(Message {
        head: head(EventCode::InitConnection),
        info: LoginInfo { user: "operator".to_owned(), password: "hash".to_owned() },
    });

    transport
        .queue_message(message.clone())
        .unwrap_or_else(|error| panic!("queue_message should succeed: {error}"));

    let queued_message = outgoing_rx
        .try_recv()
        .unwrap_or_else(|error| panic!("queued message should be available: {error}"));
    assert_eq!(queued_message, message);
}

#[test]
fn queue_message_returns_error_when_sender_is_closed() {
    let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
    drop(outgoing_rx);
    let (shutdown_tx, _) = watch::channel(false);
    let transport = ClientTransport { runtime: None, shutdown_tx, outgoing_tx };

    let result = transport.queue_message(OperatorMessage::Login(Message {
        head: head(EventCode::InitConnection),
        info: LoginInfo { user: "operator".to_owned(), password: "hash".to_owned() },
    }));

    assert!(matches!(result, Err(TransportError::OutgoingQueueClosed)));
}

#[test]
fn agent_task_records_activity_in_connected_operators() {
    use red_cell_common::operator::AgentTaskInfo;

    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "alice".to_owned(),
            timestamp: "10/03/2026 12:00:00".to_owned(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "1".to_owned(),
            command_line: "shell whoami".to_owned(),
            demon_id: "abcd1234".to_owned(),
            command_id: "9".to_owned(),
            ..AgentTaskInfo::default()
        },
    }));
    state.apply_operator_message(OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "alice".to_owned(),
            timestamp: "10/03/2026 12:01:00".to_owned(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "2".to_owned(),
            command_line: "ps".to_owned(),
            demon_id: "beef5678".to_owned(),
            command_id: "35".to_owned(),
            ..AgentTaskInfo::default()
        },
    }));

    let alice = state
        .connected_operators
        .get("alice")
        .unwrap_or_else(|| panic!("alice should be in connected_operators"));
    assert_eq!(alice.recent_commands.len(), 2, "both commands should be recorded");
    // Newest first.
    assert_eq!(alice.recent_commands[0].command_line, "ps");
    assert_eq!(alice.recent_commands[0].agent_id, "BEEF5678");
    assert_eq!(alice.recent_commands[1].command_line, "shell whoami");
    assert_eq!(alice.recent_commands[1].agent_id, "ABCD1234");
    assert_eq!(
        alice.last_seen.as_deref(),
        Some("10/03/2026 12:01:00"),
        "last_seen should reflect most recent command timestamp"
    );
}

#[test]
fn agent_task_with_empty_user_is_ignored() {
    use red_cell_common::operator::AgentTaskInfo;

    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: String::new(),
            timestamp: "10/03/2026 12:00:00".to_owned(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "1".to_owned(),
            command_line: "shell whoami".to_owned(),
            demon_id: "abcd1234".to_owned(),
            command_id: "9".to_owned(),
            ..AgentTaskInfo::default()
        },
    }));

    assert!(
        state.connected_operators.is_empty(),
        "empty-username task should not create an operator entry"
    );
}

#[test]
fn activity_feed_capped_at_max_operator_activity() {
    use red_cell_common::operator::AgentTaskInfo;

    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    for i in 0..=(MAX_OPERATOR_ACTIVITY + 5) {
        state.apply_operator_message(OperatorMessage::AgentTask(Message {
            head: MessageHead {
                event: EventCode::Session,
                user: "bob".to_owned(),
                timestamp: format!("ts-{i}"),
                one_time: String::new(),
            },
            info: AgentTaskInfo {
                task_id: i.to_string(),
                command_line: format!("cmd-{i}"),
                demon_id: "abcd1234".to_owned(),
                command_id: "9".to_owned(),
                ..AgentTaskInfo::default()
            },
        }));
    }

    let bob = state
        .connected_operators
        .get("bob")
        .unwrap_or_else(|| panic!("bob should be in connected_operators"));
    assert_eq!(
        bob.recent_commands.len(),
        MAX_OPERATOR_ACTIVITY,
        "activity feed must not exceed MAX_OPERATOR_ACTIVITY entries"
    );
}

#[test]
fn operator_snapshot_populates_connected_operators_with_role_and_presence() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::InitConnectionInfo(Message {
        head: head(EventCode::InitConnection),
        info: FlatInfo {
            fields: BTreeMap::from([(
                "Operators".to_owned(),
                serde_json::json!([
                    {
                        "Username": "operator",
                        "Role": "Operator",
                        "Online": true,
                        "LastSeen": "2026-03-10T12:00:00Z"
                    },
                    {
                        "Username": "admin",
                        "Role": "Admin",
                        "Online": false,
                        "LastSeen": null
                    }
                ]),
            )]),
        },
    }));

    let op = state
        .connected_operators
        .get("operator")
        .unwrap_or_else(|| panic!("operator should be in connected_operators"));
    assert_eq!(op.role.as_deref(), Some("Operator"));
    assert!(op.online);
    assert_eq!(op.last_seen.as_deref(), Some("2026-03-10T12:00:00Z"));

    let admin = state
        .connected_operators
        .get("admin")
        .unwrap_or_else(|| panic!("admin should be in connected_operators"));
    assert_eq!(admin.role.as_deref(), Some("Admin"));
    assert!(!admin.online);
}

#[test]
fn chat_user_presence_updates_connected_operators() {
    use red_cell_common::operator::ChatUserInfo;

    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // Connect alice.
    state.apply_operator_message(OperatorMessage::ChatUserConnected(Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: String::new(),
            timestamp: "10/03/2026 12:00:00".to_owned(),
            one_time: String::new(),
        },
        info: ChatUserInfo { user: "alice".to_owned() },
    }));
    let alice = state
        .connected_operators
        .get("alice")
        .unwrap_or_else(|| panic!("alice should appear on connect"));
    assert!(alice.online);
    assert_eq!(alice.last_seen.as_deref(), Some("10/03/2026 12:00:00"));

    // Disconnect alice.
    state.apply_operator_message(OperatorMessage::ChatUserDisconnected(Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: String::new(),
            timestamp: "10/03/2026 12:05:00".to_owned(),
            one_time: String::new(),
        },
        info: ChatUserInfo { user: "alice".to_owned() },
    }));
    let alice = state
        .connected_operators
        .get("alice")
        .unwrap_or_else(|| panic!("alice should still be present after disconnect"));
    assert!(!alice.online);
    assert_eq!(alice.last_seen.as_deref(), Some("10/03/2026 12:05:00"));
}

#[test]
fn classify_tls_error_expired() {
    let msg = classify_tls_error("invalid peer certificate: certificate expired: ...");
    assert!(msg.contains("expired"), "expected 'expired' in: {msg}");
}

#[test]
fn classify_tls_error_hostname_mismatch() {
    let msg = classify_tls_error("invalid peer certificate: certificate not valid for name ...");
    assert!(msg.contains("hostname mismatch"), "expected 'hostname mismatch' in: {msg}");
}

#[test]
fn classify_tls_error_unknown_issuer() {
    let msg = classify_tls_error("invalid peer certificate: UnknownIssuer");
    assert!(msg.contains("unknown authority"), "expected 'unknown authority' in: {msg}");
}

#[test]
fn classify_tls_error_connection_refused() {
    let msg = classify_tls_error("tcp connect error: Connection refused (os error 111)");
    assert!(msg.contains("Connection refused"), "expected 'Connection refused' in: {msg}");
}

#[test]
fn classify_tls_error_fingerprint_mismatch() {
    let msg = classify_tls_error("certificate fingerprint mismatch: expected abc, got def");
    assert!(msg.contains("fingerprint"), "expected 'fingerprint' in: {msg}");
}

#[test]
fn classify_tls_failure_kind_fingerprint_mismatch() {
    let kind =
        classify_tls_failure_kind("certificate fingerprint mismatch: expected aabb, got ccdd");
    assert_eq!(
        kind,
        crate::login::TlsFailureKind::CertificateChanged { stored_fingerprint: "aabb".to_owned() },
        "fingerprint mismatch must produce CertificateChanged with the stored fingerprint"
    );
}

#[test]
fn classify_tls_failure_kind_unknown_issuer_uppercase() {
    let kind = classify_tls_failure_kind("invalid peer certificate: UnknownIssuer");
    assert_eq!(
        kind,
        crate::login::TlsFailureKind::UnknownServer,
        "UnknownIssuer must map to UnknownServer"
    );
}

#[test]
fn classify_tls_failure_kind_unknown_issuer_lowercase() {
    let kind = classify_tls_failure_kind("unknown issuer");
    assert_eq!(
        kind,
        crate::login::TlsFailureKind::UnknownServer,
        "lowercase 'unknown issuer' must map to UnknownServer"
    );
}

#[test]
fn classify_tls_failure_kind_generic_fallthrough() {
    let kind = classify_tls_failure_kind("invalid peer certificate: certificate expired");
    assert_eq!(
        kind,
        crate::login::TlsFailureKind::CertificateError,
        "unrecognised error string must fall through to CertificateError"
    );
}

#[test]
fn classify_tls_failure_kind_malformed_mismatch_no_expected_token() {
    // No "expected " token — fingerprint extraction must return empty string, not panic.
    let kind = classify_tls_failure_kind("certificate fingerprint mismatch: no tokens here");
    assert_eq!(
        kind,
        crate::login::TlsFailureKind::CertificateChanged { stored_fingerprint: "".to_owned() },
        "malformed mismatch string must produce CertificateChanged with empty fingerprint"
    );
}

#[test]
fn is_tls_cert_error_detects_invalid_cert() {
    assert!(is_tls_cert_error("invalid peer certificate: UnknownIssuer"));
    assert!(is_tls_cert_error("certificate fingerprint mismatch: expected abc, got def"));
    assert!(!is_tls_cert_error("Connection refused (os error 111)"));
    assert!(!is_tls_cert_error("broken pipe"));
}

#[test]
fn build_tls_connector_rejects_empty_pem_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let empty_pem = dir.path().join("empty.pem");
    std::fs::write(&empty_pem, b"").expect("write empty pem");
    let sink = Arc::new(std::sync::Mutex::new(None));

    let result = build_tls_connector(&TlsVerification::CustomCa(empty_pem.clone()), sink);

    assert!(result.is_err(), "empty PEM file must fail");
    let err = result.err().expect("should be Err");
    assert!(matches!(err, TransportError::CustomCaEmpty(_)), "expected CustomCaEmpty, got: {err}");
}

#[test]
fn build_tls_connector_rejects_malformed_pem_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bad_pem = dir.path().join("bad.pem");
    // Write something that looks like PEM structure but has garbage inside.
    std::fs::write(
        &bad_pem,
        b"-----BEGIN CERTIFICATE-----\nNOT-VALID-BASE64!!!@@@\n-----END CERTIFICATE-----\n",
    )
    .expect("write bad pem");
    let sink = Arc::new(std::sync::Mutex::new(None));

    let result = build_tls_connector(&TlsVerification::CustomCa(bad_pem.clone()), sink);

    assert!(result.is_err(), "malformed PEM must fail");
    let err = result.err().expect("should be Err");
    assert!(matches!(err, TransportError::CustomCaParse(_)), "expected CustomCaParse, got: {err}");
}

#[test]
fn build_tls_connector_rejects_nonexistent_ca_file() {
    let sink = Arc::new(std::sync::Mutex::new(None));
    let result = build_tls_connector(
        &TlsVerification::CustomCa(PathBuf::from("/nonexistent/path/ca.pem")),
        sink,
    );

    assert!(result.is_err(), "nonexistent CA file must fail");
    let err = result.err().expect("should be Err");
    assert!(
        matches!(err, TransportError::CustomCaRead { .. }),
        "expected CustomCaRead, got: {err}"
    );
}

#[test]
fn build_tls_connector_succeeds_for_certificate_authority() {
    red_cell_common::tls::install_default_crypto_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let result = build_tls_connector(&TlsVerification::CertificateAuthority, sink);
    assert!(result.is_ok(), "CertificateAuthority mode should build successfully");
}

#[test]
fn build_tls_connector_succeeds_for_fingerprint_mode() {
    red_cell_common::tls::install_default_crypto_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let fingerprint = "ab".repeat(32); // 64 hex chars = SHA-256
    let result = build_tls_connector(&TlsVerification::Fingerprint(fingerprint), sink);
    assert!(result.is_ok(), "Fingerprint mode should build successfully");
}

#[test]
fn build_tls_connector_succeeds_for_dangerous_skip_verify() {
    red_cell_common::tls::install_default_crypto_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let result = build_tls_connector(&TlsVerification::DangerousSkipVerify, sink);
    assert!(result.is_ok(), "DangerousSkipVerify mode should build successfully");
}

#[test]
fn fingerprint_verifier_accepts_matching_cert() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["test.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let cert_der = {
        let mut reader = std::io::BufReader::new(identity.certificate_pem());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("cert PEM should parse");
        certs.into_iter().next().expect("should have one cert")
    };
    let fingerprint = certificate_fingerprint(cert_der.as_ref());

    let provider = aws_lc_rs::default_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let verifier = FingerprintCertificateVerifier {
        expected_fingerprint: fingerprint.clone(),
        provider,
        fingerprint_sink: Arc::clone(&sink),
    };

    let result = verifier.verify_server_cert(
        &cert_der,
        &[],
        &ServerName::try_from("test.local").expect("valid server name"),
        &[],
        UnixTime::now(),
    );
    assert!(result.is_ok(), "matching fingerprint should be accepted");
    assert_eq!(
        sink.lock().unwrap().as_deref(),
        Some(fingerprint.as_str()),
        "fingerprint sink should contain the actual fingerprint"
    );
}

#[test]
fn fingerprint_verifier_rejects_mismatched_cert() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["test.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let cert_der = {
        let mut reader = std::io::BufReader::new(identity.certificate_pem());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("cert PEM should parse");
        certs.into_iter().next().expect("should have one cert")
    };
    let actual_fingerprint = certificate_fingerprint(cert_der.as_ref());
    let wrong_fingerprint = "00".repeat(32);

    let provider = aws_lc_rs::default_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let verifier = FingerprintCertificateVerifier {
        expected_fingerprint: wrong_fingerprint,
        provider,
        fingerprint_sink: Arc::clone(&sink),
    };

    let result = verifier.verify_server_cert(
        &cert_der,
        &[],
        &ServerName::try_from("test.local").expect("valid server name"),
        &[],
        UnixTime::now(),
    );
    assert!(result.is_err(), "mismatched fingerprint should be rejected");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("fingerprint mismatch"),
        "error should mention fingerprint mismatch, got: {err_msg}"
    );
    assert_eq!(
        sink.lock().unwrap().as_deref(),
        Some(actual_fingerprint.as_str()),
        "fingerprint sink should be populated even on mismatch"
    );
}

#[test]
fn fingerprint_verifier_case_insensitive_match() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["test.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let cert_der = {
        let mut reader = std::io::BufReader::new(identity.certificate_pem());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("cert PEM should parse");
        certs.into_iter().next().expect("should have one cert")
    };
    let fingerprint = certificate_fingerprint(cert_der.as_ref());
    // The expected_fingerprint is lowercased in build_tls_connector, so test
    // that the verifier works when given an already-lowercase fingerprint
    // (which is what build_tls_connector passes).
    assert_eq!(fingerprint, fingerprint.to_ascii_lowercase());

    let provider = aws_lc_rs::default_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let verifier = FingerprintCertificateVerifier {
        expected_fingerprint: fingerprint.to_ascii_uppercase(),
        provider,
        fingerprint_sink: Arc::clone(&sink),
    };

    // Upper-case expected vs lower-case actual — should fail because
    // verify_server_cert does a direct string comparison. The case
    // normalisation happens in build_tls_connector, not in the verifier.
    let result = verifier.verify_server_cert(
        &cert_der,
        &[],
        &ServerName::try_from("test.local").expect("valid server name"),
        &[],
        UnixTime::now(),
    );
    assert!(
        result.is_err(),
        "upper-case expected should not match lower-case actual in the verifier itself"
    );
}

#[test]
fn next_reconnect_delay_initial_value_doubles() {
    let delay = next_reconnect_delay(INITIAL_RECONNECT_DELAY);
    assert_eq!(delay, Duration::from_secs(2));
}

#[test]
fn next_reconnect_delay_doubles_each_step() {
    let mut delay = INITIAL_RECONNECT_DELAY;
    let expected_secs = [2, 4, 8, 16];
    for &expected in &expected_secs {
        delay = next_reconnect_delay(delay);
        assert_eq!(delay, Duration::from_secs(expected));
    }
}

#[test]
fn next_reconnect_delay_saturates_at_max() {
    let mut delay = INITIAL_RECONNECT_DELAY;
    // Run enough iterations to well exceed MAX_RECONNECT_DELAY (30s).
    for _ in 0..20 {
        delay = next_reconnect_delay(delay);
    }
    assert_eq!(delay, MAX_RECONNECT_DELAY);
}

#[test]
fn next_reconnect_delay_at_boundary_does_not_exceed_max() {
    // 16s -> 32s would exceed 30s cap.
    let delay = next_reconnect_delay(Duration::from_secs(16));
    assert_eq!(delay, MAX_RECONNECT_DELAY);
}

#[test]
fn next_reconnect_delay_already_at_max_stays_at_max() {
    let delay = next_reconnect_delay(MAX_RECONNECT_DELAY);
    assert_eq!(delay, MAX_RECONNECT_DELAY);
}

#[test]
fn reconnect_delay_resets_after_success() {
    // Simulate several backoff steps then a successful connection reset.
    let mut delay = INITIAL_RECONNECT_DELAY;
    for _ in 0..5 {
        delay = next_reconnect_delay(delay);
    }
    assert!(delay > INITIAL_RECONNECT_DELAY);

    // On success the connection manager resets to INITIAL_RECONNECT_DELAY.
    delay = INITIAL_RECONNECT_DELAY;
    assert_eq!(delay, Duration::from_secs(1));

    // Next failure should start doubling from the initial value again.
    let after_reset = next_reconnect_delay(delay);
    assert_eq!(after_reset, Duration::from_secs(2));
}

#[test]
fn spawn_connects_to_mock_websocket_server() {
    // Bind a TCP listener on a random port using std (so we can get the port
    // synchronously before spawning any async runtime).
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to random port");
    let port = std_listener.local_addr().expect("local addr").port();
    std_listener.set_nonblocking(true).expect("set nonblocking");

    // Run a mock WebSocket server on a background thread with its own runtime.
    let server_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("server runtime");
        rt.block_on(async {
            let listener = TcpListener::from_std(std_listener).expect("convert to tokio listener");
            if let Ok((stream, _)) = listener.accept().await {
                let _ws = accept_async(stream).await.ok();
                // Keep the connection alive long enough for the client to observe
                // Connected status.
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    });

    let app_state: SharedAppState = Arc::new(Mutex::new(AppState::new(String::new())));
    let ctx = egui::Context::default();

    let transport = ClientTransport::spawn(
        format!("ws://127.0.0.1:{port}"),
        app_state.clone(),
        ctx,
        None,
        TlsVerification::DangerousSkipVerify,
    )
    .expect("spawn should succeed");

    // Poll until the connection manager reaches Connected status.
    let mut connected = false;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        let state = lock_app_state(&app_state);
        if matches!(state.connection_status, ConnectionStatus::Connected) {
            connected = true;
            break;
        }
    }

    assert!(connected, "transport should reach Connected status");

    drop(transport);
    server_handle.join().ok();
}

#[test]
fn spawn_reports_error_for_refused_connection() {
    // Bind then immediately drop to obtain a port with nothing listening.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to random port");
        listener.local_addr().expect("local addr").port()
    };

    let app_state: SharedAppState = Arc::new(Mutex::new(AppState::new(String::new())));
    let ctx = egui::Context::default();

    // spawn() itself must not panic even when the target is unreachable.
    let transport = ClientTransport::spawn(
        format!("ws://127.0.0.1:{port}"),
        app_state.clone(),
        ctx,
        None,
        TlsVerification::DangerousSkipVerify,
    )
    .expect("spawn should not panic for unreachable target");

    // The connection manager should eventually transition to Retrying or Error.
    let mut saw_failure_status = false;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        let state = lock_app_state(&app_state);
        match &state.connection_status {
            ConnectionStatus::Retrying(_) | ConnectionStatus::Error(_) => {
                saw_failure_status = true;
                break;
            }
            _ => {}
        }
    }

    assert!(
        saw_failure_status,
        "transport should report Retrying or Error for a refused connection"
    );

    drop(transport);
}

#[test]
fn outgoing_sender_delivers_messages_to_channel() {
    // Build a ClientTransport by hand so we retain a handle to the receiver.
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();
    let transport = ClientTransport { runtime: None, shutdown_tx, outgoing_tx };

    let sender = transport.outgoing_sender();

    // Send a message via the cloned sender.
    let msg = OperatorMessage::Login(Message {
        head: head(EventCode::InitConnection),
        info: LoginInfo { user: "test-user".to_owned(), password: "hunter2".to_owned() },
    });
    sender.send(msg).expect("send via cloned sender should succeed");

    // The message must arrive on the receiver.
    assert!(
        outgoing_rx.try_recv().is_ok(),
        "message sent via outgoing_sender should appear on the receiver"
    );

    // The original transport sender should still work after cloning.
    let msg2 = OperatorMessage::Login(Message {
        head: head(EventCode::InitConnection),
        info: LoginInfo { user: "another-user".to_owned(), password: "pass".to_owned() },
    });
    transport.queue_message(msg2).expect("queue_message via original sender should succeed");
    assert!(outgoing_rx.try_recv().is_ok(), "message sent via queue_message should also arrive");
}

#[test]
fn init_connection_success_sets_connected_and_populates_operator() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    assert!(matches!(state.connection_status, ConnectionStatus::Disconnected));
    assert!(state.operator_info.is_none());
    assert!(state.online_operators.is_empty());

    let events = state.apply_operator_message(OperatorMessage::InitConnectionSuccess(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: "alice".to_owned(),
            timestamp: "18/03/2026 09:30:00".to_owned(),
            one_time: String::new(),
        },
        info: MessageInfo { message: "Authentication successful".to_owned() },
    }));

    assert!(
        matches!(state.connection_status, ConnectionStatus::Connected),
        "connection_status should be Connected after success"
    );

    let info = state.operator_info.as_ref().expect("operator_info should be populated");
    assert_eq!(info.username, "alice");
    assert!(info.online);
    assert_eq!(info.last_seen.as_deref(), Some("18/03/2026 09:30:00"));

    assert!(state.online_operators.contains("alice"), "alice should be in online_operators");

    // A system event should have been logged.
    assert_eq!(state.event_log.len(), 1);

    // apply_operator_message returns no AppEvent variants for this message type.
    assert!(events.is_empty());
}

#[test]
fn init_connection_success_with_empty_user_skips_operator_info() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::InitConnectionSuccess(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: String::new(),
            timestamp: "18/03/2026 09:30:00".to_owned(),
            one_time: String::new(),
        },
        info: MessageInfo { message: "Connected".to_owned() },
    }));

    assert!(matches!(state.connection_status, ConnectionStatus::Connected));
    assert!(state.operator_info.is_none(), "operator_info should remain None when user is empty");
    assert!(state.online_operators.is_empty());
    assert_eq!(state.event_log.len(), 1);
}

#[test]
fn init_connection_error_sets_error_status_and_logs_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let events = state.apply_operator_message(OperatorMessage::InitConnectionError(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: String::new(),
            timestamp: "18/03/2026 09:31:00".to_owned(),
            one_time: String::new(),
        },
        info: MessageInfo { message: "Invalid credentials".to_owned() },
    }));

    assert!(
        matches!(&state.connection_status, ConnectionStatus::Error(msg) if msg == "Invalid credentials"),
        "connection_status should be Error with the message"
    );

    assert_eq!(
        state.last_auth_error.as_deref(),
        Some("Invalid credentials"),
        "last_auth_error should capture the error message"
    );

    // operator_info should remain None after an error.
    assert!(state.operator_info.is_none());

    // A system event should be logged.
    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.front().expect("should have one event entry");
    assert_eq!(entry.message, "Invalid credentials");

    assert!(events.is_empty());
}

#[test]
fn listener_edit_upserts_and_emits_edit_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // Add an initial listener via ListenerNew.
    state.apply_operator_message(OperatorMessage::ListenerNew(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("http".to_owned()),
            protocol: Some("Https".to_owned()),
            status: Some("Online".to_owned()),
            ..ListenerInfo::default()
        },
    }));
    assert_eq!(state.listeners.len(), 1);
    assert_eq!(state.listeners[0].protocol, "Https");

    // Edit the listener — should update in place, not add a duplicate.
    let events = state.apply_operator_message(OperatorMessage::ListenerEdit(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("http".to_owned()),
            protocol: Some("Http".to_owned()),
            status: Some("Offline".to_owned()),
            ..ListenerInfo::default()
        },
    }));

    assert_eq!(state.listeners.len(), 1, "should upsert, not duplicate");
    assert_eq!(state.listeners[0].protocol, "Http");
    assert_eq!(state.listeners[0].status, "Offline");

    assert_eq!(events.len(), 1);
    assert!(
        matches!(&events[0], AppEvent::ListenerChanged { name, action } if name == "http" && action == "edit"),
        "expected ListenerChanged edit event, got {events:?}",
    );
}

#[test]
fn listener_edit_creates_new_entry_when_absent() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let events = state.apply_operator_message(OperatorMessage::ListenerEdit(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("smb".to_owned()),
            protocol: Some("SMB".to_owned()),
            status: Some("Online".to_owned()),
            ..ListenerInfo::default()
        },
    }));

    assert_eq!(state.listeners.len(), 1);
    assert_eq!(state.listeners[0].name, "smb");
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], AppEvent::ListenerChanged { action, .. } if action == "edit"),);
}

#[test]
fn listener_remove_deletes_listener_and_emits_stop_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // Add two listeners.
    state.apply_operator_message(OperatorMessage::ListenerNew(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("http".to_owned()),
            protocol: Some("Https".to_owned()),
            status: Some("Online".to_owned()),
            ..ListenerInfo::default()
        },
    }));
    state.apply_operator_message(OperatorMessage::ListenerNew(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("smb".to_owned()),
            protocol: Some("SMB".to_owned()),
            status: Some("Online".to_owned()),
            ..ListenerInfo::default()
        },
    }));
    assert_eq!(state.listeners.len(), 2);

    // Remove the first one.
    let events = state.apply_operator_message(OperatorMessage::ListenerRemove(Message {
        head: head(EventCode::Listener),
        info: NameInfo { name: "http".to_owned() },
    }));

    assert_eq!(state.listeners.len(), 1);
    assert_eq!(state.listeners[0].name, "smb", "only 'smb' should remain");

    assert_eq!(events.len(), 1);
    assert!(
        matches!(&events[0], AppEvent::ListenerChanged { name, action } if name == "http" && action == "stop"),
        "expected ListenerChanged stop event, got {events:?}",
    );
}

#[test]
fn listener_remove_is_noop_for_unknown_listener() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let events = state.apply_operator_message(OperatorMessage::ListenerRemove(Message {
        head: head(EventCode::Listener),
        info: NameInfo { name: "nonexistent".to_owned() },
    }));

    assert!(state.listeners.is_empty());
    // Event is still emitted even if no listener was present.
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], AppEvent::ListenerChanged { action, .. } if action == "stop"),);
}

#[test]
fn listener_mark_updates_status_of_existing_listener() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // Add a listener.
    state.apply_operator_message(OperatorMessage::ListenerNew(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("http".to_owned()),
            protocol: Some("Https".to_owned()),
            status: Some("Online".to_owned()),
            ..ListenerInfo::default()
        },
    }));
    assert_eq!(state.listeners[0].status, "Online");

    // Mark it as offline.
    let events = state.apply_operator_message(OperatorMessage::ListenerMark(Message {
        head: head(EventCode::Listener),
        info: ListenerMarkInfo { name: "http".to_owned(), mark: "Offline".to_owned() },
    }));

    assert_eq!(state.listeners.len(), 1);
    assert_eq!(state.listeners[0].status, "Offline");
    assert_eq!(state.listeners[0].protocol, "Https", "protocol should be unchanged");

    // ListenerMark does not emit events.
    assert!(events.is_empty());
}

#[test]
fn listener_mark_creates_placeholder_when_listener_absent() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::ListenerMark(Message {
        head: head(EventCode::Listener),
        info: ListenerMarkInfo { name: "unknown-listener".to_owned(), mark: "Offline".to_owned() },
    }));

    assert_eq!(state.listeners.len(), 1);
    assert_eq!(state.listeners[0].name, "unknown-listener");
    assert_eq!(state.listeners[0].status, "Offline");
    assert_eq!(state.listeners[0].protocol, "unknown");
}

#[test]
fn chat_message_pushes_operator_event_with_user_and_message() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let mut fields = BTreeMap::new();
    fields.insert("User".to_owned(), Value::String("alice".to_owned()));
    fields.insert("Message".to_owned(), Value::String("hello team".to_owned()));

    state.apply_operator_message(OperatorMessage::ChatMessage(Message {
        head: head(EventCode::Chat),
        info: FlatInfo { fields },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::Operator);
    assert_eq!(entry.author, "alice");
    assert_eq!(entry.message, "hello team");
}

#[test]
fn chat_message_uses_fallback_when_fields_missing() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::ChatMessage(Message {
        head: head(EventCode::Chat),
        info: FlatInfo { fields: BTreeMap::new() },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::Operator);
    assert_eq!(entry.author, "system");
    assert_eq!(entry.message, "Received event");
}

#[test]
fn chat_message_extracts_alternate_keys_name_and_text() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let mut fields = BTreeMap::new();
    fields.insert("Name".to_owned(), Value::String("bob".to_owned()));
    fields.insert("Text".to_owned(), Value::String("hi there".to_owned()));

    state.apply_operator_message(OperatorMessage::ChatMessage(Message {
        head: head(EventCode::Chat),
        info: FlatInfo { fields },
    }));

    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.author, "bob");
    assert_eq!(entry.message, "hi there");
}

#[test]
fn chat_listener_pushes_agent_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let mut fields = BTreeMap::new();
    fields.insert("User".to_owned(), Value::String("listener1".to_owned()));
    fields.insert("Message".to_owned(), Value::String("listener event".to_owned()));

    state.apply_operator_message(OperatorMessage::ChatListener(Message {
        head: head(EventCode::Chat),
        info: FlatInfo { fields },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::Agent);
    assert_eq!(entry.author, "listener1");
    assert_eq!(entry.message, "listener event");
}

#[test]
fn chat_agent_pushes_agent_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let mut fields = BTreeMap::new();
    fields.insert("DemonID".to_owned(), Value::String("deadbeef".to_owned()));
    fields.insert("Output".to_owned(), Value::String("agent output".to_owned()));

    state.apply_operator_message(OperatorMessage::ChatAgent(Message {
        head: head(EventCode::Chat),
        info: FlatInfo { fields },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::Agent);
    assert_eq!(entry.author, "deadbeef");
    assert_eq!(entry.message, "agent output");
}

#[test]
fn teamserver_log_pushes_system_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::TeamserverLog(Message {
        head: head(EventCode::Teamserver),
        info: TeamserverLogInfo { text: "server started".to_owned() },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::System);
    assert_eq!(entry.author, "teamserver");
    assert_eq!(entry.message, "server started");
}

#[test]
fn build_payload_message_pushes_formatted_system_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::BuildPayloadMessage(Message {
        head: head(EventCode::Teamserver),
        info: BuildPayloadMessageInfo {
            message_type: "Info".to_owned(),
            message: "compiling agent".to_owned(),
        },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::System);
    assert_eq!(entry.author, "builder");
    assert_eq!(entry.message, "Info: compiling agent");
}

#[test]
fn build_payload_response_pushes_built_filename_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::BuildPayloadResponse(Message {
        head: head(EventCode::Teamserver),
        info: BuildPayloadResponseInfo {
            payload_array: String::new(),
            format: "exe".to_owned(),
            file_name: "demon.exe".to_owned(),
        },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::System);
    assert_eq!(entry.author, "builder");
    assert_eq!(entry.message, "Built demon.exe");
}

#[test]
fn build_payload_message_stores_console_entry() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::BuildPayloadMessage(Message {
        head: head(EventCode::Teamserver),
        info: BuildPayloadMessageInfo {
            message_type: "Info".to_owned(),
            message: "compiling core dll".to_owned(),
        },
    }));

    assert_eq!(state.build_console_messages.len(), 1);
    assert_eq!(state.build_console_messages[0].message_type, "Info");
    assert_eq!(state.build_console_messages[0].message, "compiling core dll");
}

#[test]
fn build_payload_response_stores_decoded_payload() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let payload_bytes = b"binary payload data";
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload_bytes);

    state.apply_operator_message(OperatorMessage::BuildPayloadResponse(Message {
        head: head(EventCode::Teamserver),
        info: BuildPayloadResponseInfo {
            payload_array: encoded,
            format: "Windows Exe".to_owned(),
            file_name: "demon.exe".to_owned(),
        },
    }));

    let result = state.last_payload_response.as_ref().unwrap();
    assert_eq!(result.payload_bytes, payload_bytes);
    assert_eq!(result.format, "Windows Exe");
    assert_eq!(result.file_name, "demon.exe");
}

#[test]
fn build_payload_response_invalid_base64_does_not_store() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::BuildPayloadResponse(Message {
        head: head(EventCode::Teamserver),
        info: BuildPayloadResponseInfo {
            payload_array: "!!!not-valid-base64!!!".to_owned(),
            format: "exe".to_owned(),
            file_name: "demon.exe".to_owned(),
        },
    }));

    // Invalid base64 should not produce a stored result.
    assert!(state.last_payload_response.is_none());
    // But the event log entry should still be pushed.
    assert_eq!(state.event_log.len(), 1);
}

#[test]
fn build_console_messages_accumulate() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    for msg in &["Starting build", "Compiling source", "Finished compiling"] {
        state.apply_operator_message(OperatorMessage::BuildPayloadMessage(Message {
            head: head(EventCode::Teamserver),
            info: BuildPayloadMessageInfo {
                message_type: "Info".to_owned(),
                message: (*msg).to_owned(),
            },
        }));
    }

    assert_eq!(state.build_console_messages.len(), 3);
    assert_eq!(state.build_console_messages[2].message, "Finished compiling");
}

// ── EventLog tests ──────────────────────────────────────────────

#[test]
fn event_log_new_is_empty() {
    let log = EventLog::new(5);
    assert_eq!(log.len(), 0);
    assert_eq!(log.unread_count, 0);
    assert!(log.entries.is_empty());
}

#[test]
fn event_log_push_increments_len_and_unread() {
    let mut log = EventLog::new(3);
    log.push(EventKind::Agent, "alice", "t1", "msg1");
    assert_eq!(log.len(), 1);
    assert_eq!(log.unread_count, 1);

    log.push(EventKind::System, "server", "t2", "msg2");
    assert_eq!(log.len(), 2);
    assert_eq!(log.unread_count, 2);
}

#[test]
fn event_log_push_evicts_oldest_when_at_capacity() {
    let mut log = EventLog::new(3);
    log.push(EventKind::Agent, "a", "t1", "first");
    log.push(EventKind::System, "b", "t2", "second");
    log.push(EventKind::Operator, "c", "t3", "third");
    assert_eq!(log.len(), 3);
    assert_eq!(log.unread_count, 3);

    // 4th push should evict "first"
    log.push(EventKind::Agent, "d", "t4", "fourth");
    assert_eq!(log.len(), 3);
    // evicted entry was unread, so unread_count = 3 - 1 + 1 = 3
    assert_eq!(log.unread_count, 3);

    // Verify "first" is gone and "second" is now the oldest
    assert_eq!(log.entries.front().unwrap().message, "second");
    assert_eq!(log.entries.back().unwrap().message, "fourth");
}

#[test]
fn event_log_eviction_of_read_entry_does_not_decrement_unread() {
    let mut log = EventLog::new(2);
    log.push(EventKind::Agent, "a", "t1", "old");
    log.mark_all_read();
    assert_eq!(log.unread_count, 0);

    log.push(EventKind::Agent, "b", "t2", "new");
    assert_eq!(log.unread_count, 1);
    assert_eq!(log.len(), 2);

    // Evicts "old" which is read — unread_count should not be decremented
    log.push(EventKind::Agent, "c", "t3", "newest");
    assert_eq!(log.len(), 2);
    // 1 (prior unread) + 1 (new push) - 0 (evicted was read) = 2
    assert_eq!(log.unread_count, 2);
}

#[test]
fn event_log_eviction_of_unread_entry_decrements_unread() {
    let mut log = EventLog::new(2);
    log.push(EventKind::Agent, "a", "t1", "old-unread");
    log.push(EventKind::System, "b", "t2", "newer");
    assert_eq!(log.unread_count, 2);

    // Evicts "old-unread" which is unread
    log.push(EventKind::Operator, "c", "t3", "newest");
    assert_eq!(log.len(), 2);
    // 2 - 1 (evicted unread) + 1 (new push) = 2
    assert_eq!(log.unread_count, 2);
}

#[test]
fn event_log_mark_all_read_zeroes_unread_and_flags_entries() {
    let mut log = EventLog::new(5);
    log.push(EventKind::Agent, "a", "t1", "m1");
    log.push(EventKind::System, "b", "t2", "m2");
    log.push(EventKind::Operator, "c", "t3", "m3");
    assert_eq!(log.unread_count, 3);

    log.mark_all_read();
    assert_eq!(log.unread_count, 0);
    for entry in &log.entries {
        assert!(entry.read, "entry {:?} should be marked read", entry.message);
    }
}

#[test]
fn event_log_mark_all_read_is_idempotent() {
    let mut log = EventLog::new(5);
    log.push(EventKind::Agent, "a", "t1", "m1");
    log.mark_all_read();
    log.mark_all_read();
    assert_eq!(log.unread_count, 0);
}

#[test]
fn event_log_unread_by_kind_filters_correctly() {
    let mut log = EventLog::new(10);
    log.push(EventKind::Agent, "a", "t1", "agent1");
    log.push(EventKind::Agent, "a", "t2", "agent2");
    log.push(EventKind::System, "s", "t3", "sys1");
    log.push(EventKind::Operator, "o", "t4", "op1");
    log.push(EventKind::System, "s", "t5", "sys2");

    assert_eq!(log.unread_by_kind(EventKind::Agent), 2);
    assert_eq!(log.unread_by_kind(EventKind::System), 2);
    assert_eq!(log.unread_by_kind(EventKind::Operator), 1);
}

#[test]
fn event_log_unread_by_kind_excludes_read_entries() {
    let mut log = EventLog::new(10);
    log.push(EventKind::Agent, "a", "t1", "agent1");
    log.push(EventKind::System, "s", "t2", "sys1");
    log.mark_all_read();
    log.push(EventKind::Agent, "a", "t3", "agent2");

    assert_eq!(log.unread_by_kind(EventKind::Agent), 1);
    assert_eq!(log.unread_by_kind(EventKind::System), 0);
}

#[test]
fn event_log_unread_by_kind_returns_zero_when_empty() {
    let log = EventLog::new(5);
    assert_eq!(log.unread_by_kind(EventKind::Agent), 0);
    assert_eq!(log.unread_by_kind(EventKind::System), 0);
    assert_eq!(log.unread_by_kind(EventKind::Operator), 0);
}

#[test]
fn event_log_len_reflects_entries_after_eviction() {
    let mut log = EventLog::new(2);
    log.push(EventKind::Agent, "a", "t1", "m1");
    log.push(EventKind::Agent, "a", "t2", "m2");
    assert_eq!(log.len(), 2);

    log.push(EventKind::Agent, "a", "t3", "m3");
    assert_eq!(log.len(), 2);
}

#[test]
fn event_log_max_size_one() {
    let mut log = EventLog::new(1);
    log.push(EventKind::Agent, "a", "t1", "first");
    assert_eq!(log.len(), 1);
    assert_eq!(log.unread_count, 1);

    log.push(EventKind::System, "b", "t2", "second");
    assert_eq!(log.len(), 1);
    assert_eq!(log.unread_count, 1);
    assert_eq!(log.entries.front().unwrap().message, "second");
}

#[test]
fn event_log_push_stores_correct_fields() {
    let mut log = EventLog::new(5);
    log.push(EventKind::Operator, "alice", "2026-03-18T12:00:00", "hello world");

    let entry = log.entries.front().unwrap();
    assert_eq!(entry.kind, EventKind::Operator);
    assert_eq!(entry.author, "alice");
    assert_eq!(entry.sent_at, "2026-03-18T12:00:00");
    assert_eq!(entry.message, "hello world");
    assert!(!entry.read);
}

#[test]
fn event_log_full_scenario_push_evict_read_unread_by_kind() {
    // Integration-style test combining all operations
    let mut log = EventLog::new(3);

    // Fill to capacity
    log.push(EventKind::Agent, "a", "t1", "a1");
    log.push(EventKind::System, "s", "t2", "s1");
    log.push(EventKind::Agent, "a", "t3", "a2");
    assert_eq!(log.len(), 3);
    assert_eq!(log.unread_count, 3);
    assert_eq!(log.unread_by_kind(EventKind::Agent), 2);
    assert_eq!(log.unread_by_kind(EventKind::System), 1);

    // Push a 4th — evicts "a1" (unread Agent)
    log.push(EventKind::Operator, "o", "t4", "o1");
    assert_eq!(log.len(), 3);
    assert_eq!(log.unread_count, 3);
    assert_eq!(log.unread_by_kind(EventKind::Agent), 1);
    assert_eq!(log.unread_by_kind(EventKind::System), 1);
    assert_eq!(log.unread_by_kind(EventKind::Operator), 1);

    // Mark all read
    log.mark_all_read();
    assert_eq!(log.unread_count, 0);
    assert_eq!(log.unread_by_kind(EventKind::Agent), 0);

    // Push after mark_all_read — only new entry is unread
    log.push(EventKind::System, "s", "t5", "s2");
    assert_eq!(log.len(), 3);
    // Evicted "s1" which was read — no unread decrement
    assert_eq!(log.unread_count, 1);
    assert_eq!(log.unread_by_kind(EventKind::System), 1);
}

// ── normalize_agent_id ──────────────────────────────────────────

#[test]
fn normalize_agent_id_strips_0x_prefix_and_zero_pads() {
    assert_eq!(normalize_agent_id("0xAABB0001"), "AABB0001");
}

#[test]
fn normalize_agent_id_lowcase_hex_without_prefix() {
    assert_eq!(normalize_agent_id("aabb0001"), "AABB0001");
}

#[test]
fn normalize_agent_id_trims_whitespace_and_prefix() {
    assert_eq!(normalize_agent_id("  0xAA  "), "000000AA");
}

#[test]
fn normalize_agent_id_short_hex_is_zero_padded() {
    assert_eq!(normalize_agent_id("FF"), "000000FF");
}

#[test]
fn normalize_agent_id_empty_string_falls_back_to_uppercase() {
    // empty after trim → from_str_radix("", 16) fails → fallback
    assert_eq!(normalize_agent_id(""), "");
}

#[test]
fn normalize_agent_id_non_hex_falls_back_to_uppercase() {
    assert_eq!(normalize_agent_id("not-hex"), "NOT-HEX");
}

#[test]
fn normalize_agent_id_max_u32() {
    assert_eq!(normalize_agent_id("FFFFFFFF"), "FFFFFFFF");
}

#[test]
fn normalize_agent_id_overflow_u32_falls_back_to_uppercase() {
    // 1_0000_0000 hex > u32::MAX → parse fails → fallback
    assert_eq!(normalize_agent_id("100000000"), "100000000");
}

// ── sanitize_text ───────────────────────────────────────────────

#[test]
fn sanitize_text_empty_returns_connected() {
    assert_eq!(sanitize_text(""), "Connected");
}

#[test]
fn sanitize_text_whitespace_only_returns_connected() {
    assert_eq!(sanitize_text("   \t\n  "), "Connected");
}

#[test]
fn sanitize_text_normal_text_unchanged() {
    assert_eq!(sanitize_text("hello world"), "hello world");
}

#[test]
fn sanitize_text_trims_leading_and_trailing_whitespace() {
    assert_eq!(sanitize_text("  hello  "), "hello");
}

// ── CredentialsAdd / CredentialsEdit ──────────────────────────────

/// Helper: build a `FlatInfo` from key-value pairs.
fn flat_info(pairs: &[(&str, &str)]) -> FlatInfo {
    FlatInfo {
        fields: pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), Value::String((*v).to_owned())))
            .collect(),
    }
}

#[test]
fn credentials_add_inserts_loot_and_emits_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let events = state.apply_operator_message(OperatorMessage::CredentialsAdd(Message {
        head: head(EventCode::Credentials),
        info: flat_info(&[
            ("Name", "admin"),
            ("DemonID", "aabb1122"),
            ("Credential", "P@ssw0rd"),
            ("CapturedAt", "2026-03-19 10:00:00"),
        ]),
    }));

    assert_eq!(state.loot.len(), 1, "loot list should contain one item");
    let item = &state.loot[0];
    assert_eq!(item.kind, LootKind::Credential);
    assert_eq!(item.name, "admin");
    assert_eq!(item.agent_id, "AABB1122");
    assert_eq!(item.preview.as_deref(), Some("P@ssw0rd"));

    assert_eq!(events.len(), 1);
    assert!(
        matches!(&events[0], AppEvent::LootCaptured(l) if l.name == "admin"),
        "expected LootCaptured event, got {events:?}"
    );
}

#[test]
fn credentials_edit_upserts_existing_loot() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // Insert initial credential.
    state.apply_operator_message(OperatorMessage::CredentialsAdd(Message {
        head: head(EventCode::Credentials),
        info: flat_info(&[
            ("Name", "admin"),
            ("DemonID", "aabb1122"),
            ("Credential", "old"),
            ("CapturedAt", "2026-03-19 10:00:00"),
        ]),
    }));

    // Edit it — same name, agent, timestamp → should upsert.
    state.apply_operator_message(OperatorMessage::CredentialsEdit(Message {
        head: head(EventCode::Credentials),
        info: flat_info(&[
            ("Name", "admin"),
            ("DemonID", "aabb1122"),
            ("Credential", "new-password"),
            ("CapturedAt", "2026-03-19 10:00:00"),
        ]),
    }));

    assert_eq!(state.loot.len(), 1, "upsert should not duplicate loot");
    assert_eq!(state.loot[0].preview.as_deref(), Some("new-password"));
}

#[test]
fn credentials_add_with_missing_name_produces_no_loot() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // FlatInfo without Name/FileName/LootName → loot_item_from_flat_info returns None.
    let events = state.apply_operator_message(OperatorMessage::CredentialsAdd(Message {
        head: head(EventCode::Credentials),
        info: flat_info(&[("DemonID", "aabb1122")]),
    }));

    assert!(state.loot.is_empty(), "no loot should be added when name is missing");
    assert!(events.is_empty(), "no events should be emitted when name is missing");
}

// ── CredentialsRemove ─────────────────────────────────────────────

#[test]
fn credentials_remove_deletes_matching_loot() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // Add two credentials.
    state.apply_operator_message(OperatorMessage::CredentialsAdd(Message {
        head: head(EventCode::Credentials),
        info: flat_info(&[("Name", "admin"), ("DemonID", "aabb1122"), ("CapturedAt", "t1")]),
    }));
    state.apply_operator_message(OperatorMessage::CredentialsAdd(Message {
        head: head(EventCode::Credentials),
        info: flat_info(&[("Name", "guest"), ("DemonID", "aabb1122"), ("CapturedAt", "t2")]),
    }));
    assert_eq!(state.loot.len(), 2);

    // Remove the "admin" credential.
    state.apply_operator_message(OperatorMessage::CredentialsRemove(Message {
        head: head(EventCode::Credentials),
        info: flat_info(&[("Name", "admin"), ("DemonID", "aabb1122")]),
    }));

    assert_eq!(state.loot.len(), 1, "one credential should remain");
    assert_eq!(state.loot[0].name, "guest");
}

#[test]
fn credentials_remove_with_missing_name_is_noop() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::CredentialsAdd(Message {
        head: head(EventCode::Credentials),
        info: flat_info(&[("Name", "admin"), ("DemonID", "aabb1122"), ("CapturedAt", "t1")]),
    }));

    // Remove with no Name key → loot_item_from_flat_info returns None → noop.
    state.apply_operator_message(OperatorMessage::CredentialsRemove(Message {
        head: head(EventCode::Credentials),
        info: flat_info(&[("DemonID", "aabb1122")]),
    }));

    assert_eq!(state.loot.len(), 1, "remove without name should be a noop");
}

// ── HostFileAdd / HostFileRemove ──────────────────────────────────

#[test]
fn host_file_add_inserts_file_loot_and_emits_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let events = state.apply_operator_message(OperatorMessage::HostFileAdd(Message {
        head: head(EventCode::HostFile),
        info: flat_info(&[
            ("Name", "secrets.txt"),
            ("DemonID", "ccdd3344"),
            ("FilePath", "/tmp/secrets.txt"),
            ("CapturedAt", "2026-03-19 11:00:00"),
        ]),
    }));

    assert_eq!(state.loot.len(), 1);
    let item = &state.loot[0];
    assert_eq!(item.kind, LootKind::File);
    assert_eq!(item.name, "secrets.txt");
    assert_eq!(item.file_path.as_deref(), Some("/tmp/secrets.txt"));

    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], AppEvent::LootCaptured(l) if l.kind == LootKind::File));
}

#[test]
fn host_file_remove_deletes_matching_file_loot() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::HostFileAdd(Message {
        head: head(EventCode::HostFile),
        info: flat_info(&[("Name", "secrets.txt"), ("DemonID", "ccdd3344"), ("CapturedAt", "t1")]),
    }));
    assert_eq!(state.loot.len(), 1);

    state.apply_operator_message(OperatorMessage::HostFileRemove(Message {
        head: head(EventCode::HostFile),
        info: flat_info(&[("Name", "secrets.txt"), ("DemonID", "ccdd3344")]),
    }));

    assert!(state.loot.is_empty(), "file loot should have been removed");
}

// ── AgentTask ─────────────────────────────────────────────────────

#[test]
fn agent_task_returns_no_events() {
    use red_cell_common::operator::AgentTaskInfo;

    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let events = state.apply_operator_message(OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "bob".to_owned(),
            timestamp: "ts".to_owned(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "1".to_owned(),
            command_line: "ls".to_owned(),
            demon_id: "11223344".to_owned(),
            command_id: "9".to_owned(),
            ..AgentTaskInfo::default()
        },
    }));

    assert!(events.is_empty(), "AgentTask should not emit AppEvents");
}

// ── flat_info_string ─────────────────────────────────────────────

fn make_flat_info(pairs: &[(&str, serde_json::Value)]) -> FlatInfo {
    let fields = pairs.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect();
    FlatInfo { fields }
}

#[test]
fn flat_info_string_returns_first_matching_key() {
    let info = make_flat_info(&[
        ("Name", Value::String("first".to_owned())),
        ("FileName", Value::String("second".to_owned())),
    ]);
    let result = flat_info_string(&info, &["Name", "FileName"]);
    assert_eq!(result, Some("first".to_owned()));
}

#[test]
fn flat_info_string_falls_back_to_later_key() {
    let info = make_flat_info(&[("FileName", Value::String("fallback".to_owned()))]);
    let result = flat_info_string(&info, &["Name", "FileName"]);
    assert_eq!(result, Some("fallback".to_owned()));
}

#[test]
fn flat_info_string_converts_number_to_string() {
    let info = make_flat_info(&[("ID", Value::Number(serde_json::Number::from(42)))]);
    let result = flat_info_string(&info, &["ID"]);
    assert_eq!(result, Some("42".to_owned()));
}

#[test]
fn flat_info_string_returns_none_for_null() {
    let info = make_flat_info(&[("Name", Value::Null)]);
    let result = flat_info_string(&info, &["Name"]);
    assert_eq!(result, None);
}

#[test]
fn flat_info_string_returns_none_for_bool() {
    let info = make_flat_info(&[("Name", Value::Bool(true))]);
    let result = flat_info_string(&info, &["Name"]);
    assert_eq!(result, None);
}

#[test]
fn flat_info_string_returns_none_for_array() {
    let info = make_flat_info(&[("Name", Value::Array(vec![]))]);
    let result = flat_info_string(&info, &["Name"]);
    assert_eq!(result, None);
}

#[test]
fn flat_info_string_returns_none_for_missing_keys() {
    let info = make_flat_info(&[("Other", Value::String("value".to_owned()))]);
    let result = flat_info_string(&info, &["Name", "FileName"]);
    assert_eq!(result, None);
}

#[test]
fn flat_info_string_returns_none_for_empty_info() {
    let info = make_flat_info(&[]);
    let result = flat_info_string(&info, &["Name"]);
    assert_eq!(result, None);
}

#[test]
fn flat_info_string_respects_key_priority_order() {
    // Both keys present; first key in the priority list wins even if it
    // appears later in the BTreeMap iteration order.
    let info = make_flat_info(&[
        ("ZName", Value::String("z".to_owned())),
        ("AName", Value::String("a".to_owned())),
    ]);
    // "ZName" is first in the key list, so it should win.
    let result = flat_info_string(&info, &["ZName", "AName"]);
    assert_eq!(result, Some("z".to_owned()));
}

// ── loot_item_from_flat_info ─────────────────────────────────────

#[test]
fn loot_item_from_flat_info_populates_all_fields() {
    let info = make_flat_info(&[
        ("Name", Value::String("creds.txt".to_owned())),
        ("DemonID", Value::String("0xAABBCCDD".to_owned())),
        ("FilePath", Value::String("C:\\Users\\creds.txt".to_owned())),
        ("Operator", Value::String("admin".to_owned())),
        ("Kind", Value::String("Credential".to_owned())),
        ("LootID", Value::Number(serde_json::Number::from(7))),
        ("CapturedAt", Value::String("2026-03-18T10:00:00Z".to_owned())),
        ("SizeBytes", Value::Number(serde_json::Number::from(1024))),
        ("ContentBase64", Value::String("dGVzdA==".to_owned())),
        ("Credential", Value::String("user:pass".to_owned())),
    ]);

    let item = loot_item_from_flat_info(&info, LootKind::Other).expect("should produce a LootItem");

    assert_eq!(item.name, "creds.txt");
    assert_eq!(item.agent_id, "AABBCCDD");
    assert_eq!(item.file_path, Some("C:\\Users\\creds.txt".to_owned()));
    assert_eq!(item.source, "admin");
    assert_eq!(item.kind, LootKind::Credential);
    assert_eq!(item.id, Some(7));
    assert_eq!(item.collected_at, "2026-03-18T10:00:00Z");
    assert_eq!(item.size_bytes, Some(1024));
    assert_eq!(item.content_base64, Some("dGVzdA==".to_owned()));
    assert_eq!(item.preview, Some("user:pass".to_owned()));
}

#[test]
fn loot_item_from_flat_info_returns_none_when_name_missing() {
    let info = make_flat_info(&[("DemonID", Value::String("11223344".to_owned()))]);
    assert!(loot_item_from_flat_info(&info, LootKind::File).is_none());
}

#[test]
fn loot_item_from_flat_info_uses_fallback_kind_when_kind_is_other() {
    let info = make_flat_info(&[("Name", Value::String("data".to_owned()))]);
    let item =
        loot_item_from_flat_info(&info, LootKind::Screenshot).expect("should produce a LootItem");
    // "data" doesn't match any specific kind, so loot_kind_from_strings
    // returns Other, and the fallback should be used.
    assert_eq!(item.kind, LootKind::Screenshot);
}

#[test]
fn loot_item_from_flat_info_uses_fallback_keys() {
    // Use alternate key names: FileName, AgentID, Path
    let info = make_flat_info(&[
        ("FileName", Value::String("report.pdf".to_owned())),
        ("AgentID", Value::String("DEADBEEF".to_owned())),
        ("Path", Value::String("/tmp/report.pdf".to_owned())),
    ]);
    let item = loot_item_from_flat_info(&info, LootKind::Other).expect("should produce a LootItem");
    assert_eq!(item.name, "report.pdf");
    assert_eq!(item.agent_id, "DEADBEEF");
    assert_eq!(item.file_path, Some("/tmp/report.pdf".to_owned()));
    // Path contains '/' so loot_kind_from_strings detects File kind
    assert_eq!(item.kind, LootKind::File);
}

#[test]
fn loot_item_from_flat_info_defaults_missing_optional_fields() {
    let info = make_flat_info(&[("Name", Value::String("minimal".to_owned()))]);
    let item = loot_item_from_flat_info(&info, LootKind::Other).expect("should produce a LootItem");
    assert_eq!(item.agent_id, "");
    assert_eq!(item.collected_at, "");
    assert_eq!(item.file_path, None);
    assert_eq!(item.size_bytes, None);
    assert_eq!(item.content_base64, None);
    assert_eq!(item.preview, None);
    assert_eq!(item.id, None);
}

#[test]
fn loot_item_from_flat_info_source_falls_back_to_kind_label() {
    // No Operator/Pattern/Kind/Type key for source, so it should use
    // fallback_kind.label().to_ascii_lowercase().
    let info = make_flat_info(&[("Name", Value::String("screenshot.png".to_owned()))]);
    let item = loot_item_from_flat_info(&info, LootKind::File).expect("should produce a LootItem");
    assert_eq!(item.source, "file");
}

#[test]
fn loot_item_from_flat_info_sanitizes_display_fields() {
    let info = make_flat_info(&[
        ("Name", Value::String("  creds\tentry\n".to_owned())),
        ("DemonID", Value::String("aabb1122".to_owned())),
        ("FilePath", Value::String("/tmp/secrets\tvault\n".to_owned())),
        ("Operator", Value::String("  sekurlsa\tpwdump\n".to_owned())),
        ("Credential", Value::String("alice\tadmin\r\nhash".to_owned())),
    ]);

    let item = loot_item_from_flat_info(&info, LootKind::Credential)
        .unwrap_or_else(|| panic!("should produce a LootItem"));

    assert_eq!(item.name, "creds entry");
    assert_eq!(item.agent_id, "AABB1122");
    assert_eq!(item.file_path.as_deref(), Some("/tmp/secrets vault"));
    assert_eq!(item.source, "sekurlsa pwdump");
    assert_eq!(item.preview.as_deref(), Some("alice admin  hash"));
}

#[test]
fn event_log_max_size_zero_caps_at_one_entry() {
    // With max_size=0, `len() >= max_size` is always true so push()
    // always tries to evict first. On the first push the deque is empty,
    // so pop_front returns None and the entry is added — the log holds
    // one entry. On subsequent pushes the existing entry is evicted and
    // replaced. Document this behavior so changes don't silently break it.
    let mut log = EventLog::new(0);
    log.push(EventKind::Agent, "a", "t1", "first");
    assert_eq!(log.len(), 1);
    assert_eq!(log.unread_count, 1);

    log.push(EventKind::Agent, "a", "t2", "second");
    assert_eq!(log.len(), 1);
    assert_eq!(log.entries[0].message, "second");
    // Evicted entry was unread: -1 +1 = still 1
    assert_eq!(log.unread_count, 1);

    log.mark_all_read();
    log.push(EventKind::System, "s", "t3", "third");
    assert_eq!(log.len(), 1);
    assert_eq!(log.entries[0].message, "third");
    // Evicted entry was read: 0 +1 = 1
    assert_eq!(log.unread_count, 1);
}

#[test]
fn event_log_eviction_unread_count_stays_consistent_over_mixed_cycle() {
    // Push → mark_all_read → push past capacity → verify unread_count is
    // consistent with the actual number of unread entries at each step.
    let mut log = EventLog::new(3);
    log.push(EventKind::Agent, "a", "t1", "m1");
    log.push(EventKind::Operator, "b", "t2", "m2");
    log.push(EventKind::System, "c", "t3", "m3");
    assert_eq!(log.unread_count, 3);

    log.mark_all_read();
    assert_eq!(log.unread_count, 0);

    // Push two more — evicts two read entries, adds two unread entries
    log.push(EventKind::Agent, "a", "t4", "m4");
    log.push(EventKind::Agent, "a", "t5", "m5");
    assert_eq!(log.unread_count, 2);
    assert_eq!(
        log.entries.iter().filter(|e| !e.read).count(),
        log.unread_count,
        "unread_count must equal actual unread entries"
    );

    // Verify per-kind counts match too
    assert_eq!(log.unread_by_kind(EventKind::Agent), 2);
    assert_eq!(log.unread_by_kind(EventKind::Operator), 0);
    assert_eq!(log.unread_by_kind(EventKind::System), 0);
}

/// Helper to build a full `OperatorAgentInfo` with the given `name_id` and
/// `hostname`, using sensible defaults for all other fields.
fn make_agent_info(name_id: &str, hostname: &str) -> OperatorAgentInfo {
    OperatorAgentInfo {
        active: "true".to_owned(),
        background_check: false,
        domain_name: "LAB".to_owned(),
        elevated: false,
        internal_ip: "10.0.0.10".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        first_call_in: "10/03/2026 11:59:00".to_owned(),
        last_call_in: "10/03/2026 12:00:00".to_owned(),
        hostname: hostname.to_owned(),
        listener: "http".to_owned(),
        magic_value: "deadbeef".to_owned(),
        name_id: name_id.to_owned(),
        os_arch: "x64".to_owned(),
        os_build: "19045".to_owned(),
        os_version: "Windows 11".to_owned(),
        pivots: AgentPivotsInfo::default(),
        port_fwds: Vec::new(),
        process_arch: "x64".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_pid: "1234".to_owned(),
        process_ppid: "1111".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        reason: "manual".to_owned(),
        note: String::new(),
        sleep_delay: serde_json::Value::from(5),
        sleep_jitter: serde_json::Value::from(10),
        kill_date: serde_json::Value::Null,
        working_hours: serde_json::Value::Null,
        socks_cli: Vec::new(),
        socks_cli_mtx: None,
        socks_svr: Vec::new(),
        tasked_once: false,
        username: "operator".to_owned(),
        pivot_parent: String::new(),
    }
}

#[test]
fn duplicate_agent_new_updates_in_place_without_duplicating() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // First AgentNew for "abcd1234".
    state.apply_operator_message(OperatorMessage::AgentNew(Box::new(Message {
        head: head(EventCode::Session),
        info: make_agent_info("abcd1234", "wkstn-1"),
    })));
    assert_eq!(state.agents.len(), 1);
    assert_eq!(state.agents[0].hostname, "wkstn-1");

    // Second AgentNew with the same name_id but different hostname.
    let events = state.apply_operator_message(OperatorMessage::AgentNew(Box::new(Message {
        head: head(EventCode::Session),
        info: make_agent_info("abcd1234", "wkstn-2"),
    })));

    // upsert_agent must replace in-place — still only one entry.
    assert_eq!(state.agents.len(), 1, "duplicate AgentNew must not create a second entry");
    assert_eq!(
        state.agents[0].hostname, "wkstn-2",
        "the agent fields should be updated to the latest values"
    );
    assert_eq!(state.agents[0].name_id, "ABCD1234", "name_id must remain normalised");
    // An AgentCheckin event is still emitted for the duplicate.
    assert_eq!(events, vec![AppEvent::AgentCheckin("ABCD1234".to_owned())]);
}

#[test]
fn agent_response_for_unknown_agent_does_not_panic() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    assert!(state.agents.is_empty());

    // Send a response for an agent that was never registered.
    let events = state.apply_operator_message(OperatorMessage::AgentResponse(Message {
        head: head(EventCode::Session),
        info: AgentResponseInfo {
            demon_id: "deadbeef".to_owned(),
            command_id: "42".to_owned(),
            output: "some output".to_owned(),
            command_line: Some("whoami".to_owned()),
            extra: BTreeMap::new(),
        },
    }));

    // The response should still be recorded in the console for that agent_id,
    // and a CommandResponse event should be emitted — no panic.
    assert!(
        events.iter().any(|e| matches!(e, AppEvent::CommandResponse { .. })),
        "a CommandResponse event should be emitted even for an unknown agent"
    );
    let console = state.agent_consoles.get("DEADBEEF");
    assert!(console.is_some(), "console entry should be created for unknown agent");
    assert_eq!(console.map(|c| c.len()), Some(1));
}

#[test]
fn agent_response_empty_output_for_unknown_agent_returns_no_events() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let events = state.apply_operator_message(OperatorMessage::AgentResponse(Message {
        head: head(EventCode::Session),
        info: AgentResponseInfo {
            demon_id: "deadbeef".to_owned(),
            command_id: "42".to_owned(),
            output: String::new(),
            command_line: None,
            extra: BTreeMap::new(),
        },
    }));

    // Empty output causes early return — no events, no console entry.
    assert!(events.is_empty(), "empty output should produce no events");
    assert!(!state.agent_consoles.contains_key("DEADBEEF"), "no console entry for empty output");
}

// ─── extract_session_token ────────────────────────────────────────────────────

#[test]
fn extract_session_token_parses_standard_format() {
    let msg = "Successful Authenticated; SessionToken=abc123";
    assert_eq!(extract_session_token(msg), Some("abc123"));
}

#[test]
fn extract_session_token_returns_none_on_missing_marker() {
    let msg = "Successful Authenticated";
    assert!(extract_session_token(msg).is_none());
}

#[test]
fn extract_session_token_returns_none_on_empty_string() {
    assert!(extract_session_token("").is_none());
}

#[test]
fn extract_session_token_returns_empty_token_when_marker_is_at_end() {
    // "SessionToken=" with nothing after yields an empty token, not None.
    let msg = "Successful Authenticated; SessionToken=";
    assert_eq!(extract_session_token(msg), Some(""));
}

#[test]
fn extract_session_token_returns_full_suffix_after_marker() {
    // Everything after "SessionToken=" is the token, including any extra text.
    let msg = "SessionToken=tok-xyz; extra=stuff";
    assert_eq!(extract_session_token(msg), Some("tok-xyz; extra=stuff"));
}
