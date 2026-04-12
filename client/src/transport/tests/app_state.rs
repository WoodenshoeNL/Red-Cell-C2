use super::super::operator_msg::{
    flat_info_string, loot_item_from_flat_info, loot_item_from_response, normalize_agent_id,
    sanitize_text,
};
use super::super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::helpers::head;
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
    Arc::make_mut(&mut state.agents).push(AgentSummary {
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
    Arc::make_mut(&mut state.agents).push(AgentSummary {
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
    Arc::make_mut(&mut state.agents).push(AgentSummary {
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
    assert_eq!(processes.refresh_generation, 1);
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
