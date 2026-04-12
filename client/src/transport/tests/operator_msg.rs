use super::super::operator_msg::{
    flat_info_string, loot_item_from_flat_info, normalize_agent_id, sanitize_text,
};
use super::super::*;
use std::collections::BTreeMap;

use super::helpers::{flat_info, head, make_agent_info, make_flat_info};
use red_cell_common::operator::{AgentResponseInfo, EventCode, Message, MessageHead};
use serde_json::Value;
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
