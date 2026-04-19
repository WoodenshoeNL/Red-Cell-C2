//! Tests for Logons, Sessions, and Users `CommandNet` subcommands,
//! and for the `format_net_sessions` helper.

use red_cell_common::demon::DemonNetCommand;

use super::super::super::CommandDispatchError;
use super::super::handle_net_callback;
use super::super::sessions::format_net_sessions;
use super::common::{
    AGENT_ID, REQUEST_ID, assert_agent_response, call_and_recv, encode_bool, encode_u32,
    encode_utf16, net_payload,
};
use crate::EventBus;

// ── Logons ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn logons_broadcasts_user_list() {
    let mut rest = encode_utf16("SERVER01");
    rest.extend(encode_utf16("alice"));
    rest.extend(encode_utf16("bob"));
    let payload = net_payload(DemonNetCommand::Logons, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Logged on users at SERVER01 [2]: ");
    assert!(output.contains("alice"));
    assert!(output.contains("bob"));
    assert!(output.contains("Usernames"));
}

#[tokio::test]
async fn logons_empty_list_broadcasts_zero_count() {
    let rest = encode_utf16("SERVER01");
    let payload = net_payload(DemonNetCommand::Logons, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Logged on users at SERVER01 [0]: ");
    assert!(output.contains("Usernames"));
    assert!(output.contains("---------"));
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 2, "only header + separator, no user rows");
}

// ── Sessions ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sessions_broadcasts_session_table() {
    let mut rest = encode_utf16("DC01");
    rest.extend(encode_utf16("10.0.0.5"));
    rest.extend(encode_utf16("admin"));
    rest.extend(encode_u32(120));
    rest.extend(encode_u32(5));
    let payload = net_payload(DemonNetCommand::Sessions, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Sessions for DC01 [1]: ");
    assert!(output.contains("10.0.0.5"));
    assert!(output.contains("admin"));
    assert!(output.contains("120"));
}

#[tokio::test]
async fn sessions_empty_list_broadcasts_zero_count() {
    let rest = encode_utf16("DC01");
    let payload = net_payload(DemonNetCommand::Sessions, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Sessions for DC01 [0]: ");
    assert!(output.is_empty());
}

#[tokio::test]
async fn sessions_empty_string_row_data_aligns_correctly() {
    let mut rest = encode_utf16("DC01");
    rest.extend(encode_utf16(""));
    rest.extend(encode_utf16(""));
    rest.extend(encode_u32(0));
    rest.extend(encode_u32(0));
    let payload = net_payload(DemonNetCommand::Sessions, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Sessions for DC01 [1]: ");
    assert!(output.contains("Computer"));
    assert!(output.contains("Username"));
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 3, "header + separator + one data row");
}

#[tokio::test]
async fn truncated_sessions_row_returns_invalid_callback_payload() {
    let mut rest = encode_utf16("DC01");
    rest.extend(encode_utf16("10.0.0.5"));
    rest.extend(encode_utf16("admin"));
    rest.extend(encode_u32(120));
    // missing: idle u32
    let payload = net_payload(DemonNetCommand::Sessions, &rest);
    let events = EventBus::default();
    let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated Sessions row, got {result:?}"
    );
}

// ── Users ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn users_broadcasts_user_list_with_admin_flag() {
    let mut rest = encode_utf16("HOST01");
    rest.extend(encode_utf16("Administrator"));
    rest.extend(encode_bool(true));
    rest.extend(encode_utf16("guest"));
    rest.extend(encode_bool(false));
    let payload = net_payload(DemonNetCommand::Users, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Users on HOST01: ");
    assert!(output.contains("Administrator"));
    assert!(output.contains("(Admin)"));
    assert!(output.contains("guest"));
    for line in output.lines() {
        if line.contains("guest") {
            assert!(!line.contains("(Admin)"), "guest should not be admin: {line}");
        }
    }
}

#[tokio::test]
async fn users_empty_list_broadcasts_empty_output() {
    let rest = encode_utf16("HOST01");
    let payload = net_payload(DemonNetCommand::Users, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Users on HOST01: ");
    assert!(output.is_empty());
}

#[tokio::test]
async fn truncated_users_row_returns_invalid_callback_payload() {
    let mut rest = encode_utf16("HOST01");
    rest.extend(encode_utf16("Administrator"));
    // missing: is_admin bool
    let payload = net_payload(DemonNetCommand::Users, &rest);
    let events = EventBus::default();
    let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated Users row, got {result:?}"
    );
}

// ── format_net_sessions ───────────────────────────────────────────────────────

#[test]
fn format_net_sessions_empty_returns_empty_string() {
    assert_eq!(format_net_sessions(&[]), "");
}

#[test]
fn format_net_sessions_single_row_shorter_than_header_uses_min_width() {
    let rows = vec![("pc".to_owned(), "alice".to_owned(), 5u32, 0u32)];
    let result = format_net_sessions(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 3, "header + separator + one data row");
    assert_eq!(lines[0], " Computer   Username   Active   Idle");
    assert_eq!(lines[1], " --------   --------   ------   ----");
    assert_eq!(lines[2], " pc         alice      5        0");
}

#[test]
fn format_net_sessions_long_data_expands_column_width() {
    let computer = "very-long-computer-name".to_owned();
    let user = "u".to_owned();
    let rows = vec![(computer.clone(), user, 10u32, 2u32)];
    let result = format_net_sessions(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(
        lines[0].contains(&format!("{:<23}", "Computer")),
        "header column should expand to data width"
    );
    assert!(lines[2].starts_with(&format!(" {computer}")));
}

#[test]
fn format_net_sessions_multiple_rows_all_present() {
    let rows = vec![
        ("host1".to_owned(), "user1".to_owned(), 100u32, 0u32),
        ("host2".to_owned(), "user2".to_owned(), 200u32, 5u32),
    ];
    let result = format_net_sessions(&rows);
    assert!(result.contains("host1"));
    assert!(result.contains("host2"));
    assert!(result.contains("user1"));
    assert!(result.contains("user2"));
}

#[test]
fn format_net_sessions_empty_string_values_align_to_min_widths() {
    let rows = vec![("".to_owned(), "".to_owned(), 0u32, 0u32)];
    let result = format_net_sessions(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 3, "header + separator + one data row");
    assert_eq!(lines[0], " Computer   Username   Active   Idle");
    assert_eq!(lines[1], " --------   --------   ------   ----");
    let expected_data = format!(" {:<8}   {:<8}   {:<6}   {}", "", "", 0, 0);
    assert_eq!(lines[2], expected_data);
}
