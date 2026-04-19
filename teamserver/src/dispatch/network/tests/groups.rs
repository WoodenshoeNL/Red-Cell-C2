//! Tests for Share, LocalGroup, and Group `CommandNet` subcommands,
//! and for the `format_net_shares` and `format_net_group_descriptions` helpers.

use red_cell_common::demon::DemonNetCommand;

use super::super::super::CommandDispatchError;
use super::super::groups::{format_net_group_descriptions, format_net_shares};
use super::super::handle_net_callback;
use super::common::{
    AGENT_ID, REQUEST_ID, assert_agent_response, call_and_recv, encode_u32, encode_utf16,
    net_payload,
};
use crate::EventBus;

// ── Share ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn share_broadcasts_share_table() {
    let mut rest = encode_utf16("FILESERV");
    rest.extend(encode_utf16("ADMIN$"));
    rest.extend(encode_utf16("C:\\Windows"));
    rest.extend(encode_utf16("Remote Admin"));
    rest.extend(encode_u32(0));
    let payload = net_payload(DemonNetCommand::Share, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Shares for FILESERV [1]: ");
    assert!(output.contains("ADMIN$"));
    assert!(output.contains("C:\\Windows"));
    assert!(output.contains("Remote Admin"));
}

#[tokio::test]
async fn share_empty_list_broadcasts_zero_count() {
    let rest = encode_utf16("FILESERV");
    let payload = net_payload(DemonNetCommand::Share, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Shares for FILESERV [0]: ");
    assert!(output.is_empty());
}

#[tokio::test]
async fn share_empty_string_row_data_aligns_correctly() {
    let mut rest = encode_utf16("FILESERV");
    rest.extend(encode_utf16(""));
    rest.extend(encode_utf16(""));
    rest.extend(encode_utf16(""));
    rest.extend(encode_u32(0));
    let payload = net_payload(DemonNetCommand::Share, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Shares for FILESERV [1]: ");
    assert!(output.contains("Share name"));
    assert!(output.contains("Path"));
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 3, "header + separator + one data row");
}

#[tokio::test]
async fn truncated_share_access_returns_invalid_callback_payload() {
    let mut rest = encode_utf16("FILESERV");
    rest.extend(encode_utf16("ADMIN$"));
    rest.extend(encode_utf16("C:\\Windows"));
    rest.extend(encode_utf16("Remote Admin"));
    let mut access = encode_u32(0);
    access.pop();
    rest.extend(access);
    let payload = net_payload(DemonNetCommand::Share, &rest);
    let events = EventBus::default();
    let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated Share access u32, got {result:?}"
    );
}

// ── LocalGroup ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn localgroup_broadcasts_group_table() {
    let mut rest = encode_utf16("WORKSTATION");
    rest.extend(encode_utf16("Administrators"));
    rest.extend(encode_utf16("Full control"));
    rest.extend(encode_utf16("Users"));
    rest.extend(encode_utf16("Ordinary users"));
    let payload = net_payload(DemonNetCommand::LocalGroup, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Local Groups for WORKSTATION: ");
    assert!(output.contains("Administrators"));
    assert!(output.contains("Full control"));
    assert!(output.contains("Users"));
    assert!(output.contains("Ordinary users"));
}

#[tokio::test]
async fn localgroup_empty_list_broadcasts_empty_output() {
    let rest = encode_utf16("WORKSTATION");
    let payload = net_payload(DemonNetCommand::LocalGroup, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Local Groups for WORKSTATION: ");
    assert!(output.is_empty());
}

#[tokio::test]
async fn truncated_localgroup_description_returns_invalid_callback_payload() {
    let mut rest = encode_utf16("WORKSTATION");
    rest.extend(encode_utf16("Administrators"));
    let mut desc = encode_utf16("Full control");
    desc.pop();
    rest.extend(desc);
    let payload = net_payload(DemonNetCommand::LocalGroup, &rest);
    let events = EventBus::default();
    let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated LocalGroup description, got {result:?}"
    );
}

// ── Group ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn group_broadcasts_group_table() {
    let mut rest = encode_utf16("DC01");
    rest.extend(encode_utf16("Domain Admins"));
    rest.extend(encode_utf16("DA group"));
    let payload = net_payload(DemonNetCommand::Group, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "List groups on DC01: ");
    assert!(output.contains("Domain Admins"));
    assert!(output.contains("DA group"));
}

#[tokio::test]
async fn group_empty_list_broadcasts_empty_output() {
    let rest = encode_utf16("DC01");
    let payload = net_payload(DemonNetCommand::Group, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "List groups on DC01: ");
    assert!(output.is_empty());
}

#[tokio::test]
async fn truncated_group_description_returns_invalid_callback_payload() {
    let mut rest = encode_utf16("DC01");
    rest.extend(encode_utf16("Domain Admins"));
    let mut desc = encode_utf16("DA group");
    desc.pop();
    rest.extend(desc);
    let payload = net_payload(DemonNetCommand::Group, &rest);
    let events = EventBus::default();
    let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated Group description, got {result:?}"
    );
}

// ── format_net_shares ────────────────────────────────────────────────────────

#[test]
fn format_net_shares_empty_returns_empty_string() {
    assert_eq!(format_net_shares(&[]), "");
}

#[test]
fn format_net_shares_single_row_shorter_than_header_uses_min_width() {
    let rows = vec![("C$".to_owned(), "C:\\".to_owned(), "".to_owned(), 0u32)];
    let result = format_net_shares(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 3, "header + separator + one data row");
    assert_eq!(lines[0], " Share name   Path   Remark   Access");
    assert_eq!(lines[1], " ----------   ----   ------   ------");
    assert_eq!(lines[2], " C$           C:\\             0");
}

#[test]
fn format_net_shares_long_data_expands_column_width() {
    let name = "very-long-share-name-here".to_owned();
    let rows = vec![(name.clone(), "C:\\share".to_owned(), "test".to_owned(), 1u32)];
    let result = format_net_shares(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(
        lines[0].contains(&format!("{:<25}", "Share name")),
        "header should expand to data width"
    );
    assert!(lines[2].starts_with(&format!(" {name}")));
}

#[test]
fn format_net_shares_multiple_rows_all_present() {
    let rows = vec![
        ("ADMIN$".to_owned(), "C:\\Windows".to_owned(), "Admin share".to_owned(), 0u32),
        ("IPC$".to_owned(), "".to_owned(), "Remote IPC".to_owned(), 0u32),
    ];
    let result = format_net_shares(&rows);
    assert!(result.contains("ADMIN$"));
    assert!(result.contains("IPC$"));
    assert!(result.contains("Admin share"));
    assert!(result.contains("Remote IPC"));
}

#[test]
fn format_net_shares_empty_string_values_align_to_min_widths() {
    let rows = vec![("".to_owned(), "".to_owned(), "".to_owned(), 0u32)];
    let result = format_net_shares(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 3, "header + separator + one data row");
    assert_eq!(lines[0], " Share name   Path   Remark   Access");
    assert_eq!(lines[1], " ----------   ----   ------   ------");
    let expected_data = format!(" {:<10}   {:<4}   {:<6}   {}", "", "", "", 0);
    assert_eq!(lines[2], expected_data);
}

// ── format_net_group_descriptions ────────────────────────────────────────────

#[test]
fn format_net_group_descriptions_empty_returns_empty_string() {
    assert_eq!(format_net_group_descriptions(&[]), "");
}

#[test]
fn format_net_group_descriptions_empty_string_values_trims_whitespace_only_row() {
    let rows = vec![("".to_owned(), "".to_owned())];
    let result = format_net_group_descriptions(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 2, "data row is all-whitespace and gets trimmed");
    assert_eq!(lines[0], " Group  Description");
    assert_eq!(lines[1], " -----  -----------");
}

#[test]
fn format_net_group_descriptions_empty_group_nonempty_description_preserves_row() {
    let rows = vec![("".to_owned(), "Some description".to_owned())];
    let result = format_net_group_descriptions(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 3, "header + separator + one data row");
    assert_eq!(lines[0], " Group  Description");
    assert_eq!(lines[1], " -----  -----------");
    let expected_data = format!(" {:<5}  {}", "", "Some description");
    assert_eq!(lines[2], expected_data);
}

#[test]
fn format_net_group_descriptions_single_row_shorter_than_header_uses_min_width() {
    let rows = vec![("Adm".to_owned(), "Administrators".to_owned())];
    let result = format_net_group_descriptions(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 3, "header + separator + one data row");
    assert_eq!(lines[0], " Group  Description");
    assert_eq!(lines[1], " -----  -----------");
    assert_eq!(lines[2], " Adm    Administrators");
}

#[test]
fn format_net_group_descriptions_single_row_name_exceeds_min_width() {
    let rows = vec![("Admins".to_owned(), "Local administrators".to_owned())];
    let result = format_net_group_descriptions(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 3, "header + separator + one data row");
    assert_eq!(lines[0], " Group   Description");
    assert_eq!(lines[1], " -----   -----------");
    assert_eq!(lines[2], " Admins  Local administrators");
}

#[test]
fn format_net_group_descriptions_long_name_pads_columns_to_name_width() {
    let long_name = "Domain-Power-Editor!".to_owned();
    let rows = vec![(long_name.clone(), "Can edit power things".to_owned())];
    let result = format_net_group_descriptions(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], format!(" {:<20}  Description", "Group"));
    assert_eq!(lines[1], format!(" {:<20}  -----------", "-----"));
    assert_eq!(lines[2], format!(" {:<20}  Can edit power things", long_name));
}

#[test]
fn format_net_group_descriptions_multiple_rows_varying_widths() {
    let rows = vec![
        ("Guests".to_owned(), "Built-in guest account".to_owned()),
        ("Administrators".to_owned(), "Full control".to_owned()),
        ("Users".to_owned(), "Ordinary users".to_owned()),
    ];
    let result = format_net_group_descriptions(&rows);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 5, "header + separator + 3 data rows");
    assert_eq!(lines[0], " Group           Description");
    assert_eq!(lines[1], " -----           -----------");
    assert!(lines[2].starts_with(" Guests         "));
    assert!(lines[3].starts_with(" Administrators "));
    assert!(lines[4].starts_with(" Users          "));
    assert!(result.contains("Built-in guest account"));
    assert!(result.contains("Full control"));
    assert!(result.contains("Ordinary users"));
}
