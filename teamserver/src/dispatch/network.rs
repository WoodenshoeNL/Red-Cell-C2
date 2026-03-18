use red_cell_common::demon::{DemonCommand, DemonNetCommand};

use crate::EventBus;

use super::{CallbackParser, CommandDispatchError, agent_response_event};

pub(super) async fn handle_net_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandNet));
    let subcommand = parser.read_u32("net subcommand")?;
    let subcommand = DemonNetCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandNet),
            message: error.to_string(),
        }
    })?;

    let (kind, message, output) = match subcommand {
        DemonNetCommand::Domain => {
            let domain = parser.read_string("net domain")?;
            if domain.is_empty() {
                ("Good", "The machine does not seem to be joined to a domain".to_owned(), None)
            } else {
                ("Good", format!("Domain for this Host: {domain}"), None)
            }
        }
        DemonNetCommand::Logons => {
            let target = parser.read_utf16("net logons target")?;
            let mut users = Vec::new();
            while !parser.is_empty() {
                users.push(parser.read_utf16("net logon user")?);
            }
            let mut output = String::from(" Usernames\n ---------\n");
            for user in &users {
                output.push_str(&format!("  {user}\n"));
            }
            (
                "Info",
                format!("Logged on users at {target} [{}]: ", users.len()),
                Some(output.trim_end().to_owned()),
            )
        }
        DemonNetCommand::Sessions => {
            let target = parser.read_utf16("net sessions target")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                rows.push((
                    parser.read_utf16("net session client")?,
                    parser.read_utf16("net session user")?,
                    parser.read_u32("net session active")?,
                    parser.read_u32("net session idle")?,
                ));
            }
            (
                "Info",
                format!("Sessions for {target} [{}]: ", rows.len()),
                Some(format_net_sessions(&rows)),
            )
        }
        DemonNetCommand::Computer | DemonNetCommand::DcList => return Ok(None),
        DemonNetCommand::Share => {
            let target = parser.read_utf16("net shares target")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                rows.push((
                    parser.read_utf16("net share name")?,
                    parser.read_utf16("net share path")?,
                    parser.read_utf16("net share remark")?,
                    parser.read_u32("net share access")?,
                ));
            }
            (
                "Info",
                format!("Shares for {target} [{}]: ", rows.len()),
                Some(format_net_shares(&rows)),
            )
        }
        DemonNetCommand::LocalGroup => {
            let target = parser.read_utf16("net localgroup target")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                rows.push((
                    parser.read_utf16("net localgroup name")?,
                    parser.read_utf16("net localgroup description")?,
                ));
            }
            (
                "Info",
                format!("Local Groups for {target}: "),
                Some(format_net_group_descriptions(&rows)),
            )
        }
        DemonNetCommand::Group => {
            let target = parser.read_utf16("net group target")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                rows.push((
                    parser.read_utf16("net group name")?,
                    parser.read_utf16("net group description")?,
                ));
            }
            (
                "Info",
                format!("List groups on {target}: "),
                Some(format_net_group_descriptions(&rows)),
            )
        }
        DemonNetCommand::Users => {
            let target = parser.read_utf16("net users target")?;
            let mut users = Vec::new();
            while !parser.is_empty() {
                let username = parser.read_utf16("net user name")?;
                let is_admin = parser.read_bool("net user admin")?;
                users.push((username, is_admin));
            }
            let mut output = String::new();
            for (username, is_admin) in &users {
                output.push_str(&format!(
                    " - {username}{}\n",
                    if *is_admin { " (Admin)" } else { "" }
                ));
            }
            ("Info", format!("Users on {target}: "), Some(output.trim_end().to_owned()))
        }
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandNet),
        request_id,
        kind,
        &message,
        output,
    )?);
    Ok(None)
}

pub(super) fn format_net_sessions(rows: &[(String, String, u32, u32)]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let computer_width = rows.iter().map(|row| row.0.len()).max().unwrap_or(8).max(8);
    let user_width = rows.iter().map(|row| row.1.len()).max().unwrap_or(8).max(8);
    let mut output = format!(
        " {:<computer_width$}   {:<user_width$}   {:<6}   {}\n",
        "Computer", "Username", "Active", "Idle"
    );
    output.push_str(&format!(
        " {:<computer_width$}   {:<user_width$}   {:<6}   {}\n",
        "--------", "--------", "------", "----"
    ));

    for (computer, username, active, idle) in rows {
        output.push_str(&format!(
            " {:<computer_width$}   {:<user_width$}   {:<6}   {}\n",
            computer, username, active, idle
        ));
    }

    output.trim_end().to_owned()
}

pub(super) fn format_net_shares(rows: &[(String, String, String, u32)]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let name_width = rows.iter().map(|row| row.0.len()).max().unwrap_or(10).max(10);
    let path_width = rows.iter().map(|row| row.1.len()).max().unwrap_or(4).max(4);
    let remark_width = rows.iter().map(|row| row.2.len()).max().unwrap_or(6).max(6);
    let mut output = format!(
        " {:<name_width$}   {:<path_width$}   {:<remark_width$}   {}\n",
        "Share name", "Path", "Remark", "Access"
    );
    output.push_str(&format!(
        " {:<name_width$}   {:<path_width$}   {:<remark_width$}   {}\n",
        "----------", "----", "------", "------"
    ));

    for (name, path, remark, access) in rows {
        output.push_str(&format!(
            " {:<name_width$}   {:<path_width$}   {:<remark_width$}   {}\n",
            name, path, remark, access
        ));
    }

    output.trim_end().to_owned()
}

pub(super) fn format_net_group_descriptions(rows: &[(String, String)]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let group_width = rows.iter().map(|row| row.0.len()).max().unwrap_or(5).max(5);
    let mut output = format!(" {:<group_width$}  {}\n", "Group", "Description");
    output.push_str(&format!(" {:<group_width$}  {}\n", "-----", "-----------"));

    for (group, description) in rows {
        output.push_str(&format!(" {:<group_width$}  {}\n", group, description));
    }

    output.trim_end().to_owned()
}

pub(super) fn int_to_ipv4(value: u32) -> String {
    let bytes = value.to_le_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

#[cfg(test)]
mod tests {
    use red_cell_common::demon::{DemonCommand, DemonNetCommand};
    use red_cell_common::operator::OperatorMessage;
    use serde_json::Value;

    use super::*;
    use crate::EventBus;

    // ── payload encoding helpers ────────────────────────────────────────────

    fn encode_u32(v: u32) -> Vec<u8> {
        v.to_le_bytes().to_vec()
    }

    fn encode_string(s: &str) -> Vec<u8> {
        let mut buf = encode_u32(s.len() as u32);
        buf.extend_from_slice(s.as_bytes());
        buf
    }

    fn encode_utf16(s: &str) -> Vec<u8> {
        let words: Vec<u16> = s.encode_utf16().collect();
        let byte_len = (words.len() * 2) as u32;
        let mut buf = encode_u32(byte_len);
        for w in &words {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        buf
    }

    fn encode_bool(v: bool) -> Vec<u8> {
        encode_u32(u32::from(v))
    }

    fn net_payload(subcommand: DemonNetCommand, rest: &[u8]) -> Vec<u8> {
        let mut payload = encode_u32(subcommand as u32);
        payload.extend_from_slice(rest);
        payload
    }

    const AGENT_ID: u32 = 0xDEAD_BEEF;
    const REQUEST_ID: u32 = 42;

    async fn call_and_recv(
        payload: &[u8],
    ) -> (Result<Option<Vec<u8>>, CommandDispatchError>, Option<OperatorMessage>) {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, payload).await;
        drop(events);
        let msg = rx.recv().await;
        (result, msg)
    }

    fn assert_agent_response<'a>(
        msg: &'a OperatorMessage,
        expected_kind: &str,
        expected_message: &str,
    ) -> &'a str {
        let OperatorMessage::AgentResponse(m) = msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        assert_eq!(m.info.demon_id, format!("{AGENT_ID:08X}"));
        assert_eq!(m.info.command_id, u32::from(DemonCommand::CommandNet).to_string());
        assert_eq!(m.info.extra.get("Type").and_then(Value::as_str), Some(expected_kind));
        assert_eq!(m.info.extra.get("Message").and_then(Value::as_str), Some(expected_message));
        &m.info.output
    }

    // ── handle_net_callback: Domain ─────────────────────────────────────────

    #[tokio::test]
    async fn domain_non_empty_broadcasts_domain_name() {
        let payload = net_payload(DemonNetCommand::Domain, &encode_string("CORP.LOCAL"));
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        let msg = msg.expect("should broadcast");
        let output = assert_agent_response(&msg, "Good", "Domain for this Host: CORP.LOCAL");
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn domain_empty_broadcasts_not_joined_message() {
        let payload = net_payload(DemonNetCommand::Domain, &encode_string(""));
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Good", "The machine does not seem to be joined to a domain");
    }

    // ── handle_net_callback: Logons ─────────────────────────────────────────

    #[tokio::test]
    async fn logons_broadcasts_user_list() {
        let mut rest = encode_utf16("SERVER01");
        rest.extend(encode_utf16("alice"));
        rest.extend(encode_utf16("bob"));
        let payload = net_payload(DemonNetCommand::Logons, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        let msg = msg.expect("should broadcast");
        let output = assert_agent_response(&msg, "Info", "Logged on users at SERVER01 [2]: ");
        assert!(output.contains("alice"));
        assert!(output.contains("bob"));
        assert!(output.contains("Usernames"));
    }

    // ── handle_net_callback: Sessions ───────────────────────────────────────

    #[tokio::test]
    async fn sessions_broadcasts_session_table() {
        let mut rest = encode_utf16("DC01");
        // one session row
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

    // ── handle_net_callback: Computer / DcList (no-op) ──────────────────────

    #[tokio::test]
    async fn computer_returns_none_without_broadcast() {
        let payload = net_payload(DemonNetCommand::Computer, &[]);
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        drop(events);
        // No message should have been broadcast
        let msg = rx.recv().await;
        assert!(msg.is_none(), "Computer should not broadcast");
    }

    #[tokio::test]
    async fn dclist_returns_none_without_broadcast() {
        let payload = net_payload(DemonNetCommand::DcList, &[]);
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        drop(events);
        let msg = rx.recv().await;
        assert!(msg.is_none(), "DcList should not broadcast");
    }

    // ── handle_net_callback: Share ──────────────────────────────────────────

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

    // ── handle_net_callback: LocalGroup ─────────────────────────────────────

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

    // ── handle_net_callback: Group ──────────────────────────────────────────

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

    // ── handle_net_callback: Users ──────────────────────────────────────────

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
        // guest should NOT have (Admin)
        for line in output.lines() {
            if line.contains("guest") {
                assert!(!line.contains("(Admin)"), "guest should not be admin: {line}");
            }
        }
    }

    // ── handle_net_callback: error paths ──────────────────────────────────────

    #[tokio::test]
    async fn invalid_subcommand_returns_invalid_callback_payload() {
        // Subcommand 0xFF is outside the valid range (1..=9)
        let payload = encode_u32(0xFF);
        let events = EventBus::default();
        let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload, got {result:?}"
        );
    }

    #[tokio::test]
    async fn empty_payload_returns_invalid_callback_payload() {
        // No bytes at all — cannot even read the subcommand u32
        let events = EventBus::default();
        let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &[]).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for empty payload, got {result:?}"
        );
    }

    #[tokio::test]
    async fn truncated_sessions_row_returns_invalid_callback_payload() {
        // Sessions: valid target, then start a row but truncate before the idle u32
        let mut rest = encode_utf16("DC01");
        rest.extend(encode_utf16("10.0.0.5")); // client
        rest.extend(encode_utf16("admin")); // user
        rest.extend(encode_u32(120)); // active
        // missing: idle u32 — parser should fail
        let payload = net_payload(DemonNetCommand::Sessions, &rest);
        let events = EventBus::default();
        let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated Sessions row, got {result:?}"
        );
    }

    #[tokio::test]
    async fn truncated_users_row_returns_invalid_callback_payload() {
        // Users: valid target, then a username but missing the is_admin bool
        let mut rest = encode_utf16("HOST01");
        rest.extend(encode_utf16("Administrator")); // username
        // missing: is_admin bool — parser should fail
        let payload = net_payload(DemonNetCommand::Users, &rest);
        let events = EventBus::default();
        let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated Users row, got {result:?}"
        );
    }

    // ── format_net_sessions ───────────────────────────────────────────────────

    #[test]
    fn format_net_sessions_empty_returns_empty_string() {
        assert_eq!(format_net_sessions(&[]), "");
    }

    #[test]
    fn format_net_sessions_single_row_shorter_than_header_uses_min_width() {
        // "pc" (2) < min 8, "alice" (5) < min 8 → column widths stay at 8
        let rows = vec![("pc".to_owned(), "alice".to_owned(), 5u32, 0u32)];
        let result = format_net_sessions(&rows);
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3, "header + separator + one data row");
        // Header columns are left-padded to width 8
        assert_eq!(lines[0], " Computer   Username   Active   Idle");
        assert_eq!(lines[1], " --------   --------   ------   ----");
        // Data row aligns to the same widths ("pc" padded to 8, "alice" padded to 8)
        assert_eq!(lines[2], " pc         alice      5        0");
    }

    #[test]
    fn format_net_sessions_long_data_expands_column_width() {
        let computer = "very-long-computer-name".to_owned(); // len 23 > min 8
        let user = "u".to_owned();
        let rows = vec![(computer.clone(), user, 10u32, 2u32)];
        let result = format_net_sessions(&rows);
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3);
        // Header "Computer" must be padded to at least len(computer)=23
        assert!(
            lines[0].contains(&format!("{:<23}", "Computer")),
            "header column should expand to data width"
        );
        // Data row starts with the full computer name
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

    // ── format_net_shares ────────────────────────────────────────────────────

    #[test]
    fn format_net_shares_empty_returns_empty_string() {
        assert_eq!(format_net_shares(&[]), "");
    }

    #[test]
    fn format_net_shares_single_row_shorter_than_header_uses_min_width() {
        // "C$" (2) < min 10, "C:\\" (3) < min 4, "" (0) < min 6
        let rows = vec![("C$".to_owned(), "C:\\".to_owned(), "".to_owned(), 0u32)];
        let result = format_net_shares(&rows);
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3, "header + separator + one data row");
        // Header columns must use min widths: name=10, path=4, remark=6
        assert_eq!(lines[0], " Share name   Path   Remark   Access");
        assert_eq!(lines[1], " ----------   ----   ------   ------");
        // Data row: "C$" padded to 10, "C:\\" padded to 4, "" padded to 6
        assert_eq!(lines[2], " C$           C:\\             0");
    }

    #[test]
    fn format_net_shares_long_data_expands_column_width() {
        let name = "very-long-share-name-here".to_owned(); // len 25 > min 10
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

    // ── format_net_group_descriptions ────────────────────────────────────────

    #[test]
    fn format_net_group_descriptions_empty_returns_empty_string() {
        assert_eq!(format_net_group_descriptions(&[]), "");
    }

    #[test]
    fn format_net_group_descriptions_single_row_shorter_than_header_uses_min_width() {
        // "Adm" (3) < min 5
        let rows = vec![("Adm".to_owned(), "Administrators".to_owned())];
        let result = format_net_group_descriptions(&rows);
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3, "header + separator + one data row");
        assert_eq!(lines[0], " Group  Description");
        assert_eq!(lines[1], " -----  -----------");
        // "Adm" padded to 5
        assert_eq!(lines[2], " Adm    Administrators");
    }

    #[test]
    fn format_net_group_descriptions_single_row_name_exceeds_min_width() {
        // "Admins" (6) > min 5 → group_width must expand to 6
        let rows = vec![("Admins".to_owned(), "Local administrators".to_owned())];
        let result = format_net_group_descriptions(&rows);
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3, "header + separator + one data row");
        // group_width = 6, so format is " {:<6}  {}"
        assert_eq!(lines[0], " Group   Description");
        assert_eq!(lines[1], " -----   -----------");
        assert_eq!(lines[2], " Admins  Local administrators");
    }

    #[test]
    fn format_net_group_descriptions_long_name_pads_columns_to_name_width() {
        // 20-char group name forces group_width = 20
        let long_name = "Domain-Power-Editor!".to_owned(); // exactly 20 chars
        let rows = vec![(long_name.clone(), "Can edit power things".to_owned())];
        let result = format_net_group_descriptions(&rows);
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3);
        // "Group" padded to width 20
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
        // group_width = max(14, 5) = 14 (len of "Administrators")
        // Format " {:<14}  {}" → "Group" (5) + 9 padding + 2 sep = 11 spaces after "Group"
        assert_eq!(lines[0], " Group           Description");
        assert_eq!(lines[1], " -----           -----------");
        // All rows must align to width 14
        assert!(lines[2].starts_with(" Guests         "));
        assert!(lines[3].starts_with(" Administrators "));
        assert!(lines[4].starts_with(" Users          "));
        assert!(result.contains("Built-in guest account"));
        assert!(result.contains("Full control"));
        assert!(result.contains("Ordinary users"));
    }

    // ── int_to_ipv4 ──────────────────────────────────────────────────────────

    #[test]
    fn int_to_ipv4_zero_is_all_zeros() {
        assert_eq!(int_to_ipv4(0x0000_0000), "0.0.0.0");
    }

    #[test]
    fn int_to_ipv4_little_endian_192_168_1_1() {
        // LE bytes of 0x0101A8C0: C0 A8 01 01 → 192.168.1.1
        assert_eq!(int_to_ipv4(0x0101_A8C0), "192.168.1.1");
    }

    #[test]
    fn int_to_ipv4_localhost() {
        // LE bytes of 0x0100007F: 7F 00 00 01 → 127.0.0.1
        assert_eq!(int_to_ipv4(0x0100_007F), "127.0.0.1");
    }

    #[test]
    fn int_to_ipv4_broadcast() {
        // LE bytes of 0xFFFFFFFF: FF FF FF FF → 255.255.255.255
        assert_eq!(int_to_ipv4(0xFFFF_FFFF), "255.255.255.255");
    }

    /// Pin byte-order: 0xC0A8_0101 under `to_le_bytes()` yields [0x01, 0x01, 0xA8, 0xC0],
    /// i.e. "1.1.168.192". If someone swaps to `to_be_bytes()` this would become
    /// "192.168.1.1" — the test catches the regression.
    #[test]
    fn int_to_ipv4_byte_order_pinned() {
        assert_eq!(int_to_ipv4(0xC0A8_0101), "1.1.168.192");
    }
}
