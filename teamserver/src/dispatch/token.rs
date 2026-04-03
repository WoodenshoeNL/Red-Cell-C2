use red_cell_common::demon::{DemonCommand, DemonTokenCommand};
use tracing::warn;

use crate::EventBus;

use super::{CallbackParser, CommandDispatchError, agent_response_event};

pub(super) async fn handle_token_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandToken));
    let subcommand = parser.read_u32("token subcommand")?;
    let cmd = u32::from(DemonCommand::CommandToken);

    match DemonTokenCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload { command_id: cmd, message: error.to_string() }
    })? {
        DemonTokenCommand::Impersonate => {
            let success = parser.read_u32("token impersonation success")?;
            let user = parser.read_string("token impersonation user")?;
            let (kind, message) = if success != 0 {
                ("Good", format!("Successfully impersonated {user}"))
            } else {
                ("Error", format!("Failed to impersonate {user}"))
            };
            events
                .broadcast(agent_response_event(agent_id, cmd, request_id, kind, &message, None)?);
        }

        DemonTokenCommand::Steal => {
            let user = parser.read_utf16("token steal user")?;
            let token_id = parser.read_u32("token steal token id")?;
            let target_pid = parser.read_u32("token steal target pid")?;
            events.broadcast(agent_response_event(
                agent_id,
                cmd,
                request_id,
                "Good",
                &format!(
                    "Successfully stole and impersonated token from {target_pid} User:[{user}] TokenID:[{token_id}]"
                ),
                None,
            )?);
        }

        DemonTokenCommand::List => {
            let output = format_token_list(&mut parser)?;
            let message = "Token Vault:";
            events.broadcast(agent_response_event(
                agent_id,
                cmd,
                request_id,
                "Info",
                message,
                Some(output),
            )?);
        }

        DemonTokenCommand::PrivsGetOrList => {
            let priv_list = parser.read_u32("token privs list flag")?;
            if priv_list != 0 {
                let output = format_token_privs_list(&mut parser)?;
                events.broadcast(agent_response_event(
                    agent_id,
                    cmd,
                    request_id,
                    "Good",
                    "List Privileges for current Token:",
                    Some(output),
                )?);
            } else {
                let success = parser.read_u32("token privs get success")?;
                let priv_name = parser.read_string("token privs get name")?;
                let (kind, message) = if success != 0 {
                    ("Good", format!("The privilege {priv_name} was successfully enabled"))
                } else {
                    ("Error", format!("Failed to enable the {priv_name} privilege"))
                };
                events.broadcast(agent_response_event(
                    agent_id, cmd, request_id, kind, &message, None,
                )?);
            }
        }

        DemonTokenCommand::Make => {
            if parser.is_empty() {
                events.broadcast(agent_response_event(
                    agent_id,
                    cmd,
                    request_id,
                    "Error",
                    "Failed to create token",
                    None,
                )?);
            } else {
                let user_domain = parser.read_utf16("token make user domain")?;
                events.broadcast(agent_response_event(
                    agent_id,
                    cmd,
                    request_id,
                    "Good",
                    &format!("Successfully created and impersonated token: {user_domain}"),
                    None,
                )?);
            }
        }

        DemonTokenCommand::GetUid => {
            let elevated = parser.read_u32("token getuid elevated")?;
            let user = parser.read_utf16("token getuid user")?;
            let message = if elevated != 0 {
                format!("Token User: {user} (Admin)")
            } else {
                format!("Token User: {user}")
            };
            events.broadcast(agent_response_event(
                agent_id, cmd, request_id, "Good", &message, None,
            )?);
        }

        DemonTokenCommand::Revert => {
            let success = parser.read_u32("token revert success")?;
            let (kind, message) = if success != 0 {
                ("Good", "Successful reverted token to itself")
            } else {
                ("Error", "Failed to revert token to itself")
            };
            events.broadcast(agent_response_event(agent_id, cmd, request_id, kind, message, None)?);
        }

        DemonTokenCommand::Remove => {
            let success = parser.read_u32("token remove success")?;
            let token_id = parser.read_u32("token remove id")?;
            let (kind, message) = if success != 0 {
                ("Good", format!("Successful removed token [{token_id}] from vault"))
            } else {
                ("Error", format!("Failed to remove token [{token_id}] from vault"))
            };
            events
                .broadcast(agent_response_event(agent_id, cmd, request_id, kind, &message, None)?);
        }

        DemonTokenCommand::Clear => {
            events.broadcast(agent_response_event(
                agent_id,
                cmd,
                request_id,
                "Good",
                "Token vault has been cleared",
                None,
            )?);
        }

        DemonTokenCommand::FindTokens => {
            let success = parser.read_u32("token find success")?;
            if success == 0 {
                events.broadcast(agent_response_event(
                    agent_id,
                    cmd,
                    request_id,
                    "Error",
                    "Failed to list existing tokens",
                    None,
                )?);
            } else {
                let output = format_found_tokens(&mut parser)?;
                events.broadcast(agent_response_event(
                    agent_id,
                    cmd,
                    request_id,
                    "Info",
                    "Tokens available:",
                    Some(output),
                )?);
            }
        }
    }

    Ok(None)
}

fn format_token_list(parser: &mut CallbackParser<'_>) -> Result<String, CommandDispatchError> {
    struct TokenEntry {
        index: u32,
        handle: u32,
        domain_user: String,
        process_id: u32,
        token_type: u32,
        impersonating: u32,
    }

    let mut entries = Vec::new();
    while !parser.is_empty() {
        let index = parser.read_u32("token list index")?;
        let handle = parser.read_u32("token list handle")?;
        let domain_user = parser.read_utf16("token list domain user")?;
        let process_id = parser.read_u32("token list process id")?;
        let token_type = parser.read_u32("token list type")?;
        let impersonating = parser.read_u32("token list impersonating")?;
        entries.push(TokenEntry {
            index,
            handle,
            domain_user,
            process_id,
            token_type,
            impersonating,
        });
    }

    if entries.is_empty() {
        return Ok("\nThe token vault is empty".to_owned());
    }

    let max_user = entries.iter().map(|e| e.domain_user.len()).max().unwrap_or(11).max(11);

    let mut output = format!(
        "\n {:<4}  {:<6}  {:<width$}  {:<4}  {:<14} {:<4}\n",
        " ID ",
        "Handle",
        "Domain\\User",
        "PID",
        "Type",
        "Impersonating",
        width = max_user
    );
    output.push_str(&format!(
        " {:<4}  {:<6}  {:<width$}  {:<4}  {:<14} {:<4}\n",
        "----",
        "------",
        "-----------",
        "---",
        "--------------",
        "-------------",
        width = max_user
    ));

    for entry in &entries {
        let type_str = match entry.token_type {
            1 => "stolen",
            2 => "make (local)",
            3 => "make (network)",
            _ => "unknown",
        };
        let imp_str = if entry.impersonating != 0 { "Yes" } else { "No" };
        output.push_str(&format!(
            " {:<4}  0x{:<4x}  {:<width$}  {:<4}  {:<14} {:<4}\n",
            entry.index,
            entry.handle,
            entry.domain_user,
            entry.process_id,
            type_str,
            imp_str,
            width = max_user
        ));
    }

    Ok(output)
}

fn format_token_privs_list(
    parser: &mut CallbackParser<'_>,
) -> Result<String, CommandDispatchError> {
    let mut output = String::from("\n");
    while !parser.is_empty() {
        let privilege = parser.read_string("token privilege name")?;
        let state = parser.read_u32("token privilege state")?;
        let state_str = match state {
            3 => "Enabled",
            2 => "Adjusted",
            0 => "Disabled",
            _ => "Unknown",
        };
        output.push_str(&format!(" {privilege} :: {state_str}\n"));
    }
    Ok(output)
}

fn format_found_tokens(parser: &mut CallbackParser<'_>) -> Result<String, CommandDispatchError> {
    const SECURITY_MANDATORY_LOW_RID: u32 = 0x0000_1000;
    const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x0000_2000;
    const SECURITY_MANDATORY_HIGH_RID: u32 = 0x0000_3000;
    const SECURITY_MANDATORY_SYSTEM_RID: u32 = 0x0000_4000;

    struct FoundToken {
        domain_user: String,
        integrity: String,
        token_type: String,
        impersonation: String,
        remote_auth: String,
        process_id: u32,
        handle: u32,
    }

    let num_tokens = parser.read_u32("token find count")?;
    if num_tokens == 0 {
        return Ok("\nNo tokens found".to_owned());
    }

    let mut tokens = Vec::new();
    for i in 0..num_tokens {
        if parser.is_empty() {
            warn!(
                declared = num_tokens,
                parsed = i,
                "format_found_tokens: payload declared {num_tokens} tokens but only {i} were present"
            );
            break;
        }
        let domain_user = parser.read_utf16("found token user")?;
        let process_id = parser.read_u32("found token pid")?;
        let handle = parser.read_u32("found token handle")?;
        let integrity_level = parser.read_u32("found token integrity")?;
        let impersonation_level = parser.read_u32("found token impersonation")?;
        let token_type_raw = parser.read_u32("found token type")?;

        let integrity = if integrity_level <= SECURITY_MANDATORY_LOW_RID {
            "Low"
        } else if (SECURITY_MANDATORY_MEDIUM_RID..SECURITY_MANDATORY_HIGH_RID)
            .contains(&integrity_level)
        {
            "Medium"
        } else if (SECURITY_MANDATORY_HIGH_RID..SECURITY_MANDATORY_SYSTEM_RID)
            .contains(&integrity_level)
        {
            "High"
        } else if integrity_level >= SECURITY_MANDATORY_SYSTEM_RID {
            "System"
        } else {
            "Low"
        };

        let (token_type, impersonation, remote_auth) = if token_type_raw == 2 {
            let imp = match impersonation_level {
                0 => "Anonymous",
                1 => "Identification",
                2 => "Impersonation",
                3 => "Delegation",
                _ => "Unknown",
            };
            let remote = if impersonation_level == 3 { "Yes" } else { "No" };
            ("Impersonation", imp, remote)
        } else if token_type_raw == 1 {
            ("Primary", "N/A", "Yes")
        } else {
            ("?", "Unknown", "No")
        };

        tokens.push(FoundToken {
            domain_user,
            integrity: integrity.to_owned(),
            token_type: token_type.to_owned(),
            impersonation: impersonation.to_owned(),
            remote_auth: remote_auth.to_owned(),
            process_id,
            handle,
        });
    }

    if tokens.is_empty() {
        return Ok("\nNo tokens found".to_owned());
    }

    let max_user = tokens.iter().map(|t| t.domain_user.len()).max().unwrap_or(13).max(13);

    let mut output = format!(
        "\n {:<width$}  {:<9}  {:<13}  {:<16}  {:<9} {:<10} {:<9} {:<9}\n",
        " Domain\\User",
        "Integrity",
        "TokenType",
        "Impersonation LV",
        "LocalAuth",
        "RemoteAuth",
        "ProcessID",
        "Handle",
        width = max_user,
    );
    output.push_str(&format!(
        " {:<width$}  {:<9}  {:<13}  {:<16}  {:<9} {:<10} {:<9} {:<9}\n",
        "-".repeat(max_user),
        "---------",
        "-------------",
        "----------------",
        "---------",
        "----------",
        "---------",
        "------",
        width = max_user,
    ));

    for token in &tokens {
        let handle_str =
            if token.handle == 0 { String::new() } else { format!("{:x}", token.handle) };
        output.push_str(&format!(
            " {:<width$}  {:<9}  {:<13}  {:<16}  {:<9} {:<10} {:<9} {:<9}\n",
            token.domain_user,
            token.integrity,
            token.token_type,
            token.impersonation,
            "Yes",
            token.remote_auth,
            token.process_id,
            handle_str,
            width = max_user,
        ));
    }

    output.push_str("\nTo impersonate a user, run: token steal [process id] (handle)");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use red_cell_common::demon::DemonTokenCommand;
    use red_cell_common::operator::OperatorMessage;
    use serde_json::Value;

    use super::super::CallbackParser;
    use super::handle_token_callback;
    use crate::EventBus;

    /// Helper: append a little-endian u32 to a buffer.
    fn push_u32(buf: &mut Vec<u8>, val: u32) {
        buf.extend_from_slice(&val.to_le_bytes());
    }

    /// Helper: append a length-prefixed UTF-16LE string (as CallbackParser::read_utf16 expects).
    fn push_utf16(buf: &mut Vec<u8>, s: &str) {
        let words: Vec<u16> = s.encode_utf16().collect();
        let byte_len = (words.len() * 2) as u32;
        push_u32(buf, byte_len);
        for w in &words {
            buf.extend_from_slice(&w.to_le_bytes());
        }
    }

    /// Helper: append a length-prefixed UTF-8 string (as CallbackParser::read_string expects).
    fn push_string(buf: &mut Vec<u8>, s: &str) {
        push_u32(buf, s.len() as u32);
        buf.extend_from_slice(s.as_bytes());
    }

    // -----------------------------------------------------------------------
    // format_token_list tests
    // -----------------------------------------------------------------------

    #[test]
    fn format_token_list_empty() {
        let buf = Vec::new();
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_list(&mut parser).expect("unwrap");
        assert_eq!(output, "\nThe token vault is empty");
    }

    #[test]
    fn format_token_list_stolen_impersonating() {
        let mut buf = Vec::new();
        // index=0, handle=0x10, domain_user="CORP\\admin", pid=1234, type=1 (stolen), impersonating=1
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 0x10);
        push_utf16(&mut buf, "CORP\\admin");
        push_u32(&mut buf, 1234);
        push_u32(&mut buf, 1); // stolen
        push_u32(&mut buf, 1); // impersonating

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_list(&mut parser).expect("unwrap");
        assert!(output.contains("stolen"), "expected 'stolen' in output: {output}");
        assert!(output.contains("Yes"), "expected 'Yes' for impersonating");
        assert!(output.contains("CORP\\admin"));
    }

    #[test]
    fn format_token_list_make_local_not_impersonating() {
        let mut buf = Vec::new();
        push_u32(&mut buf, 1);
        push_u32(&mut buf, 0x20);
        push_utf16(&mut buf, "LOCAL\\user");
        push_u32(&mut buf, 5678);
        push_u32(&mut buf, 2); // make (local)
        push_u32(&mut buf, 0); // not impersonating

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_list(&mut parser).expect("unwrap");
        assert!(output.contains("make (local)"));
        assert!(output.contains("No"));
    }

    #[test]
    fn format_token_list_make_network() {
        let mut buf = Vec::new();
        push_u32(&mut buf, 2);
        push_u32(&mut buf, 0x30);
        push_utf16(&mut buf, "NET\\svc");
        push_u32(&mut buf, 9999);
        push_u32(&mut buf, 3); // make (network)
        push_u32(&mut buf, 0);

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_list(&mut parser).expect("unwrap");
        assert!(output.contains("make (network)"));
    }

    #[test]
    fn format_token_list_unknown_type() {
        let mut buf = Vec::new();
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 0x40);
        push_utf16(&mut buf, "X\\Y");
        push_u32(&mut buf, 42);
        push_u32(&mut buf, 99); // unknown type
        push_u32(&mut buf, 0);

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_list(&mut parser).expect("unwrap");
        assert!(output.contains("unknown"));
    }

    // -----------------------------------------------------------------------
    // format_token_privs_list tests
    // -----------------------------------------------------------------------

    #[test]
    fn format_token_privs_list_all_states() {
        let mut buf = Vec::new();
        // state 3 = Enabled
        push_string(&mut buf, "SeDebugPrivilege");
        push_u32(&mut buf, 3);
        // state 2 = Adjusted
        push_string(&mut buf, "SeBackupPrivilege");
        push_u32(&mut buf, 2);
        // state 0 = Disabled
        push_string(&mut buf, "SeShutdownPrivilege");
        push_u32(&mut buf, 0);
        // unknown state
        push_string(&mut buf, "SeRestorePrivilege");
        push_u32(&mut buf, 99);

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).expect("unwrap");
        assert!(output.contains("SeDebugPrivilege :: Enabled"));
        assert!(output.contains("SeBackupPrivilege :: Adjusted"));
        assert!(output.contains("SeShutdownPrivilege :: Disabled"));
        assert!(output.contains("SeRestorePrivilege :: Unknown"));
    }

    #[test]
    fn format_token_privs_list_empty() {
        let buf = Vec::new();
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).expect("unwrap");
        assert_eq!(output, "\n");
    }

    #[test]
    fn format_token_privs_list_single_enabled() {
        let mut buf = Vec::new();
        push_string(&mut buf, "SeDebugPrivilege");
        push_u32(&mut buf, 3);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).expect("unwrap");
        assert_eq!(output, "\n SeDebugPrivilege :: Enabled\n");
    }

    #[test]
    fn format_token_privs_list_single_adjusted() {
        let mut buf = Vec::new();
        push_string(&mut buf, "SeBackupPrivilege");
        push_u32(&mut buf, 2);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).expect("unwrap");
        assert_eq!(output, "\n SeBackupPrivilege :: Adjusted\n");
    }

    #[test]
    fn format_token_privs_list_single_disabled() {
        let mut buf = Vec::new();
        push_string(&mut buf, "SeShutdownPrivilege");
        push_u32(&mut buf, 0);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).expect("unwrap");
        assert_eq!(output, "\n SeShutdownPrivilege :: Disabled\n");
    }

    #[test]
    fn format_token_privs_list_state_1_is_unknown() {
        let mut buf = Vec::new();
        push_string(&mut buf, "SeImpersonatePrivilege");
        push_u32(&mut buf, 1);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).expect("unwrap");
        assert_eq!(output, "\n SeImpersonatePrivilege :: Unknown\n");
    }

    #[test]
    fn format_token_privs_list_large_unknown_state() {
        let mut buf = Vec::new();
        push_string(&mut buf, "SeLoadDriverPrivilege");
        push_u32(&mut buf, 255);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).expect("unwrap");
        assert_eq!(output, "\n SeLoadDriverPrivilege :: Unknown\n");
    }

    #[test]
    fn format_token_privs_list_multiple_preserves_order() {
        let mut buf = Vec::new();
        push_string(&mut buf, "SeDebugPrivilege");
        push_u32(&mut buf, 3);
        push_string(&mut buf, "SeShutdownPrivilege");
        push_u32(&mut buf, 0);
        push_string(&mut buf, "SeBackupPrivilege");
        push_u32(&mut buf, 2);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).expect("unwrap");
        assert_eq!(
            output,
            "\n SeDebugPrivilege :: Enabled\n SeShutdownPrivilege :: Disabled\n SeBackupPrivilege :: Adjusted\n"
        );
    }

    // -----------------------------------------------------------------------
    // format_found_tokens tests — integrity level boundaries
    // -----------------------------------------------------------------------

    /// Build a found-tokens payload with a single token at the given integrity level.
    fn build_found_token_payload(integrity_level: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, 1); // num_tokens = 1
        push_utf16(&mut buf, "DOMAIN\\user");
        push_u32(&mut buf, 1000); // pid
        push_u32(&mut buf, 0x100); // handle
        push_u32(&mut buf, integrity_level);
        push_u32(&mut buf, 2); // impersonation level (Impersonation)
        push_u32(&mut buf, 2); // token_type = Impersonation
        buf
    }

    fn get_integrity_from_output(output: &str) -> String {
        // The integrity value appears in the table body (skip the header lines).
        // Table lines look like: " DOMAIN\user  Low       Impersonation  ..."
        for line in output.lines().skip(3) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].to_string();
            }
        }
        panic!("Could not find integrity value in output:\n{output}");
    }

    #[test]
    fn format_found_tokens_integrity_0x0000_is_low() {
        let buf = build_found_token_payload(0x0000);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(get_integrity_from_output(&output), "Low");
    }

    #[test]
    fn format_found_tokens_integrity_0x1000_is_low() {
        let buf = build_found_token_payload(0x1000);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(get_integrity_from_output(&output), "Low");
    }

    #[test]
    fn format_found_tokens_integrity_0x1001_falls_through_to_low() {
        // This is the gap: 0x1001 is above LOW_RID but below MEDIUM_RID,
        // and falls through all range checks to the else branch ("Low").
        let buf = build_found_token_payload(0x1001);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(get_integrity_from_output(&output), "Low");
    }

    #[test]
    fn format_found_tokens_integrity_0x1fff_falls_through_to_low() {
        let buf = build_found_token_payload(0x1FFF);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(get_integrity_from_output(&output), "Low");
    }

    #[test]
    fn format_found_tokens_integrity_0x2000_is_medium() {
        let buf = build_found_token_payload(0x2000);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(get_integrity_from_output(&output), "Medium");
    }

    #[test]
    fn format_found_tokens_integrity_0x2fff_is_medium() {
        let buf = build_found_token_payload(0x2FFF);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(get_integrity_from_output(&output), "Medium");
    }

    #[test]
    fn format_found_tokens_integrity_0x3000_is_high() {
        let buf = build_found_token_payload(0x3000);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(get_integrity_from_output(&output), "High");
    }

    #[test]
    fn format_found_tokens_integrity_0x3fff_is_high() {
        let buf = build_found_token_payload(0x3FFF);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(get_integrity_from_output(&output), "High");
    }

    #[test]
    fn format_found_tokens_integrity_0x4000_is_system() {
        let buf = build_found_token_payload(0x4000);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(get_integrity_from_output(&output), "System");
    }

    #[test]
    fn format_found_tokens_zero_count() {
        let mut buf = Vec::new();
        push_u32(&mut buf, 0); // num_tokens = 0
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(output, "\nNo tokens found");
    }

    #[test]
    fn format_found_tokens_primary_token_type() {
        let mut buf = Vec::new();
        push_u32(&mut buf, 1);
        push_utf16(&mut buf, "NT AUTHORITY\\SYSTEM");
        push_u32(&mut buf, 4); // pid
        push_u32(&mut buf, 0x200); // handle
        push_u32(&mut buf, 0x4000); // SYSTEM integrity
        push_u32(&mut buf, 0); // impersonation level (unused for Primary)
        push_u32(&mut buf, 1); // token_type = Primary

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert!(output.contains("Primary"), "expected 'Primary' in output: {output}");
        assert!(output.contains("N/A"), "expected 'N/A' impersonation for Primary");
    }

    #[test]
    fn format_found_tokens_impersonation_levels() {
        // Test all impersonation levels for token_type=2
        let levels = [
            (0u32, "Anonymous"),
            (1, "Identification"),
            (2, "Impersonation"),
            (3, "Delegation"),
            (99, "Unknown"),
        ];
        for (imp_level, expected_label) in &levels {
            let mut buf = Vec::new();
            push_u32(&mut buf, 1);
            push_utf16(&mut buf, "CORP\\user");
            push_u32(&mut buf, 100);
            push_u32(&mut buf, 0x50);
            push_u32(&mut buf, 0x2000); // Medium integrity
            push_u32(&mut buf, *imp_level);
            push_u32(&mut buf, 2); // Impersonation token type

            let mut parser = CallbackParser::new(&buf, 0);
            let output = super::format_found_tokens(&mut parser).expect("unwrap");
            assert!(
                output.contains(expected_label),
                "imp_level={imp_level}: expected '{expected_label}' in output: {output}"
            );
        }
    }

    #[test]
    fn format_token_list_column_expansion_with_long_domain_user() {
        // Multiple entries with varying domain\user lengths to verify column expansion.
        let mut buf = Vec::new();
        // Short name: "A\\B" (3 chars)
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 0x10);
        push_utf16(&mut buf, "A\\B");
        push_u32(&mut buf, 100);
        push_u32(&mut buf, 1);
        push_u32(&mut buf, 0);
        // Long name: "VERYLONGDOMAIN\\administratoraccount" (35 chars)
        push_u32(&mut buf, 1);
        push_u32(&mut buf, 0x20);
        push_utf16(&mut buf, "VERYLONGDOMAIN\\administratoraccount");
        push_u32(&mut buf, 200);
        push_u32(&mut buf, 2);
        push_u32(&mut buf, 1);

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_list(&mut parser).expect("unwrap");

        // The header "Domain\User" is 11 chars. The long name is 35 chars,
        // so max_user should be 35 and columns should expand accordingly.
        assert!(output.contains("VERYLONGDOMAIN\\administratoraccount"));
        assert!(output.contains("A\\B"));

        // Verify that data lines (rows with actual token data) share the same width,
        // confirming column expansion is applied consistently.
        let data_lines: Vec<&str> = output
            .lines()
            .filter(|l| !l.is_empty())
            .skip(2) // skip header + separator
            .collect();
        assert_eq!(data_lines.len(), 2, "expected 2 data rows");
        assert_eq!(
            data_lines[0].len(),
            data_lines[1].len(),
            "data rows should have same width:\n  row0: '{}'\n  row1: '{}'",
            data_lines[0],
            data_lines[1]
        );
    }

    #[test]
    fn format_found_tokens_column_expansion_with_long_domain_user() {
        let mut buf = Vec::new();
        push_u32(&mut buf, 2); // num_tokens
        // Short name
        push_utf16(&mut buf, "X\\Y");
        push_u32(&mut buf, 10);
        push_u32(&mut buf, 0x50);
        push_u32(&mut buf, 0x2000); // Medium
        push_u32(&mut buf, 2); // Impersonation level
        push_u32(&mut buf, 2); // Impersonation token
        // Long name (wider than "Domain\User" header of 13 chars)
        push_utf16(&mut buf, "LONGCORP\\very_long_username_here");
        push_u32(&mut buf, 20);
        push_u32(&mut buf, 0x60);
        push_u32(&mut buf, 0x3000); // High
        push_u32(&mut buf, 1); // Identification
        push_u32(&mut buf, 2); // Impersonation token

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");

        assert!(output.contains("LONGCORP\\very_long_username_here"));
        assert!(output.contains("X\\Y"));

        // Verify column alignment: all table lines (header, separator, data) should have same length.
        let table_lines: Vec<&str> =
            output.lines().filter(|l| !l.is_empty() && !l.starts_with("To impersonate")).collect();
        assert!(table_lines.len() >= 3);
        let expected_len = table_lines[0].len();
        for line in &table_lines {
            assert_eq!(
                line.len(),
                expected_len,
                "column misalignment in found_tokens:\n  expected len {expected_len}\n  got len {} for: '{line}'",
                line.len()
            );
        }
    }

    #[test]
    fn format_found_tokens_integrity_0x0fff_is_low() {
        // 0x0FFF is <= LOW_RID (0x1000), so it's "Low"
        let buf = build_found_token_payload(0x0FFF);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(get_integrity_from_output(&output), "Low");
    }

    #[test]
    fn format_found_tokens_unknown_token_type() {
        let mut buf = Vec::new();
        push_u32(&mut buf, 1);
        push_utf16(&mut buf, "DOM\\user");
        push_u32(&mut buf, 42);
        push_u32(&mut buf, 0x10);
        push_u32(&mut buf, 0x2000); // Medium
        push_u32(&mut buf, 0); // impersonation level
        push_u32(&mut buf, 99); // unknown token_type_raw

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert!(output.contains("?"), "expected '?' for unknown token type: {output}");
        assert!(output.contains("Unknown"), "expected 'Unknown' impersonation for unknown type");
    }

    #[test]
    fn format_found_tokens_truncates_when_num_tokens_exceeds_payload() {
        // Declare num_tokens=3 but only encode 1 token entry.
        // The function should return a table with exactly 1 data row
        // (silently truncating) and emit a warning.
        let mut buf = Vec::new();
        push_u32(&mut buf, 3); // num_tokens = 3 (overstated)
        // Only one token entry follows:
        push_utf16(&mut buf, "CORP\\admin");
        push_u32(&mut buf, 1234); // pid
        push_u32(&mut buf, 0x10); // handle
        push_u32(&mut buf, 0x2000); // Medium integrity
        push_u32(&mut buf, 2); // Impersonation level
        push_u32(&mut buf, 2); // Impersonation token type

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");

        // Should still produce a valid table with the 1 token we did provide.
        assert!(output.contains("CORP\\admin"), "expected the single token in output: {output}");

        // Count data rows (skip header line, separator line, and the trailing
        // "To impersonate" hint). Data rows contain the domain\user string.
        let data_rows: Vec<&str> = output.lines().filter(|l| l.contains("CORP\\admin")).collect();
        assert_eq!(
            data_rows.len(),
            1,
            "expected exactly 1 data row, got {}: {output}",
            data_rows.len()
        );

        // Should NOT say "No tokens found" since we did parse one.
        assert!(!output.contains("No tokens found"));
    }

    #[test]
    fn format_found_tokens_num_tokens_exceeds_payload_completely_empty() {
        // Declare num_tokens=5 but include zero token entries after the count.
        // The loop should immediately break on parser.is_empty() and return "No tokens found".
        let mut buf = Vec::new();
        push_u32(&mut buf, 5); // num_tokens = 5 (but no entries follow)

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        assert_eq!(output, "\nNo tokens found");
    }

    #[test]
    fn format_found_tokens_delegation_has_remote_auth_yes() {
        let mut buf = Vec::new();
        push_u32(&mut buf, 1);
        push_utf16(&mut buf, "CORP\\admin");
        push_u32(&mut buf, 500);
        push_u32(&mut buf, 0x60);
        push_u32(&mut buf, 0x3000); // High
        push_u32(&mut buf, 3); // Delegation
        push_u32(&mut buf, 2); // Impersonation token

        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).expect("unwrap");
        // For delegation (impersonation_level=3), remote_auth should be "Yes"
        // The table has: LocalAuth=Yes, RemoteAuth=Yes
        // Count "Yes" occurrences — should appear for both LocalAuth and RemoteAuth
        let yes_count = output.matches("Yes").count();
        assert!(
            yes_count >= 2,
            "expected at least 2 'Yes' (Local+Remote) for delegation: {output}"
        );
    }

    // -----------------------------------------------------------------------
    // handle_token_callback integration tests
    // -----------------------------------------------------------------------

    const AGENT_ID: u32 = 0xDEAD_BEEF;
    const REQUEST_ID: u32 = 42;
    const TOKEN_CMD: u32 = 40; // DemonCommand::CommandToken

    /// Build a payload with the subcommand u32 prepended.
    fn token_payload(subcmd: DemonTokenCommand, rest: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, subcmd as u32);
        buf.extend_from_slice(rest);
        buf
    }

    /// Call `handle_token_callback` and capture the broadcast event.
    async fn call_and_recv(
        payload: &[u8],
    ) -> (Result<Option<Vec<u8>>, super::super::CommandDispatchError>, Option<OperatorMessage>)
    {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let result = handle_token_callback(&events, AGENT_ID, REQUEST_ID, payload).await;
        // Drop the bus so the receiver sees the channel close after pending messages.
        drop(events);
        let msg = rx.recv().await;
        (result, msg)
    }

    /// Assert that the broadcast message is an AgentResponse with expected kind/message.
    /// Returns the output field for further assertions.
    fn assert_response(
        msg: &OperatorMessage,
        expected_kind: &str,
        expected_message: &str,
    ) -> String {
        let OperatorMessage::AgentResponse(m) = msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        assert_eq!(m.info.demon_id, format!("{AGENT_ID:08X}"));
        assert_eq!(m.info.command_id, TOKEN_CMD.to_string());
        assert_eq!(
            m.info.extra.get("Type").and_then(Value::as_str),
            Some(expected_kind),
            "expected kind={expected_kind}, extra={:?}",
            m.info.extra
        );
        assert_eq!(
            m.info.extra.get("Message").and_then(Value::as_str),
            Some(expected_message),
            "expected message={expected_message}, extra={:?}",
            m.info.extra
        );
        m.info.output.clone()
    }

    // -- Impersonate --

    #[tokio::test]
    async fn handle_impersonate_success() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 1); // success = non-zero
        push_string(&mut rest, "CORP\\admin");
        let payload = token_payload(DemonTokenCommand::Impersonate, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        assert_eq!(result.expect("unwrap"), None);
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Good", "Successfully impersonated CORP\\admin");
    }

    #[tokio::test]
    async fn handle_impersonate_failure() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 0); // success = 0 → failure
        push_string(&mut rest, "CORP\\user");
        let payload = token_payload(DemonTokenCommand::Impersonate, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Error", "Failed to impersonate CORP\\user");
    }

    // -- Steal --

    #[tokio::test]
    async fn handle_steal() {
        let mut rest = Vec::new();
        push_utf16(&mut rest, "CORP\\admin");
        push_u32(&mut rest, 7); // token_id
        push_u32(&mut rest, 1234); // target_pid
        let payload = token_payload(DemonTokenCommand::Steal, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(
            &msg,
            "Good",
            "Successfully stole and impersonated token from 1234 User:[CORP\\admin] TokenID:[7]",
        );
    }

    // -- Revert --

    #[tokio::test]
    async fn handle_revert_success() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 1); // success
        let payload = token_payload(DemonTokenCommand::Revert, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Good", "Successful reverted token to itself");
    }

    #[tokio::test]
    async fn handle_revert_failure() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 0);
        let payload = token_payload(DemonTokenCommand::Revert, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Error", "Failed to revert token to itself");
    }

    // -- Make --

    #[tokio::test]
    async fn handle_make_success() {
        let mut rest = Vec::new();
        push_utf16(&mut rest, "CORP\\newuser");
        let payload = token_payload(DemonTokenCommand::Make, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Good", "Successfully created and impersonated token: CORP\\newuser");
    }

    #[tokio::test]
    async fn handle_make_empty_payload_is_error() {
        // Make with empty rest payload → "Failed to create token"
        let payload = token_payload(DemonTokenCommand::Make, &[]);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Error", "Failed to create token");
    }

    // -- GetUid --

    #[tokio::test]
    async fn handle_getuid_elevated() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 1); // elevated
        push_utf16(&mut rest, "NT AUTHORITY\\SYSTEM");
        let payload = token_payload(DemonTokenCommand::GetUid, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Good", "Token User: NT AUTHORITY\\SYSTEM (Admin)");
    }

    #[tokio::test]
    async fn handle_getuid_not_elevated() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 0); // not elevated
        push_utf16(&mut rest, "CORP\\user");
        let payload = token_payload(DemonTokenCommand::GetUid, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Good", "Token User: CORP\\user");
    }

    // -- Clear --

    #[tokio::test]
    async fn handle_clear() {
        let payload = token_payload(DemonTokenCommand::Clear, &[]);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Good", "Token vault has been cleared");
    }

    // -- Remove --

    #[tokio::test]
    async fn handle_remove_success() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 1); // success
        push_u32(&mut rest, 5); // token_id
        let payload = token_payload(DemonTokenCommand::Remove, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Good", "Successful removed token [5] from vault");
    }

    #[tokio::test]
    async fn handle_remove_failure() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 0); // failure
        push_u32(&mut rest, 3); // token_id
        let payload = token_payload(DemonTokenCommand::Remove, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Error", "Failed to remove token [3] from vault");
    }

    // -- List --

    #[tokio::test]
    async fn handle_list_empty_vault() {
        // List with no token entries after the subcommand
        let payload = token_payload(DemonTokenCommand::List, &[]);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        let output = assert_response(&msg, "Info", "Token Vault:");
        assert!(output.contains("token vault is empty"), "output={output}");
    }

    #[tokio::test]
    async fn handle_list_with_entries() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 0); // index
        push_u32(&mut rest, 0x10); // handle
        push_utf16(&mut rest, "CORP\\admin");
        push_u32(&mut rest, 1234); // pid
        push_u32(&mut rest, 1); // stolen
        push_u32(&mut rest, 1); // impersonating
        let payload = token_payload(DemonTokenCommand::List, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        let output = assert_response(&msg, "Info", "Token Vault:");
        assert!(output.contains("CORP\\admin"));
        assert!(output.contains("stolen"));
    }

    // -- PrivsGetOrList --

    #[tokio::test]
    async fn handle_privs_list() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 1); // priv_list = non-zero → list mode
        push_string(&mut rest, "SeDebugPrivilege");
        push_u32(&mut rest, 3); // Enabled
        let payload = token_payload(DemonTokenCommand::PrivsGetOrList, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        let output = assert_response(&msg, "Good", "List Privileges for current Token:");
        assert!(output.contains("SeDebugPrivilege :: Enabled"));
    }

    #[tokio::test]
    async fn handle_privs_get_success() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 0); // priv_list = 0 → get mode
        push_u32(&mut rest, 1); // success
        push_string(&mut rest, "SeDebugPrivilege");
        let payload = token_payload(DemonTokenCommand::PrivsGetOrList, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Good", "The privilege SeDebugPrivilege was successfully enabled");
    }

    #[tokio::test]
    async fn handle_privs_get_failure() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 0); // priv_list = 0 → get mode
        push_u32(&mut rest, 0); // failure
        push_string(&mut rest, "SeDebugPrivilege");
        let payload = token_payload(DemonTokenCommand::PrivsGetOrList, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Error", "Failed to enable the SeDebugPrivilege privilege");
    }

    // -- FindTokens --

    #[tokio::test]
    async fn handle_find_tokens_success() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 1); // success
        push_u32(&mut rest, 1); // num_tokens
        push_utf16(&mut rest, "CORP\\admin");
        push_u32(&mut rest, 500); // pid
        push_u32(&mut rest, 0x60); // handle
        push_u32(&mut rest, 0x3000); // High integrity
        push_u32(&mut rest, 2); // Impersonation level
        push_u32(&mut rest, 2); // Impersonation token type
        let payload = token_payload(DemonTokenCommand::FindTokens, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        let output = assert_response(&msg, "Info", "Tokens available:");
        assert!(output.contains("CORP\\admin"));
        assert!(output.contains("High"));
    }

    #[tokio::test]
    async fn handle_find_tokens_failure() {
        let mut rest = Vec::new();
        push_u32(&mut rest, 0); // success = 0 → failure
        let payload = token_payload(DemonTokenCommand::FindTokens, &rest);

        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_response(&msg, "Error", "Failed to list existing tokens");
    }

    // -- Error paths --

    #[tokio::test]
    async fn handle_invalid_subcommand() {
        let mut payload = Vec::new();
        push_u32(&mut payload, 9999); // invalid subcommand

        let events = EventBus::default();
        let result = handle_token_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_err());
        let err = result.expect_err("expected Err");
        let err_str = err.to_string();
        assert!(
            err_str.contains("0x00000028"), // CommandToken = 40 = 0x28
            "error should reference token command id: {err_str}"
        );
    }

    #[tokio::test]
    async fn handle_empty_payload() {
        let payload: &[u8] = &[];

        let events = EventBus::default();
        let result = handle_token_callback(&events, AGENT_ID, REQUEST_ID, payload).await;
        assert!(result.is_err(), "empty payload should fail to read subcommand");
    }

    #[tokio::test]
    async fn handle_truncated_impersonate_payload() {
        // Impersonate needs success(u32) + user(string) — provide only subcommand
        let payload = token_payload(DemonTokenCommand::Impersonate, &[]);

        let events = EventBus::default();
        let result = handle_token_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_err(), "truncated Impersonate should fail");
    }

    #[tokio::test]
    async fn handle_truncated_steal_payload() {
        // Steal needs utf16 + u32 + u32 — provide only subcommand
        let payload = token_payload(DemonTokenCommand::Steal, &[]);

        let events = EventBus::default();
        let result = handle_token_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_err(), "truncated Steal should fail");
    }

    #[tokio::test]
    async fn handle_truncated_revert_payload() {
        let payload = token_payload(DemonTokenCommand::Revert, &[]);

        let events = EventBus::default();
        let result = handle_token_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_err(), "truncated Revert should fail");
    }

    #[tokio::test]
    async fn handle_truncated_getuid_payload() {
        let payload = token_payload(DemonTokenCommand::GetUid, &[]);

        let events = EventBus::default();
        let result = handle_token_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_err(), "truncated GetUid should fail");
    }

    #[tokio::test]
    async fn handle_truncated_remove_payload() {
        // Remove needs success(u32) + token_id(u32)
        let mut rest = Vec::new();
        push_u32(&mut rest, 1); // success only, missing token_id
        let payload = token_payload(DemonTokenCommand::Remove, &rest);

        let events = EventBus::default();
        let result = handle_token_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_err(), "truncated Remove should fail");
    }

    #[tokio::test]
    async fn handle_truncated_find_tokens_payload() {
        // FindTokens with success=1 but missing the num_tokens field
        let mut rest = Vec::new();
        push_u32(&mut rest, 1); // success = 1, but no num_tokens follows
        let payload = token_payload(DemonTokenCommand::FindTokens, &rest);

        let events = EventBus::default();
        let result = handle_token_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        // format_found_tokens reads num_tokens — should fail on truncated payload
        assert!(result.is_err(), "truncated FindTokens should fail");
    }

    #[tokio::test]
    async fn handle_truncated_privs_get_or_list_payload() {
        let payload = token_payload(DemonTokenCommand::PrivsGetOrList, &[]);

        let events = EventBus::default();
        let result = handle_token_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_err(), "truncated PrivsGetOrList should fail");
    }

    #[tokio::test]
    async fn handle_all_subcommands_return_none() {
        // Verify every successful subcommand returns Ok(None) — no response payload.
        let test_cases: Vec<Vec<u8>> = {
            let mut cases = Vec::new();

            // Impersonate (success)
            let mut r = Vec::new();
            push_u32(&mut r, 1);
            push_string(&mut r, "user");
            cases.push(token_payload(DemonTokenCommand::Impersonate, &r));

            // Steal
            let mut r = Vec::new();
            push_utf16(&mut r, "user");
            push_u32(&mut r, 1);
            push_u32(&mut r, 2);
            cases.push(token_payload(DemonTokenCommand::Steal, &r));

            // List (empty)
            cases.push(token_payload(DemonTokenCommand::List, &[]));

            // PrivsGetOrList (list mode, empty)
            let mut r = Vec::new();
            push_u32(&mut r, 1);
            cases.push(token_payload(DemonTokenCommand::PrivsGetOrList, &r));

            // Make (empty → error path)
            cases.push(token_payload(DemonTokenCommand::Make, &[]));

            // GetUid
            let mut r = Vec::new();
            push_u32(&mut r, 0);
            push_utf16(&mut r, "user");
            cases.push(token_payload(DemonTokenCommand::GetUid, &r));

            // Revert
            let mut r = Vec::new();
            push_u32(&mut r, 1);
            cases.push(token_payload(DemonTokenCommand::Revert, &r));

            // Remove
            let mut r = Vec::new();
            push_u32(&mut r, 1);
            push_u32(&mut r, 0);
            cases.push(token_payload(DemonTokenCommand::Remove, &r));

            // Clear
            cases.push(token_payload(DemonTokenCommand::Clear, &[]));

            // FindTokens (failure path)
            let mut r = Vec::new();
            push_u32(&mut r, 0);
            cases.push(token_payload(DemonTokenCommand::FindTokens, &r));

            cases
        };

        for (i, payload) in test_cases.iter().enumerate() {
            let events = EventBus::default();
            let _rx = events.subscribe();
            let result = handle_token_callback(&events, AGENT_ID, REQUEST_ID, payload).await;
            assert!(result.is_ok(), "case {i} should succeed");
            assert_eq!(result.expect("unwrap"), None, "case {i} should return None");
        }
    }
}
