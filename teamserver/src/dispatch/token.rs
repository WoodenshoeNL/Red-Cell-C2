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
    use super::super::CallbackParser;

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
        let output = super::format_token_list(&mut parser).unwrap();
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
        let output = super::format_token_list(&mut parser).unwrap();
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
        let output = super::format_token_list(&mut parser).unwrap();
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
        let output = super::format_token_list(&mut parser).unwrap();
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
        let output = super::format_token_list(&mut parser).unwrap();
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
        let output = super::format_token_privs_list(&mut parser).unwrap();
        assert!(output.contains("SeDebugPrivilege :: Enabled"));
        assert!(output.contains("SeBackupPrivilege :: Adjusted"));
        assert!(output.contains("SeShutdownPrivilege :: Disabled"));
        assert!(output.contains("SeRestorePrivilege :: Unknown"));
    }

    #[test]
    fn format_token_privs_list_empty() {
        let buf = Vec::new();
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).unwrap();
        assert_eq!(output, "\n");
    }

    #[test]
    fn format_token_privs_list_single_enabled() {
        let mut buf = Vec::new();
        push_string(&mut buf, "SeDebugPrivilege");
        push_u32(&mut buf, 3);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).unwrap();
        assert_eq!(output, "\n SeDebugPrivilege :: Enabled\n");
    }

    #[test]
    fn format_token_privs_list_single_adjusted() {
        let mut buf = Vec::new();
        push_string(&mut buf, "SeBackupPrivilege");
        push_u32(&mut buf, 2);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).unwrap();
        assert_eq!(output, "\n SeBackupPrivilege :: Adjusted\n");
    }

    #[test]
    fn format_token_privs_list_single_disabled() {
        let mut buf = Vec::new();
        push_string(&mut buf, "SeShutdownPrivilege");
        push_u32(&mut buf, 0);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).unwrap();
        assert_eq!(output, "\n SeShutdownPrivilege :: Disabled\n");
    }

    #[test]
    fn format_token_privs_list_state_1_is_unknown() {
        let mut buf = Vec::new();
        push_string(&mut buf, "SeImpersonatePrivilege");
        push_u32(&mut buf, 1);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).unwrap();
        assert_eq!(output, "\n SeImpersonatePrivilege :: Unknown\n");
    }

    #[test]
    fn format_token_privs_list_large_unknown_state() {
        let mut buf = Vec::new();
        push_string(&mut buf, "SeLoadDriverPrivilege");
        push_u32(&mut buf, 255);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_token_privs_list(&mut parser).unwrap();
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
        let output = super::format_token_privs_list(&mut parser).unwrap();
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
        let output = super::format_found_tokens(&mut parser).unwrap();
        assert_eq!(get_integrity_from_output(&output), "Low");
    }

    #[test]
    fn format_found_tokens_integrity_0x1000_is_low() {
        let buf = build_found_token_payload(0x1000);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).unwrap();
        assert_eq!(get_integrity_from_output(&output), "Low");
    }

    #[test]
    fn format_found_tokens_integrity_0x1001_falls_through_to_low() {
        // This is the gap: 0x1001 is above LOW_RID but below MEDIUM_RID,
        // and falls through all range checks to the else branch ("Low").
        let buf = build_found_token_payload(0x1001);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).unwrap();
        assert_eq!(get_integrity_from_output(&output), "Low");
    }

    #[test]
    fn format_found_tokens_integrity_0x1fff_falls_through_to_low() {
        let buf = build_found_token_payload(0x1FFF);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).unwrap();
        assert_eq!(get_integrity_from_output(&output), "Low");
    }

    #[test]
    fn format_found_tokens_integrity_0x2000_is_medium() {
        let buf = build_found_token_payload(0x2000);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).unwrap();
        assert_eq!(get_integrity_from_output(&output), "Medium");
    }

    #[test]
    fn format_found_tokens_integrity_0x2fff_is_medium() {
        let buf = build_found_token_payload(0x2FFF);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).unwrap();
        assert_eq!(get_integrity_from_output(&output), "Medium");
    }

    #[test]
    fn format_found_tokens_integrity_0x3000_is_high() {
        let buf = build_found_token_payload(0x3000);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).unwrap();
        assert_eq!(get_integrity_from_output(&output), "High");
    }

    #[test]
    fn format_found_tokens_integrity_0x3fff_is_high() {
        let buf = build_found_token_payload(0x3FFF);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).unwrap();
        assert_eq!(get_integrity_from_output(&output), "High");
    }

    #[test]
    fn format_found_tokens_integrity_0x4000_is_system() {
        let buf = build_found_token_payload(0x4000);
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).unwrap();
        assert_eq!(get_integrity_from_output(&output), "System");
    }

    #[test]
    fn format_found_tokens_zero_count() {
        let mut buf = Vec::new();
        push_u32(&mut buf, 0); // num_tokens = 0
        let mut parser = CallbackParser::new(&buf, 0);
        let output = super::format_found_tokens(&mut parser).unwrap();
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
        let output = super::format_found_tokens(&mut parser).unwrap();
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
            let output = super::format_found_tokens(&mut parser).unwrap();
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
        let output = super::format_token_list(&mut parser).unwrap();

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
        let output = super::format_found_tokens(&mut parser).unwrap();

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
        let output = super::format_found_tokens(&mut parser).unwrap();
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
        let output = super::format_found_tokens(&mut parser).unwrap();
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
        let output = super::format_found_tokens(&mut parser).unwrap();

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
        let output = super::format_found_tokens(&mut parser).unwrap();
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
        let output = super::format_found_tokens(&mut parser).unwrap();
        // For delegation (impersonation_level=3), remote_auth should be "Yes"
        // The table has: LocalAuth=Yes, RemoteAuth=Yes
        // Count "Yes" occurrences — should appear for both LocalAuth and RemoteAuth
        let yes_count = output.matches("Yes").count();
        assert!(
            yes_count >= 2,
            "expected at least 2 'Yes' (Local+Remote) for delegation: {output}"
        );
    }
}
