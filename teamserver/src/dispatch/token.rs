use red_cell_common::demon::{DemonCommand, DemonTokenCommand};

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
    for _ in 0..num_tokens {
        if parser.is_empty() {
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
