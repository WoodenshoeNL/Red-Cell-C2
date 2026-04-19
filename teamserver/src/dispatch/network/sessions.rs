//! Handlers for session/user `CommandNet` subcommands.
//!
//! Covers: Logons (logged-on user enumeration), Sessions (active SMB sessions),
//! and Users (local user listing with admin flag).

use super::super::{CallbackParser, CommandDispatchError};

type HandlerResult = Result<(&'static str, String, Option<String>), CommandDispatchError>;

pub(super) fn handle_logons(parser: &mut CallbackParser<'_>) -> HandlerResult {
    let target = parser.read_utf16("net logons target")?;
    let mut users = Vec::new();
    while !parser.is_empty() {
        users.push(parser.read_utf16("net logon user")?);
    }
    let mut output = String::from(" Usernames\n ---------\n");
    for user in &users {
        output.push_str(&format!("  {user}\n"));
    }
    Ok((
        "Info",
        format!("Logged on users at {target} [{}]: ", users.len()),
        Some(output.trim_end().to_owned()),
    ))
}

pub(super) fn handle_sessions(parser: &mut CallbackParser<'_>) -> HandlerResult {
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
    Ok((
        "Info",
        format!("Sessions for {target} [{}]: ", rows.len()),
        Some(format_net_sessions(&rows)),
    ))
}

pub(super) fn handle_users(parser: &mut CallbackParser<'_>) -> HandlerResult {
    let target = parser.read_utf16("net users target")?;
    let mut users = Vec::new();
    while !parser.is_empty() {
        let username = parser.read_utf16("net user name")?;
        let is_admin = parser.read_bool("net user admin")?;
        users.push((username, is_admin));
    }
    let mut output = String::new();
    for (username, is_admin) in &users {
        output.push_str(&format!(" - {username}{}\n", if *is_admin { " (Admin)" } else { "" }));
    }
    Ok(("Info", format!("Users on {target}: "), Some(output.trim_end().to_owned())))
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
