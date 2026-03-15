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
