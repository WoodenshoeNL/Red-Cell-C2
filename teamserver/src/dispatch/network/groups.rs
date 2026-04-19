//! Handlers for share/group `CommandNet` subcommands.
//!
//! Covers: Share (network share enumeration), LocalGroup (local group listing),
//! and Group (domain group listing).

use super::super::{CallbackParser, CommandDispatchError};

type HandlerResult = Result<(&'static str, String, Option<String>), CommandDispatchError>;

pub(super) fn handle_share(parser: &mut CallbackParser<'_>) -> HandlerResult {
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
    Ok(("Info", format!("Shares for {target} [{}]: ", rows.len()), Some(format_net_shares(&rows))))
}

pub(super) fn handle_local_group(parser: &mut CallbackParser<'_>) -> HandlerResult {
    let target = parser.read_utf16("net localgroup target")?;
    let mut rows = Vec::new();
    while !parser.is_empty() {
        rows.push((
            parser.read_utf16("net localgroup name")?,
            parser.read_utf16("net localgroup description")?,
        ));
    }
    Ok(("Info", format!("Local Groups for {target}: "), Some(format_net_group_descriptions(&rows))))
}

pub(super) fn handle_group(parser: &mut CallbackParser<'_>) -> HandlerResult {
    let target = parser.read_utf16("net group target")?;
    let mut rows = Vec::new();
    while !parser.is_empty() {
        rows.push((
            parser.read_utf16("net group name")?,
            parser.read_utf16("net group description")?,
        ));
    }
    Ok(("Info", format!("List groups on {target}: "), Some(format_net_group_descriptions(&rows))))
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
