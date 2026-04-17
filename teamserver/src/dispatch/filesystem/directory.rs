//! Directory operation handlers for `CommandFs` callbacks.
//!
//! Handles the Dir, Mkdir, Cd, GetPwd, Remove, Copy and Move subcommands.
//! Each helper is invoked by `handle_filesystem_callback` in `mod.rs` with
//! an already-positioned `CallbackParser` (subcommand byte consumed).

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};
use serde_json::Value;

use crate::EventBus;

use super::super::transfer::byte_count;
use super::super::{
    CallbackParser, CommandDispatchError, agent_response_event, agent_response_event_with_extra,
};

pub(super) fn handle_dir(
    events: &EventBus,
    parser: &mut CallbackParser<'_>,
    agent_id: u32,
    request_id: u32,
) -> Result<(), CommandDispatchError> {
    let explorer = parser.read_bool("filesystem dir explorer")?;
    let list_only = parser.read_bool("filesystem dir list only")?;
    let root_path = parser.read_utf16("filesystem dir root path")?;
    let success = parser.read_bool("filesystem dir success")?;
    let mut lines = Vec::new();
    let mut explorer_rows = Vec::new();

    if success {
        while !parser.is_empty() {
            let path = parser.read_utf16("filesystem dir path")?;
            let file_count = parser.read_u32("filesystem dir file count")?;
            let dir_count = parser.read_u32("filesystem dir dir count")?;
            let total_size =
                if list_only { None } else { Some(parser.read_u64("filesystem dir total size")?) };

            if !explorer {
                lines.push(format!(" Directory of {path}"));
                lines.push(String::new());
            }

            let item_count = file_count.checked_add(dir_count).ok_or(
                CommandDispatchError::InvalidCallbackPayload {
                    command_id: u32::from(DemonCommand::CommandFs),
                    message: format!(
                        "filesystem dir item count overflow: file_count={file_count}, dir_count={dir_count}"
                    ),
                },
            )?;
            for _ in 0..item_count {
                let name = parser.read_utf16("filesystem dir item name")?;
                if list_only {
                    lines.push(format!("{}{}", path.trim_end_matches('*'), name));
                    continue;
                }
                let is_dir = parser.read_bool("filesystem dir item is dir")?;
                let size = parser.read_u64("filesystem dir item size")?;
                let day = parser.read_u32("filesystem dir item day")?;
                let month = parser.read_u32("filesystem dir item month")?;
                let year = parser.read_u32("filesystem dir item year")?;
                let minute = parser.read_u32("filesystem dir item minute")?;
                let hour = parser.read_u32("filesystem dir item hour")?;
                let modified = format!("{day:02}/{month:02}/{year}  {hour:02}:{minute:02}");
                if explorer {
                    explorer_rows.push(Value::Object(
                        [
                            (
                                "Type".to_owned(),
                                Value::String(if is_dir { "dir" } else { "" }.to_owned()),
                            ),
                            (
                                "Size".to_owned(),
                                Value::String(if is_dir {
                                    String::new()
                                } else {
                                    byte_count(size)
                                }),
                            ),
                            ("Modified".to_owned(), Value::String(modified)),
                            ("Name".to_owned(), Value::String(name)),
                        ]
                        .into_iter()
                        .collect(),
                    ));
                } else {
                    let dir_text = if is_dir { "<DIR>" } else { "" };
                    let size_text = if is_dir { String::new() } else { byte_count(size) };
                    lines
                        .push(format!("{modified:<17}    {dir_text:<5}  {size_text:<12}   {name}"));
                }
            }

            if !explorer && !list_only && (file_count > 0 || dir_count > 0) {
                lines.push(format!(
                    "               {file_count} File(s)     {}",
                    byte_count(total_size.unwrap_or_default())
                ));
                lines.push(format!("               {dir_count} Folder(s)"));
                lines.push(String::new());
            }
        }
    }

    let output = if lines.is_empty() {
        "No file or folder was found".to_owned()
    } else {
        lines.join("\n").trim().to_owned()
    };
    let mut extra = BTreeMap::new();
    if explorer {
        extra.insert("MiscType".to_owned(), Value::String("FileExplorer".to_owned()));
        extra.insert(
            "MiscData".to_owned(),
            Value::String(
                BASE64_STANDARD.encode(
                    serde_json::to_vec(&Value::Object(
                        [
                            ("Path".to_owned(), Value::String(root_path)),
                            ("Files".to_owned(), Value::Array(explorer_rows)),
                        ]
                        .into_iter()
                        .collect(),
                    ))
                    .map_err(|error| {
                        CommandDispatchError::InvalidCallbackPayload {
                            command_id: u32::from(DemonCommand::CommandFs),
                            message: error.to_string(),
                        }
                    })?,
                ),
            ),
        );
    }
    events.broadcast(agent_response_event_with_extra(
        agent_id,
        u32::from(DemonCommand::CommandFs),
        request_id,
        "Info",
        if output == "No file or folder was found" {
            "No file or folder was found"
        } else {
            "Directory listing completed"
        },
        extra,
        output,
    )?);
    Ok(())
}

pub(super) fn handle_cd(
    events: &EventBus,
    parser: &mut CallbackParser<'_>,
    agent_id: u32,
    request_id: u32,
) -> Result<(), CommandDispatchError> {
    let path = parser.read_utf16("filesystem cd path")?;
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandFs),
        request_id,
        "Info",
        &format!("Changed directory: {path}"),
        None,
    )?);
    Ok(())
}

pub(super) fn handle_remove(
    events: &EventBus,
    parser: &mut CallbackParser<'_>,
    agent_id: u32,
    request_id: u32,
) -> Result<(), CommandDispatchError> {
    let is_dir = parser.read_bool("filesystem remove is dir")?;
    let path = parser.read_utf16("filesystem remove path")?;
    let noun = if is_dir { "directory" } else { "file" };
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandFs),
        request_id,
        "Info",
        &format!("Removed {noun}: {path}"),
        None,
    )?);
    Ok(())
}

pub(super) fn handle_mkdir(
    events: &EventBus,
    parser: &mut CallbackParser<'_>,
    agent_id: u32,
    request_id: u32,
) -> Result<(), CommandDispatchError> {
    let path = parser.read_utf16("filesystem mkdir path")?;
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandFs),
        request_id,
        "Info",
        &format!("Created directory: {path}"),
        None,
    )?);
    Ok(())
}

pub(super) fn handle_copy_move(
    events: &EventBus,
    parser: &mut CallbackParser<'_>,
    subcommand: DemonFilesystemCommand,
    agent_id: u32,
    request_id: u32,
) -> Result<(), CommandDispatchError> {
    let success = parser.read_bool("filesystem copy/move success")?;
    let from = parser.read_utf16("filesystem copy/move from")?;
    let to = parser.read_utf16("filesystem copy/move to")?;
    let is_copy = matches!(subcommand, DemonFilesystemCommand::Copy);
    let kind = if success { "Good" } else { "Error" };
    let message = if success {
        let verb = if is_copy { "copied" } else { "moved" };
        format!("Successfully {verb} file {from} to {to}")
    } else {
        let verb = if is_copy { "copy" } else { "move" };
        format!("Failed to {verb} file {from} to {to}")
    };
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandFs),
        request_id,
        kind,
        &message,
        None,
    )?);
    Ok(())
}

pub(super) fn handle_getpwd(
    events: &EventBus,
    parser: &mut CallbackParser<'_>,
    agent_id: u32,
    request_id: u32,
) -> Result<(), CommandDispatchError> {
    let path = parser.read_utf16("filesystem pwd path")?;
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandFs),
        request_id,
        "Info",
        &format!("Current directory: {path}"),
        None,
    )?);
    Ok(())
}
