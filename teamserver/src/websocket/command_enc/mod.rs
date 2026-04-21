//! Task-encoding helpers: build agent jobs and encode Demon binary payloads.

mod helpers;
mod payload;

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use helpers::{parse_bool_field, parse_u32_field};
use payload::{
    encode_fs_payload, encode_inject_dll_payload, encode_inject_shellcode_payload,
    encode_kerberos_payload, encode_proc_command_payload, encode_proc_list_payload,
    encode_socket_payload, encode_spawn_dll_payload, encode_token_payload,
};
// Re-export binary helpers consumed by sibling modules (upload, websocket mod).
pub(super) use helpers::{
    encode_utf16, random_u32, write_len_prefixed_bytes, write_u32, write_u64,
};
// Re-export subcommand parsers used by sibling modules (dispatch/agents).
pub(super) use payload::{filesystem_subcommand, socket_command};
use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};
use red_cell_common::operator::FlatInfo;
use serde_json::Value;
use time::OffsetDateTime;
use tracing::debug;

use super::AgentCommandError;
use crate::Job;

// ── Job builders ────────────────────────────────────────────────────────────

#[cfg(test)]
pub(super) fn build_job(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Job, AgentCommandError> {
    let mut jobs = build_jobs(info, "")?;
    jobs.pop().ok_or(AgentCommandError::MissingField { field: "CommandID" })
}

pub(super) fn build_jobs(
    info: &red_cell_common::operator::AgentTaskInfo,
    operator: &str,
) -> Result<Vec<Job>, AgentCommandError> {
    let command_id = info.command_id.trim();
    let task_id_trimmed = info.task_id.trim();
    let request_id = u32::from_str_radix(task_id_trimmed, 16)
        .map_err(|_| AgentCommandError::InvalidTaskId { task_id: info.task_id.clone() })?;

    if is_teamserver_note_command(info) {
        return Err(AgentCommandError::MissingNote);
    }

    let command = if is_exit_command(info) {
        u32::from(DemonCommand::CommandExit)
    } else {
        command_id.parse::<u32>().map_err(|_| AgentCommandError::InvalidCommandId {
            command_id: command_id.to_owned(),
        })?
    };
    let created_at = OffsetDateTime::now_utc().unix_timestamp().to_string();

    if command == u32::from(DemonCommand::CommandFs)
        && matches!(filesystem_subcommand(info)?, DemonFilesystemCommand::Upload)
    {
        return build_upload_jobs(info, request_id, &created_at, operator);
    }

    let payload = task_payload(info, command)?;
    Ok(vec![Job {
        command,
        request_id,
        payload,
        command_line: info.command_line.clone(),
        task_id: info.task_id.clone(),
        created_at,
        operator: operator.to_owned(),
    }])
}

fn task_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
    command: u32,
) -> Result<Vec<u8>, AgentCommandError> {
    if is_exit_command(info) {
        return Ok(exit_method(info).to_be_bytes().to_vec());
    }

    if let Some(payload) = raw_task_payload(info)? {
        return Ok(payload);
    }

    if command == u32::from(DemonCommand::CommandProcList) {
        return Ok(encode_proc_list_payload(info));
    }

    if command == u32::from(DemonCommand::CommandFs) {
        return encode_fs_payload(info);
    }

    if command == u32::from(DemonCommand::CommandProc) {
        return encode_proc_command_payload(info);
    }

    if command == u32::from(DemonCommand::CommandInjectShellcode) {
        return encode_inject_shellcode_payload(info);
    }

    if command == u32::from(DemonCommand::CommandToken) {
        return encode_token_payload(info);
    }

    if command == u32::from(DemonCommand::CommandSocket) {
        return encode_socket_payload(info);
    }

    if command == u32::from(DemonCommand::CommandKerberos) {
        return encode_kerberos_payload(info);
    }

    if command == u32::from(DemonCommand::CommandInjectDll) {
        return encode_inject_dll_payload(info);
    }

    if command == u32::from(DemonCommand::CommandSpawnDll) {
        return encode_spawn_dll_payload(info);
    }

    // Allow known Demon commands to proceed with an empty payload (they may
    // legitimately require none), but reject unrecognised numeric command IDs
    // that also lack an explicit raw payload — those are protocol validation
    // errors that should not be silently enqueued.
    if DemonCommand::try_from(command).is_err() {
        return Err(AgentCommandError::UnsupportedCommandId { command_id: command });
    }

    Ok(Vec::new())
}

pub(super) use super::upload::build_upload_jobs;

// ── Note / exit helpers ─────────────────────────────────────────────────────

pub(super) fn note_from_task(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Option<String>, AgentCommandError> {
    if !is_teamserver_note_command(info) {
        return Ok(None);
    }

    let note = info
        .arguments
        .clone()
        .or_else(|| info.task_message.clone())
        .or_else(|| flat_info_string_from_extra(&info.extra, &["Note", "note"]))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(AgentCommandError::MissingNote)?;

    if note.len() > red_cell_common::operator::MAX_AGENT_NOTE_LEN {
        return Err(AgentCommandError::NoteTooLong {
            length: note.len(),
            limit: red_cell_common::operator::MAX_AGENT_NOTE_LEN,
        });
    }

    Ok(Some(note))
}

pub(super) fn is_teamserver_note_command(info: &red_cell_common::operator::AgentTaskInfo) -> bool {
    info.command_id.eq_ignore_ascii_case("Teamserver")
        && info.command.as_deref().is_some_and(|command| {
            command.eq_ignore_ascii_case("note") || command.eq_ignore_ascii_case("agent::note")
        })
}

pub(super) fn is_exit_command(info: &red_cell_common::operator::AgentTaskInfo) -> bool {
    info.command_id.trim() == u32::from(DemonCommand::CommandExit).to_string()
        || info.command.as_deref().is_some_and(|command| {
            command.eq_ignore_ascii_case("kill") || command.eq_ignore_ascii_case("agent::kill")
        })
}

fn exit_method(info: &red_cell_common::operator::AgentTaskInfo) -> u32 {
    match info.arguments.as_deref() {
        Some(argument) if argument.eq_ignore_ascii_case("process") => 2,
        _ => 1,
    }
}

// ── Agent ID parsing ────────────────────────────────────────────────────────

pub(super) fn parse_agent_id(agent_id: &str) -> Result<u32, AgentCommandError> {
    let trimmed = agent_id.trim();
    if trimmed.is_empty() {
        return Err(AgentCommandError::MissingAgentId);
    }

    u32::from_str_radix(trimmed.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|_| AgentCommandError::InvalidAgentId { agent_id: trimmed.to_owned() })
}

// ── Field extraction helpers ────────────────────────────────────────────────

pub(super) fn flat_info_string(info: &FlatInfo, keys: &[&str]) -> Option<String> {
    flat_info_string_from_extra(&info.fields, keys)
}

pub(super) fn flat_info_string_from_extra(
    extra: &BTreeMap<String, Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| extra.get(*key)).and_then(Value::as_str).map(ToOwned::to_owned)
}

fn raw_task_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Option<Vec<u8>>, AgentCommandError> {
    if let Some(payload) = flat_info_string_from_extra(&info.extra, &["PayloadBase64"]) {
        let decoded = BASE64_STANDARD.decode(payload.trim()).map_err(|error| {
            AgentCommandError::InvalidBase64Field {
                field: "PayloadBase64".to_owned(),
                message: error.to_string(),
            }
        })?;
        return Ok(Some(decoded));
    }

    Ok(flat_info_string_from_extra(&info.extra, &["Payload"]).map(|payload| payload.into_bytes()))
}

pub(super) fn required_string(
    info: &red_cell_common::operator::AgentTaskInfo,
    keys: &[&str],
    field: &'static str,
) -> Result<String, AgentCommandError> {
    string_field(info, keys).ok_or(AgentCommandError::MissingField { field })
}

fn required_u32(
    info: &red_cell_common::operator::AgentTaskInfo,
    keys: &[&str],
    field: &'static str,
) -> Result<u32, AgentCommandError> {
    let value = required_string(info, keys, field)?;
    parse_u32_field(field, &value)
}

fn optional_u32(info: &red_cell_common::operator::AgentTaskInfo, keys: &[&str]) -> Option<u32> {
    string_field(info, keys).and_then(|value| {
        let trimmed = value.trim();
        match trimmed.parse::<u32>() {
            Ok(n) => Some(n),
            Err(err) => {
                debug!(
                    field = ?keys,
                    value = trimmed,
                    %err,
                    "optional_u32: ignoring unparseable value"
                );
                None
            }
        }
    })
}

fn optional_base64(
    info: &red_cell_common::operator::AgentTaskInfo,
    keys: &[&str],
) -> Result<Option<Vec<u8>>, AgentCommandError> {
    string_field(info, keys).map(|value| decode_base64_field(keys[0], &value)).transpose()
}

fn decode_base64_required(
    info: &red_cell_common::operator::AgentTaskInfo,
    keys: &[&str],
    field: &'static str,
) -> Result<Vec<u8>, AgentCommandError> {
    let value = required_string(info, keys, field)?;
    decode_base64_field(field, &value)
}

fn decode_base64_field(field: &str, value: &str) -> Result<Vec<u8>, AgentCommandError> {
    BASE64_STANDARD.decode(value.trim()).map_err(|error| AgentCommandError::InvalidBase64Field {
        field: field.to_owned(),
        message: error.to_string(),
    })
}

fn string_field(info: &red_cell_common::operator::AgentTaskInfo, keys: &[&str]) -> Option<String> {
    for key in keys {
        match *key {
            "Arguments" => {
                if let Some(value) = info.arguments.clone() {
                    return Some(value);
                }
            }
            "SubCommand" => {
                if let Some(value) = info.sub_command.clone() {
                    return Some(value);
                }
            }
            _ => {}
        }

        if let Some(value) = info.extra.get(*key) {
            match value {
                Value::String(text) => return Some(text.clone()),
                Value::Bool(flag) => return Some(flag.to_string()),
                Value::Number(number) => return Some(number.to_string()),
                _ => {}
            }
        }
    }

    None
}

fn extra_bool(info: &red_cell_common::operator::AgentTaskInfo, keys: &[&str]) -> Option<bool> {
    for key in keys {
        let Some(value) = info.extra.get(*key) else {
            continue;
        };
        match value {
            Value::Bool(flag) => return Some(*flag),
            Value::String(text) => {
                if let Ok(flag) = parse_bool_field(key, text) {
                    return Some(flag);
                }
            }
            Value::Number(number) => return Some(number.as_u64().unwrap_or_default() != 0),
            _ => {}
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::operator::{AgentTaskInfo, MAX_AGENT_NOTE_LEN};

    fn note_task(note: String) -> AgentTaskInfo {
        AgentTaskInfo {
            command_id: "Teamserver".to_owned(),
            command: Some("agent::note".to_owned()),
            arguments: Some(note),
            ..AgentTaskInfo::default()
        }
    }

    #[test]
    fn note_from_task_accepts_note_at_limit() {
        let note = "x".repeat(MAX_AGENT_NOTE_LEN);
        let info = note_task(note.clone());

        let extracted = note_from_task(&info).expect("note at limit should be accepted");
        assert_eq!(extracted, Some(note));
    }

    #[test]
    fn note_from_task_rejects_oversized_note() {
        let note = "x".repeat(MAX_AGENT_NOTE_LEN + 1);
        let info = note_task(note);

        let err = note_from_task(&info).expect_err("oversized note should be rejected");
        match err {
            AgentCommandError::NoteTooLong { length, limit } => {
                assert_eq!(length, MAX_AGENT_NOTE_LEN + 1);
                assert_eq!(limit, MAX_AGENT_NOTE_LEN);
            }
            other => panic!("expected NoteTooLong, got {other:?}"),
        }
    }

    #[test]
    fn note_from_task_rejects_oversized_note_from_task_message() {
        let note = "y".repeat(MAX_AGENT_NOTE_LEN + 1024);
        let info = AgentTaskInfo {
            command_id: "Teamserver".to_owned(),
            command: Some("agent::note".to_owned()),
            task_message: Some(note),
            ..AgentTaskInfo::default()
        };

        let err = note_from_task(&info).expect_err("oversized note_message should be rejected");
        assert!(matches!(err, AgentCommandError::NoteTooLong { .. }));
    }

    #[test]
    fn note_from_task_rejects_missing_note() {
        let info = AgentTaskInfo {
            command_id: "Teamserver".to_owned(),
            command: Some("agent::note".to_owned()),
            ..AgentTaskInfo::default()
        };

        let err = note_from_task(&info).expect_err("empty note should be rejected");
        assert!(matches!(err, AgentCommandError::MissingNote));
    }

    #[test]
    fn note_from_task_returns_none_for_non_note_commands() {
        let info = AgentTaskInfo {
            command_id: "42".to_owned(),
            command: Some("ls".to_owned()),
            arguments: Some("x".repeat(MAX_AGENT_NOTE_LEN + 1024)),
            ..AgentTaskInfo::default()
        };

        let extracted =
            note_from_task(&info).expect("non-note commands should not trigger validation");
        assert_eq!(extracted, None);
    }
}
