//! Private per-command task-builder helpers.
//!
//! These functions are called exclusively from [`super`] and are not part of
//! the public API.  They are `pub(super)` so the parent module can call them
//! after dispatching on the command string.

use std::collections::BTreeMap;

use base64::Engine;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::AgentTaskInfo;

pub(super) fn process_kill_info(agent_id: &str, pid: u32) -> AgentTaskInfo {
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandProc).to_string(),
        command_line: format!("proc kill {pid}"),
        command: Some("proc".to_owned()),
        sub_command: Some("kill".to_owned()),
        arguments: Some(pid.to_string()),
        extra: BTreeMap::from([("Args".to_owned(), serde_json::Value::String(pid.to_string()))]),
        ..AgentTaskInfo::default()
    }
}

/// Builds a task with a single command ID and optional arguments string.
pub(super) fn simple_task(
    agent_id: &str,
    command_line: &str,
    demon_cmd: DemonCommand,
    command: &str,
    arguments: Option<String>,
) -> AgentTaskInfo {
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(demon_cmd).to_string(),
        command_line: command_line.to_owned(),
        command: Some(command.to_owned()),
        arguments,
        ..AgentTaskInfo::default()
    }
}

pub(super) fn sleep_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next(); // skip "sleep"
    let delay = parts.next().ok_or_else(|| "Usage: sleep <seconds> [jitter%]".to_owned())?;
    let jitter = parts.next().unwrap_or("0");
    let delay_val: u32 = delay.parse().map_err(|_| format!("Invalid delay `{delay}`."))?;
    let jitter_val: u32 =
        jitter.trim_end_matches('%').parse().map_err(|_| format!("Invalid jitter `{jitter}`."))?;
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandSleep).to_string(),
        command_line: command_line.to_owned(),
        command: Some("sleep".to_owned()),
        arguments: Some(format!("{delay_val};{jitter_val}")),
        ..AgentTaskInfo::default()
    })
}

pub(super) fn filesystem_copy_or_move_task(
    agent_id: &str,
    command_line: &str,
    sub_command: &str,
) -> Result<AgentTaskInfo, String> {
    let rest = super::rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let src = parts.next().ok_or_else(|| format!("Usage: {sub_command} <src> <dst>"))?;
    let dst = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Usage: {sub_command} <src> <dst>"))?;
    Ok(super::filesystem_task(agent_id, command_line, sub_command, Some(format!("{src};{dst}"))))
}

pub(super) fn upload_console_task(
    agent_id: &str,
    command_line: &str,
) -> Result<AgentTaskInfo, String> {
    let rest = super::rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let local_path = parts.next().ok_or_else(|| "Usage: upload <local> <remote>".to_owned())?;
    let remote_path = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Usage: upload <local> <remote>".to_owned())?;
    let content =
        std::fs::read(local_path).map_err(|err| format!("Failed to read `{local_path}`: {err}"))?;
    let remote_b64 = base64::engine::general_purpose::STANDARD.encode(remote_path.as_bytes());
    let content_b64 = base64::engine::general_purpose::STANDARD.encode(&content);
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command_line: command_line.to_owned(),
        command: Some("fs".to_owned()),
        sub_command: Some("upload".to_owned()),
        arguments: Some(format!("{remote_b64};{content_b64}")),
        ..AgentTaskInfo::default()
    })
}

pub(super) fn token_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next(); // skip "token"
    let sub = parts.next().ok_or_else(|| {
        "Usage: token <list|steal|make|impersonate|revert|privs|uid|clear> [args]".to_owned()
    })?;
    let sub_lower = sub.to_ascii_lowercase();
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandToken).to_string(),
        command_line: command_line.to_owned(),
        command: Some("token".to_owned()),
        sub_command: Some(sub_lower),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

pub(super) fn inline_execute_task(
    agent_id: &str,
    command_line: &str,
) -> Result<AgentTaskInfo, String> {
    let rest = super::rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let bof_path =
        parts.next().ok_or_else(|| "Usage: inline-execute <bof-path> [args]".to_owned())?;
    let bof_args = parts.next().unwrap_or_default().trim().to_owned();
    let binary =
        std::fs::read(bof_path).map_err(|err| format!("Failed to read `{bof_path}`: {err}"))?;
    let binary_b64 = base64::engine::general_purpose::STANDARD.encode(&binary);
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandInlineExecute).to_string(),
        command_line: command_line.to_owned(),
        command: Some("inline-execute".to_owned()),
        arguments: Some(if bof_args.is_empty() {
            binary_b64
        } else {
            format!("{binary_b64};{bof_args}")
        }),
        ..AgentTaskInfo::default()
    })
}

pub(super) fn inject_dll_console_task(
    agent_id: &str,
    command_line: &str,
) -> Result<AgentTaskInfo, String> {
    let rest = super::rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let pid_str = parts.next().ok_or_else(|| "Usage: inject-dll <pid> <dll-path>".to_owned())?;
    let dll_path = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Usage: inject-dll <pid> <dll-path>".to_owned())?;
    let pid: u32 = pid_str.parse().map_err(|_| format!("Invalid PID `{pid_str}`."))?;
    let binary =
        std::fs::read(dll_path).map_err(|err| format!("Failed to read `{dll_path}`: {err}"))?;
    let binary_b64 = base64::engine::general_purpose::STANDARD.encode(&binary);
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandInjectDll).to_string(),
        command_line: command_line.to_owned(),
        command: Some("inject-dll".to_owned()),
        extra: BTreeMap::from([
            ("PID".to_owned(), serde_json::Value::Number(serde_json::Number::from(pid))),
            ("Binary".to_owned(), serde_json::Value::String(binary_b64)),
        ]),
        ..AgentTaskInfo::default()
    })
}

pub(super) fn inject_shellcode_console_task(
    agent_id: &str,
    command_line: &str,
) -> Result<AgentTaskInfo, String> {
    let rest = super::rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let pid_str =
        parts.next().ok_or_else(|| "Usage: inject-shellcode <pid> <bin-path>".to_owned())?;
    let bin_path = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Usage: inject-shellcode <pid> <bin-path>".to_owned())?;
    let pid: u32 = pid_str.parse().map_err(|_| format!("Invalid PID `{pid_str}`."))?;
    let binary =
        std::fs::read(bin_path).map_err(|err| format!("Failed to read `{bin_path}`: {err}"))?;
    let binary_b64 = base64::engine::general_purpose::STANDARD.encode(&binary);
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandInjectShellcode).to_string(),
        command_line: command_line.to_owned(),
        command: Some("inject-shellcode".to_owned()),
        extra: BTreeMap::from([
            ("PID".to_owned(), serde_json::Value::Number(serde_json::Number::from(pid))),
            ("Binary".to_owned(), serde_json::Value::String(binary_b64)),
        ]),
        ..AgentTaskInfo::default()
    })
}

pub(super) fn spawn_dll_console_task(
    agent_id: &str,
    command_line: &str,
) -> Result<AgentTaskInfo, String> {
    let rest = super::rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let dll_path = parts.next().ok_or_else(|| "Usage: spawn-dll <dll-path> [args]".to_owned())?;
    let args = parts.next().unwrap_or_default().trim().to_owned();
    let binary =
        std::fs::read(dll_path).map_err(|err| format!("Failed to read `{dll_path}`: {err}"))?;
    let binary_b64 = base64::engine::general_purpose::STANDARD.encode(&binary);
    let args_b64 = if args.is_empty() {
        String::new()
    } else {
        base64::engine::general_purpose::STANDARD.encode(args.as_bytes())
    };
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandSpawnDll).to_string(),
        command_line: command_line.to_owned(),
        command: Some("spawn-dll".to_owned()),
        extra: BTreeMap::from([
            ("Binary".to_owned(), serde_json::Value::String(binary_b64)),
            ("Arguments".to_owned(), serde_json::Value::String(args_b64)),
        ]),
        ..AgentTaskInfo::default()
    })
}

pub(super) fn net_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next(); // skip "net"
    let sub = parts.next().ok_or_else(|| {
        "Usage: net <domain|logons|sessions|computers|dclist|share|localgroup|group> [args]"
            .to_owned()
    })?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandNet).to_string(),
        command_line: command_line.to_owned(),
        command: Some("net".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

pub(super) fn pivot_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub =
        parts.next().ok_or_else(|| "Usage: pivot <list|connect|disconnect> [args]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandPivot).to_string(),
        command_line: command_line.to_owned(),
        command: Some("pivot".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

pub(super) fn rportfwd_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub =
        parts.next().ok_or_else(|| "Usage: rportfwd <add|remove|list|clear> [args]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    let sub_lower = sub.to_ascii_lowercase();
    let sub_full = format!("rportfwd {sub_lower}");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandSocket).to_string(),
        command_line: command_line.to_owned(),
        command: Some("socket".to_owned()),
        sub_command: Some(sub_full),
        arguments: if args.is_empty() { None } else { Some(args.replace(' ', ";")) },
        ..AgentTaskInfo::default()
    })
}

pub(super) fn kerberos_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub =
        parts.next().ok_or_else(|| "Usage: kerberos <luid|klist|purge|ptt> [args]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandKerberos).to_string(),
        command_line: command_line.to_owned(),
        command: Some("kerberos".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

pub(super) fn config_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub = parts.next().ok_or_else(|| "Usage: config <option> [value]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", super::next_task_id()),
        command_id: u32::from(DemonCommand::CommandConfig).to_string(),
        command_line: command_line.to_owned(),
        command: Some("config".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}
