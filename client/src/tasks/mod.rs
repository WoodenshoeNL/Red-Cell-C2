//! Task-builder functions for Demon agent commands and console helpers.
//!
//! This module constructs [`OperatorMessage`] payloads that are sent to the
//! teamserver and forwarded to the agent.  All functions are pure (no UI
//! side-effects) and depend only on types from `red_cell_common` and the
//! in-file state types.

mod builders;
pub(crate) mod console;

#[allow(unused_imports)]
pub(crate) use console::*;

use std::collections::BTreeMap;

use base64::Engine;
use eframe::egui::Color32;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentTaskInfo, BuildPayloadRequestInfo, EventCode, FlatInfo, ListenerInfo, Message,
    MessageHead, NameInfo, OperatorMessage,
};

use crate::{
    InjectionTargetAction, InjectionTechnique, PayloadDialogState, human_size,
    normalized_process_arch,
};

// ─── Task builders ───────────────────────────────────────────────────────────

pub(crate) fn build_kill_task(agent_id: &str, operator: &str) -> OperatorMessage {
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandExit).to_string(),
            command_line: "kill".to_owned(),
            command: Some("kill".to_owned()),
            ..AgentTaskInfo::default()
        },
    )
}

pub(crate) fn build_process_list_task(agent_id: &str, operator: &str) -> OperatorMessage {
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandProcList).to_string(),
            command_line: "ps".to_owned(),
            command: Some("ps".to_owned()),
            extra: BTreeMap::from([(
                "FromProcessManager".to_owned(),
                serde_json::Value::Bool(true),
            )]),
            ..AgentTaskInfo::default()
        },
    )
}

pub(crate) fn build_process_kill_task(agent_id: &str, pid: u32, operator: &str) -> OperatorMessage {
    build_agent_task(operator, builders::process_kill_info(agent_id, pid))
}

pub(crate) fn build_process_injection_task(
    agent_id: &str,
    pid: u32,
    arch: &str,
    technique: InjectionTechnique,
    binary: &[u8],
    arguments: &str,
    action: InjectionTargetAction,
    operator: &str,
) -> OperatorMessage {
    let command_line = format!(
        "{} pid={} arch={} {}",
        action.label().to_ascii_lowercase(),
        pid,
        normalized_process_arch(arch),
        human_size(binary.len() as u64)
    );
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandInjectShellcode).to_string(),
            command_line,
            command: Some("shellcode".to_owned()),
            sub_command: Some("inject".to_owned()),
            extra: BTreeMap::from([
                ("Way".to_owned(), serde_json::Value::String("Inject".to_owned())),
                (
                    "Technique".to_owned(),
                    serde_json::Value::String(technique.as_wire_value().to_owned()),
                ),
                ("Arch".to_owned(), serde_json::Value::String(normalized_process_arch(arch))),
                (
                    "Binary".to_owned(),
                    serde_json::Value::String(
                        base64::engine::general_purpose::STANDARD.encode(binary),
                    ),
                ),
                ("PID".to_owned(), serde_json::Value::String(pid.to_string())),
                ("Action".to_owned(), serde_json::Value::String(action.label().to_owned())),
                (
                    "Arguments".to_owned(),
                    serde_json::Value::String(
                        base64::engine::general_purpose::STANDARD.encode(arguments.as_bytes()),
                    ),
                ),
            ]),
            ..AgentTaskInfo::default()
        },
    )
}

pub(crate) fn build_note_task(agent_id: &str, note: &str, operator: &str) -> OperatorMessage {
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: "Teamserver".to_owned(),
            command_line: "note".to_owned(),
            command: Some("note".to_owned()),
            arguments: Some(note.to_owned()),
            ..AgentTaskInfo::default()
        },
    )
}

pub(crate) fn build_chat_message(operator: Option<&str>, message: &str) -> Option<OperatorMessage> {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(OperatorMessage::ChatMessage(Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: operator.unwrap_or_default().to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo {
            fields: std::collections::BTreeMap::from([(
                "Message".to_owned(),
                serde_json::Value::String(trimmed.to_owned()),
            )]),
        },
    }))
}

fn build_agent_task(operator: &str, info: AgentTaskInfo) -> OperatorMessage {
    OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: red_cell_common::operator::EventCode::Session,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info,
    })
}

pub(crate) fn build_listener_new(info: ListenerInfo, operator: &str) -> OperatorMessage {
    OperatorMessage::ListenerNew(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info,
    })
}

pub(crate) fn build_listener_edit(info: ListenerInfo, operator: &str) -> OperatorMessage {
    OperatorMessage::ListenerEdit(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info,
    })
}

pub(crate) fn build_listener_remove(name: &str, operator: &str) -> OperatorMessage {
    OperatorMessage::ListenerRemove(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: NameInfo { name: name.to_owned() },
    })
}

pub(crate) fn build_payload_request(
    dialog: &PayloadDialogState,
    operator: &str,
) -> OperatorMessage {
    OperatorMessage::BuildPayloadRequest(Message {
        head: MessageHead {
            event: EventCode::Gate,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: BuildPayloadRequestInfo {
            agent_type: dialog.agent_type.clone(),
            listener: dialog.listener.clone(),
            arch: dialog.arch.label().to_owned(),
            format: dialog.format.label().to_owned(),
            config: dialog.config_json(),
        },
    })
}

/// Map a build console message type to a display color.
pub(crate) fn build_console_message_color(message_type: &str) -> Color32 {
    match message_type {
        "Good" => Color32::from_rgb(85, 255, 85),
        "Error" => Color32::from_rgb(255, 85, 85),
        "Warning" => Color32::from_rgb(255, 200, 50),
        _ => Color32::from_rgb(180, 180, 220), // Info / default
    }
}

/// Map a build console message type to a prefix tag (like Havoc's [*] / [+] / [-]).
pub(crate) fn build_console_message_prefix(message_type: &str) -> &'static str {
    match message_type {
        "Good" => "[+]",
        "Error" => "[-]",
        "Warning" => "[!]",
        _ => "[*]",
    }
}

pub(super) fn next_task_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};

    static TASK_COUNTER: AtomicU32 = AtomicU32::new(1);
    TASK_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Extract the task ID from an outgoing `AgentTask` message.
pub(crate) fn agent_task_id(message: &OperatorMessage) -> Option<String> {
    match message {
        OperatorMessage::AgentTask(m) => Some(m.info.task_id.clone()),
        _ => None,
    }
}

/// Returns the last 4 characters of a task ID for compact display (e.g. `"3f2a"`).
pub(crate) fn short_task_id(task_id: &str) -> &str {
    let bytes = task_id.as_bytes();
    if bytes.len() >= 4 {
        // SAFETY: task IDs are ASCII hex strings.
        &task_id[bytes.len() - 4..]
    } else {
        task_id
    }
}

// ─── File browser task builders ──────────────────────────────────────────────

pub(crate) fn build_file_browser_list_task(
    agent_id: &str,
    path: &str,
    operator: &str,
) -> OperatorMessage {
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            command_line: format!("ls {path}"),
            command: Some("fs".to_owned()),
            sub_command: Some("dir".to_owned()),
            arguments: Some(format!("{path};true;false;false;false;;;")),
            ..AgentTaskInfo::default()
        },
    )
}

pub(crate) fn build_file_browser_pwd_task(agent_id: &str, operator: &str) -> OperatorMessage {
    build_agent_task(operator, filesystem_task(agent_id, "pwd", "pwd", None))
}

pub(crate) fn build_file_browser_cd_task(
    agent_id: &str,
    path: &str,
    operator: &str,
) -> OperatorMessage {
    build_agent_task(
        operator,
        filesystem_task(agent_id, &format!("cd {path}"), "cd", Some(path.to_owned())),
    )
}

pub(crate) fn build_file_browser_download_task(
    agent_id: &str,
    path: &str,
    operator: &str,
) -> OperatorMessage {
    build_agent_task(
        operator,
        filesystem_transfer_task(agent_id, &format!("download {path}"), "download", path),
    )
}

pub(crate) fn build_file_browser_delete_task(
    agent_id: &str,
    path: &str,
    operator: &str,
) -> OperatorMessage {
    build_agent_task(
        operator,
        filesystem_task(agent_id, &format!("rm {path}"), "remove", Some(path.to_owned())),
    )
}

pub(crate) fn build_file_browser_upload_task(
    agent_id: &str,
    remote_path: &str,
    content: &[u8],
    operator: &str,
) -> OperatorMessage {
    let remote = base64::engine::general_purpose::STANDARD.encode(remote_path.as_bytes());
    let content = base64::engine::general_purpose::STANDARD.encode(content);
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            command_line: format!("upload {remote_path}"),
            command: Some("fs".to_owned()),
            sub_command: Some("upload".to_owned()),
            arguments: Some(format!("{remote};{content}")),
            ..AgentTaskInfo::default()
        },
    )
}

/// Builds a `CommandTransfer` stop task to cancel an in-progress download.
///
/// The binary payload `[stop_subcommand_u32_le, file_id_u32_le]` is pre-encoded as
/// `PayloadBase64` so the teamserver forwards it verbatim to the agent.  This avoids
/// adding transfer-command encoding logic to the teamserver's `task_payload` function.
///
/// Returns `None` if `file_id_hex` cannot be parsed as a hexadecimal `u32`.
pub(crate) fn build_transfer_stop_task(
    agent_id: &str,
    file_id_hex: &str,
    operator: &str,
) -> Option<OperatorMessage> {
    let file_id = u32::from_str_radix(file_id_hex.trim(), 16).ok().or_else(|| {
        // Handle 64-bit hex file IDs by taking the lower 32 bits.
        u64::from_str_radix(file_id_hex.trim(), 16).ok().map(|v| v as u32)
    })?;
    // Binary payload: [DEMON_COMMAND_TRANSFER_STOP=1 as u32 LE, file_id as u32 LE]
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&file_id.to_le_bytes());
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
    Some(build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(red_cell_common::demon::DemonCommand::CommandTransfer)
                .to_string(),
            command_line: format!("transfer stop {file_id_hex}"),
            extra: BTreeMap::from([(
                "PayloadBase64".to_owned(),
                serde_json::Value::String(payload_b64),
            )]),
            ..AgentTaskInfo::default()
        },
    ))
}

// ─── Console task dispatch ────────────────────────────────────────────────────

pub(crate) fn build_console_task(
    agent_id: &str,
    input: &str,
    operator: &str,
) -> Result<OperatorMessage, String> {
    let trimmed = input.trim();
    let mut parts = trimmed.split_whitespace();
    let Some(command) = parts.next() else {
        return Err("Command input is empty.".to_owned());
    };
    let command = command.to_ascii_lowercase();

    let info = match command.as_str() {
        // Local-only commands are handled before this function is called.
        "help" | "?" => {
            return Err("Use the help command for usage information.".to_owned());
        }
        "shell" => {
            let shell_cmd = rest_after_word(trimmed)?;
            builders::simple_task(
                agent_id,
                trimmed,
                DemonCommand::CommandInlineExecute,
                "shell",
                Some(shell_cmd),
            )
        }
        "sleep" => builders::sleep_task(agent_id, trimmed)?,
        "checkin" => {
            builders::simple_task(agent_id, trimmed, DemonCommand::CommandCheckin, "checkin", None)
        }
        "kill" | "exit" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandExit).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("kill".to_owned()),
            arguments: parts.next().map(ToOwned::to_owned),
            ..AgentTaskInfo::default()
        },
        "ps" | "proclist" => {
            builders::simple_task(agent_id, trimmed, DemonCommand::CommandProcList, "ps", None)
        }
        "screenshot" => builders::simple_task(
            agent_id,
            trimmed,
            DemonCommand::CommandScreenshot,
            "screenshot",
            None,
        ),
        "pwd" => filesystem_task(agent_id, trimmed, "pwd", None),
        "cd" => filesystem_task(agent_id, trimmed, "cd", Some(rest_after_word(trimmed)?)),
        "dir" | "ls" => {
            let path = rest_after_word(trimmed)?;
            filesystem_task(
                agent_id,
                trimmed,
                "dir",
                Some(format!("{path};true;false;false;false;;;")),
            )
        }
        "mkdir" => filesystem_task(agent_id, trimmed, "mkdir", Some(rest_after_word(trimmed)?)),
        "rm" | "del" | "remove" => {
            filesystem_task(agent_id, trimmed, "remove", Some(rest_after_word(trimmed)?))
        }
        "cp" | "copy" => builders::filesystem_copy_or_move_task(agent_id, trimmed, "cp")?,
        "mv" | "move" => builders::filesystem_copy_or_move_task(agent_id, trimmed, "move")?,
        "download" => {
            filesystem_transfer_task(agent_id, trimmed, "download", &rest_after_word(trimmed)?)
        }
        "upload" => builders::upload_console_task(agent_id, trimmed)?,
        "cat" | "type" => {
            filesystem_transfer_task(agent_id, trimmed, "cat", &rest_after_word(trimmed)?)
        }
        "proc" => process_task(agent_id, trimmed)?,
        "token" => builders::token_task(agent_id, trimmed)?,
        "inline-execute" | "bof" => builders::inline_execute_task(agent_id, trimmed)?,
        "inject-dll" => builders::inject_dll_console_task(agent_id, trimmed)?,
        "inject-shellcode" => builders::inject_shellcode_console_task(agent_id, trimmed)?,
        "spawn-dll" => builders::spawn_dll_console_task(agent_id, trimmed)?,
        "net" => builders::net_task(agent_id, trimmed)?,
        "pivot" => builders::pivot_task(agent_id, trimmed)?,
        "rportfwd" => builders::rportfwd_task(agent_id, trimmed)?,
        "kerberos" => builders::kerberos_task(agent_id, trimmed)?,
        "config" => builders::config_task(agent_id, trimmed)?,
        _ => {
            let usage =
                closest_command_usage(&command).unwrap_or("Type `help` for available commands.");
            return Err(format!("Unsupported console command `{command}`. {usage}"));
        }
    };

    Ok(build_agent_task(operator, info))
}

pub(crate) fn filesystem_task(
    agent_id: &str,
    command_line: &str,
    sub_command: &str,
    arguments: Option<String>,
) -> AgentTaskInfo {
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command_line: command_line.to_owned(),
        command: Some("fs".to_owned()),
        sub_command: Some(sub_command.to_owned()),
        arguments,
        ..AgentTaskInfo::default()
    }
}

pub(crate) fn filesystem_transfer_task(
    agent_id: &str,
    command_line: &str,
    sub_command: &str,
    path: &str,
) -> AgentTaskInfo {
    let encoded = Some(base64::engine::general_purpose::STANDARD.encode(path.as_bytes()));
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command_line: command_line.to_owned(),
        command: Some("fs".to_owned()),
        sub_command: Some(sub_command.to_owned()),
        arguments: encoded,
        ..AgentTaskInfo::default()
    }
}

pub(crate) fn process_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub_command = parts
        .next()
        .ok_or_else(|| "Usage: proc <kill|modules|grep|create|memory> [args]".to_owned())?;
    let sub_lower = sub_command.to_ascii_lowercase();
    match sub_lower.as_str() {
        "kill" => {
            let pid = parts.next().ok_or_else(|| "Usage: proc kill <pid>".to_owned())?;
            if parts.next().is_some() {
                return Err("Usage: proc kill <pid>".to_owned());
            }
            let pid = pid.parse::<u32>().map_err(|_| format!("Invalid PID `{pid}`."))?;
            Ok(builders::process_kill_info(agent_id, pid))
        }
        "modules" | "grep" | "create" | "memory" => {
            let args: String = parts.collect::<Vec<_>>().join(" ");
            Ok(AgentTaskInfo {
                demon_id: agent_id.to_owned(),
                task_id: format!("{:08X}", next_task_id()),
                command_id: u32::from(DemonCommand::CommandProc).to_string(),
                command_line: command_line.to_owned(),
                command: Some("proc".to_owned()),
                sub_command: Some(sub_lower),
                arguments: if args.is_empty() { None } else { Some(args) },
                ..AgentTaskInfo::default()
            })
        }
        _ => Err("Usage: proc <kill|modules|grep|create|memory> [args]".to_owned()),
    }
}

pub(crate) fn rest_after_word(input: &str) -> Result<String, String> {
    let mut parts = input.trim().splitn(2, char::is_whitespace);
    let _ = parts.next();
    let rest = parts.next().map(str::trim).unwrap_or_default();
    if rest.is_empty() {
        Err("This command requires an argument.".to_owned())
    } else {
        Ok(rest.to_owned())
    }
}
