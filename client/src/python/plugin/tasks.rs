//! Agent task message builders: console command dispatch and raw-bytes command encoding.

use std::collections::BTreeMap;

use base64::Engine;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use serde_json::Value;

pub(super) fn build_agent_task(operator: &str, info: AgentTaskInfo) -> OperatorMessage {
    OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info,
    })
}

pub(super) fn next_task_id_string() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};

    static TASK_COUNTER: AtomicU32 = AtomicU32::new(1);
    format!("{:08X}", TASK_COUNTER.fetch_add(1, Ordering::Relaxed))
}

pub(super) fn build_console_task_message(
    agent_id: &str,
    task_id: &str,
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
        "checkin" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: task_id.to_owned(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("checkin".to_owned()),
            ..AgentTaskInfo::default()
        },
        "kill" | "exit" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: task_id.to_owned(),
            command_id: u32::from(DemonCommand::CommandExit).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("kill".to_owned()),
            arguments: parts.next().map(ToOwned::to_owned),
            ..AgentTaskInfo::default()
        },
        "ps" | "proclist" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: task_id.to_owned(),
            command_id: u32::from(DemonCommand::CommandProcList).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("ps".to_owned()),
            ..AgentTaskInfo::default()
        },
        "screenshot" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: task_id.to_owned(),
            command_id: u32::from(DemonCommand::CommandScreenshot).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("screenshot".to_owned()),
            ..AgentTaskInfo::default()
        },
        "pwd" => filesystem_task(agent_id, task_id, trimmed, "pwd", None),
        "cd" => filesystem_task(agent_id, task_id, trimmed, "cd", Some(rest_after_word(trimmed)?)),
        "mkdir" => {
            filesystem_task(agent_id, task_id, trimmed, "mkdir", Some(rest_after_word(trimmed)?))
        }
        "rm" | "del" | "remove" => {
            filesystem_task(agent_id, task_id, trimmed, "remove", Some(rest_after_word(trimmed)?))
        }
        "download" => filesystem_transfer_task(
            agent_id,
            task_id,
            trimmed,
            "download",
            &rest_after_word(trimmed)?,
        ),
        "cat" | "type" => {
            filesystem_transfer_task(agent_id, task_id, trimmed, "cat", &rest_after_word(trimmed)?)
        }
        "proc" => process_task(agent_id, task_id, trimmed)?,
        _ => return Err(format!("Unsupported console command `{command}`.")),
    };

    Ok(build_agent_task(operator, info))
}

pub(super) fn build_agent_command_message(
    agent_id: &str,
    task_id: &str,
    command: &str,
    command_arg: &[u8],
    operator: &str,
) -> OperatorMessage {
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: task_id.to_owned(),
            command_id: "0".to_owned(),
            command_line: String::new(),
            command: Some(command.to_owned()),
            arguments: Some(base64::engine::general_purpose::STANDARD.encode(command_arg)),
            extra: BTreeMap::from([(
                "CommandArg".to_owned(),
                Value::String(base64::engine::general_purpose::STANDARD.encode(command_arg)),
            )]),
            ..AgentTaskInfo::default()
        },
    )
}

fn filesystem_task(
    agent_id: &str,
    task_id: &str,
    command_line: &str,
    sub_command: &str,
    arguments: Option<String>,
) -> AgentTaskInfo {
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: task_id.to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command_line: command_line.to_owned(),
        command: Some("fs".to_owned()),
        sub_command: Some(sub_command.to_owned()),
        arguments,
        ..AgentTaskInfo::default()
    }
}

fn filesystem_transfer_task(
    agent_id: &str,
    task_id: &str,
    command_line: &str,
    sub_command: &str,
    path: &str,
) -> AgentTaskInfo {
    let encoded = Some(base64::engine::general_purpose::STANDARD.encode(path.as_bytes()));
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: task_id.to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command_line: command_line.to_owned(),
        command: Some("fs".to_owned()),
        sub_command: Some(sub_command.to_owned()),
        arguments: encoded,
        ..AgentTaskInfo::default()
    }
}

fn process_task(
    agent_id: &str,
    task_id: &str,
    command_line: &str,
) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub_command = parts.next().ok_or_else(|| "Usage: proc kill <pid>".to_owned())?;
    match sub_command.to_ascii_lowercase().as_str() {
        "kill" => {
            let pid = parts.next().ok_or_else(|| "Usage: proc kill <pid>".to_owned())?;
            if parts.next().is_some() {
                return Err("Usage: proc kill <pid>".to_owned());
            }
            let pid = pid.parse::<u32>().map_err(|_| format!("Invalid PID `{pid}`."))?;
            Ok(AgentTaskInfo {
                demon_id: agent_id.to_owned(),
                task_id: task_id.to_owned(),
                command_id: u32::from(DemonCommand::CommandProc).to_string(),
                command_line: format!("proc kill {pid}"),
                command: Some("proc".to_owned()),
                sub_command: Some("kill".to_owned()),
                arguments: Some(pid.to_string()),
                extra: BTreeMap::from([("Args".to_owned(), Value::String(pid.to_string()))]),
                ..AgentTaskInfo::default()
            })
        }
        _ => Err("Usage: proc kill <pid>".to_owned()),
    }
}

fn rest_after_word(input: &str) -> Result<String, String> {
    let mut parts = input.trim().splitn(2, char::is_whitespace);
    let _ = parts.next();
    let rest = parts.next().map(str::trim).unwrap_or_default();
    if rest.is_empty() {
        Err("This command requires an argument.".to_owned())
    } else {
        Ok(rest.to_owned())
    }
}
