use std::collections::BTreeMap;

use red_cell_common::demon::{DemonCommand, DemonInjectError, DemonProcessCommand};
use serde_json::{Value, json};

use crate::agent_events::agent_mark_event;
use crate::{AgentRegistry, Database, EventBus};

use super::{
    AgentResponseEntry, CallbackParser, CommandDispatchError, agent_response_event,
    broadcast_and_persist_agent_response, loot_context,
};

async fn persist_process_agent_response(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    response: AgentResponseEntry,
) -> Result<(), CommandDispatchError> {
    let context = loot_context(registry, response.agent_id, response.request_id).await;
    broadcast_and_persist_agent_response(database, events, response, &context).await
}

pub(super) async fn handle_proc_ppid_spoof_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandProcPpidSpoof));
    let ppid = parser.read_u32("proc ppid spoof pid")?;
    let had_agent = if let Some(mut agent) = registry.get(agent_id).await {
        agent.process_ppid = ppid;
        registry.update_agent(agent.clone()).await?;
        events.broadcast(agent_mark_event(&agent));
        true
    } else {
        false
    };
    let message = format!("Changed parent pid to spoof: {ppid}");
    if had_agent {
        persist_process_agent_response(
            registry,
            database,
            events,
            AgentResponseEntry {
                agent_id,
                command_id: u32::from(DemonCommand::CommandProcPpidSpoof),
                request_id,
                kind: "Good".to_owned(),
                message: message.clone(),
                extra: BTreeMap::new(),
                output: message,
            },
        )
        .await?;
    } else {
        events.broadcast(agent_response_event(
            agent_id,
            u32::from(DemonCommand::CommandProcPpidSpoof),
            request_id,
            "Good",
            &message,
            None,
        )?);
    }
    Ok(None)
}

pub(super) async fn handle_process_list_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandProcList));
    let _from_process_manager = parser.read_u32("process ui flag")?;
    let mut rows = Vec::new();

    while !parser.is_empty() {
        let name = parser.read_utf16("process name")?;
        let pid = parser.read_u32("process pid")?;
        let is_wow = parser.read_u32("process wow64")?;
        let ppid = parser.read_u32("process ppid")?;
        let session = parser.read_u32("process session")?;
        let threads = parser.read_u32("process threads")?;
        let user = parser.read_utf16("process user")?;
        let arch = if is_wow == 0 { "x64" } else { "x86" };
        rows.push(ProcessRow { name, pid, ppid, session, arch: arch.to_owned(), threads, user });
    }

    let output = format_process_table(&rows);
    if output.is_empty() {
        return Ok(None);
    }

    let mut extra = BTreeMap::new();
    extra.insert("ProcessListRows".to_owned(), process_rows_json(&rows));

    persist_process_agent_response(
        registry,
        database,
        events,
        AgentResponseEntry {
            agent_id,
            command_id: u32::from(DemonCommand::CommandProcList),
            request_id,
            kind: "Info".to_owned(),
            message: "Process List:".to_owned(),
            extra,
            output,
        },
    )
    .await?;
    Ok(None)
}

pub(super) async fn handle_process_command_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandProc));
    let subcommand = parser.read_u32("process subcommand")?;

    match DemonProcessCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandProc),
            message: error.to_string(),
        }
    })? {
        DemonProcessCommand::Create => {
            let path = parser.read_utf16("process path")?;
            let pid = parser.read_u32("process pid")?;
            let success = parser.read_u32("process create success")?;
            let piped = parser.read_u32("process create piped")?;
            let verbose = parser.read_u32("process create verbose")?;

            if verbose != 0 {
                let (kind, message) = if success != 0 {
                    ("Info", format!("Process started: Path:[{path}] ProcessID:[{pid}]"))
                } else {
                    ("Error", format!("Process could not be started: Path:[{path}]"))
                };
                persist_process_agent_response(
                    registry,
                    database,
                    events,
                    AgentResponseEntry {
                        agent_id,
                        command_id: u32::from(DemonCommand::CommandProc),
                        request_id,
                        kind: kind.to_owned(),
                        message: message.clone(),
                        extra: BTreeMap::new(),
                        output: message,
                    },
                )
                .await?;
            } else if success == 0 || piped == 0 {
                let message = "Process create completed".to_owned();
                persist_process_agent_response(
                    registry,
                    database,
                    events,
                    AgentResponseEntry {
                        agent_id,
                        command_id: u32::from(DemonCommand::CommandProc),
                        request_id,
                        kind: "Info".to_owned(),
                        message: message.clone(),
                        extra: BTreeMap::new(),
                        output: message,
                    },
                )
                .await?;
            }
        }
        DemonProcessCommand::Kill => {
            let success = parser.read_u32("process kill success")?;
            let pid = parser.read_u32("process kill pid")?;
            let (kind, message) = if success != 0 {
                ("Good", format!("Successfully killed process: {pid}"))
            } else {
                ("Error", "Failed to kill process".to_owned())
            };
            persist_process_agent_response(
                registry,
                database,
                events,
                AgentResponseEntry {
                    agent_id,
                    command_id: u32::from(DemonCommand::CommandProc),
                    request_id,
                    kind: kind.to_owned(),
                    message: message.clone(),
                    extra: BTreeMap::new(),
                    output: message,
                },
            )
            .await?;
        }
        DemonProcessCommand::Modules => {
            let pid = parser.read_u32("proc modules pid")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                let name = parser.read_string("module name")?;
                let base = parser.read_u64("module base address")?;
                rows.push(ModuleRow { name, base });
            }

            let output = format_module_table(&rows);
            let mut extra = BTreeMap::new();
            extra.insert(
                "ModuleRows".to_owned(),
                Value::Array(
                    rows.iter()
                        .map(|r| {
                            json!({
                                "Name": r.name,
                                "Base": format!("0x{:016X}", r.base),
                            })
                        })
                        .collect(),
                ),
            );

            let message = format!("Process Modules (PID: {pid}):");
            persist_process_agent_response(
                registry,
                database,
                events,
                AgentResponseEntry {
                    agent_id,
                    command_id: u32::from(DemonCommand::CommandProc),
                    request_id,
                    kind: "Info".to_owned(),
                    message: message.clone(),
                    extra,
                    output,
                },
            )
            .await?;
        }
        DemonProcessCommand::Grep => {
            let mut rows = Vec::new();
            while !parser.is_empty() {
                let name = parser.read_utf16("proc grep name")?;
                let pid = parser.read_u32("proc grep pid")?;
                let ppid = parser.read_u32("proc grep ppid")?;
                let user_raw = parser.read_bytes("proc grep user")?;
                let user = String::from_utf8_lossy(&user_raw).trim_end_matches('\0').to_owned();
                let arch_val = parser.read_u32("proc grep arch")?;
                let arch = if arch_val == 86 { "x86" } else { "x64" };
                rows.push(GrepRow { name, pid, ppid, user, arch: arch.to_owned() });
            }

            let output = format_grep_table(&rows);
            let mut extra = BTreeMap::new();
            extra.insert(
                "GrepRows".to_owned(),
                Value::Array(
                    rows.iter()
                        .map(|r| {
                            json!({
                                "Name": r.name,
                                "PID": r.pid,
                                "PPID": r.ppid,
                                "User": r.user,
                                "Arch": r.arch,
                            })
                        })
                        .collect(),
                ),
            );

            persist_process_agent_response(
                registry,
                database,
                events,
                AgentResponseEntry {
                    agent_id,
                    command_id: u32::from(DemonCommand::CommandProc),
                    request_id,
                    kind: "Info".to_owned(),
                    message: "Process Grep:".to_owned(),
                    extra,
                    output,
                },
            )
            .await?;
        }
        DemonProcessCommand::Memory => {
            let pid = parser.read_u32("proc memory pid")?;
            let query_protect = parser.read_u32("proc memory query protect")?;
            let mut rows = Vec::new();
            while !parser.is_empty() {
                let base = parser.read_u64("memory region base")?;
                let size = parser.read_u32("memory region size")?;
                let protect = parser.read_u32("memory region protect")?;
                let state = parser.read_u32("memory region state")?;
                let mem_type = parser.read_u32("memory region type")?;
                rows.push(MemoryRow { base, size, protect, state, mem_type });
            }

            let output = format_memory_table(&rows);
            let mut extra = BTreeMap::new();
            extra.insert(
                "MemoryRows".to_owned(),
                Value::Array(
                    rows.iter()
                        .map(|r| {
                            json!({
                                "Base": format!("0x{:016X}", r.base),
                                "Size": format!("0x{:X}", r.size),
                                "Protect": format_memory_protect(r.protect),
                                "State": format_memory_state(r.state),
                                "Type": format_memory_type(r.mem_type),
                            })
                        })
                        .collect(),
                ),
            );

            let message = format!(
                "Process Memory (PID: {pid}, Filter: {}):",
                if query_protect == 0 {
                    "All".to_owned()
                } else {
                    format_memory_protect(query_protect)
                }
            );
            persist_process_agent_response(
                registry,
                database,
                events,
                AgentResponseEntry {
                    agent_id,
                    command_id: u32::from(DemonCommand::CommandProc),
                    request_id,
                    kind: "Info".to_owned(),
                    message: message.clone(),
                    extra,
                    output,
                },
            )
            .await?;
        }
    }

    Ok(None)
}

pub(super) async fn handle_inject_shellcode_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandInjectShellcode));
    let status = parser.read_u32("shellcode inject status")?;
    let (kind, message) = match status {
        x if x == u32::from(DemonInjectError::Success) => {
            ("Good", "Successfully injected shellcode")
        }
        x if x == u32::from(DemonInjectError::Failed) => ("Error", "Failed to inject shellcode"),
        x if x == u32::from(DemonInjectError::InvalidParam) => {
            ("Error", "Invalid parameter specified")
        }
        x if x == u32::from(DemonInjectError::ProcessArchMismatch) => {
            ("Error", "Process architecture mismatch")
        }
        other => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandInjectShellcode),
                message: format!("unknown shellcode injection status {other}"),
            });
        }
    };

    let cmd_id = u32::from(DemonCommand::CommandInjectShellcode);
    let message_owned = message.to_owned();
    if registry.get(agent_id).await.is_some() {
        persist_process_agent_response(
            registry,
            database,
            events,
            AgentResponseEntry {
                agent_id,
                command_id: cmd_id,
                request_id,
                kind: kind.to_owned(),
                message: message_owned.clone(),
                extra: BTreeMap::new(),
                output: message_owned,
            },
        )
        .await?;
    } else {
        events.broadcast(agent_response_event(
            agent_id,
            cmd_id,
            request_id,
            kind,
            &message_owned,
            Some(message_owned.clone()),
        )?);
    }
    Ok(None)
}

pub(super) async fn handle_inject_dll_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let cmd = u32::from(DemonCommand::CommandInjectDll);
    let mut parser = CallbackParser::new(payload, cmd);
    let status = parser.read_u32("dll inject status")?;
    let (kind, message) = match status {
        x if x == u32::from(DemonInjectError::Success) => {
            ("Good", "Successfully injected DLL into remote process")
        }
        x if x == u32::from(DemonInjectError::Failed) => {
            ("Error", "Failed to inject DLL into remote process")
        }
        x if x == u32::from(DemonInjectError::InvalidParam) => {
            ("Error", "DLL injection failed: invalid parameter")
        }
        x if x == u32::from(DemonInjectError::ProcessArchMismatch) => {
            ("Error", "DLL injection failed: process architecture mismatch")
        }
        other => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: cmd,
                message: format!("unknown DLL injection status {other}"),
            });
        }
    };

    let message_owned = message.to_owned();
    if registry.get(agent_id).await.is_some() {
        persist_process_agent_response(
            registry,
            database,
            events,
            AgentResponseEntry {
                agent_id,
                command_id: cmd,
                request_id,
                kind: kind.to_owned(),
                message: message_owned.clone(),
                extra: BTreeMap::new(),
                output: message_owned,
            },
        )
        .await?;
    } else {
        events.broadcast(agent_response_event(
            agent_id,
            cmd,
            request_id,
            kind,
            &message_owned,
            Some(message_owned.clone()),
        )?);
    }
    Ok(None)
}

pub(super) async fn handle_spawn_dll_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let cmd = u32::from(DemonCommand::CommandSpawnDll);
    let mut parser = CallbackParser::new(payload, cmd);
    let status = parser.read_u32("spawn dll status")?;
    let (kind, message) = match status {
        x if x == u32::from(DemonInjectError::Success) => {
            ("Good", "Successfully spawned DLL in new process")
        }
        x if x == u32::from(DemonInjectError::Failed) => {
            ("Error", "Failed to spawn DLL in new process")
        }
        x if x == u32::from(DemonInjectError::InvalidParam) => {
            ("Error", "DLL spawn failed: invalid parameter")
        }
        x if x == u32::from(DemonInjectError::ProcessArchMismatch) => {
            ("Error", "DLL spawn failed: process architecture mismatch")
        }
        other => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: cmd,
                message: format!("unknown DLL spawn status {other}"),
            });
        }
    };

    let message_owned = message.to_owned();
    if registry.get(agent_id).await.is_some() {
        persist_process_agent_response(
            registry,
            database,
            events,
            AgentResponseEntry {
                agent_id,
                command_id: cmd,
                request_id,
                kind: kind.to_owned(),
                message: message_owned.clone(),
                extra: BTreeMap::new(),
                output: message_owned,
            },
        )
        .await?;
    } else {
        events.broadcast(agent_response_event(
            agent_id,
            cmd,
            request_id,
            kind,
            &message_owned,
            Some(message_owned.clone()),
        )?);
    }
    Ok(None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcessRow {
    pub(super) name: String,
    pub(super) pid: u32,
    pub(super) ppid: u32,
    pub(super) session: u32,
    pub(super) arch: String,
    pub(super) threads: u32,
    pub(super) user: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ModuleRow {
    pub(super) name: String,
    pub(super) base: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GrepRow {
    pub(super) name: String,
    pub(super) pid: u32,
    pub(super) ppid: u32,
    pub(super) user: String,
    pub(super) arch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MemoryRow {
    pub(super) base: u64,
    pub(super) size: u32,
    pub(super) protect: u32,
    pub(super) state: u32,
    pub(super) mem_type: u32,
}

pub(super) fn format_process_table(rows: &[ProcessRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let name_width = rows.iter().map(|row| row.name.len()).max().unwrap_or(4).max(4);
    let mut output = String::new();
    output.push_str(&format_process_row(
        name_width, "Name", "PID", "PPID", "Session", "Arch", "Threads", "User",
    ));
    output.push('\n');
    output.push_str(&format_process_row(
        name_width, "----", "---", "----", "-------", "----", "-------", "----",
    ));
    output.push('\n');

    for row in rows {
        output.push_str(&format_process_row(
            name_width,
            &row.name,
            row.pid,
            row.ppid,
            row.session,
            &row.arch,
            row.threads,
            &row.user,
        ));
        output.push('\n');
    }

    output
}

pub(super) fn process_rows_json(rows: &[ProcessRow]) -> Value {
    Value::Array(
        rows.iter()
            .map(|row| {
                json!({
                    "Name": row.name,
                    "PID": row.pid,
                    "PPID": row.ppid,
                    "Session": row.session,
                    "Arch": row.arch,
                    "Threads": row.threads,
                    "User": row.user,
                })
            })
            .collect(),
    )
}

fn format_process_row(
    name_width: usize,
    name: impl std::fmt::Display,
    pid: impl std::fmt::Display,
    ppid: impl std::fmt::Display,
    session: impl std::fmt::Display,
    arch: impl std::fmt::Display,
    threads: impl std::fmt::Display,
    user: impl std::fmt::Display,
) -> String {
    format!(
        " {name:<name_width$}   {pid:<4}   {ppid:<4}   {session:<7}   {arch:<5}   {threads:<7}   {user:<4}",
        name = name,
        pid = pid,
        ppid = ppid,
        session = session,
        arch = arch,
        threads = threads,
        user = user,
        name_width = name_width,
    )
}

pub(super) fn format_module_table(rows: &[ModuleRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let name_width = rows.iter().map(|r| r.name.len()).max().unwrap_or(6).max(6);
    let mut output = format!("\n {:<name_width$}   {:>18}\n", "Module", "Base Address");
    output.push_str(&format!(" {:<name_width$}   {:>18}\n", "------", "------------"));

    for row in rows {
        output.push_str(&format!(" {:<name_width$}   0x{:016X}\n", row.name, row.base));
    }

    output
}

pub(super) fn format_grep_table(rows: &[GrepRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let name_width = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
    let user_width = rows.iter().map(|r| r.user.len()).max().unwrap_or(4).max(4);
    let mut output = format!(
        "\n {:<name_width$}   {:<8}   {:<8}   {:<user_width$}   {}\n",
        "Name", "PID", "PPID", "User", "Arch"
    );
    output.push_str(&format!(
        " {:<name_width$}   {:<8}   {:<8}   {:<user_width$}   {}\n",
        "----", "---", "----", "----", "----"
    ));

    for row in rows {
        output.push_str(&format!(
            " {:<name_width$}   {:<8}   {:<8}   {:<user_width$}   {}\n",
            row.name, row.pid, row.ppid, row.user, row.arch
        ));
    }

    output
}

pub(super) fn format_memory_table(rows: &[MemoryRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let mut output = format!(
        "\n {:>18}   {:>12}   {:<24}   {:<12}   {}\n",
        "Base Address", "Size", "Protection", "State", "Type"
    );
    output.push_str(&format!(
        " {:>18}   {:>12}   {:<24}   {:<12}   {}\n",
        "------------", "----", "----------", "-----", "----"
    ));

    for row in rows {
        output.push_str(&format!(
            " 0x{:016X}   0x{:>10X}   {:<24}   {:<12}   {}\n",
            row.base,
            row.size,
            format_memory_protect(row.protect),
            format_memory_state(row.state),
            format_memory_type(row.mem_type),
        ));
    }

    output
}

pub(super) fn format_memory_protect(protect: u32) -> String {
    match protect {
        0x01 => "PAGE_NOACCESS".to_owned(),
        0x02 => "PAGE_READONLY".to_owned(),
        0x04 => "PAGE_READWRITE".to_owned(),
        0x08 => "PAGE_WRITECOPY".to_owned(),
        0x10 => "PAGE_EXECUTE".to_owned(),
        0x20 => "PAGE_EXECUTE_READ".to_owned(),
        0x40 => "PAGE_EXECUTE_READWRITE".to_owned(),
        0x80 => "PAGE_EXECUTE_WRITECOPY".to_owned(),
        0x100 => "PAGE_GUARD".to_owned(),
        other => format!("0x{other:X}"),
    }
}

pub(super) fn win32_error_code_name(code: u32) -> Option<&'static str> {
    match code {
        2 => Some("ERROR_FILE_NOT_FOUND"),
        5 => Some("ERROR_ACCESS_DENIED"),
        87 => Some("ERROR_INVALID_PARAMETER"),
        183 => Some("ERROR_ALREADY_EXISTS"),
        997 => Some("ERROR_IO_PENDING"),
        _ => None,
    }
}

pub(super) fn format_memory_state(state: u32) -> String {
    match state {
        0x1000 => "MEM_COMMIT".to_owned(),
        0x2000 => "MEM_RESERVE".to_owned(),
        0x10000 => "MEM_FREE".to_owned(),
        other => format!("0x{other:X}"),
    }
}

pub(super) fn format_memory_type(mem_type: u32) -> String {
    match mem_type {
        0x20000 => "MEM_PRIVATE".to_owned(),
        0x40000 => "MEM_MAPPED".to_owned(),
        0x1000000 => "MEM_IMAGE".to_owned(),
        other => format!("0x{other:X}"),
    }
}
