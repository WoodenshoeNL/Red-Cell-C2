use std::collections::BTreeMap;

use red_cell_common::demon::{DemonCommand, DemonInjectError, DemonProcessCommand};
use serde_json::{Value, json};

use crate::agent_events::agent_mark_event;
use crate::{AgentRegistry, EventBus};

use super::{
    CallbackParser, CommandDispatchError, agent_response_event, agent_response_event_with_extra,
};

pub(super) async fn handle_proc_ppid_spoof_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandProcPpidSpoof));
    let ppid = parser.read_u32("proc ppid spoof pid")?;
    if let Some(mut agent) = registry.get(agent_id).await {
        agent.process_ppid = ppid;
        registry.update_agent(agent.clone()).await?;
        events.broadcast(agent_mark_event(&agent));
    }
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandProcPpidSpoof),
        request_id,
        "Good",
        &format!("Changed parent pid to spoof: {ppid}"),
        None,
    )?);
    Ok(None)
}

pub(super) async fn handle_process_list_callback(
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

    events.broadcast(agent_response_event_with_extra(
        agent_id,
        u32::from(DemonCommand::CommandProcList),
        request_id,
        "Info",
        "Process List:",
        extra,
        output,
    )?);
    Ok(None)
}

pub(super) async fn handle_process_command_callback(
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
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandProc),
                    request_id,
                    kind,
                    &message,
                    None,
                )?);
            } else if success == 0 || piped == 0 {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandProc),
                    request_id,
                    "Info",
                    "Process create completed",
                    None,
                )?);
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
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandProc),
                request_id,
                kind,
                &message,
                None,
            )?);
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

            events.broadcast(agent_response_event_with_extra(
                agent_id,
                u32::from(DemonCommand::CommandProc),
                request_id,
                "Info",
                &format!("Process Modules (PID: {pid}):"),
                extra,
                output,
            )?);
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

            events.broadcast(agent_response_event_with_extra(
                agent_id,
                u32::from(DemonCommand::CommandProc),
                request_id,
                "Info",
                "Process Grep:",
                extra,
                output,
            )?);
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

            events.broadcast(agent_response_event_with_extra(
                agent_id,
                u32::from(DemonCommand::CommandProc),
                request_id,
                "Info",
                &format!(
                    "Process Memory (PID: {pid}, Filter: {}):",
                    if query_protect == 0 {
                        "All".to_owned()
                    } else {
                        format_memory_protect(query_protect)
                    }
                ),
                extra,
                output,
            )?);
        }
    }

    Ok(None)
}

pub(super) async fn handle_inject_shellcode_callback(
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

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandInjectShellcode),
        request_id,
        kind,
        message,
        None,
    )?);
    Ok(None)
}

pub(super) async fn handle_inject_dll_callback(
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

    events.broadcast(agent_response_event(agent_id, cmd, request_id, kind, message, None)?);
    Ok(None)
}

pub(super) async fn handle_spawn_dll_callback(
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

    events.broadcast(agent_response_event(agent_id, cmd, request_id, kind, message, None)?);
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn make_process_row(name: &str, pid: u32, ppid: u32) -> ProcessRow {
        ProcessRow {
            name: name.to_owned(),
            pid,
            ppid,
            session: 1,
            arch: "x64".to_owned(),
            threads: 4,
            user: "SYSTEM".to_owned(),
        }
    }

    // ── format_process_table ─────────────────────────────────────────────────

    #[test]
    fn format_process_table_empty_returns_empty_string() {
        assert_eq!(format_process_table(&[]), "");
    }

    #[test]
    fn format_process_table_single_row_contains_header_separator_and_data() {
        let rows = vec![make_process_row("svchost.exe", 1234, 456)];
        let table = format_process_table(&rows);

        // Header line must be present
        assert!(table.contains("Name"), "missing Name header: {table}");
        assert!(table.contains("PID"), "missing PID header: {table}");
        assert!(table.contains("PPID"), "missing PPID header: {table}");
        assert!(table.contains("Session"), "missing Session header: {table}");
        assert!(table.contains("Arch"), "missing Arch header: {table}");
        assert!(table.contains("Threads"), "missing Threads header: {table}");
        assert!(table.contains("User"), "missing User header: {table}");

        // Separator dashes must be present
        assert!(table.contains("----"), "missing separator: {table}");

        // Data row must be present
        assert!(table.contains("svchost.exe"), "missing process name: {table}");
        assert!(table.contains("1234"), "missing PID: {table}");
        assert!(table.contains("456"), "missing PPID: {table}");

        // Three lines: header, separator, data row (each ends with '\n')
        assert_eq!(table.lines().count(), 3, "expected 3 lines:\n{table}");
    }

    #[test]
    fn format_process_table_name_width_is_dynamic() {
        // A long process name should widen the Name column for all rows.
        let rows =
            vec![make_process_row("a", 1, 0), make_process_row("very_long_process_name.exe", 2, 0)];
        let table = format_process_table(&rows);
        // Both rows must have the same leading-space alignment — i.e. "a" must
        // be left-padded to the same width as "very_long_process_name.exe".
        let lines: Vec<&str> = table.lines().collect();
        // data rows start at index 2
        let short_row = lines[2];
        let long_row = lines[3];
        // The PID column starts at the same offset in both rows when names
        // are padded correctly; verify by checking equal lengths up to PID.
        assert_eq!(
            short_row.find("1   "),
            long_row.find("2   "),
            "PID column offsets differ — name width not applied uniformly"
        );
    }

    // ── process_rows_json ────────────────────────────────────────────────────

    #[test]
    fn process_rows_json_two_rows_produce_correct_array() {
        let rows = vec![
            ProcessRow {
                name: "explorer.exe".to_owned(),
                pid: 100,
                ppid: 4,
                session: 1,
                arch: "x64".to_owned(),
                threads: 32,
                user: "user1".to_owned(),
            },
            ProcessRow {
                name: "cmd.exe".to_owned(),
                pid: 200,
                ppid: 100,
                session: 1,
                arch: "x86".to_owned(),
                threads: 2,
                user: "user2".to_owned(),
            },
        ];

        let Value::Array(arr) = process_rows_json(&rows) else {
            panic!("expected JSON array");
        };

        assert_eq!(arr.len(), 2);

        assert_eq!(arr[0]["Name"], "explorer.exe");
        assert_eq!(arr[0]["PID"], 100u32);
        assert_eq!(arr[0]["PPID"], 4u32);
        assert_eq!(arr[0]["Session"], 1u32);
        assert_eq!(arr[0]["Arch"], "x64");
        assert_eq!(arr[0]["Threads"], 32u32);
        assert_eq!(arr[0]["User"], "user1");

        assert_eq!(arr[1]["Name"], "cmd.exe");
        assert_eq!(arr[1]["PID"], 200u32);
        assert_eq!(arr[1]["PPID"], 100u32);
        assert_eq!(arr[1]["Arch"], "x86");
        assert_eq!(arr[1]["User"], "user2");
    }

    #[test]
    fn process_rows_json_empty_produces_empty_array() {
        let Value::Array(arr) = process_rows_json(&[]) else {
            panic!("expected JSON array");
        };
        assert!(arr.is_empty());
    }

    // ── format_module_table ──────────────────────────────────────────────────

    #[test]
    fn format_module_table_empty_returns_empty_string() {
        assert_eq!(format_module_table(&[]), "");
    }

    #[test]
    fn format_module_table_formats_hex_base_address() {
        let rows = vec![ModuleRow { name: "ntdll.dll".to_owned(), base: 0x7FFE_0000_1234_ABCD }];
        let table = format_module_table(&rows);
        assert!(table.contains("7FFE00001234ABCD"), "expected hex base address in table:\n{table}");
        assert!(table.contains("ntdll.dll"), "missing module name:\n{table}");
    }

    // ── format_grep_table ────────────────────────────────────────────────────

    #[test]
    fn format_grep_table_empty_returns_empty_string() {
        assert_eq!(format_grep_table(&[]), "");
    }

    #[test]
    fn format_grep_table_contains_expected_row_data() {
        let rows = vec![GrepRow {
            name: "lsass.exe".to_owned(),
            pid: 700,
            ppid: 4,
            user: "SYSTEM".to_owned(),
            arch: "x64".to_owned(),
        }];
        let table = format_grep_table(&rows);
        assert!(table.contains("lsass.exe"), "missing name:\n{table}");
        assert!(table.contains("700"), "missing PID:\n{table}");
        assert!(table.contains("SYSTEM"), "missing user:\n{table}");
    }

    // ── format_memory_table ──────────────────────────────────────────────────

    #[test]
    fn format_memory_table_empty_returns_empty_string() {
        assert_eq!(format_memory_table(&[]), "");
    }

    #[test]
    fn format_memory_table_formats_row_correctly() {
        let rows = vec![MemoryRow {
            base: 0x0000_7FF0_0000_0000,
            size: 0x1000,
            protect: 0x20,     // PAGE_EXECUTE_READ
            state: 0x1000,     // MEM_COMMIT
            mem_type: 0x20000, // MEM_PRIVATE
        }];
        let table = format_memory_table(&rows);
        assert!(table.contains("PAGE_EXECUTE_READ"), "missing protect:\n{table}");
        assert!(table.contains("MEM_COMMIT"), "missing state:\n{table}");
        assert!(table.contains("MEM_PRIVATE"), "missing type:\n{table}");
        assert!(table.contains("7FF000000000"), "missing base address:\n{table}");
    }

    // ── format_memory_protect ────────────────────────────────────────────────

    #[test]
    fn format_memory_protect_known_constants_return_names() {
        assert_eq!(format_memory_protect(0x01), "PAGE_NOACCESS");
        assert_eq!(format_memory_protect(0x02), "PAGE_READONLY");
        assert_eq!(format_memory_protect(0x04), "PAGE_READWRITE");
        assert_eq!(format_memory_protect(0x08), "PAGE_WRITECOPY");
        assert_eq!(format_memory_protect(0x10), "PAGE_EXECUTE");
        assert_eq!(format_memory_protect(0x20), "PAGE_EXECUTE_READ");
        assert_eq!(format_memory_protect(0x40), "PAGE_EXECUTE_READWRITE");
        assert_eq!(format_memory_protect(0x80), "PAGE_EXECUTE_WRITECOPY");
        assert_eq!(format_memory_protect(0x100), "PAGE_GUARD");
    }

    #[test]
    fn format_memory_protect_unknown_constant_returns_hex_fallback() {
        assert_eq!(format_memory_protect(0x99), "0x99");
        assert_eq!(format_memory_protect(0), "0x0");
        // Combined flags (e.g. PAGE_GUARD | PAGE_READWRITE) fall through to hex
        assert_eq!(format_memory_protect(0x104), "0x104");
        // Uppercase hex must be preserved for consistency
        assert_eq!(format_memory_protect(0xAB), "0xAB");
    }

    // ── format_memory_state ──────────────────────────────────────────────────

    #[test]
    fn format_memory_state_known_constants_return_names() {
        assert_eq!(format_memory_state(0x1000), "MEM_COMMIT");
        assert_eq!(format_memory_state(0x2000), "MEM_RESERVE");
        assert_eq!(format_memory_state(0x10000), "MEM_FREE");
    }

    #[test]
    fn format_memory_state_unknown_constant_returns_hex_fallback() {
        assert_eq!(format_memory_state(0xABCD), "0xABCD");
        // Combined flags (e.g. MEM_COMMIT | MEM_RESERVE) fall through to hex
        assert_eq!(format_memory_state(0x3000), "0x3000");
        assert_eq!(format_memory_state(0), "0x0");
    }

    // ── format_memory_type ───────────────────────────────────────────────────

    #[test]
    fn format_memory_type_known_constants_return_names() {
        assert_eq!(format_memory_type(0x20000), "MEM_PRIVATE");
        assert_eq!(format_memory_type(0x40000), "MEM_MAPPED");
        assert_eq!(format_memory_type(0x1000000), "MEM_IMAGE");
    }

    #[test]
    fn format_memory_type_unknown_constant_returns_hex_fallback() {
        assert_eq!(format_memory_type(0x99999), "0x99999");
        assert_eq!(format_memory_type(0x9999), "0x9999");
        assert_eq!(format_memory_type(0), "0x0");
    }

    // ── win32_error_code_name ────────────────────────────────────────────────

    #[test]
    fn win32_error_code_name_known_codes_return_symbolic_names() {
        assert_eq!(win32_error_code_name(2), Some("ERROR_FILE_NOT_FOUND"));
        assert_eq!(win32_error_code_name(5), Some("ERROR_ACCESS_DENIED"));
        assert_eq!(win32_error_code_name(87), Some("ERROR_INVALID_PARAMETER"));
        assert_eq!(win32_error_code_name(183), Some("ERROR_ALREADY_EXISTS"));
        assert_eq!(win32_error_code_name(997), Some("ERROR_IO_PENDING"));
    }

    #[test]
    fn win32_error_code_name_unknown_codes_return_none() {
        assert_eq!(win32_error_code_name(0), None);
        assert_eq!(win32_error_code_name(1), None);
        assert_eq!(win32_error_code_name(9999), None);
    }

    // ── handle_process_command_callback — Create branch ─────────────────────

    use red_cell_common::operator::OperatorMessage;

    /// Build a binary payload for the `Create` subcommand of `CommandProc`.
    fn build_process_create_payload(
        path: &str,
        pid: u32,
        success: u32,
        piped: u32,
        verbose: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        // subcommand
        buf.extend_from_slice(&u32::from(DemonProcessCommand::Create).to_le_bytes());
        // path (UTF-16 LE, null-terminated, length-prefixed)
        let mut encoded: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.extend_from_slice(&[0, 0]); // null terminator
        buf.extend_from_slice(&u32::try_from(encoded.len()).expect("unwrap").to_le_bytes());
        buf.extend_from_slice(&encoded);
        // pid, success, piped, verbose
        buf.extend_from_slice(&pid.to_le_bytes());
        buf.extend_from_slice(&success.to_le_bytes());
        buf.extend_from_slice(&piped.to_le_bytes());
        buf.extend_from_slice(&verbose.to_le_bytes());
        buf
    }

    /// Helper: extract the `Type` and `Message` extra fields from an `AgentResponse`.
    fn extract_response_kind_and_message(msg: &OperatorMessage) -> (String, String) {
        let OperatorMessage::AgentResponse(m) = msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        let kind = m.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("").to_owned();
        let message = m.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("").to_owned();
        (kind, message)
    }

    #[tokio::test]
    async fn process_create_verbose_success_broadcasts_info_with_path_and_pid() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_process_create_payload("C:\\cmd.exe", 1234, 1, 0, 1);

        handle_process_command_callback(&events, 0xAA, 1, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive event within timeout")
            .expect("should have a broadcast event");

        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Info");
        assert!(
            message.contains("C:\\cmd.exe") && message.contains("1234"),
            "expected path and pid in message, got: {message}"
        );
    }

    #[tokio::test]
    async fn process_create_verbose_failure_broadcasts_error() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_process_create_payload("C:\\bad.exe", 0, 0, 0, 1);

        handle_process_command_callback(&events, 0xBB, 2, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive event within timeout")
            .expect("should have a broadcast event");

        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("C:\\bad.exe"), "expected path in error message, got: {message}");
    }

    #[tokio::test]
    async fn process_create_non_verbose_failure_unpiped_broadcasts_fallback() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        // verbose=0, success=0, piped=0
        let payload = build_process_create_payload("C:\\app.exe", 0, 0, 0, 0);

        handle_process_command_callback(&events, 0xCC, 3, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive event within timeout")
            .expect("should have a broadcast event");

        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Info");
        assert_eq!(message, "Process create completed");
    }

    #[tokio::test]
    async fn process_create_non_verbose_failure_piped_broadcasts_fallback() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        // verbose=0, success=0, piped=1
        let payload = build_process_create_payload("C:\\app.exe", 0, 0, 1, 0);

        handle_process_command_callback(&events, 0xDD, 4, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive event within timeout")
            .expect("should have a broadcast event");

        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Info");
        assert_eq!(message, "Process create completed");
    }

    #[tokio::test]
    async fn process_create_non_verbose_success_unpiped_broadcasts_fallback() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        // verbose=0, success=1, piped=0
        let payload = build_process_create_payload("C:\\app.exe", 999, 1, 0, 0);

        handle_process_command_callback(&events, 0xEE, 5, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive event within timeout")
            .expect("should have a broadcast event");

        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Info");
        assert_eq!(message, "Process create completed");
    }

    #[tokio::test]
    async fn process_create_non_verbose_success_piped_does_not_broadcast() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        // verbose=0, success=1, piped=1 → no broadcast
        let payload = build_process_create_payload("C:\\app.exe", 999, 1, 1, 0);

        handle_process_command_callback(&events, 0xFF, 6, &payload)
            .await
            .expect("handler should succeed");

        let result = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;

        assert!(result.is_err(), "expected no broadcast when verbose=0, success=1, piped=1");
    }

    // ── payload builder helpers ─────────────────────────────────────────────

    fn add_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn add_utf16(buf: &mut Vec<u8>, value: &str) {
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.extend_from_slice(&[0, 0]); // null terminator
        buf.extend_from_slice(&u32::try_from(encoded.len()).expect("unwrap").to_le_bytes());
        buf.extend_from_slice(&encoded);
    }

    /// Build a binary payload for `handle_proc_ppid_spoof_callback`.
    fn build_ppid_spoof_payload(ppid: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32(&mut buf, ppid);
        buf
    }

    /// Build a binary payload for `handle_process_list_callback`.
    fn build_process_list_payload(
        from_process_manager: u32,
        rows: &[(&str, u32, u32, u32, u32, u32, &str)], // name, pid, is_wow, ppid, session, threads, user
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32(&mut buf, from_process_manager);
        for &(name, pid, is_wow, ppid, session, threads, user) in rows {
            add_utf16(&mut buf, name);
            add_u32(&mut buf, pid);
            add_u32(&mut buf, is_wow);
            add_u32(&mut buf, ppid);
            add_u32(&mut buf, session);
            add_u32(&mut buf, threads);
            add_utf16(&mut buf, user);
        }
        buf
    }

    /// Build a payload containing a single u32 status code (for inject/spawn handlers).
    fn build_status_payload(status: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32(&mut buf, status);
        buf
    }

    // ── handle_proc_ppid_spoof_callback ─────────────────────────────────────

    fn temp_db_path() -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!("red-cell-dispatch-process-{}.sqlite", uuid::Uuid::new_v4()))
    }

    async fn test_registry() -> AgentRegistry {
        let db = crate::Database::connect(temp_db_path()).await.expect("unwrap");
        AgentRegistry::new(db)
    }

    fn sample_agent(agent_id: u32) -> red_cell_common::AgentRecord {
        use red_cell_common::AgentEncryptionInfo;
        use zeroize::Zeroizing;
        red_cell_common::AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(b"0123456789abcdef0123456789abcdef".to_vec()),
                aes_iv: Zeroizing::new(b"0123456789abcdef".to_vec()),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "LAB".to_owned(),
            external_ip: "127.0.0.1".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            base_address: 0x1000,
            process_pid: 1337,
            process_tid: 7331,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 10,
            sleep_jitter: 25,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-09T20:00:00Z".to_owned(),
            last_call_in: "2026-03-09T20:00:00Z".to_owned(),
        }
    }

    #[tokio::test]
    async fn ppid_spoof_updates_registry_and_broadcasts() {
        let registry = test_registry().await;
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let agent_id = 0xABCD_0001;
        let agent = sample_agent(agent_id);
        registry.insert(agent).await.expect("unwrap");

        let payload = build_ppid_spoof_payload(9999);
        handle_proc_ppid_spoof_callback(&registry, &events, agent_id, 1, &payload)
            .await
            .expect("handler should succeed");

        // Agent's process_ppid should be updated in the registry.
        let updated = registry.get(agent_id).await.expect("agent should exist");
        assert_eq!(updated.process_ppid, 9999);

        // Two events: agent_mark_event + agent_response_event
        let _mark_event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive mark event")
            .expect("mark event");

        let response_event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive response event")
            .expect("response event");

        let (kind, message) = extract_response_kind_and_message(&response_event);
        assert_eq!(kind, "Good");
        assert!(message.contains("9999"), "expected ppid in message, got: {message}");
    }

    #[tokio::test]
    async fn ppid_spoof_missing_agent_still_broadcasts_response() {
        let registry = test_registry().await;
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let agent_id = 0xDEAD_BEEF;

        let payload = build_ppid_spoof_payload(42);
        let result =
            handle_proc_ppid_spoof_callback(&registry, &events, agent_id, 5, &payload).await;

        assert!(result.is_ok(), "handler should not panic for missing agent");

        // Only the response event should be broadcast (no mark event).
        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive response event")
            .expect("response event");

        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Good");
        assert!(message.contains("42"), "expected ppid in message, got: {message}");
    }

    #[tokio::test]
    async fn ppid_spoof_truncated_payload_returns_error() {
        let registry = test_registry().await;
        let events = EventBus::default();
        // Payload too short — only 2 bytes instead of 4.
        let result = handle_proc_ppid_spoof_callback(&registry, &events, 1, 1, &[0x01, 0x02]).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload, got: {result:?}"
        );
    }

    // ── handle_process_list_callback ────────────────────────────────────────

    #[tokio::test]
    async fn process_list_happy_path_broadcasts_table_and_json() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_process_list_payload(
            0, // from_process_manager
            &[
                ("svchost.exe", 800, 0, 4, 0, 12, "SYSTEM"),
                ("explorer.exe", 1200, 1, 800, 1, 32, "user1"),
            ],
        );

        let result = handle_process_list_callback(&events, 0xAA, 1, &payload).await;
        assert!(result.is_ok());
        assert!(result.expect("unwrap").is_none());

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive event")
            .expect("broadcast event");

        let OperatorMessage::AgentResponse(ref msg) = event else {
            panic!("expected AgentResponse, got {event:?}");
        };

        // Check structured JSON extra
        let rows_json = msg.info.extra.get("ProcessListRows").expect("missing ProcessListRows");
        let arr = rows_json.as_array().expect("ProcessListRows should be array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["Name"], "svchost.exe");
        assert_eq!(arr[0]["PID"], 800);
        assert_eq!(arr[0]["Arch"], "x64"); // is_wow=0 → x64
        assert_eq!(arr[1]["Name"], "explorer.exe");
        assert_eq!(arr[1]["Arch"], "x86"); // is_wow=1 → x86
        assert_eq!(arr[1]["User"], "user1");

        // Check the message type
        let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(kind, "Info");
    }

    #[tokio::test]
    async fn process_list_empty_returns_none_without_broadcasting() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        // No rows, just the from_process_manager flag.
        let payload = build_process_list_payload(0, &[]);

        let result = handle_process_list_callback(&events, 0xBB, 2, &payload).await;
        assert!(result.is_ok());
        assert!(result.expect("unwrap").is_none());

        let timeout_result =
            tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(timeout_result.is_err(), "expected no broadcast for empty process list");
    }

    #[tokio::test]
    async fn process_list_truncated_row_returns_error() {
        let events = EventBus::default();
        // Payload with the flag but a truncated row (just 2 bytes of garbage).
        let mut payload = Vec::new();
        add_u32(&mut payload, 0); // from_process_manager
        payload.extend_from_slice(&[0x01, 0x02]); // truncated — not enough for a utf16 length

        let result = handle_process_list_callback(&events, 0xCC, 3, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated row, got: {result:?}"
        );
    }

    // ── handle_inject_shellcode_callback ────────────────────────────────────

    #[tokio::test]
    async fn inject_shellcode_success_broadcasts_good() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::Success));

        handle_inject_shellcode_callback(&events, 0xAA, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Good");
        assert!(message.contains("Successfully"), "got: {message}");
    }

    #[tokio::test]
    async fn inject_shellcode_failed_broadcasts_error() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::Failed));

        handle_inject_shellcode_callback(&events, 0xAA, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, _) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Error");
    }

    #[tokio::test]
    async fn inject_shellcode_invalid_param_broadcasts_error() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::InvalidParam));

        handle_inject_shellcode_callback(&events, 0xAA, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("Invalid parameter"), "got: {message}");
    }

    #[tokio::test]
    async fn inject_shellcode_arch_mismatch_broadcasts_error() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::ProcessArchMismatch));

        handle_inject_shellcode_callback(&events, 0xAA, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("architecture mismatch"), "got: {message}");
    }

    #[tokio::test]
    async fn inject_shellcode_unknown_status_returns_error() {
        let events = EventBus::default();
        let payload = build_status_payload(0xFFFF);

        let result = handle_inject_shellcode_callback(&events, 0xAA, 1, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for unknown status, got: {result:?}"
        );
    }

    // ── handle_inject_dll_callback ──────────────────────────────────────────

    #[tokio::test]
    async fn inject_dll_success_broadcasts_good() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::Success));

        handle_inject_dll_callback(&events, 0xBB, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Good");
        assert!(message.contains("Successfully"), "got: {message}");
    }

    #[tokio::test]
    async fn inject_dll_failed_broadcasts_error() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::Failed));

        handle_inject_dll_callback(&events, 0xBB, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, _) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Error");
    }

    #[tokio::test]
    async fn inject_dll_invalid_param_broadcasts_error() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::InvalidParam));

        handle_inject_dll_callback(&events, 0xBB, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("invalid parameter"), "got: {message}");
    }

    #[tokio::test]
    async fn inject_dll_arch_mismatch_broadcasts_error() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::ProcessArchMismatch));

        handle_inject_dll_callback(&events, 0xBB, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("architecture mismatch"), "got: {message}");
    }

    #[tokio::test]
    async fn inject_dll_unknown_status_returns_error() {
        let events = EventBus::default();
        let payload = build_status_payload(0xFFFF);

        let result = handle_inject_dll_callback(&events, 0xBB, 1, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload, got: {result:?}"
        );
    }

    // ── handle_spawn_dll_callback ───────────────────────────────────────────

    #[tokio::test]
    async fn spawn_dll_success_broadcasts_good() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::Success));

        handle_spawn_dll_callback(&events, 0xCC, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Good");
        assert!(message.contains("Successfully"), "got: {message}");
    }

    #[tokio::test]
    async fn spawn_dll_failed_broadcasts_error() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::Failed));

        handle_spawn_dll_callback(&events, 0xCC, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, _) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Error");
    }

    #[tokio::test]
    async fn spawn_dll_invalid_param_broadcasts_error() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::InvalidParam));

        handle_spawn_dll_callback(&events, 0xCC, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("invalid parameter"), "got: {message}");
    }

    #[tokio::test]
    async fn spawn_dll_arch_mismatch_broadcasts_error() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_status_payload(u32::from(DemonInjectError::ProcessArchMismatch));

        handle_spawn_dll_callback(&events, 0xCC, 1, &payload).await.expect("should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("architecture mismatch"), "got: {message}");
    }

    #[tokio::test]
    async fn spawn_dll_unknown_status_returns_error() {
        let events = EventBus::default();
        let payload = build_status_payload(0xFFFF);

        let result = handle_spawn_dll_callback(&events, 0xCC, 1, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload, got: {result:?}"
        );
    }

    // ── handle_process_command_callback — Kill branch ──────────────────────

    fn build_process_kill_payload(success: u32, pid: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32(&mut buf, u32::from(DemonProcessCommand::Kill));
        add_u32(&mut buf, success);
        add_u32(&mut buf, pid);
        buf
    }

    #[tokio::test]
    async fn process_kill_success_broadcasts_good_with_pid() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_process_kill_payload(1, 4200);

        handle_process_command_callback(&events, 0xA1, 10, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Good");
        assert!(message.contains("4200"), "expected pid in message, got: {message}");
    }

    #[tokio::test]
    async fn process_kill_failure_broadcasts_error() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_process_kill_payload(0, 4200);

        handle_process_command_callback(&events, 0xA2, 11, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        let (kind, message) = extract_response_kind_and_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("Failed"), "expected failure message, got: {message}");
    }

    // ── handle_process_command_callback — Kill branch (truncated payloads) ─

    #[tokio::test]
    async fn process_kill_empty_payload_returns_error() {
        let events = EventBus::default();
        // Payload: only the subcommand u32 (Kill), no success or pid fields.
        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonProcessCommand::Kill));

        let result = handle_process_command_callback(&events, 0xA3, 12, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for empty kill body, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn process_kill_truncated_pid_returns_error() {
        let events = EventBus::default();
        // Payload: subcommand u32 (Kill) + success u32, but NO pid field.
        let mut payload = Vec::new();
        add_u32(&mut payload, u32::from(DemonProcessCommand::Kill));
        add_u32(&mut payload, 1); // success field only

        let result = handle_process_command_callback(&events, 0xA4, 13, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated kill pid, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn process_kill_full_payload_success_returns_ok() {
        // Regression guard: a well-formed 8-byte body (success=1, pid) must still succeed.
        let events = EventBus::default();
        let payload = build_process_kill_payload(1, 9999);

        let result = handle_process_command_callback(&events, 0xA5, 14, &payload).await;
        assert!(result.is_ok(), "expected Ok for full kill payload, got: {result:?}");
    }

    // ── handle_process_command_callback — Modules branch ────────────────────

    fn add_string(buf: &mut Vec<u8>, value: &str) {
        let bytes = value.as_bytes();
        add_u32(buf, u32::try_from(bytes.len()).expect("unwrap"));
        buf.extend_from_slice(bytes);
    }

    fn add_u64(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn build_process_modules_payload(pid: u32, modules: &[(&str, u64)]) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32(&mut buf, u32::from(DemonProcessCommand::Modules));
        add_u32(&mut buf, pid);
        for &(name, base) in modules {
            add_string(&mut buf, name);
            add_u64(&mut buf, base);
        }
        buf
    }

    #[tokio::test]
    async fn process_modules_broadcasts_info_with_table_and_json() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_process_modules_payload(
            1234,
            &[("ntdll.dll", 0x7FFE_0000_0000), ("kernel32.dll", 0x7FFE_0001_0000)],
        );

        handle_process_command_callback(&events, 0xB1, 20, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");

        let OperatorMessage::AgentResponse(ref msg) = event else {
            panic!("expected AgentResponse, got {event:?}");
        };

        let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(kind, "Info");

        let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(message.contains("1234"), "expected PID in message, got: {message}");

        let rows_json = msg.info.extra.get("ModuleRows").expect("missing ModuleRows");
        let arr = rows_json.as_array().expect("ModuleRows should be array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["Name"], "ntdll.dll");
        assert_eq!(arr[1]["Name"], "kernel32.dll");
    }

    #[tokio::test]
    async fn process_modules_empty_list_still_broadcasts() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_process_modules_payload(999, &[]);

        handle_process_command_callback(&events, 0xB2, 21, &payload)
            .await
            .expect("handler should succeed");

        // Empty module table → format_module_table returns "" but handler still broadcasts
        // because the Modules branch always broadcasts (unlike process list which checks is_empty)
        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");

        let OperatorMessage::AgentResponse(ref msg) = event else {
            panic!("expected AgentResponse, got {event:?}");
        };
        let rows_json = msg.info.extra.get("ModuleRows").expect("missing ModuleRows");
        let arr = rows_json.as_array().expect("ModuleRows should be array");
        assert!(arr.is_empty());
    }

    // ── handle_process_command_callback — Grep branch ───────────────────────

    fn add_bytes_raw(buf: &mut Vec<u8>, data: &[u8]) {
        add_u32(buf, u32::try_from(data.len()).expect("unwrap"));
        buf.extend_from_slice(data);
    }

    fn build_process_grep_payload(rows: &[(&str, u32, u32, &[u8], u32)]) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32(&mut buf, u32::from(DemonProcessCommand::Grep));
        for &(name, pid, ppid, user_bytes, arch) in rows {
            add_utf16(&mut buf, name);
            add_u32(&mut buf, pid);
            add_u32(&mut buf, ppid);
            add_bytes_raw(&mut buf, user_bytes);
            add_u32(&mut buf, arch);
        }
        buf
    }

    #[tokio::test]
    async fn process_grep_broadcasts_info_with_table_and_json() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_process_grep_payload(&[
            ("lsass.exe", 700, 4, b"SYSTEM\0", 64),
            ("cmd.exe", 1200, 700, b"user1\0", 86),
        ]);

        handle_process_command_callback(&events, 0xC1, 30, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");

        let OperatorMessage::AgentResponse(ref msg) = event else {
            panic!("expected AgentResponse, got {event:?}");
        };

        let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(kind, "Info");

        let rows_json = msg.info.extra.get("GrepRows").expect("missing GrepRows");
        let arr = rows_json.as_array().expect("GrepRows should be array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["Name"], "lsass.exe");
        assert_eq!(arr[0]["PID"], 700);
        assert_eq!(arr[0]["User"], "SYSTEM");
        assert_eq!(arr[0]["Arch"], "x64"); // arch != 86 → x64
        assert_eq!(arr[1]["Name"], "cmd.exe");
        assert_eq!(arr[1]["Arch"], "x86"); // arch == 86 → x86
    }

    #[tokio::test]
    async fn process_grep_user_bytes_null_terminator_edge_cases() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_process_grep_payload(&[
            // No null terminator — raw string should be preserved as-is
            ("notepad.exe", 100, 4, b"admin", 64),
            // Multiple trailing null bytes — all should be stripped
            ("svchost.exe", 200, 4, b"user\0\0\0", 64),
            // Entirely null bytes — should produce an empty string
            ("idle.exe", 300, 4, b"\0", 86),
        ]);

        handle_process_command_callback(&events, 0xC2, 31, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");

        let OperatorMessage::AgentResponse(ref msg) = event else {
            panic!("expected AgentResponse, got {event:?}");
        };

        let rows_json = msg.info.extra.get("GrepRows").expect("missing GrepRows");
        let arr = rows_json.as_array().expect("GrepRows should be array");
        assert_eq!(arr.len(), 3);

        // No null terminator — user string preserved
        assert_eq!(arr[0]["Name"], "notepad.exe");
        assert_eq!(arr[0]["User"], "admin");

        // Multiple trailing nulls — all stripped
        assert_eq!(arr[1]["Name"], "svchost.exe");
        assert_eq!(arr[1]["User"], "user");

        // Entirely null — empty string
        assert_eq!(arr[2]["Name"], "idle.exe");
        assert_eq!(arr[2]["User"], "");
    }

    // ── handle_process_command_callback — Memory branch ─────────────────────

    fn build_process_memory_payload(
        pid: u32,
        query_protect: u32,
        regions: &[(u64, u32, u32, u32, u32)],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32(&mut buf, u32::from(DemonProcessCommand::Memory));
        add_u32(&mut buf, pid);
        add_u32(&mut buf, query_protect);
        for &(base, size, protect, state, mem_type) in regions {
            add_u64(&mut buf, base);
            add_u32(&mut buf, size);
            add_u32(&mut buf, protect);
            add_u32(&mut buf, state);
            add_u32(&mut buf, mem_type);
        }
        buf
    }

    #[tokio::test]
    async fn process_memory_broadcasts_info_with_table_and_json() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_process_memory_payload(
            500,
            0, // query_protect=0 → "All"
            &[(0x7FF0_0000_0000, 0x1000, 0x20, 0x1000, 0x20000)],
        );

        handle_process_command_callback(&events, 0xD1, 40, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");

        let OperatorMessage::AgentResponse(ref msg) = event else {
            panic!("expected AgentResponse, got {event:?}");
        };

        let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(kind, "Info");

        let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(message.contains("500"), "expected PID in message, got: {message}");
        assert!(message.contains("All"), "expected 'All' filter, got: {message}");

        let rows_json = msg.info.extra.get("MemoryRows").expect("missing MemoryRows");
        let arr = rows_json.as_array().expect("MemoryRows should be array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["Protect"], "PAGE_EXECUTE_READ");
        assert_eq!(arr[0]["State"], "MEM_COMMIT");
        assert_eq!(arr[0]["Type"], "MEM_PRIVATE");
    }

    #[tokio::test]
    async fn process_memory_with_protect_filter_shows_protect_name() {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let payload = build_process_memory_payload(
            600,
            0x40, // PAGE_EXECUTE_READWRITE
            &[(0x1000, 0x100, 0x40, 0x1000, 0x1000000)],
        );

        handle_process_command_callback(&events, 0xD2, 41, &payload)
            .await
            .expect("handler should succeed");

        let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .expect("timeout")
            .expect("event");

        let OperatorMessage::AgentResponse(ref msg) = event else {
            panic!("expected AgentResponse, got {event:?}");
        };
        let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            message.contains("PAGE_EXECUTE_READWRITE"),
            "expected protect name in filter, got: {message}"
        );
    }

    // ── handle_process_command_callback — invalid subcommand ────────────────

    #[tokio::test]
    async fn process_command_invalid_subcommand_returns_error() {
        let events = EventBus::default();
        let mut buf = Vec::new();
        add_u32(&mut buf, 0xFF); // invalid subcommand

        let result = handle_process_command_callback(&events, 0xE1, 50, &buf).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for invalid subcommand, got: {result:?}"
        );
    }

    // ── handle_process_command_callback — truncated multi-row payload ───────

    #[tokio::test]
    async fn process_modules_truncated_second_row_returns_error() {
        let events = EventBus::default();
        // Build a valid first module row, then a truncated second row
        let mut buf = Vec::new();
        add_u32(&mut buf, u32::from(DemonProcessCommand::Modules));
        add_u32(&mut buf, 1234); // pid
        // First complete module row
        add_string(&mut buf, "ntdll.dll");
        add_u64(&mut buf, 0x7FFE_0000_0000);
        // Second row: name length says 10 bytes, but only provide 3
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&[0x41, 0x42, 0x43]); // only 3 of the promised 10 bytes

        let result = handle_process_command_callback(&events, 0xF1, 60, &buf).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated module row, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn inject_shellcode_truncated_payload_returns_error() {
        let events = EventBus::default();
        let result = handle_inject_shellcode_callback(&events, 0xAA, 1, &[0x01]).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated payload, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn inject_dll_truncated_payload_returns_error() {
        let events = EventBus::default();
        let result = handle_inject_dll_callback(&events, 0xBB, 1, &[]).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated payload, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn spawn_dll_truncated_payload_returns_error() {
        let events = EventBus::default();
        let result = handle_spawn_dll_callback(&events, 0xCC, 1, &[0xFF, 0xFF]).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated payload, got: {result:?}"
        );
    }

    // ── Unicode / non-ASCII process name formatting ─────────────────────────
    //
    // Note on alignment: `format_process_table` and `format_grep_table` compute
    // column widths via `.len()` (byte length) and pad via `format!("{:<w$}", …)`
    // (which counts Unicode scalar values, not display width).  For multi-byte
    // UTF-8 characters this means:
    //
    //  - CJK characters: 3 bytes each, 1 char, 2 display columns
    //    → `.len()` over-counts vs char count → extra padding spaces
    //    → display columns = display_width + padding > expected column width
    //
    //  - Accented Latin (e.g. "é"): 2 bytes, 1 char, 1 display column
    //    → `.len()` over-counts vs char count → extra padding spaces
    //
    // The result is that rows with multi-byte names get more visual padding than
    // pure-ASCII rows, causing slight column misalignment.  This is a known
    // cosmetic limitation.  Fixing it properly requires a Unicode display-width
    // library (e.g. `unicode-width`).  The tests below document the current
    // behavior so any future fix can be validated.

    #[test]
    fn format_process_table_cjk_name_output_is_well_formed() {
        let rows = vec![
            make_process_row("测试进程.exe", 1000, 4),
            make_process_row("svchost.exe", 800, 4),
        ];
        let table = format_process_table(&rows);

        // All data must appear in the output
        assert!(table.contains("测试进程.exe"), "missing CJK process name:\n{table}");
        assert!(table.contains("svchost.exe"), "missing ASCII process name:\n{table}");
        assert!(table.contains("1000"), "missing PID 1000:\n{table}");
        assert!(table.contains("800"), "missing PID 800:\n{table}");

        // Must still have 4 lines: header, separator, 2 data rows
        assert_eq!(table.lines().count(), 4, "expected 4 lines:\n{table}");

        // Header and separator must still be present
        assert!(table.contains("Name"), "missing Name header:\n{table}");
        assert!(table.contains("----"), "missing separator:\n{table}");
    }

    #[test]
    fn format_process_table_cjk_name_byte_len_exceeds_char_count() {
        // "测试进程.exe" = 4 CJK chars (3 bytes each) + ".exe" (4 bytes) = 16 bytes, 8 chars
        // This documents the known divergence between .len() and char count.
        let name = "测试进程.exe";
        assert_eq!(name.len(), 16, "byte length");
        assert_eq!(name.chars().count(), 8, "char count");

        let rows = vec![make_process_row(name, 1, 0)];
        let table = format_process_table(&rows);
        let data_line = table.lines().nth(2).expect("data row");

        // The Name column is padded to byte-length (16) by format!("{:<16}", …),
        // but since the string is only 8 chars, format! adds 8 spaces of padding.
        // Verify the name appears and is followed by spaces (over-padded).
        assert!(
            data_line.contains("测试进程.exe"),
            "data line must contain CJK name:\n{data_line}"
        );
    }

    #[test]
    fn format_process_table_accented_latin_name_is_present() {
        // "Ünïcödé.exe" contains multi-byte Latin chars
        let rows = vec![make_process_row("Ünïcödé.exe", 42, 1)];
        let table = format_process_table(&rows);

        assert!(table.contains("Ünïcödé.exe"), "missing accented name:\n{table}");
        assert_eq!(table.lines().count(), 3, "expected 3 lines:\n{table}");
    }

    #[test]
    fn format_process_table_mixed_script_rows_all_present() {
        // Mix of ASCII, CJK, Cyrillic, and accented names
        let rows = vec![
            make_process_row("explorer.exe", 100, 4),
            make_process_row("测试.exe", 200, 4),
            make_process_row("процесс.exe", 300, 4),
            make_process_row("café.exe", 400, 4),
        ];
        let table = format_process_table(&rows);

        assert!(table.contains("explorer.exe"), "missing ASCII name:\n{table}");
        assert!(table.contains("测试.exe"), "missing CJK name:\n{table}");
        assert!(table.contains("процесс.exe"), "missing Cyrillic name:\n{table}");
        assert!(table.contains("café.exe"), "missing accented name:\n{table}");
        assert_eq!(table.lines().count(), 6, "expected 6 lines (header+sep+4 data):\n{table}");
    }

    #[test]
    fn format_process_table_unicode_user_field_is_present() {
        // Non-ASCII user name (e.g. domain with CJK characters)
        let row = ProcessRow {
            name: "cmd.exe".to_owned(),
            pid: 10,
            ppid: 1,
            session: 0,
            arch: "x64".to_owned(),
            threads: 1,
            user: "域\\管理员".to_owned(),
        };
        let table = format_process_table(&[row]);
        assert!(table.contains("域\\管理员"), "missing Unicode user:\n{table}");
    }

    #[test]
    fn format_grep_table_cjk_name_output_is_well_formed() {
        let rows = vec![GrepRow {
            name: "恶意软件.exe".to_owned(),
            pid: 999,
            ppid: 4,
            user: "SYSTEM".to_owned(),
            arch: "x64".to_owned(),
        }];
        let table = format_grep_table(&rows);

        assert!(table.contains("恶意软件.exe"), "missing CJK name:\n{table}");
        assert!(table.contains("999"), "missing PID:\n{table}");
        assert!(table.contains("SYSTEM"), "missing user:\n{table}");
        // header + separator + 1 data row
        assert_eq!(
            table.lines().filter(|l| !l.is_empty()).count(),
            3,
            "expected 3 non-empty lines:\n{table}"
        );
    }

    #[test]
    fn format_grep_table_unicode_user_is_present() {
        let rows = vec![GrepRow {
            name: "notepad.exe".to_owned(),
            pid: 50,
            ppid: 1,
            user: "用户".to_owned(),
            arch: "x86".to_owned(),
        }];
        let table = format_grep_table(&rows);
        assert!(table.contains("用户"), "missing Unicode user:\n{table}");
    }

    #[test]
    fn format_module_table_cjk_module_name_is_present() {
        let rows =
            vec![ModuleRow { name: "テスト.dll".to_owned(), base: 0x7FFE_0000_0000_0000 }];
        let table = format_module_table(&rows);
        assert!(table.contains("テスト.dll"), "missing CJK module name:\n{table}");
    }

    #[test]
    fn format_process_table_empty_name_does_not_panic() {
        // Edge case: empty process name (could happen with malformed agent data)
        let rows = vec![make_process_row("", 1, 0)];
        let table = format_process_table(&rows);
        // Name column minimum width is 4 ("Name" header), so this should still work
        assert_eq!(table.lines().count(), 3, "expected 3 lines:\n{table}");
    }
}
