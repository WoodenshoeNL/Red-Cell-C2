//! I/O helpers, SOCKS5 protocol parser, and payload encode/parse functions.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;

use tokio::net::TcpStream as TokioTcpStream;

use red_cell_common::demon::{DemonSocketCommand, DemonSocketType};

use super::socket_state::SocketError;

// ─── SOCKS5 protocol constants ──────────────────────────────────────────────

pub(super) const SOCKS_VERSION: u8 = 5;
pub(super) const SOCKS_METHOD_NO_AUTH: u8 = 0;
pub(super) const SOCKS_METHOD_NOT_ACCEPTABLE: u8 = 0xFF;
pub(super) const SOCKS_COMMAND_CONNECT: u8 = 1;
pub(super) const SOCKS_REPLY_SUCCEEDED: u8 = 0;
pub(super) const SOCKS_REPLY_GENERAL_FAILURE: u8 = 1;
pub(super) const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;
pub(super) const SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 8;

// ─── Protocol types returned by the SOCKS5 parser ───────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SocksConnectRequest {
    pub(super) atyp: u8,
    pub(super) address: Vec<u8>,
    pub(super) port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SocksRequestError {
    GeneralFailure,
    CommandNotSupported,
    AddressTypeNotSupported,
}

// ─── Connection helpers ──────────────────────────────────────────────────────

/// Connect to a target via SOCKS5 address type.
pub(super) async fn connect_socks_target(
    atyp: u8,
    host: &[u8],
    port: u16,
) -> Result<TcpStream, u32> {
    let target = match atyp {
        1 if host.len() == 4 => format!("{}.{}.{}.{}:{port}", host[0], host[1], host[2], host[3]),
        3 => {
            let hostname = String::from_utf8(host.to_vec()).map_err(|_| 1_u32)?;
            format!("{hostname}:{port}")
        }
        4 if host.len() == 16 => {
            let segments: Vec<u16> = host
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect();
            format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{port}",
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            )
        }
        _ => return Err(1),
    };

    let stream = TokioTcpStream::connect(&target).await.map_err(|e| raw_socket_error(&e))?;
    let stream = stream.into_std().map_err(|e| raw_socket_error(&e))?;
    stream.set_nonblocking(true).map_err(|e| raw_socket_error(&e))?;
    Ok(stream)
}

/// Connect to an IPv4 target by u32 address and port.
pub(super) async fn connect_ipv4_target(addr: u32, port: u16) -> Result<TcpStream, u32> {
    use std::net::Ipv4Addr;
    let octets = Ipv4Addr::from(addr).octets();
    connect_socks_target(1, &octets, port).await
}

// ─── Stream I/O helpers ──────────────────────────────────────────────────────

/// Read all available data from a non-blocking stream.
pub(super) fn read_available(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> Result<bool, SocketError> {
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(SocketError::Io(e.to_string())),
        }
    }
}

/// Pump data from source to sink. Returns `true` if the connection is closed.
pub(super) fn pump_stream(source: &mut TcpStream, sink: &mut TcpStream) -> bool {
    let mut buffer = [0_u8; 4096];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => return true,
            Ok(read) => {
                if write_all_nonblocking(sink, &buffer[..read]).is_err() {
                    return true;
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return false,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return true,
        }
    }
}

/// Write all data to a non-blocking stream, retrying on EINTR.
pub(super) fn write_all_nonblocking(
    stream: &mut TcpStream,
    mut data: &[u8],
) -> std::io::Result<()> {
    while !data.is_empty() {
        match stream.write(data) {
            Ok(0) => return Err(std::io::Error::new(ErrorKind::WriteZero, "socket closed")),
            Ok(written) => data = &data[written..],
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ─── SOCKS5 protocol parser ──────────────────────────────────────────────────

/// Try to parse a SOCKS5 greeting from the buffer.
pub(super) fn try_parse_socks_greeting(buffer: &[u8]) -> Option<Result<usize, u8>> {
    if buffer.len() < 2 {
        return None;
    }
    if buffer[0] != SOCKS_VERSION {
        return Some(Err(SOCKS_METHOD_NOT_ACCEPTABLE));
    }
    let total = 2 + usize::from(buffer[1]);
    if buffer.len() < total {
        return None;
    }
    if !buffer[2..total].contains(&SOCKS_METHOD_NO_AUTH) {
        return Some(Err(SOCKS_METHOD_NOT_ACCEPTABLE));
    }
    Some(Ok(total))
}

/// Try to parse a SOCKS5 request from the buffer.
pub(super) fn try_parse_socks_request(
    buffer: &[u8],
) -> Option<Result<(usize, SocksConnectRequest), SocksRequestError>> {
    if buffer.len() < 4 {
        return None;
    }
    if buffer[0] != SOCKS_VERSION {
        return Some(Err(SocksRequestError::GeneralFailure));
    }
    if buffer[1] != SOCKS_COMMAND_CONNECT {
        return Some(Err(SocksRequestError::CommandNotSupported));
    }

    let atyp = buffer[3];
    let address_len = match atyp {
        1 => 4,
        3 => {
            if buffer.len() < 5 {
                return None;
            }
            usize::from(buffer[4]) + 1
        }
        4 => 16,
        _ => return Some(Err(SocksRequestError::AddressTypeNotSupported)),
    };

    let header_len = 4 + address_len;
    if buffer.len() < header_len + 2 {
        return None;
    }

    let address = match atyp {
        3 => buffer[5..header_len].to_vec(),
        _ => buffer[4..header_len].to_vec(),
    };
    let port = u16::from_be_bytes([buffer[header_len], buffer[header_len + 1]]);
    Some(Ok((header_len + 2, SocksConnectRequest { atyp, address, port })))
}

/// Send a SOCKS5 reply to a client stream.
pub(super) fn send_socks_reply(
    stream: &mut TcpStream,
    reply: u8,
    atyp: u8,
    address: &[u8],
    port: u16,
) -> Result<(), SocketError> {
    let mut response = vec![SOCKS_VERSION, reply, 0, atyp];
    match atyp {
        3 => {
            let length = u8::try_from(address.len())
                .map_err(|_| SocketError::Parse("SOCKS domain too long"))?;
            response.push(length);
            response.extend_from_slice(address);
        }
        _ => response.extend_from_slice(address),
    }
    response.extend_from_slice(&port.to_be_bytes());
    write_all_nonblocking(stream, &response).map_err(|e| SocketError::Io(e.to_string()))
}

/// Extract the raw OS error code from an I/O error.
pub(super) fn raw_socket_error(error: &std::io::Error) -> u32 {
    error.raw_os_error().and_then(|code| u32::try_from(code).ok()).unwrap_or(1)
}

// ─── Payload parsing helpers (LE, server → agent) ───────────────────────────

pub(super) fn parse_u32_le(buf: &[u8], offset: &mut usize) -> Result<u32, SocketError> {
    if buf.len() < *offset + 4 {
        return Err(SocketError::Parse("buffer too short for u32 LE"));
    }
    let val = u32::from_le_bytes(
        buf[*offset..*offset + 4]
            .try_into()
            .map_err(|_| SocketError::Parse("slice-to-array conversion failed"))?,
    );
    *offset += 4;
    Ok(val)
}

pub(super) fn parse_bytes_le(buf: &[u8], offset: &mut usize) -> Result<Vec<u8>, SocketError> {
    let len = parse_u32_le(buf, offset)? as usize;
    if buf.len() < *offset + len {
        return Err(SocketError::Parse("buffer too short for payload bytes"));
    }
    let bytes = buf[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(bytes)
}

// ─── Payload encoding helpers (BE, agent → server) ──────────────────────────

pub(super) fn encode_u32(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

pub(super) fn encode_bool(value: bool) -> Vec<u8> {
    encode_u32(u32::from(value))
}

pub(super) fn encode_bytes(value: &[u8]) -> Result<Vec<u8>, SocketError> {
    let len =
        u32::try_from(value.len()).map_err(|_| SocketError::Parse("socket payload too large"))?;
    let mut out = Vec::with_capacity(4 + value.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(out)
}

pub(super) fn encode_port_forward_add(
    command: DemonSocketCommand,
    success: bool,
    socket_id: u32,
    bind_addr: u32,
    bind_port: u32,
    forward_addr: u32,
    forward_port: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(command));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(bind_addr));
    payload.extend_from_slice(&encode_u32(bind_port));
    payload.extend_from_slice(&encode_u32(forward_addr));
    payload.extend_from_slice(&encode_u32(forward_port));
    payload
}

pub(super) fn encode_socket_open(
    socket_id: u32,
    bind_addr: u32,
    bind_port: u32,
    forward_addr: u32,
    forward_port: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Open));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(bind_addr));
    payload.extend_from_slice(&encode_u32(bind_port));
    payload.extend_from_slice(&encode_u32(forward_addr));
    payload.extend_from_slice(&encode_u32(forward_port));
    payload
}

pub(super) fn encode_socket_read_success(
    socket_id: u32,
    socket_type: DemonSocketType,
    data: &[u8],
) -> Result<Vec<u8>, SocketError> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Read));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(u32::from(socket_type)));
    payload.extend_from_slice(&encode_bool(true));
    payload.extend_from_slice(&encode_bytes(data)?);
    Ok(payload)
}

pub(super) fn encode_socket_read_failure(
    socket_id: u32,
    socket_type: DemonSocketType,
    error_code: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Read));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(u32::from(socket_type)));
    payload.extend_from_slice(&encode_bool(false));
    payload.extend_from_slice(&encode_u32(error_code));
    payload
}

pub(super) fn encode_socket_write_failure(
    socket_id: u32,
    socket_type: DemonSocketType,
    error_code: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Write));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(u32::from(socket_type)));
    payload.extend_from_slice(&encode_bool(false));
    payload.extend_from_slice(&encode_u32(error_code));
    payload
}

pub(super) fn encode_socket_close(socket_id: u32, socket_type: DemonSocketType) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Close));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(u32::from(socket_type)));
    payload
}

pub(super) fn encode_socket_connect(success: bool, socket_id: u32, error_code: u32) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Connect));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(error_code));
    payload
}

pub(super) fn encode_socks_proxy_add(
    success: bool,
    socket_id: u32,
    bind_addr: u32,
    bind_port: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyAdd));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(bind_addr));
    payload.extend_from_slice(&encode_u32(bind_port));
    payload
}

pub(super) fn encode_socks_proxy_remove(socket_id: u32) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyRemove));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload
}

pub(super) fn encode_socks_proxy_clear(success: bool) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyClear));
    payload.extend_from_slice(&encode_bool(success));
    payload
}

pub(super) fn encode_rportfwd_remove(
    socket_id: u32,
    socket_type: DemonSocketType,
    bind_addr: u32,
    bind_port: u32,
    forward_addr: u32,
    forward_port: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::ReversePortForwardRemove));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(u32::from(socket_type)));
    payload.extend_from_slice(&encode_u32(bind_addr));
    payload.extend_from_slice(&encode_u32(bind_port));
    payload.extend_from_slice(&encode_u32(forward_addr));
    payload.extend_from_slice(&encode_u32(forward_port));
    payload
}

pub(super) fn encode_socket_clear(success: bool) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::ReversePortForwardClear));
    payload.extend_from_slice(&encode_bool(success));
    payload
}
