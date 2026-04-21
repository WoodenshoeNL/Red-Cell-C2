//! SOCKS5 protocol codec functions for the socket relay subsystem.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tracing::warn;

use crate::TeamserverError;

use super::types::{
    SOCKS_ATYP_DOMAIN, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6, SOCKS_COMMAND_CONNECT,
    SOCKS_METHOD_NO_AUTH, SOCKS_METHOD_NOT_ACCEPTABLE, SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
    SOCKS_REPLY_GENERAL_FAILURE, SOCKS_VERSION, SocksConnectRequest,
};

#[cfg(test)]
mod tests;

pub(super) async fn negotiate_socks5(stream: &mut TcpStream) -> Result<(), io::Error> {
    let version = read_u8(stream).await?;
    if version != SOCKS_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS version"));
    }

    let method_count = usize::from(read_u8(stream).await?);
    let mut methods = vec![0_u8; method_count];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&SOCKS_METHOD_NO_AUTH) {
        stream.write_all(&[SOCKS_VERSION, SOCKS_METHOD_NOT_ACCEPTABLE]).await?;
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "SOCKS no-auth unavailable"));
    }

    stream.write_all(&[SOCKS_VERSION, SOCKS_METHOD_NO_AUTH]).await
}

pub(super) async fn read_socks_connect_request(
    stream: &mut TcpStream,
) -> Result<SocksConnectRequest, io::Error> {
    let version = read_u8(stream).await?;
    let command = read_u8(stream).await?;
    let _reserved = read_u8(stream).await?;
    let atyp = read_u8(stream).await?;

    if version != SOCKS_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS request version"));
    }

    if command != SOCKS_COMMAND_CONNECT {
        stream
            .write_all(&[
                SOCKS_VERSION,
                SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
                0,
                SOCKS_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await?;
        return Err(io::Error::new(io::ErrorKind::Unsupported, "SOCKS command not supported"));
    }

    let address = match atyp {
        SOCKS_ATYP_IPV4 => read_exact_vec(stream, 4).await?,
        SOCKS_ATYP_IPV6 => read_exact_vec(stream, 16).await?,
        SOCKS_ATYP_DOMAIN => {
            let len = usize::from(read_u8(stream).await?);
            read_exact_vec(stream, len).await?
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS address type")),
    };

    let mut port_bytes = [0_u8; 2];
    stream.read_exact(&mut port_bytes).await?;

    Ok(SocksConnectRequest { atyp, address, port: u16::from_be_bytes(port_bytes) })
}

pub(super) async fn send_socks_connect_reply(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    reply: u8,
    atyp: u8,
    address: &[u8],
    port: u16,
) {
    if atyp == SOCKS_ATYP_DOMAIN && address.len() > usize::from(u8::MAX) {
        warn!(
            address_len = address.len(),
            "refusing to send invalid SOCKS5 domain reply with oversized address"
        );
        let failure_response =
            [SOCKS_VERSION, SOCKS_REPLY_GENERAL_FAILURE, 0, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0];
        let mut writer = writer.lock().await;
        let _ = writer.write_all(&failure_response).await;
        return;
    }

    let mut response = vec![SOCKS_VERSION, reply, 0, atyp];
    match atyp {
        SOCKS_ATYP_DOMAIN => {
            response.push(address.len() as u8);
            response.extend_from_slice(address);
        }
        _ => response.extend_from_slice(address),
    }
    response.extend_from_slice(&port.to_be_bytes());

    let mut writer = writer.lock().await;
    let _ = writer.write_all(&response).await;
}

async fn read_u8(stream: &mut TcpStream) -> Result<u8, io::Error> {
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte).await?;
    Ok(byte[0])
}

async fn read_exact_vec(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>, io::Error> {
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub(super) fn write_len_prefixed_bytes(
    buf: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), TeamserverError> {
    let len = u32::try_from(value.len())
        .map_err(|_| TeamserverError::PayloadTooLarge { length: value.len() })?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(value);
    Ok(())
}
