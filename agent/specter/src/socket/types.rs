//! Internal types for socket registry state.

use std::net::{TcpListener, TcpStream};

use red_cell_common::demon::DemonSocketType;

/// A pending response to be sent back to the teamserver.
#[derive(Debug, Clone)]
pub(super) struct PendingSocketResponse {
    pub(super) request_id: u32,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct ReversePortForward {
    pub(super) listener: TcpListener,
    pub(super) mode: ReversePortForwardMode,
    pub(super) bind_addr: u32,
    pub(super) bind_port: u32,
    pub(super) forward_addr: u32,
    pub(super) forward_port: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReversePortForwardMode {
    Teamserver,
    Local,
}

#[derive(Debug)]
pub(super) struct SocksProxy {
    pub(super) listener: TcpListener,
    pub(super) bind_addr: u32,
    pub(super) bind_port: u32,
}

#[derive(Debug)]
pub(super) struct ManagedSocket {
    pub(super) stream: TcpStream,
    pub(super) socket_type: DemonSocketType,
    pub(super) bind_addr: u32,
    pub(super) bind_port: u32,
    pub(super) forward_addr: u32,
    pub(super) forward_port: u32,
}

#[derive(Debug)]
pub(super) struct LocalRelayConnection {
    pub(super) left: TcpStream,
    pub(super) right: TcpStream,
    pub(super) parent_id: u32,
}

#[derive(Debug)]
pub(super) struct SocksClient {
    pub(super) stream: TcpStream,
    pub(super) server_id: u32,
    pub(super) state: SocksClientState,
}

#[derive(Debug)]
pub(super) enum SocksClientState {
    Greeting { buffer: Vec<u8> },
    Request { buffer: Vec<u8> },
    Relay { target: TcpStream },
}
