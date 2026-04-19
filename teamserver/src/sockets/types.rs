//! Type definitions and small helpers for the socket relay module.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{Mutex, oneshot};

use crate::TeamserverError;

// ── SOCKS5 protocol constants ───────────────────────────────────────────────

pub(super) const SOCKS_VERSION: u8 = 5;
pub(super) const SOCKS_METHOD_NO_AUTH: u8 = 0;
pub(super) const SOCKS_METHOD_NOT_ACCEPTABLE: u8 = 0xFF;
pub(super) const SOCKS_COMMAND_CONNECT: u8 = 1;
pub(super) const SOCKS_REPLY_SUCCEEDED: u8 = 0;
pub(super) const SOCKS_REPLY_GENERAL_FAILURE: u8 = 1;
pub(super) const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;
pub(super) const SOCKS_ATYP_IPV4: u8 = 1;
pub(super) const SOCKS_ATYP_DOMAIN: u8 = 3;
pub(super) const SOCKS_ATYP_IPV6: u8 = 4;

// ── Runtime constants ───────────────────────────────────────────────────────

pub(super) const STALE_AGENT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum concurrent SOCKS client connections per agent.
pub(super) const MAX_SOCKETS_PER_AGENT: usize = 256;

/// Maximum concurrent SOCKS client connections across all agents.
pub(super) const MAX_GLOBAL_SOCKETS: usize = 4096;

/// Maximum number of active SOCKS relay server listeners across all agents.
pub(super) const MAX_RELAY_LISTENERS: usize = 64;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by [`super::SocketRelayManager`].
#[derive(Debug, Error)]
pub enum SocketRelayError {
    /// The teamserver could not update the agent job queue.
    #[error("{0}")]
    Teamserver(#[from] TeamserverError),
    /// The provided SOCKS port is invalid.
    #[error("invalid SOCKS5 port `{port}`")]
    InvalidPort {
        /// Invalid port string.
        port: String,
    },
    /// A tracked SOCKS server has an invalid local bind address.
    #[error("invalid SOCKS5 listener address `{local_addr}`")]
    InvalidLocalAddress {
        /// Invalid local bind address string.
        local_addr: String,
    },
    /// A SOCKS server on the same port already exists for the agent.
    #[error("a SOCKS5 proxy on port {port} already exists for agent 0x{agent_id:08X}")]
    DuplicateServer {
        /// Agent identifier.
        agent_id: u32,
        /// Duplicate local port.
        port: u16,
    },
    /// No matching SOCKS server was found.
    #[error("SOCKS5 proxy on port {port} not found for agent 0x{agent_id:08X}")]
    ServerNotFound {
        /// Agent identifier.
        agent_id: u32,
        /// Missing local port.
        port: u16,
    },
    /// A requested client socket is no longer present.
    #[error("SOCKS5 client 0x{socket_id:08X} not found for agent 0x{agent_id:08X}")]
    ClientNotFound {
        /// Agent identifier.
        agent_id: u32,
        /// Missing socket identifier.
        socket_id: u32,
    },
    /// The local SOCKS listener could not bind.
    #[error("failed to bind SOCKS5 listener on {bind_addr}: {message}")]
    BindFailed {
        /// Socket bind address.
        bind_addr: String,
        /// IO failure message.
        message: String,
    },
    /// Per-agent connection limit reached.
    #[error("agent 0x{agent_id:08X} has reached the per-agent SOCKS connection limit ({limit})")]
    AgentConnectionLimit {
        /// Agent identifier.
        agent_id: u32,
        /// The enforced limit.
        limit: usize,
    },
    /// Global connection limit reached.
    #[error("global SOCKS connection limit reached ({limit})")]
    GlobalConnectionLimit {
        /// The enforced limit.
        limit: usize,
    },
    /// Maximum number of relay server listeners reached.
    #[error("relay listener limit reached ({limit})")]
    ListenerLimit {
        /// The enforced limit.
        limit: usize,
    },
}

// ── Internal types ──────────────────────────────────────────────────────────

/// A point-in-time snapshot of an agent's active socket relay state.
///
/// Populated by [`super::SocketRelayManager::agent_socket_snapshot`] and used to fill
/// the `PortFwds`, `SocksCli`, and `SocksSvr` fields in the operator agent info.
#[derive(Clone, Debug, Default)]
pub struct AgentSocketSnapshot {
    /// Formatted strings for each active reverse port forward, e.g. `"127.0.0.1:8080 -> 10.0.0.1:80"`.
    pub port_fwds: Vec<String>,
    /// Formatted strings for each active SOCKS5 relay server listener, e.g. `"127.0.0.1:1080"`.
    pub socks_svr: Vec<String>,
    /// Formatted strings for each pending/connected SOCKS5 client session.
    pub socks_cli: Vec<String>,
}

#[derive(Clone, Debug)]
pub(super) struct PortFwdEntry {
    pub(super) display: String,
}

#[derive(Debug, Default)]
pub(super) struct AgentSocketState {
    pub(super) servers: BTreeMap<u16, SocksServerHandle>,
    pub(super) clients: HashMap<u32, PendingClient>,
    /// Active reverse port forwards, keyed by socket ID.
    pub(super) port_fwds: BTreeMap<u32, PortFwdEntry>,
}

#[derive(Debug)]
pub(super) struct RelayStateSweeper {
    pub(super) shutdown: Option<oneshot::Sender<()>>,
    pub(super) task: tokio::task::JoinHandle<()>,
}

impl Drop for RelayStateSweeper {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

#[derive(Debug)]
pub(super) struct SocksServerHandle {
    pub(super) local_addr: String,
    pub(super) shutdown: Option<oneshot::Sender<()>>,
    pub(super) task: tokio::task::JoinHandle<()>,
}

impl SocksServerHandle {
    pub(super) fn shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }

    pub(super) fn port(&self) -> Result<u16, SocketRelayError> {
        self.local_addr
            .rsplit(':')
            .next()
            .ok_or_else(|| SocketRelayError::InvalidLocalAddress {
                local_addr: self.local_addr.clone(),
            })?
            .parse::<u16>()
            .map_err(|_| SocketRelayError::InvalidLocalAddress {
                local_addr: self.local_addr.clone(),
            })
    }
}

impl Drop for SocksServerHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

#[derive(Debug)]
pub(super) struct PendingClient {
    pub(super) server_port: u16,
    pub(super) atyp: u8,
    pub(super) address: Vec<u8>,
    pub(super) port: u16,
    pub(super) connected: bool,
    pub(super) writer: Arc<Mutex<OwnedWriteHalf>>,
    pub(super) read_half: Option<tokio::net::tcp::OwnedReadHalf>,
}

#[derive(Debug)]
pub(super) struct SocksConnectRequest {
    pub(super) atyp: u8,
    pub(super) address: Vec<u8>,
    pub(super) port: u16,
}

// ── Small helpers ───────────────────────────────────────────────────────────

pub(super) fn parse_port(port: &str) -> Result<u16, SocketRelayError> {
    port.trim().parse::<u16>().map_err(|_| SocketRelayError::InvalidPort { port: port.to_owned() })
}

pub(super) fn io_error(error: TeamserverError) -> io::Error {
    io::Error::other(error.to_string())
}
