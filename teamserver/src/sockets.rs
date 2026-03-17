//! Teamserver-managed socket relay runtime for Demon `COMMAND_SOCKET` tasks.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use red_cell_common::demon::{DemonCommand, DemonSocketCommand};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::sync::{Mutex, RwLock, oneshot};
use tracing::{debug, warn};

use crate::{AgentRegistry, EventBus, Job, TeamserverError};

const SOCKS_VERSION: u8 = 5;
const SOCKS_METHOD_NO_AUTH: u8 = 0;
const SOCKS_METHOD_NOT_ACCEPTABLE: u8 = 0xFF;
const SOCKS_COMMAND_CONNECT: u8 = 1;
const SOCKS_REPLY_SUCCEEDED: u8 = 0;
const SOCKS_REPLY_GENERAL_FAILURE: u8 = 1;
const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;
const SOCKS_ATYP_IPV4: u8 = 1;
const SOCKS_ATYP_DOMAIN: u8 = 3;
const SOCKS_ATYP_IPV6: u8 = 4;
const STALE_AGENT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Errors returned by [`SocketRelayManager`].
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
}

/// Teamserver-owned SOCKS5 listeners and pending reverse-proxy client sockets.
#[derive(Clone, Debug)]
pub struct SocketRelayManager {
    registry: AgentRegistry,
    _events: EventBus,
    next_socket_id: Arc<AtomicU32>,
    state: Arc<RwLock<HashMap<u32, AgentSocketState>>>,
    _sweeper: Option<Arc<RelayStateSweeper>>,
}

impl SocketRelayManager {
    /// Create an empty socket relay manager.
    #[must_use]
    pub fn new(registry: AgentRegistry, events: EventBus) -> Self {
        let state = Arc::new(RwLock::new(HashMap::new()));
        let sweeper = spawn_stale_agent_sweeper(registry.clone(), state.clone());

        Self {
            registry,
            _events: events,
            next_socket_id: Arc::new(AtomicU32::new(1)),
            state,
            _sweeper: sweeper,
        }
    }

    /// Remove all relay state for an agent, closing local resources.
    pub async fn remove_agent(&self, agent_id: u32) -> bool {
        let agent_state = {
            let mut state = self.state.write().await;
            state.remove(&agent_id)
        };

        if let Some(agent_state) = agent_state {
            close_agent_state(agent_state).await;
            return true;
        }

        false
    }

    /// Remove relay state for agents that are missing or inactive in the registry.
    pub async fn prune_stale_agents(&self) -> usize {
        let active_agents = self
            .registry
            .list_active()
            .await
            .into_iter()
            .map(|agent| agent.agent_id)
            .collect::<std::collections::HashSet<_>>();
        let stale_states = {
            let mut state = self.state.write().await;
            let stale_agent_ids = state
                .keys()
                .copied()
                .filter(|agent_id| !active_agents.contains(agent_id))
                .collect::<Vec<_>>();
            stale_agent_ids
                .into_iter()
                .filter_map(|agent_id| state.remove(&agent_id))
                .collect::<Vec<_>>()
        };

        let removed = stale_states.len();
        for agent_state in stale_states {
            close_agent_state(agent_state).await;
        }

        removed
    }

    /// Start a SOCKS5 listener for an agent.
    pub async fn add_socks_server(
        &self,
        agent_id: u32,
        port: &str,
    ) -> Result<String, SocketRelayError> {
        let port = parse_port(port)?;
        let bind_addr = format!("127.0.0.1:{port}");
        let listener =
            TcpListener::bind(&bind_addr).await.map_err(|error| SocketRelayError::BindFailed {
                bind_addr: bind_addr.clone(),
                message: error.to_string(),
            })?;
        let local_addr = listener.local_addr().map(|addr| addr.to_string()).unwrap_or(bind_addr);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let manager = self.clone();

        {
            let mut state = self.state.write().await;
            let agent_state = state.entry(agent_id).or_default();
            if agent_state.servers.contains_key(&port) {
                return Err(SocketRelayError::DuplicateServer { agent_id, port });
            }

            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        accept = listener.accept() => {
                            let Ok((stream, peer_addr)) = accept else {
                                break;
                            };
                            let manager = manager.clone();
                            tokio::spawn(async move {
                                if let Err(error) = manager.handle_socks_client(agent_id, port, stream).await {
                                    warn!(agent_id = format_args!("{agent_id:08X}"), port, peer = %peer_addr, %error, "SOCKS5 client session failed");
                                }
                            });
                        }
                    }
                }
            });

            agent_state.servers.insert(
                port,
                SocksServerHandle {
                    local_addr: local_addr.clone(),
                    shutdown: Some(shutdown_tx),
                    task,
                },
            );
        }

        Ok(format!("Started SOCKS5 server on {local_addr}"))
    }

    /// Return a formatted list of active SOCKS5 listeners for an agent.
    pub async fn list_socks_servers(&self, agent_id: u32) -> String {
        let state = self.state.read().await;
        let Some(agent_state) = state.get(&agent_id) else {
            return "No active SOCKS5 servers".to_owned();
        };

        if agent_state.servers.is_empty() {
            return "No active SOCKS5 servers".to_owned();
        }

        let mut output = String::from("SOCKS5 servers:\n");
        for server in agent_state.servers.values() {
            output.push_str(" - ");
            output.push_str(&server.local_addr);
            output.push('\n');
        }
        output.trim_end().to_owned()
    }

    /// Stop a single SOCKS5 listener for an agent.
    pub async fn remove_socks_server(
        &self,
        agent_id: u32,
        port: &str,
    ) -> Result<String, SocketRelayError> {
        let port = parse_port(port)?;
        let mut handle = {
            let mut state = self.state.write().await;
            let Some(agent_state) = state.get_mut(&agent_id) else {
                return Err(SocketRelayError::ServerNotFound { agent_id, port });
            };
            agent_state
                .servers
                .remove(&port)
                .ok_or(SocketRelayError::ServerNotFound { agent_id, port })?
        };

        handle.shutdown();
        self.close_clients_for_port(agent_id, port).await?;
        Ok(format!("Closed SOCKS5 server on {}", handle.local_addr))
    }

    /// Stop every SOCKS5 listener for an agent.
    pub async fn clear_socks_servers(&self, agent_id: u32) -> Result<String, SocketRelayError> {
        let mut handles = {
            let mut state = self.state.write().await;
            let Some(agent_state) = state.get_mut(&agent_id) else {
                return Ok("No active SOCKS5 servers".to_owned());
            };
            let handles = std::mem::take(&mut agent_state.servers)
                .into_values()
                .collect::<Vec<SocksServerHandle>>();
            let ports =
                handles.iter().map(SocksServerHandle::port).collect::<Result<Vec<_>, _>>()?;
            drop(state);
            for port in ports {
                self.close_clients_for_port(agent_id, port).await?;
            }
            handles
        };

        if handles.is_empty() {
            return Ok("No active SOCKS5 servers".to_owned());
        }

        for handle in &mut handles {
            handle.shutdown();
        }

        Ok(format!("Closed {} SOCKS5 server(s)", handles.len()))
    }

    /// Deliver reverse-proxy bytes received from the agent to a pending SOCKS client.
    pub async fn write_client_data(
        &self,
        agent_id: u32,
        socket_id: u32,
        data: &[u8],
    ) -> Result<(), SocketRelayError> {
        let writer = {
            let state = self.state.read().await;
            let Some(agent_state) = state.get(&agent_id) else {
                return Err(SocketRelayError::ClientNotFound { agent_id, socket_id });
            };
            let Some(client) = agent_state.clients.get(&socket_id) else {
                return Err(SocketRelayError::ClientNotFound { agent_id, socket_id });
            };
            client.writer.clone()
        };

        let mut writer = writer.lock().await;
        writer
            .write_all(data)
            .await
            .map_err(|_| SocketRelayError::ClientNotFound { agent_id, socket_id })
    }

    /// Finalize a SOCKS connect request after the agent reports success or failure.
    pub async fn finish_connect(
        &self,
        agent_id: u32,
        socket_id: u32,
        success: bool,
        error_code: u32,
    ) -> Result<(), SocketRelayError> {
        let pending = {
            let mut state = self.state.write().await;
            let Some(agent_state) = state.get_mut(&agent_id) else {
                return Err(SocketRelayError::ClientNotFound { agent_id, socket_id });
            };
            let Some(client) = agent_state.clients.get_mut(&socket_id) else {
                return Err(SocketRelayError::ClientNotFound { agent_id, socket_id });
            };
            client.connected = success;
            (
                client.writer.clone(),
                client.atyp,
                client.address.clone(),
                client.port,
                client.read_half.take(),
            )
        };

        if success {
            send_socks_connect_reply(
                &pending.0,
                SOCKS_REPLY_SUCCEEDED,
                pending.1,
                &pending.2,
                pending.3,
            )
            .await;
            if let Some(read_half) = pending.4 {
                self.spawn_client_reader(agent_id, socket_id, read_half).await;
            }
            return Ok(());
        }

        let reply = u8::try_from(error_code).unwrap_or(SOCKS_REPLY_GENERAL_FAILURE);
        send_socks_connect_reply(&pending.0, reply, pending.1, &pending.2, pending.3).await;
        let _ = self.remove_client(agent_id, socket_id).await;
        Ok(())
    }

    /// Close a pending or connected SOCKS client and remove it from the relay state.
    pub async fn close_client(
        &self,
        agent_id: u32,
        socket_id: u32,
    ) -> Result<(), SocketRelayError> {
        let client = self.remove_client(agent_id, socket_id).await?;
        let mut writer = client.writer.lock().await;
        let _ = writer.shutdown().await;
        Ok(())
    }

    async fn handle_socks_client(
        &self,
        agent_id: u32,
        server_port: u16,
        mut stream: TcpStream,
    ) -> Result<(), io::Error> {
        negotiate_socks5(&mut stream).await?;
        let request = read_socks_connect_request(&mut stream).await?;
        let socket_id = self.next_socket_id.fetch_add(1, Ordering::Relaxed);
        let (read_half, write_half) = stream.into_split();

        self.register_client(
            agent_id,
            socket_id,
            PendingClient {
                server_port,
                atyp: request.atyp,
                address: request.address.clone(),
                port: request.port,
                connected: false,
                writer: Arc::new(Mutex::new(write_half)),
                read_half: Some(read_half),
            },
        )
        .await;
        self.enqueue_connect_job(agent_id, socket_id, &request).await.map_err(io_error)?;
        Ok(())
    }

    async fn register_client(&self, agent_id: u32, socket_id: u32, client: PendingClient) {
        let mut state = self.state.write().await;
        let agent_state = state.entry(agent_id).or_default();
        agent_state.clients.insert(socket_id, client);
    }

    async fn spawn_client_reader(
        &self,
        agent_id: u32,
        socket_id: u32,
        mut reader: tokio::net::tcp::OwnedReadHalf,
    ) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut buf = vec![0_u8; 4096];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        let _ = manager.enqueue_close_job(agent_id, socket_id).await;
                        let _ = manager.remove_client(agent_id, socket_id).await;
                        break;
                    }
                    Ok(read) => {
                        if manager
                            .enqueue_write_job(agent_id, socket_id, &buf[..read])
                            .await
                            .is_err()
                        {
                            let _ = manager.remove_client(agent_id, socket_id).await;
                            break;
                        }
                    }
                    Err(error) => {
                        debug!(agent_id = format_args!("{agent_id:08X}"), socket_id = format_args!("{socket_id:08X}"), %error, "SOCKS5 client read loop failed");
                        let _ = manager.enqueue_close_job(agent_id, socket_id).await;
                        let _ = manager.remove_client(agent_id, socket_id).await;
                        break;
                    }
                }
            }
        });
    }

    async fn enqueue_connect_job(
        &self,
        agent_id: u32,
        socket_id: u32,
        request: &SocksConnectRequest,
    ) -> Result<(), TeamserverError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonSocketCommand::Connect).to_le_bytes());
        payload.extend_from_slice(&socket_id.to_le_bytes());
        payload.push(request.atyp);
        write_len_prefixed_bytes(&mut payload, &request.address)?;
        payload.extend_from_slice(&request.port.to_le_bytes());
        self.enqueue_socket_job(agent_id, socket_id, payload, "socket connect").await
    }

    async fn enqueue_write_job(
        &self,
        agent_id: u32,
        socket_id: u32,
        data: &[u8],
    ) -> Result<(), TeamserverError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonSocketCommand::Write).to_le_bytes());
        payload.extend_from_slice(&socket_id.to_le_bytes());
        write_len_prefixed_bytes(&mut payload, data)?;
        self.enqueue_socket_job(agent_id, socket_id, payload, "socket write").await
    }

    async fn enqueue_close_job(
        &self,
        agent_id: u32,
        socket_id: u32,
    ) -> Result<(), TeamserverError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonSocketCommand::Close).to_le_bytes());
        payload.extend_from_slice(&socket_id.to_le_bytes());
        self.enqueue_socket_job(agent_id, socket_id, payload, "socket close").await
    }

    async fn enqueue_socket_job(
        &self,
        agent_id: u32,
        socket_id: u32,
        payload: Vec<u8>,
        command_line: &str,
    ) -> Result<(), TeamserverError> {
        self.registry
            .enqueue_job(
                agent_id,
                Job {
                    command: u32::from(DemonCommand::CommandSocket),
                    request_id: 0,
                    payload,
                    command_line: command_line.to_owned(),
                    task_id: format!("relay-{socket_id:08X}"),
                    created_at: "0".to_owned(),
                    operator: String::new(),
                },
            )
            .await
    }

    async fn remove_client(
        &self,
        agent_id: u32,
        socket_id: u32,
    ) -> Result<PendingClient, SocketRelayError> {
        let mut state = self.state.write().await;
        let Some(agent_state) = state.get_mut(&agent_id) else {
            return Err(SocketRelayError::ClientNotFound { agent_id, socket_id });
        };
        agent_state
            .clients
            .remove(&socket_id)
            .ok_or(SocketRelayError::ClientNotFound { agent_id, socket_id })
    }

    async fn close_clients_for_port(
        &self,
        agent_id: u32,
        port: u16,
    ) -> Result<(), SocketRelayError> {
        let socket_ids = {
            let state = self.state.read().await;
            let Some(agent_state) = state.get(&agent_id) else {
                return Ok(());
            };
            agent_state
                .clients
                .iter()
                .filter_map(|(socket_id, client)| {
                    (client.server_port == port).then_some(*socket_id)
                })
                .collect::<Vec<_>>()
        };

        for socket_id in socket_ids {
            let _ = self.enqueue_close_job(agent_id, socket_id).await;
            let _ = self.close_client(agent_id, socket_id).await;
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
struct AgentSocketState {
    servers: BTreeMap<u16, SocksServerHandle>,
    clients: HashMap<u32, PendingClient>,
}

#[derive(Debug)]
struct RelayStateSweeper {
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
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
struct SocksServerHandle {
    local_addr: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl SocksServerHandle {
    fn shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }

    fn port(&self) -> Result<u16, SocketRelayError> {
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
struct PendingClient {
    server_port: u16,
    atyp: u8,
    address: Vec<u8>,
    port: u16,
    connected: bool,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    read_half: Option<tokio::net::tcp::OwnedReadHalf>,
}

#[derive(Debug)]
struct SocksConnectRequest {
    atyp: u8,
    address: Vec<u8>,
    port: u16,
}

fn parse_port(port: &str) -> Result<u16, SocketRelayError> {
    port.trim().parse::<u16>().map_err(|_| SocketRelayError::InvalidPort { port: port.to_owned() })
}

fn io_error(error: TeamserverError) -> io::Error {
    io::Error::other(error.to_string())
}

fn spawn_stale_agent_sweeper(
    registry: AgentRegistry,
    state: Arc<RwLock<HashMap<u32, AgentSocketState>>>,
) -> Option<Arc<RelayStateSweeper>> {
    let handle = Handle::try_current().ok()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let task = handle.spawn(async move {
        let mut ticker = tokio::time::interval(STALE_AGENT_SWEEP_INTERVAL);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = ticker.tick() => {
                    let _ = prune_stale_agent_state(&registry, &state).await;
                }
            }
        }
    });

    Some(Arc::new(RelayStateSweeper { shutdown: Some(shutdown_tx), task }))
}

async fn prune_stale_agent_state(
    registry: &AgentRegistry,
    state: &Arc<RwLock<HashMap<u32, AgentSocketState>>>,
) -> usize {
    let active_agents = registry
        .list_active()
        .await
        .into_iter()
        .map(|agent| agent.agent_id)
        .collect::<std::collections::HashSet<_>>();
    let stale_states = {
        let mut state = state.write().await;
        let stale_agent_ids = state
            .keys()
            .copied()
            .filter(|agent_id| !active_agents.contains(agent_id))
            .collect::<Vec<_>>();
        stale_agent_ids
            .into_iter()
            .filter_map(|agent_id| state.remove(&agent_id))
            .collect::<Vec<_>>()
    };

    let removed = stale_states.len();
    for agent_state in stale_states {
        close_agent_state(agent_state).await;
    }
    removed
}

async fn close_agent_state(agent_state: AgentSocketState) {
    for mut handle in agent_state.servers.into_values() {
        handle.shutdown();
    }

    for client in agent_state.clients.into_values() {
        let mut writer = client.writer.lock().await;
        let _ = writer.shutdown().await;
    }
}

async fn negotiate_socks5(stream: &mut TcpStream) -> Result<(), io::Error> {
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

async fn read_socks_connect_request(
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

async fn send_socks_connect_reply(
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

fn write_len_prefixed_bytes(buf: &mut Vec<u8>, value: &[u8]) -> Result<(), TeamserverError> {
    let len = u32::try_from(value.len())
        .map_err(|_| TeamserverError::PayloadTooLarge { length: value.len() })?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use red_cell_common::AgentEncryptionInfo;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use zeroize::Zeroizing;

    use super::{SocketRelayError, SocketRelayManager, SocksServerHandle};
    use crate::{AgentRegistry, Database, EventBus};

    async fn test_manager()
    -> Result<(Database, AgentRegistry, SocketRelayManager), SocketRelayError> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let manager = SocketRelayManager::new(registry.clone(), EventBus::default());
        Ok((database, registry, manager))
    }

    fn sample_agent(agent_id: u32) -> red_cell_common::AgentRecord {
        red_cell_common::AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0u8; 32]),
                aes_iv: Zeroizing::new(vec![0u8; 16]),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "LAB".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.10".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            base_address: 0,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 0,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-10T10:00:00Z".to_owned(),
            last_call_in: "2026-03-10T10:00:00Z".to_owned(),
        }
    }

    #[tokio::test]
    async fn socks_server_lifecycle_commands_track_state() -> Result<(), SocketRelayError> {
        let (_database, registry, manager) = test_manager().await?;
        registry.insert(sample_agent(0xDEAD_BEEF)).await?;

        let start = manager.add_socks_server(0xDEAD_BEEF, "0").await;
        assert!(start.is_ok());
        assert!(start.as_deref().is_ok_and(|message| message.contains("127.0.0.1:")));
        assert!(manager.list_socks_servers(0xDEAD_BEEF).await.contains("SOCKS5 servers"));
        let cleared = manager.clear_socks_servers(0xDEAD_BEEF).await;
        assert!(cleared.is_ok());
        assert_eq!(manager.list_socks_servers(0xDEAD_BEEF).await, "No active SOCKS5 servers");

        Ok(())
    }

    #[tokio::test]
    async fn add_socks_server_rejects_invalid_port() -> Result<(), SocketRelayError> {
        let (_database, registry, manager) = test_manager().await?;
        registry.insert(sample_agent(0xDEAD_BEEF)).await?;

        let invalid_text = manager.add_socks_server(0xDEAD_BEEF, "not-a-port").await;
        assert!(matches!(
            invalid_text,
            Err(SocketRelayError::InvalidPort { port }) if port == "not-a-port"
        ));

        let out_of_range = manager.add_socks_server(0xDEAD_BEEF, "99999").await;
        assert!(matches!(
            out_of_range,
            Err(SocketRelayError::InvalidPort { port }) if port == "99999"
        ));

        Ok(())
    }

    #[tokio::test]
    async fn add_socks_server_rejects_duplicate_server_registration() -> Result<(), SocketRelayError>
    {
        let (_database, registry, manager) = test_manager().await?;
        registry.insert(sample_agent(0xDEAD_BEEF)).await?;

        let duplicate_port = 0;
        let (shutdown_tx, _shutdown_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        {
            let mut state = manager.state.write().await;
            let agent_state = state.entry(0xDEAD_BEEF).or_default();
            agent_state.servers.insert(
                duplicate_port,
                SocksServerHandle {
                    local_addr: "127.0.0.1:0".to_owned(),
                    shutdown: Some(shutdown_tx),
                    task,
                },
            );
        }

        let duplicate = manager.add_socks_server(0xDEAD_BEEF, &duplicate_port.to_string()).await;
        assert!(matches!(
            duplicate,
            Err(SocketRelayError::DuplicateServer { agent_id, port })
                if agent_id == 0xDEAD_BEEF && port == duplicate_port
        ));

        manager.clear_socks_servers(0xDEAD_BEEF).await?;

        Ok(())
    }

    #[tokio::test]
    async fn remove_agent_clears_tracked_socket_state() -> Result<(), SocketRelayError> {
        let (_database, registry, manager) = test_manager().await?;
        registry.insert(sample_agent(0xDEAD_BEEF)).await?;

        manager.add_socks_server(0xDEAD_BEEF, "0").await?;
        assert!(manager.state.read().await.contains_key(&0xDEAD_BEEF));

        assert!(manager.remove_agent(0xDEAD_BEEF).await);
        assert!(!manager.state.read().await.contains_key(&0xDEAD_BEEF));
        assert_eq!(manager.list_socks_servers(0xDEAD_BEEF).await, "No active SOCKS5 servers");

        Ok(())
    }

    #[tokio::test]
    async fn prune_stale_agents_removes_inactive_agent_state() -> Result<(), SocketRelayError> {
        let (_database, registry, manager) = test_manager().await?;
        registry.insert(sample_agent(0xDEAD_BEEF)).await?;
        registry.insert(sample_agent(0xFEED_FACE)).await?;

        manager.add_socks_server(0xDEAD_BEEF, "0").await?;
        manager.add_socks_server(0xFEED_FACE, "0").await?;
        registry.mark_dead(0xDEAD_BEEF, "lost contact").await?;

        assert_eq!(manager.prune_stale_agents().await, 1);
        let state = manager.state.read().await;
        assert!(!state.contains_key(&0xDEAD_BEEF));
        assert!(state.contains_key(&0xFEED_FACE));

        Ok(())
    }

    #[tokio::test]
    async fn remove_socks_server_returns_server_not_found_for_unknown_agent()
    -> Result<(), SocketRelayError> {
        let (_database, _registry, manager) = test_manager().await?;

        let result = manager.remove_socks_server(0xDEAD_BEEF, "1080").await;

        assert!(matches!(
            result,
            Err(SocketRelayError::ServerNotFound { agent_id, port })
                if agent_id == 0xDEAD_BEEF && port == 1080
        ));

        Ok(())
    }

    #[tokio::test]
    async fn remove_socks_server_returns_server_not_found_for_unknown_port()
    -> Result<(), SocketRelayError> {
        let (_database, registry, manager) = test_manager().await?;
        registry.insert(sample_agent(0xDEAD_BEEF)).await?;
        manager.add_socks_server(0xDEAD_BEEF, "0").await?;

        let result = manager.remove_socks_server(0xDEAD_BEEF, "65535").await;

        assert!(matches!(
            result,
            Err(SocketRelayError::ServerNotFound { agent_id, port })
                if agent_id == 0xDEAD_BEEF && port == 65535
        ));
        manager.clear_socks_servers(0xDEAD_BEEF).await?;

        Ok(())
    }

    #[tokio::test]
    async fn write_client_data_returns_client_not_found_for_unknown_agent()
    -> Result<(), SocketRelayError> {
        let (_database, _registry, manager) = test_manager().await?;

        let result = manager.write_client_data(0xDEAD_BEEF, 0x1234_5678, b"relay").await;

        assert!(matches!(
            result,
            Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
                if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
        ));

        Ok(())
    }

    #[tokio::test]
    async fn write_client_data_returns_client_not_found_for_unknown_socket()
    -> Result<(), SocketRelayError> {
        let (_database, registry, manager) = test_manager().await?;
        registry.insert(sample_agent(0xDEAD_BEEF)).await?;
        manager.add_socks_server(0xDEAD_BEEF, "0").await?;

        let result = manager.write_client_data(0xDEAD_BEEF, 0x1234_5678, b"relay").await;

        assert!(matches!(
            result,
            Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
                if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
        ));
        manager.clear_socks_servers(0xDEAD_BEEF).await?;

        Ok(())
    }

    #[tokio::test]
    async fn close_client_returns_client_not_found_for_unknown_agent()
    -> Result<(), SocketRelayError> {
        let (_database, _registry, manager) = test_manager().await?;

        let result = manager.close_client(0xDEAD_BEEF, 0x1234_5678).await;

        assert!(matches!(
            result,
            Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
                if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
        ));

        Ok(())
    }

    #[tokio::test]
    async fn close_client_returns_client_not_found_for_unknown_socket()
    -> Result<(), SocketRelayError> {
        let (_database, registry, manager) = test_manager().await?;
        registry.insert(sample_agent(0xDEAD_BEEF)).await?;
        manager.add_socks_server(0xDEAD_BEEF, "0").await?;

        let result = manager.close_client(0xDEAD_BEEF, 0x1234_5678).await;

        assert!(matches!(
            result,
            Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
                if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
        ));
        manager.clear_socks_servers(0xDEAD_BEEF).await?;

        Ok(())
    }

    #[tokio::test]
    async fn socks_server_handle_shutdown_signals_graceful_exit() {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let graceful_exit = Arc::new(AtomicBool::new(false));
        let graceful_exit_task = Arc::clone(&graceful_exit);
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = shutdown_rx => graceful_exit_task.store(true, Ordering::SeqCst),
                _ = std::future::pending::<()>() => {}
            }
        });
        let mut handle = SocksServerHandle {
            local_addr: "127.0.0.1:0".to_owned(),
            shutdown: Some(shutdown_tx),
            task,
        };

        handle.shutdown();

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !handle.task.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown task should finish");
        assert!(graceful_exit.load(Ordering::SeqCst));
        assert!(handle.shutdown.is_none());
    }

    #[tokio::test]
    async fn socks_server_handle_port_returns_error_for_invalid_local_addr() {
        let task = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        let handle =
            SocksServerHandle { local_addr: "invalid-address".to_owned(), shutdown: None, task };

        assert!(matches!(
            handle.port(),
            Err(SocketRelayError::InvalidLocalAddress { local_addr }) if local_addr == "invalid-address"
        ));
    }

    #[tokio::test]
    async fn clear_socks_servers_returns_error_for_invalid_local_addr()
    -> Result<(), SocketRelayError> {
        let (_database, registry, manager) = test_manager().await?;
        registry.insert(sample_agent(0xDEAD_BEEF)).await?;

        let (shutdown_tx, _shutdown_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        {
            let mut state = manager.state.write().await;
            let agent_state = state.entry(0xDEAD_BEEF).or_default();
            agent_state.servers.insert(
                1080,
                SocksServerHandle {
                    local_addr: "invalid-address".to_owned(),
                    shutdown: Some(shutdown_tx),
                    task,
                },
            );
        }

        let result = manager.clear_socks_servers(0xDEAD_BEEF).await;

        assert!(matches!(
            result,
            Err(SocketRelayError::InvalidLocalAddress { local_addr }) if local_addr == "invalid-address"
        ));

        Ok(())
    }

    async fn connected_write_half_and_reader() -> io::Result<(
        Arc<tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>>,
        tokio::net::tcp::OwnedReadHalf,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let client = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (server_stream, _) = listener.accept().await?;
        let client_stream = client.await.map_err(|error| io::Error::other(error.to_string()))??;
        let (_client_read, client_write) = client_stream.into_split();
        let (server_read, _server_write) = server_stream.into_split();
        Ok((Arc::new(tokio::sync::Mutex::new(client_write)), server_read))
    }

    #[tokio::test]
    async fn send_socks_connect_reply_rejects_oversized_domain_addresses() -> io::Result<()> {
        let (writer, mut reader) = connected_write_half_and_reader().await?;
        let oversized_domain = vec![b'a'; usize::from(u8::MAX) + 1];

        super::send_socks_connect_reply(
            &writer,
            super::SOCKS_REPLY_SUCCEEDED,
            super::SOCKS_ATYP_DOMAIN,
            &oversized_domain,
            8080,
        )
        .await;

        let mut response = [0_u8; 10];
        reader.read_exact(&mut response).await?;

        assert_eq!(
            response,
            [
                super::SOCKS_VERSION,
                super::SOCKS_REPLY_GENERAL_FAILURE,
                0,
                super::SOCKS_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn send_socks_connect_reply_domain_success_path() -> io::Result<()> {
        let (writer, mut reader) = connected_write_half_and_reader().await?;
        let domain = b"example.com";

        super::send_socks_connect_reply(
            &writer,
            super::SOCKS_REPLY_SUCCEEDED,
            super::SOCKS_ATYP_DOMAIN,
            domain,
            443,
        )
        .await;

        // Expected: [VER=5, REP=0, RSV=0, ATYP=3, LEN=11, "example.com", PORT_HI=1, PORT_LO=187]
        let mut response = vec![0_u8; 4 + 1 + domain.len() + 2];
        reader.read_exact(&mut response).await?;

        assert_eq!(response[0], super::SOCKS_VERSION);
        assert_eq!(response[1], super::SOCKS_REPLY_SUCCEEDED);
        assert_eq!(response[2], 0); // reserved
        assert_eq!(response[3], super::SOCKS_ATYP_DOMAIN);
        assert_eq!(response[4], 11); // length prefix for "example.com"
        assert_eq!(&response[5..16], b"example.com");
        assert_eq!(&response[16..18], &443_u16.to_be_bytes());

        Ok(())
    }

    #[test]
    fn write_len_prefixed_bytes_normal_input() -> Result<(), SocketRelayError> {
        let mut buf = Vec::new();
        super::write_len_prefixed_bytes(&mut buf, b"data")?;
        assert_eq!(buf[..4], 4_u32.to_le_bytes());
        assert_eq!(&buf[4..], b"data");
        Ok(())
    }

    #[test]
    fn write_len_prefixed_bytes_empty_input() -> Result<(), SocketRelayError> {
        let mut buf = Vec::new();
        super::write_len_prefixed_bytes(&mut buf, &[])?;
        assert_eq!(buf, 0_u32.to_le_bytes());
        Ok(())
    }

    /// Returns a connected pair of `TcpStream`s: `(client, server)`.
    async fn connected_stream_pair() -> io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let client_task = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (server, _) = listener.accept().await?;
        let client = client_task.await.map_err(|e| io::Error::other(e.to_string()))??;
        Ok((client, server))
    }

    #[tokio::test]
    async fn negotiate_socks5_rejects_wrong_version() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send version=4 with one method (no-auth) — wrong SOCKS version.
        let client_task =
            tokio::spawn(
                async move { client.write_all(&[4, 1, super::SOCKS_METHOD_NO_AUTH]).await },
            );

        let result = super::negotiate_socks5(&mut server).await;

        assert!(result.is_err(), "negotiate_socks5 should return an error for version=4");
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "error kind should be InvalidData for wrong SOCKS version"
        );

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn negotiate_socks5_rejects_auth_only_methods() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send version=5 with only method 0x02 (username/password) — no no-auth offered.
        let client_task = tokio::spawn(async move {
            client.write_all(&[super::SOCKS_VERSION, 1, 0x02]).await?;
            // Read the rejection response sent by negotiate_socks5.
            let mut response = [0_u8; 2];
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut response).await?;
            io::Result::Ok(response)
        });

        let result = super::negotiate_socks5(&mut server).await;

        assert!(
            result.is_err(),
            "negotiate_socks5 should return an error when no-auth is not offered"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "error kind should be PermissionDenied when only auth methods are offered"
        );

        let response = client_task.await.map_err(|e| io::Error::other(e.to_string()))??;
        assert_eq!(
            response,
            [super::SOCKS_VERSION, super::SOCKS_METHOD_NOT_ACCEPTABLE],
            "server should send [5, 0xFF] rejection to client"
        );

        Ok(())
    }

    #[tokio::test]
    async fn negotiate_socks5_rejects_zero_methods() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send version=5, n_methods=0, no method bytes — adversarial/malformed greeting.
        let client_task = tokio::spawn(async move {
            client.write_all(&[super::SOCKS_VERSION, 0]).await?;
            // Read the rejection response sent by negotiate_socks5.
            let mut response = [0_u8; 2];
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut response).await?;
            io::Result::Ok(response)
        });

        let result = super::negotiate_socks5(&mut server).await;

        assert!(
            result.is_err(),
            "negotiate_socks5 should return an error when zero methods are advertised"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "error kind should be PermissionDenied when no methods are advertised"
        );

        let response = client_task.await.map_err(|e| io::Error::other(e.to_string()))??;
        assert_eq!(
            response,
            [super::SOCKS_VERSION, super::SOCKS_METHOD_NOT_ACCEPTABLE],
            "server should send [5, 0xFF] rejection to client"
        );

        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_rejects_non_connect_command() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send a BIND command (0x02) — not CONNECT.
        let client_task = tokio::spawn(async move {
            // version=5, command=BIND, reserved=0, atyp=IPv4, addr=0.0.0.0, port=0
            client
                .write_all(&[
                    super::SOCKS_VERSION,
                    2, // BIND
                    0,
                    super::SOCKS_ATYP_IPV4,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await?;
            // Read the COMMAND_NOT_SUPPORTED reply sent by read_socks_connect_request.
            let mut response = [0_u8; 10];
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut response).await?;
            io::Result::Ok(response)
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_err(), "BIND command should be rejected");
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::Unsupported,
            "error kind should be Unsupported for non-CONNECT command"
        );

        let response = client_task.await.map_err(|e| io::Error::other(e.to_string()))??;
        assert_eq!(
            response,
            [
                super::SOCKS_VERSION,
                super::SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
                0,
                super::SOCKS_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            "server should send COMMAND_NOT_SUPPORTED reply to client"
        );

        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_rejects_unknown_atyp() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send a CONNECT request with an unknown address type (0xFF).
        let client_task = tokio::spawn(async move {
            client
                .write_all(&[
                    super::SOCKS_VERSION,
                    super::SOCKS_COMMAND_CONNECT,
                    0,
                    0xFF, // unknown atyp
                ])
                .await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_err(), "unknown atyp should be rejected");
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "error kind should be InvalidData for unknown address type"
        );

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_accepts_ipv6_address() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        let ipv6_addr: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let port: u16 = 443;

        let client_task = tokio::spawn(async move {
            let mut request =
                vec![super::SOCKS_VERSION, super::SOCKS_COMMAND_CONNECT, 0, super::SOCKS_ATYP_IPV6];
            request.extend_from_slice(&ipv6_addr);
            request.extend_from_slice(&port.to_be_bytes());
            client.write_all(&request).await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_ok(), "IPv6 CONNECT request should succeed: {:?}", result.err());
        let req = result.unwrap();
        assert_eq!(req.atyp, super::SOCKS_ATYP_IPV6, "atyp should be IPv6");
        assert_eq!(req.address, ipv6_addr, "address should be the full 16-byte IPv6 address");
        assert_eq!(req.port, port, "port should match");

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_accepts_domain_address() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        let domain = b"example.com";
        let port: u16 = 443;

        let client_task = tokio::spawn(async move {
            let mut request = vec![
                super::SOCKS_VERSION,
                super::SOCKS_COMMAND_CONNECT,
                0,
                super::SOCKS_ATYP_DOMAIN,
                u8::try_from(domain.len()).unwrap(),
            ];
            request.extend_from_slice(domain);
            request.extend_from_slice(&port.to_be_bytes());
            client.write_all(&request).await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_ok(), "DOMAIN CONNECT request should succeed: {:?}", result.err());
        let req = result.unwrap();
        assert_eq!(req.atyp, super::SOCKS_ATYP_DOMAIN, "atyp should be DOMAIN");
        assert_eq!(req.address, domain.to_vec(), "address should be the domain bytes");
        assert_eq!(req.port, port, "port should match");

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_accepts_zero_length_domain() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        let port: u16 = 80;

        let client_task = tokio::spawn(async move {
            let request = vec![
                super::SOCKS_VERSION,
                super::SOCKS_COMMAND_CONNECT,
                0,
                super::SOCKS_ATYP_DOMAIN,
                0, // zero-length domain
                0,
                80, // port 80 in big-endian
            ];
            client.write_all(&request).await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_ok(), "zero-length DOMAIN request should not panic: {:?}", result.err());
        let req = result.unwrap();
        assert_eq!(req.atyp, super::SOCKS_ATYP_DOMAIN, "atyp should be DOMAIN");
        assert!(req.address.is_empty(), "address should be empty for zero-length domain");
        assert_eq!(req.port, port, "port should match");

        let _ = client_task.await;
        Ok(())
    }

    /// Build a registered `PendingClient` for `agent_id`/`socket_id` and return the read half of
    /// the peer socket so the caller can verify what the manager writes to the client.
    ///
    /// The caller receives `(peer_read, peer_write)`:
    /// - `peer_read` reads everything that the manager writes via `PendingClient.writer`
    /// - `peer_write` keeps the connection alive so the spawned `spawn_client_reader` task does
    ///   not see EOF prematurely
    async fn register_pending_client(
        manager: &SocketRelayManager,
        agent_id: u32,
        socket_id: u32,
    ) -> io::Result<(tokio::net::tcp::OwnedReadHalf, tokio::net::tcp::OwnedWriteHalf)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let connect_task = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (server_stream, _) = listener.accept().await?;
        let client_stream = connect_task.await.map_err(|e| io::Error::other(e.to_string()))??;
        // client_stream (stream A): write_A sends to read_B, read_A receives from write_B
        // server_stream (stream B): read_B receives what write_A sent, write_B sends to read_A
        let (client_read, client_write) = client_stream.into_split();
        let (server_read, server_write) = server_stream.into_split();

        {
            let mut state = manager.state.write().await;
            let agent_state = state.entry(agent_id).or_default();
            agent_state.clients.insert(
                socket_id,
                super::PendingClient {
                    server_port: 1080,
                    atyp: super::SOCKS_ATYP_IPV4,
                    address: vec![127, 0, 0, 1],
                    port: 80,
                    connected: false,
                    writer: Arc::new(tokio::sync::Mutex::new(client_write)),
                    read_half: Some(client_read),
                },
            );
        }

        // server_read: verifies what the manager writes to PendingClient.writer (write_A → read_B)
        // server_write: held by the caller to prevent EOF on client_read inside the reader task
        Ok((server_read, server_write))
    }

    #[tokio::test]
    async fn finish_connect_success_sends_succeeded_reply_and_retains_client() -> io::Result<()> {
        let (_database, registry, manager) =
            test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
        registry
            .insert(sample_agent(0xDEAD_BEEF))
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let agent_id: u32 = 0xDEAD_BEEF;
        let socket_id: u32 = 0x0000_0001;
        let (mut peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, socket_id).await?;

        manager
            .finish_connect(agent_id, socket_id, true, 0)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // SOCKS5 reply: VER=5, REP=0(succeeded), RSV=0, ATYP=1(IPv4), ADDR=127.0.0.1,
        // PORT=80 big-endian → [0, 80]
        let mut response = [0_u8; 10];
        peer_read.read_exact(&mut response).await?;
        assert_eq!(
            response,
            [
                super::SOCKS_VERSION,
                super::SOCKS_REPLY_SUCCEEDED,
                0,
                super::SOCKS_ATYP_IPV4,
                127,
                0,
                0,
                1,
                0,
                80,
            ],
            "finish_connect(success=true) must send SOCKS_REPLY_SUCCEEDED to the client"
        );

        // On success the client entry must remain in the manager state so that subsequent
        // write_client_data and close_client calls can find it.
        let state = manager.state.read().await;
        assert!(
            state.get(&agent_id).is_some_and(|s| s.clients.contains_key(&socket_id)),
            "client must remain in state after a successful connect"
        );

        Ok(())
    }

    #[tokio::test]
    async fn finish_connect_failure_sends_error_reply_and_removes_client() -> io::Result<()> {
        let (_database, registry, manager) =
            test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
        registry
            .insert(sample_agent(0xDEAD_BEEF))
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let agent_id: u32 = 0xDEAD_BEEF;
        let socket_id: u32 = 0x0000_0002;
        let (mut peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, socket_id).await?;

        // error_code=5 fits in u8, so the reply byte must be exactly 5.
        manager
            .finish_connect(agent_id, socket_id, false, 5)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let mut response = [0_u8; 10];
        peer_read.read_exact(&mut response).await?;
        assert_eq!(
            response,
            [super::SOCKS_VERSION, 5, 0, super::SOCKS_ATYP_IPV4, 127, 0, 0, 1, 0, 80],
            "finish_connect(success=false, error_code=5) must send reply byte 5"
        );

        // On failure the client must be removed so no further relay traffic is forwarded.
        let state = manager.state.read().await;
        assert!(
            !state.get(&agent_id).is_some_and(|s| s.clients.contains_key(&socket_id)),
            "client must be removed from state after a failed connect"
        );

        Ok(())
    }

    #[tokio::test]
    async fn finish_connect_failure_out_of_range_error_code_uses_general_failure() -> io::Result<()>
    {
        let (_database, registry, manager) =
            test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
        registry
            .insert(sample_agent(0xDEAD_BEEF))
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let agent_id: u32 = 0xDEAD_BEEF;
        let socket_id: u32 = 0x0000_0003;
        let (mut peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, socket_id).await?;

        // error_code=300 does not fit in u8; the implementation falls back to
        // SOCKS_REPLY_GENERAL_FAILURE (1).
        manager
            .finish_connect(agent_id, socket_id, false, 300)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let mut response = [0_u8; 10];
        peer_read.read_exact(&mut response).await?;
        assert_eq!(
            response[1],
            super::SOCKS_REPLY_GENERAL_FAILURE,
            "error_code values that do not fit in u8 must fall back to SOCKS_REPLY_GENERAL_FAILURE"
        );

        let state = manager.state.read().await;
        assert!(
            !state.get(&agent_id).is_some_and(|s| s.clients.contains_key(&socket_id)),
            "client must be removed from state after a failed connect"
        );

        Ok(())
    }

    // --- Happy-path coverage for the three previously untested public lifecycle APIs ---

    /// `write_client_data` forwards bytes from the agent to the local SOCKS client socket.
    #[tokio::test]
    async fn write_client_data_delivers_bytes_to_local_socks_client() -> io::Result<()> {
        let (_database, registry, manager) =
            test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
        registry
            .insert(sample_agent(0xDEAD_BEEF))
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let agent_id: u32 = 0xDEAD_BEEF;
        let socket_id: u32 = 0xCAFE_0001;
        let (mut peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, socket_id).await?;

        manager
            .write_client_data(agent_id, socket_id, b"relay payload")
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let mut buf = vec![0_u8; 13];
        peer_read.read_exact(&mut buf).await?;
        assert_eq!(
            &buf, b"relay payload",
            "bytes written by write_client_data must arrive at the peer reader"
        );

        Ok(())
    }

    /// `remove_socks_server` returns a close message and removes both the server entry and any
    /// clients that were on that port from the manager state.
    ///
    /// `add_socks_server("0")` stores the server under key `0` (the *requested* port), so
    /// `remove_socks_server` must also use `"0"`.  The `local_addr` field in the handle carries
    /// the real ephemeral port assigned by the OS, which appears in the close message.
    #[tokio::test]
    async fn remove_socks_server_returns_close_message_and_removes_client_state() -> io::Result<()>
    {
        let (_database, registry, manager) =
            test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
        registry
            .insert(sample_agent(0xDEAD_BEEF))
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let agent_id: u32 = 0xDEAD_BEEF;

        // Start a real listener on port "0" (OS-assigned ephemeral port).
        // The server is stored under key 0 in the servers BTreeMap.
        let start_msg = manager
            .add_socks_server(agent_id, "0")
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        assert!(
            start_msg.starts_with("Started SOCKS5 server on 127.0.0.1:"),
            "unexpected start message: {start_msg}"
        );

        // Inject a fake client with server_port=0 so close_clients_for_port picks it up.
        let socket_id: u32 = 0xCAFE_0002;
        let (_, _peer_write) = register_pending_client(&manager, agent_id, socket_id).await?;
        {
            let mut state = manager.state.write().await;
            let agent_state = state.get_mut(&agent_id).expect("agent state present");
            let client = agent_state.clients.get_mut(&socket_id).expect("client present");
            client.server_port = 0; // match the key used by add_socks_server("0")
        }

        // Remove using the same port string that was used to add.
        let close_msg = manager
            .remove_socks_server(agent_id, "0")
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        assert!(
            close_msg.starts_with("Closed SOCKS5 server on 127.0.0.1:"),
            "close message should contain the bound address, got: {close_msg}"
        );

        let state = manager.state.read().await;
        let agent_state = state.get(&agent_id).expect("agent state still present after remove");
        assert!(
            !agent_state.servers.contains_key(&0_u16),
            "server entry must be removed after remove_socks_server"
        );
        assert!(
            !agent_state.clients.contains_key(&socket_id),
            "client entry must be removed when its server is stopped"
        );

        Ok(())
    }

    /// `close_client` removes the client from state and shuts down its write half so the peer
    /// reader sees EOF.
    #[tokio::test]
    async fn close_client_removes_state_and_shuts_down_writer() -> io::Result<()> {
        let (_database, registry, manager) =
            test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
        registry
            .insert(sample_agent(0xDEAD_BEEF))
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let agent_id: u32 = 0xDEAD_BEEF;
        let socket_id: u32 = 0xCAFE_0003;
        let (mut peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, socket_id).await?;

        manager
            .close_client(agent_id, socket_id)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // The client entry must be gone from state.
        {
            let state = manager.state.read().await;
            let agent_state =
                state.get(&agent_id).expect("agent state still present after close_client");
            assert!(
                !agent_state.clients.contains_key(&socket_id),
                "client entry must be removed by close_client"
            );
        }

        // The writer shutdown must have propagated as EOF to the peer reader.
        let mut buf = vec![0_u8; 1];
        let n = peer_read.read(&mut buf).await?;
        assert_eq!(n, 0, "peer reader must see EOF after close_client shuts down the writer");

        Ok(())
    }

    /// The SOCKS5 server must bind exclusively to the loopback interface (`127.0.0.1`) and must
    /// NOT advertise itself on any external or wildcard address (`0.0.0.0`).
    ///
    /// # Security boundary — no authentication
    ///
    /// The SOCKS5 relay uses `NO_AUTH` (method 0x00) by design: only operators who already have
    /// an authenticated WebSocket session with the teamserver are expected to obtain a SOCKS5 port
    /// (via the `COMMAND_SOCKET` task response), and the port is never exposed outside
    /// `127.0.0.1`.  Localhost-only binding is therefore the **sole** access-control layer for
    /// this tunnel.  This is a known, intentional security boundary: any local OS process that
    /// learns the ephemeral port could connect without further authentication.  Accept this
    /// trade-off consciously — do not relax the loopback-only constraint without adding an
    /// authentication layer.
    #[tokio::test]
    async fn socks5_server_binds_to_localhost_only() -> io::Result<()> {
        let (_database, registry, manager) =
            test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
        registry
            .insert(sample_agent(0xDEAD_BEEF))
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Start the server on an OS-assigned ephemeral port.
        let start_msg = manager
            .add_socks_server(0xDEAD_BEEF, "0")
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // The reported bind address must be on the loopback interface, not a wildcard.
        assert!(
            start_msg.contains("127.0.0.1:"),
            "SOCKS5 server must report a 127.0.0.1 bind address, got: {start_msg}"
        );
        assert!(
            !start_msg.contains("0.0.0.0:"),
            "SOCKS5 server must not bind to the wildcard address, got: {start_msg}"
        );

        // Extract the port from the reported address so we can attempt an external connection.
        let bound_port: u16 = start_msg
            .trim_start_matches("Started SOCKS5 server on 127.0.0.1:")
            .trim()
            .parse()
            .map_err(|e| {
                io::Error::other(format!("could not parse port from '{start_msg}': {e}"))
            })?;

        // If this machine has a non-loopback IP, a connection to it on `bound_port` must be
        // refused — the listener is bound only to 127.0.0.1 so external interfaces are not
        // reachable.  We discover the outbound IP with a connected UDP socket (no packet is
        // actually sent; connecting UDP just populates the kernel routing table entry).
        // `192.0.2.1` is TEST-NET-1 (RFC 5737) — routable but unassigned, safe to use here.
        let non_loopback_ip: Option<std::net::IpAddr> = (|| {
            use std::net::UdpSocket;
            let udp = UdpSocket::bind("0.0.0.0:0").ok()?;
            udp.connect("192.0.2.1:80").ok()?;
            let ip = udp.local_addr().ok()?.ip();
            if ip.is_loopback() { None } else { Some(ip) }
        })();

        if let Some(ext_ip) = non_loopback_ip {
            let external_connect = TcpStream::connect(format!("{ext_ip}:{bound_port}")).await;
            assert!(
                external_connect.is_err(),
                "connection to {ext_ip}:{bound_port} must be refused — SOCKS5 must not be \
                 reachable on non-loopback addresses"
            );
        }

        // A connection to 127.0.0.1 on the same port must succeed, confirming the server is
        // reachable only via loopback.
        TcpStream::connect(format!("127.0.0.1:{bound_port}")).await.map_err(|e| {
            io::Error::other(format!("loopback connection to 127.0.0.1:{bound_port} failed: {e}"))
        })?;

        Ok(())
    }
}
