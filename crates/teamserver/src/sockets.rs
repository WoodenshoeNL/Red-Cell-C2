//! Teamserver-managed socket relay runtime for Demon `COMMAND_SOCKET` tasks.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use red_cell_common::demon::{DemonCommand, DemonSocketCommand};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
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
}

impl SocketRelayManager {
    /// Create an empty socket relay manager.
    #[must_use]
    pub fn new(registry: AgentRegistry, events: EventBus) -> Self {
        Self {
            registry,
            _events: events,
            next_socket_id: Arc::new(AtomicU32::new(1)),
            state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start a SOCKS5 listener for an agent.
    pub async fn add_socks_server(
        &self,
        agent_id: u32,
        port: &str,
    ) -> Result<String, SocketRelayError> {
        let port = parse_port(port)?;
        let bind_addr = format!("0.0.0.0:{port}");
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
        let handle = {
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
        let handles = {
            let mut state = self.state.write().await;
            let Some(agent_state) = state.get_mut(&agent_id) else {
                return Ok("No active SOCKS5 servers".to_owned());
            };
            let handles = std::mem::take(&mut agent_state.servers)
                .into_values()
                .collect::<Vec<SocksServerHandle>>();
            let ports = handles.iter().map(|handle| handle.port()).collect::<Vec<_>>();
            drop(state);
            for port in ports {
                self.close_clients_for_port(agent_id, port).await?;
            }
            handles
        };

        if handles.is_empty() {
            return Ok("No active SOCKS5 servers".to_owned());
        }

        for handle in &handles {
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
        write_len_prefixed_bytes(&mut payload, &request.address);
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
        write_len_prefixed_bytes(&mut payload, data);
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
struct SocksServerHandle {
    local_addr: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl SocksServerHandle {
    fn shutdown(&self) {
        self.task.abort();
    }

    fn port(&self) -> u16 {
        self.local_addr.rsplit(':').next().and_then(|value| value.parse::<u16>().ok()).unwrap_or(0)
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
    let mut response = vec![SOCKS_VERSION, reply, 0, atyp];
    match atyp {
        SOCKS_ATYP_DOMAIN => {
            response.push(u8::try_from(address.len()).unwrap_or_default());
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

fn write_len_prefixed_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&u32::try_from(value.len()).unwrap_or_default().to_le_bytes());
    buf.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use red_cell_common::AgentEncryptionInfo;

    use super::SocketRelayManager;
    use crate::{AgentRegistry, Database, EventBus, TeamserverError};

    fn sample_agent(agent_id: u32) -> red_cell_common::AgentInfo {
        red_cell_common::AgentInfo {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
                aes_iv: "AAAAAAAAAAAAAAAAAAAAAA==".to_owned(),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "LAB".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.10".to_owned(),
            process_name: "explorer.exe".to_owned(),
            base_address: 0,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
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
    async fn socks_server_lifecycle_commands_track_state() -> Result<(), TeamserverError> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        registry.insert(sample_agent(0xDEAD_BEEF)).await?;
        let manager = SocketRelayManager::new(registry, EventBus::default());

        let start = manager.add_socks_server(0xDEAD_BEEF, "0").await;
        assert!(start.is_ok());
        assert!(manager.list_socks_servers(0xDEAD_BEEF).await.contains("SOCKS5 servers"));
        let cleared = manager.clear_socks_servers(0xDEAD_BEEF).await;
        assert!(cleared.is_ok());
        assert_eq!(manager.list_socks_servers(0xDEAD_BEEF).await, "No active SOCKS5 servers");

        Ok(())
    }
}
