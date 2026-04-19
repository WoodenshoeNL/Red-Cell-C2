//! Teamserver-managed socket relay runtime for Demon `COMMAND_SOCKET` tasks.

mod cleanup;
mod relay;
mod socks_proto;
mod types;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, oneshot};
use tracing::warn;

use crate::{AgentRegistry, EventBus};

use cleanup::{close_agent_state, spawn_stale_agent_sweeper};
pub use types::{AgentSocketSnapshot, SocketRelayError};
use types::{
    AgentSocketState, MAX_RELAY_LISTENERS, PortFwdEntry, RelayStateSweeper,
    SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_SUCCEEDED, SocksServerHandle, parse_port,
};

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
            let total_listeners: usize = state.values().map(|s| s.servers.len()).sum();
            if total_listeners >= MAX_RELAY_LISTENERS {
                warn!(
                    agent_id = format_args!("{agent_id:08X}"),
                    total_listeners,
                    limit = MAX_RELAY_LISTENERS,
                    "SOCKS5 relay listener limit reached — rejecting new server"
                );
                return Err(SocketRelayError::ListenerLimit { limit: MAX_RELAY_LISTENERS });
            }
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
            socks_proto::send_socks_connect_reply(
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
        socks_proto::send_socks_connect_reply(&pending.0, reply, pending.1, &pending.2, pending.3)
            .await;
        if let Err(error) = self.remove_client(agent_id, socket_id).await {
            warn!(agent_id = format_args!("{agent_id:08X}"), socket_id = format_args!("{socket_id:08X}"), %error, "SOCKS5 connect failure: remove_client failed");
        }
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
        if let Err(error) = writer.shutdown().await {
            warn!(agent_id = format_args!("{agent_id:08X}"), socket_id = format_args!("{socket_id:08X}"), %error, "SOCKS5 close_client: writer shutdown failed");
        }
        Ok(())
    }

    /// Record an active reverse port forward for an agent.
    pub async fn add_port_fwd(&self, agent_id: u32, socket_id: u32, display: String) {
        let mut state = self.state.write().await;
        let agent_state = state.entry(agent_id).or_default();
        agent_state.port_fwds.insert(socket_id, PortFwdEntry { display });
    }

    /// Remove a single reverse port forward record for an agent.
    pub async fn remove_port_fwd(&self, agent_id: u32, socket_id: u32) {
        let mut state = self.state.write().await;
        if let Some(agent_state) = state.get_mut(&agent_id) {
            agent_state.port_fwds.remove(&socket_id);
        }
    }

    /// Remove all reverse port forward records for an agent.
    pub async fn clear_port_fwds(&self, agent_id: u32) {
        let mut state = self.state.write().await;
        if let Some(agent_state) = state.get_mut(&agent_id) {
            agent_state.port_fwds.clear();
        }
    }

    /// Return a snapshot of all active socket relay state for an agent.
    pub async fn agent_socket_snapshot(&self, agent_id: u32) -> AgentSocketSnapshot {
        let state = self.state.read().await;
        let Some(agent_state) = state.get(&agent_id) else {
            return AgentSocketSnapshot::default();
        };

        let port_fwds = agent_state.port_fwds.values().map(|e| e.display.clone()).collect();

        let socks_svr = agent_state.servers.values().map(|s| s.local_addr.clone()).collect();

        let socks_cli = agent_state.clients.values().map(format_socks_client).collect();

        AgentSocketSnapshot { port_fwds, socks_svr, socks_cli }
    }
}

fn format_socks_client(client: &types::PendingClient) -> String {
    let dest = format_socks_address(client.atyp, &client.address, client.port);
    let state = if client.connected { "connected" } else { "connecting" };
    format!("{dest} [{state}]")
}

fn format_socks_address(atyp: u8, address: &[u8], port: u16) -> String {
    use types::{SOCKS_ATYP_DOMAIN, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6};
    match atyp {
        SOCKS_ATYP_IPV4 if address.len() == 4 => {
            format!("{}.{}.{}.{}:{port}", address[0], address[1], address[2], address[3])
        }
        SOCKS_ATYP_DOMAIN => {
            let host = String::from_utf8_lossy(address);
            format!("{host}:{port}")
        }
        SOCKS_ATYP_IPV6 if address.len() == 16 => {
            let octets: [u8; 16] = address.try_into().unwrap_or([0u8; 16]);
            let addr = std::net::Ipv6Addr::from(octets);
            format!("[{addr}]:{port}")
        }
        _ => format!("<unknown>:{port}"),
    }
}

#[cfg(test)]
mod tests;
