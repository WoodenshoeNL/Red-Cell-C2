//! Private relay runtime methods for [`SocketRelayManager`].
//!
//! This file uses the Rust split-impl pattern: the struct is defined in
//! `mod.rs` while this module provides an additional `impl` block with
//! internal helper methods used by the public API.

use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use red_cell_common::demon::{DemonCommand, DemonSocketCommand};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::{Job, TeamserverError};

use super::socks_proto;
use super::types::{MAX_GLOBAL_SOCKETS, MAX_SOCKETS_PER_AGENT, PendingClient, SocksConnectRequest};
use super::{SocketRelayError, SocketRelayManager};

impl SocketRelayManager {
    pub(super) async fn handle_socks_client(
        &self,
        agent_id: u32,
        server_port: u16,
        mut stream: tokio::net::TcpStream,
    ) -> Result<(), io::Error> {
        socks_proto::negotiate_socks5(&mut stream).await?;
        let request = socks_proto::read_socks_connect_request(&mut stream).await?;
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
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
        self.enqueue_connect_job(agent_id, socket_id, &request)
            .await
            .map_err(super::types::io_error)?;
        Ok(())
    }

    pub(super) async fn register_client(
        &self,
        agent_id: u32,
        socket_id: u32,
        client: PendingClient,
    ) -> Result<(), SocketRelayError> {
        let mut state = self.state.write().await;

        let global_count: usize = state.values().map(|s| s.clients.len()).sum();
        if global_count >= MAX_GLOBAL_SOCKETS {
            warn!(
                agent_id = format_args!("{agent_id:08X}"),
                global_count,
                limit = MAX_GLOBAL_SOCKETS,
                "global SOCKS connection limit reached — rejecting new client"
            );
            return Err(SocketRelayError::GlobalConnectionLimit { limit: MAX_GLOBAL_SOCKETS });
        }

        let agent_state = state.entry(agent_id).or_default();
        if agent_state.clients.len() >= MAX_SOCKETS_PER_AGENT {
            warn!(
                agent_id = format_args!("{agent_id:08X}"),
                agent_count = agent_state.clients.len(),
                limit = MAX_SOCKETS_PER_AGENT,
                "per-agent SOCKS connection limit reached — rejecting new client"
            );
            return Err(SocketRelayError::AgentConnectionLimit {
                agent_id,
                limit: MAX_SOCKETS_PER_AGENT,
            });
        }

        agent_state.clients.insert(socket_id, client);
        Ok(())
    }

    pub(super) async fn spawn_client_reader(
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
                        if let Err(e) = manager.enqueue_close_job(agent_id, socket_id).await {
                            warn!(agent_id = format_args!("{agent_id:08X}"), socket_id = format_args!("{socket_id:08X}"), error = %e, "SOCKS5 read EOF: enqueue_close_job failed");
                        }
                        if let Err(e) = manager.remove_client(agent_id, socket_id).await {
                            warn!(agent_id = format_args!("{agent_id:08X}"), socket_id = format_args!("{socket_id:08X}"), error = %e, "SOCKS5 read EOF: remove_client failed");
                        }
                        break;
                    }
                    Ok(read) => {
                        if manager
                            .enqueue_write_job(agent_id, socket_id, &buf[..read])
                            .await
                            .is_err()
                        {
                            if let Err(e) = manager.remove_client(agent_id, socket_id).await {
                                warn!(agent_id = format_args!("{agent_id:08X}"), socket_id = format_args!("{socket_id:08X}"), error = %e, "SOCKS5 write failure: remove_client failed");
                            }
                            break;
                        }
                    }
                    Err(error) => {
                        debug!(agent_id = format_args!("{agent_id:08X}"), socket_id = format_args!("{socket_id:08X}"), %error, "SOCKS5 client read loop failed");
                        if let Err(e) = manager.enqueue_close_job(agent_id, socket_id).await {
                            warn!(agent_id = format_args!("{agent_id:08X}"), socket_id = format_args!("{socket_id:08X}"), error = %e, "SOCKS5 read error: enqueue_close_job failed");
                        }
                        if let Err(e) = manager.remove_client(agent_id, socket_id).await {
                            warn!(agent_id = format_args!("{agent_id:08X}"), socket_id = format_args!("{socket_id:08X}"), error = %e, "SOCKS5 read error: remove_client failed");
                        }
                        break;
                    }
                }
            }
        });
    }

    pub(super) async fn enqueue_connect_job(
        &self,
        agent_id: u32,
        socket_id: u32,
        request: &SocksConnectRequest,
    ) -> Result<(), TeamserverError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonSocketCommand::Connect).to_le_bytes());
        payload.extend_from_slice(&socket_id.to_le_bytes());
        payload.push(request.atyp);
        socks_proto::write_len_prefixed_bytes(&mut payload, &request.address)?;
        payload.extend_from_slice(&request.port.to_le_bytes());
        self.enqueue_socket_job(agent_id, socket_id, payload, "socket connect").await
    }

    pub(super) async fn enqueue_write_job(
        &self,
        agent_id: u32,
        socket_id: u32,
        data: &[u8],
    ) -> Result<(), TeamserverError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonSocketCommand::Write).to_le_bytes());
        payload.extend_from_slice(&socket_id.to_le_bytes());
        socks_proto::write_len_prefixed_bytes(&mut payload, data)?;
        self.enqueue_socket_job(agent_id, socket_id, payload, "socket write").await
    }

    pub(super) async fn enqueue_close_job(
        &self,
        agent_id: u32,
        socket_id: u32,
    ) -> Result<(), TeamserverError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonSocketCommand::Close).to_le_bytes());
        payload.extend_from_slice(&socket_id.to_le_bytes());
        self.enqueue_socket_job(agent_id, socket_id, payload, "socket close").await
    }

    pub(super) async fn enqueue_socket_job(
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

    pub(super) async fn remove_client(
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

    pub(super) async fn close_clients_for_port(
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
            if let Err(e) = self.enqueue_close_job(agent_id, socket_id).await {
                warn!(agent_id = format_args!("{agent_id:08X}"), socket_id = format_args!("{socket_id:08X}"), error = %e, "SOCKS5 prune: enqueue_close_job failed");
            }
            if let Err(e) = self.close_client(agent_id, socket_id).await {
                warn!(agent_id = format_args!("{agent_id:08X}"), socket_id = format_args!("{socket_id:08X}"), error = %e, "SOCKS5 prune: close_client failed");
            }
        }

        Ok(())
    }
}
