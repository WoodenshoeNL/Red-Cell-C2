use red_cell_common::demon::{DemonCommand, DemonSocketCommand, DemonSocketType};
use tracing::{trace, warn};

use crate::{EventBus, SocketRelayManager};

use super::network::int_to_ipv4;
use super::{CallbackParser, CommandDispatchError, agent_response_event};

pub(super) async fn handle_socket_callback(
    events: &EventBus,
    sockets: &SocketRelayManager,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandSocket));
    let subcommand = parser.read_u32("socket subcommand")?;

    match DemonSocketCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandSocket),
            message: error.to_string(),
        }
    })? {
        DemonSocketCommand::ReversePortForwardAdd => {
            let success = parser.read_u32("rportfwd add success")?;
            let socket_id = parser.read_u32("rportfwd add socket id")?;
            let local_addr = int_to_ipv4(parser.read_u32("rportfwd add local addr")?);
            let local_port = parser.read_u32("rportfwd add local port")?;
            let forward_addr = int_to_ipv4(parser.read_u32("rportfwd add forward addr")?);
            let forward_port = parser.read_u32("rportfwd add forward port")?;
            let (kind, message) = if success != 0 {
                (
                    "Info",
                    format!(
                        "Started reverse port forward on {local_addr}:{local_port} to {forward_addr}:{forward_port} [Id: {socket_id:x}]"
                    ),
                )
            } else {
                (
                    "Error",
                    format!(
                        "Failed to start reverse port forward on {local_addr}:{local_port} to {forward_addr}:{forward_port}"
                    ),
                )
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
        DemonSocketCommand::ReversePortForwardList => {
            let output = format_rportfwd_list(&mut parser)?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                "Info",
                "reverse port forwards:",
                Some(output),
            )?);
        }
        DemonSocketCommand::ReversePortForwardRemove => {
            let socket_id = parser.read_u32("rportfwd remove socket id")?;
            let socket_type = parser.read_u32("rportfwd remove type")?;
            let local_addr = int_to_ipv4(parser.read_u32("rportfwd remove local addr")?);
            let local_port = parser.read_u32("rportfwd remove local port")?;
            let forward_addr = int_to_ipv4(parser.read_u32("rportfwd remove forward addr")?);
            let forward_port = parser.read_u32("rportfwd remove forward port")?;
            if socket_type == u32::from(DemonSocketType::ReversePortForward) {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandSocket),
                    request_id,
                    "Info",
                    &format!(
                        "Successful closed and removed rportfwd [SocketID: {socket_id:x}] [Forward: {local_addr}:{local_port} -> {forward_addr}:{forward_port}]"
                    ),
                    None,
                )?);
            }
        }
        DemonSocketCommand::ReversePortForwardClear => {
            let success = parser.read_u32("rportfwd clear success")?;
            let (kind, message) = if success != 0 {
                ("Good", "Successful closed and removed all rportfwds")
            } else {
                ("Error", "Failed to closed and remove all rportfwds")
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                kind,
                message,
                None,
            )?);
        }
        DemonSocketCommand::Read => {
            let socket_id = parser.read_u32("socket read socket id")?;
            let socket_type = parser.read_u32("socket read type")?;
            let success = parser.read_u32("socket read success")?;
            if success == 0 {
                let error_code = parser.read_u32("socket read error code")?;
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandSocket),
                    request_id,
                    "Error",
                    &format!("Failed to read from socks target {socket_id}: {error_code}"),
                    None,
                )?);
                return Ok(None);
            }

            let data = parser.read_bytes("socket read data")?;
            if socket_type == u32::from(DemonSocketType::ReverseProxy) {
                if let Err(error) = sockets.write_client_data(agent_id, socket_id, &data).await {
                    warn!(
                        agent_id = format_args!("{agent_id:08X}"),
                        socket_id = format_args!("{socket_id:08X}"),
                        %error,
                        "failed to deliver reverse proxy data to SOCKS client"
                    );
                    events.broadcast(agent_response_event(
                        agent_id,
                        u32::from(DemonCommand::CommandSocket),
                        request_id,
                        "Error",
                        &format!("Failed to deliver socks data for {socket_id}: {error}"),
                        None,
                    )?);
                }
            }
        }
        DemonSocketCommand::Write => {
            let socket_id = parser.read_u32("socket write socket id")?;
            let _socket_type = parser.read_u32("socket write type")?;
            let success = parser.read_u32("socket write success")?;
            if success == 0 {
                let error_code = parser.read_u32("socket write error code")?;
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandSocket),
                    request_id,
                    "Error",
                    &format!("Failed to write to socks target {socket_id}: {error_code}"),
                    None,
                )?);
            }
        }
        DemonSocketCommand::Close => {
            let socket_id = parser.read_u32("socket close socket id")?;
            let socket_type = parser.read_u32("socket close type")?;
            if socket_type == u32::from(DemonSocketType::ReverseProxy) {
                if let Err(error) = sockets.close_client(agent_id, socket_id).await {
                    warn!(
                        agent_id = format_args!("{agent_id:08X}"),
                        socket_id = format_args!("{socket_id:08X}"),
                        %error,
                        "failed to close SOCKS client on socket close callback"
                    );
                }
            }
        }
        DemonSocketCommand::Connect => {
            let success = parser.read_u32("socket connect success")?;
            let socket_id = parser.read_u32("socket connect socket id")?;
            let error_code = parser.read_u32("socket connect error code")?;
            if let Err(error) =
                sockets.finish_connect(agent_id, socket_id, success != 0, error_code).await
            {
                warn!(
                    agent_id = format_args!("{agent_id:08X}"),
                    socket_id = format_args!("{socket_id:08X}"),
                    %error,
                    "failed to finish SOCKS connect on connect callback"
                );
            }
        }
        DemonSocketCommand::SocksProxyAdd => {
            let success = parser.read_u32("socks proxy add success")?;
            let socket_id = parser.read_u32("socks proxy add socket id")?;
            let bind_addr = int_to_ipv4(parser.read_u32("socks proxy add bind addr")?);
            let bind_port = parser.read_u32("socks proxy add bind port")?;
            let (kind, message) = if success != 0 {
                (
                    "Info",
                    format!("Started SOCKS proxy on {bind_addr}:{bind_port} [Id: {socket_id:x}]"),
                )
            } else {
                ("Error", format!("Failed to start SOCKS proxy on {bind_addr}:{bind_port}"))
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
        DemonSocketCommand::SocksProxyList => {
            let output = format_socks_proxy_list(&mut parser)?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                "Info",
                "socks proxies:",
                Some(output),
            )?);
        }
        DemonSocketCommand::SocksProxyRemove => {
            let socket_id = parser.read_u32("socks proxy remove socket id")?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                "Info",
                &format!("Removed SOCKS proxy [SocketID: {socket_id:x}]"),
                None,
            )?);
        }
        DemonSocketCommand::SocksProxyClear => {
            let success = parser.read_u32("socks proxy clear success")?;
            let (kind, message) = if success != 0 {
                ("Good", "Successful closed and removed all SOCKS proxies")
            } else {
                ("Error", "Failed to close and remove all SOCKS proxies")
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                kind,
                message,
                None,
            )?);
        }
        DemonSocketCommand::Open => {
            let socket_id = parser.read_u32("socket open socket id")?;
            let local_addr = int_to_ipv4(parser.read_u32("socket open local addr")?);
            let local_port = parser.read_u32("socket open local port")?;
            let forward_addr = int_to_ipv4(parser.read_u32("socket open forward addr")?);
            let forward_port = parser.read_u32("socket open forward port")?;
            trace!(
                agent_id = format_args!("{agent_id:08X}"),
                socket_id = format_args!("{socket_id:08X}"),
                %local_addr, local_port,
                %forward_addr, forward_port,
                "socket open callback"
            );
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                "Info",
                &format!(
                    "Opened socket {local_addr}:{local_port} -> {forward_addr}:{forward_port} [Id: {socket_id:x}]"
                ),
                None,
            )?);
        }
        DemonSocketCommand::ReversePortForwardAddLocal => {
            let success = parser.read_u32("rportfwd add local success")?;
            let socket_id = parser.read_u32("rportfwd add local socket id")?;
            let local_addr = int_to_ipv4(parser.read_u32("rportfwd add local addr")?);
            let local_port = parser.read_u32("rportfwd add local port")?;
            let forward_addr = int_to_ipv4(parser.read_u32("rportfwd add local forward addr")?);
            let forward_port = parser.read_u32("rportfwd add local forward port")?;
            let (kind, message) = if success != 0 {
                (
                    "Info",
                    format!(
                        "Started local reverse port forward on {local_addr}:{local_port} to {forward_addr}:{forward_port} [Id: {socket_id:x}]"
                    ),
                )
            } else {
                (
                    "Error",
                    format!(
                        "Failed to start local reverse port forward on {local_addr}:{local_port} to {forward_addr}:{forward_port}"
                    ),
                )
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandSocket),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
    }

    Ok(None)
}

fn format_rportfwd_list(parser: &mut CallbackParser<'_>) -> Result<String, CommandDispatchError> {
    let mut output = String::from("\n Socket ID     Forward\n ---------     -------\n");

    while !parser.is_empty() {
        let socket_id = parser.read_u32("rportfwd list socket id")?;
        let local_addr = int_to_ipv4(parser.read_u32("rportfwd list local addr")?);
        let local_port = parser.read_u32("rportfwd list local port")?;
        let forward_addr = int_to_ipv4(parser.read_u32("rportfwd list forward addr")?);
        let forward_port = parser.read_u32("rportfwd list forward port")?;
        output.push_str(&format!(
            " {socket_id:<13x}{local_addr}:{local_port} -> {forward_addr}:{forward_port}\n"
        ));
    }

    Ok(output.trim_end().to_owned())
}

fn format_socks_proxy_list(
    parser: &mut CallbackParser<'_>,
) -> Result<String, CommandDispatchError> {
    let mut output = String::from("\n Socket ID     Bind Address\n ---------     ------------\n");

    while !parser.is_empty() {
        let socket_id = parser.read_u32("socks proxy list socket id")?;
        let bind_addr = int_to_ipv4(parser.read_u32("socks proxy list bind addr")?);
        let bind_port = parser.read_u32("socks proxy list bind port")?;
        output.push_str(&format!(" {socket_id:<13x}{bind_addr}:{bind_port}\n"));
    }

    Ok(output.trim_end().to_owned())
}
