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

#[cfg(test)]
mod tests {
    use red_cell_common::demon::{DemonSocketCommand, DemonSocketType};
    use red_cell_common::operator::OperatorMessage;
    use serde_json::Value;

    use super::*;
    use crate::{AgentRegistry, Database, EventBus, SocketRelayManager};

    // ── payload encoding helpers ────────────────────────────────────────────

    fn add_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn add_bytes(buf: &mut Vec<u8>, data: &[u8]) {
        add_u32(buf, data.len() as u32);
        buf.extend_from_slice(data);
    }

    fn socket_payload(subcommand: DemonSocketCommand, rest: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        add_u32(&mut payload, subcommand as u32);
        payload.extend_from_slice(rest);
        payload
    }

    const AGENT_ID: u32 = 0xDEAD_BEEF;
    const REQUEST_ID: u32 = 42;
    const COMMAND_SOCKET: u32 = 2540;

    async fn test_deps() -> (EventBus, SocketRelayManager) {
        let db = Database::connect_in_memory().await.expect("in-memory db");
        let registry = AgentRegistry::new(db);
        let events = EventBus::new(8);
        let sockets = SocketRelayManager::new(registry, events.clone());
        (events, sockets)
    }

    async fn call_and_recv(
        payload: &[u8],
    ) -> (Result<Option<Vec<u8>>, CommandDispatchError>, Option<OperatorMessage>) {
        let (events, sockets) = test_deps().await;
        let mut rx = events.subscribe();
        let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, payload).await;
        // Drop both to close the broadcast channel so rx.recv() returns None
        // when no message was sent (SocketRelayManager holds an EventBus clone).
        drop(events);
        drop(sockets);
        let msg = rx.recv().await;
        (result, msg)
    }

    fn assert_agent_response(msg: &OperatorMessage, expected_kind: &str, expected_substr: &str) {
        let OperatorMessage::AgentResponse(m) = msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        assert_eq!(m.info.demon_id, format!("{AGENT_ID:08X}"));
        assert_eq!(m.info.command_id, COMMAND_SOCKET.to_string());
        let kind = m.info.extra.get("Type").and_then(Value::as_str);
        assert_eq!(kind, Some(expected_kind), "expected Type={expected_kind}");
        let message = m.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(
            message.contains(expected_substr),
            "expected Message to contain {expected_substr:?}, got {message:?}"
        );
    }

    fn get_output(msg: &OperatorMessage) -> &str {
        let OperatorMessage::AgentResponse(m) = msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        &m.info.output
    }

    // ── format_rportfwd_list (via ReversePortForwardList subcommand) ────────

    #[tokio::test]
    async fn rportfwd_list_zero_entries_shows_header_only() {
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardList, &[]);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Info", "reverse port forwards:");
        let output = get_output(&msg);
        assert!(output.contains("Socket ID"), "should contain header");
        assert!(output.contains("Forward"), "should contain header");
        // Only header lines, no data rows
        let data_lines: Vec<&str> = output
            .lines()
            .filter(|l| !l.is_empty() && !l.contains("Socket ID") && !l.contains("---------"))
            .collect();
        assert!(data_lines.is_empty(), "expected no data rows, got {data_lines:?}");
    }

    #[tokio::test]
    async fn rportfwd_list_single_entry() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0xABCD_0001); // socket_id
        add_u32(&mut rest, 0x0100_007F); // local_addr = 127.0.0.1
        add_u32(&mut rest, 8080); // local_port
        add_u32(&mut rest, 0x0101_A8C0); // forward_addr = 192.168.1.1
        add_u32(&mut rest, 4443); // forward_port
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardList, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        let output = get_output(&msg);
        assert!(output.contains("abcd0001"), "should contain socket id in hex");
        assert!(output.contains("127.0.0.1:8080"), "should contain local addr:port");
        assert!(output.contains("192.168.1.1:4443"), "should contain forward addr:port");
        assert!(output.contains("->"), "should contain arrow separator");
    }

    #[tokio::test]
    async fn rportfwd_list_multiple_entries() {
        let mut rest = Vec::new();
        // entry 1
        add_u32(&mut rest, 0x0000_0001);
        add_u32(&mut rest, 0x0100_007F); // 127.0.0.1
        add_u32(&mut rest, 9090);
        add_u32(&mut rest, 0x0A01_A8C0); // 192.168.1.10
        add_u32(&mut rest, 80);
        // entry 2
        add_u32(&mut rest, 0x0000_0002);
        add_u32(&mut rest, 0x0100_007F); // 127.0.0.1
        add_u32(&mut rest, 9091);
        add_u32(&mut rest, 0x1401_A8C0); // 192.168.1.20
        add_u32(&mut rest, 443);
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardList, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        let output = get_output(&msg);
        assert!(output.contains("127.0.0.1:9090"));
        assert!(output.contains("127.0.0.1:9091"));
        // Both entries present
        let data_lines: Vec<&str> = output
            .lines()
            .filter(|l| !l.is_empty() && !l.contains("Socket ID") && !l.contains("---------"))
            .collect();
        assert_eq!(data_lines.len(), 2, "expected 2 data rows, got {data_lines:?}");
    }

    #[tokio::test]
    async fn rportfwd_list_truncated_second_entry_returns_error() {
        let mut rest = Vec::new();
        // complete first entry (5 × u32 = 20 bytes)
        add_u32(&mut rest, 0xABCD_0001); // socket_id
        add_u32(&mut rest, 0x0100_007F); // local_addr = 127.0.0.1
        add_u32(&mut rest, 8080); // local_port
        add_u32(&mut rest, 0x0101_A8C0); // forward_addr = 192.168.1.1
        add_u32(&mut rest, 4443); // forward_port
        // truncated second entry: only socket_id, missing the other 4 fields
        add_u32(&mut rest, 0xABCD_0002); // socket_id only
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardList, &rest);
        let (events, sockets) = test_deps().await;
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated list entry, got {result:?}"
        );
    }

    // ── ReversePortForwardAdd ───────────────────────────────────────────────

    #[tokio::test]
    async fn rportfwd_add_success_broadcasts_info() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 1); // success
        add_u32(&mut rest, 0x00FF_0001); // socket_id
        add_u32(&mut rest, 0x0100_007F); // local_addr 127.0.0.1
        add_u32(&mut rest, 4444); // local_port
        add_u32(&mut rest, 0x0101_A8C0); // forward_addr 192.168.1.1
        add_u32(&mut rest, 8443); // forward_port
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardAdd, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Info", "Started reverse port forward");
        let message = get_extra_message(&msg);
        assert!(message.contains("127.0.0.1:4444"));
        assert!(message.contains("192.168.1.1:8443"));
        assert!(message.contains("ff0001"), "should contain socket id in hex");
    }

    #[tokio::test]
    async fn rportfwd_add_failure_broadcasts_error() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0); // failure
        add_u32(&mut rest, 0x00FF_0002); // socket_id
        add_u32(&mut rest, 0x0100_007F); // local_addr
        add_u32(&mut rest, 4444); // local_port
        add_u32(&mut rest, 0x0101_A8C0); // forward_addr
        add_u32(&mut rest, 8443); // forward_port
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardAdd, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Error", "Failed to start reverse port forward");
    }

    // ── ReversePortForwardRemove ────────────────────────────────────────────

    #[tokio::test]
    async fn rportfwd_remove_rportfwd_type_broadcasts_info() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_0042); // socket_id
        add_u32(&mut rest, u32::from(DemonSocketType::ReversePortForward)); // type
        add_u32(&mut rest, 0x0100_007F); // local_addr
        add_u32(&mut rest, 5555); // local_port
        add_u32(&mut rest, 0x0101_A8C0); // forward_addr
        add_u32(&mut rest, 6666); // forward_port
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardRemove, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast for ReversePortForward type");
        assert_agent_response(&msg, "Info", "Successful closed and removed rportfwd");
        let message = get_extra_message(&msg);
        assert!(message.contains("42"), "should contain socket id");
    }

    #[tokio::test]
    async fn rportfwd_remove_non_rportfwd_type_no_broadcast() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_0042); // socket_id
        add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // not ReversePortForward
        add_u32(&mut rest, 0x0100_007F);
        add_u32(&mut rest, 5555);
        add_u32(&mut rest, 0x0101_A8C0);
        add_u32(&mut rest, 6666);
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardRemove, &rest);
        let (events, sockets) = test_deps().await;
        let mut rx = events.subscribe();
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_ok());
        drop(events);
        drop(sockets);
        let msg = rx.recv().await;
        assert!(msg.is_none(), "should not broadcast for non-ReversePortForward type");
    }

    #[tokio::test]
    async fn rportfwd_remove_truncated_returns_error() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_0042); // socket_id only, missing 5 remaining fields
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardRemove, &rest);
        let (events, sockets) = test_deps().await;
        let mut rx = events.subscribe();
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated payload, got {result:?}"
        );
        drop(events);
        drop(sockets);
        let msg = rx.recv().await;
        assert!(msg.is_none(), "should not broadcast on truncated payload");
    }

    // ── ReversePortForwardClear ─────────────────────────────────────────────

    #[tokio::test]
    async fn rportfwd_clear_success_broadcasts_good() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 1); // success
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardClear, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Good", "Successful closed and removed all rportfwds");
    }

    #[tokio::test]
    async fn rportfwd_clear_failure_broadcasts_error() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0); // failure
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardClear, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Error", "Failed to closed and remove all rportfwds");
    }

    // ── Read subcommand ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn read_failure_broadcasts_error_with_code() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_AAAA); // socket_id
        add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // type
        add_u32(&mut rest, 0); // success = false
        add_u32(&mut rest, 10054); // error_code (WSAECONNRESET)
        let payload = socket_payload(DemonSocketCommand::Read, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast error");
        assert_agent_response(&msg, "Error", "Failed to read from socks target");
        let message = get_extra_message(&msg);
        assert!(message.contains("10054"), "should contain error code");
    }

    #[tokio::test]
    async fn read_success_reverse_proxy_no_client_broadcasts_delivery_error() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_BBBB); // socket_id
        add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // type
        add_u32(&mut rest, 1); // success = true
        add_bytes(&mut rest, b"hello relay data"); // data
        let payload = socket_payload(DemonSocketCommand::Read, &rest);
        // No client registered, so write_client_data will fail with ClientNotFound
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast delivery error");
        assert_agent_response(&msg, "Error", "Failed to deliver socks data");
    }

    #[tokio::test]
    async fn read_success_non_reverse_proxy_no_broadcast() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_CCCC); // socket_id
        add_u32(&mut rest, u32::from(DemonSocketType::ReversePortForward)); // not ReverseProxy
        add_u32(&mut rest, 1); // success = true
        add_bytes(&mut rest, b"some data"); // data
        let payload = socket_payload(DemonSocketCommand::Read, &rest);
        let (events, sockets) = test_deps().await;
        let mut rx = events.subscribe();
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_ok());
        drop(events);
        drop(sockets);
        let msg = rx.recv().await;
        assert!(msg.is_none(), "should not broadcast when socket type is not ReverseProxy");
    }

    // ── Write subcommand ────────────────────────────────────────────────────

    #[tokio::test]
    async fn write_failure_broadcasts_error_with_code() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_DDDD); // socket_id
        add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // type
        add_u32(&mut rest, 0); // success = false
        add_u32(&mut rest, 10053); // error_code (WSAECONNABORTED)
        let payload = socket_payload(DemonSocketCommand::Write, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast error");
        assert_agent_response(&msg, "Error", "Failed to write to socks target");
        let message = get_extra_message(&msg);
        assert!(message.contains("10053"), "should contain error code");
    }

    #[tokio::test]
    async fn write_success_no_broadcast() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_EEEE); // socket_id
        add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // type
        add_u32(&mut rest, 1); // success = true
        let payload = socket_payload(DemonSocketCommand::Write, &rest);
        let (events, sockets) = test_deps().await;
        let mut rx = events.subscribe();
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_ok());
        drop(events);
        drop(sockets);
        let msg = rx.recv().await;
        assert!(msg.is_none(), "write success should not broadcast");
    }

    // ── Close subcommand ────────────────────────────────────────────────────

    #[tokio::test]
    async fn close_reverse_proxy_calls_close_client() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_1234); // socket_id
        add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // type
        let payload = socket_payload(DemonSocketCommand::Close, &rest);
        // close_client will return ClientNotFound error (logged as warn, not broadcast)
        let (result, _msg) = call_and_recv(&payload).await;
        // The handler should still return Ok even if close_client errors
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn close_non_reverse_proxy_skips_close_client() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_1234); // socket_id
        add_u32(&mut rest, u32::from(DemonSocketType::ReversePortForward)); // not ReverseProxy
        let payload = socket_payload(DemonSocketCommand::Close, &rest);
        let (events, sockets) = test_deps().await;
        let mut rx = events.subscribe();
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_ok());
        drop(events);
        drop(sockets);
        let msg = rx.recv().await;
        assert!(msg.is_none(), "non-ReverseProxy close should not broadcast");
    }

    // ── Connect subcommand ──────────────────────────────────────────────────

    #[tokio::test]
    async fn connect_returns_ok_even_when_no_client_exists() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 1); // success
        add_u32(&mut rest, 0x0000_5678); // socket_id
        add_u32(&mut rest, 0); // error_code
        let payload = socket_payload(DemonSocketCommand::Connect, &rest);
        // finish_connect will error with ClientNotFound (logged as warn)
        let (result, _msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn connect_failure_calls_finish_connect_with_false() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0); // success = 0 (connection refused)
        add_u32(&mut rest, 0x0000_5678); // socket_id
        add_u32(&mut rest, 10061); // error_code (WSAECONNREFUSED)
        let payload = socket_payload(DemonSocketCommand::Connect, &rest);
        // finish_connect will error with ClientNotFound (logged as warn), but
        // the handler must not panic or return Err on a refused-connection payload.
        let (result, _msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // ── SocksProxyAdd ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn socks_proxy_add_success_broadcasts_info() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 1); // success
        add_u32(&mut rest, 0x00AA_0001); // socket_id
        add_u32(&mut rest, 0x0100_007F); // bind_addr 127.0.0.1
        add_u32(&mut rest, 1080); // bind_port
        let payload = socket_payload(DemonSocketCommand::SocksProxyAdd, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Info", "Started SOCKS proxy");
        let message = get_extra_message(&msg);
        assert!(message.contains("127.0.0.1:1080"));
        assert!(message.contains("aa0001"), "should contain socket id in hex");
    }

    #[tokio::test]
    async fn socks_proxy_add_failure_broadcasts_error() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0); // failure
        add_u32(&mut rest, 0x00AA_0002); // socket_id
        add_u32(&mut rest, 0x0100_007F); // bind_addr
        add_u32(&mut rest, 1080); // bind_port
        let payload = socket_payload(DemonSocketCommand::SocksProxyAdd, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Error", "Failed to start SOCKS proxy");
    }

    #[tokio::test]
    async fn socks_proxy_add_truncated_returns_error() {
        let payload = socket_payload(DemonSocketCommand::SocksProxyAdd, &[]);
        let (events, sockets) = test_deps().await;
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated payload, got {result:?}"
        );
    }

    // ── SocksProxyList ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn socks_proxy_list_zero_entries_shows_header_only() {
        let payload = socket_payload(DemonSocketCommand::SocksProxyList, &[]);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Info", "socks proxies:");
        let output = get_output(&msg);
        assert!(output.contains("Socket ID"), "should contain header");
        assert!(output.contains("Bind Address"), "should contain header");
        let data_lines: Vec<&str> = output
            .lines()
            .filter(|l| !l.is_empty() && !l.contains("Socket ID") && !l.contains("---------"))
            .collect();
        assert!(data_lines.is_empty(), "expected no data rows, got {data_lines:?}");
    }

    #[tokio::test]
    async fn socks_proxy_list_single_entry() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0xBBCC_0001); // socket_id
        add_u32(&mut rest, 0x0100_007F); // bind_addr = 127.0.0.1
        add_u32(&mut rest, 1080); // bind_port
        let payload = socket_payload(DemonSocketCommand::SocksProxyList, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        let output = get_output(&msg);
        assert!(output.contains("bbcc0001"), "should contain socket id in hex");
        assert!(output.contains("127.0.0.1:1080"), "should contain bind addr:port");
    }

    #[tokio::test]
    async fn socks_proxy_list_multiple_entries() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_0001);
        add_u32(&mut rest, 0x0100_007F); // 127.0.0.1
        add_u32(&mut rest, 1080);
        add_u32(&mut rest, 0x0000_0002);
        add_u32(&mut rest, 0x0000_0000); // 0.0.0.0
        add_u32(&mut rest, 9050);
        let payload = socket_payload(DemonSocketCommand::SocksProxyList, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        let output = get_output(&msg);
        assert!(output.contains("127.0.0.1:1080"));
        assert!(output.contains("0.0.0.0:9050"));
        let data_lines: Vec<&str> = output
            .lines()
            .filter(|l| !l.is_empty() && !l.contains("Socket ID") && !l.contains("---------"))
            .collect();
        assert_eq!(data_lines.len(), 2, "expected 2 data rows, got {data_lines:?}");
    }

    // ── SocksProxyRemove ───────────────────────────────────────────────────

    #[tokio::test]
    async fn socks_proxy_remove_broadcasts_info() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_00FF); // socket_id
        let payload = socket_payload(DemonSocketCommand::SocksProxyRemove, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Info", "Removed SOCKS proxy");
        let message = get_extra_message(&msg);
        assert!(message.contains("ff"), "should contain socket id in hex");
    }

    #[tokio::test]
    async fn socks_proxy_remove_truncated_returns_error() {
        let payload = socket_payload(DemonSocketCommand::SocksProxyRemove, &[]);
        let (events, sockets) = test_deps().await;
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated payload, got {result:?}"
        );
    }

    // ── SocksProxyClear ────────────────────────────────────────────────────

    #[tokio::test]
    async fn socks_proxy_clear_success_broadcasts_good() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 1); // success
        let payload = socket_payload(DemonSocketCommand::SocksProxyClear, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Good", "Successful closed and removed all SOCKS proxies");
    }

    #[tokio::test]
    async fn socks_proxy_clear_failure_broadcasts_error() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0); // failure
        let payload = socket_payload(DemonSocketCommand::SocksProxyClear, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Error", "Failed to close and remove all SOCKS proxies");
    }

    // ── Open subcommand ────────────────────────────────────────────────────

    #[tokio::test]
    async fn open_broadcasts_info_with_addresses() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_ABCD); // socket_id
        add_u32(&mut rest, 0x0100_007F); // local_addr 127.0.0.1
        add_u32(&mut rest, 8080); // local_port
        add_u32(&mut rest, 0x0101_A8C0); // forward_addr 192.168.1.1
        add_u32(&mut rest, 4443); // forward_port
        let payload = socket_payload(DemonSocketCommand::Open, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Info", "Opened socket");
        let message = get_extra_message(&msg);
        assert!(message.contains("127.0.0.1:8080"));
        assert!(message.contains("192.168.1.1:4443"));
        assert!(message.contains("abcd"), "should contain socket id in hex");
        assert!(message.contains("->"), "should contain arrow separator");
    }

    #[tokio::test]
    async fn open_truncated_returns_error() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0x0000_ABCD); // socket_id only
        let payload = socket_payload(DemonSocketCommand::Open, &rest);
        let (events, sockets) = test_deps().await;
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated payload, got {result:?}"
        );
    }

    // ── ReversePortForwardAddLocal ─────────────────────────────────────────

    #[tokio::test]
    async fn rportfwd_add_local_success_broadcasts_info() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 1); // success
        add_u32(&mut rest, 0x00CC_0001); // socket_id
        add_u32(&mut rest, 0x0100_007F); // local_addr 127.0.0.1
        add_u32(&mut rest, 3333); // local_port
        add_u32(&mut rest, 0x0101_A8C0); // forward_addr 192.168.1.1
        add_u32(&mut rest, 7777); // forward_port
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardAddLocal, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Info", "Started local reverse port forward");
        let message = get_extra_message(&msg);
        assert!(message.contains("127.0.0.1:3333"));
        assert!(message.contains("192.168.1.1:7777"));
        assert!(message.contains("cc0001"), "should contain socket id in hex");
    }

    #[tokio::test]
    async fn rportfwd_add_local_failure_broadcasts_error() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 0); // failure
        add_u32(&mut rest, 0x00CC_0002); // socket_id
        add_u32(&mut rest, 0x0100_007F); // local_addr
        add_u32(&mut rest, 3333); // local_port
        add_u32(&mut rest, 0x0101_A8C0); // forward_addr
        add_u32(&mut rest, 7777); // forward_port
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardAddLocal, &rest);
        let (result, msg) = call_and_recv(&payload).await;
        assert!(result.is_ok());
        let msg = msg.expect("should broadcast");
        assert_agent_response(&msg, "Error", "Failed to start local reverse port forward");
    }

    #[tokio::test]
    async fn rportfwd_add_local_truncated_returns_error() {
        let mut rest = Vec::new();
        add_u32(&mut rest, 1); // success only
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardAddLocal, &rest);
        let (events, sockets) = test_deps().await;
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated payload, got {result:?}"
        );
    }

    // ── Error paths ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_payload_returns_invalid_callback_payload() {
        let (events, sockets) = test_deps().await;
        let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &[]).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for empty payload, got {result:?}"
        );
    }

    #[tokio::test]
    async fn invalid_subcommand_returns_invalid_callback_payload() {
        let payload = 0xFFFF_FFFFu32.to_le_bytes().to_vec();
        let (events, sockets) = test_deps().await;
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for invalid subcommand, got {result:?}"
        );
    }

    #[tokio::test]
    async fn truncated_rportfwd_add_returns_error() {
        // Only subcommand + success, missing remaining fields
        let mut rest = Vec::new();
        add_u32(&mut rest, 1); // success
        let payload = socket_payload(DemonSocketCommand::ReversePortForwardAdd, &rest);
        let (events, sockets) = test_deps().await;
        let result =
            handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "expected InvalidCallbackPayload for truncated payload, got {result:?}"
        );
    }

    // ── helper ──────────────────────────────────────────────────────────────

    fn get_extra_message(msg: &OperatorMessage) -> String {
        let OperatorMessage::AgentResponse(m) = msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        m.info.extra.get("Message").and_then(Value::as_str).unwrap_or("").to_owned()
    }
}
