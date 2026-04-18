use red_cell_common::demon::{DemonCommand, DemonSocketCommand};

use super::socket_io::{
    SOCKS_METHOD_NOT_ACCEPTABLE, SocksRequestError, encode_bool, encode_bytes, encode_socket_clear,
    encode_socks_proxy_clear, encode_u32, parse_u32_le, try_parse_socks_greeting,
    try_parse_socks_request,
};
use super::socket_state::SocketState;

// ── SOCKS5 greeting parsing ─────────────────────────────────────────────

#[test]
fn parse_socks_greeting_valid_no_auth() {
    let greeting = [5, 1, 0]; // version 5, 1 method, method 0 (no auth)
    assert_eq!(try_parse_socks_greeting(&greeting), Some(Ok(3)));
}

#[test]
fn parse_socks_greeting_multiple_methods_includes_no_auth() {
    let greeting = [5, 3, 1, 2, 0]; // version 5, 3 methods, includes 0
    assert_eq!(try_parse_socks_greeting(&greeting), Some(Ok(5)));
}

#[test]
fn parse_socks_greeting_no_acceptable_method() {
    let greeting = [5, 2, 1, 2]; // version 5, 2 methods, neither is 0
    assert_eq!(try_parse_socks_greeting(&greeting), Some(Err(SOCKS_METHOD_NOT_ACCEPTABLE)));
}

#[test]
fn parse_socks_greeting_wrong_version() {
    let greeting = [4, 1, 0]; // SOCKS4, not SOCKS5
    assert_eq!(try_parse_socks_greeting(&greeting), Some(Err(SOCKS_METHOD_NOT_ACCEPTABLE)));
}

#[test]
fn parse_socks_greeting_incomplete() {
    assert!(try_parse_socks_greeting(&[5]).is_none());
    assert!(try_parse_socks_greeting(&[5, 2, 0]).is_none()); // needs 4 bytes total
}

// ── SOCKS5 request parsing ──────────────────────────────────────────────

#[test]
fn parse_socks_request_ipv4_connect() {
    // CONNECT to 192.168.1.1:8080
    let request = [5, 1, 0, 1, 192, 168, 1, 1, 0x1F, 0x90];
    let result = try_parse_socks_request(&request);
    let Some(Ok((consumed, req))) = result else {
        panic!("expected Ok, got {result:?}");
    };
    assert_eq!(consumed, 10);
    assert_eq!(req.atyp, 1);
    assert_eq!(req.address, vec![192, 168, 1, 1]);
    assert_eq!(req.port, 8080);
}

#[test]
fn parse_socks_request_domain_connect() {
    // CONNECT to example.com:443
    let domain = b"example.com";
    let mut request = vec![5, 1, 0, 3, domain.len() as u8];
    request.extend_from_slice(domain);
    request.extend_from_slice(&443u16.to_be_bytes());
    let result = try_parse_socks_request(&request);
    let Some(Ok((consumed, req))) = result else {
        panic!("expected Ok, got {result:?}");
    };
    assert_eq!(consumed, request.len());
    assert_eq!(req.atyp, 3);
    assert_eq!(req.address, domain.to_vec());
    assert_eq!(req.port, 443);
}

#[test]
fn parse_socks_request_unsupported_command() {
    let request = [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]; // BIND (2), not CONNECT
    let result = try_parse_socks_request(&request);
    assert!(matches!(result, Some(Err(SocksRequestError::CommandNotSupported))));
}

#[test]
fn parse_socks_request_unsupported_atyp() {
    let request = [5, 1, 0, 5, 0, 0, 0, 0, 0, 0]; // atyp 5 is invalid
    let result = try_parse_socks_request(&request);
    assert!(matches!(result, Some(Err(SocksRequestError::AddressTypeNotSupported))));
}

#[test]
fn parse_socks_request_incomplete() {
    assert!(try_parse_socks_request(&[5, 1, 0]).is_none());
}

// ── Encoding helpers ────────────────────────────────────────────────────

#[test]
fn encode_u32_is_big_endian() {
    assert_eq!(encode_u32(0x01020304), vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn encode_bool_true() {
    assert_eq!(encode_bool(true), vec![0, 0, 0, 1]);
}

#[test]
fn encode_bool_false() {
    assert_eq!(encode_bool(false), vec![0, 0, 0, 0]);
}

#[test]
fn encode_bytes_length_prefixed() {
    let data = vec![0xAA, 0xBB, 0xCC];
    let encoded = encode_bytes(&data).expect("encode");
    assert_eq!(encoded, vec![0, 0, 0, 3, 0xAA, 0xBB, 0xCC]);
}

// ── parse_u32_le ────────────────────────────────────────────────────────

#[test]
fn parse_u32_le_reads_correct_value() {
    let buf = [0x01, 0x00, 0x00, 0x00];
    let mut offset = 0;
    assert_eq!(parse_u32_le(&buf, &mut offset).expect("parse"), 1);
    assert_eq!(offset, 4);
}

#[test]
fn parse_u32_le_short_buffer() {
    let buf = [0x01, 0x00, 0x00];
    let mut offset = 0;
    assert!(parse_u32_le(&buf, &mut offset).is_err());
}

// ── Socket state management ─────────────────────────────────────────────

#[test]
fn allocate_socket_id_is_unique() {
    let state = SocketState::new();
    let id1 = state.allocate_socket_id();
    assert_ne!(id1, 0);
    assert_ne!(id1 & 1, 0, "ID must have bit 0 set");
}

#[test]
fn has_active_connections_empty() {
    let state = SocketState::new();
    assert!(!state.has_active_connections());
}

// ── Socket command: ReversePortForwardList ───────────────────────────────

#[tokio::test]
async fn handle_rportfwd_list_empty() {
    let mut state = SocketState::new();
    let mut payload = Vec::new();
    payload
        .extend_from_slice(&(u32::from(DemonSocketCommand::ReversePortForwardList)).to_le_bytes());
    state.handle_command(1, &payload).await.expect("handle");
    let responses = state.drain_responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].command_id, u32::from(DemonCommand::CommandSocket));
    // Payload should be just the subcommand ID (0x02) in BE
    assert_eq!(
        responses[0].payload,
        encode_u32(u32::from(DemonSocketCommand::ReversePortForwardList))
    );
}

// ── Socket command: SocksProxyList ───────────────────────────────────────

#[tokio::test]
async fn handle_socks_proxy_list_empty() {
    let mut state = SocketState::new();
    let mut payload = Vec::new();
    payload.extend_from_slice(&(u32::from(DemonSocketCommand::SocksProxyList)).to_le_bytes());
    state.handle_command(1, &payload).await.expect("handle");
    let responses = state.drain_responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].payload, encode_u32(u32::from(DemonSocketCommand::SocksProxyList)));
}

// ── Socket command: SocksProxyClear ─────────────────────────────────────

#[tokio::test]
async fn handle_socks_proxy_clear() {
    let mut state = SocketState::new();
    let mut payload = Vec::new();
    payload.extend_from_slice(&(u32::from(DemonSocketCommand::SocksProxyClear)).to_le_bytes());
    state.handle_command(1, &payload).await.expect("handle");
    let responses = state.drain_responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].payload, encode_socks_proxy_clear(true));
}

// ── Socket command: ReversePortForwardClear ─────────────────────────────

#[tokio::test]
async fn handle_rportfwd_clear_empty() {
    let mut state = SocketState::new();
    let mut payload = Vec::new();
    payload
        .extend_from_slice(&(u32::from(DemonSocketCommand::ReversePortForwardClear)).to_le_bytes());
    state.handle_command(1, &payload).await.expect("handle");
    let responses = state.drain_responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].payload, encode_socket_clear(true));
}

// ── Socket command: SocksProxyAdd ───────────────────────────────────────

#[tokio::test]
async fn handle_socks_proxy_add_binds_listener() {
    let mut state = SocketState::new();
    let mut payload = Vec::new();
    payload.extend_from_slice(&(u32::from(DemonSocketCommand::SocksProxyAdd)).to_le_bytes());
    // bind to 127.0.0.1 (0x7F000001 in LE)
    payload.extend_from_slice(&0x7F000001_u32.to_le_bytes());
    // port 0 = OS picks
    payload.extend_from_slice(&0_u32.to_le_bytes());

    state.handle_command(42, &payload).await.expect("handle");
    let responses = state.drain_responses();
    assert_eq!(responses.len(), 1);

    // Parse the response: subcommand(4) + success(4) + socket_id(4) + addr(4) + port(4)
    let resp = &responses[0].payload;
    assert!(resp.len() >= 20);
    let success = u32::from_be_bytes(resp[4..8].try_into().expect("success"));
    assert_eq!(success, 1, "socks proxy add should succeed");
    assert!(state.has_active_connections());
}

// ── Socket command: ReversePortForwardAdd ────────────────────────────────

#[tokio::test]
async fn handle_rportfwd_add_binds_listener() {
    let mut state = SocketState::new();
    let mut payload = Vec::new();
    payload
        .extend_from_slice(&(u32::from(DemonSocketCommand::ReversePortForwardAdd)).to_le_bytes());
    payload.extend_from_slice(&0x7F000001_u32.to_le_bytes()); // bind addr
    payload.extend_from_slice(&0_u32.to_le_bytes()); // port 0
    payload.extend_from_slice(&0x7F000001_u32.to_le_bytes()); // forward addr
    payload.extend_from_slice(&8080_u32.to_le_bytes()); // forward port

    state.handle_command(42, &payload).await.expect("handle");
    let responses = state.drain_responses();
    assert_eq!(responses.len(), 1);

    let resp = &responses[0].payload;
    let success = u32::from_be_bytes(resp[4..8].try_into().expect("success"));
    assert_eq!(success, 1, "rportfwd add should succeed");
    assert!(state.has_active_connections());
}

// ── Socket command: Close nonexistent ───────────────────────────────────

#[tokio::test]
async fn handle_socket_close_nonexistent_is_no_op() {
    let mut state = SocketState::new();
    let mut payload = Vec::new();
    payload.extend_from_slice(&(u32::from(DemonSocketCommand::Close)).to_le_bytes());
    payload.extend_from_slice(&0xDEAD_u32.to_le_bytes());
    state.handle_command(1, &payload).await.expect("handle");
    let responses = state.drain_responses();
    assert!(responses.is_empty());
}

// ── Socket command: Write to nonexistent ────────────────────────────────

#[tokio::test]
async fn handle_socket_write_nonexistent_is_no_op() {
    let mut state = SocketState::new();
    let mut payload = Vec::new();
    payload.extend_from_slice(&(u32::from(DemonSocketCommand::Write)).to_le_bytes());
    payload.extend_from_slice(&0xDEAD_u32.to_le_bytes()); // socket id
    let data = b"hello";
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes()); // length prefix
    payload.extend_from_slice(data);
    state.handle_command(1, &payload).await.expect("handle");
    let responses = state.drain_responses();
    assert!(responses.is_empty());
}

// ── Socket command: Connect failure ─────────────────────────────────────

#[tokio::test]
async fn handle_connect_to_unreachable_returns_error() {
    let mut state = SocketState::new();
    let mut payload = Vec::new();
    payload.extend_from_slice(&(u32::from(DemonSocketCommand::Connect)).to_le_bytes());
    payload.extend_from_slice(&0x1234_u32.to_le_bytes()); // socket id
    payload.push(1); // atyp = IPv4
    // host: 127.0.0.1 as length-prefixed bytes
    payload.extend_from_slice(&4_u32.to_le_bytes());
    payload.extend_from_slice(&[127, 0, 0, 1]);
    // port 1 (likely unreachable) as i16 LE
    payload.extend_from_slice(&1_u16.to_le_bytes());

    state.handle_command(42, &payload).await.expect("handle");
    let responses = state.drain_responses();
    assert_eq!(responses.len(), 1);

    // Parse: subcommand(4) + success(4) + socket_id(4) + error_code(4)
    let resp = &responses[0].payload;
    let subcmd = u32::from_be_bytes(resp[0..4].try_into().expect("subcmd"));
    assert_eq!(subcmd, u32::from(DemonSocketCommand::Connect));
    let success = u32::from_be_bytes(resp[4..8].try_into().expect("success"));
    assert_eq!(success, 0, "connect to port 1 should fail");
}

// ── Socket command: Add and remove socks proxy ──────────────────────────

#[tokio::test]
async fn socks_proxy_add_then_remove() {
    let mut state = SocketState::new();

    // Add
    let mut add_payload = Vec::new();
    add_payload.extend_from_slice(&(u32::from(DemonSocketCommand::SocksProxyAdd)).to_le_bytes());
    add_payload.extend_from_slice(&0x7F000001_u32.to_le_bytes());
    add_payload.extend_from_slice(&0_u32.to_le_bytes());
    state.handle_command(1, &add_payload).await.expect("add");
    let responses = state.drain_responses();
    assert_eq!(responses.len(), 1);

    // Extract socket_id from response
    let resp = &responses[0].payload;
    let socket_id = u32::from_be_bytes(resp[8..12].try_into().expect("socket_id"));

    // Remove
    let mut rm_payload = Vec::new();
    rm_payload.extend_from_slice(&(u32::from(DemonSocketCommand::SocksProxyRemove)).to_le_bytes());
    rm_payload.extend_from_slice(&socket_id.to_le_bytes());
    state.handle_command(2, &rm_payload).await.expect("remove");
    let responses = state.drain_responses();
    assert_eq!(responses.len(), 1);

    assert!(!state.has_active_connections());
}

// ── Socket command: Add and remove rportfwd ─────────────────────────────

#[tokio::test]
async fn rportfwd_add_then_remove() {
    let mut state = SocketState::new();

    // Add
    let mut add_payload = Vec::new();
    add_payload
        .extend_from_slice(&(u32::from(DemonSocketCommand::ReversePortForwardAdd)).to_le_bytes());
    add_payload.extend_from_slice(&0x7F000001_u32.to_le_bytes());
    add_payload.extend_from_slice(&0_u32.to_le_bytes());
    add_payload.extend_from_slice(&0x7F000001_u32.to_le_bytes());
    add_payload.extend_from_slice(&8080_u32.to_le_bytes());
    state.handle_command(1, &add_payload).await.expect("add");
    let responses = state.drain_responses();
    assert_eq!(responses.len(), 1);

    // Extract listener_id from response (at offset 8)
    let resp = &responses[0].payload;
    let listener_id = u32::from_be_bytes(resp[8..12].try_into().expect("listener_id"));

    // Remove
    let mut rm_payload = Vec::new();
    rm_payload.extend_from_slice(
        &(u32::from(DemonSocketCommand::ReversePortForwardRemove)).to_le_bytes(),
    );
    rm_payload.extend_from_slice(&listener_id.to_le_bytes());
    state.handle_command(2, &rm_payload).await.expect("remove");
    let responses = state.drain_responses();
    // remove_reverse_port_forward queues a callback
    assert!(!responses.is_empty());

    assert!(!state.has_active_connections());
}

// ── drain_responses produces correct command_id ──────────────────────────

#[tokio::test]
async fn drain_responses_sets_command_socket_id() {
    let mut state = SocketState::new();
    state.queue_response(42, vec![1, 2, 3]);
    let responses = state.drain_responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].command_id, u32::from(DemonCommand::CommandSocket));
    assert_eq!(responses[0].request_id, 42);
    assert_eq!(responses[0].payload, vec![1, 2, 3]);
}

// ── poll on empty state ─────────────────────────────────────────────────

#[tokio::test]
async fn poll_empty_state_is_no_op() {
    let mut state = SocketState::new();
    state.poll().await.expect("poll");
    assert!(state.drain_responses().is_empty());
}
