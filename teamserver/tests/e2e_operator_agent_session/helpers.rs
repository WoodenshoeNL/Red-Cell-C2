use std::collections::BTreeMap;
use std::time::Duration;

#[cfg(unix)]
use interprocess::local_socket::ToNsName as _;
#[cfg(unix)]
use interprocess::local_socket::tokio::Stream as LocalSocketStream;
#[cfg(unix)]
use interprocess::local_socket::traits::tokio::Stream as _;
#[cfg(unix)]
use interprocess::os::unix::local_socket::AbstractNsUdSocket;
use red_cell_common::config::Profile;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentResponseInfo, AgentTaskInfo, EventCode, ListenerInfo, Message, MessageHead,
    OperatorMessage,
};
use red_cell_common::{DnsListenerConfig, HttpListenerConfig, ListenerConfig, SmbListenerConfig};
use serde_json::Value;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::Message as ClientMessage;

pub(crate) fn listener_new_message(user: &str, port: u16) -> String {
    serde_json::to_string(&OperatorMessage::ListenerNew(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: user.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: ListenerInfo {
            name: Some("edge-http".to_owned()),
            protocol: Some("Http".to_owned()),
            status: Some("Online".to_owned()),
            hosts: Some("127.0.0.1".to_owned()),
            host_bind: Some("127.0.0.1".to_owned()),
            host_rotation: Some("round-robin".to_owned()),
            port_bind: Some(port.to_string()),
            port_conn: Some(port.to_string()),
            uris: Some("/".to_owned()),
            secure: Some("false".to_owned()),
            ..ListenerInfo::default()
        },
    }))
    .expect("listener message should serialize")
}

pub(crate) fn listener_new_smb_message(user: &str, name: &str, pipe_name: &str) -> String {
    serde_json::to_string(&OperatorMessage::ListenerNew(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: user.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: ListenerInfo {
            name: Some(name.to_owned()),
            protocol: Some("SMB".to_owned()),
            status: Some("Online".to_owned()),
            extra: BTreeMap::from([("PipeName".to_owned(), Value::String(pipe_name.to_owned()))]),
            ..ListenerInfo::default()
        },
    }))
    .expect("smb listener message should serialize")
}

pub(crate) fn listener_new_dns_message(user: &str, name: &str, port: u16, domain: &str) -> String {
    serde_json::to_string(&OperatorMessage::ListenerNew(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: user.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: ListenerInfo {
            name: Some(name.to_owned()),
            protocol: Some("Dns".to_owned()),
            status: Some("Online".to_owned()),
            host_bind: Some("127.0.0.1".to_owned()),
            port_bind: Some(port.to_string()),
            extra: BTreeMap::from([("Domain".to_owned(), Value::String(domain.to_owned()))]),
            ..ListenerInfo::default()
        },
    }))
    .expect("dns listener message should serialize")
}

pub(crate) fn agent_task_message(task_id: &str) -> String {
    agent_task_message_for(task_id, "12345678")
}

pub(crate) fn agent_task_message_for(task_id: &str, demon_id: &str) -> String {
    serde_json::to_string(&OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: task_id.to_owned(),
            command_line: "checkin".to_owned(),
            demon_id: demon_id.to_owned(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            ..AgentTaskInfo::default()
        },
    }))
    .expect("agent task should serialize")
}

pub(crate) fn assert_agent_output(info: &AgentResponseInfo, output_text: &str) {
    assert_eq!(info.demon_id, "12345678");
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandOutput).to_string());
    assert_eq!(info.output, output_text);
    assert_eq!(info.command_line.as_deref(), Some("checkin"));
    assert_eq!(info.extra.get("RequestID").and_then(serde_json::Value::as_str), Some("2A"));
}

pub(crate) fn http_listener_config(port: u16) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: "edge-http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    })
}

pub(crate) fn smb_listener_config(name: &str, pipe_name: &str) -> ListenerConfig {
    ListenerConfig::from(SmbListenerConfig {
        name: name.to_owned(),
        pipe_name: pipe_name.to_owned(),
        kill_date: None,
        working_hours: None,
    })
}

pub(crate) fn dns_listener_config(name: &str, port: u16, domain: &str) -> ListenerConfig {
    ListenerConfig::from(DnsListenerConfig {
        name: name.to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: domain.to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    })
}

/// Profile with two Operator-role users for fan-out broadcast testing.
pub(crate) fn two_operator_profile() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "op_alpha" {
            Password = "alpha_pw"
            Role = "Operator"
          }
          user "op_beta" {
            Password = "beta_pw"
            Role = "Operator"
          }
        }

        Demon {
          AllowLegacyCtr = true
        }
        "#,
    )
    .expect("two-operator profile should parse")
}

/// Spin up a minimal teamserver with Admin, Operator, and Analyst users.
pub(crate) fn multi_role_profile() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "admin" {
            Password = "adminpw"
            Role = "Admin"
          }
          user "operator" {
            Password = "operatorpw"
            Role = "Operator"
          }
          user "analyst" {
            Password = "analystpw"
            Role = "Analyst"
          }
        }

        Demon {}
        "#,
    )
    .expect("multi-role profile should parse")
}

/// Read the next frame and assert it is a Close frame, indicating RBAC rejection.
pub(crate) async fn assert_connection_closed_after_rbac_denial(
    socket: &mut crate::common::WsSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let next =
        timeout(Duration::from_secs(30), futures_util::StreamExt::next(&mut socket.socket)).await?;
    match next {
        Some(Ok(ClientMessage::Close(_))) | None => Ok(()),
        Some(Ok(frame)) => {
            Err(format!("expected Close frame after RBAC denial, got {frame:?}").into())
        }
        Some(Err(error)) => Err(format!("websocket error after RBAC denial: {error}").into()),
    }
}

pub(crate) async fn read_until_operator_message<F>(
    socket: &mut crate::common::WsSession,
    mut predicate: F,
) -> Result<OperatorMessage, Box<dyn std::error::Error>>
where
    F: FnMut(&OperatorMessage) -> bool,
{
    for _ in 0..10 {
        let message = crate::common::read_operator_message(socket).await?;
        if predicate(&message) {
            return Ok(message);
        }
    }

    Err("did not observe expected operator message within 10 frames".into())
}

// ---------------------------------------------------------------------------
// DNS helpers
// ---------------------------------------------------------------------------

/// Base32hex alphabet (RFC 4648 §7).
const BASE32HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Encode `data` using base32hex (unpadded, uppercase).
pub(crate) fn base32hex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for &byte in data {
        buf = (buf << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(char::from(BASE32HEX_ALPHABET[((buf >> bits) & 0x1F) as usize]));
        }
    }
    if bits > 0 {
        buf <<= 5 - bits;
        result.push(char::from(BASE32HEX_ALPHABET[(buf & 0x1F) as usize]));
    }
    result
}

/// Decode base32hex (unpadded, case-insensitive) into bytes.
pub(crate) fn base32hex_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut result = Vec::with_capacity(input.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for ch in input.chars() {
        let val = match ch {
            '0'..='9' => (ch as u8) - b'0',
            'A'..='V' => (ch as u8) - b'A' + 10,
            'a'..='v' => (ch as u8) - b'a' + 10,
            '=' => continue,
            _ => return Err(format!("invalid base32hex character: {ch}").into()),
        };
        buf = (buf << 5) | u32::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
        }
    }
    Ok(result)
}

/// Build a DNS upload qname for the C2 protocol.
pub(crate) fn dns_upload_qname(
    agent_id: u32,
    seq: u16,
    total: u16,
    chunk: &[u8],
    domain: &str,
) -> String {
    format!("{}.{seq:x}-{total:x}-{agent_id:08x}.up.{domain}", base32hex_encode(chunk))
}

/// Build a DNS download qname for the C2 protocol.
pub(crate) fn dns_download_qname(agent_id: u32, seq: u16, domain: &str) -> String {
    format!("{seq:x}-{agent_id:08x}.dn.{domain}")
}

/// Build a minimal DNS TXT query packet.
pub(crate) fn build_dns_txt_query(id: u16, qname: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100_u16.to_be_bytes()); // flags: QR=0, RD=1
    buf.extend_from_slice(&1_u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // arcount
    for label in qname.split('.') {
        buf.push(u8::try_from(label.len()).expect("label too long"));
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&16_u16.to_be_bytes()); // QTYPE TXT
    buf.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS IN
    buf
}

/// DNS wire-format header length.
const DNS_HEADER_LEN: usize = 12;

/// Parse the TXT answer from a DNS response packet.
pub(crate) fn parse_dns_txt_answer(packet: &[u8]) -> Option<String> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let mut pos = DNS_HEADER_LEN;
    while pos < packet.len() {
        let len = usize::from(packet[pos]);
        pos += 1;
        if len == 0 {
            break;
        }
        pos = pos.checked_add(len)?;
    }
    pos = pos.checked_add(4)?; // QTYPE + QCLASS
    pos = pos.checked_add(2 + 2 + 2 + 4 + 2)?; // NAME + TYPE + CLASS + TTL + RDLENGTH
    let txt_len = usize::from(*packet.get(pos)?);
    let start = pos.checked_add(1)?;
    let end = start.checked_add(txt_len)?;
    std::str::from_utf8(packet.get(start..end)?).ok().map(str::to_owned)
}

/// Find a free UDP port on 127.0.0.1.
pub(crate) fn free_udp_port() -> u16 {
    let sock =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind ephemeral UDP socket");
    sock.local_addr().expect("failed to read local addr").port()
}

/// Wait for the DNS listener to start responding.
pub(crate) async fn wait_for_dns_listener(
    port: u16,
) -> Result<UdpSocket, Box<dyn std::error::Error>> {
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.connect(format!("127.0.0.1:{port}")).await?;

    for _ in 0..40 {
        let packet = build_dns_txt_query(0xFFFF, "probe.other.domain.com");
        let _ = client.send(&packet).await;
        let mut buf = vec![0u8; 512];
        if timeout(Duration::from_millis(50), client.recv(&mut buf)).await.is_ok() {
            return Ok(client);
        }
        sleep(Duration::from_millis(25)).await;
    }
    Err(format!("DNS listener on port {port} did not become ready").into())
}

/// Upload a Demon packet via chunked DNS queries. Returns the final TXT answer.
pub(crate) async fn dns_upload_demon_packet(
    client: &UdpSocket,
    agent_id: u32,
    payload: &[u8],
    domain: &str,
    query_id_base: u16,
) -> Result<String, Box<dyn std::error::Error>> {
    let chunks: Vec<&[u8]> = payload.chunks(39).collect();
    let total = u16::try_from(chunks.len())?;
    let mut last_txt = String::new();

    for (seq, chunk) in chunks.iter().enumerate() {
        let seq_u16 = u16::try_from(seq)?;
        let qname = dns_upload_qname(agent_id, seq_u16, total, chunk, domain);
        let packet = build_dns_txt_query(query_id_base.wrapping_add(seq_u16), &qname);
        client.send(&packet).await?;

        let mut buf = vec![0u8; 4096];
        let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
        buf.truncate(len);
        last_txt = parse_dns_txt_answer(&buf).ok_or("failed to parse TXT answer")?;
    }

    Ok(last_txt)
}

/// Download the queued DNS response by polling download queries.
pub(crate) async fn dns_download_response(
    client: &UdpSocket,
    agent_id: u32,
    domain: &str,
    query_id_base: u16,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut chunks: Vec<String> = Vec::new();
    let mut expected_total: Option<usize> = None;
    let mut seq: u16 = 0;

    loop {
        let qname = dns_download_qname(agent_id, seq, domain);
        let packet = build_dns_txt_query(query_id_base.wrapping_add(seq), &qname);
        client.send(&packet).await?;

        let mut buf = vec![0u8; 4096];
        let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
        buf.truncate(len);
        let txt = parse_dns_txt_answer(&buf).ok_or("failed to parse download TXT answer")?;

        if txt == "wait" {
            sleep(Duration::from_millis(50)).await;
            continue;
        }
        if txt == "done" {
            break;
        }

        let (total_str, b32_chunk) =
            txt.split_once(' ').ok_or_else(|| format!("unexpected download response: {txt}"))?;
        let total: usize = total_str.parse()?;
        if let Some(et) = expected_total {
            assert_eq!(et, total, "inconsistent total across download chunks");
        } else {
            expected_total = Some(total);
        }
        chunks.push(b32_chunk.to_owned());
        seq += 1;

        if chunks.len() >= total {
            let done_qname = dns_download_qname(agent_id, seq, domain);
            let done_packet = build_dns_txt_query(query_id_base.wrapping_add(seq), &done_qname);
            client.send(&done_packet).await?;
            let mut done_buf = vec![0u8; 4096];
            let done_len = timeout(Duration::from_secs(5), client.recv(&mut done_buf)).await??;
            done_buf.truncate(done_len);
            let done_txt = parse_dns_txt_answer(&done_buf);
            assert_eq!(done_txt.as_deref(), Some("done"), "expected 'done' after last chunk");
            break;
        }
    }

    let mut assembled = Vec::new();
    for chunk in &chunks {
        assembled.extend_from_slice(&base32hex_decode(chunk)?);
    }
    Ok(assembled)
}

// ---------------------------------------------------------------------------
// SMB helpers
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) const SMB_PIPE_PREFIX: &str = r"\\.\pipe\";

#[cfg(unix)]
pub(crate) fn unique_pipe_name(suffix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    format!("red-cell-smb-e2e-{suffix}-{ts}")
}

#[cfg(unix)]
pub(crate) fn resolve_socket_name(
    pipe_name: &str,
) -> Result<interprocess::local_socket::Name<'static>, Box<dyn std::error::Error>> {
    let trimmed = pipe_name.trim();
    let full = if trimmed.starts_with('/') || trimmed.starts_with(r"\\") {
        trimmed.to_owned()
    } else {
        format!("{SMB_PIPE_PREFIX}{trimmed}")
    };
    Ok(full.to_ns_name::<AbstractNsUdSocket>()?.into_owned())
}

#[cfg(unix)]
pub(crate) async fn connect_smb(
    pipe_name: &str,
) -> Result<LocalSocketStream, Box<dyn std::error::Error>> {
    let socket_name = resolve_socket_name(pipe_name)?;
    Ok(LocalSocketStream::connect(socket_name).await?)
}

#[cfg(unix)]
pub(crate) async fn wait_for_smb_listener(
    pipe_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..40 {
        if connect_smb(pipe_name).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }

    Err(format!("SMB listener on pipe `{pipe_name}` did not become ready within 1 s").into())
}

#[cfg(unix)]
pub(crate) async fn write_smb_frame(
    stream: &mut LocalSocketStream,
    agent_id: u32,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_u32_le(agent_id).await?;
    stream.write_u32_le(u32::try_from(payload.len())?).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(unix)]
pub(crate) async fn read_smb_frame(
    stream: &mut LocalSocketStream,
) -> Result<(u32, Vec<u8>), Box<dyn std::error::Error>> {
    let agent_id = stream.read_u32_le().await?;
    let payload_len = usize::try_from(stream.read_u32_le().await?)?;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok((agent_id, payload))
}
