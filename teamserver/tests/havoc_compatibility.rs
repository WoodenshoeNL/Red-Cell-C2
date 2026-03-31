// This test file is only compiled when the `havoc-compat` feature is enabled.
//
// Without the feature the file is excluded entirely — tests cannot silently
// return Ok(()) and give false confidence in CI environments that lack the
// Go toolchain.
//
// To run:
//   cargo test --features havoc-compat -p red-cell havoc_compatibility
#![cfg(feature = "havoc-compat")]

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell::{AgentRegistry, Database, EventBus, Job, ListenerManager, SocketRelayManager};
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
    encrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DemonCommand, DemonMessage, DemonPackage};
use red_cell_common::{DnsListenerConfig, HttpListenerConfig, ListenerConfig};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tempfile::tempdir;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn red_cell_packets_match_havoc_at_offset_zero_and_advance_afterward()
-> Result<(), Box<dyn std::error::Error>> {
    if let Some(reason) = havoc_compatibility_skip_reason() {
        panic!(
            "havoc-compat feature is enabled but the Go toolchain is unavailable: {reason}\n\
             Install Go (https://go.dev/dl/) or run without --features havoc-compat."
        );
    }

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;
    let agent_id = 0x1234_5678;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let mut ctr_offset = 0_u64;

    manager.create(http_listener("havoc-http-compat", port)).await?;
    drop(guard);
    manager.start("havoc-http-compat").await?;
    common::wait_for_listener(port).await?;

    let client = Client::new();
    let init_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_ack = init_response.bytes().await?;

    let havoc_init_ack = havoc_encrypt_many(&key, &iv, 0, &[agent_id.to_le_bytes().to_vec()])?;
    assert_eq!(init_ack.as_ref(), havoc_init_ack[0].as_slice());
    assert_eq!(
        decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_ack)?,
        agent_id.to_le_bytes()
    );
    ctr_offset += ctr_blocks_for_len(init_ack.len());

    let first_payload = vec![1, 2, 3, 4];
    let second_payload = vec![5, 6, 7];
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandSleep),
                request_id: 41,
                payload: first_payload.clone(),
                command_line: "sleep 10".to_owned(),
                task_id: "task-41".to_owned(),
                created_at: "2026-03-09T20:10:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandCheckin),
                request_id: 42,
                payload: second_payload.clone(),
                command_line: "checkin".to_owned(),
                task_id: "task-42".to_owned(),
                created_at: "2026-03-09T20:11:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;

    let get_job_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            9,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let response_bytes = get_job_response.bytes().await?;
    let message = DemonMessage::from_bytes(response_bytes.as_ref())?;
    ctr_offset += ctr_blocks_for_len(4);
    let first_ciphertext = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &first_payload)?;
    let second_ciphertext = encrypt_agent_data_at_offset(
        &key,
        &iv,
        ctr_offset + ctr_blocks_for_len(first_payload.len()),
        &second_payload,
    )?;

    let expected = DemonMessage::new(vec![
        DemonPackage {
            command_id: u32::from(DemonCommand::CommandSleep),
            request_id: 41,
            payload: first_ciphertext.clone(),
        },
        DemonPackage {
            command_id: u32::from(DemonCommand::CommandCheckin),
            request_id: 42,
            payload: second_ciphertext.clone(),
        },
    ])
    .to_bytes()?;

    assert_eq!(message.packages.len(), 2);
    assert_eq!(response_bytes.as_ref(), expected.as_slice());

    // Cross-validate the per-payload ciphertexts against the Go AES-256-CTR
    // implementation at the correct accumulated block offsets.  This detects
    // any drift in `ctr_blocks_for_len` or `encrypt_agent_data_at_offset`
    // that would only manifest when the CTR counter is not at zero — the
    // scenario that arises for every packet after the initial handshake.
    let havoc_first = havoc_encrypt_many(&key, &iv, ctr_offset, &[first_payload.clone()])?;
    assert_eq!(
        first_ciphertext.as_slice(),
        havoc_first[0].as_slice(),
        "first job payload ciphertext must match Go AES-CTR at block offset {ctr_offset}"
    );

    let second_offset = ctr_offset + ctr_blocks_for_len(first_payload.len());
    let havoc_second = havoc_encrypt_many(&key, &iv, second_offset, &[second_payload.clone()])?;
    assert_eq!(
        second_ciphertext.as_slice(),
        havoc_second[0].as_slice(),
        "second job payload ciphertext must match Go AES-CTR at block offset {second_offset}"
    );

    manager.stop("havoc-http-compat").await?;
    Ok(())
}

#[tokio::test]
async fn demon_info_and_reconnect_match_havoc_after_non_zero_ctr_advance()
-> Result<(), Box<dyn std::error::Error>> {
    if let Some(reason) = havoc_compatibility_skip_reason() {
        panic!(
            "havoc-compat feature is enabled but the Go toolchain is unavailable: {reason}\n\
             Install Go (https://go.dev/dl/) or run without --features havoc-compat."
        );
    }

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;
    let agent_id = 0x2468_ACED;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE5, 0xF8, 0x0B, 0x1E, 0x31, 0x44, 0x57, 0x6A, 0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF,
        0x02,
    ];

    manager.create(http_listener("havoc-http-reconnect-compat", port)).await?;
    drop(guard);
    manager.start("havoc-http-reconnect-compat").await?;
    common::wait_for_listener(port).await?;

    let client = Client::new();
    let init_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_ack = init_response.bytes().await?;
    let mut ctr_offset = ctr_blocks_for_len(init_ack.len());
    assert_eq!(ctr_offset, 1, "init ACK should consume one AES block");

    let demon_info_payload = demon_info_mem_alloc_payload(0x1234_5678_9ABC_DEF0, 4096, 0x20);
    let mut expected_plaintext = Vec::with_capacity(4 + demon_info_payload.len());
    expected_plaintext.extend_from_slice(&u32::try_from(demon_info_payload.len())?.to_be_bytes());
    expected_plaintext.extend_from_slice(&demon_info_payload);
    let expected_plaintext_len = expected_plaintext.len();
    let expected_ciphertext = havoc_encrypt_many(&key, &iv, ctr_offset, &[expected_plaintext])?;

    let demon_info_request = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        ctr_offset,
        u32::from(DemonCommand::DemonInfo),
        0x10,
        &demon_info_payload,
    );
    let envelope = red_cell_common::demon::DemonEnvelope::from_bytes(&demon_info_request)?;
    assert_eq!(
        &envelope.payload[8..],
        expected_ciphertext[0].as_slice(),
        "DEMON_INFO callback ciphertext must match Go AES-CTR at block offset {ctr_offset}"
    );

    let demon_info_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(demon_info_request)
        .send()
        .await?
        .error_for_status()?;
    assert!(
        demon_info_response.bytes().await?.is_empty(),
        "DEMON_INFO callbacks should not return a body"
    );

    ctr_offset += ctr_blocks_for_len(expected_plaintext_len);
    assert!(ctr_offset > 1, "DEMON_INFO callback should advance the CTR past the initial block");
    assert_eq!(registry.ctr_offset(agent_id).await?, ctr_offset);

    let reconnect_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(common::valid_demon_reconnect_body(agent_id))
        .send()
        .await?
        .error_for_status()?;
    let reconnect_ack = reconnect_response.bytes().await?;
    let havoc_reconnect_ack =
        havoc_encrypt_many(&key, &iv, ctr_offset, &[agent_id.to_le_bytes().to_vec()])?;
    assert_eq!(
        reconnect_ack.as_ref(),
        havoc_reconnect_ack[0].as_slice(),
        "reconnect ACK must match Go AES-CTR at preserved block offset {ctr_offset}"
    );
    assert_eq!(
        decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &reconnect_ack)?,
        agent_id.to_le_bytes()
    );
    assert_eq!(
        registry.ctr_offset(agent_id).await?,
        ctr_offset,
        "reconnect ACK must not advance the stored CTR offset"
    );

    manager.stop("havoc-http-reconnect-compat").await?;
    Ok(())
}

fn http_listener(name: &str, port: u16) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
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
    })
}

fn demon_info_mem_alloc_payload(pointer: u64, size: u32, protection: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&10_u32.to_le_bytes());
    payload.extend_from_slice(&pointer.to_le_bytes());
    payload.extend_from_slice(&size.to_le_bytes());
    payload.extend_from_slice(&protection.to_le_bytes());
    payload
}

#[derive(Serialize)]
struct HavocEncryptRequest {
    key: String,
    iv: String,
    /// AES-CTR block offset to seek to before encrypting the first payload.
    /// Each block is 16 bytes; subsequent payloads share the same stream
    /// in sequence (no reset between them).
    offset: u64,
    payloads: Vec<String>,
}

#[derive(Deserialize)]
struct HavocEncryptResponse {
    ciphertexts: Vec<String>,
}

/// Invoke the Go AES-256-CTR harness, starting the keystream at `block_offset`
/// blocks into the cipher, then encrypting each payload in sequence.
///
/// This mirrors what `encrypt_agent_data_at_offset` does on the Rust side: seek
/// to `block_offset * 16` bytes into the keystream and XOR the payload.  Calling
/// this function with a single payload at the correct accumulated offset lets the
/// test assert byte-for-byte agreement between the two implementations at any
/// CTR position — not just at the initial offset-zero position.
fn havoc_encrypt_many(
    key: &[u8; AGENT_KEY_LENGTH],
    iv: &[u8; AGENT_IV_LENGTH],
    block_offset: u64,
    payloads: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let harness_dir = tempdir()?;
    let mut go_mod = std::fs::File::create(harness_dir.path().join("go.mod"))?;
    go_mod.write_all(b"module havoccompat\n\ngo 1.22.0\n")?;
    let mut harness = std::fs::File::create(harness_dir.path().join("main.go"))?;
    harness.write_all(
        br#"package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "encoding/json"
    "io"
    "os"
)

type request struct {
    Key      string   `json:"key"`
    IV       string   `json:"iv"`
    Offset   uint64   `json:"offset"`
    Payloads []string `json:"payloads"`
}

type response struct {
    Ciphertexts []string `json:"ciphertexts"`
}

func main() {
    var req request
    data, err := io.ReadAll(os.Stdin)
    if err != nil {
        panic(err)
    }
    if err := json.Unmarshal(data, &req); err != nil {
        panic(err)
    }

    key, err := base64.StdEncoding.DecodeString(req.Key)
    if err != nil {
        panic(err)
    }
    iv, err := base64.StdEncoding.DecodeString(req.IV)
    if err != nil {
        panic(err)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }
    stream := cipher.NewCTR(block, iv)

    // Advance to the requested block offset (each AES block = 16 bytes).
    // This is equivalent to what cipher.Seek does in the Rust ctr crate:
    // seek to byte position block_offset * 16.
    if req.Offset > 0 {
        dummy := make([]byte, req.Offset*16)
        stream.XORKeyStream(dummy, dummy)
    }

    out := response{Ciphertexts: make([]string, 0, len(req.Payloads))}
    for _, payloadText := range req.Payloads {
        payload, err := base64.StdEncoding.DecodeString(payloadText)
        if err != nil {
            panic(err)
        }
        ciphertext := make([]byte, len(payload))
        stream.XORKeyStream(ciphertext, payload)
        out.Ciphertexts = append(out.Ciphertexts, base64.StdEncoding.EncodeToString(ciphertext))
    }

    if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
        panic(err)
    }
}
"#,
    )?;

    let request = HavocEncryptRequest {
        key: BASE64_STANDARD.encode(key),
        iv: BASE64_STANDARD.encode(iv),
        offset: block_offset,
        payloads: payloads.iter().map(|payload| BASE64_STANDARD.encode(payload)).collect(),
    };
    let mut child = Command::new("go")
        .env("GOFLAGS", "-mod=mod")
        .arg("run")
        .arg(".")
        .current_dir(harness_dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let input = serde_json::to_vec(&request)?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(&input)?;
    } else {
        return Err("failed to open go harness stdin".into());
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(
            format!("go harness failed: {}", String::from_utf8_lossy(&output.stderr)).into()
        );
    }

    let response: HavocEncryptResponse = serde_json::from_slice(&output.stdout)?;
    response
        .ciphertexts
        .into_iter()
        .map(|ciphertext| Ok(BASE64_STANDARD.decode(ciphertext)?))
        .collect()
}

fn havoc_compatibility_skip_reason() -> Option<String> {
    if !go_available() {
        return Some("Go toolchain is unavailable".to_owned());
    }

    None
}

fn go_available() -> bool {
    Command::new("go")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

// ---------------------------------------------------------------------------
// DNS transport helpers
// ---------------------------------------------------------------------------

/// Base32hex alphabet (RFC 4648 §7).
const BASE32HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Encode `data` using base32hex (unpadded, uppercase).
fn base32hex_encode(data: &[u8]) -> String {
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
fn base32hex_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
fn dns_upload_qname(agent_id: u32, seq: u16, total: u16, chunk: &[u8], domain: &str) -> String {
    format!("{}.{seq:x}-{total:x}-{agent_id:08x}.up.{domain}", base32hex_encode(chunk))
}

/// Build a DNS download qname for the C2 protocol.
fn dns_download_qname(agent_id: u32, seq: u16, domain: &str) -> String {
    format!("{seq:x}-{agent_id:08x}.dn.{domain}")
}

/// Build a minimal DNS TXT query packet.
fn build_dns_txt_query(id: u16, qname: &str) -> Vec<u8> {
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
    buf.push(0); // zero terminator
    buf.extend_from_slice(&16_u16.to_be_bytes()); // QTYPE = TXT
    buf.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS = IN
    buf
}

/// DNS wire-format header length.
const DNS_HEADER_LEN: usize = 12;

/// Parse the TXT answer from a DNS response packet.
fn parse_dns_txt_answer(packet: &[u8]) -> Option<String> {
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
fn free_udp_port() -> u16 {
    let sock =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind ephemeral UDP socket");
    sock.local_addr().expect("failed to read local addr").port()
}

/// Wait for the DNS listener to start responding.
async fn wait_for_dns_listener(port: u16) -> Result<UdpSocket, Box<dyn std::error::Error>> {
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

/// Upload a Demon packet to the DNS listener as chunked DNS queries.
async fn dns_upload_demon_packet(
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

/// Poll DNS download queries until all chunks are received and reassemble the payload.
async fn dns_download_response(
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
            break;
        }
    }

    let mut assembled = Vec::new();
    for chunk in &chunks {
        assembled.extend_from_slice(&base32hex_decode(chunk)?);
    }
    Ok(assembled)
}

fn dns_listener(name: &str, port: u16, domain: &str) -> ListenerConfig {
    ListenerConfig::from(DnsListenerConfig {
        name: name.to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: domain.to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    })
}

// ---------------------------------------------------------------------------
// DNS compatibility test
// ---------------------------------------------------------------------------

/// Cross-validate that a DNS listener's AES-256-CTR init ACK matches the Go
/// reference implementation byte-for-byte.
///
/// The DNS and HTTP listeners share the same `process_demon_transport` function
/// and therefore the same AES-256-CTR crypto path.  The DNS transport adds
/// base32hex encoding and multi-chunk framing on top — this test verifies that
/// the framing layer does not corrupt, pad, or otherwise alter the ciphertext
/// that reaches the agent.
///
/// If the DNS framing ever introduces its own CTR offset accounting (e.g.
/// padding, counter reset, or a different block alignment rule), this test
/// will catch the divergence against the Go ground truth.
#[tokio::test]
async fn dns_listener_init_ack_matches_havoc_aes_ctr_at_offset_zero()
-> Result<(), Box<dyn std::error::Error>> {
    if let Some(reason) = havoc_compatibility_skip_reason() {
        panic!(
            "havoc-compat feature is enabled but the Go toolchain is unavailable: {reason}\n\
             Install Go (https://go.dev/dl/) or run without --features havoc-compat."
        );
    }

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let port = free_udp_port();
    let domain = "c2.compat.test";
    let agent_id = 0xDEAD_CAFE_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x41, 0x42, 0x43, 0x44,
        0x45, 0x46,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD0, 0xE1, 0xF2, 0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7A, 0x8B, 0x9C, 0xAD, 0xBE,
        0xCF,
    ];

    manager.create(dns_listener("havoc-dns-compat", port, domain)).await?;
    manager.start("havoc-dns-compat").await?;
    let client = wait_for_dns_listener(port).await?;

    // 1. Upload a DEMON_INIT via DNS chunked queries.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0x1000).await?;
    assert_eq!(init_result, "ack", "DEMON_INIT upload must be acknowledged");

    // 2. Download the init ACK ciphertext via DNS download queries.
    let ack_ciphertext = dns_download_response(&client, agent_id, domain, 0x2000).await?;
    assert!(!ack_ciphertext.is_empty(), "init ACK must be non-empty");

    // 3. Decrypt the ACK and verify it contains the agent_id (sanity check).
    let decrypted =
        red_cell_common::crypto::decrypt_agent_data_at_offset(&key, &iv, 0, &ack_ciphertext)?;
    assert_eq!(
        decrypted.as_slice(),
        &agent_id.to_le_bytes(),
        "init ACK plaintext must be the agent_id in LE bytes"
    );

    // 4. Cross-validate: the Go AES-256-CTR implementation at offset 0 must
    //    produce the same ciphertext the DNS listener delivered.
    let havoc_ack = havoc_encrypt_many(&key, &iv, 0, &[agent_id.to_le_bytes().to_vec()])?;
    assert_eq!(
        ack_ciphertext.as_slice(),
        havoc_ack[0].as_slice(),
        "DNS listener init ACK ciphertext must match Go AES-CTR at block offset 0 — \
         this confirms the DNS transport framing (base32hex chunking) does not alter \
         the underlying ciphertext produced by the shared crypto path"
    );

    // 5. Verify the CTR offset advanced correctly for subsequent callbacks.
    let ctr_offset = ctr_blocks_for_len(ack_ciphertext.len());
    assert_eq!(ctr_offset, 1, "init ACK should consume one AES block");
    assert_eq!(
        registry.ctr_offset(agent_id).await?,
        ctr_offset,
        "registry CTR offset must match the init ACK block count"
    );

    manager.stop("havoc-dns-compat").await?;
    Ok(())
}
