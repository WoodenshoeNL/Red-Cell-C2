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
use red_cell_common::{HttpListenerConfig, ListenerConfig};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tempfile::tempdir;

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
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
    let port = common::available_port()?;
    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    manager.create(http_listener("havoc-http-compat", port)).await?;
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
