use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell::{AgentRegistry, Database, EventBus, Job, ListenerManager, SocketRelayManager};
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data, encrypt_agent_data,
};
use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonMessage, DemonPackage};
use red_cell_common::{HttpListenerConfig, ListenerConfig};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tempfile::tempdir;
use tokio::time::sleep;

#[tokio::test]
async fn red_cell_packets_match_havoc_reference_aes_ctr_behavior()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
    let port = available_port()?;
    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];

    manager.create(http_listener("havoc-http-compat", port)).await?;
    manager.start("havoc-http-compat").await?;
    wait_for_listener(port).await?;

    let client = Client::new();
    let init_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_ack = init_response.bytes().await?;

    let havoc_init_ack = havoc_encrypt_many(&key, &iv, &[agent_id.to_le_bytes().to_vec()])?;
    assert_eq!(init_ack.as_ref(), havoc_init_ack[0].as_slice());
    assert_eq!(decrypt_agent_data(&key, &iv, &init_ack)?, agent_id.to_le_bytes());

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
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            9,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let response_bytes = get_job_response.bytes().await?;
    let message = DemonMessage::from_bytes(response_bytes.as_ref())?;
    let havoc_payloads = havoc_encrypt_many(&key, &iv, &[first_payload, second_payload])?;

    let expected = DemonMessage::new(vec![
        DemonPackage {
            command_id: u32::from(DemonCommand::CommandSleep),
            request_id: 41,
            payload: havoc_payloads[0].clone(),
        },
        DemonPackage {
            command_id: u32::from(DemonCommand::CommandCheckin),
            request_id: 42,
            payload: havoc_payloads[1].clone(),
        },
    ])
    .to_bytes()?;

    assert_eq!(message.packages.len(), 2);
    assert_eq!(response_bytes.as_ref(), expected.as_slice());

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

fn available_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

async fn wait_for_listener(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    for _ in 0..40 {
        if let Ok(response) = client.get(format!("http://127.0.0.1:{port}/")).send().await {
            if response.status() != reqwest::StatusCode::NOT_IMPLEMENTED {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(25)).await;
    }

    Err(format!("listener on port {port} did not become ready").into())
}

fn valid_demon_init_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&agent_id.to_be_bytes());
    add_length_prefixed_bytes_be(&mut metadata, b"wkstn-01");
    add_length_prefixed_bytes_be(&mut metadata, b"operator");
    add_length_prefixed_bytes_be(&mut metadata, b"REDCELL");
    add_length_prefixed_bytes_be(&mut metadata, b"10.0.0.25");
    add_length_prefixed_utf16_be(&mut metadata, "C:\\Windows\\explorer.exe");
    metadata.extend_from_slice(&1337_u32.to_be_bytes());
    metadata.extend_from_slice(&1338_u32.to_be_bytes());
    metadata.extend_from_slice(&512_u32.to_be_bytes());
    metadata.extend_from_slice(&2_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0x401000_u64.to_be_bytes());
    metadata.extend_from_slice(&10_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&22000_u32.to_be_bytes());
    metadata.extend_from_slice(&9_u32.to_be_bytes());
    metadata.extend_from_slice(&15_u32.to_be_bytes());
    metadata.extend_from_slice(&20_u32.to_be_bytes());
    metadata.extend_from_slice(&1_893_456_000_u64.to_be_bytes());
    metadata.extend_from_slice(&0b101010_u32.to_be_bytes());

    let encrypted = encrypt_agent_data(&key, &iv, &metadata)
        .unwrap_or_else(|error| panic!("metadata encryption should succeed: {error}"));
    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
        key.as_slice(),
        iv.as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| panic!("failed to build demon init request body: {error}"))
        .to_bytes()
}

fn valid_demon_callback_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    command_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut decrypted = Vec::new();
    decrypted.extend_from_slice(&u32::try_from(payload.len()).unwrap_or_default().to_be_bytes());
    decrypted.extend_from_slice(payload);

    let encrypted = encrypt_agent_data(&key, &iv, &decrypted)
        .unwrap_or_else(|error| panic!("callback encrypt failed: {error}"));
    let body = [
        command_id.to_be_bytes().as_slice(),
        request_id.to_be_bytes().as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, body)
        .unwrap_or_else(|error| panic!("failed to build demon callback request body: {error}"))
        .to_bytes()
}

fn add_length_prefixed_bytes_be(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or_default().to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn add_length_prefixed_utf16_be(buf: &mut Vec<u8>, value: &str) {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_be_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    add_length_prefixed_bytes_be(buf, &encoded);
}

#[derive(Serialize)]
struct HavocEncryptRequest {
    key: String,
    iv: String,
    payloads: Vec<String>,
}

#[derive(Deserialize)]
struct HavocEncryptResponse {
    ciphertexts: Vec<String>,
}

fn havoc_encrypt_many(
    key: &[u8; AGENT_KEY_LENGTH],
    iv: &[u8; AGENT_IV_LENGTH],
    payloads: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let harness_dir = tempdir()?;
    let mut go_mod = std::fs::File::create(harness_dir.path().join("go.mod"))?;
    go_mod.write_all(
        br#"module havoccompat

go 1.22.0

require Havoc v0.0.0

replace Havoc => /home/michel/Red-Cell-C2/src/Havoc/teamserver
"#,
    )?;
    let mut harness = std::fs::File::create(harness_dir.path().join("main.go"))?;
    harness.write_all(
        br#"package main

import (
    "encoding/base64"
    "encoding/json"
    "io"
    "os"

    "Havoc/pkg/common/crypt"
)

type request struct {
    Key string `json:"key"`
    IV string `json:"iv"`
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

    out := response{Ciphertexts: make([]string, 0, len(req.Payloads))}
    for _, payloadText := range req.Payloads {
        payload, err := base64.StdEncoding.DecodeString(payloadText)
        if err != nil {
            panic(err)
        }
        ciphertext := crypt.XCryptBytesAES256(payload, key, iv)
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
