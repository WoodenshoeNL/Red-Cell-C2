use std::time::Duration;

use red_cell::{AgentRegistry, Database, EventBus, ListenerManager, SocketRelayManager};
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, advance_iv, ctr_blocks_for_length, decrypt_agent_data,
    encrypt_agent_data, encrypt_agent_data_ctr,
};
use red_cell_common::demon::{DemonCommand, DemonEnvelope};
use red_cell_common::operator::OperatorMessage;
use red_cell_common::{HttpListenerConfig, ListenerConfig};
use reqwest::Client;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn http_listener_pipeline_registers_agent_and_broadcasts_checkin()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None);
    let mut event_receiver = events.subscribe();
    let port = available_port()?;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let agent_id = 0x1234_5678;

    manager.create(http_listener("edge-http-pipeline", port)).await?;
    manager.start("edge-http-pipeline").await?;
    wait_for_listener(port).await?;

    let client = Client::new();
    let init_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("x-real-ip", "198.51.100.44")
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_ack = init_response.bytes().await?;

    let ack_offset = registry.ctr_offset(agent_id).await? - ctr_blocks_for_length(4);
    let effective_iv = advance_iv(&iv, ack_offset);
    let decrypted_ack = decrypt_agent_data(&key, &effective_iv, &init_ack)?;
    assert_eq!(decrypted_ack.as_slice(), &agent_id.to_le_bytes());

    let stored = registry.get(agent_id).await.ok_or("agent should be registered")?;
    let before_checkin = stored.last_call_in.clone();
    assert_eq!(stored.hostname, "wkstn-01");
    assert_eq!(stored.external_ip, "198.51.100.44");

    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentNew(message)) = event else {
        panic!("expected agent registration event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, "edge-http-pipeline");
    assert_eq!(message.info.external_ip, "198.51.100.44");

    let checkin_offset = registry.ctr_offset(agent_id).await?;
    let checkin_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body_ctr(
            agent_id,
            key,
            iv,
            checkin_offset,
            u32::from(DemonCommand::CommandCheckin),
            6,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(checkin_response.bytes().await?.is_empty());

    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentUpdate(message)) = event else {
        panic!("expected agent checkin event");
    };
    assert_eq!(message.info.agent_id, "12345678");
    assert_eq!(message.info.marked, "Alive");

    let updated = registry.get(agent_id).await.ok_or("agent should remain registered")?;
    assert_ne!(updated.last_call_in, before_checkin);

    manager.stop("edge-http-pipeline").await?;
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

fn valid_demon_callback_body_ctr(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    block_offset: u64,
    command_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut decrypted = Vec::new();
    decrypted.extend_from_slice(&u32::try_from(payload.len()).unwrap_or_default().to_be_bytes());
    decrypted.extend_from_slice(payload);

    let (encrypted, _) = encrypt_agent_data_ctr(&key, &iv, block_offset, &decrypted)
        .unwrap_or_else(|error| panic!("ctr encrypt failed: {error}"));
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
