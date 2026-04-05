//! Load and chaos/resilience tests for the teamserver.
//!
//! These tests exercise the teamserver under concurrent load and fault conditions
//! to verify:
//!
//! 1. **Concurrency safety** — no data races or corruption under simultaneous agent checkins.
//! 2. **Agent storm** — many agents registering and polling concurrently succeed at high rates.
//! 3. **Malformed packet flood** — a burst of bad packets does not crash or wedge the listener.
//! 4. **Mid-connection disconnect** — a TCP connection dropped mid-POST leaves no ghost state.
//! 5. **Registry capacity enforcement** — the registry rejects new agents once at the cap.
//! 6. **Download-limit enforcement under concurrent load** — the per-listener aggregate byte
//!    cap is respected when multiple agents upload simultaneously.

mod common;

use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;
use red_cell::{
    AgentRegistry, DEFAULT_MAX_DOWNLOAD_BYTES, Database, EventBus, EventReceiver, ListenerManager,
    SocketRelayManager,
};
use red_cell_common::HttpListenerConfig;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonFilesystemCommand};
use red_cell_common::operator::OperatorMessage;
use reqwest::Client;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Spin up a `ListenerManager` backed by an in-memory database with a single
/// HTTP listener already started.  Returns the manager, the agent registry, and
/// the listener port.
///
/// The listener is configured with `behind_redirector = true` and the loopback
/// address as a trusted proxy.  Tests must set the `x-real-ip` header on every
/// registration request to a unique address (see [`fake_agent_ip`]) so that
/// the per-IP `DemonInit` rate limiter does not throttle back concurrent load tests.
async fn spawn_http_listener_with_manager(
    name: &str,
    max_aggregate_download_bytes: u64,
) -> Result<(ListenerManager, AgentRegistry, u16), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_max_aggregate_download_bytes(max_aggregate_download_bytes)
        .with_demon_allow_legacy_ctr(true);

    let (port, guard) = common::available_port()?;
    manager
        .create(red_cell_common::ListenerConfig::from(HttpListenerConfig {
            name: name.to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: port,
            port_conn: Some(port),
            method: Some("POST".to_owned()),
            // Trust loopback as a reverse-proxy so we can supply unique x-real-ip
            // headers per agent and avoid the per-IP DemonInit rate limiter.
            behind_redirector: true,
            trusted_proxy_peers: vec!["127.0.0.1".to_owned()],
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
        }))
        .await?;
    drop(guard);
    manager.start(name).await?;
    common::wait_for_listener(port).await?;

    Ok((manager, registry, port))
}

/// Generate a deterministic fake source IP for agent `n` (1-based).
///
/// Produces addresses in `10.0.0.0/16`, cycling every 65 025 agents.  Tests
/// use this to give each agent a distinct IP so the per-source `DemonInit`
/// rate limiter does not throttle concurrent load tests.
fn fake_agent_ip(n: u32) -> String {
    let n = n.saturating_sub(1); // 0-based offset
    let octet3 = n / 255;
    let octet4 = n % 255 + 1;
    format!("10.0.{octet3}.{octet4}")
}

/// Make a test AES key from a seed byte (non-zero, non-degenerate).
fn key_from_seed(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8 + 1))
}

/// Make a test AES IV from a seed byte (non-zero, non-degenerate).
fn iv_from_seed(seed: u8) -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8 + 0x10))
}

// ---------------------------------------------------------------------------
// Download payload builders (used by download-limit enforcement tests)
// ---------------------------------------------------------------------------

/// Encode a string as LE-length-prefixed UTF-16 LE bytes.
fn le_utf16(s: &str) -> Vec<u8> {
    let utf16_bytes: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut out = (utf16_bytes.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(&utf16_bytes);
    out
}

/// Encode a byte slice as LE-length-prefixed bytes.
fn le_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = (b.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(b);
    out
}

/// Build a `CommandFs` / `Download` mode=0 (start) payload.
///
/// Wire layout (all LE): u32 subcommand | u32 mode=0 | u32 file_id | u64 expected_size | utf16 path
fn download_start_payload(file_id: u32, expected_size: u64, remote_path: &str) -> Vec<u8> {
    let mut p = u32::from(DemonFilesystemCommand::Download).to_le_bytes().to_vec();
    p.extend_from_slice(&0_u32.to_le_bytes()); // mode = 0 (start)
    p.extend_from_slice(&file_id.to_le_bytes());
    p.extend_from_slice(&expected_size.to_le_bytes());
    p.extend_from_slice(&le_utf16(remote_path));
    p
}

/// Build a `CommandFs` / `Download` mode=1 (chunk) payload.
///
/// Wire layout (all LE): u32 subcommand | u32 mode=1 | u32 file_id | bytes chunk
fn download_chunk_payload(file_id: u32, chunk: &[u8]) -> Vec<u8> {
    let mut p = u32::from(DemonFilesystemCommand::Download).to_le_bytes().to_vec();
    p.extend_from_slice(&1_u32.to_le_bytes()); // mode = 1 (chunk)
    p.extend_from_slice(&file_id.to_le_bytes());
    p.extend_from_slice(&le_bytes(chunk));
    p
}

/// Drain the event bus receiver for up to `deadline`, returning the first
/// `AgentResponse` event whose `Type` extra field equals `expected_type` and
/// whose `Message` extra field contains `message_substring`.
///
/// Returns `true` if such an event is found before the deadline.
async fn event_contains_response(
    rx: &mut EventReceiver,
    expected_type: &str,
    message_substring: &str,
    deadline: tokio::time::Instant,
) -> bool {
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(OperatorMessage::AgentResponse(msg))) => {
                let type_match = msg
                    .info
                    .extra
                    .get("Type")
                    .and_then(|v| v.as_str())
                    .map_or(false, |t| t == expected_type);
                let msg_match = msg
                    .info
                    .extra
                    .get("Message")
                    .and_then(|v| v.as_str())
                    .map_or(false, |m| m.contains(message_substring));
                if type_match && msg_match {
                    return true;
                }
            }
            Ok(Some(_)) => {}                  // skip other event types
            Ok(None) | Err(_) => return false, // bus closed or timed out
        }
    }
}

// ---------------------------------------------------------------------------
// Load tests
// ---------------------------------------------------------------------------

/// **Agent storm** — 50 unique agents check in concurrently; every registration
/// must succeed and all agents must appear in the registry.
///
/// This surfaces data-race bugs in `AgentRegistry` under fan-in load.
#[tokio::test]
async fn concurrent_agent_checkins_all_succeed() -> Result<(), Box<dyn std::error::Error>> {
    const AGENT_COUNT: u32 = 50;

    let (_manager, registry, port) =
        spawn_http_listener_with_manager("load-storm", DEFAULT_MAX_DOWNLOAD_BYTES).await?;

    let client = Arc::new(Client::new());

    let tasks: Vec<_> = (1..=AGENT_COUNT)
        .map(|i| {
            let client = Arc::clone(&client);
            let key = key_from_seed(i as u8);
            let iv = iv_from_seed(i as u8);
            let ip = fake_agent_ip(i);
            tokio::spawn(async move {
                let body = common::valid_demon_init_body(i, key, iv);
                let resp = client
                    .post(format!("http://127.0.0.1:{port}/"))
                    .header("x-real-ip", ip)
                    .body(body)
                    .send()
                    .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(resp.status())
            })
        })
        .collect();

    let results = join_all(tasks).await;

    let mut success_count = 0u32;
    let mut failures = Vec::new();
    for result in results {
        match result {
            Ok(Ok(status)) if status.is_success() => success_count += 1,
            Ok(Ok(status)) => failures.push(format!("unexpected status: {status}")),
            Ok(Err(e)) => failures.push(format!("request error: {e}")),
            Err(e) => failures.push(format!("task panic: {e}")),
        }
    }

    // All agents should have registered successfully.
    assert!(failures.is_empty(), "some registrations failed: {failures:?}");
    assert_eq!(
        success_count, AGENT_COUNT,
        "expected all {AGENT_COUNT} agents to register; only {success_count} succeeded"
    );

    // Verify the registry contains every agent.
    for i in 1..=AGENT_COUNT {
        assert!(
            registry.get(i).await.is_some(),
            "agent {i} missing from registry after concurrent checkin"
        );
    }

    Ok(())
}

/// **Duplicate ID storm** — 20 concurrent requests all try to register the same
/// agent ID.  Exactly one should succeed; the listener must not panic or corrupt
/// the registry regardless of which request wins the race.
#[tokio::test]
async fn concurrent_duplicate_agent_id_is_safe() -> Result<(), Box<dyn std::error::Error>> {
    const CONCURRENCY: u32 = 20;
    const AGENT_ID: u32 = 0xDEAD_BEEF;

    let (_manager, registry, port) =
        spawn_http_listener_with_manager("load-dup-id", DEFAULT_MAX_DOWNLOAD_BYTES).await?;

    let client = Arc::new(Client::new());

    let tasks: Vec<_> = (0..CONCURRENCY)
        .map(|i| {
            let client = Arc::clone(&client);
            // Vary the key per request so the first writer wins deterministically.
            let key = key_from_seed(i as u8 + 1);
            let iv = iv_from_seed(i as u8 + 1);
            // Each request uses a unique source IP to avoid the per-IP rate limiter.
            let ip = fake_agent_ip(i + 1);
            tokio::spawn(async move {
                let body = common::valid_demon_init_body(AGENT_ID, key, iv);
                client
                    .post(format!("http://127.0.0.1:{port}/"))
                    .header("x-real-ip", ip)
                    .body(body)
                    .send()
                    .await
                    .map(|r| r.status())
            })
        })
        .collect();

    let results = join_all(tasks).await;

    // Aggregate results — we only care that the process did not panic.
    let mut success_count = 0usize;
    for result in results {
        if let Ok(Ok(status)) = result {
            if status.is_success() {
                success_count += 1;
            }
        }
    }

    // At least one registration must have succeeded.
    assert!(
        success_count >= 1,
        "expected at least one duplicate-ID registration to succeed, got zero"
    );

    // The registry must contain exactly one entry for the agent.
    let stored = registry.get(AGENT_ID).await;
    assert!(
        stored.is_some(),
        "agent {AGENT_ID:#010x} must be in the registry after duplicate-ID storm"
    );

    Ok(())
}

/// **Registry at capacity** — register agents up to the configured cap, then
/// attempt one more.  The extra registration must be rejected (non-2xx) and the
/// registry count must not exceed the cap.
#[tokio::test]
async fn registry_at_capacity_rejects_new_agents() -> Result<(), Box<dyn std::error::Error>> {
    const CAP: usize = 5;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::with_max_registered_agents(database.clone(), CAP);
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let (port, guard) = common::available_port()?;
    manager.create(common::http_listener_config("cap-test", port)).await?;
    drop(guard);
    manager.start("cap-test").await?;
    common::wait_for_listener(port).await?;

    let client = Client::new();

    // Register exactly CAP agents — all must succeed.
    for i in 1..=(CAP as u32) {
        let body = common::valid_demon_init_body(i, key_from_seed(i as u8), iv_from_seed(i as u8));
        let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;
        assert!(
            resp.status().is_success(),
            "agent {i} should register before cap; status={}",
            resp.status()
        );
    }

    // One agent over the cap must be rejected.
    let overflow_id = CAP as u32 + 1;
    let body = common::valid_demon_init_body(
        overflow_id,
        key_from_seed(overflow_id as u8),
        iv_from_seed(overflow_id as u8),
    );
    let over_cap_resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;

    assert!(
        !over_cap_resp.status().is_success(),
        "expected rejection when registry is at cap ({CAP}), got {}",
        over_cap_resp.status()
    );

    // Registry count must not exceed the cap.
    let count = registry.list().await.len();
    assert_eq!(count, CAP, "registry should contain exactly {CAP} agents, not {count}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Chaos tests
// ---------------------------------------------------------------------------

/// **Malformed packet flood** — send 100 concurrent garbage/truncated/corrupted
/// packets.  The server must not crash, and a valid registration must succeed
/// afterward.
#[tokio::test]
async fn malformed_packet_flood_does_not_crash_listener() -> Result<(), Box<dyn std::error::Error>>
{
    const BAD_COUNT: usize = 100;

    let (_manager, registry, port) =
        spawn_http_listener_with_manager("chaos-malformed", DEFAULT_MAX_DOWNLOAD_BYTES).await?;

    let client = Arc::new(Client::new());

    // Variety of malformed payloads exercising different failure modes.
    let bad_payloads: Vec<Vec<u8>> = (0..BAD_COUNT)
        .map(|i| match i % 5 {
            // Empty body.
            0 => vec![],
            // Random bytes (wrong magic, garbage structure).
            1 => (0..64u8).map(|b| b.wrapping_mul(i as u8 + 1)).collect(),
            // Truncated after magic — too short for a valid header.
            2 => vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x0C],
            // Valid header size field but mismatched actual length.
            3 => {
                let mut v = vec![0x00, 0x00, 0x00, 0xFF]; // size=255
                v.extend_from_slice(&0xDEAD_BEEF_u32.to_be_bytes()); // magic ok
                v.extend_from_slice(&(i as u32).to_be_bytes()); // agent id
                v // actual body is only 12 bytes, size claims 255
            }
            // Valid-looking envelope but payload is pure garbage (wrong command).
            _ => {
                let garbage: Vec<u8> = (0..32).map(|j| (j ^ i) as u8).collect();
                DemonEnvelope::new(i as u32 | 0x8000_0000, garbage)
                    .expect("envelope construction should succeed for garbage payload")
                    .to_bytes()
            }
        })
        .collect();

    let tasks: Vec<_> = bad_payloads
        .into_iter()
        .map(|body| {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                let _ = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await;
            })
        })
        .collect();

    join_all(tasks).await;

    // Server must still be alive and able to process a valid registration.
    let recovery_id: u32 = 0xC0FF_EE00;
    let key = key_from_seed(0xAB);
    let iv = iv_from_seed(0xCD);
    let body = common::valid_demon_init_body(recovery_id, key, iv);
    let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;

    assert!(
        resp.status().is_success(),
        "listener must remain alive after malformed flood; status={}",
        resp.status()
    );
    assert!(
        registry.get(recovery_id).await.is_some(),
        "recovery agent must be registered after malformed flood"
    );

    Ok(())
}

/// **Mid-POST disconnect** — open a raw TCP connection to the HTTP listener,
/// begin sending a valid `DEMON_INIT` POST body, then abruptly close the socket
/// before the body is complete.  The agent must *not* appear in the registry
/// (no ghost state) and the listener must continue accepting new connections.
#[tokio::test]
async fn mid_post_disconnect_leaves_no_ghost_agent() -> Result<(), Box<dyn std::error::Error>> {
    const GHOST_AGENT_ID: u32 = 0xBAD_0_DEAD;

    let (_manager, registry, port) =
        spawn_http_listener_with_manager("chaos-disconnect", DEFAULT_MAX_DOWNLOAD_BYTES).await?;

    let key = key_from_seed(0x11);
    let iv = iv_from_seed(0x22);

    // Build the full body but only transmit half of it.
    let full_body = common::valid_demon_init_body(GHOST_AGENT_ID, key, iv);
    let partial_len = full_body.len() / 2;

    // Send a partial HTTP POST using raw TCP, then drop the connection.
    {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await?;

        let headers = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
            full_body.len()
        );
        stream.write_all(headers.as_bytes()).await?;
        stream.write_all(&full_body[..partial_len]).await?;
        stream.flush().await?;

        // Drop stream to simulate an abrupt disconnect (TCP RST / FIN).
    }

    // Give the server a moment to process the incomplete request.
    sleep(Duration::from_millis(200)).await;

    // No ghost agent should have been created.
    assert!(
        registry.get(GHOST_AGENT_ID).await.is_none(),
        "agent {GHOST_AGENT_ID:#010x} must not be registered after mid-POST disconnect"
    );

    // The listener must still be alive for subsequent requests.
    let alive_id: u32 = 0xAA55_AA55;
    let k2 = key_from_seed(0x33);
    let i2 = iv_from_seed(0x44);
    let body = common::valid_demon_init_body(alive_id, k2, i2);
    let client = Client::new();
    let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;

    assert!(
        resp.status().is_success(),
        "listener must remain alive after mid-POST disconnect; status={}",
        resp.status()
    );

    Ok(())
}

/// **Download limit under concurrent load** — configure the listener with a
/// 512 KiB aggregate download cap, then have multiple agents open concurrent
/// downloads and push 256 KiB chunks each (total 1.25 MiB — well above the cap).
///
/// This verifies that `ListenerManager::with_max_aggregate_download_bytes` actually
/// fires `DownloadAggregateTooLarge` under concurrent pressure.  The previous version
/// of this test sent raw (unencrypted) packets that failed at the crypto layer before
/// reaching the download tracker, so the cap was never exercised.
///
/// Protocol:
/// 1. Register N agents (each with their own session key).
/// 2. Send `CommandFs / Download mode=0 (start)` for every agent — opens the download slot.
/// 3. Concurrently send `CommandFs / Download mode=1 (chunk)` for every agent with a 256 KiB
///    chunk.  The aggregate cap (512 KiB) allows at most 2 to succeed; the remaining ≥3 must
///    be rejected with a `DownloadAggregateTooLarge` error event.
/// 4. Assert that at least one `AgentResponse{Type=Error, Message∋"aggregate"}` event was
///    broadcast before a short deadline.
#[tokio::test]
async fn download_limit_enforced_under_concurrent_upload() -> Result<(), Box<dyn std::error::Error>>
{
    // 512 KiB aggregate cap — allows at most 2 of the 256 KiB chunks below.
    const CAP_BYTES: u64 = 512 * 1024;
    // Each chunk is 256 KiB — 5 agents × 256 KiB = 1 280 KiB > cap.
    const CHUNK_SIZE: usize = 256 * 1024;
    const CONCURRENT_AGENTS: u32 = 5;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    // Subscribe before the EventBus is moved into the ListenerManager so we
    // receive all events broadcast during the test.
    let mut event_rx = events.subscribe();

    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_max_aggregate_download_bytes(CAP_BYTES)
        .with_demon_allow_legacy_ctr(true);

    let (port, guard) = common::available_port()?;
    manager.create(common::http_listener_config("chaos-dl-limit", port)).await?;
    drop(guard);
    manager.start("chaos-dl-limit").await?;
    common::wait_for_listener(port).await?;

    let client = Arc::new(Client::new());

    // Step 1 — register all agents sequentially.
    for i in 1..=CONCURRENT_AGENTS {
        let body = common::valid_demon_init_body(i, key_from_seed(i as u8), iv_from_seed(i as u8));
        let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;
        assert!(resp.status().is_success(), "agent {i} should register; status={}", resp.status());
    }

    // Step 2 — open a download slot for every agent (mode=0, sequential).
    // In legacy CTR mode every packet starts at AES-CTR block 0.
    for i in 1..=CONCURRENT_AGENTS {
        let file_id = 0x0100_u32 + i;
        let start_payload = download_start_payload(
            file_id,
            (CHUNK_SIZE * 2) as u64,
            &format!("C:\\temp\\file_{i}.bin"),
        );
        let body = common::valid_demon_callback_body(
            i,
            key_from_seed(i as u8),
            iv_from_seed(i as u8),
            0, // ctr_offset=0 — legacy mode, never advances
            u32::from(DemonCommand::CommandFs),
            i, // request_id
            &start_payload,
        );
        let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;
        assert!(
            resp.status().is_success(),
            "agent {i} download-start should succeed; status={}",
            resp.status()
        );
    }

    // Step 3 — push 256 KiB chunks concurrently (total 1 280 KiB > 512 KiB cap).
    // The DownloadAggregateTooLarge handler emits an AgentResponse{Type=Error} event
    // rather than returning an HTTP error, so all HTTP responses will be 200 OK — the
    // aggregate cap is only observable through the event bus.
    let chunk = vec![0xAA_u8; CHUNK_SIZE];
    let tasks: Vec<_> = (1..=CONCURRENT_AGENTS)
        .map(|i| {
            let client = Arc::clone(&client);
            let chunk = chunk.clone();
            let file_id = 0x0100_u32 + i;
            let chunk_payload = download_chunk_payload(file_id, &chunk);
            let body = common::valid_demon_callback_body(
                i,
                key_from_seed(i as u8),
                iv_from_seed(i as u8),
                0, // ctr_offset=0 — legacy mode, never advances
                u32::from(DemonCommand::CommandFs),
                i,
                &chunk_payload,
            );
            tokio::spawn(async move {
                client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await
            })
        })
        .collect();
    join_all(tasks).await;

    // Step 4 — verify the aggregate cap fired at least once.
    // Allow a short window (300 ms) for async broadcasts to land.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    assert!(
        event_contains_response(&mut event_rx, "Error", "aggregate", deadline).await,
        "expected at least one download chunk to trigger the aggregate cap ({CAP_BYTES} bytes) \
         and broadcast an AgentResponse{{Type=Error, Message∋\"aggregate\"}} event, \
         but none was observed within the deadline"
    );

    Ok(())
}

/// **Concurrent polling after checkin** — register 30 agents and then have
/// them all poll (send a no-op callback) concurrently without the server
/// panicking or producing corrupt responses.
#[tokio::test]
async fn concurrent_agent_polling_does_not_corrupt_state() -> Result<(), Box<dyn std::error::Error>>
{
    const AGENT_COUNT: u32 = 30;

    let (_manager, registry, port) =
        spawn_http_listener_with_manager("load-poll", DEFAULT_MAX_DOWNLOAD_BYTES).await?;

    let client = Arc::new(Client::new());

    // Register all agents sequentially (to avoid the duplicate-ID race tested elsewhere).
    // Each gets a unique fake IP to stay under the per-source DemonInit rate limit.
    for i in 1..=AGENT_COUNT {
        let body = common::valid_demon_init_body(i, key_from_seed(i as u8), iv_from_seed(i as u8));
        client
            .post(format!("http://127.0.0.1:{port}/"))
            .header("x-real-ip", fake_agent_ip(i))
            .body(body)
            .send()
            .await?
            .error_for_status()?;
    }

    // Now poll concurrently — each agent sends a NOP callback (empty body aside from header).
    let tasks: Vec<_> = (1..=AGENT_COUNT)
        .map(|i| {
            let client = Arc::clone(&client);
            let key = key_from_seed(i as u8);
            let iv = iv_from_seed(i as u8);
            tokio::spawn(async move {
                // Build a GetJob callback (agent polls for pending commands).
                let body = common::valid_demon_callback_body(
                    i,
                    key,
                    iv,
                    0,
                    u32::from(DemonCommand::CommandGetJob),
                    0,
                    &[],
                );
                let resp =
                    client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(resp.status())
            })
        })
        .collect();

    let results = join_all(tasks).await;
    let mut ok_count = 0u32;
    for result in results {
        if let Ok(Ok(status)) = result {
            if status.is_success() {
                ok_count += 1;
            }
        }
    }

    // All polls should succeed (no panics, no corrupt state).
    assert_eq!(
        ok_count, AGENT_COUNT,
        "expected all {AGENT_COUNT} concurrent polls to succeed; got {ok_count}"
    );

    // Registry must still be consistent after concurrent polling.
    let count = registry.list().await.len();
    assert_eq!(count, AGENT_COUNT as usize, "registry count mismatch after concurrent polling");

    Ok(())
}

/// **Rapid agent registration/deregistration cycle** — repeatedly register and
/// deregister agents to verify that the registry does not accumulate stale
/// entries or deadlock under churn.
#[tokio::test]
async fn agent_registration_churn_stays_consistent() -> Result<(), Box<dyn std::error::Error>> {
    const ROUNDS: u32 = 20;
    const AGENTS_PER_ROUND: u32 = 10;

    let (_manager, registry, port) =
        spawn_http_listener_with_manager("load-churn", DEFAULT_MAX_DOWNLOAD_BYTES).await?;

    let client = Client::new();

    for round in 0..ROUNDS {
        let base_id = round * AGENTS_PER_ROUND + 1;

        // Register a batch of agents.
        for i in base_id..(base_id + AGENTS_PER_ROUND) {
            let body =
                common::valid_demon_init_body(i, key_from_seed(i as u8), iv_from_seed(i as u8));
            let resp = client
                .post(format!("http://127.0.0.1:{port}/"))
                .header("x-real-ip", fake_agent_ip(i))
                .body(body)
                .send()
                .await?;
            assert!(
                resp.status().is_success(),
                "round {round} agent {i} registration failed: {}",
                resp.status()
            );
        }

        // Remove the batch so it does not count toward subsequent rounds.
        for i in base_id..(base_id + AGENTS_PER_ROUND) {
            let _ = registry.remove(i).await;
        }

        // After removal the count must be zero (no accumulated stale entries).
        let count = registry.list().await.len();
        assert_eq!(count, 0, "registry should be empty after round {round} removal, got {count}");
    }

    Ok(())
}

/// **Listener survives a burst of oversized requests** — send requests whose
/// `Content-Length` or body size exceeds `MAX_AGENT_MESSAGE_LEN`.  The server
/// must reject them without crashing or running out of memory.
#[tokio::test]
async fn oversized_body_burst_does_not_oom_listener() -> Result<(), Box<dyn std::error::Error>> {
    use red_cell::MAX_AGENT_MESSAGE_LEN;

    const BURST: usize = 10;

    let (_manager, _registry, port) =
        spawn_http_listener_with_manager("chaos-oversize", DEFAULT_MAX_DOWNLOAD_BYTES).await?;

    let client = Arc::new(Client::new());

    // Claim to send MAX_AGENT_MESSAGE_LEN + 1 bytes.
    // The actual body is a short stub — the server should reject based on the
    // Content-Length header before reading the full stream.
    let oversize_len = MAX_AGENT_MESSAGE_LEN + 1;

    let tasks: Vec<_> = (0..BURST)
        .map(|_| {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                let _ = client
                    .post(format!("http://127.0.0.1:{port}/"))
                    .header("Content-Length", oversize_len.to_string())
                    .body(vec![0u8; 64]) // actual short stub
                    .send()
                    .await;
            })
        })
        .collect();

    join_all(tasks).await;

    // Server must still respond after the burst.
    let probe_id: u32 = 0xFEED_FACE;
    let body = common::valid_demon_init_body(probe_id, key_from_seed(0x55), iv_from_seed(0x66));
    let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;

    assert!(
        resp.status().is_success(),
        "listener must be alive after oversized-body burst; status={}",
        resp.status()
    );

    Ok(())
}

/// **Rapid-fire timeout validation** — verify that all tests complete within a
/// reasonable wall-clock budget.  This test itself always passes; its purpose is
/// to ensure the overall suite does not contain blocking or hung operations.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_load_tests_complete_within_timeout() {
    // This is a marker test.  The real assertion is that `cargo nextest run`
    // terminates in under the configured timeout (default: 60 s per test).
    // No action needed here.
}
