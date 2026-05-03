//! Integration tests for monotonic AES-CTR mode (INIT_EXT_MONOTONIC_CTR).
//!
//! Verifies the full pipeline for agents that opt into monotonic CTR mode:
//!
//! 1. An agent sends `DEMON_INIT` with `INIT_EXT_MONOTONIC_CTR` set in the extension flags.
//! 2. The teamserver registers the agent with `legacy_ctr = false`.
//! 3. The init ACK is encrypted at CTR block offset 0; the server advances its offset to 1.
//! 4. Subsequent callbacks from the agent are encrypted at monotonically advancing offsets.
//! 5. The server successfully decrypts all callbacks and keeps the shared offset in sync.

mod common;

use red_cell::demon::INIT_EXT_MONOTONIC_CTR;
use red_cell_common::{
    HttpListenerConfig, ListenerConfig,
    crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset},
    demon::{DemonCommand, DemonMessage},
};

fn monotonic_test_profile() -> red_cell_common::config::Profile {
    red_cell_common::config::Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Demon {}
        "#,
    )
    .expect("test profile should parse")
}

/// Profile that opts into legacy-CTR acceptance; used only by the legacy-CTR integration test.
fn legacy_ctr_test_profile() -> red_cell_common::config::Profile {
    red_cell_common::config::Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Demon {
          AllowLegacyCtr = true
        }
        "#,
    )
    .expect("test profile should parse")
}

/// Spawn a test server with an HTTP listener and a connected operator WebSocket.
///
/// Uses the monotonic-CTR profile (default, `AllowLegacyCtr = false`).
async fn spawn_server(
    listener_name: &str,
) -> Result<(common::TestServer, u16, reqwest::Client, common::WsSession), Box<dyn std::error::Error>>
{
    spawn_server_with_profile(listener_name, monotonic_test_profile()).await
}

/// Spawn a test server using an explicit profile.
async fn spawn_server_with_profile(
    listener_name: &str,
    profile: red_cell_common::config::Profile,
) -> Result<(common::TestServer, u16, reqwest::Client, common::WsSession), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(profile).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    use tokio_tungstenite::connect_async;
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(ListenerConfig::from(HttpListenerConfig {
            name: listener_name.to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: listener_port,
            port_conn: Some(listener_port),
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
        }))
        .await?;
    drop(listener_guard);
    server.listeners.start(listener_name).await?;
    common::wait_for_listener(listener_port).await?;

    Ok((server, listener_port, client, socket))
}

/// An agent that opts into monotonic CTR mode via `INIT_EXT_MONOTONIC_CTR` must be
/// registered with `legacy_ctr = false`, and the server must successfully decrypt
/// multiple subsequent callbacks whose payloads are encrypted at monotonically
/// advancing CTR block offsets.
///
/// Concretely:
/// - DEMON_INIT response (init ACK): server encrypts `agent_id` (4 bytes = 1 block) at
///   offset 0 → offset advances to 1.
/// - First callback (GetJob, empty payload): agent encrypts 4+0=4 bytes at offset 1 →
///   offset advances to 2.
/// - Second callback (CommandOutput, 20-byte payload): agent encrypts 4+20=24 bytes at
///   offset 2 → offset advances to 2 + ceil(24/16) = 4.
/// - Third callback (CommandOutput, another payload): agent encrypts at offset 4.
///
/// After each callback the test queries the registry to confirm the offset advanced
/// correctly and never reset to zero.
#[tokio::test]
async fn monotonic_ctr_init_and_sequential_callbacks() -> Result<(), Box<dyn std::error::Error>> {
    let (server, listener_port, client, mut socket) = spawn_server("mono-ctr-http").await?;

    let agent_id: u32 = 0xAB_CD_12_34;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        0x01, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91, 0xA1, 0xB1, 0xC1, 0xD1, 0xE1,
        0xF1, 0x02,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0x00,
    ];

    // ── Step 1: DEMON_INIT with INIT_EXT_MONOTONIC_CTR ──────────────────────────────────────────

    let init_body =
        common::valid_demon_init_body_with_ext_flags(agent_id, key, iv, INIT_EXT_MONOTONIC_CTR);
    let init_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(init_body)
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;

    // The init ACK is encrypted at CTR block offset 0 (4-byte agent_id = 1 block).
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, 0, &init_bytes)?;
    assert_eq!(
        init_ack.as_slice(),
        &agent_id.to_le_bytes(),
        "init ACK must be the agent_id in LE bytes"
    );

    // ── Step 2: Verify server registered the agent with legacy_ctr = false ──────────────────────

    // Give the server a moment to complete async registration before querying.
    let _ = common::read_operator_message(&mut socket).await?; // AgentNew event

    assert!(
        !server.agent_registry.legacy_ctr(agent_id).await?,
        "agent registered with INIT_EXT_MONOTONIC_CTR must have legacy_ctr = false"
    );

    // After the init ACK the server has consumed 1 CTR block (4-byte agent_id).
    let expected_offset_after_init = ctr_blocks_for_len(4); // = 1
    assert_eq!(
        server.agent_registry.ctr_offset(agent_id).await?,
        expected_offset_after_init,
        "CTR offset must be 1 after init ACK (4-byte payload = 1 AES block)"
    );

    // ── Step 3: First callback (GetJob) at the advancing offset ─────────────────────────────────

    // The agent encrypts its GetJob callback at offset 1 (batched format: empty body = 0 encrypted bytes).
    let offset_cb1 = expected_offset_after_init; // 1
    let get_job_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            offset_cb1,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = get_job_response.bytes().await?;

    // The job queue response uses the DemonMessage wire format (not AES-CTR encrypted).
    // When no tasks are queued the server returns a single DEMON_COMMAND_NO_JOB package
    // so the Demon agent's CommandDispatcher loop keeps running to drain JobCheckList.
    let message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(message.packages.len(), 1, "empty queue must return a single NO_JOB package");
    assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandNoJob));
    assert!(message.packages[0].payload.is_empty());

    // After the GetJob callback: batched format encrypts 0 bytes → 0 blocks advanced.
    let expected_offset_after_cb1 = offset_cb1 + ctr_blocks_for_len(0); // 1 + 0 = 1
    assert_eq!(
        server.agent_registry.ctr_offset(agent_id).await?,
        expected_offset_after_cb1,
        "CTR offset must advance by 1 block after GetJob callback (4-byte encrypted payload)"
    );
    assert_eq!(
        expected_offset_after_cb1, expected_offset_after_init,
        "empty GET_JOB body encrypts 0 bytes, so CTR offset must not advance"
    );

    // ── Step 4: Second callback (CommandOutput) at the advancing offset ─────────────────────────

    let output1 = "hello from specter";
    let output1_payload = common::command_output_payload(output1);
    let offset_cb2 = expected_offset_after_cb1; // 2
    let cb2_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            offset_cb2,
            u32::from(DemonCommand::CommandOutput),
            1,
            &output1_payload,
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(cb2_response.bytes().await?.is_empty(), "CommandOutput response must be empty");

    // After callback 2: encrypted portion was 4 + output1_payload.len() bytes.
    let encrypted_len_cb2 = 4 + output1_payload.len();
    let expected_offset_after_cb2 = offset_cb2 + ctr_blocks_for_len(encrypted_len_cb2);
    assert_eq!(
        server.agent_registry.ctr_offset(agent_id).await?,
        expected_offset_after_cb2,
        "CTR offset must advance by {} block(s) after CommandOutput callback",
        ctr_blocks_for_len(encrypted_len_cb2)
    );
    assert!(
        expected_offset_after_cb2 > expected_offset_after_cb1,
        "offset must keep advancing after second callback"
    );

    // ── Step 5: Third callback (CommandOutput) at the further-advancing offset ─────────────────

    let output2 = "second output from specter agent";
    let output2_payload = common::command_output_payload(output2);
    let offset_cb3 = expected_offset_after_cb2;
    let cb3_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            offset_cb3,
            u32::from(DemonCommand::CommandOutput),
            2,
            &output2_payload,
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(cb3_response.bytes().await?.is_empty(), "third CommandOutput response must be empty");

    let encrypted_len_cb3 = 4 + output2_payload.len();
    let expected_offset_after_cb3 = offset_cb3 + ctr_blocks_for_len(encrypted_len_cb3);
    assert_eq!(
        server.agent_registry.ctr_offset(agent_id).await?,
        expected_offset_after_cb3,
        "CTR offset must advance by {} block(s) after third callback",
        ctr_blocks_for_len(encrypted_len_cb3)
    );
    assert!(
        expected_offset_after_cb3 > expected_offset_after_cb2,
        "offset must keep advancing after third callback"
    );

    // ── Step 6: Confirm offset never reset to zero ───────────────────────────────────────────────

    // The init-ack offset (1) must be strictly less than each successive callback offset.
    assert!(
        expected_offset_after_cb3 > expected_offset_after_init,
        "monotonic CTR must never reset: final offset ({expected_offset_after_cb3}) must exceed \
         post-init offset ({expected_offset_after_init})"
    );

    // ── Teardown ─────────────────────────────────────────────────────────────────────────────────

    socket.close(None).await?;
    server.listeners.stop("mono-ctr-http").await?;
    Ok(())
}

/// An agent that sends `DEMON_INIT` **without** extension flags (legacy Havoc behavior) must
/// be registered with `legacy_ctr = true`, and subsequent callbacks must all be accepted at
/// CTR block offset 0 — no offset advancement.
///
/// This is the counter-example to `monotonic_ctr_init_and_sequential_callbacks`: it
/// ensures that the legacy path is unaffected by the monotonic CTR feature.
#[tokio::test]
async fn legacy_ctr_init_callbacks_all_at_offset_zero() -> Result<(), Box<dyn std::error::Error>> {
    let (server, listener_port, client, mut socket) =
        spawn_server_with_profile("legacy-ctr-http", legacy_ctr_test_profile()).await?;

    let agent_id: u32 = 0xDE_AD_BE_EF;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
        0x3E, 0x3F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];

    // DEMON_INIT without extension flags → legacy mode.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(init_body)
        .send()
        .await?
        .error_for_status()?;

    let _ = common::read_operator_message(&mut socket).await?; // AgentNew event

    // In legacy mode legacy_ctr must be true.
    assert!(
        server.agent_registry.legacy_ctr(agent_id).await?,
        "legacy DEMON_INIT (no ext flags) must register with legacy_ctr = true"
    );

    // Legacy CTR: the init-ack does not advance the offset.
    assert_eq!(
        server.agent_registry.ctr_offset(agent_id).await?,
        0,
        "legacy CTR mode: offset must remain at 0 after init ACK"
    );

    // First callback at offset 0 must succeed.
    let cb1_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            0,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = cb1_response.bytes().await?;
    let message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(message.packages.len(), 1, "empty queue must return a single NO_JOB package");
    assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandNoJob));

    // Legacy CTR: offset stays at 0 after every callback.
    assert_eq!(
        server.agent_registry.ctr_offset(agent_id).await?,
        0,
        "legacy CTR mode: offset must remain at 0 after callbacks"
    );

    socket.close(None).await?;
    server.listeners.stop("legacy-ctr-http").await?;
    Ok(())
}
