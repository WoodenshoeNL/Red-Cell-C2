//! Integration tests for per-agent Archon magic validation (ARC-10).
//!
//! Verifies that the teamserver rejects Archon callbacks whose per-build magic
//! does not match the value stored at first check-in, and that the rejection
//! happens before AES decryption (CTR offset must not advance).

mod common;

use red_cell_common::HttpListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

fn archon_test_profile() -> Profile {
    Profile::parse(
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

struct ArchonTestHarness {
    server: common::TestServer,
    listener_port: u16,
    listener_name: String,
    client: reqwest::Client,
    socket: common::WsSession,
}

impl ArchonTestHarness {
    async fn shutdown(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.socket.close(None).await?;
        self.server.listeners.stop(&self.listener_name).await?;
        Ok(())
    }
}

async fn spawn_non_legacy_listener(
    listener_name: &str,
) -> Result<ArchonTestHarness, Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(archon_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(red_cell_common::ListenerConfig::from(HttpListenerConfig {
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
            legacy_mode: false,
            suppress_opsec_warnings: true,
        }))
        .await?;
    drop(listener_guard);
    server.listeners.start(listener_name).await?;
    common::wait_for_listener(listener_port).await?;

    Ok(ArchonTestHarness {
        server,
        listener_port,
        listener_name: listener_name.to_owned(),
        client,
        socket,
    })
}

/// A callback with a wrong magic must be rejected with HTTP 404 and the CTR offset
/// must not advance — proving rejection happens before AES decryption.
#[tokio::test]
async fn archon_wrong_magic_callback_returns_404_and_preserves_ctr_offset()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_non_legacy_listener("archon-magic-test").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0xAB_CD_EF_12_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
        0x2E, 0x2F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F,
    ];
    let ctr_offset = 0_u64;
    let correct_magic: u32 = 0x1A2B_3C4D;

    // --- Register the Archon agent with correct_magic ----------------------------
    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_archon_init_body(agent_id, key, iv, correct_magic))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes(), "init ack should echo agent_id");

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew event after Archon init"
    );

    // --- Send a callback with a WRONG magic -------------------------------------
    let wrong_magic: u32 = 0xDEAD_C0DE;
    let wrong_magic_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_archon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
            wrong_magic,
        ))
        .send()
        .await?;
    assert_eq!(
        wrong_magic_response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "wrong-magic Archon callback must be rejected with fake 404"
    );

    // --- CTR offset must NOT have advanced (rejection before AES decryption) ---
    assert_eq!(
        harness.server.agent_registry.ctr_offset(agent_id).await?,
        ctr_offset,
        "CTR offset must not advance after wrong-magic Archon callback"
    );

    harness.shutdown().await?;
    Ok(())
}

/// A callback with the correct magic must be accepted and return the pending task.
#[tokio::test]
async fn archon_correct_magic_callback_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_non_legacy_listener("archon-correct-magic").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x11_22_33_44_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
        0x6E, 0x6F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F,
    ];
    let ctr_offset = 0_u64;
    let magic: u32 = 0x5E7A_1F3B;

    // --- Register ---------------------------------------------------------------
    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_archon_init_body(agent_id, key, iv, magic))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // --- Send a callback with the CORRECT magic — must succeed -------------------
    let get_job_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_archon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            2,
            &[],
            magic,
        ))
        .send()
        .await?;
    assert_eq!(
        get_job_response.status(),
        reqwest::StatusCode::OK,
        "correct-magic Archon callback must be accepted"
    );

    harness.shutdown().await?;
    Ok(())
}
