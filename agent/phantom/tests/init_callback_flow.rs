//! Integration test exercising Phantom against the real teamserver.
//!
//! This mirrors Specter's `init_callback_flow.rs` — it spins up an in-memory
//! teamserver with an HTTP listener, runs the Phantom agent through init +
//! checkin, and verifies that both sides stay CTR-synchronised.
//!
//! Unlike the E2E mock tests in `e2e_integration.rs`, this test catches any
//! protocol incompatibility between Phantom and the real teamserver code.

#[path = "../../../teamserver/tests/common/mod.rs"]
mod common;

use phantom::{PhantomAgent, PhantomConfig};
use red_cell::Job;
use red_cell_common::HttpListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::demon::DemonCommand;
use tokio_tungstenite::connect_async;

fn demon_test_profile() -> Profile {
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

        Demon {}
        "#,
    )
    .expect("test profile should parse")
}

struct DemonTestHarness {
    server: common::TestServer,
    listener_port: u16,
    listener_name: String,
    socket: common::WsClient,
}

impl DemonTestHarness {
    async fn shutdown(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.socket.close(None).await?;
        self.server.listeners.stop(&self.listener_name).await?;
        Ok(())
    }
}

async fn spawn_server_with_http_listener(
    listener_name: &str,
) -> Result<DemonTestHarness, Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(demon_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let (mut socket, _) = connect_async(server.ws_url()).await?;
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
        }))
        .await?;
    drop(listener_guard);
    server.listeners.start(listener_name).await?;
    common::wait_for_listener(listener_port).await?;

    Ok(DemonTestHarness { server, listener_port, listener_name: listener_name.to_owned(), socket })
}

/// Phantom agent init + checkin against the real teamserver stays CTR-synchronised.
#[tokio::test]
async fn phantom_agent_init_and_checkin_stay_ctr_synchronised()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("phantom-http").await?;
    let callback_url = format!("http://127.0.0.1:{}/", harness.listener_port);
    let mut agent = PhantomAgent::new(PhantomConfig {
        callback_url,
        sleep_delay_ms: 0,
        sleep_jitter: 0,
        ..PhantomConfig::default()
    })?;

    // --- Init handshake ---
    agent.init_handshake().await?;

    // Monotonic CTR mode: init ACK advances the shared CTR by 1 block.
    let ctr_after_init = agent.ctr_offset();
    assert_eq!(ctr_after_init, 1, "shared CTR must be 1 after init ACK");
    assert_eq!(
        harness.server.agent_registry.ctr_offset(agent.agent_id()).await?,
        ctr_after_init,
        "server and agent CTR must agree after init"
    );

    // Verify the teamserver received the agent registration event.
    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    let red_cell_common::operator::OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent registration event, got: {agent_new:?}");
    };
    assert_eq!(message.info.name_id, format!("{:08X}", agent.agent_id()));
    assert_eq!(message.info.listener, "phantom-http");
    assert!(!message.info.hostname.is_empty());

    // --- Checkin (empty, no tasks) ---
    let ctr_before_checkin = agent.ctr_offset();
    let exit = agent.checkin().await?;
    assert!(!exit, "empty checkin should not signal exit");

    // CTR must advance after the checkin round-trip (callback send + response decrypt).
    assert!(agent.ctr_offset() > ctr_before_checkin, "CTR must advance after checkin");

    // --- Checkin with a sleep task ---
    // Enqueue a sleep task so the agent receives and processes it.
    harness
        .server
        .agent_registry
        .enqueue_job(
            agent.agent_id(),
            Job {
                command: u32::from(DemonCommand::CommandSleep),
                request_id: 0x42,
                payload: vec![0x0A, 0x00, 0x00, 0x00], // sleep 10ms (LE i32)
                command_line: "sleep 10".to_owned(),
                task_id: "task-42".to_owned(),
                created_at: "2026-03-31T00:00:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;

    let ctr_before_task = agent.ctr_offset();
    let exit = agent.checkin().await?;
    assert!(!exit, "sleep task should not signal exit");

    // CTR must advance further after processing the tasking.
    assert!(agent.ctr_offset() > ctr_before_task, "CTR must advance after checkin with task");

    // The server-side job queue must be empty: the task was actually fetched and consumed.
    let remaining = harness.server.agent_registry.queued_jobs(agent.agent_id()).await?;
    assert!(remaining.is_empty(), "job queue must be empty after checkin processed the task");

    // The CommandSleep payload (0x0A 0x00 0x00 0x00 = 10 ms LE i32) must have been executed
    // — i.e. config.sleep_delay_ms updated — which confirms execute() was actually called.
    assert_eq!(
        agent.sleep_delay_ms(),
        10,
        "sleep_delay_ms must be updated to 10 after executing the CommandSleep task"
    );

    harness.shutdown().await?;
    Ok(())
}
