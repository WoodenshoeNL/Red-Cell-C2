#[path = "../../../teamserver/tests/common/mod.rs"]
mod common;

use red_cell::Job;
use red_cell_common::HttpListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::demon::DemonCommand;
use specter::{SpecterAgent, SpecterConfig};
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
            doh_domain: None,
            doh_provider: None,
        }))
        .await?;
    drop(listener_guard);
    server.listeners.start(listener_name).await?;
    common::wait_for_listener(listener_port).await?;

    Ok(DemonTestHarness { server, listener_port, listener_name: listener_name.to_owned(), socket })
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

#[tokio::test]
async fn specter_agent_init_checkin_and_get_job_stay_ctr_synchronised()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("specter-http").await?;
    let callback_url = format!("http://127.0.0.1:{}/", harness.listener_port);
    let mut agent =
        SpecterAgent::new(SpecterConfig { callback_url, sleep_delay_ms: 1, ..Default::default() })?;

    agent.init_handshake().await?;
    // Monotonic CTR mode (Specter sends INIT_EXT_MONOTONIC_CTR): the init ACK advances
    // the shared CTR by 1 block on both server and agent.
    let ctr_after_init = agent.ctr_offset();
    assert_eq!(ctr_after_init, 1, "shared CTR must be 1 after init ACK");
    assert_eq!(
        harness.server.agent_registry.ctr_offset(agent.agent_id()).await?,
        ctr_after_init,
        "server and agent CTR must agree after init"
    );

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    let red_cell_common::operator::OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent registration event");
    };
    assert_eq!(message.info.name_id, format!("{:08X}", agent.agent_id()));
    assert_eq!(message.info.listener, "specter-http");
    assert!(!message.info.hostname.is_empty());

    let ctr_before_checkin = agent.ctr_offset();
    let checkin_response = agent.checkin().await?;
    assert!(checkin_response.is_empty());
    // Monotonic CTR: shared offset advances after both the callback send and response decrypt.
    assert!(agent.ctr_offset() > ctr_before_checkin, "CTR must advance after checkin");

    let ctr_before_job = agent.ctr_offset();

    harness
        .server
        .agent_registry
        .enqueue_job(
            agent.agent_id(),
            Job {
                command: u32::from(DemonCommand::CommandSleep),
                request_id: 0x2A,
                payload: vec![0x05, 0x00, 0x00, 0x00],
                command_line: "sleep 5".to_owned(),
                task_id: "task-2A".to_owned(),
                created_at: "2026-03-22T00:00:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;

    let tasking = agent.get_job().await?;
    assert_eq!(tasking.packages.len(), 1);
    assert_eq!(tasking.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
    assert_eq!(tasking.packages[0].request_id, 0x2A);
    assert_eq!(tasking.packages[0].payload, vec![0x05, 0x00, 0x00, 0x00]);
    // CTR offset must have advanced after the job round-trip.
    assert!(agent.ctr_offset() > ctr_before_job, "CTR must advance after get_job");

    harness.shutdown().await?;
    Ok(())
}
