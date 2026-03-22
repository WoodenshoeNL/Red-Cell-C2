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
    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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
    assert_eq!(agent.send_ctr_offset(), 1);
    assert_eq!(agent.recv_ctr_offset(), 1);
    assert_eq!(harness.server.agent_registry.ctr_offset(agent.agent_id()).await?, 1);

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    let red_cell_common::operator::OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent registration event");
    };
    assert_eq!(message.info.name_id, format!("{:08X}", agent.agent_id()));
    assert_eq!(message.info.listener, "specter-http");
    assert!(!message.info.hostname.is_empty());

    let checkin_response = agent.checkin().await?;
    assert!(checkin_response.is_empty());
    assert_eq!(agent.send_ctr_offset(), 2);
    assert_eq!(agent.recv_ctr_offset(), 2);
    assert_eq!(harness.server.agent_registry.ctr_offset(agent.agent_id()).await?, 2);

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
    assert_eq!(agent.send_ctr_offset(), 4);
    assert_eq!(agent.recv_ctr_offset(), 4);
    assert_eq!(harness.server.agent_registry.ctr_offset(agent.agent_id()).await?, 4);

    harness.shutdown().await?;
    Ok(())
}
