//! Shared test harness for mock Demon agent checkin tests.

use red_cell::ListenerManager;
use red_cell_common::HttpListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentResponseInfo, AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage,
};
use tokio_tungstenite::connect_async;

use super::common;

pub(super) fn demon_test_profile() -> Profile {
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

pub(super) struct DemonTestHarness {
    pub(super) server: common::TestServer,
    pub(super) listener_port: u16,
    pub(super) listener_name: String,
    pub(super) client: reqwest::Client,
    pub(super) socket: common::WsSession,
}

impl DemonTestHarness {
    pub(super) async fn shutdown(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.socket.close(None).await?;
        self.server.listeners.stop(&self.listener_name).await?;
        Ok(())
    }
}

/// Spawn a test server, create and start an HTTP listener, connect a WebSocket
/// operator, and return the handles needed by the test body.
pub(super) async fn spawn_server_with_http_listener(
    listener_name: &str,
) -> Result<DemonTestHarness, Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(demon_test_profile()).await?;
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
        }))
        .await?;
    drop(listener_guard);
    server.listeners.start(listener_name).await?;
    common::wait_for_listener(listener_port).await?;

    Ok(DemonTestHarness {
        server,
        listener_port,
        listener_name: listener_name.to_owned(),
        client,
        socket,
    })
}

/// Like [`spawn_server_with_http_listener`], but applies `customize` to the
/// [`ListenerManager`] before the listener is created.
pub(super) async fn spawn_server_with_http_listener_custom(
    listener_name: &str,
    customize: impl FnOnce(ListenerManager) -> ListenerManager,
) -> Result<DemonTestHarness, Box<dyn std::error::Error>> {
    let server = common::spawn_test_server_custom(demon_test_profile(), customize).await?;
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
        }))
        .await?;
    drop(listener_guard);
    server.listeners.start(listener_name).await?;
    common::wait_for_listener(listener_port).await?;

    Ok(DemonTestHarness {
        server,
        listener_port,
        listener_name: listener_name.to_owned(),
        client,
        socket,
    })
}

pub(super) fn operator_task_message(
    task_id: &str,
    command_line: &str,
    demon_id: &str,
    command_id: DemonCommand,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(&OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: task_id.to_owned(),
            command_line: command_line.to_owned(),
            demon_id: demon_id.to_owned(),
            command_id: u32::from(command_id).to_string(),
            ..AgentTaskInfo::default()
        },
    }))
}

pub(super) fn assert_agent_output(
    info: &AgentResponseInfo,
    task_id: &str,
    request_id: u32,
    command_line: &str,
    output_text: &str,
) {
    let request_id_hex = format!("{request_id:X}");
    assert_eq!(info.demon_id, "12345678");
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandOutput).to_string());
    assert_eq!(info.output, output_text);
    assert_eq!(info.command_line.as_deref(), Some(command_line));
    assert_eq!(
        info.extra.get("RequestID").and_then(serde_json::Value::as_str),
        Some(request_id_hex.as_str())
    );
    assert_eq!(info.extra.get("TaskID").and_then(serde_json::Value::as_str), Some(task_id));
}
