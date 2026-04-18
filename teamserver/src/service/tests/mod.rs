use super::agent::{
    handle_agent_instance_register, handle_agent_output, handle_agent_response, handle_agent_task,
    handle_register_agent,
};
pub(super) use super::auth::SERVICE_AUTH_FRAME_TIMEOUT;
use super::listeners::{handle_listener_add, handle_listener_start};
use super::*;
use red_cell_common::operator::{
    AgentResponseInfo, EventCode, ListenerErrorInfo, ListenerMarkInfo, Message, MessageHead,
    OperatorMessage, ServiceAgentRegistrationInfo, ServiceListenerRegistrationInfo,
};
use std::time::Duration;

mod agent_task;
mod audit;
mod auth;
mod bridge;
mod dispatch;
mod listener;
mod routes;

// ── Shared test helpers ──────────────────────────────────────────────

/// Create a test database and webhook notifier pair for audit logging tests.
pub(super) async fn test_audit_deps() -> (Database, AuditWebhookNotifier) {
    let database = crate::database::Database::connect_in_memory().await.expect("in-memory db");
    let webhooks = AuditWebhookNotifier::default();
    (database, webhooks)
}

/// Create an Argon2id verifier from a plaintext password (for test use).
pub(super) fn test_verifier(password: &str) -> String {
    password_verifier_for_sha3(&hash_password_sha3(password))
        .expect("test verifier should be generated")
}

pub(super) async fn test_registry() -> AgentRegistry {
    let database = crate::database::Database::connect_in_memory().await.expect("in-memory db");
    AgentRegistry::new(database)
}

pub(super) fn test_agent_record(agent_id: u32) -> red_cell_common::AgentRecord {
    red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: red_cell_common::AgentEncryptionInfo::default(),
        hostname: "WORKSTATION".to_owned(),
        username: "admin".to_owned(),
        domain_name: "DOMAIN".to_owned(),
        external_ip: "10.0.0.1".to_owned(),
        internal_ip: "192.168.1.100".to_owned(),
        process_name: "svc.exe".to_owned(),
        process_path: "C:\\svc.exe".to_owned(),
        base_address: 0,
        process_pid: 1234,
        process_tid: 0,
        process_ppid: 0,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: "Windows 10".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "0".to_owned(),
        last_call_in: "0".to_owned(),
    }
}

/// Create a WebSocket pair using a real TCP connection and axum upgrade.
pub(super) async fn ws_pair() -> (
    WebSocket,
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
) {
    use tokio::net::TcpListener;

    let (tx, rx) = tokio::sync::mpsc::channel::<WebSocket>(1);

    let app = axum::Router::new().route(
        "/ws",
        axum::routing::get(move |ws: WebSocketUpgrade| {
            let tx = tx.clone();
            async move {
                ws.on_upgrade(move |socket| async move {
                    let _ = tx.send(socket).await;
                })
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle =
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

    let url = format!("ws://127.0.0.1:{}/ws", addr.port());
    let (client, _) = tokio_tungstenite::connect_async(&url).await.expect("ws connect");

    let mut rx = rx;
    let server_socket = rx.recv().await.expect("server socket");

    server_handle.abort();
    (server_socket, client)
}

/// Helper: send a text message from the tungstenite client side of a ws_pair.
pub(super) async fn client_send(
    client: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    text: &str,
) {
    use futures_util::SinkExt as _;
    use tokio_tungstenite::tungstenite::Message as TungMsg;
    client.send(TungMsg::Text(text.into())).await.expect("client send");
}

/// Helper: read a text message from the tungstenite client side.
pub(super) async fn client_recv(
    client: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> String {
    use futures_util::StreamExt as _;
    let msg = client.next().await.expect("should receive").expect("not error");
    msg.into_text().expect("text message").to_string()
}
