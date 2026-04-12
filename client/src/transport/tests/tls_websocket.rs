use super::super::operator_msg::{
    flat_info_string, loot_item_from_flat_info, loot_item_from_response, normalize_agent_id,
    sanitize_text,
};
use super::super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::super::ClientWebSocket;
use base64::Engine as _;
use futures_util::SinkExt;
use futures_util::StreamExt;
use red_cell_common::OperatorInfo;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentInfo as OperatorAgentInfo, AgentPivotsInfo, AgentResponseInfo, AgentUpdateInfo,
    BuildPayloadMessageInfo, BuildPayloadResponseInfo, ChatCode, EventCode, FlatInfo,
    InitConnectionCode, ListenerCode, ListenerErrorInfo, ListenerInfo, ListenerMarkInfo, LoginInfo,
    Message, MessageHead, MessageInfo, NameInfo, SessionCode, TeamserverLogInfo,
};
use red_cell_common::tls::{TlsKeyAlgorithm, generate_self_signed_tls_identity};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::protocol::Message as WebSocketMessage;
use tokio_tungstenite::{accept_async, tungstenite::Message as TungsteniteMessage};
async fn spawn_tls_echo_server(
    identity: &red_cell_common::tls::TlsIdentity,
) -> std::net::SocketAddr {
    let tls_acceptor = identity.tls_acceptor().expect("tls acceptor should build");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
    let address = listener.local_addr().expect("listener should have local address");

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("client should connect");
        let tls_stream = tls_acceptor.accept(stream).await.expect("tls handshake should succeed");
        let mut websocket =
            accept_async(tls_stream).await.expect("websocket upgrade should succeed");
        let payload = serde_json::to_string(&OperatorMessage::TeamserverLog(Message {
            head: MessageHead {
                event: EventCode::Teamserver,
                user: "teamserver".to_owned(),
                timestamp: "10/03/2026 12:00:00".to_owned(),
                one_time: String::new(),
            },
            info: TeamserverLogInfo { text: "hello".to_owned() },
        }))
        .expect("message should serialize");
        websocket
            .send(TungsteniteMessage::Text(payload.into()))
            .await
            .expect("server should send log event");
    });

    address
}

async fn assert_websocket_receives_log(mut socket: ClientWebSocket) {
    let frame =
        socket.next().await.expect("server frame should arrive").expect("frame should be valid");

    match frame {
        WebSocketMessage::Text(payload) => {
            let message: OperatorMessage =
                serde_json::from_str(&payload).expect("payload should deserialize");
            assert!(matches!(message, OperatorMessage::TeamserverLog(_)));
        }
        other => panic!("unexpected websocket frame: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dangerous_skip_verify_accepts_self_signed_certificates() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["127.0.0.1".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");
    let address = spawn_tls_echo_server(&identity).await;

    let sink = Arc::new(std::sync::Mutex::new(None));
    let socket = connect_websocket(
        &format!("wss://{address}/havoc/"),
        &TlsVerification::DangerousSkipVerify,
        &sink,
    )
    .await
    .expect("client should accept self-signed cert with skip-verify");
    assert_websocket_receives_log(socket).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fingerprint_verification_accepts_matching_certificate() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["127.0.0.1".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let cert_der = {
        let mut reader = std::io::BufReader::new(identity.certificate_pem());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("cert PEM should parse");
        certs.into_iter().next().expect("should have one cert")
    };
    let fingerprint = certificate_fingerprint(cert_der.as_ref());
    let address = spawn_tls_echo_server(&identity).await;

    let sink = Arc::new(std::sync::Mutex::new(None));
    let socket = connect_websocket(
        &format!("wss://{address}/havoc/"),
        &TlsVerification::Fingerprint(fingerprint),
        &sink,
    )
    .await
    .expect("client should accept cert with matching fingerprint");
    assert_websocket_receives_log(socket).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fingerprint_verification_rejects_mismatched_certificate() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["127.0.0.1".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");
    let address = spawn_tls_echo_server(&identity).await;

    let wrong_fingerprint = "00".repeat(32);
    let sink = Arc::new(std::sync::Mutex::new(None));
    let result = connect_websocket(
        &format!("wss://{address}/havoc/"),
        &TlsVerification::Fingerprint(wrong_fingerprint),
        &sink,
    )
    .await;

    assert!(result.is_err(), "mismatched fingerprint should be rejected");
    assert!(
        sink.lock().unwrap().is_some(),
        "fingerprint sink should be populated even on mismatch"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_ca_verification_accepts_certificate_signed_by_ca() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["127.0.0.1".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let ca_dir = tempfile::tempdir().expect("tempdir should be created");
    let ca_path = ca_dir.path().join("ca.pem");
    std::fs::write(&ca_path, identity.certificate_pem()).expect("CA cert should be written");

    let address = spawn_tls_echo_server(&identity).await;

    let sink = Arc::new(std::sync::Mutex::new(None));
    let socket = connect_websocket(
        &format!("wss://{address}/havoc/"),
        &TlsVerification::CustomCa(ca_path),
        &sink,
    )
    .await
    .expect("client should accept cert signed by custom CA");
    assert_websocket_receives_log(socket).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ca_verification_rejects_self_signed_certificate() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["127.0.0.1".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");
    let address = spawn_tls_echo_server(&identity).await;

    let sink = Arc::new(std::sync::Mutex::new(None));
    let result = connect_websocket(
        &format!("wss://{address}/havoc/"),
        &TlsVerification::CertificateAuthority,
        &sink,
    )
    .await;

    assert!(result.is_err(), "self-signed cert should be rejected by default CA verification");
    assert!(
        sink.lock().unwrap().is_some(),
        "fingerprint sink should be populated even when CA verification fails"
    );
}

#[test]
fn certificate_fingerprint_produces_hex_sha256() {
    let identity =
        generate_self_signed_tls_identity(&["test.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let cert_der = {
        let mut reader = std::io::BufReader::new(identity.certificate_pem());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("cert PEM should parse");
        certs.into_iter().next().expect("should have one cert")
    };

    let fingerprint = certificate_fingerprint(cert_der.as_ref());
    assert_eq!(fingerprint.len(), 64, "SHA-256 hex should be 64 chars");
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()), "fingerprint should be hex-only");
}
