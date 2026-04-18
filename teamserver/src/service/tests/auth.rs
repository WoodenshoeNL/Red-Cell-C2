use super::*;

#[tokio::test]
async fn authenticate_correct_password_succeeds() {
    let server_verifier = test_verifier("correct-pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    let register_msg = serde_json::json!({
        "Head": { "Type": "Register" },
        "Body": { "Password": "correct-pw" },
    });
    client_send(&mut client_ws, &register_msg.to_string()).await;

    let response_text = client_recv(&mut client_ws).await;
    let response: Value = serde_json::from_str(&response_text).expect("valid json");
    assert!(response["Body"]["Success"].as_bool().expect("bool"), "auth should succeed");

    let result = auth_handle.await.expect("join");
    assert!(result.is_ok(), "authenticate should return Ok");
}

#[tokio::test]
async fn authenticate_wrong_password_fails() {
    let server_verifier = test_verifier("correct-pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    let register_msg = serde_json::json!({
        "Head": { "Type": "Register" },
        "Body": { "Password": "wrong-pw" },
    });
    client_send(&mut client_ws, &register_msg.to_string()).await;

    let response_text = client_recv(&mut client_ws).await;
    let response: Value = serde_json::from_str(&response_text).expect("valid json");
    assert!(!response["Body"]["Success"].as_bool().expect("bool"), "auth should report failure");

    let result = auth_handle.await.expect("join");
    assert!(result.is_err(), "authenticate should return Err");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
        "expected AuthenticationFailed error"
    );
}

#[tokio::test]
async fn authenticate_malformed_json_fails() {
    let server_verifier = test_verifier("pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    client_send(&mut client_ws, "this is not json!!!").await;

    let result = auth_handle.await.expect("join");
    assert!(result.is_err(), "malformed JSON should fail");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::Json(_)),
        "expected Json parse error"
    );
}

#[tokio::test]
async fn authenticate_non_register_head_type_fails() {
    let server_verifier = test_verifier("pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    let message = serde_json::json!({
        "Head": { "Type": "Agent" },
        "Body": { "Password": "pw" },
    });
    client_send(&mut client_ws, &message.to_string()).await;

    let result = auth_handle.await.expect("join");
    assert!(result.is_err(), "non-Register type should fail");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
        "expected AuthenticationFailed error"
    );
}

#[tokio::test]
async fn authenticate_missing_password_field_fails() {
    let server_verifier = test_verifier("secret");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    let message = serde_json::json!({
        "Head": { "Type": "Register" },
        "Body": {},
    });
    client_send(&mut client_ws, &message.to_string()).await;

    // Missing Password defaults to empty string, which won't match "secret"
    let response_text = client_recv(&mut client_ws).await;
    let response: Value = serde_json::from_str(&response_text).expect("valid json");
    assert!(
        !response["Body"]["Success"].as_bool().expect("bool"),
        "missing password should fail auth"
    );

    let result = auth_handle.await.expect("join");
    assert!(result.is_err());
}

#[tokio::test]
async fn authenticate_empty_password_matches_empty_config() {
    let server_verifier = test_verifier("");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    let message = serde_json::json!({
        "Head": { "Type": "Register" },
        "Body": { "Password": "" },
    });
    client_send(&mut client_ws, &message.to_string()).await;

    let response_text = client_recv(&mut client_ws).await;
    let response: Value = serde_json::from_str(&response_text).expect("valid json");
    assert!(response["Body"]["Success"].as_bool().expect("bool"));

    let result = auth_handle.await.expect("join");
    assert!(result.is_ok());
}

#[tokio::test]
async fn handle_agent_output_broadcasts_callback_as_agent_response() {
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_OUTPUT,
            "AgentID": "CAFE0001",
            "Callback": { "Output": "command output here" },
        },
    });

    handle_agent_output(&message, &events).await.expect("agent output should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "CAFE0001");
            assert_eq!(msg.head.user, "service");
            assert_eq!(msg.head.event, EventCode::Session);
            // Callback was a JSON object — it should be serialized into output.
            assert!(
                msg.info.output.contains("command output here"),
                "callback content should be forwarded, got: {}",
                msg.info.output
            );
        }
        other => panic!("expected AgentResponse, got: {other:?}"),
    }
}

#[tokio::test]
async fn handle_agent_output_string_callback_forwarded_verbatim() {
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_OUTPUT,
            "AgentID": "BEEF0002",
            "Callback": "raw text output",
        },
    });

    handle_agent_output(&message, &events).await.expect("agent output should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "BEEF0002");
            assert_eq!(msg.info.output, "raw text output");
        }
        other => panic!("expected AgentResponse, got: {other:?}"),
    }
}

#[tokio::test]
async fn handle_agent_output_missing_body_returns_error() {
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
    });

    let err = handle_agent_output(&message, &events).await.expect_err("should fail without Body");
    assert!(matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Body")));
}

#[tokio::test]
async fn handle_agent_output_missing_agent_id_uses_unknown() {
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_OUTPUT,
        },
    });

    handle_agent_output(&message, &events).await.expect("should succeed with defaults");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "unknown");
            assert!(msg.info.output.is_empty(), "no callback means empty output");
        }
        other => panic!("expected AgentResponse, got: {other:?}"),
    }
}

#[tokio::test]
async fn handle_agent_message_dispatches_agent_register() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let registry = test_registry().await;

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "AgentID": "FF001122",
                "MagicValue": "DEADBEEF",
            },
            "RegisterInfo": {
                "Hostname": "DISPATCH-TEST",
                "Username": "user1",
            },
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect("dispatch to AgentRegister should succeed");

    let agent = registry.get(0xFF00_1122).await.expect("agent should be registered");
    assert_eq!(agent.hostname, "DISPATCH-TEST");

    let event = rx.recv().await.expect("event should be broadcast");
    assert!(matches!(event, OperatorMessage::AgentNew(_)));
}

#[tokio::test]
async fn handle_agent_message_dispatches_agent_response() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let registry = test_registry().await;

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_RESPONSE,
            "Agent": { "NameID": "DISPATCH01" },
            "Response": "dGVzdA==",
            "RandID": "dispatch-rand",
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect("dispatch to AgentResponse should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "DISPATCH01");
            assert_eq!(msg.info.command_id, "dispatch-rand");
        }
        other => panic!("expected AgentResponse, got: {other:?}"),
    }
}

#[tokio::test]
async fn handle_agent_message_dispatches_agent_output() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let registry = test_registry().await;

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_OUTPUT,
            "AgentID": "OUTPUT01",
            "Callback": { "Output": "hello" },
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect("dispatch to AgentOutput should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "OUTPUT01");
            assert!(msg.info.output.contains("hello"));
        }
        other => panic!("expected AgentResponse, got: {other:?}"),
    }
}

#[tokio::test]
async fn handle_agent_message_unknown_body_type_returns_ok() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let registry = test_registry().await;

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": "SomethingCompletelyUnknown",
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    let result =
        handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws).await;
    assert!(result.is_ok(), "unknown agent body type should be silently ignored");
}

#[tokio::test]
async fn authenticate_rate_limits_after_max_failures() {
    let server_verifier = test_verifier("correct-pw");
    let rate_limiter = LoginRateLimiter::new();
    let ip: IpAddr = "10.0.0.99".parse().expect("valid IP");

    // Exhaust the rate limiter for this IP (5 failures).
    for _ in 0..5 {
        rate_limiter.record_failure(ip).await;
    }

    // The next attempt should be rate-limited without even reading a message.
    let (mut server_ws, _client_ws) = ws_pair().await;
    let result = authenticate(&mut server_ws, &server_verifier, &rate_limiter, ip).await;
    assert!(result.is_err(), "should be rate limited");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::RateLimited),
        "expected RateLimited error"
    );
}

#[tokio::test]
async fn authenticate_allows_different_ip_when_one_is_limited() {
    let server_verifier = test_verifier("correct-pw");
    let rate_limiter = LoginRateLimiter::new();
    let blocked_ip: IpAddr = "10.0.0.100".parse().expect("valid IP");
    let allowed_ip: IpAddr = "10.0.0.101".parse().expect("valid IP");

    // Exhaust the rate limiter for blocked_ip.
    for _ in 0..5 {
        rate_limiter.record_failure(blocked_ip).await;
    }

    // blocked_ip should be rejected.
    let (mut server_ws, _client_ws) = ws_pair().await;
    let result = authenticate(&mut server_ws, &server_verifier, &rate_limiter, blocked_ip).await;
    assert!(matches!(result.expect_err("expected Err"), ServiceBridgeError::RateLimited));

    // allowed_ip should still work (correct password).
    let (mut server_ws2, mut client_ws2) = ws_pair().await;
    let rl = rate_limiter.clone();
    let hash = server_verifier.clone();
    let auth_handle =
        tokio::spawn(async move { authenticate(&mut server_ws2, &hash, &rl, allowed_ip).await });

    let msg = serde_json::json!({
        "Head": { "Type": "Register" },
        "Body": { "Password": "correct-pw" },
    });
    client_send(&mut client_ws2, &msg.to_string()).await;
    let _ = client_recv(&mut client_ws2).await;

    let result = auth_handle.await.expect("join");
    assert!(result.is_ok(), "unblocked IP should authenticate successfully");
}

#[tokio::test]
async fn authenticate_times_out_when_no_frame_sent() {
    let server_verifier = test_verifier("correct-pw");
    let rate_limiter = LoginRateLimiter::new();
    let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");

    let (mut server_ws, _client_ws) = ws_pair().await;

    // Hold `_client_ws` open but never send anything — the server side
    // should time out after SERVICE_AUTH_FRAME_TIMEOUT.
    let start = tokio::time::Instant::now();
    let result = authenticate(&mut server_ws, &server_verifier, &rate_limiter, ip).await;
    let elapsed = start.elapsed();

    assert!(
        matches!(result, Err(ServiceBridgeError::AuthenticationTimeout)),
        "expected AuthenticationTimeout, got {result:?}"
    );
    // Should complete within a reasonable margin of the timeout.
    assert!(
        elapsed < SERVICE_AUTH_FRAME_TIMEOUT + Duration::from_secs(2),
        "took too long: {elapsed:?}"
    );
}

#[tokio::test]
async fn authenticate_binary_frame_returns_auth_failed() {
    let server_verifier = test_verifier("pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    // Send a binary frame instead of a text frame.
    {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::Message as TungMsg;
        client_ws
            .send(TungMsg::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF].into()))
            .await
            .expect("client send binary");
    }

    let result = auth_handle.await.expect("join");
    assert!(result.is_err(), "binary frame should fail auth");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
        "expected AuthenticationFailed for binary frame"
    );
}

#[tokio::test]
async fn authenticate_close_frame_returns_auth_failed() {
    let server_verifier = test_verifier("pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    // Send a close frame instead of a text frame.
    {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::Message as TungMsg;
        client_ws.send(TungMsg::Close(None)).await.expect("client send close");
    }

    let result = auth_handle.await.expect("join");
    assert!(result.is_err(), "close frame should fail auth");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
        "expected AuthenticationFailed for close frame"
    );
}
