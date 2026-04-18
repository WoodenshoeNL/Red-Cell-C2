//! Operator authentication rejection and malformed message tests.

use futures_util::StreamExt;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{EventCode, Message, MessageHead, OperatorMessage};
use tokio::time::{Duration, timeout};
use tokio_tungstenite::connect_async;

use super::common;
use super::helpers::{operator_task_message, spawn_server_with_http_listener};

/// An unauthenticated WebSocket client must not be able to inject tasks for a
/// live agent.  The server should reject the pre-auth `AgentTask` message and
/// the agent's subsequent `COMMAND_GET_JOB` poll must return no queued jobs.
#[tokio::test]
async fn unauthenticated_operator_cannot_inject_agent_task()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = spawn_server_with_http_listener("edge-http-unauth-inject").await?;
    let listener_port = harness.listener_port;

    // --- Register a live agent via the Demon init handshake -----------------------
    let agent_id = 0x1234_5678;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
        0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
        0xD8, 0xD9,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB9, 0xCC, 0xDF, 0xF2, 0x05, 0x18, 0x2B, 0x3E, 0x51, 0x64, 0x77, 0x8A, 0x9D, 0xB0, 0xC3,
        0xD6,
    ];
    let ctr_offset = 0_u64;

    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.

    // --- Open a second (unauthenticated) WebSocket client -------------------------
    let (raw_unauth_socket_, _) = connect_async(harness.server.ws_url()).await?;
    let mut unauth_socket = common::WsSession::new(raw_unauth_socket_);

    // Send an AgentTask as the very first frame — no login attempt at all.
    let task =
        operator_task_message("FF", "shell whoami", "12345678", DemonCommand::CommandCheckin)?;
    unauth_socket.send_text(task).await?;

    // The server must reject the non-login message during the auth phase.
    // It responds with `InitConnectionError` and closes the connection.
    let rejection = common::read_operator_message(&mut unauth_socket).await?;
    assert!(
        matches!(rejection, OperatorMessage::InitConnectionError(_)),
        "expected InitConnectionError for unauthenticated AgentTask, got {rejection:?}"
    );

    // --- Agent polls for jobs — must receive nothing ------------------------------
    let get_job_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = get_job_response.bytes().await?;
    assert!(
        job_bytes.is_empty(),
        "agent must receive no jobs after unauthenticated task injection attempt, got {} bytes",
        job_bytes.len()
    );

    // Clean up: close the unauthenticated socket (may already be closed by the
    // server — ignore errors).
    let _ = unauth_socket.close(None).await;

    harness.shutdown().await?;
    Ok(())
}

/// A WebSocket client that fails authentication (wrong password) must not be
/// able to queue agent tasks either.
#[tokio::test]
async fn failed_login_operator_cannot_inject_agent_task() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = spawn_server_with_http_listener("edge-http-badcred-inject").await?;
    let listener_port = harness.listener_port;

    // --- Register a live agent ----------------------------------------------------
    let agent_id = 0x1234_5678;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
        0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC,
        0xFD, 0xFE,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xEE, 0x01, 0x14, 0x27, 0x3A, 0x4D, 0x60, 0x73, 0x86, 0x99, 0xAC, 0xBF, 0xD2, 0xE5, 0xF8,
        0x0B,
    ];
    let ctr_offset = 0_u64;

    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.

    // --- Attempt login with wrong password ----------------------------------------
    let (raw_bad_socket_, _) = connect_async(harness.server.ws_url()).await?;
    let mut bad_socket = common::WsSession::new(raw_bad_socket_);
    let login_payload = serde_json::to_string(&OperatorMessage::Login(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: red_cell_common::operator::LoginInfo {
            user: "operator".to_owned(),
            password: red_cell_common::crypto::hash_password_sha3("wrong_password"),
        },
    }))?;
    bad_socket.send_text(login_payload).await?;

    // Server responds with InitConnectionError for bad credentials.
    let rejection = common::read_operator_message(&mut bad_socket).await?;
    assert!(
        matches!(rejection, OperatorMessage::InitConnectionError(_)),
        "expected InitConnectionError for wrong password, got {rejection:?}"
    );

    // --- Agent polls — must receive no jobs ---------------------------------------
    let get_job_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = get_job_response.bytes().await?;
    assert!(
        job_bytes.is_empty(),
        "agent must receive no jobs after failed-auth task injection attempt, got {} bytes",
        job_bytes.len()
    );

    let _ = bad_socket.close(None).await;
    harness.shutdown().await?;
    Ok(())
}

/// Verify that a malformed (non-JSON) operator WebSocket message closes the
/// offending connection but does not break task dispatch for other operators.
///
/// Regression test: ensures the server-side message loop gracefully handles
/// parse errors instead of panicking or poisoning shared state.
#[tokio::test]
async fn malformed_operator_message_closes_connection_without_breaking_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-malformed").await?;
    let listener_port = harness.listener_port;

    // Register a Demon agent so we can verify task dispatch still works.
    let agent_id = 0x1234_5678;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];

    harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;

    // Consume the AgentNew event on the first operator socket.
    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    // Open a second operator connection for the "bad" client.
    let (raw_bad_socket_, _) = connect_async(harness.server.ws_url()).await?;
    let mut bad_socket = common::WsSession::new(raw_bad_socket_);
    common::login(&mut bad_socket).await?;

    // The second socket receives snapshot events (listeners, agents, etc.).
    // Drain until we see the AgentNew entry so the socket is ready for our test.
    let mut saw_agent_new = false;
    for _ in 0..10 {
        let event = common::read_operator_message(&mut bad_socket).await?;
        if matches!(event, OperatorMessage::AgentNew(_)) {
            saw_agent_new = true;
            break;
        }
    }
    assert!(saw_agent_new, "expected AgentNew in snapshot on second socket");

    // --- Send malformed (non-JSON) message on the bad socket ---
    bad_socket.send_text("not valid json").await?;

    // The server should close the bad connection.
    let close_frame = timeout(Duration::from_secs(10), bad_socket.socket.next()).await?;
    assert!(
        close_frame
            .as_ref()
            .map(|r| r.as_ref().map(|m| m.is_close()).unwrap_or(false))
            .unwrap_or(true),
        "expected close frame on bad socket after malformed message, got {close_frame:?}"
    );

    // --- Verify the good operator connection still works ---
    // Submit a valid agent task on the original (good) socket.
    let task = operator_task_message("AA", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send_text(task).await?;

    // We should receive the task echo, proving the dispatch loop is alive.
    let task_echo = common::read_operator_message(&mut harness.socket).await?;
    let OperatorMessage::AgentTask(message) = task_echo else {
        panic!("expected AgentTask echo on good socket, got {task_echo:?}");
    };
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.task_id, "AA");

    // Confirm the job is actually enqueued — agent can retrieve it.
    let get_job_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            0,
            u32::from(DemonCommand::CommandGetJob),
            7,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = get_job_response.bytes().await?;
    let jobs = red_cell_common::demon::DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert!(
        !jobs.packages.is_empty(),
        "agent should have at least one job enqueued after malformed message on other socket"
    );
    assert_eq!(jobs.packages[0].command_id, u32::from(DemonCommand::CommandCheckin));

    harness.shutdown().await?;
    Ok(())
}
