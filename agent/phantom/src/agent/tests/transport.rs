use std::error::Error;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use red_cell_common::crypto::{
    ctr_blocks_for_len, decrypt_agent_data_at_offset, encrypt_agent_data,
    encrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonMessage, DemonPackage};

use super::super::PhantomAgent;
use super::{read_http_request, write_http_response};
use crate::command::PendingCallback;
use crate::config::PhantomConfig;
use crate::ecdh::EcdhSession;
use crate::error::PhantomError;
use crate::protocol::callback_ctr_blocks;

#[tokio::test]
async fn init_handshake_accepts_valid_acknowledgement() -> Result<(), Box<dyn Error + Send + Sync>>
{
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let (request_tx, request_rx) = mpsc::channel::<Vec<u8>>();
    let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

    let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        let (mut stream, _) = listener.accept()?;
        let request = read_http_request(&mut stream)?;
        request_tx.send(request)?;

        let body = response_rx.recv()?;
        write_http_response(&mut stream, &body)?;
        Ok(())
    });

    let config = PhantomConfig {
        callback_url: format!("http://{address}/"),
        sleep_delay_ms: 0,
        ..PhantomConfig::default()
    };
    let mut agent = PhantomAgent::new(config)?;
    let ack = encrypt_agent_data(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        &agent.agent_id.to_le_bytes(),
    )?;
    response_tx.send(ack)?;

    agent.init_handshake().await?;

    let init_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
    assert!(!init_packet.is_empty());
    assert_eq!(agent.ctr_offset, 1);

    let server_result = server.join().map_err(|_| "server thread panicked")?;
    server_result?;

    Ok(())
}

#[tokio::test]
async fn get_job_returns_empty_when_server_sends_nothing()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

    let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        let (mut stream, _) = listener.accept()?;
        let _request = read_http_request(&mut stream)?;
        let body = response_rx.recv()?;
        write_http_response(&mut stream, &body)?;
        Ok(())
    });

    let config = PhantomConfig {
        callback_url: format!("http://{address}/"),
        sleep_delay_ms: 0,
        ..PhantomConfig::default()
    };
    let mut agent = PhantomAgent::new(config)?;
    agent.ctr_offset = 5;
    let offset_before = agent.ctr_offset;

    response_tx.send(Vec::new())?;

    let packages = agent.get_job().await?;
    assert!(packages.is_empty());
    // CTR must advance by callback_ctr_blocks for the sent packet only.
    assert_eq!(
        agent.ctr_offset,
        offset_before + callback_ctr_blocks(u32::from(DemonCommand::CommandGetJob), 0)
    );

    server.join().map_err(|_| "server thread panicked")??;
    Ok(())
}

/// red-cell-c2-1fhji — get_job with connection-refused must NOT advance CTR/seq.
/// The server never received the packet, so its state is unchanged.
#[tokio::test]
async fn get_job_connection_refused_does_not_advance_ctr()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let mut config = PhantomConfig::default();
    // Port 1 has no listener — OS returns ECONNREFUSED immediately.
    config.callback_url = "http://127.0.0.1:1/".to_string();
    let mut agent = PhantomAgent::new(config)?;
    agent.ctr_offset = 11;
    agent.callback_seq = 9;
    let err = agent.get_job().await.expect_err("closed port must fail TCP connect");
    assert!(
        matches!(err, PhantomError::PreConnectFailure(_)),
        "connection-refused must surface as PreConnectFailure, got {err:?}"
    );
    // CTR and seq must NOT advance — server never received the packet.
    assert_eq!(agent.ctr_offset, 11, "CTR must not advance on connection-refused");
    assert_eq!(agent.callback_seq, 9, "seq must not advance on connection-refused");
    Ok(())
}

/// red-cell-c2-0xpyf — get_job with TCP-reset must advance CTR/seq unconditionally.
/// The teamserver consumed and decrypted the packet before resetting the connection,
/// so we MUST advance to stay aligned with the server's keystream.
#[tokio::test]
async fn get_job_tcp_reset_advances_ctr_and_seq() -> Result<(), Box<dyn Error + Send + Sync>> {
    use red_cell_common::agent_protocol::callback_ctr_blocks;
    use red_cell_common::crypto::encrypt_agent_data;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

    // init succeeds; get_job connection is accepted then immediately dropped (TCP-reset).
    let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        let (mut stream, _) = listener.accept()?;
        let _body = read_http_request(&mut stream)?;
        write_http_response(&mut stream, &response_rx.recv()?)?;
        // get_job — accept and immediately drop; agent sees connection-reset.
        let _ = listener.accept()?;
        Ok(())
    });

    let mut agent = PhantomAgent::new(PhantomConfig {
        callback_url: format!("http://{address}/"),
        sleep_delay_ms: 0,
        ..PhantomConfig::default()
    })?;
    response_tx.send(encrypt_agent_data(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        &agent.agent_id.to_le_bytes(),
    )?)?;
    agent.init_handshake().await?;
    assert_eq!(agent.ctr_offset, 1);
    let ctr_before = agent.ctr_offset;
    let seq_before = agent.callback_seq;

    let err = agent.get_job().await.expect_err("TCP-reset must fail");
    assert!(
        matches!(err, PhantomError::Transport(_)),
        "TCP-reset must surface as Transport, got {err:?}"
    );
    let expected_ctr = ctr_before + callback_ctr_blocks(u32::from(DemonCommand::CommandGetJob), 0);
    assert_eq!(agent.ctr_offset, expected_ctr, "CTR must advance on TCP-reset");
    assert_eq!(agent.callback_seq, seq_before + 1, "seq must advance on TCP-reset");

    server.join().map_err(|_| "server thread panicked")??;
    Ok(())
}

#[tokio::test]
async fn ecdh_flush_pending_callbacks_requeues_on_transport_error_returns_ok()
-> Result<(), Box<dyn Error + Send + Sync>> {
    use red_cell_common::crypto::ecdh::ConnectionId;
    let mut config = PhantomConfig::default();
    config.callback_url = "http://127.0.0.1:1/".to_string();
    let mut agent = PhantomAgent::new(config)?;
    agent.ecdh_session = Some(EcdhSession {
        connection_id: ConnectionId::generate()?,
        session_key: [7u8; 32],
        agent_id: agent.agent_id,
    });
    agent
        .state
        .queue_callback(PendingCallback::Output { request_id: 42, text: "pending flush".into() });

    let result = agent.flush_pending_callbacks().await;
    assert!(result.is_ok(), "transport failure should be recoverable; flush returns Ok");

    let pending = agent.state.drain_callbacks();
    assert_eq!(pending.len(), 1);
    assert!(matches!(
        &pending[0],
        PendingCallback::Output { request_id: 42, text } if text == "pending flush"
    ));
    Ok(())
}

/// red-cell-c2-1fhji — flush_pending_callbacks must NOT advance CTR/seq when connection is
/// refused (ECONNREFUSED): the server never received the packet so its state is unchanged.
/// Advancing here would permanently desync the CTR on every retry cycle.
#[tokio::test]
async fn flush_pending_callbacks_connection_refused_does_not_advance_ctr_and_requeues()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let mut config = PhantomConfig::default();
    // Port 1 has no listener — OS returns ECONNREFUSED immediately.
    config.callback_url = "http://127.0.0.1:1/".to_string();
    let mut agent = PhantomAgent::new(config)?;
    // No ECDH session — exercises the non-ECDH path.
    assert!(agent.ecdh_session.is_none());
    agent.ctr_offset = 7;
    agent.callback_seq = 3;
    agent
        .state
        .queue_callback(PendingCallback::Output { request_id: 11, text: "lost output".into() });

    let ctr_before = agent.ctr_offset;
    let seq_before = agent.callback_seq;
    let result = agent.flush_pending_callbacks().await;
    assert!(result.is_err(), "non-ECDH flush must propagate connection-refused error");

    // CTR and seq must NOT advance — the server never processed the packet.
    assert_eq!(
        agent.ctr_offset, ctr_before,
        "CTR must not advance on connection-refused (server state unchanged)"
    );
    assert_eq!(
        agent.callback_seq, seq_before,
        "seq must not advance on connection-refused (server state unchanged)"
    );

    // Callback must be requeued so the next cycle can retry.
    let pending = agent.state.drain_callbacks();
    assert_eq!(pending.len(), 1, "failed callback must be requeued");
    assert!(matches!(
        &pending[0],
        PendingCallback::Output { request_id: 11, text } if text == "lost output"
    ));
    Ok(())
}

/// red-cell-c2-n4kr4 — flush_pending_callbacks must advance CTR/seq on TCP-reset (server
/// received and processed the packet before the response was lost).
#[tokio::test]
async fn flush_pending_callbacks_tcp_reset_advances_ctr_and_requeues()
-> Result<(), Box<dyn Error + Send + Sync>> {
    use red_cell_common::crypto::encrypt_agent_data;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

    // init succeeds; callback connection is accepted then immediately dropped (TCP-reset).
    let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        // init
        let (mut stream, _) = listener.accept()?;
        let _body = read_http_request(&mut stream)?;
        write_http_response(&mut stream, &response_rx.recv()?)?;
        // callback — accept and immediately drop; agent sees connection-reset.
        let _ = listener.accept()?;
        Ok(())
    });

    let config = PhantomConfig {
        callback_url: format!("http://{address}/"),
        sleep_delay_ms: 0,
        ..PhantomConfig::default()
    };
    let mut agent = PhantomAgent::new(config)?;
    response_tx.send(encrypt_agent_data(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        &agent.agent_id.to_le_bytes(),
    )?)?;
    agent.init_handshake().await?;
    // ctr_offset = 1 after init ack.
    assert_eq!(agent.ctr_offset, 1);

    agent.state.queue_callback(PendingCallback::Output {
        request_id: 42,
        text: "tcp-reset output".into(),
    });
    let ctr_before = agent.ctr_offset;
    let seq_before = agent.callback_seq;

    let result = agent.flush_pending_callbacks().await;
    assert!(result.is_err(), "flush must propagate TCP-reset error");

    // CTR and seq MUST advance: server processed the packet before resetting.
    assert!(
        agent.ctr_offset > ctr_before,
        "CTR must advance on TCP-reset (server already consumed the packet)"
    );
    assert_eq!(
        agent.callback_seq,
        seq_before + 1,
        "seq must advance on TCP-reset (server already consumed the packet)"
    );

    // Callback must be requeued.
    let pending = agent.state.drain_callbacks();
    assert_eq!(pending.len(), 1, "failed callback must be requeued");

    server.join().map_err(|_| "server thread panicked")??;
    Ok(())
}

/// red-cell-c2-n4kr4 — COMMAND_CHECKIN send failure in checkin() must advance CTR/seq
/// unconditionally so the next retry uses the aligned keystream offset.
#[tokio::test]
async fn checkin_transport_failure_on_checkin_packet_advances_ctr()
-> Result<(), Box<dyn Error + Send + Sync>> {
    use red_cell_common::crypto::encrypt_agent_data;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

    // init handshake succeeds; COMMAND_CHECKIN connection is accepted then immediately dropped.
    let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        // init
        let (mut stream, _) = listener.accept()?;
        let _body = read_http_request(&mut stream)?;
        write_http_response(&mut stream, &response_rx.recv()?)?;
        // checkin — accept and immediately drop; agent sees connection-reset.
        let _ = listener.accept()?;
        Ok(())
    });

    let config = PhantomConfig {
        callback_url: format!("http://{address}/"),
        sleep_delay_ms: 0,
        ..PhantomConfig::default()
    };
    let mut agent = PhantomAgent::new(config)?;
    response_tx.send(encrypt_agent_data(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        &agent.agent_id.to_le_bytes(),
    )?)?;
    agent.init_handshake().await?;
    // ctr_offset = 1 after init ack.
    assert_eq!(agent.ctr_offset, 1);
    let before_seq = agent.callback_seq;

    let result = agent.checkin().await;
    assert!(result.is_err(), "checkin must propagate transport error");

    // CTR must have advanced by exactly the COMMAND_CHECKIN cost.
    let expected_ctr = 1 + callback_ctr_blocks(u32::from(DemonCommand::CommandCheckin), 0);
    assert_eq!(
        agent.ctr_offset, expected_ctr,
        "CTR must advance even when COMMAND_CHECKIN response is lost"
    );
    assert_eq!(
        agent.callback_seq,
        before_seq + 1,
        "seq must advance even when COMMAND_CHECKIN response is lost"
    );

    server.join().map_err(|_| "server thread panicked")??;
    Ok(())
}

/// red-cell-c2-1fhji — COMMAND_CHECKIN with connection-refused must NOT advance CTR/seq.
/// The server never received the packet, so its state is unchanged.  Advancing here
/// permanently desynchs the keystream on every retry cycle.
#[tokio::test]
async fn checkin_connection_refused_does_not_advance_ctr()
-> Result<(), Box<dyn Error + Send + Sync>> {
    use red_cell_common::crypto::encrypt_agent_data;
    // Bind and immediately release a port so we get a guaranteed connection-refused target.
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let refused_addr = listener.local_addr()?;
    drop(listener);

    // Use a live server for init, then redirect to the refused port before checkin.
    let init_listener = TcpListener::bind(("127.0.0.1", 0))?;
    let init_addr = init_listener.local_addr()?;
    let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

    let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        let (mut stream, _) = init_listener.accept()?;
        let _body = read_http_request(&mut stream)?;
        write_http_response(&mut stream, &response_rx.recv()?)?;
        Ok(())
    });

    let mut agent = PhantomAgent::new(PhantomConfig {
        callback_url: format!("http://{init_addr}/"),
        sleep_delay_ms: 0,
        ..PhantomConfig::default()
    })?;
    response_tx.send(encrypt_agent_data(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        &agent.agent_id.to_le_bytes(),
    )?)?;
    agent.init_handshake().await?;
    assert_eq!(agent.ctr_offset, 1);

    // Redirect to the refused port — checkin will get ECONNREFUSED.
    agent.transport = crate::transport::HttpTransport::new(&PhantomConfig {
        callback_url: format!("http://{refused_addr}/"),
        ..PhantomConfig::default()
    })?;

    let ctr_before = agent.ctr_offset;
    let seq_before = agent.callback_seq;

    let result = agent.checkin().await;
    assert!(result.is_err(), "checkin must propagate connection-refused error");

    // CTR and seq must NOT advance on connection-refused.
    assert_eq!(
        agent.ctr_offset, ctr_before,
        "CTR must not advance on connection-refused (server state unchanged)"
    );
    assert_eq!(
        agent.callback_seq, seq_before,
        "seq must not advance on connection-refused (server state unchanged)"
    );

    server.join().map_err(|_| "server thread panicked")??;
    Ok(())
}

#[tokio::test]
async fn get_job_decrypts_returned_task_packages() -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

    let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        let (mut stream, _) = listener.accept()?;
        let _request = read_http_request(&mut stream)?;
        let body = response_rx.recv()?;
        write_http_response(&mut stream, &body)?;
        Ok(())
    });

    let config = PhantomConfig {
        callback_url: format!("http://{address}/"),
        sleep_delay_ms: 0,
        ..PhantomConfig::default()
    };
    let mut agent = PhantomAgent::new(config)?;
    // Simulate ctr_offset after init+checkin.
    agent.ctr_offset = 3;
    let get_job_send_offset = agent.ctr_offset; // 3
    let after_send =
        get_job_send_offset + callback_ctr_blocks(u32::from(DemonCommand::CommandGetJob), 0); // 4

    // Server encrypts the task payload at 'after_send'.
    let plain_payload = 42_i32.to_le_bytes().to_vec();
    let enc_payload = encrypt_agent_data_at_offset(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        after_send,
        &plain_payload,
    )?;
    let task = DemonPackage {
        command_id: u32::from(DemonCommand::CommandExit),
        request_id: 99,
        payload: enc_payload.clone(),
    };
    let get_job_response = DemonMessage::new(vec![task]).to_bytes()?;
    response_tx.send(get_job_response)?;

    let packages = agent.get_job().await?;
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandExit));
    assert_eq!(packages[0].request_id, 99);
    assert_eq!(packages[0].payload, plain_payload);
    // CTR must have advanced: 1 block for send + 1 block for 4-byte payload.
    assert_eq!(agent.ctr_offset, after_send + ctr_blocks_for_len(enc_payload.len()));

    server.join().map_err(|_| "server thread panicked")??;
    Ok(())
}

#[tokio::test]
async fn checkin_processes_exit_task() -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let (request_tx, request_rx) = mpsc::channel::<Vec<u8>>();
    let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

    // Four connections: init, checkin (empty), get_job (task), exit callback.
    let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            request_tx.send(request)?;
            let body = response_rx.recv()?;
            write_http_response(&mut stream, &body)?;
        }
        Ok(())
    });

    let config = PhantomConfig {
        callback_url: format!("http://{address}/"),
        sleep_delay_ms: 0,
        ..PhantomConfig::default()
    };
    let mut agent = PhantomAgent::new(config)?;

    response_tx.send(encrypt_agent_data(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        &agent.agent_id.to_le_bytes(),
    )?)?;
    agent.init_handshake().await?;

    let init_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
    assert!(!init_packet.is_empty());

    // After init_handshake, ctr_offset == 1.  The agent will:
    //   1. encrypt checkin at ctr_offset=1, advance by callback_ctr_blocks(CommandCheckin, 0)   → offset=2
    //   2. encrypt get_job at ctr_offset=2, advance by callback_ctr_blocks(CommandGetJob, 0)   → offset=3
    //   3. decrypt task payload at offset=3, advance by ctr_blocks_for_len(4)   → offset=4
    //   4. encrypt exit callback at ctr_offset=4, advance by callback_ctr_blocks(CommandExit, 4) → offset=5
    let checkin_encrypt_offset = agent.ctr_offset; // 1
    let after_checkin_send =
        checkin_encrypt_offset + callback_ctr_blocks(u32::from(DemonCommand::CommandCheckin), 0); // 2
    let after_get_job_send =
        after_checkin_send + callback_ctr_blocks(u32::from(DemonCommand::CommandGetJob), 0); // 3
    let task_payload = 9_i32.to_le_bytes().to_vec();
    let encrypted_task_payload = encrypt_agent_data_at_offset(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        after_get_job_send,
        &task_payload,
    )?;
    let after_task_decrypt = after_get_job_send + ctr_blocks_for_len(encrypted_task_payload.len()); // 4

    // Build the raw DemonMessage returned by handle_get_job: each package
    // payload is individually encrypted; no outer DemonEnvelope.
    let task = DemonPackage {
        command_id: u32::from(DemonCommand::CommandExit),
        request_id: 7,
        payload: encrypted_task_payload,
    };
    let get_job_response = DemonMessage::new(vec![task]).to_bytes()?;

    // checkin → empty; get_job → task; exit callback → empty
    response_tx.send(Vec::new())?;
    response_tx.send(get_job_response)?;
    response_tx.send(Vec::new())?;

    let exit_requested = agent.checkin().await?;
    assert!(exit_requested);

    let checkin_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
    let envelope = DemonEnvelope::from_bytes(&checkin_packet)?;
    // command_id and request_id are in the clear.
    assert_eq!(&envelope.payload[..4], &u32::from(DemonCommand::CommandCheckin).to_be_bytes());
    assert_eq!(&envelope.payload[4..8], &0_u32.to_be_bytes());
    // Remaining bytes are encrypted: seq_num(8 LE) + payload_len(4) only (empty checkin payload).
    let decrypted = decrypt_agent_data_at_offset(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        checkin_encrypt_offset,
        &envelope.payload[8..],
    )?;
    // seq_num starts at 1; checkin is the first callback sent after init.
    let decoded_seq = u64::from_le_bytes(decrypted[..8].try_into()?);
    assert_eq!(decoded_seq, 1_u64);
    // payload_len at offset 8 must be 0 (empty checkin body).
    assert_eq!(&decrypted[8..12], &0_u32.to_be_bytes());
    let expected_final_offset =
        after_task_decrypt + callback_ctr_blocks(u32::from(DemonCommand::CommandExit), 4); // 5
    assert_eq!(agent.ctr_offset, expected_final_offset);

    let _get_job_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
    let exit_callback_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
    assert!(!exit_callback_packet.is_empty());

    let server_result = server.join().map_err(|_| "server thread panicked")?;
    server_result?;

    Ok(())
}

#[tokio::test]
async fn run_exits_cleanly_after_exit_task() -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let (request_tx, request_rx) = mpsc::channel::<Vec<u8>>();
    let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

    // Four connections: init, checkin (empty), get_job (task), exit callback.
    let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            request_tx.send(request)?;
            let body = response_rx.recv()?;
            write_http_response(&mut stream, &body)?;
        }
        Ok(())
    });

    let config = PhantomConfig {
        callback_url: format!("http://{address}/"),
        sleep_delay_ms: 0,
        // Use Plain mode: Mprotect marks the process-wide heap PROT_NONE
        // which crashes any other test thread that touches the heap.
        sleep_mode: crate::sleep_obfuscate::SleepMode::Plain,
        ..PhantomConfig::default()
    };
    let mut agent = PhantomAgent::new(config)?;

    response_tx.send(encrypt_agent_data(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        &agent.agent_id.to_le_bytes(),
    )?)?;

    // checkin sends at 1, advances by callback_ctr_blocks(CommandCheckin, 0) → 2.
    // get_job sends at 2, advances by callback_ctr_blocks(CommandGetJob, 0) → 3.
    // Task payload is encrypted at offset 3.
    let after_get_job_send = 1
        + callback_ctr_blocks(u32::from(DemonCommand::CommandCheckin), 0)
        + callback_ctr_blocks(u32::from(DemonCommand::CommandGetJob), 0); // 3
    let task_payload = 1_i32.to_le_bytes().to_vec();
    let encrypted_task_payload = encrypt_agent_data_at_offset(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        after_get_job_send,
        &task_payload,
    )?;
    let task = DemonPackage {
        command_id: u32::from(DemonCommand::CommandExit),
        request_id: 42,
        payload: encrypted_task_payload,
    };
    let get_job_response = DemonMessage::new(vec![task]).to_bytes()?;

    // checkin → empty; get_job → task; exit callback → empty
    response_tx.send(Vec::new())?;
    response_tx.send(get_job_response)?;
    response_tx.send(Vec::new())?;

    agent.run().await?;

    let init_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
    assert!(!init_packet.is_empty());

    let checkin_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
    let envelope = DemonEnvelope::from_bytes(&checkin_packet)?;
    // command_id and request_id are in the clear.
    assert_eq!(&envelope.payload[..4], &u32::from(DemonCommand::CommandCheckin).to_be_bytes());
    assert_eq!(&envelope.payload[4..8], &0_u32.to_be_bytes());
    // Remaining bytes are encrypted: seq_num(8 LE) + payload_len(4) only (empty checkin payload).
    let decrypted = decrypt_agent_data_at_offset(
        &agent.session_crypto.key,
        &agent.session_crypto.iv,
        1, // checkin encrypted at ctr_offset=1 (after init ack)
        &envelope.payload[8..],
    )?;
    // seq_num = 1 (first callback after init).
    let decoded_seq = u64::from_le_bytes(decrypted[..8].try_into()?);
    assert_eq!(decoded_seq, 1_u64);
    // payload_len at offset 8 must be 0 (empty checkin body).
    assert_eq!(&decrypted[8..12], &0_u32.to_be_bytes());

    let _get_job_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
    let exit_callback_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
    assert!(!exit_callback_packet.is_empty());

    let server_result = server.join().map_err(|_| "server thread panicked")?;
    server_result?;
    Ok(())
}
