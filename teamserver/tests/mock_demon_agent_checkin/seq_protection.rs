//! Wrong-key rejection, duplicate init, and sequence protection tests.

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::OperatorMessage;

use super::common;
use super::helpers::{operator_task_message, spawn_server_with_http_listener};

/// A callback encrypted with the wrong AES key must be rejected with HTTP 404
/// (the server's fake-404 response), and the server's CTR offset must not
/// advance.  A subsequent callback with the *correct* key must still succeed,
/// proving the server did not desync.
#[tokio::test]
async fn wrong_key_callback_returns_404_and_preserves_ctr_offset()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-wrong-key").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21,
        0x22, 0x23,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x23, 0x36, 0x49, 0x5C, 0x6F, 0x82, 0x95, 0xA8, 0xBB, 0xCE, 0xE1, 0xF4, 0x07, 0x1A, 0x2D,
        0x40,
    ];
    let ctr_offset = 0_u64;

    // --- Register the agent normally ------------------------------------------------
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

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // --- Send a callback encrypted with a WRONG key ---------------------------------
    let wrong_key: [u8; AGENT_KEY_LENGTH] = [
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x47, 0x48,
    ];
    let wrong_key_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            wrong_key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?;
    assert_eq!(
        wrong_key_response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "wrong-key callback must be rejected with fake 404"
    );

    common::skip_optional_teamserver_log(
        &mut harness.socket,
        std::time::Duration::from_millis(250),
    )
    .await;

    // --- Verify the server's CTR offset was NOT advanced ----------------------------
    assert_eq!(
        harness.server.agent_registry.ctr_offset(agent_id).await?,
        ctr_offset,
        "CTR offset must not advance after a wrong-key callback"
    );

    // --- A subsequent valid callback must still succeed ------------------------------
    let task = operator_task_message("CC", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send_text(task).await?;
    let _task_echo = common::read_operator_message(&mut harness.socket).await?;

    let valid_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            2,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = valid_response.bytes().await?;
    let message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(
        message.packages.len(),
        1,
        "valid callback after wrong-key must still retrieve queued tasks"
    );
    assert_eq!(message.packages[0].request_id, 0xCC);

    harness.shutdown().await?;
    Ok(())
}

/// A duplicate full `DEMON_INIT` for an already-registered agent must be
/// rejected with HTTP 404.  The original agent's crypto state must be
/// preserved — a subsequent callback with the original key must still work.
#[tokio::test]
async fn duplicate_demon_init_rejected_preserves_original_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-dup-init").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C,
        0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
        0x6C, 0x6D,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x8D, 0xA0, 0xB3, 0xC6, 0xD9, 0xEC, 0xFF, 0x12, 0x25, 0x38, 0x4B, 0x5E, 0x71, 0x84, 0x97,
        0xAA,
    ];
    let ctr_offset = 0_u64;

    // --- First (legitimate) init ----------------------------------------------------
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

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let ctr_before_dup = harness.server.agent_registry.ctr_offset(agent_id).await?;

    // --- Second (duplicate) init with different key material ------------------------
    let dup_key: [u8; AGENT_KEY_LENGTH] = [
        0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81,
        0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
        0x91, 0x92,
    ];
    let dup_iv: [u8; AGENT_IV_LENGTH] = [
        0xC2, 0xD5, 0xE8, 0xFB, 0x0E, 0x21, 0x34, 0x47, 0x5A, 0x6D, 0x80, 0x93, 0xA6, 0xB9, 0xCC,
        0xDF,
    ];
    let dup_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, dup_key, dup_iv))
        .send()
        .await?;
    assert_eq!(
        dup_response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "duplicate DEMON_INIT must be rejected with fake 404"
    );

    common::skip_optional_teamserver_log(
        &mut harness.socket,
        std::time::Duration::from_millis(250),
    )
    .await;

    // --- Verify CTR offset unchanged ------------------------------------------------
    assert_eq!(
        harness.server.agent_registry.ctr_offset(agent_id).await?,
        ctr_before_dup,
        "CTR offset must not change after duplicate init rejection"
    );

    // --- Verify original key still works --------------------------------------------
    let task = operator_task_message("DD", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send_text(task).await?;
    let _task_echo = common::read_operator_message(&mut harness.socket).await?;

    let valid_response = harness
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
    let job_bytes = valid_response.bytes().await?;
    let message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(message.packages.len(), 1);
    assert_eq!(message.packages[0].request_id, 0xDD);

    harness.shutdown().await?;
    Ok(())
}
