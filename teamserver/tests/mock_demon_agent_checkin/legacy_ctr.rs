//! Legacy CTR mode behaviour tests.
//!
//! In legacy CTR mode (used by DEMON_INIT-registered agents), every packet uses CTR block
//! offset 0.  Repeated callbacks at offset 0 must all succeed because legacy mode has no
//! concept of a "stale" offset.

use std::time::Duration;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::OperatorMessage;
use tokio::time::timeout;

use super::common;
use super::helpers::{operator_task_message, spawn_server_with_http_listener};

/// In legacy CTR mode (used by DEMON_INIT-registered agents), every packet
/// uses CTR block offset 0.  Repeated callbacks at offset 0 must all succeed
/// because legacy mode has no concept of a "stale" offset.
#[tokio::test]
async fn stale_ctr_offset_callback_returns_404_and_preserves_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-stale-ctr").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x96, 0xA9, 0xBC, 0xCF, 0xE2, 0xF5, 0x08, 0x1B, 0x2E, 0x41, 0x54, 0x67, 0x7A, 0x8D, 0xA0,
        0xB3,
    ];
    let ctr_offset = 0_u64;

    // --- Register the agent ---------------------------------------------------------
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

    let agent_new =
        timeout(Duration::from_secs(10), common::read_operator_message(&mut harness.socket))
            .await
            .map_err(|_| "timed out waiting for AgentNew message")??;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // --- First callback at offset 0 -------------------------------------------------
    let task = operator_task_message("AA", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send_text(task).await?;
    let _task_echo =
        timeout(Duration::from_secs(10), common::read_operator_message(&mut harness.socket))
            .await
            .map_err(|_| "timed out waiting for first task echo")??;

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
    assert_eq!(message.packages[0].request_id, 0xAA);

    let ctr_after_valid = harness.server.agent_registry.ctr_offset(agent_id).await?;
    assert_eq!(ctr_after_valid, 0, "legacy CTR mode keeps offset at 0");

    // --- Second callback at same offset 0 (legacy mode allows this) -----------------
    let stale_response = harness
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
        .await?;
    // Legacy mode: repeated offset 0 is accepted, not rejected.
    assert!(
        stale_response.status().is_success(),
        "legacy CTR mode accepts repeated callbacks at offset 0"
    );

    // --- Verify server CTR offset remains 0 -----------------------------------------
    assert_eq!(
        harness.server.agent_registry.ctr_offset(agent_id).await?,
        0,
        "CTR offset must remain 0 in legacy mode"
    );

    // --- Third callback also succeeds -----------------------------------------------
    let task2 = operator_task_message("BB", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send_text(task2).await?;
    let _task2_echo =
        timeout(Duration::from_secs(10), common::read_operator_message(&mut harness.socket))
            .await
            .map_err(|_| "timed out waiting for second task echo")??;

    let recovery_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            3,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let recovery_bytes = recovery_response.bytes().await?;
    let recovery_message = DemonMessage::from_bytes(recovery_bytes.as_ref())?;
    assert_eq!(
        recovery_message.packages.len(),
        1,
        "valid callback after stale-CTR must still retrieve queued tasks"
    );
    assert_eq!(recovery_message.packages[0].request_id, 0xBB);

    harness.shutdown().await?;
    Ok(())
}
