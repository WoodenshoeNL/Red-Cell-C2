//! Legacy CTR mode behaviour tests.
//!
//! In legacy CTR mode (used by DEMON_INIT-registered agents), every packet uses CTR block
//! offset 0.  Repeated callbacks at offset 0 must all succeed because legacy mode has no
//! concept of a "stale" offset.

use std::collections::BTreeMap;
use std::time::Duration;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
use red_cell_common::demon::{
    DemonCommand, DemonMessage, DemonProcessCommand, format_proc_create_args,
};
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use serde_json::Value;
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

/// Frozen Havoc-style Demon registers with **legacy** AES-CTR (no `INIT_EXT_*` flags).
/// This exercises the same server path as autotest Windows Demon: dequeue a `CommandProc`
/// create task and accept piped `CommandOutput` while CTR offset stays at zero.
#[tokio::test]
async fn legacy_ctr_proc_create_task_and_output_round_trip()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-legacy-proc-output").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54,
        0x55, 0x56,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xC1, 0xD4, 0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59, 0x6C, 0x7F, 0x92, 0xA5, 0xB8, 0xCB,
        0xDE,
    ];
    const CTR: u64 = 0;

    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, CTR, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());

    assert!(
        harness.server.agent_registry.legacy_ctr(agent_id).await?,
        "init without extension flags must register legacy_ctr = true"
    );
    assert_eq!(harness.server.agent_registry.ctr_offset(agent_id).await?, 0);

    let _agent_new =
        timeout(Duration::from_secs(10), common::read_operator_message(&mut harness.socket))
            .await
            .map_err(|_| "timed out waiting for AgentNew message")??;

    let proc_task = serde_json::to_string(&OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "4D".to_owned(),
            command_line: "whoami".to_owned(),
            demon_id: "12345678".to_owned(),
            command_id: u32::from(DemonCommand::CommandProc).to_string(),
            sub_command: Some("create".to_owned()),
            extra: BTreeMap::from([(
                String::from("Args"),
                Value::String(format_proc_create_args("whoami")),
            )]),
            ..AgentTaskInfo::default()
        },
    }))?;
    harness.socket.send_text(proc_task).await?;
    let _echo =
        timeout(Duration::from_secs(10), common::read_operator_message(&mut harness.socket))
            .await
            .map_err(|_| "timed out waiting for task echo")??;

    let get_job_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            CTR,
            u32::from(DemonCommand::CommandGetJob),
            0x10,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = get_job_response.bytes().await?;
    let message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(message.packages.len(), 1);
    assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandProc));
    assert_eq!(message.packages[0].request_id, 0x4D);

    let job_plaintext = decrypt_agent_data_at_offset(&key, &iv, CTR, &message.packages[0].payload)?;
    assert!(
        job_plaintext.len() >= 4
            && u32::from_le_bytes(job_plaintext[0..4].try_into().unwrap())
                == u32::from(DemonProcessCommand::Create)
    );

    let output_text = "workgroup\\developer";
    let cb = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            CTR,
            u32::from(DemonCommand::CommandOutput),
            0x4D,
            &{
                let mut p = Vec::new();
                p.extend_from_slice(&(output_text.len() as u32).to_be_bytes());
                p.extend_from_slice(output_text.as_bytes());
                p
            },
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(cb.bytes().await?.is_empty());

    let output_event =
        timeout(Duration::from_secs(10), common::read_operator_message(&mut harness.socket))
            .await
            .map_err(|_| "timed out waiting for CommandOutput")??;
    let OperatorMessage::AgentResponse(resp) = output_event else {
        panic!("expected AgentResponse");
    };
    assert_eq!(resp.info.output, output_text);
    assert_eq!(resp.info.command_line.as_deref(), Some("whoami"));
    assert_eq!(resp.info.extra.get("TaskID").and_then(serde_json::Value::as_str), Some("4D"));

    assert_eq!(harness.server.agent_registry.ctr_offset(agent_id).await?, 0);

    harness.shutdown().await?;
    Ok(())
}
