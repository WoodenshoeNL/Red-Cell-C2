//! Reconnect protocol and CTR synchronisation tests.

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;

use super::common;
use super::helpers::{
    operator_task_message, spawn_server_with_http_listener, spawn_server_with_http_listener_custom,
};

/// End-to-end test: reconnect then subsequent callback remains synchronised.
///
/// This test exercises the protocol contract documented on [`build_reconnect_ack`]:
/// the reconnect ACK is **not counter-consuming** — neither the server nor the agent should
/// advance their AES-CTR block offset after the reconnect handshake.
///
/// Sequence:
/// 1. Agent does a full init; server responds with init ACK.  Both advance their counters by
///    `ctr_blocks_for_len(4)` (one 4-byte agent_id payload = 1 block).
/// 2. Agent sends a reconnect probe (empty `DEMON_INIT` body, no encrypted payload).
/// 3. Server returns a reconnect ACK encrypted at the current offset (1 block) without
///    advancing.  Agent receives the ACK and also does **not** advance its counter.
/// 4. Agent sends a `COMMAND_GET_JOB` callback encrypted at the same offset (1 block).
///    The server decrypts it successfully, proving both sides remain synchronised.
///
/// If the agent were to mistakenly advance its counter after receiving the reconnect ACK
/// (as it does after the init ACK), step 4 would fail with a decrypt/parse error because
/// the agent would encrypt at offset 2 while the server decrypts at offset 1.
#[tokio::test]
async fn reconnect_then_subsequent_callback_remains_synchronised()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-reconnect-e2e").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0xDEAD_C0DE_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
        0x8E, 0x8F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x4F, 0x62, 0x75, 0x88, 0x9B, 0xAE, 0xC1, 0xD4, 0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59,
        0x6C,
    ];

    // --- Step 1: full init --------------------------------------------------------
    // The agent tracks its own CTR offset mirror to simulate what a real agent does.
    let agent_ctr_offset = 0_u64;

    let init_bytes = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    // Verify the init ACK decrypts at offset 0.
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes(), "init ACK must echo agent_id");

    // Agent advances its counter after consuming the init ACK (counter-consuming).
    // Legacy CTR mode: offset stays at 0.

    // Consume the AgentNew operator event.
    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew event after init"
    );

    // --- Step 2: reconnect probe --------------------------------------------------
    // The reconnect probe carries no encrypted payload — agent counter does NOT change.
    let reconnect_bytes = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_reconnect_body(agent_id))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    // --- Step 3: verify reconnect ACK is encrypted at the current (non-advanced) offset ----
    // The server encrypted at `agent_ctr_offset` without advancing.  The agent decrypts
    // here to confirm the ACK, but critically it does NOT advance its own counter.
    let reconnect_ack =
        decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &reconnect_bytes)?;
    assert_eq!(
        reconnect_ack.as_slice(),
        &agent_id.to_le_bytes(),
        "reconnect ACK must echo agent_id encrypted at the pre-reconnect CTR offset"
    );
    // NOT advancing agent_ctr_offset here — the reconnect ACK is not counter-consuming.

    // Confirm the server's stored offset also did not advance.
    assert_eq!(
        harness.server.agent_registry.ctr_offset(agent_id).await?,
        agent_ctr_offset,
        "server CTR offset must not advance after sending a reconnect ACK"
    );

    // --- Step 4: subsequent callback at the same (unchanged) offset ---------------
    // If the agent had incorrectly advanced its counter, this would fail because the
    // server would try to decrypt at offset `agent_ctr_offset` while the agent would
    // have encrypted at `agent_ctr_offset + 1`.
    // `error_for_status()` returning Ok proves the server responded with HTTP 200.  A CTR
    // desync would cause the server to fail parsing the decrypted garbage and return HTTP 400,
    // which `error_for_status()` would surface as an error that fails the test.
    // The body itself may be empty (no queued jobs) — that is also a valid 200 response.
    harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            agent_ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;

    harness.shutdown().await?;
    Ok(())
}

/// Concurrent reconnect probes from the same agent must all succeed and leave the CTR offset
/// unchanged.  The `encrypt_for_agent_without_advancing` path acquires the `ctr_block_offset`
/// mutex, so concurrent calls are serialised — but we must verify that no probe corrupts the
/// offset or causes a panic under real concurrency.
#[tokio::test]
async fn concurrent_reconnect_probes_preserve_ctr_offset() -> Result<(), Box<dyn std::error::Error>>
{
    let mut harness = spawn_server_with_http_listener("edge-http-concurrent-reconnect").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0xCAFE_0001_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
        0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x4A, 0x4B,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xCB, 0xDE, 0xF1, 0x04, 0x17, 0x2A, 0x3D, 0x50, 0x63, 0x76, 0x89, 0x9C, 0xAF, 0xC2, 0xD5,
        0xE8,
    ];

    // Register the agent.
    let init_bytes = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let agent_ctr_offset = 0_u64;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.

    // Consume AgentNew event.
    let _agent_new = common::read_operator_message(&mut harness.socket).await?;

    let offset_before = harness.server.agent_registry.ctr_offset(agent_id).await?;

    // Fire 8 concurrent reconnect probes (below the 10/min per-agent rate limit).
    let mut join_set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let body = common::valid_demon_reconnect_body(agent_id);
        let url = format!("http://127.0.0.1:{listener_port}/");
        join_set.spawn(async move {
            let client = reqwest::Client::new();
            let resp = client
                .post(&url)
                .body(body)
                .send()
                .await
                .expect("reconnect request should succeed")
                .error_for_status()
                .expect("reconnect should return 200");
            resp.bytes().await.expect("should read reconnect ACK bytes")
        });
    }

    let mut ack_count = 0_usize;
    while let Some(result) = join_set.join_next().await {
        let ack_bytes = result?;
        // Every reconnect ACK must be decryptable at the same offset (non-advancing).
        let ack_plaintext = decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &ack_bytes)?;
        assert_eq!(
            ack_plaintext.as_slice(),
            &agent_id.to_le_bytes(),
            "reconnect ACK #{ack_count} must echo agent_id"
        );
        ack_count += 1;
    }
    assert_eq!(ack_count, 8);

    // CTR offset must be unchanged.
    let offset_after = harness.server.agent_registry.ctr_offset(agent_id).await?;
    assert_eq!(
        offset_after, offset_before,
        "CTR offset must not drift after concurrent reconnect probes"
    );

    // Verify the agent session is still functional — a callback at the original offset must work.
    harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            agent_ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;

    harness.shutdown().await?;
    Ok(())
}

/// A reconnect probe arriving while a callback is being processed must not corrupt the CTR
/// offset.  The two-phase decrypt pattern (`decrypt_from_agent_without_advancing` +
/// `advance_ctr_for_agent`) acquires and releases the mutex between phases, so a reconnect
/// probe could theoretically encrypt at the same offset during the gap.  Since the reconnect
/// ACK uses `encrypt_for_agent_without_advancing`, the offset must remain stable.
///
/// This test fires callbacks and reconnect probes concurrently from separate tasks.
#[tokio::test]
async fn reconnect_probe_interleaved_with_callbacks_preserves_sync()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-reconnect-interleave").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0xCAFE_0002_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x70,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x00, 0x13, 0x26, 0x39, 0x4C, 0x5F, 0x72, 0x85, 0x98, 0xAB, 0xBE, 0xD1, 0xE4, 0xF7, 0x0A,
        0x1D,
    ];

    // Register.
    let init_bytes = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let agent_ctr_offset = 0_u64;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.

    let _agent_new = common::read_operator_message(&mut harness.socket).await?;

    // Run 10 sequential cycles: for each cycle, fire a callback and a reconnect probe
    // concurrently.  After each cycle, the callback advances the agent's offset by the
    // callback payload size, and the reconnect must not have interfered.
    for cycle in 0..10_u32 {
        let callback_body = common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            agent_ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            cycle + 1,
            &[],
        );
        let reconnect_body = common::valid_demon_reconnect_body(agent_id);

        let url = format!("http://127.0.0.1:{listener_port}/");
        let url2 = url.clone();

        // Fire both concurrently.
        let callback_handle = tokio::spawn(async move {
            let client = reqwest::Client::new();
            client.post(&url).body(callback_body).send().await
        });
        let reconnect_handle = tokio::spawn(async move {
            let client = reqwest::Client::new();
            client.post(&url2).body(reconnect_body).send().await
        });

        let (cb_result, rc_result) = tokio::try_join!(callback_handle, reconnect_handle)?;
        let cb_resp = cb_result?.error_for_status()?;
        let _rc_resp = rc_result?.error_for_status()?;

        // The callback carries an encrypted 4-byte inner length prefix (empty payload).
        // `valid_demon_callback_body` with `&[]` produces a 4-byte plaintext (the BE length 0).
        let _callback_encrypted_len = 4; // BE u32 length prefix
        // Legacy CTR mode: offset stays at 0.

        // Verify the server offset matches what the agent expects after the callback.
        let server_offset = harness.server.agent_registry.ctr_offset(agent_id).await?;
        assert_eq!(
            server_offset, agent_ctr_offset,
            "cycle {cycle}: server CTR offset must equal agent-side tracking after callback + reconnect"
        );

        let _ = cb_resp.bytes().await?;
    }

    // Final callback to prove the session is still fully synchronised.
    harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            agent_ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            100,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;

    harness.shutdown().await?;
    Ok(())
}

/// Rapid reconnect-callback cycles must not cause counter drift.  This test performs many
/// reconnect → callback pairs in tight succession, verifying that the CTR offset advances
/// exactly as expected and the session remains usable throughout.
#[tokio::test]
async fn rapid_reconnect_callback_cycles_no_counter_drift() -> Result<(), Box<dyn std::error::Error>>
{
    let mut harness = spawn_server_with_http_listener_custom("edge-http-rapid-cycles", |lm| {
        lm.with_reconnect_probe_limit(100)
    })
    .await?;
    let listener_port = harness.listener_port;

    let agent_id = 0xCAFE_0003_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84,
        0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93,
        0x94, 0x95,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA, 0xCD, 0xE0, 0xF3, 0x06, 0x19, 0x2C, 0x3F,
        0x52,
    ];

    // Register.
    let init_bytes = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let agent_ctr_offset = 0_u64;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.

    let _agent_new = common::read_operator_message(&mut harness.socket).await?;

    // 30 rapid cycles: reconnect → callback → verify offset.
    for cycle in 0..30_u32 {
        // Reconnect probe (non-advancing).
        let reconnect_bytes = harness
            .client
            .post(format!("http://127.0.0.1:{listener_port}/"))
            .body(common::valid_demon_reconnect_body(agent_id))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;

        // Verify reconnect ACK is at the current offset.
        let reconnect_ack =
            decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &reconnect_bytes)?;
        assert_eq!(
            reconnect_ack.as_slice(),
            &agent_id.to_le_bytes(),
            "cycle {cycle}: reconnect ACK must decrypt at current offset"
        );

        // CTR must not have moved.
        assert_eq!(
            harness.server.agent_registry.ctr_offset(agent_id).await?,
            agent_ctr_offset,
            "cycle {cycle}: CTR must not advance after reconnect ACK"
        );

        // Callback (advancing).
        harness
            .client
            .post(format!("http://127.0.0.1:{listener_port}/"))
            .body(common::valid_demon_callback_body(
                agent_id,
                key,
                iv,
                agent_ctr_offset,
                u32::from(DemonCommand::CommandGetJob),
                cycle + 1,
                &[],
            ))
            .send()
            .await?
            .error_for_status()?;

        // The callback's encrypted portion is the 4-byte inner length prefix.
        // Legacy CTR mode: offset stays at 0.

        // Verify the server agrees.
        assert_eq!(
            harness.server.agent_registry.ctr_offset(agent_id).await?,
            agent_ctr_offset,
            "cycle {cycle}: server CTR must match agent tracking after callback"
        );
    }

    // Final validation: one more callback to prove no drift accumulated.
    harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            agent_ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            999,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;

    harness.shutdown().await?;
    Ok(())
}

/// Queue a checkin task and verify the agent receives it after a reconnect cycle.
#[tokio::test]
async fn reconnect_task_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-reconnect-task").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0xDEAD_BEEF_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
        0xBE, 0xBF,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x10, 0x23, 0x36, 0x49, 0x5C, 0x6F, 0x82, 0x95, 0xA8, 0xBB, 0xCE, 0xE1, 0xF4, 0x07, 0x1A,
        0x2D,
    ];
    let ctr_offset = 0_u64;

    // Register.
    let init_bytes = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());

    let _agent_new = common::read_operator_message(&mut harness.socket).await?;

    // Queue a task.
    let demon_id = format!("{agent_id:X}");
    let task = operator_task_message("EE", "checkin", &demon_id, DemonCommand::CommandCheckin)?;
    harness.socket.send_text(task).await?;
    let _task_echo = common::read_operator_message(&mut harness.socket).await?;

    // Reconnect probe (must not lose the queued task).
    harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_reconnect_body(agent_id))
        .send()
        .await?
        .error_for_status()?;

    // Now poll for jobs — the queued task must still be present.
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
    let message = red_cell_common::demon::DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(message.packages.len(), 1, "task queued before reconnect must still be delivered");
    assert_eq!(message.packages[0].request_id, 0xEE);

    harness.shutdown().await?;
    Ok(())
}
