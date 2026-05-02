//! Regression test for red-cell-c2-qo8fd.
//!
//! Before the fix, `AgentRegistry::load_with_max_registered_agents` hardcoded
//! `ecdh_transport = false` for every persisted agent.  After a teamserver
//! restart, Phantom/Specter agents were still present in `ts_ecdh_sessions`
//! but `handle_get_job` no longer recognised them as ECDH transports, so it
//! re-encrypted job payloads with the legacy AES-CTR path.  The agent then
//! received bytes in the wrong transport format and jobbing broke until the
//! agent fully re-registered.
//!
//! The fix reconstructs `ecdh_transport` on registry load by checking whether
//! an agent has any persisted session row in `ts_ecdh_sessions`.  This test
//! pins that behaviour end-to-end: after a simulated restart, a queued job
//! dispatched via `CommandGetJob` must come back in the response unchanged
//! (plaintext inside the outer AES-GCM ECDH envelope), not AES-CTR encrypted.

use red_cell::{
    AgentRegistry, CommandDispatcher, Database, EventBus, Job, SocketRelayManager,
    database::TeamserverError,
};
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ConnectionId};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use zeroize::Zeroizing;

fn sample_agent(agent_id: u32) -> AgentRecord {
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF,
    ];
    AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(key.to_vec()),
            aes_iv: Zeroizing::new(iv.to_vec()),
            monotonic_ctr: false,
        },
        hostname: "phantom-host".to_owned(),
        username: "phantom-user".to_owned(),
        domain_name: "lab".to_owned(),
        external_ip: "203.0.113.7".to_owned(),
        internal_ip: "10.0.0.7".to_owned(),
        process_name: "phantom.exe".to_owned(),
        process_path: "C:\\phantom.exe".to_owned(),
        base_address: 0x1000,
        process_pid: 4242,
        process_tid: 4243,
        process_ppid: 4,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: "Windows 11".to_owned(),
        os_build: 22621,
        os_arch: "x64".to_owned(),
        sleep_delay: 1,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-04-23T00:00:00Z".to_owned(),
        last_call_in: "2026-04-23T00:00:01Z".to_owned(),
        archon_magic: None,
    }
}

/// Reloading the registry for an ECDH agent must restore `ecdh_transport = true`
/// so that `handle_get_job` keeps the plaintext payload rather than re-encrypting
/// it with the agent's AES-CTR stream (which ECDH agents do not use).
#[tokio::test]
async fn load_restores_ecdh_transport_from_persisted_session()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let agent_id: u32 = 0xECD0_0001;

    // --- Phase 1: register an ECDH agent and persist an ECDH session row ---
    {
        let registry = AgentRegistry::new(database.clone());
        registry
            .insert_full(
                sample_agent(agent_id),
                "https-ecdh",
                0,     // ctr_block_offset
                false, // legacy_ctr
                true,  // ecdh_transport: this is a Phantom/Specter agent
                false, // seq_protected
            )
            .await?;

        database.ecdh().store_session(&ConnectionId([0xCD; 16]), agent_id, &[0x77_u8; 32]).await?;

        assert!(
            registry.is_ecdh_transport(agent_id).await,
            "freshly registered ECDH agent should report ecdh_transport = true"
        );
        // registry dropped — simulated teamserver restart
    }

    // --- Phase 2: reload the registry from the shared database pool ---
    let reloaded = AgentRegistry::load(database).await?;

    assert!(
        reloaded.is_ecdh_transport(agent_id).await,
        "after reload, ECDH agents must still report ecdh_transport = true; \
         the bug was that load hardcoded this to false, which caused handle_get_job \
         to double-encrypt job payloads with legacy AES-CTR and break the agent"
    );
    Ok(())
}

/// End-to-end pinning: after a simulated teamserver restart, a queued job
/// dispatched via `CommandGetJob` must be returned to the agent **verbatim**
/// (not AES-CTR encrypted).  The outer AES-256-GCM ECDH envelope provides
/// confidentiality at a higher layer; running AES-CTR on top of that produces
/// bytes the Phantom/Specter agent cannot parse.
#[tokio::test]
async fn queued_job_for_restored_ecdh_agent_dispatches_plaintext()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let agent_id: u32 = 0xECD0_0002;
    let job_payload: Vec<u8> = b"plaintext-job-payload-for-ecdh-agent".to_vec();
    let request_id: u32 = 9001;
    let command_id = u32::from(DemonCommand::CommandProcList);

    // --- Phase 1: register ECDH agent and persist an ECDH session row ---
    {
        let registry = AgentRegistry::new(database.clone());
        registry
            .insert_full(
                sample_agent(agent_id),
                "https-ecdh",
                0,
                false,
                true,  // ecdh_transport = true
                false, // seq_protected
            )
            .await?;
        database.ecdh().store_session(&ConnectionId([0xEE; 16]), agent_id, &[0x77_u8; 32]).await?;
        // registry dropped — simulated teamserver restart.  The in-memory job
        // queue is not persisted, so we enqueue the job after reload.  What
        // we are testing is that the *transport-mode metadata* survives the
        // restart — that is the actual bug in red-cell-c2-qo8fd.
    }

    // --- Phase 2: reload registry and rebuild dispatcher ---
    let reloaded = AgentRegistry::load(database.clone()).await?;
    assert!(
        reloaded.is_ecdh_transport(agent_id).await,
        "precondition: ecdh_transport must be restored on reload"
    );

    // Enqueue the job against the reloaded registry — the new dispatcher will
    // serve it via CommandGetJob and decide whether to AES-CTR encrypt based
    // on the restored ecdh_transport flag.
    reloaded
        .enqueue_job(
            agent_id,
            Job {
                command: command_id,
                request_id,
                payload: job_payload.clone(),
                command_line: String::new(),
                task_id: "t1".to_owned(),
                created_at: "2026-04-23T00:00:02Z".to_owned(),
                operator: "op1".to_owned(),
            },
        )
        .await?;

    let events = EventBus::new(8);
    let sockets = SocketRelayManager::new(reloaded.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(reloaded.clone(), events, database, sockets, None);

    // --- Phase 3: dispatch CommandGetJob and inspect the returned bytes ---
    let response_bytes = dispatcher
        .dispatch(agent_id, u32::from(DemonCommand::CommandGetJob), 0, &[])
        .await?
        .ok_or("CommandGetJob should return a response containing the queued job")?;

    let message = DemonMessage::from_bytes(&response_bytes)?;
    assert_eq!(
        message.packages.len(),
        1,
        "dispatcher should emit exactly one package for the single queued job"
    );
    let package = &message.packages[0];
    assert_eq!(package.command_id, command_id, "command id must round-trip unchanged");
    assert_eq!(package.request_id, request_id, "request id must round-trip unchanged");
    assert_eq!(
        package.payload, job_payload,
        "payload must be returned plaintext for ECDH agents; if AES-CTR was applied, \
         these bytes would differ from the original plaintext and the agent would \
         fail to parse its job"
    );
    Ok(())
}

/// A non-ECDH (Demon/Archon) agent must continue to have its job payloads
/// encrypted with AES-CTR on `CommandGetJob` after a reload.  This test
/// prevents the fix from accidentally flipping the default for agents that
/// have no persisted ECDH session.
#[tokio::test]
async fn queued_job_for_non_ecdh_agent_is_still_encrypted_after_reload()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let agent_id: u32 = 0x1EEA_0003;
    let job_payload: Vec<u8> = b"plaintext-job-for-demon-agent".to_vec();
    let command_id = u32::from(DemonCommand::CommandProcList);

    {
        let registry = AgentRegistry::new(database.clone());
        registry.insert(sample_agent(agent_id)).await?;
    }

    let reloaded = AgentRegistry::load(database.clone()).await?;
    assert!(
        !reloaded.is_ecdh_transport(agent_id).await,
        "agent with no persisted ECDH session must be reloaded as ecdh_transport = false"
    );

    // Enqueue after reload — the in-memory job queue is not persisted across
    // the simulated restart.
    reloaded
        .enqueue_job(
            agent_id,
            Job {
                command: command_id,
                request_id: 1,
                payload: job_payload.clone(),
                command_line: String::new(),
                task_id: "t1".to_owned(),
                created_at: "2026-04-23T00:00:02Z".to_owned(),
                operator: "op1".to_owned(),
            },
        )
        .await?;

    let events = EventBus::new(8);
    let sockets = SocketRelayManager::new(reloaded.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(reloaded.clone(), events, database, sockets, None);

    let response_bytes = dispatcher
        .dispatch(agent_id, u32::from(DemonCommand::CommandGetJob), 0, &[])
        .await?
        .ok_or("CommandGetJob should return a response for a queued job")?;

    let message = DemonMessage::from_bytes(&response_bytes)?;
    assert_eq!(message.packages.len(), 1);
    let package = &message.packages[0];
    assert_ne!(
        package.payload, job_payload,
        "non-ECDH agents must still have their job payloads AES-CTR encrypted by \
         handle_get_job; a plaintext match here would mean the fix accidentally \
         flipped the default for all agents"
    );
    Ok(())
}

/// Unknown agent id must return `false` rather than panicking or defaulting to `true`,
/// so `handle_get_job` falls through to the legacy AES-CTR path and the queue layer
/// (not this transport probe) is what surfaces `AgentNotFound` to the caller.
#[tokio::test]
async fn is_ecdh_transport_returns_false_for_unknown_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database);
    assert!(
        !registry.is_ecdh_transport(0xDEAD_BEEF).await,
        "is_ecdh_transport must return false for an unknown agent id rather than panic \
         or return true, so that handle_get_job falls through to the default AES-CTR path \
         and the caller sees a clean AgentNotFound from dequeue_jobs"
    );
    Ok(())
}

/// `list_agent_ids_with_sessions` must reflect the DISTINCT set of agents that
/// currently have ECDH session rows — even if one agent has multiple sessions
/// (e.g. multiple HTTP connections from the same Phantom instance).
#[tokio::test]
async fn list_agent_ids_with_sessions_deduplicates() -> Result<(), TeamserverError> {
    let database = Database::connect_in_memory().await?;
    database.ecdh().store_session(&ConnectionId([0x01; 16]), 100, &[0u8; 32]).await?;
    database.ecdh().store_session(&ConnectionId([0x02; 16]), 100, &[0u8; 32]).await?;
    database.ecdh().store_session(&ConnectionId([0x03; 16]), 200, &[0u8; 32]).await?;

    let ids = database.ecdh().list_agent_ids_with_sessions().await?;
    assert_eq!(ids.len(), 2, "two distinct agent ids");
    assert!(ids.contains(&100));
    assert!(ids.contains(&200));
    Ok(())
}
