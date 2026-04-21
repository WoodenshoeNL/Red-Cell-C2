use std::time::Duration;

use red_cell_common::AgentEncryptionInfo;
use red_cell_common::config::Profile;
use red_cell_common::operator::OperatorMessage;
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::config::AgentLivenessConfig;
use super::monitor::{AgentLivenessMonitor, spawn_agent_liveness_monitor};
use super::sweep::{collect_stale_agents, mark_stale_agent_if_unchanged, sweep_dead_agents_at};
use crate::{AgentRegistry, Database, EventBus, SocketRelayManager, TeamserverError};

fn sample_agent(agent_id: u32) -> red_cell_common::AgentRecord {
    red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0u8; 32]),
            aes_iv: Zeroizing::new(vec![0u8; 16]),
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "LAB".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        internal_ip: "10.0.0.10".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        base_address: 0,
        process_pid: 1337,
        process_tid: 1338,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-03-10T10:00:00Z".to_owned(),
        last_call_in: "2026-03-10T10:00:00Z".to_owned(),
        archon_magic: None,
    }
}

fn sample_profile(agent_timeout_secs: Option<u64>, demon_sleep_secs: u64) -> Profile {
    let timeout_line =
        agent_timeout_secs.map(|secs| format!("  AgentTimeoutSecs = {secs}\n")).unwrap_or_default();
    let profile = format!(
        r#"
        Teamserver {{
          Host = "127.0.0.1"
          Port = 40056
        {timeout_line}}}

        Operators {{
          user "neo" {{
            Password = "password1234"
          }}
        }}

        Demon {{
          Sleep = {demon_sleep_secs}
        }}
        "#
    );

    Profile::parse(&profile).expect("profile should parse")
}

async fn shutdown_monitor(mut monitor: AgentLivenessMonitor) {
    if let Some(shutdown) = monitor.shutdown.take() {
        let _ = shutdown.send(());
    }

    let task = std::mem::replace(&mut monitor.task, tokio::spawn(async {}));
    let result = task.await;
    assert!(result.is_ok(), "monitor task should exit cleanly");
}

#[tokio::test]
async fn spawn_agent_liveness_monitor_starts_and_shuts_down_cleanly() -> Result<(), TeamserverError>
{
    let profile = sample_profile(None, 5);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    let monitor = spawn_agent_liveness_monitor(registry, sockets, events, database, &profile);
    tokio::task::yield_now().await;

    assert!(!monitor.task.is_finished());
    assert!(monitor.shutdown.is_some());
    shutdown_monitor(monitor).await;
    Ok(())
}

#[tokio::test]
async fn spawn_agent_liveness_monitor_handles_aggressive_timing_profile()
-> Result<(), TeamserverError> {
    let profile = sample_profile(Some(1), 1);
    let config = AgentLivenessConfig::from_profile(&profile);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    let monitor = spawn_agent_liveness_monitor(registry, sockets, events, database, &profile);
    tokio::task::yield_now().await;

    assert_eq!(config.sweep_interval, Duration::from_secs(1));
    assert!(!monitor.task.is_finished());

    shutdown_monitor(monitor).await;
    Ok(())
}

#[tokio::test]
async fn spawn_agent_liveness_monitor_marks_stale_agents_dead_and_emits_side_effects()
-> Result<(), TeamserverError> {
    let profile = sample_profile(None, 5);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent(0xC0DE_CAFE);
    registry.insert(agent.clone()).await?;
    sockets.add_socks_server(agent.agent_id, "0").await.map_err(|error| {
        TeamserverError::InvalidPersistedValue { field: "socket_relay", message: error.to_string() }
    })?;
    let mut receiver = events.subscribe();

    let monitor = spawn_agent_liveness_monitor(
        registry.clone(),
        sockets.clone(),
        events.clone(),
        database.clone(),
        &profile,
    );

    let event = timeout(Duration::from_secs(1), receiver.recv()).await.map_err(|_| {
        TeamserverError::InvalidPersistedValue {
            field: "operator_event",
            message: "timed out waiting for dead-agent event".to_owned(),
        }
    })?;
    let event = event.ok_or(TeamserverError::InvalidPersistedValue {
        field: "operator_event",
        message: "missing dead-agent event".to_owned(),
    })?;

    let OperatorMessage::AgentUpdate(message) = event else {
        return Err(TeamserverError::InvalidPersistedValue {
            field: "operator_event",
            message: "expected AgentUpdate event".to_owned(),
        });
    };
    assert_eq!(message.info.agent_id, "C0DECAFE");
    assert_eq!(message.info.marked, "Dead");

    // The sweep writes audit entries inline before pruning sockets, so we
    // must let the sweep task finish after it broadcasts the agent event.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let stored = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(!stored.active);
    assert_eq!(stored.reason, "agent timed out after 15 seconds without callback");
    assert_eq!(sockets.list_socks_servers(agent.agent_id).await, "No active SOCKS5 servers");

    shutdown_monitor(monitor).await;
    Ok(())
}

#[tokio::test]
async fn sweep_marks_stale_agents_dead_broadcasts_and_cleans_relay_state()
-> Result<(), TeamserverError> {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "neo" {
            Password = "password1234"
          }
        }

        Demon {
          Sleep = 5
        }
        "#,
    )
    .expect("profile should parse");
    let config = AgentLivenessConfig::from_profile(&profile);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent(0xDEAD_BEEF);
    registry.insert(agent.clone()).await?;
    sockets.add_socks_server(agent.agent_id, "0").await.map_err(|error| {
        TeamserverError::InvalidPersistedValue { field: "socket_relay", message: error.to_string() }
    })?;
    let mut receiver = events.subscribe();

    let dead = sweep_dead_agents_at(
        &registry,
        &sockets,
        &events,
        &database,
        config,
        time::macros::datetime!(2026-03-10 10:00:15 UTC),
    )
    .await?;

    assert_eq!(dead, vec![agent.agent_id]);
    let stored = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(!stored.active);
    assert_eq!(stored.reason, "agent timed out after 15 seconds without callback");
    assert_eq!(sockets.list_socks_servers(agent.agent_id).await, "No active SOCKS5 servers");

    let event = receiver.recv().await.ok_or(TeamserverError::InvalidPersistedValue {
        field: "operator_event",
        message: "missing dead-agent event".to_owned(),
    })?;
    let OperatorMessage::AgentUpdate(message) = event else {
        return Err(TeamserverError::InvalidPersistedValue {
            field: "operator_event",
            message: "expected AgentUpdate event".to_owned(),
        });
    };
    assert_eq!(message.info.agent_id, "DEADBEEF");
    assert_eq!(message.info.marked, "Dead");

    Ok(())
}

#[tokio::test]
async fn sweep_uses_timeout_override_instead_of_sleep_delay() -> Result<(), TeamserverError> {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
          AgentTimeoutSecs = 30
        }

        Operators {
          user "neo" {
            Password = "password1234"
          }
        }

        Demon {
          Sleep = 5
        }
        "#,
    )
    .expect("profile should parse");
    let config = AgentLivenessConfig::from_profile(&profile);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let mut agent = sample_agent(0xFEED_FACE);
    agent.sleep_delay = 90;
    registry.insert(agent.clone()).await?;

    let dead = sweep_dead_agents_at(
        &registry,
        &sockets,
        &events,
        &database,
        config,
        time::macros::datetime!(2026-03-10 10:00:30 UTC),
    )
    .await?;

    assert_eq!(dead, vec![agent.agent_id]);
    Ok(())
}

#[tokio::test]
async fn sweep_skips_agents_with_malformed_last_call_in() -> Result<(), TeamserverError> {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "neo" {
            Password = "password1234"
          }
        }

        Demon {
          Sleep = 5
        }
        "#,
    )
    .expect("profile should parse");
    let config = AgentLivenessConfig::from_profile(&profile);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let mut agent = sample_agent(0xABCD_1234);
    agent.last_call_in = "not-a-timestamp".to_owned();
    registry.insert(agent.clone()).await?;

    let dead = sweep_dead_agents_at(
        &registry,
        &sockets,
        &events,
        &database,
        config,
        time::macros::datetime!(2026-03-10 10:00:15 UTC),
    )
    .await?;

    assert!(dead.is_empty());
    let stored = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(stored.active);
    assert_eq!(stored.last_call_in, "not-a-timestamp");
    assert!(stored.reason.is_empty());

    Ok(())
}

#[test]
fn from_profile_zero_sleep_falls_back_to_minimum_sweep_interval() {
    // Sleep = 0 is filtered out so effective_timeout uses MIN_SWEEP_INTERVAL_SECS * 3 = 3,
    // giving sweep_secs = max(3/3, MIN_SWEEP_INTERVAL_SECS) = 1.
    let profile = sample_profile(None, 0);
    let config = AgentLivenessConfig::from_profile(&profile);

    assert!(
        config.default_sleep_secs.is_none(),
        "zero sleep must be filtered out, got {:?}",
        config.default_sleep_secs,
    );
    assert_eq!(
        config.sweep_interval,
        Duration::from_secs(1),
        "sweep interval must be exactly MIN_SWEEP_INTERVAL_SECS (1 s), got {:?}",
        config.sweep_interval,
    );

    // An agent with sleep_delay = 0 must fall back to MIN_SWEEP_INTERVAL_SECS * 3 = 3 s,
    // not zero — otherwise every agent would be marked dead on the very first sweep tick.
    let mut agent = sample_agent(0x0000_0001);
    agent.sleep_delay = 0;
    assert_eq!(
        config.timeout_for(&agent),
        3,
        "timeout_for an agent with sleep_delay=0 must return 3 (MIN_SWEEP_INTERVAL_SECS * 3)",
    );
}

#[test]
fn from_profile_large_sleep_clamps_sweep_to_max_interval() {
    // Sleep = 200 → effective_timeout = 600 → sweep_secs = 200,
    // which must be clamped to MAX_SWEEP_INTERVAL_SECS (30 s).
    let profile = sample_profile(None, 200);
    let config = AgentLivenessConfig::from_profile(&profile);

    assert_eq!(
        config.sweep_interval,
        Duration::from_secs(30),
        "sweep interval must be clamped to MAX_SWEEP_INTERVAL_SECS (30 s), got {:?}",
        config.sweep_interval,
    );
    assert_eq!(
        config.default_sleep_secs,
        Some(200),
        "default_sleep_secs must be 200, got {:?}",
        config.default_sleep_secs,
    );

    // An agent with sleep_delay = 200 and no timeout override must get
    // timeout = max(200, 200).max(1) * 3 = 600 s.
    let mut agent = sample_agent(0x0000_0004);
    agent.sleep_delay = 200;
    assert_eq!(
        config.timeout_for(&agent),
        600,
        "timeout_for an agent with sleep_delay=200 must return 600",
    );
}

#[tokio::test]
async fn sweep_mixed_liveness_only_marks_stale_agents_dead() -> Result<(), TeamserverError> {
    // Two stale agents (IDs inserted in descending order to exercise the sort) and one
    // recently-active agent.  Only the stale pair must appear in `dead_agent_ids`; the
    // fresh agent must remain active = true in the registry.
    let profile = sample_profile(None, 5); // sleep=5 → timeout=15 s
    let config = AgentLivenessConfig::from_profile(&profile);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    // Stale: last_call_in is 20 s before `now` — exceeds the 15 s timeout.
    let mut stale_high = sample_agent(0x0000_0200);
    stale_high.last_call_in = "2026-03-10T09:59:56Z".to_owned();
    registry.insert(stale_high.clone()).await?;

    // Stale: same old timestamp, lower ID — inserted after stale_high so the returned
    // Vec would be unsorted if sort_unstable() were omitted.
    let mut stale_low = sample_agent(0x0000_0100);
    stale_low.last_call_in = "2026-03-10T09:59:56Z".to_owned();
    registry.insert(stale_low.clone()).await?;

    // Fresh: last_call_in is 10 s before `now` — within the 15 s timeout.
    let mut fresh = sample_agent(0x0000_0300);
    fresh.last_call_in = "2026-03-10T10:00:06Z".to_owned();
    registry.insert(fresh.clone()).await?;

    let now = time::macros::datetime!(2026-03-10 10:00:16 UTC);
    let dead = sweep_dead_agents_at(&registry, &sockets, &events, &database, config, now).await?;

    // Only the two stale agents must be returned, in ascending sorted order.
    assert_eq!(dead, vec![stale_low.agent_id, stale_high.agent_id]);

    let stored_low = registry
        .get(stale_low.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: stale_low.agent_id })?;
    assert!(!stored_low.active);

    let stored_high = registry
        .get(stale_high.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: stale_high.agent_id })?;
    assert!(!stored_high.active);

    // The recently-active agent must still be alive.
    let stored_fresh = registry
        .get(fresh.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: fresh.agent_id })?;
    assert!(stored_fresh.active);
    assert!(stored_fresh.reason.is_empty());

    Ok(())
}

#[tokio::test]
async fn sweep_toctou_guard_skips_agents_that_check_in_during_mark_phase()
-> Result<(), TeamserverError> {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "neo" {
            Password = "password1234"
          }
        }

        Demon {
          Sleep = 5
        }
        "#,
    )
    .expect("profile should parse");
    let config = AgentLivenessConfig::from_profile(&profile);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut agent = sample_agent(0xABCD_5678);
    registry.insert(agent.clone()).await?;

    let stale_agents =
        collect_stale_agents(&registry, config, time::macros::datetime!(2026-03-10 10:00:15 UTC))
            .await;
    assert_eq!(stale_agents.len(), 1);
    assert_eq!(stale_agents[0].agent_id, agent.agent_id);

    agent.last_call_in = "2026-03-10T10:00:14Z".to_owned();
    registry.update_agent(agent.clone()).await?;

    let marked =
        mark_stale_agent_if_unchanged(&registry, &events, &database, &stale_agents[0]).await?;

    assert!(!marked);
    let stored = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(stored.active);
    assert_eq!(stored.last_call_in, "2026-03-10T10:00:14Z");
    assert!(stored.reason.is_empty());

    Ok(())
}

#[tokio::test]
async fn sweep_toctou_guard_skips_agent_already_marked_dead_before_mark_phase()
-> Result<(), TeamserverError> {
    let profile = sample_profile(None, 5);
    let config = AgentLivenessConfig::from_profile(&profile);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let agent = sample_agent(0x1234_ABCD);
    registry.insert(agent.clone()).await?;

    // Collect stale agents — the agent qualifies (last_call_in is 15 s in the past).
    let stale_agents =
        collect_stale_agents(&registry, config, time::macros::datetime!(2026-03-10 10:00:15 UTC))
            .await;
    assert_eq!(stale_agents.len(), 1);
    assert_eq!(stale_agents[0].agent_id, agent.agent_id);

    // Simulate another mechanism (e.g., operator manual kill) marking the agent dead
    // between the collect and mark phases.
    registry.mark_dead(agent.agent_id, "operator killed").await?;
    let stored_before = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(!stored_before.active, "agent should already be dead before mark phase");

    // Subscribe after the manual kill so the only event we can receive is one
    // emitted by mark_stale_agent_if_unchanged itself.
    let mut receiver = events.subscribe();

    let marked =
        mark_stale_agent_if_unchanged(&registry, &events, &database, &stale_agents[0]).await?;

    // The guard must detect active=false and bail out without double-marking.
    assert!(!marked);

    // No spurious AgentUpdate should have been broadcast by mark_stale_agent_if_unchanged.
    // A very short timeout is sufficient because mark_stale_agent_if_unchanged is synchronous
    // from the perspective of the event bus — any emission would already be queued.
    let no_event = timeout(Duration::from_millis(50), receiver.recv()).await;
    assert!(
        no_event.is_err(),
        "mark_stale_agent_if_unchanged must not emit an event when the agent is already dead"
    );

    // The stored record should still reflect the earlier manual kill, not a second write.
    let stored_after = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(!stored_after.active);
    assert_eq!(stored_after.reason, "operator killed");

    Ok(())
}

#[tokio::test]
async fn sweep_handles_non_utc_offset_timestamps_correctly() -> Result<(), TeamserverError> {
    // "2026-03-10T15:30:00+05:30" is equivalent to "2026-03-10T10:00:00Z".
    // With sleep=5 the timeout is 15 s.  Sweeping at 10:00:14Z (14 s elapsed)
    // must keep the agent alive; sweeping at 10:00:16Z (16 s elapsed) must
    // mark it dead.  This confirms OffsetDateTime normalizes non-UTC offsets.
    let profile = sample_profile(None, 5); // sleep=5 → timeout=15 s
    let config = AgentLivenessConfig::from_profile(&profile);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    let mut agent = sample_agent(0x0FF5_E700);
    agent.last_call_in = "2026-03-10T15:30:00+05:30".to_owned();
    registry.insert(agent.clone()).await?;

    // Sweep at 10:00:14Z — 14 s elapsed, within the 15 s timeout → agent stays alive.
    let dead = sweep_dead_agents_at(
        &registry,
        &sockets,
        &events,
        &database,
        config,
        time::macros::datetime!(2026-03-10 10:00:14 UTC),
    )
    .await?;
    assert!(dead.is_empty(), "agent must stay alive at 14 s elapsed (timeout is 15 s)");

    let stored = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(stored.active, "agent must still be active before timeout");

    // Sweep at 10:00:16Z — 16 s elapsed, exceeds the 15 s timeout → agent marked dead.
    let dead = sweep_dead_agents_at(
        &registry,
        &sockets,
        &events,
        &database,
        config,
        time::macros::datetime!(2026-03-10 10:00:16 UTC),
    )
    .await?;
    assert_eq!(dead, vec![agent.agent_id], "agent must be marked dead at 16 s elapsed");

    let stored = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(!stored.active, "agent must be inactive after timeout");
    assert_eq!(stored.reason, "agent timed out after 15 seconds without callback");

    Ok(())
}

#[tokio::test]
async fn sweep_handles_negative_utc_offset_timestamps_correctly() -> Result<(), TeamserverError> {
    // "2026-03-10T02:00:00-08:00" is equivalent to "2026-03-10T10:00:00Z".
    // Same boundary logic as the positive-offset test above.
    let profile = sample_profile(None, 5);
    let config = AgentLivenessConfig::from_profile(&profile);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    let mut agent = sample_agent(0x0FF5_E701);
    agent.last_call_in = "2026-03-10T02:00:00-08:00".to_owned();
    registry.insert(agent.clone()).await?;

    // 14 s elapsed → alive
    let dead = sweep_dead_agents_at(
        &registry,
        &sockets,
        &events,
        &database,
        config,
        time::macros::datetime!(2026-03-10 10:00:14 UTC),
    )
    .await?;
    assert!(dead.is_empty(), "agent must stay alive at 14 s elapsed");

    // 16 s elapsed → dead
    let dead = sweep_dead_agents_at(
        &registry,
        &sockets,
        &events,
        &database,
        config,
        time::macros::datetime!(2026-03-10 10:00:16 UTC),
    )
    .await?;
    assert_eq!(dead, vec![agent.agent_id], "agent must be marked dead at 16 s elapsed");

    Ok(())
}

#[test]
fn timeout_for_override_zero_returns_zero_and_sweep_uses_minimum_interval() {
    // AgentTimeoutSecs = 0 means every agent gets a 0-second timeout.
    // effective_timeout_secs = 0 → sweep_secs = (0/3).clamp(1, 30) = 1
    let profile = sample_profile(Some(0), 5);
    let config = AgentLivenessConfig::from_profile(&profile);

    assert_eq!(
        config.sweep_interval,
        Duration::from_secs(1),
        "override=0 must clamp sweep to MIN_SWEEP_INTERVAL_SECS (1 s), got {:?}",
        config.sweep_interval,
    );

    let agent = sample_agent(0x0000_0001);
    assert_eq!(config.timeout_for(&agent), 0, "timeout_for must pass override=0 through unchanged",);
}

#[test]
fn timeout_for_very_large_override_does_not_overflow() {
    // u64::MAX / 3 is the largest value that won't overflow when the caller
    // later does i64::try_from(timeout_secs).  The sweep interval clamp uses
    // division-by-3 which is always safe; the override itself goes straight
    // through timeout_for without further multiplication.
    let large = u64::MAX / 3;
    let profile = sample_profile(Some(large), 5);
    let config = AgentLivenessConfig::from_profile(&profile);

    // sweep_secs = (large / 3).clamp(1, 30) = 30
    assert_eq!(
        config.sweep_interval,
        Duration::from_secs(30),
        "very large override must clamp sweep to MAX_SWEEP_INTERVAL_SECS (30 s), got {:?}",
        config.sweep_interval,
    );

    let agent = sample_agent(0x0000_0002);
    assert_eq!(
        config.timeout_for(&agent),
        large,
        "timeout_for must return the large override value unchanged",
    );
}

#[test]
fn timeout_for_sleep_delay_u16_max_returns_expected_value() {
    // sleep_delay is u32; using u16::MAX (65535) exercises the boundary where a
    // prior u16-field assumption would have caused a narrowing cast.
    // u64::from(65535) is lossless; with no override and default_sleep_secs = None:
    //   max(65535, 0).max(1).saturating_mul(3) = 65535 * 3 = 196605
    let profile = sample_profile(None, 0); // demon sleep 0 → default_sleep_secs = None
    let config = AgentLivenessConfig::from_profile(&profile);

    let mut agent = sample_agent(0x0000_0003);
    agent.sleep_delay = u32::from(u16::MAX);

    assert_eq!(
        config.timeout_for(&agent),
        196_605,
        "timeout_for with sleep_delay=u16::MAX must return 65535 * 3 = 196605",
    );
}

#[tokio::test]
async fn sweep_side_effects_persist_when_audit_database_fails() -> Result<(), TeamserverError> {
    // The audit write is spawned as a background task.  If the database pool
    // used for auditing is closed, that write must fail silently (logged via
    // tracing::warn) while the important side effects — agent marked dead,
    // AgentUpdate event broadcast, and SOCKS relay state pruned — still occur.
    let profile = sample_profile(None, 5); // sleep=5 → timeout=15 s
    let config = AgentLivenessConfig::from_profile(&profile);

    // Working database for the registry (agent state).
    let registry_db = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(registry_db.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    let agent = sample_agent(0xFA11_FA11);
    registry.insert(agent.clone()).await?;
    sockets.add_socks_server(agent.agent_id, "0").await.map_err(|error| {
        TeamserverError::InvalidPersistedValue { field: "socket_relay", message: error.to_string() }
    })?;

    // Separate database for audit writes — close it so every INSERT fails.
    let audit_db = Database::connect_in_memory().await?;
    audit_db.close().await;

    let mut receiver = events.subscribe();

    let dead = sweep_dead_agents_at(
        &registry,
        &sockets,
        &events,
        &audit_db, // closed → audit write will fail
        config,
        time::macros::datetime!(2026-03-10 10:00:15 UTC),
    )
    .await?;

    // Side-effect 1: stale agent is returned as dead.
    assert_eq!(dead, vec![agent.agent_id]);

    // Side-effect 2: agent is marked dead in the registry.
    let stored = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(!stored.active);
    assert_eq!(stored.reason, "agent timed out after 15 seconds without callback");

    // Side-effect 3: SOCKS relay state is pruned.
    assert_eq!(sockets.list_socks_servers(agent.agent_id).await, "No active SOCKS5 servers");

    // Side-effect 4: AgentUpdate event was broadcast to operators.
    let event = receiver.recv().await.ok_or(TeamserverError::InvalidPersistedValue {
        field: "operator_event",
        message: "missing dead-agent event".to_owned(),
    })?;
    let OperatorMessage::AgentUpdate(message) = event else {
        return Err(TeamserverError::InvalidPersistedValue {
            field: "operator_event",
            message: "expected AgentUpdate event".to_owned(),
        });
    };
    assert_eq!(message.info.agent_id, "FA11FA11");
    assert_eq!(message.info.marked, "Dead");

    // Give the spawned audit task a moment to run and fail gracefully
    // (it should log a warning, not panic).
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Confirm no audit entry was written (the audit DB is closed).
    // Use the registry DB to show that no audit row leaked there either.
    let entries = registry_db.audit_log().list().await?;
    assert!(
        entries.iter().all(|e| e.action != "agent.dead"),
        "no agent.dead audit entry should exist when the audit database is closed",
    );

    Ok(())
}

#[tokio::test]
async fn sweep_records_agent_dead_audit_entry() -> Result<(), TeamserverError> {
    // Verify that marking a stale agent dead via the sweep writes an
    // agent.dead audit log entry with actor="teamserver".
    let profile = sample_profile(None, 5);
    let config = AgentLivenessConfig::from_profile(&profile);
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent(0xDEAD_CAFE);
    registry.insert(agent.clone()).await?;

    let dead = sweep_dead_agents_at(
        &registry,
        &sockets,
        &events,
        &database,
        config,
        time::macros::datetime!(2026-03-10 10:00:15 UTC),
    )
    .await?;

    assert_eq!(dead, vec![agent.agent_id]);

    // The audit write is spawned as a background task.  Poll with a bounded
    // timeout so the test is deterministic even on a loaded CI worker.
    let dead_entry = timeout(Duration::from_millis(500), async {
        loop {
            let entries = database.audit_log().list().await?;
            if let Some(entry) = entries.into_iter().find(|e| e.action == "agent.dead") {
                return Ok::<_, TeamserverError>(entry);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| TeamserverError::InvalidPersistedValue {
        field: "audit_log",
        message: "expected agent.dead audit entry within timeout".to_owned(),
    })??;
    let dead_entry = &dead_entry;
    assert_eq!(dead_entry.actor, "teamserver");
    assert_eq!(dead_entry.target_kind, "agent");
    assert_eq!(dead_entry.target_id.as_deref(), Some("DEADCAFE"));
    let details = dead_entry.details.as_ref().ok_or(TeamserverError::InvalidPersistedValue {
        field: "details",
        message: "agent.dead audit entry must include details".to_owned(),
    })?;
    assert_eq!(details["result_status"], "success");
    assert_eq!(details["command"], "dead");

    // Verify the structured parameters include the timeout reason and external_ip.
    // A regression that drops or renames these fields would leave operators and
    // downstream audit/webhook consumers without context distinguishing a timeout
    // from other death paths.
    let params = details.get("parameters").ok_or(TeamserverError::InvalidPersistedValue {
        field: "parameters",
        message: "agent.dead audit entry must include parameters".to_owned(),
    })?;
    assert_eq!(
        params["reason"], "agent timed out after 15 seconds without callback",
        "parameters.reason must contain the timeout message",
    );
    assert_eq!(
        params["external_ip"], "203.0.113.10",
        "parameters.external_ip must match the agent's external_ip",
    );

    Ok(())
}

#[test]
fn timeout_for_agent_with_zero_sleep_delay_and_no_profile_default() {
    // Profile with Sleep = 0 → default_sleep_secs is filtered to None.
    // Agent with sleep_delay = 0 → timeout_for must floor at MIN_SWEEP_INTERVAL_SECS (1) * 3 = 3,
    // never returning zero (which would mark agents dead immediately).
    let profile = sample_profile(None, 0);
    let config = AgentLivenessConfig::from_profile(&profile);

    assert!(config.default_sleep_secs.is_none());
    assert!(config.timeout_override_secs.is_none());

    let mut agent = sample_agent(0x0000_0010);
    agent.sleep_delay = 0;

    let timeout = config.timeout_for(&agent);
    assert_eq!(
        timeout, 3,
        "sleep_delay=0 with no profile default must produce timeout=3 (MIN_SWEEP * 3), got {timeout}",
    );
}

#[test]
fn timeout_for_agent_with_u32_max_sleep_delay_saturates_correctly() {
    // Agent with sleep_delay = u32::MAX → u64::from(u32::MAX) = 4_294_967_295.
    // saturating_mul(3) = 12_884_901_885, which fits in u64 — no saturation needed,
    // but crucially no overflow either (would panic in debug or wrap in release).
    let profile = sample_profile(None, 5);
    let config = AgentLivenessConfig::from_profile(&profile);

    let mut agent = sample_agent(0x0000_0020);
    agent.sleep_delay = u32::MAX;

    let timeout = config.timeout_for(&agent);
    let expected = u64::from(u32::MAX).saturating_mul(3);
    assert_eq!(
        timeout, expected,
        "sleep_delay=u32::MAX must produce timeout={expected} via saturating_mul, got {timeout}",
    );
    assert!(timeout > 0, "timeout must never be zero");
}

#[test]
fn timeout_override_zero_produces_valid_sweep_interval() {
    // Profile with AgentTimeoutSecs = 0 → timeout_override_secs = Some(0).
    // sweep_secs = (0 / 3).clamp(1, 30) = 1 → sweep_interval must be 1 s (non-zero).
    // timeout_for must return 0 (the raw override), which means agents are immediately
    // considered stale — that is the operator's explicit choice.
    let profile = sample_profile(Some(0), 5);
    let config = AgentLivenessConfig::from_profile(&profile);

    assert_eq!(config.timeout_override_secs, Some(0));
    assert_eq!(
        config.sweep_interval,
        Duration::from_secs(1),
        "zero override must clamp sweep_interval to MIN_SWEEP_INTERVAL_SECS (1 s), got {:?}",
        config.sweep_interval,
    );

    let agent = sample_agent(0x0000_0030);
    let timeout = config.timeout_for(&agent);
    assert_eq!(timeout, 0, "timeout_override_secs=0 must propagate as timeout=0, got {timeout}",);
}
