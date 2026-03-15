//! Background liveness monitoring for agent inactivity timeouts.

use std::time::Duration;

use red_cell_common::AgentRecord;
use red_cell_common::config::Profile;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::warn;

use crate::{
    AgentRegistry, EventBus, SocketRelayManager, TeamserverError, agent_events::agent_mark_event,
};

const MIN_SWEEP_INTERVAL_SECS: u64 = 1;
const MAX_SWEEP_INTERVAL_SECS: u64 = 30;

#[derive(Clone, Copy, Debug)]
struct AgentLivenessConfig {
    timeout_override_secs: Option<u64>,
    default_sleep_secs: Option<u64>,
    sweep_interval: Duration,
}

impl AgentLivenessConfig {
    fn from_profile(profile: &Profile) -> Self {
        let timeout_override_secs = profile.teamserver.agent_timeout_secs;
        let default_sleep_secs = profile.demon.sleep.filter(|sleep| *sleep > 0);
        let effective_timeout_secs = timeout_override_secs.unwrap_or_else(|| {
            default_sleep_secs.unwrap_or(MIN_SWEEP_INTERVAL_SECS).saturating_mul(3)
        });
        let sweep_secs =
            (effective_timeout_secs / 3).clamp(MIN_SWEEP_INTERVAL_SECS, MAX_SWEEP_INTERVAL_SECS);

        Self {
            timeout_override_secs,
            default_sleep_secs,
            sweep_interval: Duration::from_secs(sweep_secs),
        }
    }

    fn timeout_for(self, agent: &AgentRecord) -> u64 {
        self.timeout_override_secs.unwrap_or_else(|| {
            let sleep_secs = u64::from(agent.sleep_delay).max(self.default_sleep_secs.unwrap_or(0));
            sleep_secs.max(MIN_SWEEP_INTERVAL_SECS).saturating_mul(3)
        })
    }
}

#[derive(Debug)]
struct StaleAgent {
    agent_id: u32,
    last_call_in: String,
    timeout_secs: u64,
}

/// Handle that owns the background agent liveness monitor task.
#[derive(Debug)]
pub struct AgentLivenessMonitor {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Drop for AgentLivenessMonitor {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

/// Start a background task that marks stale agents dead and cleans up relay state.
#[must_use]
pub fn spawn_agent_liveness_monitor(
    registry: AgentRegistry,
    sockets: SocketRelayManager,
    events: EventBus,
    profile: &Profile,
) -> AgentLivenessMonitor {
    let config = AgentLivenessConfig::from_profile(profile);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(config.sweep_interval);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = ticker.tick() => {
                    if let Err(error) = sweep_dead_agents_at(
                        &registry,
                        &sockets,
                        &events,
                        config,
                        OffsetDateTime::now_utc(),
                    ).await {
                        warn!(%error, "agent liveness sweep failed");
                    }
                }
            }
        }
    });

    AgentLivenessMonitor { shutdown: Some(shutdown_tx), task }
}

async fn sweep_dead_agents_at(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    config: AgentLivenessConfig,
    now: OffsetDateTime,
) -> Result<Vec<u32>, TeamserverError> {
    let stale_agents = collect_stale_agents(registry, config, now).await;
    let mut dead_agent_ids = Vec::new();

    for stale_agent in stale_agents {
        if mark_stale_agent_if_unchanged(registry, events, &stale_agent).await? {
            dead_agent_ids.push(stale_agent.agent_id);
        }
    }

    if !dead_agent_ids.is_empty() {
        let _ = sockets.prune_stale_agents().await;
    }

    dead_agent_ids.sort_unstable();
    Ok(dead_agent_ids)
}

async fn mark_stale_agent_if_unchanged(
    registry: &AgentRegistry,
    events: &EventBus,
    stale_agent: &StaleAgent,
) -> Result<bool, TeamserverError> {
    let Some(current) = registry.get(stale_agent.agent_id).await else {
        return Ok(false);
    };
    if !current.active || current.last_call_in != stale_agent.last_call_in {
        return Ok(false);
    }

    let reason =
        format!("agent timed out after {} seconds without callback", stale_agent.timeout_secs);
    registry.mark_dead(stale_agent.agent_id, reason).await?;

    if let Some(agent) = registry.get(stale_agent.agent_id).await {
        events.broadcast(agent_mark_event(&agent));
    }

    Ok(true)
}

async fn collect_stale_agents(
    registry: &AgentRegistry,
    config: AgentLivenessConfig,
    now: OffsetDateTime,
) -> Vec<StaleAgent> {
    let mut stale_agents = Vec::new();

    for agent in registry.list_active().await {
        let timeout_secs = config.timeout_for(&agent);
        let Some(last_call_in) = parse_timestamp(&agent.last_call_in) else {
            warn!(
                agent_id = format_args!("0x{:08X}", agent.agent_id),
                last_call_in = %agent.last_call_in,
                "skipping liveness timeout because last callback timestamp could not be parsed"
            );
            continue;
        };

        let elapsed_secs = (now - last_call_in).whole_seconds();
        if elapsed_secs >= i64::try_from(timeout_secs).unwrap_or(i64::MAX) {
            stale_agents.push(StaleAgent {
                agent_id: agent.agent_id,
                last_call_in: agent.last_call_in,
                timeout_secs,
            });
        }
    }

    stale_agents
}

fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use red_cell_common::AgentEncryptionInfo;
    use red_cell_common::config::Profile;
    use red_cell_common::operator::OperatorMessage;
    use tokio::time::timeout;
    use zeroize::Zeroizing;

    use super::{
        AgentLivenessConfig, AgentLivenessMonitor, collect_stale_agents,
        mark_stale_agent_if_unchanged, spawn_agent_liveness_monitor, sweep_dead_agents_at,
    };
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
            base_address: 0,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_arch: "x64".to_owned(),
            sleep_delay: 5,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-10T10:00:00Z".to_owned(),
            last_call_in: "2026-03-10T10:00:00Z".to_owned(),
        }
    }

    fn sample_profile(agent_timeout_secs: Option<u64>, demon_sleep_secs: u64) -> Profile {
        let timeout_line = agent_timeout_secs
            .map(|secs| format!("  AgentTimeoutSecs = {secs}\n"))
            .unwrap_or_default();
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
    async fn spawn_agent_liveness_monitor_starts_and_shuts_down_cleanly()
    -> Result<(), TeamserverError> {
        let profile = sample_profile(None, 5);
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database);
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());

        let monitor = spawn_agent_liveness_monitor(registry, sockets, events, &profile);
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
        let registry = AgentRegistry::new(database);
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());

        let monitor = spawn_agent_liveness_monitor(registry, sockets, events, &profile);
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
            TeamserverError::InvalidPersistedValue {
                field: "socket_relay",
                message: error.to_string(),
            }
        })?;
        let mut receiver = events.subscribe();

        let monitor = spawn_agent_liveness_monitor(
            registry.clone(),
            sockets.clone(),
            events.clone(),
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

        let stored = registry
            .get(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert!(!stored.active);
        assert_eq!(stored.reason, "agent timed out after 15 seconds without callback");
        assert_eq!(sockets.list_socks_servers(agent.agent_id).await, "No active SOCKS5 servers");

        let OperatorMessage::AgentUpdate(message) = event else {
            return Err(TeamserverError::InvalidPersistedValue {
                field: "operator_event",
                message: "expected AgentUpdate event".to_owned(),
            });
        };
        assert_eq!(message.info.agent_id, "C0DECAFE");
        assert_eq!(message.info.marked, "Dead");

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
            TeamserverError::InvalidPersistedValue {
                field: "socket_relay",
                message: error.to_string(),
            }
        })?;
        let mut receiver = events.subscribe();

        let dead = sweep_dead_agents_at(
            &registry,
            &sockets,
            &events,
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
        let registry = AgentRegistry::new(database);
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let mut agent = sample_agent(0xABCD_1234);
        agent.last_call_in = "not-a-timestamp".to_owned();
        registry.insert(agent.clone()).await?;

        let dead = sweep_dead_agents_at(
            &registry,
            &sockets,
            &events,
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

    #[tokio::test]
    async fn sweep_mixed_liveness_only_marks_stale_agents_dead() -> Result<(), TeamserverError> {
        // Two stale agents (IDs inserted in descending order to exercise the sort) and one
        // recently-active agent.  Only the stale pair must appear in `dead_agent_ids`; the
        // fresh agent must remain active = true in the registry.
        let profile = sample_profile(None, 5); // sleep=5 → timeout=15 s
        let config = AgentLivenessConfig::from_profile(&profile);
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database);
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
        let dead = sweep_dead_agents_at(&registry, &sockets, &events, config, now).await?;

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
        let registry = AgentRegistry::new(database);
        let events = EventBus::default();
        let mut agent = sample_agent(0xABCD_5678);
        registry.insert(agent.clone()).await?;

        let stale_agents = collect_stale_agents(
            &registry,
            config,
            time::macros::datetime!(2026-03-10 10:00:15 UTC),
        )
        .await;
        assert_eq!(stale_agents.len(), 1);
        assert_eq!(stale_agents[0].agent_id, agent.agent_id);

        agent.last_call_in = "2026-03-10T10:00:14Z".to_owned();
        registry.update_agent(agent.clone()).await?;

        let marked = mark_stale_agent_if_unchanged(&registry, &events, &stale_agents[0]).await?;

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
        let registry = AgentRegistry::new(database);
        let events = EventBus::default();
        let agent = sample_agent(0x1234_ABCD);
        registry.insert(agent.clone()).await?;

        // Collect stale agents — the agent qualifies (last_call_in is 15 s in the past).
        let stale_agents = collect_stale_agents(
            &registry,
            config,
            time::macros::datetime!(2026-03-10 10:00:15 UTC),
        )
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

        let marked = mark_stale_agent_if_unchanged(&registry, &events, &stale_agents[0]).await?;

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
}
