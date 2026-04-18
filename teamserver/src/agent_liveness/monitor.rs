//! Background monitor task: spawns the periodic sweep loop.

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::warn;

use red_cell_common::config::Profile;
use time::OffsetDateTime;

use crate::{AgentRegistry, Database, EventBus, SocketRelayManager};

use super::config::AgentLivenessConfig;
use super::sweep::sweep_dead_agents_at;

/// Handle that owns the background agent liveness monitor task.
#[derive(Debug)]
pub struct AgentLivenessMonitor {
    pub(super) shutdown: Option<oneshot::Sender<()>>,
    pub(super) task: JoinHandle<()>,
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
    database: Database,
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
                        &database,
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
