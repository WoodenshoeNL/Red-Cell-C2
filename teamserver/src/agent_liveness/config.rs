//! Liveness policy configuration derived from the operator profile.

use std::time::Duration;

use red_cell_common::AgentRecord;
use red_cell_common::config::Profile;

pub(super) const MIN_SWEEP_INTERVAL_SECS: u64 = 1;
pub(super) const MAX_SWEEP_INTERVAL_SECS: u64 = 30;

#[derive(Clone, Copy, Debug)]
pub(super) struct AgentLivenessConfig {
    pub(super) timeout_override_secs: Option<u64>,
    pub(super) default_sleep_secs: Option<u64>,
    pub(super) sweep_interval: Duration,
}

impl AgentLivenessConfig {
    pub(super) fn from_profile(profile: &Profile) -> Self {
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

    pub(super) fn timeout_for(self, agent: &AgentRecord) -> u64 {
        self.timeout_override_secs.unwrap_or_else(|| {
            let sleep_secs = u64::from(agent.sleep_delay).max(self.default_sleep_secs.unwrap_or(0));
            sleep_secs.max(MIN_SWEEP_INTERVAL_SECS).saturating_mul(3)
        })
    }
}

#[derive(Debug)]
pub(super) struct StaleAgent {
    pub(super) agent_id: u32,
    pub(super) last_call_in: String,
    pub(super) timeout_secs: u64,
}
