//! Health-check endpoint and response types.

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use tracing::warn;
use utoipa::ToSchema;

use crate::PluginHealthEntry;
use crate::app::TeamserverState;

use super::auth::ReadApiAccess;

/// Subsystem that failed while assembling the health snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum HealthFailedSubsystem {
    /// Listener inventory could not be read from the listener manager.
    Listeners,
    /// The global plugin runtime handle could not be read (for example mutex poisoned).
    Plugins,
}

/// One failed health probe — preserves the error for operators and monitors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct HealthSubsystemError {
    /// Which subsystem failed.
    subsystem: HealthFailedSubsystem,
    /// Display string of the underlying error.
    message: String,
}

/// Agent population counts returned by the health endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct HealthAgentCounts {
    /// Number of agents currently marked active.
    active: u64,
    /// Total number of agents tracked (active + dead).
    total: u64,
}

/// Listener population counts returned by the health endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct HealthListenerCounts {
    /// Number of listeners currently running.
    running: u64,
    /// Number of listeners that are stopped, created, or in error state.
    stopped: u64,
}

/// Python plugin load counts returned by the health endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct HealthPluginCounts {
    /// Number of plugins successfully loaded at startup.
    loaded: u32,
    /// Number of plugins that failed to load at startup.
    failed: u32,
    /// Number of plugins currently auto-disabled due to repeated runtime failures.
    disabled: u32,
}

/// Runtime health entry for a single loaded Python plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct HealthPluginEntry {
    /// Name of the `.py` module (without extension).
    name: String,
    /// Number of consecutive callback/command failures since the last success.
    consecutive_failures: u32,
    /// Whether the plugin has been automatically disabled.
    disabled: bool,
}

impl From<PluginHealthEntry> for HealthPluginEntry {
    fn from(entry: PluginHealthEntry) -> Self {
        Self {
            name: entry.plugin_name,
            consecutive_failures: entry.consecutive_failures,
            disabled: entry.disabled,
        }
    }
}

/// Full health check response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct HealthResponse {
    /// Overall health status — `"ok"` only when the database probe and all
    /// subsystem inventory probes succeed; `"degraded"` when the database is unhealthy
    /// or any entry appears in [`Self::subsystem_errors`].
    status: String,
    /// Seconds since the teamserver process started.
    uptime_secs: u64,
    /// Number of operators currently connected via WebSocket.
    active_operators: u64,
    /// Agent inventory counts.
    agents: HealthAgentCounts,
    /// Listener lifecycle counts.
    listeners: HealthListenerCounts,
    /// Database probe result — `"ok"` or `"degraded"`.
    database: String,
    /// Python plugin load counts.
    plugins: HealthPluginCounts,
    /// Per-plugin runtime health (only populated when plugins are loaded).
    plugin_health: Vec<HealthPluginEntry>,
    /// Subsystem collection failures (empty when listener list and plugin runtime probe both succeed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    subsystem_errors: Vec<HealthSubsystemError>,
}

#[utoipa::path(
    get,
    path = "/health",
    context_path = "/api/v1",
    tag = "rest",
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Teamserver health snapshot", body = HealthResponse),
        (status = 401, description = "Missing or invalid API key", body = super::errors::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = super::errors::ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = super::errors::ApiErrorBody)
    )
)]
pub(super) async fn get_health(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
) -> Json<HealthResponse> {
    let uptime_secs = state.started_at.elapsed().as_secs();
    let active_operators = state.connections.authenticated_count().await as u64;

    let all_agents = state.agent_registry.list().await;
    let active = all_agents.iter().filter(|a| a.active).count() as u64;
    let total = all_agents.len() as u64;

    let mut subsystem_errors: Vec<HealthSubsystemError> = Vec::new();

    let (running, stopped) = match state.listeners.list().await {
        Ok(all_listeners) => {
            let running = all_listeners
                .iter()
                .filter(|l| l.state.status == crate::ListenerStatus::Running)
                .count() as u64;
            let stopped = all_listeners
                .iter()
                .filter(|l| l.state.status != crate::ListenerStatus::Running)
                .count() as u64;
            (running, stopped)
        }
        Err(error) => {
            warn!(%error, "health snapshot: failed to list listeners");
            subsystem_errors.push(HealthSubsystemError {
                subsystem: HealthFailedSubsystem::Listeners,
                message: error.to_string(),
            });
            (0, 0)
        }
    };

    let db_ok = state.database.probe(std::time::Duration::from_millis(500)).await;
    let db_status = if db_ok { "ok".to_owned() } else { "degraded".to_owned() };

    let plugin_health: Vec<HealthPluginEntry> = match crate::PluginRuntime::current() {
        Ok(Some(rt)) => {
            rt.plugin_health_summary().into_iter().map(HealthPluginEntry::from).collect()
        }
        Ok(None) => Vec::new(),
        Err(error) => {
            warn!(%error, "health snapshot: failed to read plugin runtime handle");
            subsystem_errors.push(HealthSubsystemError {
                subsystem: HealthFailedSubsystem::Plugins,
                message: error.to_string(),
            });
            Vec::new()
        }
    };
    let disabled_count = plugin_health.iter().filter(|e| e.disabled).count() as u32;

    let overall = overall_health_status(&db_status, &subsystem_errors);

    Json(HealthResponse {
        status: overall,
        uptime_secs,
        active_operators,
        agents: HealthAgentCounts { active, total },
        listeners: HealthListenerCounts { running, stopped },
        database: db_status,
        plugins: HealthPluginCounts {
            loaded: state.plugins_loaded,
            failed: state.plugins_failed,
            disabled: disabled_count,
        },
        plugin_health,
        subsystem_errors,
    })
}

/// Fold database status and subsystem probe outcomes into the single `status` string.
fn overall_health_status(database: &str, subsystem_errors: &[HealthSubsystemError]) -> String {
    if database != "ok" || !subsystem_errors.is_empty() {
        "degraded".to_owned()
    } else {
        "ok".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overall_ok_only_when_db_ok_and_no_subsystem_errors() {
        assert_eq!(overall_health_status("ok", &[]), "ok",);
    }

    #[test]
    fn overall_degraded_when_database_degraded() {
        assert_eq!(overall_health_status("degraded", &[]), "degraded",);
    }

    #[test]
    fn health_response_omits_empty_subsystem_errors_in_json() {
        let body = HealthResponse {
            status: "ok".to_owned(),
            uptime_secs: 1,
            active_operators: 0,
            agents: HealthAgentCounts { active: 0, total: 0 },
            listeners: HealthListenerCounts { running: 0, stopped: 0 },
            database: "ok".to_owned(),
            plugins: HealthPluginCounts { loaded: 0, failed: 0, disabled: 0 },
            plugin_health: vec![],
            subsystem_errors: vec![],
        };
        let v = serde_json::to_value(&body).expect("serialize");
        assert!(v.get("subsystem_errors").is_none());
    }

    #[test]
    fn health_response_serializes_subsystem_errors_when_present() {
        let body = HealthResponse {
            status: "degraded".to_owned(),
            uptime_secs: 0,
            active_operators: 0,
            agents: HealthAgentCounts { active: 0, total: 0 },
            listeners: HealthListenerCounts { running: 0, stopped: 0 },
            database: "ok".to_owned(),
            plugins: HealthPluginCounts { loaded: 0, failed: 0, disabled: 0 },
            plugin_health: vec![],
            subsystem_errors: vec![HealthSubsystemError {
                subsystem: HealthFailedSubsystem::Plugins,
                message: "plugin runtime mutex poisoned".to_owned(),
            }],
        };
        let v = serde_json::to_value(&body).expect("serialize");
        let errs = v.get("subsystem_errors").expect("subsystem_errors present");
        assert_eq!(errs[0]["subsystem"], "plugins");
        assert_eq!(errs[0]["message"], "plugin runtime mutex poisoned");
    }
}
