//! Health-check endpoint and response types.

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use crate::PluginHealthEntry;
use crate::app::TeamserverState;

use super::auth::ReadApiAccess;

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
    /// Overall health status — `"ok"` when all subsystems are healthy.
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

    let all_listeners = state.listeners.list().await.unwrap_or_default();
    let running =
        all_listeners.iter().filter(|l| l.state.status == crate::ListenerStatus::Running).count()
            as u64;
    let stopped =
        all_listeners.iter().filter(|l| l.state.status != crate::ListenerStatus::Running).count()
            as u64;

    let db_ok = state.database.probe(std::time::Duration::from_millis(500)).await;
    let db_status = if db_ok { "ok".to_owned() } else { "degraded".to_owned() };

    let plugin_health: Vec<HealthPluginEntry> = crate::PluginRuntime::current()
        .ok()
        .flatten()
        .map(|rt| rt.plugin_health_summary().into_iter().map(HealthPluginEntry::from).collect())
        .unwrap_or_default();
    let disabled_count = plugin_health.iter().filter(|e| e.disabled).count() as u32;

    let overall = db_status.clone();

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
    })
}
