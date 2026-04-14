//! Teamserver bind settings, operators, logging, database, and build tooling.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::listeners::HttpListenerCertConfig;

/// Teamserver bind settings and payload build tooling.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TeamserverConfig {
    /// Host address to bind the teamserver to.
    #[serde(rename = "Host")]
    pub host: String,
    /// TCP port for the teamserver listener.
    #[serde(rename = "Port")]
    pub port: u16,
    /// Optional directory containing Python plugin modules.
    #[serde(rename = "PluginsDir", default)]
    pub plugins_dir: Option<String>,
    /// Maximum in-memory size of a single agent download before the server drops it.
    #[serde(rename = "MaxDownloadBytes", default)]
    pub max_download_bytes: Option<u64>,
    /// Maximum number of simultaneous in-progress downloads per agent.
    /// Defaults to 32 when absent.
    #[serde(rename = "MaxConcurrentDownloadsPerAgent", default)]
    pub max_concurrent_downloads_per_agent: Option<usize>,
    /// Aggregate in-memory cap across all active downloads (all agents combined).
    /// Defaults to 4× `MaxDownloadBytes` when absent.
    #[serde(rename = "MaxAggregateDownloadBytes", default)]
    pub max_aggregate_download_bytes: Option<u64>,
    /// Maximum pivot-chain dispatch nesting depth.
    ///
    /// When an inbound callback tunnels commands through a pivot chain, each
    /// recursive hop increments the dispatch depth. Once this limit is reached
    /// the pivot is rejected, an audit log entry is written, and an error is
    /// surfaced to the operator console for the triggering agent. Defaults to
    /// 10 when absent.
    #[serde(rename = "MaxPivotChainDepth", default)]
    pub max_pivot_chain_depth: Option<usize>,
    /// Maximum number of registered agents retained in memory and SQLite.
    #[serde(rename = "MaxRegisteredAgents", default)]
    pub max_registered_agents: Option<usize>,
    /// Graceful-shutdown drain timeout in seconds.
    #[serde(rename = "DrainTimeoutSecs", default)]
    pub drain_timeout_secs: Option<u64>,
    /// Optional agent inactivity timeout override in seconds.
    #[serde(rename = "AgentTimeoutSecs", default)]
    pub agent_timeout_secs: Option<u64>,
    /// Optional structured logging settings for the teamserver runtime.
    #[serde(rename = "Logging", default)]
    pub logging: Option<LoggingConfig>,
    /// Optional build toolchain settings.
    #[serde(rename = "Build", default)]
    pub build: Option<BuildConfig>,
    /// Optional TLS certificate and key paths for the control-plane listener.
    ///
    /// When set, the teamserver loads its TLS identity from these PEM files on every
    /// start instead of generating a fresh self-signed certificate. When absent, the
    /// teamserver generates a self-signed certificate on the first boot and persists it
    /// next to the profile file so that subsequent restarts reuse the same material.
    #[serde(rename = "Cert", default)]
    pub cert: Option<HttpListenerCertConfig>,
    /// Optional database resilience and backup configuration.
    #[serde(rename = "Database", default)]
    pub database: Option<DatabaseConfig>,
    /// Optional observability configuration for Prometheus metrics and OTel tracing.
    #[serde(rename = "Observability", default)]
    pub observability: Option<ObservabilityConfig>,
}

/// Database resilience and automated backup configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DatabaseConfig {
    /// Maximum duration in seconds to wait for a single DB query before treating
    /// it as a timeout.  Defaults to 5 seconds.
    #[serde(rename = "QueryTimeoutSecs", default)]
    pub query_timeout_secs: Option<u64>,
    /// Number of consecutive probe timeouts before the teamserver enters
    /// degraded mode and alerts connected operators.  Defaults to 3.
    #[serde(rename = "DegradedThreshold", default)]
    pub degraded_threshold: Option<u32>,
    /// Interval between database health-monitor probe cycles (both healthy and
    /// degraded states), in seconds.  Defaults to 10 seconds.
    #[serde(rename = "ProbeSecs", default)]
    pub probe_secs: Option<u64>,
    /// Directory to store automated database snapshots.
    /// When absent, automated backups are disabled.
    #[serde(rename = "BackupDir", default)]
    pub backup_dir: Option<String>,
    /// How often to take an automated hot backup, in seconds.
    /// Requires `BackupDir`.  Defaults to 3600 (1 hour).
    #[serde(rename = "BackupIntervalSecs", default)]
    pub backup_interval_secs: Option<u64>,
    /// Maximum number of deferred writes to buffer when the database is in
    /// degraded mode.  When the buffer fills, the oldest entry is evicted.
    /// Defaults to 1024.
    #[serde(rename = "WriteQueueCapacity", default)]
    pub write_queue_capacity: Option<usize>,
    /// Number of days to retain audit-log rows before automatic pruning.
    /// Defaults to 90 days.  Set to `0` to disable automatic pruning.
    #[serde(rename = "AuditRetentionDays", default)]
    pub audit_retention_days: Option<u32>,
    /// How often (in seconds) the audit-log pruner checks for expired rows.
    /// Defaults to 3600 (1 hour).  Only relevant when retention is enabled.
    #[serde(rename = "AuditPruneIntervalSecs", default)]
    pub audit_prune_interval_secs: Option<u64>,
}

/// Observability configuration for Prometheus metrics and OpenTelemetry tracing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ObservabilityConfig {
    /// Optional OpenTelemetry OTLP exporter endpoint (e.g. `http://localhost:4317`).
    /// When absent, OTel span export is disabled and no OTel dependencies are loaded
    /// at runtime.
    #[serde(rename = "OtlpEndpoint", default)]
    pub otlp_endpoint: Option<String>,
    /// Service name reported to the OTel collector.  Defaults to `"red-cell-teamserver"`.
    #[serde(rename = "ServiceName", default)]
    pub service_name: Option<String>,
}

/// Teamserver tracing configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LoggingConfig {
    /// Default log filter used when `RUST_LOG` is not set.
    #[serde(rename = "Level", default)]
    pub level: Option<String>,
    /// Formatter style used for stdout and optional file output.
    #[serde(rename = "Format", default)]
    pub format: Option<LogFormat>,
    /// Optional rolling-file output configuration.
    #[serde(rename = "File", default)]
    pub file: Option<LogFileConfig>,
}

/// Supported tracing output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum LogFormat {
    /// Human-readable, developer-oriented output.
    #[serde(rename = "Pretty", alias = "pretty")]
    Pretty,
    /// Structured JSON output for production ingestion.
    #[serde(rename = "Json", alias = "json")]
    Json,
}

/// Optional rolling-file tracing output configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LogFileConfig {
    /// Directory where rotated log files are written.
    #[serde(rename = "Directory")]
    pub directory: String,
    /// Stable filename prefix used by the rolling appender.
    #[serde(rename = "Prefix")]
    pub prefix: String,
    /// Rotation cadence for the log file.
    #[serde(rename = "Rotation", default)]
    pub rotation: Option<LogRotation>,
}

/// Supported file rotation cadences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum LogRotation {
    /// Never rotate the file.
    #[serde(rename = "Never", alias = "never")]
    Never,
    /// Rotate files hourly.
    #[serde(rename = "Hourly", alias = "hourly")]
    Hourly,
    /// Rotate files daily.
    #[serde(rename = "Daily", alias = "daily")]
    Daily,
    /// Rotate files minutely.
    #[serde(rename = "Minutely", alias = "minutely")]
    Minutely,
}

/// Cross-compilation toolchain settings used for Demon builds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BuildConfig {
    /// 64-bit MinGW compiler path.
    #[serde(rename = "Compiler64", default)]
    pub compiler64: Option<String>,
    /// 32-bit MinGW compiler path.
    #[serde(rename = "Compiler86", default)]
    pub compiler86: Option<String>,
    /// NASM executable path.
    #[serde(rename = "Nasm", default)]
    pub nasm: Option<String>,
}

/// Operator accounts defined in the profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OperatorsConfig {
    /// Operators keyed by their block label.
    #[serde(rename = "user", default)]
    pub users: BTreeMap<String, OperatorConfig>,
}

/// A single operator account definition.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct OperatorConfig {
    /// Operator password.
    #[serde(rename = "Password")]
    pub password: String,
    /// Operator role used by the teamserver RBAC layer.
    #[serde(rename = "Role", default)]
    pub role: OperatorRole,
}

impl fmt::Debug for OperatorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorConfig")
            .field("password", &"[redacted]")
            .field("role", &self.role)
            .finish()
    }
}

/// Role assigned to an operator account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, ToSchema)]
pub enum OperatorRole {
    /// Full teamserver access.
    #[default]
    #[serde(rename = "Admin", alias = "admin")]
    Admin,
    /// Can task agents and manage listeners.
    #[serde(rename = "Operator", alias = "operator")]
    Operator,
    /// Read-only access for agents, sessions, and loot.
    #[serde(rename = "Analyst", alias = "analyst")]
    Analyst,
}
