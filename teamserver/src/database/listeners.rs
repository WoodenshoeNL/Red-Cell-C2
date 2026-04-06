//! Listener CRUD repository and lifecycle status types.

use red_cell_common::{ListenerConfig, ListenerProtocol};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use utoipa::ToSchema;

use super::TeamserverError;

/// Persisted listener record stored in SQLite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PersistedListener {
    /// Unique listener name.
    pub name: String,
    /// Transport protocol family.
    pub protocol: ListenerProtocol,
    /// Full listener configuration.
    pub config: ListenerConfig,
    /// Persisted runtime state.
    pub state: PersistedListenerState,
}

/// Persisted listener runtime state stored in SQLite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PersistedListenerState {
    /// Lifecycle status.
    pub status: ListenerStatus,
    /// Most recent start failure, if any.
    pub last_error: Option<String>,
}

/// Listener lifecycle status persisted in SQLite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum ListenerStatus {
    /// Listener is configured but has never been started in this database.
    Created,
    /// Listener runtime is active.
    Running,
    /// Listener runtime is currently stopped.
    Stopped,
    /// Listener failed to start or crashed unexpectedly.
    Error,
}

impl ListenerStatus {
    /// Return the canonical storage label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Error => "error",
        }
    }

    pub(super) fn try_from_str(value: &str) -> Result<Self, TeamserverError> {
        match value {
            "created" => Ok(Self::Created),
            "running" => Ok(Self::Running),
            "stopped" => Ok(Self::Stopped),
            "error" => Ok(Self::Error),
            _ => Err(TeamserverError::InvalidListenerState { state: value.to_owned() }),
        }
    }
}

/// CRUD operations for persisted listeners.
#[derive(Clone, Debug)]
pub struct ListenerRepository {
    pool: SqlitePool,
}

impl ListenerRepository {
    /// Create a new listener repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a listener configuration.
    pub async fn create(&self, listener: &ListenerConfig) -> Result<(), TeamserverError> {
        let config = serde_json::to_string(listener)?;
        sqlx::query(
            "INSERT INTO ts_listeners (name, protocol, config, status, last_error) VALUES (?, ?, ?, ?, ?)",
        )
            .bind(listener.name())
            .bind(listener.protocol().as_str())
            .bind(config)
            .bind(ListenerStatus::Created.as_str())
            .bind(Option::<String>::None)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Replace the stored configuration for a listener name.
    pub async fn update(&self, listener: &ListenerConfig) -> Result<(), TeamserverError> {
        let config = serde_json::to_string(listener)?;
        sqlx::query("UPDATE ts_listeners SET protocol = ?, config = ? WHERE name = ?")
            .bind(listener.protocol().as_str())
            .bind(config)
            .bind(listener.name())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Fetch a listener by name.
    pub async fn get(&self, name: &str) -> Result<Option<PersistedListener>, TeamserverError> {
        let row = sqlx::query_as::<_, ListenerRow>(
            "SELECT name, protocol, config, status, last_error FROM ts_listeners WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// List all listeners.
    pub async fn list(&self) -> Result<Vec<PersistedListener>, TeamserverError> {
        let rows = sqlx::query_as::<_, ListenerRow>(
            "SELECT name, protocol, config, status, last_error FROM ts_listeners ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Return all listener names.
    pub async fn names(&self) -> Result<Vec<String>, TeamserverError> {
        sqlx::query_scalar("SELECT name FROM ts_listeners ORDER BY name")
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Return the total number of listeners.
    pub async fn count(&self) -> Result<i64, TeamserverError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM ts_listeners")
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Check whether a listener row exists.
    pub async fn exists(&self, name: &str) -> Result<bool, TeamserverError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ts_listeners WHERE name = ?")
            .bind(name)
            .fetch_one(&self.pool)
            .await?;

        Ok(count > 0)
    }

    /// Delete a listener row.
    pub async fn delete(&self, name: &str) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_listeners WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Update only the runtime state fields for a listener.
    pub async fn set_state(
        &self,
        name: &str,
        status: ListenerStatus,
        last_error: Option<&str>,
    ) -> Result<(), TeamserverError> {
        sqlx::query("UPDATE ts_listeners SET status = ?, last_error = ? WHERE name = ?")
            .bind(status.as_str())
            .bind(last_error)
            .bind(name)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[derive(Debug, FromRow)]
struct ListenerRow {
    name: String,
    protocol: String,
    config: String,
    status: String,
    last_error: Option<String>,
}

impl TryFrom<ListenerRow> for PersistedListener {
    type Error = TeamserverError;

    fn try_from(row: ListenerRow) -> Result<Self, Self::Error> {
        let protocol = ListenerProtocol::try_from_str(&row.protocol)
            .map_err(|error| super::invalid_value("protocol", &error.to_string()))?;
        let config: ListenerConfig = serde_json::from_str(&row.config)?;
        let status = ListenerStatus::try_from_str(&row.status)?;

        Ok(Self {
            name: row.name,
            protocol,
            config,
            state: PersistedListenerState { status, last_error: row.last_error },
        })
    }
}
