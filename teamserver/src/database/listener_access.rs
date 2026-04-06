//! Per-listener operator allow-list repository.

use sqlx::SqlitePool;

use super::TeamserverError;

/// Per-listener operator allow-list operations.
#[derive(Clone, Debug)]
pub struct ListenerAccessRepository {
    pool: SqlitePool,
}

impl ListenerAccessRepository {
    /// Create a new repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Return the usernames allowed to use `listener_name`.
    ///
    /// An empty result means the listener is unrestricted.
    pub async fn allowed_operators(
        &self,
        listener_name: &str,
    ) -> Result<Vec<String>, TeamserverError> {
        sqlx::query_scalar(
            "SELECT username FROM ts_listener_allowed_operators
             WHERE listener_name = ? ORDER BY username",
        )
        .bind(listener_name)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Replace the operator allow-list for `listener_name`.
    ///
    /// An empty `operators` slice removes all restrictions.
    pub async fn set_allowed_operators(
        &self,
        listener_name: &str,
        operators: &[String],
    ) -> Result<(), TeamserverError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM ts_listener_allowed_operators WHERE listener_name = ?")
            .bind(listener_name)
            .execute(&mut *tx)
            .await?;
        for username in operators {
            sqlx::query(
                "INSERT INTO ts_listener_allowed_operators (listener_name, username)
                 VALUES (?, ?)
                 ON CONFLICT(listener_name, username) DO NOTHING",
            )
            .bind(listener_name)
            .bind(username)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Return `true` when `username` is allowed to use `listener_name`.
    ///
    /// When the allow-list is empty returns `true` for everyone.
    pub async fn operator_may_use_listener(
        &self,
        username: &str,
        listener_name: &str,
    ) -> Result<bool, TeamserverError> {
        let allowed = self.allowed_operators(listener_name).await?;
        if allowed.is_empty() {
            return Ok(true);
        }
        Ok(allowed.iter().any(|u| u == username))
    }
}
