//! Agent group and operator-group-access repositories.

use sqlx::SqlitePool;

use super::TeamserverError;

/// CRUD and membership operations for named agent groups.
#[derive(Clone, Debug)]
pub struct AgentGroupRepository {
    pool: SqlitePool,
}

impl AgentGroupRepository {
    /// Create a new repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Ensure a group exists, creating it if it does not.  Idempotent.
    pub async fn ensure_group(&self, group_name: &str) -> Result<(), TeamserverError> {
        sqlx::query(
            "INSERT INTO ts_agent_groups (group_name) VALUES (?)
             ON CONFLICT(group_name) DO NOTHING",
        )
        .bind(group_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete a group (cascades to membership and operator-access rows).
    ///
    /// Returns `true` if a row was deleted.
    pub async fn delete_group(&self, group_name: &str) -> Result<bool, TeamserverError> {
        let result = sqlx::query("DELETE FROM ts_agent_groups WHERE group_name = ?")
            .bind(group_name)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Return all group names sorted alphabetically.
    pub async fn list_groups(&self) -> Result<Vec<String>, TeamserverError> {
        sqlx::query_scalar("SELECT group_name FROM ts_agent_groups ORDER BY group_name")
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Return all group names the given agent belongs to.
    pub async fn groups_for_agent(&self, agent_id: u32) -> Result<Vec<String>, TeamserverError> {
        sqlx::query_scalar(
            "SELECT group_name FROM ts_agent_group_members
             WHERE agent_id = ? ORDER BY group_name",
        )
        .bind(agent_id as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Return all agent IDs that belong to `group_name`.
    pub async fn agents_in_group(&self, group_name: &str) -> Result<Vec<u32>, TeamserverError> {
        let ids: Vec<i64> = sqlx::query_scalar(
            "SELECT agent_id FROM ts_agent_group_members
             WHERE group_name = ? ORDER BY agent_id",
        )
        .bind(group_name)
        .fetch_all(&self.pool)
        .await?;
        ids.into_iter().map(|v| super::u32_from_i64("ts_agent_group_members.agent_id", v)).collect()
    }

    /// Add `agent_id` to `group_name`.  The group must already exist.  No-ops
    /// if the membership already exists.
    pub async fn add_agent_to_group(
        &self,
        agent_id: u32,
        group_name: &str,
    ) -> Result<(), TeamserverError> {
        sqlx::query(
            "INSERT INTO ts_agent_group_members (agent_id, group_name) VALUES (?, ?)
             ON CONFLICT(agent_id, group_name) DO NOTHING",
        )
        .bind(agent_id as i64)
        .bind(group_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Remove `agent_id` from `group_name`.  Returns `true` if the membership existed.
    pub async fn remove_agent_from_group(
        &self,
        agent_id: u32,
        group_name: &str,
    ) -> Result<bool, TeamserverError> {
        let result =
            sqlx::query("DELETE FROM ts_agent_group_members WHERE agent_id = ? AND group_name = ?")
                .bind(agent_id as i64)
                .bind(group_name)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Replace the complete group membership for `agent_id`.
    ///
    /// All referenced groups are created automatically.  After the call the
    /// agent belongs to exactly the groups in `groups`.
    pub async fn set_agent_groups(
        &self,
        agent_id: u32,
        groups: &[String],
    ) -> Result<(), TeamserverError> {
        let mut tx = self.pool.begin().await?;
        for g in groups {
            sqlx::query(
                "INSERT INTO ts_agent_groups (group_name) VALUES (?)
                 ON CONFLICT(group_name) DO NOTHING",
            )
            .bind(g)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("DELETE FROM ts_agent_group_members WHERE agent_id = ?")
            .bind(agent_id as i64)
            .execute(&mut *tx)
            .await?;
        for g in groups {
            sqlx::query(
                "INSERT INTO ts_agent_group_members (agent_id, group_name) VALUES (?, ?)
                 ON CONFLICT(agent_id, group_name) DO NOTHING",
            )
            .bind(agent_id as i64)
            .bind(g)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Return the group names an operator is restricted to.
    ///
    /// An empty result means the operator is unrestricted.
    pub async fn operator_allowed_groups(
        &self,
        username: &str,
    ) -> Result<Vec<String>, TeamserverError> {
        sqlx::query_scalar(
            "SELECT group_name FROM ts_operator_group_access
             WHERE username = ? ORDER BY group_name",
        )
        .bind(username)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Replace the group-access restrictions for `username`.
    ///
    /// An empty `groups` slice removes all restrictions (operator becomes
    /// unrestricted).
    pub async fn set_operator_allowed_groups(
        &self,
        username: &str,
        groups: &[String],
    ) -> Result<(), TeamserverError> {
        let mut tx = self.pool.begin().await?;
        for g in groups {
            sqlx::query(
                "INSERT INTO ts_agent_groups (group_name) VALUES (?)
                 ON CONFLICT(group_name) DO NOTHING",
            )
            .bind(g)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("DELETE FROM ts_operator_group_access WHERE username = ?")
            .bind(username)
            .execute(&mut *tx)
            .await?;
        for g in groups {
            sqlx::query(
                "INSERT INTO ts_operator_group_access (username, group_name) VALUES (?, ?)
                 ON CONFLICT(username, group_name) DO NOTHING",
            )
            .bind(username)
            .bind(g)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Return `true` when `username` is allowed to task the agent that belongs
    /// to one of `agent_groups`.
    ///
    /// When the operator has no configured group restrictions returns `true`.
    pub async fn operator_may_task_agent(
        &self,
        username: &str,
        agent_groups: &[String],
    ) -> Result<bool, TeamserverError> {
        let allowed = self.operator_allowed_groups(username).await?;
        if allowed.is_empty() {
            return Ok(true);
        }
        Ok(agent_groups.iter().any(|ag| allowed.iter().any(|al| al == ag)))
    }
}
