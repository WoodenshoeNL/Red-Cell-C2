//! Pivot-link CRUD repository.

use sqlx::{Row, SqlitePool};

use super::TeamserverError;

/// Parent/child pivot relationship between agents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkRecord {
    /// Upstream agent identifier.
    pub parent_agent_id: u32,
    /// Downstream linked agent identifier.
    pub link_agent_id: u32,
}

/// CRUD operations for persisted pivot links.
#[derive(Clone, Debug)]
pub struct LinkRepository {
    pool: SqlitePool,
}

impl LinkRepository {
    /// Create a new link repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a parent/link relationship.
    pub async fn create(&self, link: LinkRecord) -> Result<(), TeamserverError> {
        sqlx::query("INSERT INTO ts_links (parent_agent_id, link_agent_id) VALUES (?, ?)")
            .bind(i64::from(link.parent_agent_id))
            .bind(i64::from(link.link_agent_id))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Check whether a parent/link relationship exists.
    pub async fn exists(
        &self,
        parent_agent_id: u32,
        link_agent_id: u32,
    ) -> Result<bool, TeamserverError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ts_links WHERE parent_agent_id = ? AND link_agent_id = ?",
        )
        .bind(i64::from(parent_agent_id))
        .bind(i64::from(link_agent_id))
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Return the parent agent for a linked child.
    pub async fn parent_of(&self, link_agent_id: u32) -> Result<Option<u32>, TeamserverError> {
        let parent = sqlx::query_scalar::<_, i64>(
            "SELECT parent_agent_id FROM ts_links WHERE link_agent_id = ?",
        )
        .bind(i64::from(link_agent_id))
        .fetch_optional(&self.pool)
        .await?;

        parent.map(|value| super::u32_from_i64("parent_agent_id", value)).transpose()
    }

    /// Return all directly linked child agents for a parent.
    pub async fn children_of(&self, parent_agent_id: u32) -> Result<Vec<u32>, TeamserverError> {
        let children = sqlx::query_scalar::<_, i64>(
            "SELECT link_agent_id FROM ts_links WHERE parent_agent_id = ? ORDER BY link_agent_id",
        )
        .bind(i64::from(parent_agent_id))
        .fetch_all(&self.pool)
        .await?;

        children.into_iter().map(|value| super::u32_from_i64("link_agent_id", value)).collect()
    }

    /// Return all stored pivot links.
    pub async fn list(&self) -> Result<Vec<LinkRecord>, TeamserverError> {
        let rows = sqlx::query(
            "SELECT parent_agent_id, link_agent_id FROM ts_links ORDER BY parent_agent_id, link_agent_id",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(LinkRecord {
                    parent_agent_id: super::u32_from_i64(
                        "parent_agent_id",
                        row.get("parent_agent_id"),
                    )?,
                    link_agent_id: super::u32_from_i64("link_agent_id", row.get("link_agent_id"))?,
                })
            })
            .collect()
    }

    /// Delete a parent/link relationship.
    pub async fn delete(
        &self,
        parent_agent_id: u32,
        link_agent_id: u32,
    ) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_links WHERE parent_agent_id = ? AND link_agent_id = ?")
            .bind(i64::from(parent_agent_id))
            .bind(i64::from(link_agent_id))
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
