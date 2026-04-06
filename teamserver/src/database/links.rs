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

#[cfg(test)]
mod tests {
    use red_cell_common::{AgentEncryptionInfo, AgentRecord};
    use zeroize::Zeroizing;

    use crate::database::Database;

    use super::LinkRecord;

    fn stub_agent(agent_id: u32) -> AgentRecord {
        AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(b"k".to_vec()),
                aes_iv: Zeroizing::new(b"i".to_vec()),
            },
            hostname: String::new(),
            username: String::new(),
            domain_name: String::new(),
            external_ip: String::new(),
            internal_ip: String::new(),
            process_name: String::new(),
            process_path: String::new(),
            base_address: 0,
            process_pid: 0,
            process_tid: 0,
            process_ppid: 0,
            process_arch: String::new(),
            elevated: false,
            os_version: String::new(),
            os_build: 0,
            os_arch: String::new(),
            sleep_delay: 0,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: String::new(),
            last_call_in: String::new(),
        }
    }

    async fn seed_agents(db: &Database, ids: &[u32]) {
        for &id in ids {
            db.agents().create(&stub_agent(id)).await.expect("seed_agent");
        }
    }

    /// Seed agents and create a link chain A→B→C.
    async fn seed_link_chain(db: &Database, a: u32, b: u32, c: u32) {
        seed_agents(db, &[a, b, c]).await;
        let links = db.links();
        links.create(LinkRecord { parent_agent_id: a, link_agent_id: b }).await.expect("create");
        links.create(LinkRecord { parent_agent_id: b, link_agent_id: c }).await.expect("create");
    }

    #[tokio::test]
    async fn link_chain_children_of_returns_direct_children_only() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_link_chain(&db, 1, 2, 3).await;
        let links = db.links();

        let children_of_a = links.children_of(1).await.expect("children_of");
        assert_eq!(children_of_a, vec![2], "A should have only direct child B");

        let children_of_b = links.children_of(2).await.expect("children_of");
        assert_eq!(children_of_b, vec![3], "B should have only direct child C");

        assert!(links.children_of(3).await.expect("children_of").is_empty(), "C is a leaf");
    }

    #[tokio::test]
    async fn link_delete_parent_removes_only_direct_link() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_link_chain(&db, 1, 2, 3).await;
        let links = db.links();

        links.delete(1, 2).await.expect("delete");

        assert!(!links.exists(1, 2).await.expect("exists"), "A→B link should be gone");
        assert!(links.exists(2, 3).await.expect("exists"), "B→C link should still exist");
        assert_eq!(links.parent_of(2).await.expect("parent_of"), None, "B should have no parent");
        assert_eq!(links.parent_of(3).await.expect("parent_of"), Some(2), "C still has parent B");
    }

    #[tokio::test]
    async fn link_cascade_simulation_marks_all_transitive_children() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_link_chain(&db, 1, 2, 3).await;
        let links = db.links();

        let mut affected = vec![2u32];
        let mut queue = vec![2u32];
        while let Some(node) = queue.pop() {
            let children = links.children_of(node).await.expect("children_of");
            for &child in &children {
                affected.push(child);
                queue.push(child);
            }
        }
        assert_eq!(affected, vec![2, 3], "subtree of B should include B and C");

        links.delete(1, 2).await.expect("delete");

        let remaining = links.list().await.expect("list");
        assert_eq!(remaining.len(), 1, "only B→C should remain");
        assert_eq!(remaining[0].parent_agent_id, 2);
        assert_eq!(remaining[0].link_agent_id, 3);
    }

    #[tokio::test]
    async fn link_delete_nonexistent_returns_ok() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[10, 20]).await;
        assert!(
            db.links().delete(10, 20).await.is_ok(),
            "deleting non-existent link should not error"
        );
    }

    #[tokio::test]
    async fn link_relink_after_disconnect_succeeds() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[1, 2]).await;
        let links = db.links();

        links.create(LinkRecord { parent_agent_id: 1, link_agent_id: 2 }).await.expect("create");
        assert!(links.exists(1, 2).await.expect("exists"));

        links.delete(1, 2).await.expect("delete");
        assert!(!links.exists(1, 2).await.expect("exists"));

        links.create(LinkRecord { parent_agent_id: 1, link_agent_id: 2 }).await.expect("re-create");
        assert!(links.exists(1, 2).await.expect("exists"), "re-linked A→B should exist");
        assert_eq!(links.parent_of(2).await.expect("parent_of"), Some(1));
    }

    #[tokio::test]
    async fn link_list_returns_all_links_in_chain() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_link_chain(&db, 10, 20, 30).await;
        let all = db.links().list().await.expect("list");
        assert_eq!(all.len(), 2);
        assert_eq!(
            all,
            vec![
                LinkRecord { parent_agent_id: 10, link_agent_id: 20 },
                LinkRecord { parent_agent_id: 20, link_agent_id: 30 },
            ]
        );
    }

    #[tokio::test]
    async fn link_parent_of_returns_correct_parent() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_link_chain(&db, 5, 6, 7).await;
        let links = db.links();

        assert_eq!(links.parent_of(5).await.expect("parent_of"), None, "root has no parent");
        assert_eq!(links.parent_of(6).await.expect("parent_of"), Some(5));
        assert_eq!(links.parent_of(7).await.expect("parent_of"), Some(6));
        assert_eq!(links.parent_of(99).await.expect("parent_of"), None, "unknown has no parent");
    }
}
