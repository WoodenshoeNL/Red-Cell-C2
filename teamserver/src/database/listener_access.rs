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

#[cfg(test)]
mod tests {
    use red_cell_common::{HttpListenerConfig, ListenerConfig};

    use crate::database::Database;

    fn stub_http_listener(name: &str) -> ListenerConfig {
        ListenerConfig::from(HttpListenerConfig {
            name: name.to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 8080,
            port_conn: None,
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
        })
    }

    #[tokio::test]
    async fn listener_access_unrestricted_by_default() {
        let db = Database::connect_in_memory().await.expect("db");
        db.listeners().create(&stub_http_listener("http-main")).await.expect("create");
        let repo = db.listener_access();
        assert!(repo.allowed_operators("http-main").await.expect("list").is_empty());
        assert!(repo.operator_may_use_listener("anyone", "http-main").await.expect("check"));
    }

    #[tokio::test]
    async fn listener_access_set_and_enforce() {
        let db = Database::connect_in_memory().await.expect("db");
        db.listeners().create(&stub_http_listener("exfil")).await.expect("create");
        let repo = db.listener_access();
        repo.set_allowed_operators("exfil", &["alice".to_owned()]).await.expect("set");
        assert!(repo.operator_may_use_listener("alice", "exfil").await.expect("check alice"));
        assert!(!repo.operator_may_use_listener("bob", "exfil").await.expect("check bob"));
    }

    #[tokio::test]
    async fn listener_access_set_empty_removes_restrictions() {
        let db = Database::connect_in_memory().await.expect("db");
        db.listeners().create(&stub_http_listener("http-test")).await.expect("create");
        let repo = db.listener_access();
        repo.set_allowed_operators("http-test", &["alice".to_owned()]).await.expect("set");
        repo.set_allowed_operators("http-test", &[]).await.expect("clear");
        assert!(repo.allowed_operators("http-test").await.expect("list").is_empty());
        assert!(repo.operator_may_use_listener("anyone", "http-test").await.expect("check"));
    }
}
