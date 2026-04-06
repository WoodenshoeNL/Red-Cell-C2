//! Operator CRUD repository.

use red_cell_common::config::OperatorRole;
use sqlx::{FromRow, SqlitePool};

use super::TeamserverError;

/// Persisted runtime operator credential record stored in SQLite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedOperator {
    /// Operator username.
    pub username: String,
    /// Stored password verifier for the operator's Havoc-compatible SHA3 password digest.
    pub password_verifier: String,
    /// RBAC role granted to the operator.
    pub role: OperatorRole,
}

/// CRUD operations for persisted runtime operators.
#[derive(Clone, Debug)]
pub struct OperatorRepository {
    pool: SqlitePool,
}

impl OperatorRepository {
    /// Create a new operator repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a runtime operator credential row.
    pub async fn create(&self, operator: &PersistedOperator) -> Result<(), TeamserverError> {
        sqlx::query(
            "INSERT INTO ts_runtime_operators (username, password_verifier, role) VALUES (?, ?, ?)",
        )
        .bind(&operator.username)
        .bind(&operator.password_verifier)
        .bind(operator_role_label(operator.role))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Fetch a runtime operator by username.
    pub async fn get(&self, username: &str) -> Result<Option<PersistedOperator>, TeamserverError> {
        let row = sqlx::query_as::<_, OperatorRow>(
            "SELECT username, password_verifier, role FROM ts_runtime_operators WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// Return all persisted runtime operators sorted by username.
    pub async fn list(&self) -> Result<Vec<PersistedOperator>, TeamserverError> {
        let rows = sqlx::query_as::<_, OperatorRow>(
            "SELECT username, password_verifier, role FROM ts_runtime_operators ORDER BY username",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Replace the stored verifier for a runtime operator.
    pub async fn update_password_verifier(
        &self,
        username: &str,
        password_verifier: &str,
    ) -> Result<(), TeamserverError> {
        sqlx::query("UPDATE ts_runtime_operators SET password_verifier = ? WHERE username = ?")
            .bind(password_verifier)
            .bind(username)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Delete a runtime operator by username.
    ///
    /// Returns `true` if a row was deleted, `false` if no matching row existed.
    pub async fn delete(&self, username: &str) -> Result<bool, TeamserverError> {
        let result = sqlx::query("DELETE FROM ts_runtime_operators WHERE username = ?")
            .bind(username)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update the role of a runtime operator.
    ///
    /// Returns `true` if a row was updated, `false` if no matching row existed.
    pub async fn update_role(
        &self,
        username: &str,
        role: OperatorRole,
    ) -> Result<bool, TeamserverError> {
        let result = sqlx::query("UPDATE ts_runtime_operators SET role = ? WHERE username = ?")
            .bind(operator_role_label(role))
            .bind(username)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }
}

const fn operator_role_label(role: OperatorRole) -> &'static str {
    match role {
        OperatorRole::Admin => "Admin",
        OperatorRole::Operator => "Operator",
        OperatorRole::Analyst => "Analyst",
    }
}

pub(super) fn parse_operator_role(value: &str) -> Result<OperatorRole, TeamserverError> {
    match value {
        "Admin" | "admin" => Ok(OperatorRole::Admin),
        "Operator" | "operator" => Ok(OperatorRole::Operator),
        "Analyst" | "analyst" => Ok(OperatorRole::Analyst),
        _ => Err(TeamserverError::InvalidPersistedValue {
            field: "ts_runtime_operators.role",
            message: format!("unsupported operator role `{value}`"),
        }),
    }
}

#[derive(Debug, FromRow)]
struct OperatorRow {
    username: String,
    password_verifier: String,
    role: String,
}

impl TryFrom<OperatorRow> for PersistedOperator {
    type Error = TeamserverError;

    fn try_from(row: OperatorRow) -> Result<Self, Self::Error> {
        Ok(Self {
            username: row.username,
            password_verifier: row.password_verifier,
            role: parse_operator_role(&row.role)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use red_cell_common::config::OperatorRole;

    use crate::database::Database;

    use super::{PersistedOperator, parse_operator_role};

    fn sample_operator(username: &str) -> PersistedOperator {
        PersistedOperator {
            username: username.to_string(),
            password_verifier: "argon2:initial_hash".to_string(),
            role: OperatorRole::Operator,
        }
    }

    #[tokio::test]
    async fn operator_update_password_verifier_succeeds_for_existing_user() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.operators();
        repo.create(&sample_operator("admin")).await.expect("create");
        repo.update_password_verifier("admin", "argon2:new_hash").await.expect("update");
        let fetched = repo.get("admin").await.expect("get").expect("should exist");
        assert_eq!(fetched.password_verifier, "argon2:new_hash");
    }

    #[tokio::test]
    async fn operator_update_password_verifier_silently_succeeds_for_nonexistent_user() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.operators();
        assert!(repo.update_password_verifier("ghost", "argon2:hash").await.is_ok());
        assert!(repo.get("ghost").await.expect("get").is_none());
    }

    #[tokio::test]
    async fn operator_create_and_get_round_trips() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.operators();
        repo.create(&sample_operator("testuser")).await.expect("create");
        let fetched = repo.get("testuser").await.expect("get").expect("should exist");
        assert_eq!(fetched.username, "testuser");
        assert_eq!(fetched.password_verifier, "argon2:initial_hash");
        assert_eq!(fetched.role, OperatorRole::Operator);
    }

    #[tokio::test]
    async fn operator_get_returns_none_for_missing_user() {
        let db = Database::connect_in_memory().await.expect("db");
        assert!(db.operators().get("nobody").await.expect("get").is_none());
    }

    #[tokio::test]
    async fn operator_repository_delete_removes_existing_row() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.operators();
        repo.create(&sample_operator("delme")).await.expect("create");
        assert!(repo.delete("delme").await.expect("delete"), "should delete existing row");
        assert!(repo.get("delme").await.expect("get").is_none(), "row should be gone");
    }

    #[tokio::test]
    async fn operator_repository_delete_returns_false_for_missing_user() {
        let db = Database::connect_in_memory().await.expect("db");
        assert!(!db.operators().delete("ghost").await.expect("delete"), "missing user → false");
    }

    #[tokio::test]
    async fn operator_repository_update_role_changes_stored_role() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.operators();
        let op = PersistedOperator {
            username: "rolechange".to_owned(),
            password_verifier: "v".to_owned(),
            role: OperatorRole::Analyst,
        };
        repo.create(&op).await.expect("create");
        assert!(repo.update_role("rolechange", OperatorRole::Admin).await.expect("update"));
        let updated = repo.get("rolechange").await.expect("get").expect("should exist");
        assert_eq!(updated.role, OperatorRole::Admin);
    }

    #[tokio::test]
    async fn operator_repository_update_role_returns_false_for_missing_user() {
        let db = Database::connect_in_memory().await.expect("db");
        assert!(!db.operators().update_role("ghost", OperatorRole::Admin).await.expect("update"));
    }

    #[test]
    fn parse_operator_role_accepts_titlecase() {
        assert_eq!(parse_operator_role("Admin").expect("parse"), OperatorRole::Admin);
        assert_eq!(parse_operator_role("Operator").expect("parse"), OperatorRole::Operator);
        assert_eq!(parse_operator_role("Analyst").expect("parse"), OperatorRole::Analyst);
    }

    #[test]
    fn parse_operator_role_accepts_lowercase() {
        assert_eq!(parse_operator_role("admin").expect("parse"), OperatorRole::Admin);
        assert_eq!(parse_operator_role("operator").expect("parse"), OperatorRole::Operator);
        assert_eq!(parse_operator_role("analyst").expect("parse"), OperatorRole::Analyst);
    }

    #[test]
    fn parse_operator_role_rejects_uppercase() {
        assert!(parse_operator_role("ADMIN").is_err());
        assert!(parse_operator_role("OPERATOR").is_err());
    }

    #[test]
    fn parse_operator_role_rejects_mixed_case() {
        assert!(parse_operator_role("aDmIn").is_err());
        assert!(parse_operator_role("oPeRaToR").is_err());
    }

    #[test]
    fn parse_operator_role_rejects_empty_and_unknown() {
        assert!(parse_operator_role("").is_err());
        assert!(parse_operator_role("root").is_err());
        assert!(parse_operator_role(" admin").is_err());
    }
}
