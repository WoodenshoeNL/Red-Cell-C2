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
