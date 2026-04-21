//! Agent-response repository: persisted callback output from agents.

use serde_json::Value;
use sqlx::{FromRow, SqlitePool};

use crate::database::TeamserverError;

/// Persisted agent response entry captured from a callback.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentResponseRecord {
    /// Database-assigned primary key.
    pub id: Option<i64>,
    /// Source agent identifier.
    pub agent_id: u32,
    /// Callback command identifier.
    pub command_id: u32,
    /// Original teamserver request identifier.
    pub request_id: u32,
    /// Response severity/type label.
    pub response_type: String,
    /// Human-readable status text.
    pub message: String,
    /// Raw output string emitted by the agent.
    pub output: String,
    /// Operator command line associated with the request, when known.
    pub command_line: Option<String>,
    /// Stable task identifier associated with the request, when known.
    pub task_id: Option<String>,
    /// Operator username associated with the request, when known.
    pub operator: Option<String>,
    /// Response timestamp string.
    pub received_at: String,
    /// Optional structured metadata payload.
    pub extra: Option<Value>,
}

/// CRUD operations for persisted agent-response rows.
#[derive(Clone, Debug)]
pub struct AgentResponseRepository {
    pool: SqlitePool,
}

impl AgentResponseRepository {
    /// Create a new agent-response repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert an agent-response row and return its generated primary key.
    pub async fn create(&self, response: &AgentResponseRecord) -> Result<i64, TeamserverError> {
        let extra = response.extra.as_ref().map(serde_json::to_string).transpose()?;
        let result = sqlx::query(
            r#"
            INSERT INTO ts_agent_responses (
                agent_id, command_id, request_id, response_type, message, output,
                command_line, task_id, operator, received_at, extra
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(i64::from(response.agent_id))
        .bind(i64::from(response.command_id))
        .bind(i64::from(response.request_id))
        .bind(&response.response_type)
        .bind(&response.message)
        .bind(&response.output)
        .bind(&response.command_line)
        .bind(&response.task_id)
        .bind(&response.operator)
        .bind(&response.received_at)
        .bind(extra)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Fetch a single agent-response row by id.
    pub async fn get(&self, id: i64) -> Result<Option<AgentResponseRecord>, TeamserverError> {
        let row =
            sqlx::query_as::<_, AgentResponseRow>("SELECT * FROM ts_agent_responses WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// List all persisted responses for an agent.
    pub async fn list_for_agent(
        &self,
        agent_id: u32,
    ) -> Result<Vec<AgentResponseRecord>, TeamserverError> {
        let rows = sqlx::query_as::<_, AgentResponseRow>(
            "SELECT * FROM ts_agent_responses WHERE agent_id = ? ORDER BY id",
        )
        .bind(i64::from(agent_id))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// List persisted responses for an agent with cursor-based pagination.
    ///
    /// When `since_id` is `Some(id)`, only rows with `id > since_id` are
    /// returned, enabling efficient polling for new output.
    pub async fn list_for_agent_since(
        &self,
        agent_id: u32,
        since_id: Option<i64>,
    ) -> Result<Vec<AgentResponseRecord>, TeamserverError> {
        let min_id = since_id.unwrap_or(0);
        let rows = sqlx::query_as::<_, AgentResponseRow>(
            "SELECT * FROM ts_agent_responses WHERE agent_id = ? AND id > ? ORDER BY id",
        )
        .bind(i64::from(agent_id))
        .bind(min_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Return every persisted response in insertion order.
    pub async fn list(&self) -> Result<Vec<AgentResponseRecord>, TeamserverError> {
        let rows =
            sqlx::query_as::<_, AgentResponseRow>("SELECT * FROM ts_agent_responses ORDER BY id")
                .fetch_all(&self.pool)
                .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Delete an agent-response row by id.
    pub async fn delete(&self, id: i64) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_agent_responses WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[derive(Debug, FromRow)]
struct AgentResponseRow {
    id: i64,
    agent_id: i64,
    command_id: i64,
    request_id: i64,
    response_type: String,
    message: String,
    output: String,
    command_line: Option<String>,
    task_id: Option<String>,
    operator: Option<String>,
    received_at: String,
    extra: Option<String>,
}

impl TryFrom<AgentResponseRow> for AgentResponseRecord {
    type Error = TeamserverError;

    fn try_from(row: AgentResponseRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Some(row.id),
            agent_id: super::super::u32_from_i64("agent_id", row.agent_id)?,
            command_id: super::super::u32_from_i64("command_id", row.command_id)?,
            request_id: super::super::u32_from_i64("request_id", row.request_id)?,
            response_type: row.response_type,
            message: row.message,
            output: row.output,
            command_line: row.command_line,
            task_id: row.task_id,
            operator: row.operator,
            received_at: row.received_at,
            extra: row.extra.map(|value| serde_json::from_str(&value)).transpose()?,
        })
    }
}
