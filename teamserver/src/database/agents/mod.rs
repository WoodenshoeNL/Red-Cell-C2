//! Agent CRUD repository.

mod row;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use red_cell_common::AgentRecord;
use sqlx::{Sqlite, SqlitePool};

use super::TeamserverError;
use super::crypto::DbMasterKey;
use row::{AgentRow, row_to_agent_record, row_to_persisted_agent, update_agent_ctr_block_offset};

/// Persisted agent row plus transport state needed by the in-memory registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedAgent {
    /// Agent metadata mirrored into operator-facing APIs.
    pub info: AgentRecord,
    /// Listener that accepted the current or most recent session.
    pub listener_name: String,
    /// Shared AES-CTR block offset tracked across decrypt/encrypt operations.
    pub ctr_block_offset: u64,
    /// When `true`, AES-CTR resets to block offset 0 for every packet (Demon/Archon
    /// compatibility).  When `false`, the monotonic `ctr_block_offset` advances across
    /// packets (Specter behaviour).
    pub legacy_ctr: bool,
    /// Last callback sequence number accepted from this agent.  `0` means no seq-protected
    /// callback has been received yet.
    pub last_seen_seq: u64,
    /// When `true`, the teamserver enforces monotonic sequence numbers on incoming callbacks.
    /// Demon and Archon agents (frozen wire format) are exempt (`false`).
    pub seq_protected: bool,
}

/// CRUD operations for persisted agents.
#[derive(Clone, Debug)]
pub struct AgentRepository {
    pool: SqlitePool,
    /// Master key used to encrypt/decrypt the `aes_key_enc` / `aes_iv_enc` columns.
    master_key: Arc<DbMasterKey>,
}

impl AgentRepository {
    /// Create a new agent repository from a shared pool and database master key.
    #[must_use]
    pub fn new(pool: SqlitePool, master_key: Arc<DbMasterKey>) -> Self {
        Self { pool, master_key }
    }

    /// Insert a new agent row.
    pub async fn create(&self, agent: &AgentRecord) -> Result<(), TeamserverError> {
        self.create_with_listener(agent, "null").await
    }

    /// Insert a new agent row with the listener that accepted the session.
    pub async fn create_with_listener(
        &self,
        agent: &AgentRecord,
        listener_name: &str,
    ) -> Result<(), TeamserverError> {
        self.create_with_listener_and_ctr_offset(agent, listener_name, 0).await
    }

    /// Insert a new agent row with the listener and initial CTR state for the session.
    ///
    /// Uses non-legacy (monotonic) CTR mode.  Use [`AgentRepository::create_full`] to
    /// set legacy mode for Demon/Archon agents.
    pub async fn create_with_listener_and_ctr_offset(
        &self,
        agent: &AgentRecord,
        listener_name: &str,
        ctr_block_offset: u64,
    ) -> Result<(), TeamserverError> {
        self.create_full(agent, listener_name, ctr_block_offset, false, false).await
    }

    /// Insert a new agent row with all transport parameters.
    ///
    /// `seq_protected` records whether the agent negotiated callback sequence-number
    /// replay protection (via the `INIT_EXT_SEQ_PROTECTED` extension flag) and is
    /// persisted atomically with the agent row.
    pub async fn create_full(
        &self,
        agent: &AgentRecord,
        listener_name: &str,
        ctr_block_offset: u64,
        legacy_ctr: bool,
        seq_protected: bool,
    ) -> Result<(), TeamserverError> {
        let enc_key = self.master_key.encrypt(&agent.encryption.aes_key)?;
        let enc_iv = self.master_key.encrypt(&agent.encryption.aes_iv)?;
        let mut transaction = self.pool.begin().await?;
        insert_agent_row(
            &mut *transaction,
            agent,
            listener_name,
            ctr_block_offset,
            legacy_ctr,
            seq_protected,
            &enc_key,
            &enc_iv,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Update an existing agent row.
    pub async fn update(&self, agent: &AgentRecord) -> Result<(), TeamserverError> {
        self.update_with_listener(agent, "null").await
    }

    /// Update an existing agent row and the listener that accepted the session.
    pub async fn update_with_listener(
        &self,
        agent: &AgentRecord,
        listener_name: &str,
    ) -> Result<(), TeamserverError> {
        let enc_key = self.master_key.encrypt(&agent.encryption.aes_key)?;
        let enc_iv = self.master_key.encrypt(&agent.encryption.aes_iv)?;
        let result = sqlx::query(
            r#"
            UPDATE ts_agents SET
                active = ?, reason = ?, note = ?,
                aes_key = '', aes_iv = '', aes_key_enc = ?, aes_iv_enc = ?,
                hostname = ?, username = ?,
                domain_name = ?, external_ip = ?, internal_ip = ?, process_name = ?, process_path = ?,
                base_address = ?, process_pid = ?, process_tid = ?, process_ppid = ?,
                process_arch = ?, elevated = ?, os_version = ?, os_build = ?, os_arch = ?, listener_name = ?, sleep_delay = ?,
                sleep_jitter = ?, kill_date = ?, working_hours = ?, first_call_in = ?,
                last_call_in = ?, archon_magic = ?
            WHERE agent_id = ?
            "#,
        )
        .bind(super::bool_to_i64(agent.active))
        .bind(&agent.reason)
        .bind(&agent.note)
        .bind(enc_key)
        .bind(enc_iv)
        .bind(&agent.hostname)
        .bind(&agent.username)
        .bind(&agent.domain_name)
        .bind(&agent.external_ip)
        .bind(&agent.internal_ip)
        .bind(&agent.process_name)
        .bind(&agent.process_path)
        .bind(super::i64_from_u64("base_address", agent.base_address)?)
        .bind(i64::from(agent.process_pid))
        .bind(i64::from(agent.process_tid))
        .bind(i64::from(agent.process_ppid))
        .bind(&agent.process_arch)
        .bind(super::bool_to_i64(agent.elevated))
        .bind(&agent.os_version)
        .bind(i64::from(agent.os_build))
        .bind(&agent.os_arch)
        .bind(listener_name)
        .bind(i64::from(agent.sleep_delay))
        .bind(i64::from(agent.sleep_jitter))
        .bind(agent.kill_date)
        .bind(agent.working_hours.map(i64::from))
        .bind(&agent.first_call_in)
        .bind(&agent.last_call_in)
        .bind(agent.archon_magic.map(i64::from))
        .bind(i64::from(agent.agent_id))
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(TeamserverError::AgentNotFound { agent_id: agent.agent_id });
        }

        Ok(())
    }

    /// Update an existing agent row on re-registration, resetting the CTR block offset and
    /// last-seen sequence number to 0 and refreshing all runtime metadata.
    /// Preserves the original `first_call_in` and the operator-authored `note`.
    ///
    /// `seq_protected` captures whether the agent negotiated callback sequence-number
    /// replay protection (`INIT_EXT_SEQ_PROTECTED`) on the fresh session and is persisted
    /// atomically with the rest of the re-registration update.
    pub async fn reregister_full(
        &self,
        agent: &AgentRecord,
        listener_name: &str,
        legacy_ctr: bool,
        seq_protected: bool,
    ) -> Result<(), TeamserverError> {
        let enc_key = self.master_key.encrypt(&agent.encryption.aes_key)?;
        let enc_iv = self.master_key.encrypt(&agent.encryption.aes_iv)?;
        let result = sqlx::query(
            r#"
            UPDATE ts_agents SET
                active = 1, reason = '', ctr_block_offset = 0, last_seen_seq = 0, legacy_ctr = ?,
                seq_protected = ?,
                aes_key = '', aes_iv = '', aes_key_enc = ?, aes_iv_enc = ?,
                hostname = ?, username = ?, domain_name = ?,
                external_ip = ?, internal_ip = ?, process_name = ?, process_path = ?,
                base_address = ?, process_pid = ?, process_tid = ?, process_ppid = ?,
                process_arch = ?, elevated = ?, os_version = ?, os_build = ?, os_arch = ?,
                listener_name = ?, sleep_delay = ?, sleep_jitter = ?, kill_date = ?,
                working_hours = ?, last_call_in = ?, archon_magic = ?
            WHERE agent_id = ?
            "#,
        )
        .bind(super::bool_to_i64(legacy_ctr))
        .bind(super::bool_to_i64(seq_protected))
        .bind(enc_key)
        .bind(enc_iv)
        .bind(&agent.hostname)
        .bind(&agent.username)
        .bind(&agent.domain_name)
        .bind(&agent.external_ip)
        .bind(&agent.internal_ip)
        .bind(&agent.process_name)
        .bind(&agent.process_path)
        .bind(super::i64_from_u64("base_address", agent.base_address)?)
        .bind(i64::from(agent.process_pid))
        .bind(i64::from(agent.process_tid))
        .bind(i64::from(agent.process_ppid))
        .bind(&agent.process_arch)
        .bind(super::bool_to_i64(agent.elevated))
        .bind(&agent.os_version)
        .bind(i64::from(agent.os_build))
        .bind(&agent.os_arch)
        .bind(listener_name)
        .bind(i64::from(agent.sleep_delay))
        .bind(i64::from(agent.sleep_jitter))
        .bind(agent.kill_date)
        .bind(agent.working_hours.map(i64::from))
        .bind(&agent.last_call_in)
        .bind(agent.archon_magic.map(i64::from))
        .bind(i64::from(agent.agent_id))
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(TeamserverError::AgentNotFound { agent_id: agent.agent_id });
        }

        Ok(())
    }

    /// Fetch a single agent by identifier.
    pub async fn get(&self, agent_id: u32) -> Result<Option<AgentRecord>, TeamserverError> {
        let row = sqlx::query_as::<_, AgentRow>("SELECT * FROM ts_agents WHERE agent_id = ?")
            .bind(i64::from(agent_id))
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| row_to_agent_record(&r, &self.master_key)).transpose()
    }

    /// Return all persisted agents.
    pub async fn list(&self) -> Result<Vec<AgentRecord>, TeamserverError> {
        let rows = sqlx::query_as::<_, AgentRow>("SELECT * FROM ts_agents ORDER BY agent_id")
            .fetch_all(&self.pool)
            .await?;

        rows.iter().map(|r| row_to_agent_record(r, &self.master_key)).collect()
    }

    /// Return only agents still marked active.
    pub async fn list_active(&self) -> Result<Vec<AgentRecord>, TeamserverError> {
        let rows = sqlx::query_as::<_, AgentRow>(
            "SELECT * FROM ts_agents WHERE active = 1 ORDER BY agent_id",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(|r| row_to_agent_record(r, &self.master_key)).collect()
    }

    /// Check whether an agent row exists.
    pub async fn exists(&self, agent_id: u32) -> Result<bool, TeamserverError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ts_agents WHERE agent_id = ?")
            .bind(i64::from(agent_id))
            .fetch_one(&self.pool)
            .await?;

        Ok(count > 0)
    }

    /// Update the active flag and reason for an agent.
    pub async fn set_status(
        &self,
        agent_id: u32,
        active: bool,
        reason: &str,
    ) -> Result<(), TeamserverError> {
        let result = sqlx::query("UPDATE ts_agents SET active = ?, reason = ? WHERE agent_id = ?")
            .bind(super::bool_to_i64(active))
            .bind(reason)
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(TeamserverError::AgentNotFound { agent_id });
        }

        Ok(())
    }

    /// Delete an agent row.
    pub async fn delete(&self, agent_id: u32) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_agents WHERE agent_id = ?")
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Update the operator-authored note for an agent.
    pub async fn set_note(&self, agent_id: u32, note: &str) -> Result<(), TeamserverError> {
        let result = sqlx::query("UPDATE ts_agents SET note = ? WHERE agent_id = ?")
            .bind(note)
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(TeamserverError::AgentNotFound { agent_id });
        }

        Ok(())
    }

    /// Fetch a single persisted agent plus its CTR state.
    pub async fn get_persisted(
        &self,
        agent_id: u32,
    ) -> Result<Option<PersistedAgent>, TeamserverError> {
        let row = sqlx::query_as::<_, AgentRow>("SELECT * FROM ts_agents WHERE agent_id = ?")
            .bind(i64::from(agent_id))
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| row_to_persisted_agent(r, &self.master_key)).transpose()
    }

    /// Return all persisted agents plus their CTR state.
    pub async fn list_persisted(&self) -> Result<Vec<PersistedAgent>, TeamserverError> {
        let rows = sqlx::query_as::<_, AgentRow>("SELECT * FROM ts_agents ORDER BY agent_id")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(|r| row_to_persisted_agent(r, &self.master_key)).collect()
    }

    /// Persist the current CTR block offset for an agent.
    pub async fn set_ctr_block_offset(
        &self,
        agent_id: u32,
        ctr_block_offset: u64,
    ) -> Result<(), TeamserverError> {
        update_agent_ctr_block_offset(&self.pool, agent_id, ctr_block_offset).await
    }

    /// Persist the legacy CTR mode flag for an agent.
    pub async fn set_legacy_ctr(
        &self,
        agent_id: u32,
        legacy_ctr: bool,
    ) -> Result<(), TeamserverError> {
        let result = sqlx::query("UPDATE ts_agents SET legacy_ctr = ? WHERE agent_id = ?")
            .bind(super::bool_to_i64(legacy_ctr))
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(TeamserverError::AgentNotFound { agent_id });
        }
        Ok(())
    }

    /// Persist the last accepted callback sequence number for an agent.
    pub async fn set_last_seen_seq(
        &self,
        agent_id: u32,
        last_seen_seq: u64,
    ) -> Result<(), TeamserverError> {
        let result = sqlx::query("UPDATE ts_agents SET last_seen_seq = ? WHERE agent_id = ?")
            .bind(super::i64_from_u64("last_seen_seq", last_seen_seq)?)
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(TeamserverError::AgentNotFound { agent_id });
        }
        Ok(())
    }

    /// Persist the seq-protected flag for an agent.
    ///
    /// Production code paths persist `seq_protected` atomically via [`Self::create_full`]
    /// and [`Self::reregister_full`]; this stand-alone update is retained as a test helper.
    #[cfg(test)]
    pub async fn set_seq_protected(
        &self,
        agent_id: u32,
        seq_protected: bool,
    ) -> Result<(), TeamserverError> {
        let result = sqlx::query("UPDATE ts_agents SET seq_protected = ? WHERE agent_id = ?")
            .bind(super::bool_to_i64(seq_protected))
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(TeamserverError::AgentNotFound { agent_id });
        }
        Ok(())
    }
}

pub(super) async fn insert_agent_row(
    executor: impl sqlx::Executor<'_, Database = Sqlite>,
    agent: &AgentRecord,
    listener_name: &str,
    ctr_block_offset: u64,
    legacy_ctr: bool,
    seq_protected: bool,
    enc_key: &str,
    enc_iv: &str,
) -> Result<(), TeamserverError> {
    sqlx::query(
        r#"
        INSERT INTO ts_agents (
            agent_id, active, reason, note, ctr_block_offset, legacy_ctr,
            aes_key, aes_iv, aes_key_enc, aes_iv_enc,
            hostname, username, domain_name,
            external_ip, internal_ip, process_name, process_path, base_address, process_pid, process_tid,
            process_ppid, process_arch, elevated, os_version, os_build, os_arch, listener_name, sleep_delay,
            sleep_jitter, kill_date, working_hours, first_call_in, last_call_in, last_seen_seq, seq_protected,
            archon_magic
        ) VALUES (?, ?, ?, ?, ?, ?, '', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(i64::from(agent.agent_id))
    .bind(super::bool_to_i64(agent.active))
    .bind(&agent.reason)
    .bind(&agent.note)
    .bind(super::i64_from_u64("ctr_block_offset", ctr_block_offset)?)
    .bind(super::bool_to_i64(legacy_ctr))
    .bind(enc_key)
    .bind(enc_iv)
    .bind(&agent.hostname)
    .bind(&agent.username)
    .bind(&agent.domain_name)
    .bind(&agent.external_ip)
    .bind(&agent.internal_ip)
    .bind(&agent.process_name)
    .bind(&agent.process_path)
    .bind(super::i64_from_u64("base_address", agent.base_address)?)
    .bind(i64::from(agent.process_pid))
    .bind(i64::from(agent.process_tid))
    .bind(i64::from(agent.process_ppid))
    .bind(&agent.process_arch)
    .bind(super::bool_to_i64(agent.elevated))
    .bind(&agent.os_version)
    .bind(i64::from(agent.os_build))
    .bind(&agent.os_arch)
    .bind(listener_name)
    .bind(i64::from(agent.sleep_delay))
    .bind(i64::from(agent.sleep_jitter))
    .bind(agent.kill_date)
    .bind(agent.working_hours.map(i64::from))
    .bind(&agent.first_call_in)
    .bind(&agent.last_call_in)
    .bind(0_i64) // last_seen_seq starts at 0
    .bind(super::bool_to_i64(seq_protected))
    .bind(agent.archon_magic.map(i64::from))
    .execute(executor)
    .await?;

    Ok(())
}
