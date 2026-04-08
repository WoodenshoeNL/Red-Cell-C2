//! Agent CRUD repository.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use sqlx::{FromRow, Sqlite, SqlitePool};
use zeroize::Zeroizing;

use super::TeamserverError;
use super::crypto::DbMasterKey;

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
        self.create_full(agent, listener_name, ctr_block_offset, false).await
    }

    /// Insert a new agent row with all transport parameters.
    pub async fn create_full(
        &self,
        agent: &AgentRecord,
        listener_name: &str,
        ctr_block_offset: u64,
        legacy_ctr: bool,
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
                last_call_in = ?
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
    pub async fn reregister_full(
        &self,
        agent: &AgentRecord,
        listener_name: &str,
        legacy_ctr: bool,
    ) -> Result<(), TeamserverError> {
        let enc_key = self.master_key.encrypt(&agent.encryption.aes_key)?;
        let enc_iv = self.master_key.encrypt(&agent.encryption.aes_iv)?;
        let result = sqlx::query(
            r#"
            UPDATE ts_agents SET
                active = 1, reason = '', ctr_block_offset = 0, last_seen_seq = 0, legacy_ctr = ?,
                aes_key = '', aes_iv = '', aes_key_enc = ?, aes_iv_enc = ?,
                hostname = ?, username = ?, domain_name = ?,
                external_ip = ?, internal_ip = ?, process_name = ?, process_path = ?,
                base_address = ?, process_pid = ?, process_tid = ?, process_ppid = ?,
                process_arch = ?, elevated = ?, os_version = ?, os_build = ?, os_arch = ?,
                listener_name = ?, sleep_delay = ?, sleep_jitter = ?, kill_date = ?,
                working_hours = ?, last_call_in = ?
            WHERE agent_id = ?
            "#,
        )
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
        .bind(&agent.last_call_in)
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
            sleep_jitter, kill_date, working_hours, first_call_in, last_call_in, last_seen_seq, seq_protected
        ) VALUES (?, ?, ?, ?, ?, ?, '', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    .bind(0_i64) // seq_protected defaults to false
    .execute(executor)
    .await?;

    Ok(())
}

async fn update_agent_ctr_block_offset(
    executor: impl sqlx::Executor<'_, Database = Sqlite>,
    agent_id: u32,
    ctr_block_offset: u64,
) -> Result<(), TeamserverError> {
    let result = sqlx::query("UPDATE ts_agents SET ctr_block_offset = ? WHERE agent_id = ?")
        .bind(super::i64_from_u64("ctr_block_offset", ctr_block_offset)?)
        .bind(i64::from(agent_id))
        .execute(executor)
        .await?;

    if result.rows_affected() == 0 {
        return Err(TeamserverError::AgentNotFound { agent_id });
    }

    Ok(())
}

#[derive(Debug, FromRow)]
struct AgentRow {
    agent_id: i64,
    active: i64,
    reason: String,
    note: String,
    ctr_block_offset: i64,
    /// Plaintext base64-encoded key.  Non-empty only for rows written before the
    /// at-rest encryption migration.  Cleared to `''` on the next write.
    aes_key: String,
    /// Plaintext base64-encoded IV.  Non-empty only for legacy rows.
    aes_iv: String,
    /// AES-256-GCM encrypted key blob (`base64(nonce || ciphertext)`).
    aes_key_enc: String,
    /// AES-256-GCM encrypted IV blob.
    aes_iv_enc: String,
    hostname: String,
    username: String,
    domain_name: String,
    external_ip: String,
    internal_ip: String,
    process_name: String,
    process_path: String,
    base_address: i64,
    process_pid: i64,
    process_tid: i64,
    process_ppid: i64,
    process_arch: String,
    elevated: i64,
    os_version: String,
    os_build: i64,
    os_arch: String,
    listener_name: String,
    sleep_delay: i64,
    sleep_jitter: i64,
    kill_date: Option<i64>,
    working_hours: Option<i64>,
    first_call_in: String,
    last_call_in: String,
    legacy_ctr: i64,
    last_seen_seq: i64,
    seq_protected: i64,
}

/// Decode an agent session key from a persisted row.
///
/// Preference order:
/// 1. `enc_col` non-empty → decrypt with `master_key` (new encrypted path)
/// 2. `plain_col` non-empty → base64-decode plaintext (legacy fallback for rows
///    written before the at-rest encryption migration)
/// 3. Both empty → return empty `Zeroizing<Vec<u8>>`
fn decode_agent_key(
    master_key: &DbMasterKey,
    enc_col: &str,
    plain_col: &str,
    field: &'static str,
) -> Result<Zeroizing<Vec<u8>>, TeamserverError> {
    if !enc_col.is_empty() {
        return master_key.decrypt(enc_col).map_err(|e| TeamserverError::InvalidPersistedValue {
            field,
            message: format!("at-rest decryption failed: {e}"),
        });
    }
    if !plain_col.is_empty() {
        return Zeroizing::new(BASE64_STANDARD.decode(plain_col).map_err(|e| {
            TeamserverError::InvalidPersistedValue {
                field,
                message: format!("legacy base64 decode failed: {e}"),
            }
        })?)
        .pipe_ok();
    }
    Ok(Zeroizing::new(Vec::new()))
}

/// Extension trait providing `.pipe_ok()` for wrapping an already-owned `Zeroizing<Vec<u8>>`.
trait PipeOk: Sized {
    fn pipe_ok(self) -> Result<Self, TeamserverError>;
}
impl PipeOk for Zeroizing<Vec<u8>> {
    fn pipe_ok(self) -> Result<Self, TeamserverError> {
        Ok(self)
    }
}

fn row_to_agent_record(
    row: &AgentRow,
    master_key: &DbMasterKey,
) -> Result<AgentRecord, TeamserverError> {
    let aes_key = decode_agent_key(master_key, &row.aes_key_enc, &row.aes_key, "aes_key")?;
    let aes_iv = decode_agent_key(master_key, &row.aes_iv_enc, &row.aes_iv, "aes_iv")?;
    Ok(AgentRecord {
        agent_id: super::u32_from_i64("agent_id", row.agent_id)?,
        active: super::bool_from_i64("active", row.active)?,
        reason: row.reason.clone(),
        note: row.note.clone(),
        encryption: AgentEncryptionInfo { aes_key, aes_iv },
        hostname: row.hostname.clone(),
        username: row.username.clone(),
        domain_name: row.domain_name.clone(),
        external_ip: row.external_ip.clone(),
        internal_ip: row.internal_ip.clone(),
        process_name: row.process_name.clone(),
        process_path: row.process_path.clone(),
        base_address: super::u64_from_i64("base_address", row.base_address)?,
        process_pid: super::u32_from_i64("process_pid", row.process_pid)?,
        process_tid: super::u32_from_i64("process_tid", row.process_tid)?,
        process_ppid: super::u32_from_i64("process_ppid", row.process_ppid)?,
        process_arch: row.process_arch.clone(),
        elevated: super::bool_from_i64("elevated", row.elevated)?,
        os_version: row.os_version.clone(),
        os_build: super::u32_from_i64("os_build", row.os_build)?,
        os_arch: row.os_arch.clone(),
        sleep_delay: super::u32_from_i64("sleep_delay", row.sleep_delay)?,
        sleep_jitter: super::u32_from_i64("sleep_jitter", row.sleep_jitter)?,
        kill_date: row.kill_date,
        working_hours: row
            .working_hours
            .map(i32::try_from)
            .transpose()
            .map_err(|_| super::invalid_value("working_hours", "value does not fit in i32"))?,
        first_call_in: row.first_call_in.clone(),
        last_call_in: row.last_call_in.clone(),
    })
}

fn row_to_persisted_agent(
    row: AgentRow,
    master_key: &DbMasterKey,
) -> Result<PersistedAgent, TeamserverError> {
    let ctr_block_offset = super::u64_from_i64("ctr_block_offset", row.ctr_block_offset)?;
    let legacy_ctr = super::bool_from_i64("legacy_ctr", row.legacy_ctr)?;
    let last_seen_seq = super::u64_from_i64("last_seen_seq", row.last_seen_seq)?;
    let seq_protected = super::bool_from_i64("seq_protected", row.seq_protected)?;
    let listener_name = row.listener_name.clone();
    let info = row_to_agent_record(&row, master_key)?;
    Ok(PersistedAgent {
        info,
        listener_name,
        ctr_block_offset,
        legacy_ctr,
        last_seen_seq,
        seq_protected,
    })
}

#[cfg(test)]
mod tests {
    use red_cell_common::{AgentEncryptionInfo, AgentRecord};
    use zeroize::Zeroizing;

    use crate::database::{Database, TeamserverError};

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

    #[tokio::test]
    async fn create_full_persists_listener_ctr_offset_and_legacy_ctr() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.agents();
        repo.create_full(&stub_agent(0xAA), "https-listener", 42, true).await.expect("create_full");
        let persisted = repo.get_persisted(0xAA).await.expect("get").expect("should exist");
        assert_eq!(persisted.listener_name, "https-listener");
        assert_eq!(persisted.ctr_block_offset, 42);
        assert!(persisted.legacy_ctr);
        assert_eq!(persisted.info.agent_id, 0xAA);
    }

    #[tokio::test]
    async fn set_legacy_ctr_on_missing_agent_returns_agent_not_found() {
        let db = Database::connect_in_memory().await.expect("db");
        let err = db.agents().set_legacy_ctr(0xDEAD, true).await.expect_err("expected Err");
        assert!(
            matches!(err, TeamserverError::AgentNotFound { agent_id } if agent_id == 0xDEAD),
            "expected AgentNotFound, got: {err:?}",
        );
        assert!(db.agents().get_persisted(0xDEAD).await.expect("get").is_none());
    }

    #[tokio::test]
    async fn toggle_legacy_ctr_preserves_other_fields() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.agents();
        repo.create_full(&stub_agent(0xBB), "smb-pipe", 99, true).await.expect("create_full");
        repo.set_legacy_ctr(0xBB, false).await.expect("set_legacy_ctr");
        let persisted = repo.get_persisted(0xBB).await.expect("get").expect("should exist");
        assert!(!persisted.legacy_ctr, "legacy_ctr should now be false");
        assert_eq!(persisted.listener_name, "smb-pipe");
        assert_eq!(persisted.ctr_block_offset, 99);
    }

    #[tokio::test]
    async fn set_status_persists_active_and_reason() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.agents();
        repo.create_full(&stub_agent(0xCC), "https-listener", 0, false).await.expect("create_full");
        repo.set_status(0xCC, false, "timed out").await.expect("set_status");
        let persisted = repo.get_persisted(0xCC).await.expect("get").expect("should exist");
        assert!(!persisted.info.active, "active should be false after set_status");
        assert_eq!(persisted.info.reason, "timed out");
        assert_eq!(persisted.listener_name, "https-listener");
    }

    #[tokio::test]
    async fn set_status_on_missing_agent_returns_agent_not_found() {
        let db = Database::connect_in_memory().await.expect("db");
        let err = db.agents().set_status(0xDEAD, false, "gone").await.expect_err("expected Err");
        assert!(
            matches!(err, TeamserverError::AgentNotFound { agent_id } if agent_id == 0xDEAD),
            "expected AgentNotFound, got: {err:?}",
        );
        assert!(db.agents().get_persisted(0xDEAD).await.expect("get").is_none());
    }

    #[tokio::test]
    async fn session_keys_survive_create_then_read_roundtrip() {
        let db = Database::connect_in_memory().await.expect("db");
        let agent = AgentRecord {
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0xAA; 32]),
                aes_iv: Zeroizing::new(vec![0xBB; 16]),
            },
            ..stub_agent(0x1234)
        };
        db.agents().create(&agent).await.expect("create");
        let loaded = db.agents().get(0x1234).await.expect("get").expect("should exist");
        assert_eq!(*loaded.encryption.aes_key, vec![0xAA; 32], "aes_key must survive round-trip");
        assert_eq!(*loaded.encryption.aes_iv, vec![0xBB; 16], "aes_iv must survive round-trip");
    }

    #[tokio::test]
    async fn session_keys_survive_update_then_read_roundtrip() {
        let db = Database::connect_in_memory().await.expect("db");
        let original = stub_agent(0x5678);
        db.agents().create(&original).await.expect("create");

        let updated = AgentRecord {
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0xCC; 32]),
                aes_iv: Zeroizing::new(vec![0xDD; 16]),
            },
            ..original
        };
        db.agents().update(&updated).await.expect("update");
        let loaded = db.agents().get(0x5678).await.expect("get").expect("should exist");
        assert_eq!(*loaded.encryption.aes_key, vec![0xCC; 32], "aes_key must be updated");
        assert_eq!(*loaded.encryption.aes_iv, vec![0xDD; 16], "aes_iv must be updated");
    }

    #[tokio::test]
    async fn session_keys_survive_reregister_roundtrip() {
        let db = Database::connect_in_memory().await.expect("db");
        db.agents().create(&stub_agent(0x9ABC)).await.expect("create");
        let rereg = AgentRecord {
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0xEE; 32]),
                aes_iv: Zeroizing::new(vec![0xFF; 16]),
            },
            ..stub_agent(0x9ABC)
        };
        db.agents().reregister_full(&rereg, "smb-pipe", false).await.expect("reregister");
        let loaded = db.agents().get(0x9ABC).await.expect("get").expect("should exist");
        assert_eq!(*loaded.encryption.aes_key, vec![0xEE; 32]);
        assert_eq!(*loaded.encryption.aes_iv, vec![0xFF; 16]);
    }

    #[tokio::test]
    async fn legacy_plaintext_key_fallback_survives_read() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

        let db = Database::connect_in_memory().await.expect("db");
        db.agents().create(&stub_agent(0x1111)).await.expect("create");

        // Simulate a pre-migration row: plaintext base64 in aes_key/aes_iv,
        // empty aes_key_enc/aes_iv_enc.
        let raw_key = vec![0x42u8; 32];
        let raw_iv = vec![0x13u8; 16];
        let key_b64 = BASE64_STANDARD.encode(&raw_key);
        let iv_b64 = BASE64_STANDARD.encode(&raw_iv);
        sqlx::query("UPDATE ts_agents SET aes_key = ?, aes_iv = ?, aes_key_enc = '', aes_iv_enc = '' WHERE agent_id = ?")
            .bind(&key_b64)
            .bind(&iv_b64)
            .bind(0x1111i64)
            .execute(db.pool())
            .await
            .expect("backdate row to legacy format");

        let loaded = db.agents().get(0x1111).await.expect("get").expect("exists");
        assert_eq!(*loaded.encryption.aes_key, raw_key, "legacy plaintext key must be read");
        assert_eq!(*loaded.encryption.aes_iv, raw_iv, "legacy plaintext iv must be read");
    }
}
