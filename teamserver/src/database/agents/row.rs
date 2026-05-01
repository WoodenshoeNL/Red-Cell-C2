//! Agent row decoding and conversion helpers.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use sqlx::{FromRow, Sqlite};
use zeroize::Zeroizing;

use super::super::TeamserverError;
use super::super::crypto::DbMasterKey;
use super::PersistedAgent;

#[derive(Debug, FromRow)]
pub(super) struct AgentRow {
    pub(super) agent_id: i64,
    pub(super) active: i64,
    pub(super) reason: String,
    pub(super) note: String,
    pub(super) ctr_block_offset: i64,
    /// Plaintext base64-encoded key.  Non-empty only for rows written before the
    /// at-rest encryption migration.  Cleared to `''` on the next write.
    pub(super) aes_key: String,
    /// Plaintext base64-encoded IV.  Non-empty only for legacy rows.
    pub(super) aes_iv: String,
    /// AES-256-GCM encrypted key blob (`base64(nonce || ciphertext)`).
    pub(super) aes_key_enc: String,
    /// AES-256-GCM encrypted IV blob.
    pub(super) aes_iv_enc: String,
    pub(super) hostname: String,
    pub(super) username: String,
    pub(super) domain_name: String,
    pub(super) external_ip: String,
    pub(super) internal_ip: String,
    pub(super) process_name: String,
    pub(super) process_path: String,
    pub(super) base_address: i64,
    pub(super) process_pid: i64,
    pub(super) process_tid: i64,
    pub(super) process_ppid: i64,
    pub(super) process_arch: String,
    pub(super) elevated: i64,
    pub(super) os_version: String,
    pub(super) os_build: i64,
    pub(super) os_arch: String,
    pub(super) listener_name: String,
    pub(super) sleep_delay: i64,
    pub(super) sleep_jitter: i64,
    pub(super) kill_date: Option<i64>,
    pub(super) working_hours: Option<i64>,
    pub(super) first_call_in: String,
    pub(super) last_call_in: String,
    pub(super) legacy_ctr: i64,
    pub(super) last_seen_seq: i64,
    pub(super) seq_protected: i64,
    pub(super) archon_magic: Option<i64>,
    pub(super) replay_attempt_count: i64,
    pub(super) replay_lockout_until: Option<i64>,
}

pub(super) async fn update_agent_ctr_block_offset(
    executor: impl sqlx::Executor<'_, Database = Sqlite>,
    agent_id: u32,
    ctr_block_offset: u64,
) -> Result<(), TeamserverError> {
    let result = sqlx::query("UPDATE ts_agents SET ctr_block_offset = ? WHERE agent_id = ?")
        .bind(super::super::i64_from_u64("ctr_block_offset", ctr_block_offset)?)
        .bind(i64::from(agent_id))
        .execute(executor)
        .await?;

    if result.rows_affected() == 0 {
        return Err(TeamserverError::AgentNotFound { agent_id });
    }

    Ok(())
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

pub(super) fn row_to_agent_record(
    row: &AgentRow,
    master_key: &DbMasterKey,
) -> Result<AgentRecord, TeamserverError> {
    let aes_key = decode_agent_key(master_key, &row.aes_key_enc, &row.aes_key, "aes_key")?;
    let aes_iv = decode_agent_key(master_key, &row.aes_iv_enc, &row.aes_iv, "aes_iv")?;
    Ok(AgentRecord {
        agent_id: super::super::u32_from_i64("agent_id", row.agent_id)?,
        active: super::super::bool_from_i64("active", row.active)?,
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
        base_address: super::super::u64_from_i64("base_address", row.base_address)?,
        process_pid: super::super::u32_from_i64("process_pid", row.process_pid)?,
        process_tid: super::super::u32_from_i64("process_tid", row.process_tid)?,
        process_ppid: super::super::u32_from_i64("process_ppid", row.process_ppid)?,
        process_arch: row.process_arch.clone(),
        elevated: super::super::bool_from_i64("elevated", row.elevated)?,
        os_version: row.os_version.clone(),
        os_build: super::super::u32_from_i64("os_build", row.os_build)?,
        os_arch: row.os_arch.clone(),
        sleep_delay: super::super::u32_from_i64("sleep_delay", row.sleep_delay)?,
        sleep_jitter: super::super::u32_from_i64("sleep_jitter", row.sleep_jitter)?,
        kill_date: row.kill_date,
        working_hours: row.working_hours.map(i32::try_from).transpose().map_err(|_| {
            super::super::invalid_value("working_hours", "value does not fit in i32")
        })?,
        first_call_in: row.first_call_in.clone(),
        last_call_in: row.last_call_in.clone(),
        archon_magic: row.archon_magic.map(u32::try_from).transpose().map_err(|_| {
            super::super::invalid_value("archon_magic", "value does not fit in u32")
        })?,
    })
}

pub(super) fn row_to_persisted_agent(
    row: AgentRow,
    master_key: &DbMasterKey,
) -> Result<PersistedAgent, TeamserverError> {
    let ctr_block_offset = super::super::u64_from_i64("ctr_block_offset", row.ctr_block_offset)?;
    let legacy_ctr = super::super::bool_from_i64("legacy_ctr", row.legacy_ctr)?;
    let last_seen_seq = super::super::u64_from_i64("last_seen_seq", row.last_seen_seq)?;
    let seq_protected = super::super::bool_from_i64("seq_protected", row.seq_protected)?;
    let replay_attempt_count =
        super::super::u32_from_i64("replay_attempt_count", row.replay_attempt_count)?;
    let replay_lockout_until = row.replay_lockout_until;
    let listener_name = row.listener_name.clone();
    let info = row_to_agent_record(&row, master_key)?;
    Ok(PersistedAgent {
        info,
        listener_name,
        ctr_block_offset,
        legacy_ctr,
        last_seen_seq,
        seq_protected,
        replay_attempt_count,
        replay_lockout_until,
    })
}
