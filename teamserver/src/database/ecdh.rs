//! Database persistence for ECDH listener keypairs and agent session tokens.

use std::sync::Arc;

use base64::Engine as _;
use sqlx::SqlitePool;
use tracing::instrument;

use red_cell_common::crypto::ecdh::{
    CONNECTION_ID_LEN, ConnectionId, ECDH_REG_FINGERPRINT_LEN, ListenerKeypair,
};

use super::crypto::DbMasterKey;
use super::error::TeamserverError;

/// Repository for ECDH listener keypairs and session tokens.
#[derive(Clone, Debug)]
pub struct EcdhRepository {
    pool: SqlitePool,
    master_key: Arc<DbMasterKey>,
}

impl EcdhRepository {
    pub fn new(pool: SqlitePool, master_key: Arc<DbMasterKey>) -> Self {
        Self { pool, master_key }
    }

    // ─── Listener keypairs ─────────────────────────────────────────────────────

    /// Return the existing X25519 keypair for a listener, or generate and persist a new one.
    #[instrument(skip(self), fields(listener = listener_name))]
    pub async fn get_or_create_keypair(
        &self,
        listener_name: &str,
    ) -> Result<ListenerKeypair, TeamserverError> {
        if let Some(kp) = self.get_keypair(listener_name).await? {
            return Ok(kp);
        }

        let kp = ListenerKeypair::generate()
            .map_err(|e| TeamserverError::Internal(format!("ECDH keypair generation: {e}")))?;

        let secret_enc = self
            .master_key
            .encrypt(&kp.secret_bytes)
            .map_err(|e| TeamserverError::Internal(format!("encrypt listener keypair: {e}")))?;
        let public_b64 = base64::engine::general_purpose::STANDARD.encode(kp.public_bytes);

        sqlx::query(
            "INSERT OR IGNORE INTO ts_listener_keypairs \
             (listener_name, secret_key_enc, public_key) VALUES (?, ?, ?)",
        )
        .bind(listener_name)
        .bind(&secret_enc)
        .bind(&public_b64)
        .execute(&self.pool)
        .await
        .map_err(TeamserverError::Sqlx)?;

        // Race: if INSERT OR IGNORE was a no-op, load the winner's row.
        self.get_keypair(listener_name).await?.ok_or_else(|| {
            TeamserverError::Internal(
                "ECDH keypair race: row missing after INSERT OR IGNORE".into(),
            )
        })
    }

    /// Load the persisted X25519 keypair for a listener, if one exists.
    pub async fn get_keypair(
        &self,
        listener_name: &str,
    ) -> Result<Option<ListenerKeypair>, TeamserverError> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT secret_key_enc, public_key FROM ts_listener_keypairs WHERE listener_name = ?",
        )
        .bind(listener_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(TeamserverError::Sqlx)?;

        let Some((secret_enc, _public_b64)) = row else {
            return Ok(None);
        };

        let secret_bytes = self
            .master_key
            .decrypt(&secret_enc)
            .map_err(|e| TeamserverError::Internal(format!("decrypt listener keypair: {e}")))?;

        let secret_arr: [u8; 32] = secret_bytes.as_slice().try_into().map_err(|_| {
            TeamserverError::Internal("persisted listener secret key has wrong length".into())
        })?;

        Ok(Some(ListenerKeypair::from_bytes(secret_arr)))
    }

    // ─── ECDH sessions ─────────────────────────────────────────────────────────

    /// Persist a new ECDH session (connection_id → agent_id + session_key).
    pub async fn store_session(
        &self,
        connection_id: &ConnectionId,
        agent_id: u32,
        session_key: &[u8; 32],
    ) -> Result<(), TeamserverError> {
        let key_enc = self
            .master_key
            .encrypt(session_key)
            .map_err(|e| TeamserverError::Internal(format!("encrypt ECDH session key: {e}")))?;

        let now = now_secs();
        sqlx::query(
            "INSERT INTO ts_ecdh_sessions \
             (connection_id, agent_id, session_key_enc, created_at, last_seen) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(connection_id.0.as_slice())
        .bind(i64::from(agent_id))
        .bind(&key_enc)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(TeamserverError::Sqlx)?;

        Ok(())
    }

    /// Look up a session by its `connection_id`.  Returns `(agent_id, session_key)`.
    pub async fn lookup_session(
        &self,
        connection_id_bytes: &[u8; CONNECTION_ID_LEN],
    ) -> Result<Option<(u32, [u8; 32])>, TeamserverError> {
        let row: Option<(i64, String)> = sqlx::query_as(
            "SELECT agent_id, session_key_enc FROM ts_ecdh_sessions WHERE connection_id = ?",
        )
        .bind(connection_id_bytes.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(TeamserverError::Sqlx)?;

        let Some((agent_id_i64, key_enc)) = row else {
            return Ok(None);
        };

        let agent_id = u32::try_from(agent_id_i64)
            .map_err(|_| TeamserverError::Internal("ECDH session agent_id overflow".into()))?;

        let key_bytes = self
            .master_key
            .decrypt(&key_enc)
            .map_err(|e| TeamserverError::Internal(format!("decrypt ECDH session key: {e}")))?;

        let session_key: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            TeamserverError::Internal("persisted ECDH session key has wrong length".into())
        })?;

        Ok(Some((agent_id, session_key)))
    }

    /// Validate and advance the sequence number for a session.
    ///
    /// Returns `Ok(true)` if `candidate_seq` > `last_seq_num` and the DB was
    /// updated atomically.  Returns `Ok(false)` if the packet is a replay
    /// (candidate_seq ≤ last_seq_num).  Returns `Err` on DB failure.
    pub async fn advance_seq_num(
        &self,
        connection_id_bytes: &[u8; CONNECTION_ID_LEN],
        candidate_seq: u64,
    ) -> Result<bool, TeamserverError> {
        let seq_i64 = i64::try_from(candidate_seq)
            .map_err(|_| TeamserverError::SeqNumOverflow { seq_num: candidate_seq })?;
        let rows_affected = sqlx::query(
            "UPDATE ts_ecdh_sessions \
             SET last_seq_num = ? \
             WHERE connection_id = ? AND last_seq_num < ?",
        )
        .bind(seq_i64)
        .bind(connection_id_bytes.as_slice())
        .bind(seq_i64)
        .execute(&self.pool)
        .await
        .map_err(TeamserverError::Sqlx)?
        .rows_affected();

        Ok(rows_affected > 0)
    }

    /// Update the `last_seen` timestamp for a session.
    pub async fn touch_session(
        &self,
        connection_id_bytes: &[u8; CONNECTION_ID_LEN],
    ) -> Result<(), TeamserverError> {
        sqlx::query("UPDATE ts_ecdh_sessions SET last_seen = ? WHERE connection_id = ?")
            .bind(now_secs())
            .bind(connection_id_bytes.as_slice())
            .execute(&self.pool)
            .await
            .map_err(TeamserverError::Sqlx)?;
        Ok(())
    }

    /// Delete a single session by its `connection_id`.
    pub async fn delete_session(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_ecdh_sessions WHERE connection_id = ?")
            .bind(connection_id.0.as_slice())
            .execute(&self.pool)
            .await
            .map_err(TeamserverError::Sqlx)?;
        Ok(())
    }

    /// Delete all sessions for an agent (used when an agent is deregistered).
    pub async fn delete_sessions_for_agent(&self, agent_id: u32) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_ecdh_sessions WHERE agent_id = ?")
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await
            .map_err(TeamserverError::Sqlx)?;
        Ok(())
    }

    /// Return the distinct set of `agent_id`s that currently have at least one
    /// persisted ECDH session.  Used on teamserver startup to restore the
    /// `ecdh_transport` flag for Phantom/Specter agents: an agent with any
    /// session row in `ts_ecdh_sessions` is an ECDH agent, so its job payloads
    /// must not be double-encrypted with the legacy AES-CTR path.
    pub async fn list_agent_ids_with_sessions(
        &self,
    ) -> Result<std::collections::HashSet<u32>, TeamserverError> {
        let rows: Vec<(i64,)> = sqlx::query_as("SELECT DISTINCT agent_id FROM ts_ecdh_sessions")
            .fetch_all(&self.pool)
            .await
            .map_err(TeamserverError::Sqlx)?;

        let mut ids = std::collections::HashSet::with_capacity(rows.len());
        for (agent_id_i64,) in rows {
            let agent_id = u32::try_from(agent_id_i64).map_err(|_| {
                TeamserverError::Internal(format!("ECDH session agent_id overflow: {agent_id_i64}"))
            })?;
            ids.insert(agent_id);
        }
        Ok(ids)
    }

    /// Return the decrypted session key for the most recent ECDH session belonging
    /// to `agent_id`, or `None` if no session exists for that agent.
    ///
    /// Used by `GET /debug/corpus-keys` to retrieve the real GCM session key for
    /// ECDH agents (whose AES-CTR key slot is intentionally zeroed in the registry).
    pub async fn get_session_key_by_agent_id(
        &self,
        agent_id: u32,
    ) -> Result<Option<[u8; 32]>, TeamserverError> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT session_key_enc FROM ts_ecdh_sessions \
             WHERE agent_id = ? ORDER BY created_at DESC LIMIT 1",
        )
        .bind(i64::from(agent_id))
        .fetch_optional(&self.pool)
        .await
        .map_err(TeamserverError::Sqlx)?;

        let Some((key_enc,)) = row else {
            return Ok(None);
        };

        let key_bytes = self
            .master_key
            .decrypt(&key_enc)
            .map_err(|e| TeamserverError::Internal(format!("decrypt ECDH session key: {e}")))?;

        let session_key: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            TeamserverError::Internal("persisted ECDH session key has wrong length".into())
        })?;

        Ok(Some(session_key))
    }

    // ─── Registration replay cache ──────────────────────────────────────────────

    /// Record a registration-packet fingerprint to prevent replay within the window.
    ///
    /// `fingerprint` is the first [`ECDH_REG_FINGERPRINT_LEN`] bytes of the
    /// wire packet (`ephemeral_pubkey[32] || nonce[12]`).
    ///
    /// Returns `Ok(true)` when the fingerprint is new (packet accepted).
    /// Returns `Ok(false)` when the fingerprint already exists (replay rejected).
    ///
    /// Expired entries (older than `replay_window_secs`) are pruned on each call
    /// so the table stays bounded without a background sweeper.
    pub async fn try_record_reg_fingerprint(
        &self,
        fingerprint: &[u8; ECDH_REG_FINGERPRINT_LEN],
        replay_window_secs: u64,
    ) -> Result<bool, TeamserverError> {
        let now = now_secs();
        let expires_at = now.saturating_add(i64::try_from(replay_window_secs).unwrap_or(i64::MAX));

        // Prune entries at or past their expiry time.
        sqlx::query("DELETE FROM ts_ecdh_reg_nonces WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(TeamserverError::Sqlx)?;

        // Atomically claim the fingerprint slot.
        let rows = sqlx::query(
            "INSERT OR IGNORE INTO ts_ecdh_reg_nonces (fingerprint, expires_at) VALUES (?, ?)",
        )
        .bind(fingerprint.as_slice())
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(TeamserverError::Sqlx)?
        .rows_affected();

        Ok(rows > 0)
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
        as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{Database, DbMasterKey};

    async fn test_db() -> (Database, Arc<DbMasterKey>) {
        let db = Database::connect_in_memory().await.expect("db");
        let master_key = Arc::new(DbMasterKey::random().expect("master key"));
        (db, master_key)
    }

    #[tokio::test]
    async fn get_or_create_keypair_is_idempotent() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let kp1 = repo.get_or_create_keypair("test-listener").await.expect("kp1");
        let kp2 = repo.get_or_create_keypair("test-listener").await.expect("kp2");
        assert_eq!(kp1.public_bytes, kp2.public_bytes);
    }

    #[tokio::test]
    async fn different_listeners_get_different_keypairs() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let kp1 = repo.get_or_create_keypair("listener-a").await.expect("kp1");
        let kp2 = repo.get_or_create_keypair("listener-b").await.expect("kp2");
        assert_ne!(kp1.public_bytes, kp2.public_bytes);
    }

    #[tokio::test]
    async fn store_and_lookup_session() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let conn_id = ConnectionId::generate().expect("conn_id");
        let agent_id = 0x1234_5678_u32;
        let session_key = [0xAB_u8; 32];

        repo.store_session(&conn_id, agent_id, &session_key).await.expect("store");

        let result = repo.lookup_session(&conn_id.0).await.expect("lookup");
        let (found_agent_id, found_key) = result.expect("Some");
        assert_eq!(found_agent_id, agent_id);
        assert_eq!(found_key, session_key);
    }

    #[tokio::test]
    async fn lookup_missing_session_returns_none() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let result = repo.lookup_session(&[0u8; 16]).await.expect("lookup");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn touch_session_updates_last_seen() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let conn_id = ConnectionId::generate().expect("conn_id");
        repo.store_session(&conn_id, 1, &[0u8; 32]).await.expect("store");
        repo.touch_session(&conn_id.0).await.expect("touch");
        // Just verify it doesn't error; timing is non-deterministic in tests.
    }

    #[tokio::test]
    async fn delete_sessions_for_agent() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let conn_id = ConnectionId::generate().expect("conn_id");
        repo.store_session(&conn_id, 42, &[0u8; 32]).await.expect("store");

        // Verify it's there before deletion.
        assert!(repo.lookup_session(&conn_id.0).await.expect("lookup").is_some());

        repo.delete_sessions_for_agent(42).await.expect("delete");

        assert!(repo.lookup_session(&conn_id.0).await.expect("lookup").is_none());
    }

    #[tokio::test]
    async fn advance_seq_num_accepts_first_packet() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let conn_id = ConnectionId::generate().expect("conn_id");
        repo.store_session(&conn_id, 1, &[0u8; 32]).await.expect("store");

        // First packet with seq_num = 1 must be accepted (last_seq_num starts at 0).
        assert!(repo.advance_seq_num(&conn_id.0, 1).await.expect("advance"), "seq 1 accepted");
    }

    #[tokio::test]
    async fn advance_seq_num_accepts_monotone_sequence() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let conn_id = ConnectionId::generate().expect("conn_id");
        repo.store_session(&conn_id, 2, &[0u8; 32]).await.expect("store");

        for seq in [1u64, 2, 5, 100] {
            assert!(
                repo.advance_seq_num(&conn_id.0, seq).await.expect("advance"),
                "seq {seq} must be accepted"
            );
        }
    }

    #[tokio::test]
    async fn advance_seq_num_rejects_replay() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let conn_id = ConnectionId::generate().expect("conn_id");
        repo.store_session(&conn_id, 3, &[0u8; 32]).await.expect("store");

        assert!(repo.advance_seq_num(&conn_id.0, 10).await.expect("advance"), "seq 10 accepted");

        // Replaying the same packet must be rejected.
        assert!(
            !repo.advance_seq_num(&conn_id.0, 10).await.expect("advance"),
            "seq 10 replay rejected"
        );

        // Older packet must be rejected.
        assert!(
            !repo.advance_seq_num(&conn_id.0, 5).await.expect("advance"),
            "seq 5 (old) rejected"
        );
    }

    #[tokio::test]
    async fn advance_seq_num_independent_per_connection() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let conn_a = ConnectionId::generate().expect("conn_a");
        let conn_b = ConnectionId::generate().expect("conn_b");
        repo.store_session(&conn_a, 4, &[0u8; 32]).await.expect("store a");
        repo.store_session(&conn_b, 5, &[0u8; 32]).await.expect("store b");

        // Advance A to seq 50.
        assert!(repo.advance_seq_num(&conn_a.0, 50).await.expect("advance a"));

        // B starts at 0; seq 1 must still be accepted independently.
        assert!(repo.advance_seq_num(&conn_b.0, 1).await.expect("advance b"));
    }

    #[tokio::test]
    async fn advance_seq_num_missing_session_returns_false() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        // No session stored — advance_seq_num must return false (not an error).
        assert!(!repo.advance_seq_num(&[0u8; 16], 1).await.expect("advance"), "no session → false");
    }

    #[tokio::test]
    async fn advance_seq_num_rejects_overflow() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let conn_id = ConnectionId::generate().expect("conn_id");
        repo.store_session(&conn_id, 6, &[0u8; 32]).await.expect("store");

        // seq_num values that exceed i64::MAX must return SeqNumOverflow, not silently cap.
        let overflow = (i64::MAX as u64) + 1;
        let err = repo.advance_seq_num(&conn_id.0, overflow).await.unwrap_err();
        assert!(
            matches!(err, TeamserverError::SeqNumOverflow { seq_num } if seq_num == overflow),
            "expected SeqNumOverflow, got {err:?}"
        );

        // i64::MAX itself must be accepted (boundary: still fits).
        let max_ok = i64::MAX as u64;
        assert!(
            repo.advance_seq_num(&conn_id.0, max_ok).await.expect("advance at i64::MAX"),
            "seq i64::MAX must be accepted"
        );
    }

    #[tokio::test]
    async fn reg_fingerprint_first_call_accepted() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let fp = [0xAB_u8; ECDH_REG_FINGERPRINT_LEN];
        assert!(
            repo.try_record_reg_fingerprint(&fp, 300).await.expect("record"),
            "first occurrence must be accepted"
        );
    }

    #[tokio::test]
    async fn reg_fingerprint_second_call_rejected() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let fp = [0x12_u8; ECDH_REG_FINGERPRINT_LEN];
        assert!(repo.try_record_reg_fingerprint(&fp, 300).await.expect("first"), "first accepted");
        assert!(
            !repo.try_record_reg_fingerprint(&fp, 300).await.expect("second"),
            "duplicate must be rejected"
        );
    }

    #[tokio::test]
    async fn reg_fingerprint_distinct_fps_both_accepted() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let fp_a = [0x01_u8; ECDH_REG_FINGERPRINT_LEN];
        let fp_b = [0x02_u8; ECDH_REG_FINGERPRINT_LEN];
        assert!(repo.try_record_reg_fingerprint(&fp_a, 300).await.expect("a"), "fp_a accepted");
        assert!(repo.try_record_reg_fingerprint(&fp_b, 300).await.expect("b"), "fp_b accepted");
    }

    #[tokio::test]
    async fn reg_fingerprint_expired_entry_reaccepted() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let fp = [0x99_u8; ECDH_REG_FINGERPRINT_LEN];

        // Insert with a TTL of 0 seconds (expires immediately).
        assert!(repo.try_record_reg_fingerprint(&fp, 0).await.expect("first"), "first accepted");

        // A second call should prune the already-expired entry and accept it again.
        assert!(
            repo.try_record_reg_fingerprint(&fp, 300).await.expect("second"),
            "re-registration after expiry must be accepted"
        );
    }

    #[tokio::test]
    async fn get_session_key_by_agent_id_returns_none_when_no_session() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let result = repo.get_session_key_by_agent_id(0xDEAD_BEEF).await.expect("query");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_session_key_by_agent_id_returns_most_recent_when_multiple_sessions() {
        let (db, master_key) = test_db().await;
        let repo = EcdhRepository::new(db.pool().clone(), master_key);

        let agent_id = 0x1111_2222_u32;
        let older_key = [0x11_u8; 32];
        let newer_key = [0x22_u8; 32];

        let conn_id1 = ConnectionId::generate().expect("conn1");
        repo.store_session(&conn_id1, agent_id, &older_key).await.expect("store older");

        // Wait a tick so created_at differs; SQLite stores seconds so we poke
        // the row directly with a later timestamp instead.
        let conn_id2 = ConnectionId::generate().expect("conn2");
        repo.store_session(&conn_id2, agent_id, &newer_key).await.expect("store newer");

        // Advance the second row's created_at past the first so ordering is deterministic.
        sqlx::query(
            "UPDATE ts_ecdh_sessions SET created_at = created_at + 1 WHERE connection_id = ?",
        )
        .bind(conn_id2.0.as_slice())
        .execute(db.pool())
        .await
        .expect("advance timestamp");

        let result =
            repo.get_session_key_by_agent_id(agent_id).await.expect("query").expect("Some");
        assert_eq!(result, newer_key, "must return key from most-recent session");
    }
}
