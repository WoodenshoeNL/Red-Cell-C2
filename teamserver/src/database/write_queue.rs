//! Bounded write queue for database degraded-mode operation.
//!
//! When the [`DatabaseHealthMonitor`] detects that the database is unavailable,
//! write operations can be deferred into a [`WriteQueue`] rather than failing
//! immediately.  Once the database recovers, [`WriteQueue::flush`] replays all
//! buffered operations in order.

use std::collections::VecDeque;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{error, info, warn};

use super::TeamserverError;
use crate::Database;
use crate::database::audit::AuditLogEntry;

/// Default maximum number of deferred writes held in the queue.
pub const DEFAULT_WRITE_QUEUE_CAPACITY: usize = 1024;

/// A single deferred database write operation.
///
/// Each variant captures enough state to replay the write against the database
/// when connectivity is restored.
#[derive(Clone, Debug)]
pub enum DeferredWrite {
    /// Insert a new agent row with full transport parameters.
    AgentCreateFull {
        /// Agent metadata.
        agent: red_cell_common::AgentRecord,
        /// Listener that accepted the session.
        listener_name: String,
        /// Initial AES-CTR block offset.
        ctr_block_offset: u64,
        /// Whether legacy (reset-per-packet) CTR mode is active.
        legacy_ctr: bool,
        /// Whether the agent negotiated callback sequence-number replay protection.
        seq_protected: bool,
    },
    /// Update an agent row after re-registration.
    AgentReregisterFull {
        /// Updated agent metadata.
        agent: red_cell_common::AgentRecord,
        /// Listener that accepted the fresh session.
        listener_name: String,
        /// Legacy CTR flag for the new session.
        legacy_ctr: bool,
        /// Seq-protection flag negotiated on the fresh session.
        seq_protected: bool,
    },
    /// Persist an agent metadata update (status, last callback, etc.).
    AgentUpdate {
        /// Updated agent metadata.
        agent: red_cell_common::AgentRecord,
        /// Listener name associated with the current session.
        listener_name: String,
    },
    /// Update the persisted CTR block offset for an agent.
    AgentSetCtrOffset {
        /// Agent identifier.
        agent_id: u32,
        /// New CTR block offset.
        offset: u64,
    },
    /// Update the persisted last-seen callback sequence number.
    AgentSetLastSeenSeq {
        /// Agent identifier.
        agent_id: u32,
        /// New sequence number.
        seq: u64,
    },
    /// Persist an audit-log entry.
    AuditLogCreate {
        /// The audit-log row to insert.
        entry: AuditLogEntry,
    },
}

/// Bounded queue of deferred database writes.
///
/// Thread-safe: multiple callers can enqueue concurrently.  [`WriteQueue::flush`]
/// drains the queue and replays each write against the database.
#[derive(Clone, Debug)]
pub struct WriteQueue {
    inner: Arc<Mutex<WriteQueueInner>>,
    capacity: usize,
}

#[derive(Debug)]
struct WriteQueueInner {
    queue: VecDeque<DeferredWrite>,
    dropped: u64,
}

impl WriteQueue {
    /// Create a new write queue with the given maximum capacity.
    ///
    /// When the queue is full, the oldest entry is dropped and a warning is logged.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(WriteQueueInner { queue: VecDeque::new(), dropped: 0 })),
            capacity,
        }
    }

    /// Enqueue a deferred write operation.
    ///
    /// If the queue is at capacity, the oldest entry is dropped to make room.
    /// Returns `true` if the write was accepted, `false` if a slot had to be
    /// reclaimed (the new write is still enqueued either way).
    pub async fn enqueue(&self, write: DeferredWrite) -> bool {
        let mut inner = self.inner.lock().await;
        if inner.queue.len() >= self.capacity {
            inner.queue.pop_front();
            inner.dropped = inner.dropped.saturating_add(1);
            warn!(
                dropped = inner.dropped,
                capacity = self.capacity,
                "write queue at capacity — oldest entry dropped"
            );
            inner.queue.push_back(write);
            false
        } else {
            inner.queue.push_back(write);
            true
        }
    }

    /// Number of writes currently buffered.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.queue.len()
    }

    /// Whether the queue is empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.queue.is_empty()
    }

    /// Total number of writes that were dropped because the queue was at capacity.
    pub async fn total_dropped(&self) -> u64 {
        self.inner.lock().await.dropped
    }

    /// Drain all buffered writes and replay them against the database.
    ///
    /// Writes are replayed in FIFO order.  If an individual write fails, it is
    /// logged and skipped — we do not re-enqueue on failure because the database
    /// may have already partially applied the operation.
    ///
    /// Returns `(succeeded, failed)` counts.
    pub async fn flush(&self, database: &Database) -> (usize, usize) {
        let writes = {
            let mut inner = self.inner.lock().await;
            std::mem::take(&mut inner.queue)
        };

        if writes.is_empty() {
            return (0, 0);
        }

        info!(count = writes.len(), "flushing deferred write queue");

        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for write in writes {
            match replay_write(database, &write).await {
                Ok(()) => succeeded += 1,
                Err(err) => {
                    error!(%err, ?write, "failed to replay deferred write — skipping");
                    failed += 1;
                }
            }
        }

        info!(succeeded, failed, "deferred write queue flush complete");
        (succeeded, failed)
    }
}

/// Replay a single deferred write against the database.
async fn replay_write(database: &Database, write: &DeferredWrite) -> Result<(), TeamserverError> {
    match write {
        DeferredWrite::AgentCreateFull {
            agent,
            listener_name,
            ctr_block_offset,
            legacy_ctr,
            seq_protected,
        } => {
            database
                .agents()
                .create_full(agent, listener_name, *ctr_block_offset, *legacy_ctr, *seq_protected)
                .await
        }
        DeferredWrite::AgentReregisterFull { agent, listener_name, legacy_ctr, seq_protected } => {
            database
                .agents()
                .reregister_full(agent, listener_name, *legacy_ctr, *seq_protected)
                .await
        }
        DeferredWrite::AgentUpdate { agent, listener_name } => {
            database.agents().update_with_listener(agent, listener_name).await
        }
        DeferredWrite::AgentSetCtrOffset { agent_id, offset } => {
            database.agents().set_ctr_block_offset(*agent_id, *offset).await
        }
        DeferredWrite::AgentSetLastSeenSeq { agent_id, seq } => {
            database.agents().set_last_seen_seq(*agent_id, *seq).await
        }
        DeferredWrite::AuditLogCreate { entry } => {
            database.audit_log().create(entry).await.map(|_id| ())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_queue_flush_returns_zero_counts() {
        let db = Database::connect_in_memory().await.expect("db");
        let queue = WriteQueue::new(10);
        let (ok, fail) = queue.flush(&db).await;
        assert_eq!(ok, 0);
        assert_eq!(fail, 0);
    }

    #[tokio::test]
    async fn enqueue_and_len() {
        let queue = WriteQueue::new(10);
        assert!(queue.is_empty().await);

        let write = DeferredWrite::AgentSetCtrOffset { agent_id: 0x1234, offset: 42 };
        let accepted = queue.enqueue(write).await;
        assert!(accepted);
        assert_eq!(queue.len().await, 1);
        assert!(!queue.is_empty().await);
    }

    #[tokio::test]
    async fn capacity_drops_oldest() {
        let queue = WriteQueue::new(2);

        let w1 = DeferredWrite::AgentSetCtrOffset { agent_id: 1, offset: 1 };
        let w2 = DeferredWrite::AgentSetCtrOffset { agent_id: 2, offset: 2 };
        let w3 = DeferredWrite::AgentSetCtrOffset { agent_id: 3, offset: 3 };

        assert!(queue.enqueue(w1).await);
        assert!(queue.enqueue(w2).await);
        // Queue is now full — w3 should evict w1.
        assert!(!queue.enqueue(w3).await);

        assert_eq!(queue.len().await, 2);
        assert_eq!(queue.total_dropped().await, 1);
    }

    #[tokio::test]
    async fn flush_drains_queue() {
        let db = Database::connect_in_memory().await.expect("db");
        let queue = WriteQueue::new(10);

        // Enqueue a write that will fail (agent doesn't exist) — we just verify
        // the queue is drained and counts are returned.
        let write = DeferredWrite::AgentSetCtrOffset { agent_id: 0xBEEF, offset: 99 };
        queue.enqueue(write).await;
        assert_eq!(queue.len().await, 1);

        let (_ok, _fail) = queue.flush(&db).await;
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn flush_replays_audit_log_entry() {
        let db = Database::connect_in_memory().await.expect("db");
        let queue = WriteQueue::new(10);

        let entry = AuditLogEntry {
            id: None,
            actor: "test-operator".to_owned(),
            action: "agent.register".to_owned(),
            target_kind: "agent".to_owned(),
            target_id: Some("0xDEADBEEF".to_owned()),
            details: None,
            occurred_at: "2026-04-08T12:00:00Z".to_owned(),
        };
        queue.enqueue(DeferredWrite::AuditLogCreate { entry }).await;

        let (ok, fail) = queue.flush(&db).await;
        assert_eq!(ok, 1);
        assert_eq!(fail, 0);

        // Verify the audit log entry was actually written.
        let entries = db.audit_log().list().await.expect("list audit log");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].actor, "test-operator");
    }
}
