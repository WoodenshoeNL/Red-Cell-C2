//! Periodic audit-log retention pruner.
//!
//! [`AuditLogPruner`] spawns a background Tokio task that periodically deletes
//! audit-log rows older than a configurable retention period, preventing
//! unbounded table growth in long-running teamserver instances.

use std::time::Duration;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{error, info};

use super::Database;

/// Default audit-log retention period: 90 days.
pub const DEFAULT_AUDIT_RETENTION_DAYS: u32 = 90;

/// Default interval between pruner runs: 1 hour.
pub const DEFAULT_AUDIT_PRUNE_INTERVAL_SECS: u64 = 3600;

/// Handle returned by [`AuditLogPruner::spawn`].
///
/// Dropping the handle aborts the background pruner task.
pub struct AuditLogPruner {
    handle: tokio::task::JoinHandle<()>,
}

impl AuditLogPruner {
    /// Spawn the audit-log pruner background task.
    ///
    /// * `database`       — database handle used to delete expired rows.
    /// * `retention_days` — rows older than this many days are deleted.
    /// * `interval`       — time between consecutive pruner runs.
    pub fn spawn(database: Database, retention_days: u32, interval: Duration) -> Self {
        let handle = tokio::spawn(run_pruner(database, retention_days, interval));
        Self { handle }
    }

    /// Abort the background task and await its completion.
    pub async fn stop(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }
}

impl std::fmt::Debug for AuditLogPruner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogPruner").finish_non_exhaustive()
    }
}

/// Compute the RFC 3339 cutoff timestamp for the given retention period.
fn cutoff_timestamp(retention_days: u32) -> Option<String> {
    let now = OffsetDateTime::now_utc();
    let cutoff = now - time::Duration::days(i64::from(retention_days));
    cutoff.format(&Rfc3339).ok()
}

async fn run_pruner(database: Database, retention_days: u32, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    // Skip the first immediate tick so the first prune fires after one full interval.
    ticker.tick().await;

    loop {
        ticker.tick().await;

        let Some(cutoff) = cutoff_timestamp(retention_days) else {
            error!("failed to compute audit-log cutoff timestamp — skipping this cycle");
            continue;
        };

        match database.audit_log().delete_older_than(&cutoff).await {
            Ok(0) => {
                info!(cutoff, "audit-log pruner ran — no expired rows");
            }
            Ok(deleted) => {
                info!(cutoff, deleted, "audit-log pruner deleted expired rows");
            }
            Err(err) => {
                error!(%err, cutoff, "audit-log pruner failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cutoff_timestamp_returns_rfc3339() {
        let ts = cutoff_timestamp(90).expect("should produce a timestamp");
        // Verify it parses back as a valid RFC 3339 timestamp.
        let parsed = OffsetDateTime::parse(&ts, &Rfc3339);
        assert!(parsed.is_ok(), "cutoff should be valid RFC 3339: {ts}");
    }

    #[test]
    fn cutoff_timestamp_is_in_the_past() {
        let ts = cutoff_timestamp(1).expect("should produce a timestamp");
        let parsed = OffsetDateTime::parse(&ts, &Rfc3339).expect("valid RFC 3339");
        assert!(parsed < OffsetDateTime::now_utc(), "cutoff should be in the past");
    }

    #[test]
    fn cutoff_timestamp_zero_days_is_approximately_now() {
        let before = OffsetDateTime::now_utc();
        let ts = cutoff_timestamp(0).expect("should produce a timestamp");
        let parsed = OffsetDateTime::parse(&ts, &Rfc3339).expect("valid RFC 3339");
        let after = OffsetDateTime::now_utc();
        assert!(parsed >= before - time::Duration::seconds(1));
        assert!(parsed <= after + time::Duration::seconds(1));
    }

    #[tokio::test]
    async fn pruner_deletes_old_rows() {
        use crate::database::audit::AuditLogEntry;

        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.audit_log();

        // Insert a row dated 200 days ago.
        repo.create(&AuditLogEntry {
            id: None,
            actor: "old-actor".to_owned(),
            action: "test.old".to_owned(),
            target_kind: "test".to_owned(),
            target_id: None,
            details: None,
            occurred_at: "2025-01-01T00:00:00Z".to_owned(),
        })
        .await
        .expect("insert old");

        // Insert a recent row.
        let now = OffsetDateTime::now_utc();
        let recent_ts = now.format(&Rfc3339).expect("format");
        repo.create(&AuditLogEntry {
            id: None,
            actor: "new-actor".to_owned(),
            action: "test.new".to_owned(),
            target_kind: "test".to_owned(),
            target_id: None,
            details: None,
            occurred_at: recent_ts,
        })
        .await
        .expect("insert new");

        // Prune with 90-day retention.
        let cutoff = cutoff_timestamp(90).expect("cutoff");
        let deleted = repo.delete_older_than(&cutoff).await.expect("prune");
        assert_eq!(deleted, 1, "should delete the old row");

        let remaining = repo.list().await.expect("list");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].actor, "new-actor");
    }

    #[tokio::test]
    async fn pruner_leaves_recent_rows() {
        use crate::database::audit::AuditLogEntry;

        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.audit_log();

        let now = OffsetDateTime::now_utc();
        let recent_ts = now.format(&Rfc3339).expect("format");
        repo.create(&AuditLogEntry {
            id: None,
            actor: "recent".to_owned(),
            action: "test.recent".to_owned(),
            target_kind: "test".to_owned(),
            target_id: None,
            details: None,
            occurred_at: recent_ts,
        })
        .await
        .expect("insert");

        let cutoff = cutoff_timestamp(90).expect("cutoff");
        let deleted = repo.delete_older_than(&cutoff).await.expect("prune");
        assert_eq!(deleted, 0);

        let remaining = repo.list().await.expect("list");
        assert_eq!(remaining.len(), 1);
    }

    #[tokio::test]
    async fn scheduler_prunes_on_interval() {
        use crate::database::audit::AuditLogEntry;

        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.audit_log();

        // Insert an old row.
        repo.create(&AuditLogEntry {
            id: None,
            actor: "old".to_owned(),
            action: "test.old".to_owned(),
            target_kind: "test".to_owned(),
            target_id: None,
            details: None,
            occurred_at: "2024-01-01T00:00:00Z".to_owned(),
        })
        .await
        .expect("insert");

        let pruner = AuditLogPruner::spawn(db.clone(), 90, Duration::from_millis(50));

        // Wait for the pruner to run.
        let found = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let rows = db.audit_log().list().await.expect("list");
                if rows.is_empty() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        pruner.stop().await;
        assert!(found.is_ok(), "timed out waiting for pruner to delete old row");
    }
}
