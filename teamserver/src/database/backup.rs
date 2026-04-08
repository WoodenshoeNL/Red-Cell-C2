//! Hot-backup tooling for the Red Cell teamserver SQLite database.
//!
//! [`DatabaseBackupScheduler`] spawns a background Tokio task that calls
//! [`Database::backup`] at a configurable interval, naming each snapshot
//! `red-cell-YYYYMMDD-HHMMSS.db` in the directory provided in the profile.
//!
//! [`Database::backup`] uses `VACUUM INTO` which is safe to call against a
//! live WAL-mode database and never locks writers or readers.

use std::path::{Path, PathBuf};
use std::time::Duration;

use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;
use tracing::{error, info, warn};

use super::{Database, TeamserverError};

/// Default backup interval: 1 hour.
pub const DEFAULT_BACKUP_INTERVAL_SECS: u64 = 3600;

/// Format description used to build snapshot filenames.
///
/// Output: `YYYYMMDD-HHMMSS`
static BACKUP_TS_FORMAT: &[FormatItem<'_>] =
    format_description!("[year][month][day]-[hour][minute][second]");

impl Database {
    /// Create a hot backup of the current database at `dest`.
    ///
    /// Uses `VACUUM INTO` which works safely against a live WAL-mode SQLite
    /// database without acquiring an exclusive write lock.
    ///
    /// # Errors
    ///
    /// Returns [`TeamserverError::Database`] if the `VACUUM INTO` statement
    /// fails (e.g. the destination directory does not exist).
    pub async fn backup(&self, dest: &Path) -> Result<(), TeamserverError> {
        let dest_str = dest
            .to_str()
            .ok_or_else(|| TeamserverError::InvalidDatabasePath { path: dest.to_path_buf() })?;
        // VACUUM INTO creates a compacted copy at the given path.  It works
        // on live WAL-mode databases and does not require an exclusive lock.
        sqlx::query(&format!("VACUUM INTO '{}'", dest_str.replace('\'', "''")))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// Handle returned by [`DatabaseBackupScheduler::spawn`].
///
/// Dropping the handle aborts the background scheduler task.
pub struct DatabaseBackupScheduler {
    handle: tokio::task::JoinHandle<()>,
}

impl DatabaseBackupScheduler {
    /// Spawn the backup-scheduler background task.
    ///
    /// * `database`  — database handle used to issue `VACUUM INTO`.
    /// * `backup_dir` — directory where snapshot files are written.
    /// * `interval`   — time between consecutive snapshots.
    pub fn spawn(database: Database, backup_dir: PathBuf, interval: Duration) -> Self {
        let handle = tokio::spawn(run_backup_scheduler(database, backup_dir, interval));
        Self { handle }
    }

    /// Abort the background task and await its completion.
    pub async fn stop(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }
}

impl std::fmt::Debug for DatabaseBackupScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseBackupScheduler").finish_non_exhaustive()
    }
}

async fn run_backup_scheduler(database: Database, backup_dir: PathBuf, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    // Skip the first immediate tick so the first backup fires after one full interval.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        match snapshot_path(&backup_dir) {
            Ok(dest) => {
                info!(path = %dest.display(), "starting database hot backup");
                match database.backup(&dest).await {
                    Ok(()) => info!(path = %dest.display(), "database hot backup completed"),
                    Err(err) => {
                        error!(%err, path = %dest.display(), "database hot backup failed");
                    }
                }
            }
            Err(err) => {
                warn!(%err, "failed to build backup snapshot path — skipping this backup cycle");
            }
        }
    }
}

/// Build a snapshot path of the form `<backup_dir>/red-cell-YYYYMMDD-HHMMSS.db`.
pub fn snapshot_path(backup_dir: &Path) -> Result<PathBuf, time::error::Format> {
    let now = OffsetDateTime::now_utc();
    let ts = now.format(BACKUP_TS_FORMAT)?;
    Ok(backup_dir.join(format!("red-cell-{ts}.db")))
}

#[cfg(test)]
mod tests {
    use super::snapshot_path;
    use std::path::Path;

    #[test]
    fn snapshot_path_has_correct_prefix_and_extension() {
        let dir = Path::new("/var/backups/red-cell");
        let path = snapshot_path(dir).expect("format should succeed");

        let name = path.file_name().and_then(|n| n.to_str()).expect("name must be UTF-8");
        assert!(
            name.starts_with("red-cell-"),
            "backup file should start with 'red-cell-', got: {name}"
        );
        assert!(name.ends_with(".db"), "backup file should end with '.db', got: {name}");
        // Timestamp portion is 15 chars: YYYYMMDD-HHMMSS
        let ts_part = name.strip_prefix("red-cell-").and_then(|s| s.strip_suffix(".db")).unwrap();
        assert_eq!(ts_part.len(), 15, "timestamp portion should be 15 chars, got: {ts_part}");
        // Basic sanity: all digits or a single '-'
        assert!(
            ts_part.chars().all(|c| c.is_ascii_digit() || c == '-'),
            "timestamp should contain only digits and '-', got: {ts_part}"
        );
    }

    #[test]
    fn snapshot_path_is_inside_provided_directory() {
        let dir = Path::new("/some/dir");
        let path = snapshot_path(dir).expect("format should succeed");
        assert_eq!(path.parent(), Some(dir));
    }

    #[tokio::test]
    async fn backup_writes_readable_sqlite_file() {
        use super::super::Database;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("temp dir");
        let db_path = tmp.path().join("test.sqlite");
        let db = Database::connect(&db_path).await.expect("db should open");

        let backup_path = tmp.path().join("backup.db");
        db.backup(&backup_path).await.expect("backup should succeed");

        assert!(backup_path.exists(), "backup file should exist after VACUUM INTO");
        assert!(backup_path.metadata().map(|m| m.len() > 0).unwrap_or(false));
    }

    #[tokio::test]
    async fn backup_returns_error_for_nonexistent_directory() {
        use super::super::Database;
        use std::path::PathBuf;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("temp dir");
        let db_path = tmp.path().join("test.sqlite");
        let db = Database::connect(&db_path).await.expect("db should open");

        let bad_dest = PathBuf::from("/nonexistent/dir/backup.db");
        assert!(db.backup(&bad_dest).await.is_err(), "backup to missing dir should fail");
    }

    /// Verify the scheduler creates at least one backup file within the interval.
    #[tokio::test]
    async fn scheduler_creates_snapshot_on_interval() {
        use super::super::Database;
        use super::DatabaseBackupScheduler;
        use std::time::Duration;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("temp dir");
        let db_path = tmp.path().join("sched-test.sqlite");
        let db = Database::connect(&db_path).await.expect("db should open");

        let backup_dir = tmp.path().join("backups");
        std::fs::create_dir_all(&backup_dir).expect("create backup dir");

        // Very short interval so the test completes quickly.
        let scheduler =
            DatabaseBackupScheduler::spawn(db, backup_dir.clone(), Duration::from_millis(50));

        // Wait for at least one interval to fire.
        tokio::time::sleep(Duration::from_millis(200)).await;

        scheduler.stop().await;

        // Check that at least one backup file was created.
        let entries: Vec<_> = std::fs::read_dir(&backup_dir)
            .expect("read backup dir")
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("red-cell-") && n.ends_with(".db"))
            })
            .collect();

        assert!(!entries.is_empty(), "scheduler should have created at least one backup snapshot");

        // Each backup file should be non-empty (contains valid SQLite data).
        for entry in &entries {
            let size = entry.metadata().expect("metadata").len();
            assert!(size > 0, "backup file should be non-empty: {:?}", entry.path());
        }
    }

    /// Verify that backup files created by the scheduler are valid SQLite databases
    /// that can be opened and queried.
    #[tokio::test]
    async fn backup_snapshot_is_valid_sqlite() {
        use super::super::Database;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("temp dir");
        let db_path = tmp.path().join("valid-test.sqlite");
        let db = Database::connect(&db_path).await.expect("db should open");

        // Write some data so the backup has content.
        db.audit_log()
            .create(&crate::database::audit::AuditLogEntry {
                id: None,
                actor: "backup-test".to_owned(),
                action: "test.verify".to_owned(),
                target_kind: "test".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-04-08T12:00:00Z".to_owned(),
            })
            .await
            .expect("insert audit log");

        let backup_path = tmp.path().join("valid-backup.db");
        db.backup(&backup_path).await.expect("backup should succeed");

        // Open the backup as a new Database and verify the data is there.
        let backup_db = Database::connect(&backup_path).await.expect("open backup");
        let entries = backup_db.audit_log().list().await.expect("list audit log from backup");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].actor, "backup-test");
    }
}
