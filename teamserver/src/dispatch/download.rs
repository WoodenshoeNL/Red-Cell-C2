//! In-memory download tracking for the Beacon/filesystem download sub-protocol.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use super::CommandDispatchError;

/// Multiplier applied to the per-download cap to compute the aggregate in-memory cap.
pub(super) const DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER: usize = 4;

/// Maximum number of simultaneous in-progress downloads tracked per agent.
/// A compromised agent can send unlimited Download mode=0 (start) packets, each consuming heap
/// memory before any byte-level cap activates. This count cap closes that gap.
pub(super) const MAX_CONCURRENT_DOWNLOADS_PER_AGENT: usize = 32;

/// Tracks in-flight file downloads buffered in memory until completion.
#[derive(Clone, Debug)]
pub(crate) struct DownloadTracker {
    pub(in crate::dispatch) max_download_bytes: usize,
    pub(in crate::dispatch) max_total_download_bytes: usize,
    pub(in crate::dispatch) max_concurrent_downloads_per_agent: usize,
    inner: Arc<RwLock<DownloadTrackerState>>,
}

#[derive(Debug, Default)]
struct DownloadTrackerState {
    downloads: HashMap<(u32, u32), TrackedDownload>,
    total_buffered_bytes: usize,
}

#[derive(Clone, Debug)]
struct TrackedDownload {
    state: DownloadState,
}

/// State for a single in-progress file download.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::dispatch) struct DownloadState {
    pub(in crate::dispatch) request_id: u32,
    pub(in crate::dispatch) remote_path: String,
    pub(in crate::dispatch) expected_size: u64,
    pub(in crate::dispatch) data: Vec<u8>,
    pub(in crate::dispatch) started_at: String,
}

impl DownloadTracker {
    pub(crate) fn new(max_download_bytes: usize) -> Self {
        let max_total_download_bytes = max_download_bytes
            .saturating_mul(DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER)
            .max(max_download_bytes);
        Self::with_limits(max_download_bytes, max_total_download_bytes)
    }

    pub(crate) fn from_max_download_bytes(max_download_bytes: u64) -> Self {
        let max_download_bytes = match usize::try_from(max_download_bytes) {
            Ok(value) => value,
            Err(_) => usize::MAX,
        };
        Self::new(max_download_bytes)
    }

    pub(in crate::dispatch) fn with_limits(
        max_download_bytes: usize,
        max_total_download_bytes: usize,
    ) -> Self {
        Self {
            max_download_bytes,
            max_total_download_bytes: max_total_download_bytes.max(max_download_bytes),
            max_concurrent_downloads_per_agent: MAX_CONCURRENT_DOWNLOADS_PER_AGENT,
            inner: Arc::new(RwLock::new(DownloadTrackerState::default())),
        }
    }

    /// Return the per-download in-memory cap used by this tracker.
    pub(in crate::dispatch) fn max_download_bytes(&self) -> usize {
        self.max_download_bytes
    }

    /// Override the per-agent concurrent download limit.
    ///
    /// Must be called before any downloads are tracked.
    #[must_use]
    pub(crate) fn with_max_concurrent_per_agent(mut self, limit: usize) -> Self {
        self.max_concurrent_downloads_per_agent = limit;
        self
    }

    /// Override the aggregate in-memory cap across all active downloads.
    ///
    /// The value is clamped to at least `max_download_bytes` so a single
    /// download can always make progress up to its per-download limit.
    /// Must be called before any downloads are tracked.
    #[must_use]
    pub(crate) fn with_max_aggregate_bytes(mut self, limit: usize) -> Self {
        self.max_total_download_bytes = limit.max(self.max_download_bytes);
        self
    }

    pub(super) async fn start(
        &self,
        agent_id: u32,
        file_id: u32,
        state: DownloadState,
    ) -> Result<(), CommandDispatchError> {
        let mut tracker = self.inner.write().await;
        // Replacing an existing entry for the same (agent, file) pair does not count against the
        // cap — remove it first so the count below reflects truly new slots being consumed.
        self.remove_locked(&mut tracker, agent_id, file_id);
        let active = tracker.downloads.keys().filter(|(aid, _)| *aid == agent_id).count();
        if active >= self.max_concurrent_downloads_per_agent {
            return Err(CommandDispatchError::DownloadConcurrentLimitExceeded {
                agent_id,
                file_id,
                max_concurrent: self.max_concurrent_downloads_per_agent,
            });
        }
        tracker.downloads.insert((agent_id, file_id), TrackedDownload { state });
        Ok(())
    }

    pub(super) async fn append(
        &self,
        agent_id: u32,
        file_id: u32,
        chunk: &[u8],
    ) -> Result<DownloadState, CommandDispatchError> {
        let mut tracker = self.inner.write().await;
        let Some(current_len) =
            tracker.downloads.get(&(agent_id, file_id)).map(|download| download.state.data.len())
        else {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: 0,
                message: format!(
                    "download 0x{file_id:08X} for agent 0x{agent_id:08X} was not opened"
                ),
            });
        };
        let Some(next_len) = current_len.checked_add(chunk.len()) else {
            self.remove_locked(&mut tracker, agent_id, file_id);
            return Err(CommandDispatchError::DownloadTooLarge {
                agent_id,
                file_id,
                max_download_bytes: self.max_download_bytes,
            });
        };
        if next_len > self.max_download_bytes {
            self.remove_locked(&mut tracker, agent_id, file_id);
            return Err(CommandDispatchError::DownloadTooLarge {
                agent_id,
                file_id,
                max_download_bytes: self.max_download_bytes,
            });
        }
        let Some(next_total) = tracker.total_buffered_bytes.checked_add(chunk.len()) else {
            self.remove_locked(&mut tracker, agent_id, file_id);
            return Err(CommandDispatchError::DownloadAggregateTooLarge {
                agent_id,
                file_id,
                max_total_download_bytes: self.max_total_download_bytes,
            });
        };
        if next_total > self.max_total_download_bytes {
            self.remove_locked(&mut tracker, agent_id, file_id);
            return Err(CommandDispatchError::DownloadAggregateTooLarge {
                agent_id,
                file_id,
                max_total_download_bytes: self.max_total_download_bytes,
            });
        }
        let Some(download) = tracker.downloads.get_mut(&(agent_id, file_id)) else {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: 0,
                message: format!(
                    "download 0x{file_id:08X} for agent 0x{agent_id:08X} was not opened"
                ),
            });
        };
        download.state.data.extend_from_slice(chunk);
        let updated = download.state.clone();
        let _ = download;
        tracker.total_buffered_bytes = next_total;
        Ok(updated)
    }

    pub(super) async fn finish(&self, agent_id: u32, file_id: u32) -> Option<DownloadState> {
        let mut tracker = self.inner.write().await;
        self.remove_locked(&mut tracker, agent_id, file_id)
    }

    pub(crate) async fn drain_agent(&self, agent_id: u32) -> usize {
        let mut tracker = self.inner.write().await;
        let file_ids = tracker
            .downloads
            .keys()
            .filter_map(|(download_agent_id, file_id)| {
                (*download_agent_id == agent_id).then_some(*file_id)
            })
            .collect::<Vec<_>>();

        let mut removed = 0;
        for file_id in file_ids {
            if self.remove_locked(&mut tracker, agent_id, file_id).is_some() {
                removed += 1;
            }
        }

        removed
    }

    pub(super) async fn active_for_agent(&self, agent_id: u32) -> Vec<(u32, DownloadState)> {
        let tracker = self.inner.read().await;
        let mut downloads = tracker
            .downloads
            .iter()
            .filter_map(|((download_agent_id, file_id), download)| {
                (*download_agent_id == agent_id).then_some((*file_id, download.state.clone()))
            })
            .collect::<Vec<_>>();
        downloads.sort_by_key(|(file_id, _)| *file_id);
        downloads
    }

    fn remove_locked(
        &self,
        tracker: &mut DownloadTrackerState,
        agent_id: u32,
        file_id: u32,
    ) -> Option<DownloadState> {
        let removed = tracker.downloads.remove(&(agent_id, file_id))?;
        tracker.total_buffered_bytes =
            tracker.total_buffered_bytes.saturating_sub(removed.state.data.len());
        Some(removed.state)
    }

    #[cfg(test)]
    pub(super) async fn buffered_bytes(&self) -> usize {
        self.inner.read().await.total_buffered_bytes
    }
}
