//! Job tracking for background BOF threads and spawned processes.
//!
//! Each entry in the [`JobStore`] represents one background task whose handle
//! can be suspended, resumed, or terminated by the operator via
//! `CommandJob` (21).

use std::collections::HashMap;

// ─── Constants matching Havoc's Jobs.h ──────────────────────────────────────

/// Background thread (e.g. threaded COFF execution via `CoffeeRunner`).
pub const JOB_TYPE_THREAD: u32 = 1;
/// Spawned child process.
pub const JOB_TYPE_PROCESS: u32 = 2;
/// Spawned process with output capture via anonymous pipes.
pub const JOB_TYPE_TRACK_PROCESS: u32 = 3;

/// Job is actively running.
pub const JOB_STATE_RUNNING: u32 = 1;
/// Job has been suspended by the operator.
pub const JOB_STATE_SUSPENDED: u32 = 2;
/// Job has exited or been killed.
pub const JOB_STATE_DEAD: u32 = 3;

// ─── Job entry ──────────────────────────────────────────────────────────────

/// A single tracked background job.
#[derive(Debug)]
pub struct Job {
    /// Unique identifier assigned when the job is registered.
    pub job_id: u32,
    /// One of `JOB_TYPE_THREAD`, `JOB_TYPE_PROCESS`, or `JOB_TYPE_TRACK_PROCESS`.
    pub job_type: u32,
    /// Current state: running, suspended, or dead.
    pub state: u32,
    /// Platform-native handle (HANDLE on Windows).
    #[cfg(windows)]
    pub handle: isize,
    /// Placeholder on non-Windows targets (not used).
    #[cfg(not(windows))]
    pub handle: u64,
}

// ─── JobStore ───────────────────────────────────────────────────────────────

/// Collection of tracked background jobs, keyed by job ID.
#[derive(Debug)]
pub struct JobStore {
    jobs: HashMap<u32, Job>,
    next_id: u32,
}

impl Default for JobStore {
    fn default() -> Self {
        Self { jobs: HashMap::new(), next_id: 1 }
    }
}

impl JobStore {
    /// Create an empty job store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new job and return its assigned ID.
    #[cfg(windows)]
    pub fn add(&mut self, job_type: u32, handle: isize) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.jobs.insert(id, Job { job_id: id, job_type, state: JOB_STATE_RUNNING, handle });
        id
    }

    /// Register a new job and return its assigned ID (non-Windows stub).
    #[cfg(not(windows))]
    pub fn add(&mut self, job_type: u32, handle: u64) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.jobs.insert(id, Job { job_id: id, job_type, state: JOB_STATE_RUNNING, handle });
        id
    }

    /// Return an iterator over all tracked jobs.
    pub fn list(&self) -> impl Iterator<Item = &Job> {
        self.jobs.values()
    }

    /// Suspend a running job.  Returns `true` on success.
    pub fn suspend(&mut self, job_id: u32) -> bool {
        let Some(job) = self.jobs.get_mut(&job_id) else { return false };
        if job.state != JOB_STATE_RUNNING {
            return false;
        }

        #[cfg(windows)]
        {
            // SAFETY: calling Win32 SuspendThread on a thread handle.
            let result =
                unsafe { windows_sys::Win32::System::Threading::SuspendThread(job.handle) };
            if result == u32::MAX {
                return false;
            }
        }

        job.state = JOB_STATE_SUSPENDED;
        true
    }

    /// Resume a suspended job.  Returns `true` on success.
    pub fn resume(&mut self, job_id: u32) -> bool {
        let Some(job) = self.jobs.get_mut(&job_id) else { return false };
        if job.state != JOB_STATE_SUSPENDED {
            return false;
        }

        #[cfg(windows)]
        {
            // SAFETY: calling Win32 ResumeThread on a thread handle.
            let result = unsafe { windows_sys::Win32::System::Threading::ResumeThread(job.handle) };
            if result == u32::MAX {
                return false;
            }
        }

        job.state = JOB_STATE_RUNNING;
        true
    }

    /// Kill and remove a job.  Returns `true` on success.
    pub fn kill(&mut self, job_id: u32) -> bool {
        let Some(job) = self.jobs.remove(&job_id) else { return false };

        #[cfg(windows)]
        {
            if job.job_type == JOB_TYPE_THREAD {
                // SAFETY: calling Win32 TerminateThread on a thread handle.
                unsafe {
                    windows_sys::Win32::System::Threading::TerminateThread(job.handle, 0);
                    windows_sys::Win32::Foundation::CloseHandle(job.handle);
                };
            } else {
                // SAFETY: calling Win32 TerminateProcess on a process handle.
                unsafe {
                    windows_sys::Win32::System::Threading::TerminateProcess(job.handle, 0);
                    windows_sys::Win32::Foundation::CloseHandle(job.handle);
                };
            }
        }

        // Suppress unused variable warning on non-Windows
        #[cfg(not(windows))]
        let _ = job;

        true
    }

    /// Remove jobs whose state is [`JOB_STATE_DEAD`].
    pub fn reap_dead(&mut self) {
        self.jobs.retain(|_, j| j.state != JOB_STATE_DEAD);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_store_is_empty() {
        let store = JobStore::new();
        assert_eq!(store.list().count(), 0);
    }

    #[test]
    fn add_returns_incrementing_ids() {
        let mut store = JobStore::new();
        let id1 = store.add(JOB_TYPE_THREAD, 0);
        let id2 = store.add(JOB_TYPE_PROCESS, 0);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn list_returns_all_jobs() {
        let mut store = JobStore::new();
        store.add(JOB_TYPE_THREAD, 0);
        store.add(JOB_TYPE_PROCESS, 0);
        assert_eq!(store.list().count(), 2);
    }

    #[test]
    fn suspend_nonexistent_returns_false() {
        let mut store = JobStore::new();
        assert!(!store.suspend(999));
    }

    #[test]
    fn resume_nonexistent_returns_false() {
        let mut store = JobStore::new();
        assert!(!store.resume(999));
    }

    #[test]
    fn kill_nonexistent_returns_false() {
        let mut store = JobStore::new();
        assert!(!store.kill(999));
    }

    #[test]
    fn kill_removes_job() {
        let mut store = JobStore::new();
        let id = store.add(JOB_TYPE_THREAD, 0);
        assert!(store.kill(id));
        assert_eq!(store.list().count(), 0);
    }

    #[test]
    fn reap_dead_removes_dead_jobs_only() {
        let mut store = JobStore::new();
        store.add(JOB_TYPE_THREAD, 0);
        let id2 = store.add(JOB_TYPE_PROCESS, 0);
        // Manually mark one as dead
        store.jobs.get_mut(&id2).map(|j| j.state = JOB_STATE_DEAD);
        store.reap_dead();
        assert_eq!(store.list().count(), 1);
    }

    // On non-Windows, suspend/resume just toggle state without Win32 calls.
    #[cfg(not(windows))]
    #[test]
    fn suspend_and_resume_toggle_state() {
        let mut store = JobStore::new();
        let id = store.add(JOB_TYPE_THREAD, 0);
        assert!(store.suspend(id));
        assert_eq!(store.jobs[&id].state, JOB_STATE_SUSPENDED);
        assert!(store.resume(id));
        assert_eq!(store.jobs[&id].state, JOB_STATE_RUNNING);
    }

    #[cfg(not(windows))]
    #[test]
    fn suspend_already_suspended_returns_false() {
        let mut store = JobStore::new();
        let id = store.add(JOB_TYPE_THREAD, 0);
        assert!(store.suspend(id));
        assert!(!store.suspend(id));
    }

    #[cfg(not(windows))]
    #[test]
    fn resume_running_returns_false() {
        let mut store = JobStore::new();
        let id = store.add(JOB_TYPE_THREAD, 0);
        assert!(!store.resume(id));
    }
}
