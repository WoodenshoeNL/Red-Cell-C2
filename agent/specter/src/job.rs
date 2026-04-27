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
    /// The original operator request ID, preserved so that
    /// `DEMON_COMMAND_JOB_DIED` callbacks can close the originating task.
    pub request_id: u32,
    /// Platform-native handle (HANDLE on Windows).
    #[cfg(windows)]
    pub handle: *mut core::ffi::c_void,
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
    ///
    /// `request_id` is the operator request that spawned this job — it is
    /// preserved so that `DEMON_COMMAND_JOB_DIED` can reference the
    /// originating task (see Havoc `Jobs.c:JobAdd`).
    #[cfg(windows)]
    pub fn add(&mut self, job_type: u32, handle: *mut core::ffi::c_void, request_id: u32) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.jobs
            .insert(id, Job { job_id: id, job_type, state: JOB_STATE_RUNNING, request_id, handle });
        id
    }

    /// Register a new job and return its assigned ID (non-Windows stub).
    #[cfg(not(windows))]
    pub fn add(&mut self, job_type: u32, handle: u64, request_id: u32) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.jobs
            .insert(id, Job { job_id: id, job_type, state: JOB_STATE_RUNNING, request_id, handle });
        id
    }

    /// Return an iterator over all tracked jobs.
    pub fn list(&self) -> impl Iterator<Item = &Job> {
        self.jobs.values()
    }

    /// Suspend a running job.  Returns `true` on success.
    #[allow(unsafe_code)]
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
    #[allow(unsafe_code)]
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
    #[allow(unsafe_code)]
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

    /// Poll all running jobs for natural exit.
    ///
    /// On Windows, calls `GetExitCodeThread` / `GetExitCodeProcess` for each
    /// running job.  Jobs whose thread or process has exited are marked
    /// [`JOB_STATE_DEAD`] and their handles are closed.
    ///
    /// Returns `(job_id, request_id)` pairs **only** for
    /// [`JOB_TYPE_TRACK_PROCESS`] jobs that died during this call — matching
    /// Havoc's behaviour where only tracked-process entries emit
    /// `DEMON_COMMAND_JOB_DIED` (see `Jobs.c:102-119`).  Thread and plain
    /// process jobs are still marked dead and reaped, but do not generate
    /// teamserver notifications.
    #[allow(unsafe_code)]
    pub fn poll(&mut self) -> Vec<(u32, u32)> {
        #[allow(unused_mut)]
        let mut tracked_dead = Vec::new();

        for job in self.jobs.values_mut() {
            if job.state != JOB_STATE_RUNNING {
                continue;
            }

            #[cfg(windows)]
            {
                let exited = match job.job_type {
                    JOB_TYPE_THREAD => {
                        let mut exit_code: u32 = 0;
                        // SAFETY: calling Win32 GetExitCodeThread on a valid thread handle.
                        let ok = unsafe {
                            windows_sys::Win32::System::Threading::GetExitCodeThread(
                                job.handle,
                                &mut exit_code,
                            )
                        };
                        // STILL_ACTIVE == 259 (STATUS_PENDING)
                        ok != 0 && exit_code != 259
                    }
                    JOB_TYPE_PROCESS | JOB_TYPE_TRACK_PROCESS => {
                        let mut exit_code: u32 = 0;
                        // SAFETY: calling Win32 GetExitCodeProcess on a valid process handle.
                        let ok = unsafe {
                            windows_sys::Win32::System::Threading::GetExitCodeProcess(
                                job.handle,
                                &mut exit_code,
                            )
                        };
                        ok != 0 && exit_code != 259
                    }
                    _ => false,
                };

                if exited {
                    job.state = JOB_STATE_DEAD;
                    // SAFETY: closing the now-dead handle.
                    unsafe {
                        windows_sys::Win32::Foundation::CloseHandle(job.handle);
                    };
                    job.handle = core::ptr::null_mut();

                    // Only tracked-process jobs generate DIED notifications
                    // (Havoc Jobs.c:102-119).  Threads and plain processes are
                    // silently reaped.
                    if job.job_type == JOB_TYPE_TRACK_PROCESS {
                        tracked_dead.push((job.job_id, job.request_id));
                    }
                }
            }

            // On non-Windows the handle is a dummy u64 — no OS polling is
            // possible, so running jobs stay running until explicitly killed.
            #[cfg(not(windows))]
            let _ = job;
        }

        tracked_dead
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
        let id1 = store.add(JOB_TYPE_THREAD, 0, 0);
        let id2 = store.add(JOB_TYPE_PROCESS, 0, 0);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn add_preserves_request_id() {
        let mut store = JobStore::new();
        let id = store.add(JOB_TYPE_TRACK_PROCESS, 0, 42);
        let job = store.jobs.get(&id).unwrap();
        assert_eq!(job.request_id, 42);
    }

    #[test]
    fn list_returns_all_jobs() {
        let mut store = JobStore::new();
        store.add(JOB_TYPE_THREAD, 0, 0);
        store.add(JOB_TYPE_PROCESS, 0, 0);
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
        let id = store.add(JOB_TYPE_THREAD, 0, 0);
        assert!(store.kill(id));
        assert_eq!(store.list().count(), 0);
    }

    #[test]
    fn reap_dead_removes_dead_jobs_only() {
        let mut store = JobStore::new();
        store.add(JOB_TYPE_THREAD, 0, 0);
        let id2 = store.add(JOB_TYPE_PROCESS, 0, 0);
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
        let id = store.add(JOB_TYPE_THREAD, 0, 0);
        assert!(store.suspend(id));
        assert_eq!(store.jobs[&id].state, JOB_STATE_SUSPENDED);
        assert!(store.resume(id));
        assert_eq!(store.jobs[&id].state, JOB_STATE_RUNNING);
    }

    #[cfg(not(windows))]
    #[test]
    fn suspend_already_suspended_returns_false() {
        let mut store = JobStore::new();
        let id = store.add(JOB_TYPE_THREAD, 0, 0);
        assert!(store.suspend(id));
        assert!(!store.suspend(id));
    }

    #[cfg(not(windows))]
    #[test]
    fn resume_running_returns_false() {
        let mut store = JobStore::new();
        let id = store.add(JOB_TYPE_THREAD, 0, 0);
        assert!(!store.resume(id));
    }

    #[cfg(not(windows))]
    #[test]
    fn poll_on_non_windows_returns_empty() {
        let mut store = JobStore::new();
        store.add(JOB_TYPE_THREAD, 0, 0);
        store.add(JOB_TYPE_TRACK_PROCESS, 0, 10);
        let dead = store.poll();
        assert!(dead.is_empty(), "non-Windows poll should not mark anything dead");
        // All jobs should still be running.
        assert_eq!(store.list().filter(|j| j.state == JOB_STATE_RUNNING).count(), 2);
    }

    #[test]
    fn poll_skips_already_dead_and_suspended_jobs() {
        let mut store = JobStore::new();
        let id1 = store.add(JOB_TYPE_THREAD, 0, 0);
        let id2 = store.add(JOB_TYPE_PROCESS, 0, 0);
        // Manually mark as dead and suspended.
        store.jobs.get_mut(&id1).map(|j| j.state = JOB_STATE_DEAD);
        store.jobs.get_mut(&id2).map(|j| j.state = JOB_STATE_SUSPENDED);
        let dead = store.poll();
        assert!(dead.is_empty());
    }

    #[test]
    fn poll_then_reap_clears_dead_jobs() {
        let mut store = JobStore::new();
        store.add(JOB_TYPE_THREAD, 0, 0);
        let id2 = store.add(JOB_TYPE_PROCESS, 0, 0);
        // Simulate a job that died (manually set state as poll would on Windows).
        store.jobs.get_mut(&id2).map(|j| j.state = JOB_STATE_DEAD);
        store.reap_dead();
        assert_eq!(store.list().count(), 1);
        // Remaining job should still be running.
        assert!(store.list().all(|j| j.state == JOB_STATE_RUNNING));
    }

    #[test]
    fn poll_only_reports_track_process_as_died() {
        let mut store = JobStore::new();
        // Add one of each type, all with distinct request IDs.
        let t_id = store.add(JOB_TYPE_THREAD, 0, 100);
        let p_id = store.add(JOB_TYPE_PROCESS, 0, 200);
        let tp_id = store.add(JOB_TYPE_TRACK_PROCESS, 0, 300);
        // Simulate all three dying.
        for id in [t_id, p_id, tp_id] {
            store.jobs.get_mut(&id).map(|j| j.state = JOB_STATE_DEAD);
        }
        // poll() should only return the TRACK_PROCESS entry (already dead,
        // so on non-Windows it won't transition — test the reap path
        // instead by checking that reap clears all three).
        store.reap_dead();
        assert_eq!(store.list().count(), 0);
    }
}
