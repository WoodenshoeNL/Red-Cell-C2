//! Agent job queue, queued-task snapshots, and request-context tracking.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::instrument;

use crate::database::TeamserverError;

use super::{AgentRegistry, MAX_JOB_QUEUE_DEPTH, MAX_REQUEST_CONTEXTS};

/// Queued agent task payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Job {
    /// Havoc/Demon command identifier.
    pub command: u32,
    /// Teamserver request identifier.
    pub request_id: u32,
    /// Serialized task payload sent to the agent.
    pub payload: Vec<u8>,
    /// Operator command line associated with the task, when available.
    pub command_line: String,
    /// Stable task identifier used for operator correlation.
    pub task_id: String,
    /// Timestamp string recording when the job was queued.
    pub created_at: String,
    /// Operator username that queued the task, when available.
    pub operator: String,
}

/// Task metadata retained for correlating callbacks with the originating request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JobContext {
    /// Teamserver request identifier.
    pub request_id: u32,
    /// Operator command line associated with the task.
    pub command_line: String,
    /// Stable task identifier used for operator correlation.
    pub task_id: String,
    /// Timestamp string recording when the job was queued.
    pub created_at: String,
    /// Operator username that queued the task, when available.
    pub operator: String,
}

/// Snapshot entry describing a queued job and the agent it targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedJob {
    /// Agent identifier the job is queued for.
    pub agent_id: u32,
    /// Queued job payload and metadata.
    pub job: Job,
}

impl AgentRegistry {
    /// Append a job to an agent's task queue.
    #[instrument(skip(self, job), fields(agent_id = format_args!("0x{:08X}", agent_id), command = job.command, request_id = job.request_id))]
    pub async fn enqueue_job(&self, agent_id: u32, job: Job) -> Result<(), TeamserverError> {
        self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;

        let context = JobContext {
            request_id: job.request_id,
            command_line: job.command_line.clone(),
            task_id: job.task_id.clone(),
            created_at: job.created_at.clone(),
            operator: job.operator.clone(),
        };
        let request_key = (agent_id, job.request_id);

        if let Some(parent_agent_id) = self.parent_of(agent_id).await {
            let (queue_agent_id, pivot_job) =
                self.build_pivot_job(parent_agent_id, agent_id, job).await?;
            let parent_entry = self
                .entry(queue_agent_id)
                .await
                .ok_or(TeamserverError::AgentNotFound { agent_id: queue_agent_id })?;
            let mut jobs = parent_entry.jobs.lock().await;
            if jobs.len() >= MAX_JOB_QUEUE_DEPTH {
                return Err(TeamserverError::QueueFull {
                    agent_id: queue_agent_id,
                    max_queue_depth: MAX_JOB_QUEUE_DEPTH,
                    queued: jobs.len(),
                });
            }
            jobs.push_back(pivot_job);
        } else {
            let entry =
                self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
            let mut jobs = entry.jobs.lock().await;
            if jobs.len() >= MAX_JOB_QUEUE_DEPTH {
                return Err(TeamserverError::QueueFull {
                    agent_id,
                    max_queue_depth: MAX_JOB_QUEUE_DEPTH,
                    queued: jobs.len(),
                });
            }
            jobs.push_back(job);
        }

        {
            let mut contexts = self.request_contexts.write().await;
            contexts.insert(request_key, context);
            if contexts.len() > MAX_REQUEST_CONTEXTS {
                evict_oldest_contexts(&mut contexts, MAX_REQUEST_CONTEXTS / 2);
            }
        }

        Ok(())
    }

    /// Pop the next queued job for an agent, if one exists.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn dequeue_job(&self, agent_id: u32) -> Result<Option<Job>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let mut jobs = entry.jobs.lock().await;
        Ok(jobs.pop_front())
    }

    /// Drain all queued jobs for an agent in FIFO order.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn dequeue_jobs(&self, agent_id: u32) -> Result<Vec<Job>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let mut jobs = entry.jobs.lock().await;
        Ok(jobs.drain(..).collect())
    }

    /// Return a snapshot of the current queued jobs for an agent.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn queued_jobs(&self, agent_id: u32) -> Result<Vec<Job>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let jobs = entry.jobs.lock().await;
        Ok(jobs.iter().cloned().collect())
    }

    /// Return a stable snapshot of every queued job across all tracked agents.
    #[instrument(skip(self))]
    pub async fn queued_jobs_all(&self) -> Vec<QueuedJob> {
        let entries = {
            let entries = self.entries.read().await;
            entries
                .iter()
                .map(|(agent_id, entry)| (*agent_id, Arc::clone(entry)))
                .collect::<Vec<_>>()
        };

        let mut queued = Vec::new();
        for (agent_id, entry) in entries {
            let jobs = entry.jobs.lock().await;
            queued.extend(jobs.iter().cloned().map(|job| QueuedJob { agent_id, job }));
        }

        queued.sort_by_key(|queued_job| (queued_job.agent_id, queued_job.job.request_id));
        queued
    }

    /// Return the retained task metadata for a callback request, if known.
    ///
    /// Contexts are not consumed on read because multi-phase callbacks
    /// (e.g. file downloads, output + error pairs) may reference the same
    /// `(agent_id, request_id)` more than once.  Bounded eviction in
    /// [`Self::enqueue_job`] and cleanup in [`Self::mark_dead`] /
    /// [`Self::remove`] prevent unbounded growth.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), request_id))]
    pub async fn request_context(&self, agent_id: u32, request_id: u32) -> Option<JobContext> {
        self.request_contexts.read().await.get(&(agent_id, request_id)).cloned()
    }

    pub(super) async fn purge_request_contexts(&self, agent_id: u32) {
        self.request_contexts.write().await.retain(|&(aid, _), _| aid != agent_id);
    }

    /// Return the number of retained request contexts (test-only).
    #[cfg(test)]
    pub(super) async fn request_contexts_count(&self) -> usize {
        self.request_contexts.read().await.len()
    }
}

/// Evict the oldest entries (by `created_at` timestamp) until the map has
/// at most `target_size` entries.  The `created_at` field is an RFC 3339
/// timestamp string and sorts lexicographically.
pub(super) fn evict_oldest_contexts(
    contexts: &mut HashMap<(u32, u32), JobContext>,
    target_size: usize,
) {
    if contexts.len() <= target_size {
        return;
    }
    let to_remove = contexts.len() - target_size;
    let mut entries: Vec<_> = contexts.iter().map(|(k, v)| (*k, v.created_at.clone())).collect();
    entries.sort_unstable_by(|a, b| a.1.cmp(&b.1));
    for (key, _) in entries.into_iter().take(to_remove) {
        contexts.remove(&key);
    }
}
