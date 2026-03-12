//! In-memory agent registry with SQLite synchronization.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
    encrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DemonCommand, DemonMessage, DemonPackage};
use red_cell_common::{AgentEncryptionInfo, AgentInfo};
use tokio::sync::{Mutex, RwLock};
use tracing::{instrument, warn};

use crate::database::{Database, LinkRecord, TeamserverError};

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

#[derive(Debug)]
struct AgentEntry {
    info: RwLock<AgentInfo>,
    listener_name: RwLock<String>,
    jobs: Mutex<VecDeque<Job>>,
    ctr_block_offset: Mutex<u64>,
}

impl AgentEntry {
    fn new(info: AgentInfo, listener_name: String, ctr_block_offset: u64) -> Self {
        Self {
            info: RwLock::new(info),
            listener_name: RwLock::new(listener_name),
            jobs: Mutex::new(VecDeque::new()),
            ctr_block_offset: Mutex::new(ctr_block_offset),
        }
    }
}

/// Parent and child pivot metadata associated with an agent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PivotInfo {
    /// Upstream parent agent identifier, if one exists.
    pub parent: Option<u32>,
    /// Downstream linked child agent identifiers.
    pub children: Vec<u32>,
}

/// Maximum number of retained request contexts before eviction kicks in.
///
/// When the map exceeds this threshold, the oldest entries (by `created_at`
/// timestamp) are pruned down to half the limit.
const MAX_REQUEST_CONTEXTS: usize = 10_000;
/// Default cap on the total number of registered agents accepted by the teamserver.
pub const DEFAULT_MAX_REGISTERED_AGENTS: usize = 10_000;

/// Thread-safe in-memory registry of active and historical agents.
#[derive(Clone, Debug)]
pub struct AgentRegistry {
    repository: crate::database::AgentRepository,
    link_repository: crate::database::LinkRepository,
    entries: Arc<RwLock<HashMap<u32, Arc<AgentEntry>>>>,
    parent_links: Arc<RwLock<HashMap<u32, u32>>>,
    child_links: Arc<RwLock<HashMap<u32, BTreeSet<u32>>>>,
    request_contexts: Arc<RwLock<HashMap<(u32, u32), JobContext>>>,
    max_registered_agents: usize,
}

impl AgentRegistry {
    /// Create an empty registry backed by the provided database.
    #[must_use]
    pub fn new(database: Database) -> Self {
        Self::with_max_registered_agents(database, DEFAULT_MAX_REGISTERED_AGENTS)
    }

    /// Create an empty registry with an explicit cap on registered agents.
    #[must_use]
    pub fn with_max_registered_agents(database: Database, max_registered_agents: usize) -> Self {
        Self {
            repository: database.agents(),
            link_repository: database.links(),
            entries: Arc::new(RwLock::new(HashMap::new())),
            parent_links: Arc::new(RwLock::new(HashMap::new())),
            child_links: Arc::new(RwLock::new(HashMap::new())),
            request_contexts: Arc::new(RwLock::new(HashMap::new())),
            max_registered_agents,
        }
    }

    /// Load all persisted agents from SQLite into a new registry.
    #[instrument(skip(database))]
    pub async fn load(database: Database) -> Result<Self, TeamserverError> {
        Self::load_with_max_registered_agents(database, DEFAULT_MAX_REGISTERED_AGENTS).await
    }

    /// Load all persisted agents from SQLite into a new registry with an explicit cap.
    #[instrument(skip(database))]
    pub async fn load_with_max_registered_agents(
        database: Database,
        max_registered_agents: usize,
    ) -> Result<Self, TeamserverError> {
        let agents = database.agents().list_persisted().await?;
        if agents.len() > max_registered_agents {
            return Err(TeamserverError::MaxRegisteredAgentsExceeded {
                max_registered_agents,
                registered: agents.len(),
            });
        }

        let registry = Self::with_max_registered_agents(database.clone(), max_registered_agents);
        let links = database.links().list().await?;
        let mut entries = registry.entries.write().await;
        let mut parent_links = registry.parent_links.write().await;
        let mut child_links = registry.child_links.write().await;

        for agent in agents {
            entries.insert(
                agent.info.agent_id,
                Arc::new(AgentEntry::new(agent.info, agent.listener_name, agent.ctr_block_offset)),
            );
        }

        for link in links {
            parent_links.insert(link.link_agent_id, link.parent_agent_id);
            child_links.entry(link.parent_agent_id).or_default().insert(link.link_agent_id);
        }

        drop(entries);
        drop(parent_links);
        drop(child_links);
        Ok(registry)
    }

    /// Insert a newly registered agent and persist it to SQLite.
    #[instrument(skip(self, agent), fields(agent_id = format_args!("0x{:08X}", agent.agent_id)))]
    pub async fn insert(&self, agent: AgentInfo) -> Result<(), TeamserverError> {
        self.insert_with_listener(agent, "null").await
    }

    /// Insert a newly registered agent and persist its accepting listener.
    #[instrument(skip(self, agent, listener_name), fields(agent_id = format_args!("0x{:08X}", agent.agent_id), listener_name = %listener_name))]
    pub async fn insert_with_listener(
        &self,
        agent: AgentInfo,
        listener_name: &str,
    ) -> Result<(), TeamserverError> {
        let mut entries = self.entries.write().await;

        if entries.contains_key(&agent.agent_id) {
            return Err(TeamserverError::DuplicateAgent { agent_id: agent.agent_id });
        }

        if entries.len() >= self.max_registered_agents {
            return Err(TeamserverError::MaxRegisteredAgentsExceeded {
                max_registered_agents: self.max_registered_agents,
                registered: entries.len(),
            });
        }

        self.repository.create_with_listener(&agent, listener_name).await?;
        entries
            .insert(agent.agent_id, Arc::new(AgentEntry::new(agent, listener_name.to_owned(), 0)));
        Ok(())
    }

    /// Fetch a cloned snapshot of an agent by identifier.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn get(&self, agent_id: u32) -> Option<AgentInfo> {
        let entry = self.entry(agent_id).await?;
        let info = entry.info.read().await;
        Some(info.clone())
    }

    /// Return all agents that are still marked active.
    #[instrument(skip(self))]
    pub async fn list_active(&self) -> Vec<AgentInfo> {
        let entries = self.entries.read().await;
        let handles: Vec<_> = entries.values().cloned().collect();
        drop(entries);

        let mut agents = Vec::new();
        for handle in handles {
            let info = handle.info.read().await;
            if info.active {
                agents.push(info.clone());
            }
        }
        agents.sort_by_key(|agent| agent.agent_id);
        agents
    }

    /// Return all tracked agents, including inactive historical entries.
    #[instrument(skip(self))]
    pub async fn list(&self) -> Vec<AgentInfo> {
        let entries = self.entries.read().await;
        let handles: Vec<_> = entries.values().cloned().collect();
        drop(entries);

        let mut agents = Vec::with_capacity(handles.len());
        for handle in handles {
            let info = handle.info.read().await;
            agents.push(info.clone());
        }

        agents.sort_by_key(|agent| agent.agent_id);
        agents
    }

    /// Return the listener that accepted the current or most recent session.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn listener_name(&self, agent_id: u32) -> Option<String> {
        let entry = self.entry(agent_id).await?;
        let listener_name = entry.listener_name.read().await;
        Some(listener_name.clone())
    }

    /// Replace the stored metadata for an existing agent and persist the change.
    #[instrument(skip(self, agent), fields(agent_id = format_args!("0x{:08X}", agent.agent_id)))]
    pub async fn update_agent(&self, agent: AgentInfo) -> Result<(), TeamserverError> {
        let listener_name =
            self.listener_name(agent.agent_id).await.unwrap_or_else(|| "null".to_owned());
        self.update_agent_with_listener(agent, &listener_name).await
    }

    /// Replace the stored metadata and listener provenance for an existing agent.
    #[instrument(skip(self, agent, listener_name), fields(agent_id = format_args!("0x{:08X}", agent.agent_id), listener_name = %listener_name))]
    pub async fn update_agent_with_listener(
        &self,
        agent: AgentInfo,
        listener_name: &str,
    ) -> Result<(), TeamserverError> {
        let entry = self
            .entry(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;

        self.repository.update_with_listener(&agent, listener_name).await?;
        let mut info = entry.info.write().await;
        *info = agent;
        drop(info);
        let mut stored_listener_name = entry.listener_name.write().await;
        *stored_listener_name = listener_name.to_owned();
        Ok(())
    }

    /// Mark an agent inactive with the supplied reason and persist the status change.
    #[instrument(skip(self, reason), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn mark_dead(
        &self,
        agent_id: u32,
        reason: impl Into<String>,
    ) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let reason = reason.into();

        self.repository.set_status(agent_id, false, &reason).await?;

        let mut info = entry.info.write().await;
        info.active = false;
        info.reason = reason;
        drop(info);

        let descendants = self.child_subtree(agent_id).await;
        for child_id in descendants {
            self.mark_subtree_member_dead(child_id, "pivot parent disconnected").await?;
            self.clear_links_for_agent(child_id).await?;
            self.purge_request_contexts(child_id).await;
        }

        self.clear_links_for_agent(agent_id).await?;
        self.purge_request_contexts(agent_id).await;
        Ok(())
    }

    /// Update an operator-authored note for an agent and persist the change.
    #[instrument(skip(self, note), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn set_note(
        &self,
        agent_id: u32,
        note: impl Into<String>,
    ) -> Result<AgentInfo, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let note = note.into();

        self.repository.set_note(agent_id, &note).await?;

        let mut info = entry.info.write().await;
        info.note = note;
        Ok(info.clone())
    }

    /// Remove an agent from memory and SQLite.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn remove(&self, agent_id: u32) -> Result<AgentInfo, TeamserverError> {
        self.clear_links_for_agent(agent_id).await?;
        self.purge_request_contexts(agent_id).await;
        let entry = {
            let mut entries = self.entries.write().await;
            entries.remove(&agent_id).ok_or(TeamserverError::AgentNotFound { agent_id })?
        };

        self.repository.delete(agent_id).await?;

        let info = entry.info.read().await;
        Ok(info.clone())
    }

    /// Return the current AES key and IV for an agent.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn encryption(&self, agent_id: u32) -> Result<AgentEncryptionInfo, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        Ok(info.encryption.clone())
    }

    /// Return the current CTR block offset for an agent.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn ctr_offset(&self, agent_id: u32) -> Result<u64, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let offset = entry.ctr_block_offset.lock().await;
        Ok(*offset)
    }

    /// Set the CTR block offset for an agent (e.g. after DEMON_INIT parsing).
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), offset))]
    pub async fn set_ctr_offset(&self, agent_id: u32, offset: u64) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let mut current = entry.ctr_block_offset.lock().await;
        *current = offset;
        drop(current);
        self.repository.set_ctr_block_offset(agent_id, offset).await?;
        Ok(())
    }

    /// Encrypt a plaintext payload destined for an agent.
    #[instrument(skip(self, plaintext), fields(agent_id = format_args!("0x{:08X}", agent_id), len = plaintext.len()))]
    pub async fn encrypt_for_agent(
        &self,
        agent_id: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        let (key, iv) = decode_crypto_material(agent_id, &info.encryption)?;
        drop(info);
        self.encrypt_payload_with_ctr_offset(agent_id, &entry, &key, &iv, plaintext, true).await
    }

    /// Encrypt a plaintext payload for an agent without changing registry state.
    #[instrument(skip(self, plaintext), fields(agent_id = format_args!("0x{:08X}", agent_id), len = plaintext.len()))]
    pub(crate) async fn encrypt_for_agent_without_advancing(
        &self,
        agent_id: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        let (key, iv) = decode_crypto_material(agent_id, &info.encryption)?;
        drop(info);
        self.encrypt_payload_with_ctr_offset(agent_id, &entry, &key, &iv, plaintext, false).await
    }

    /// Decrypt a ciphertext payload received from an agent.
    #[instrument(skip(self, ciphertext), fields(agent_id = format_args!("0x{:08X}", agent_id), len = ciphertext.len()))]
    pub async fn decrypt_from_agent(
        &self,
        agent_id: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        let (key, iv) = decode_crypto_material(agent_id, &info.encryption)?;
        drop(info);
        self.decrypt_payload_with_ctr_offset(agent_id, &entry, &key, &iv, ciphertext).await
    }

    /// Update the AES key and IV for an agent and persist the new values.
    #[instrument(skip(self, encryption), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn set_encryption(
        &self,
        agent_id: u32,
        encryption: AgentEncryptionInfo,
    ) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;

        let updated = {
            let mut info = entry.info.write().await;
            info.encryption = encryption;
            info.clone()
        };

        let listener_name = entry.listener_name.read().await.clone();
        self.repository.update_with_listener(&updated, &listener_name).await?;
        Ok(())
    }

    /// Append a job to an agent's task queue.
    #[instrument(skip(self, job), fields(agent_id = format_args!("0x{:08X}", agent_id), command = job.command, request_id = job.request_id))]
    pub async fn enqueue_job(&self, agent_id: u32, job: Job) -> Result<(), TeamserverError> {
        self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        {
            let mut contexts = self.request_contexts.write().await;
            contexts.insert(
                (agent_id, job.request_id),
                JobContext {
                    request_id: job.request_id,
                    command_line: job.command_line.clone(),
                    task_id: job.task_id.clone(),
                    created_at: job.created_at.clone(),
                    operator: job.operator.clone(),
                },
            );
            if contexts.len() > MAX_REQUEST_CONTEXTS {
                evict_oldest_contexts(&mut contexts, MAX_REQUEST_CONTEXTS / 2);
            }
        }

        if let Some(parent_agent_id) = self.parent_of(agent_id).await {
            let (queue_agent_id, pivot_job) =
                self.build_pivot_job(parent_agent_id, agent_id, job).await?;
            let parent_entry = self
                .entry(queue_agent_id)
                .await
                .ok_or(TeamserverError::AgentNotFound { agent_id: queue_agent_id })?;
            let mut jobs = parent_entry.jobs.lock().await;
            jobs.push_back(pivot_job);
            return Ok(());
        }

        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let mut jobs = entry.jobs.lock().await;
        jobs.push_back(job);
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

    /// Update an agent's last callback timestamp and persist the change.
    #[instrument(skip(self, last_call_in), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn set_last_call_in(
        &self,
        agent_id: u32,
        last_call_in: impl Into<String>,
    ) -> Result<AgentInfo, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let updated = {
            let mut info = entry.info.write().await;
            info.last_call_in = last_call_in.into();
            info.clone()
        };

        let listener_name = entry.listener_name.read().await.clone();
        self.repository.update_with_listener(&updated, &listener_name).await?;
        Ok(updated)
    }

    /// Return the direct parent of `agent_id`, if this agent is linked through SMB.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn parent_of(&self, agent_id: u32) -> Option<u32> {
        let parent_links = self.parent_links.read().await;
        parent_links.get(&agent_id).copied()
    }

    /// Return all directly linked child agents for `agent_id`.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn children_of(&self, agent_id: u32) -> Vec<u32> {
        let child_links = self.child_links.read().await;
        child_links
            .get(&agent_id)
            .map(|children| children.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Return the current pivot parent and child links for `agent_id`.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn pivots(&self, agent_id: u32) -> PivotInfo {
        PivotInfo {
            parent: self.parent_of(agent_id).await,
            children: self.children_of(agent_id).await,
        }
    }

    /// Persist and register a parent/child SMB pivot relationship.
    #[instrument(skip(self), fields(parent_agent_id = format_args!("0x{:08X}", parent_agent_id), link_agent_id = format_args!("0x{:08X}", link_agent_id)))]
    pub async fn add_link(
        &self,
        parent_agent_id: u32,
        link_agent_id: u32,
    ) -> Result<(), TeamserverError> {
        self.entry(parent_agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: parent_agent_id })?;
        self.entry(link_agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: link_agent_id })?;

        if parent_agent_id == link_agent_id {
            return Err(TeamserverError::InvalidPivotLink {
                message: "agent cannot pivot to itself".to_owned(),
            });
        }
        if self.path_contains(link_agent_id, parent_agent_id).await {
            return Err(TeamserverError::InvalidPivotLink {
                message: format!(
                    "linking 0x{parent_agent_id:08X} -> 0x{link_agent_id:08X} would create a cycle"
                ),
            });
        }

        let existing_parent = self.parent_of(link_agent_id).await;
        if existing_parent == Some(parent_agent_id) {
            return Ok(());
        }

        if let Some(previous_parent) = existing_parent {
            self.link_repository.delete(previous_parent, link_agent_id).await?;
            self.remove_link_from_memory(previous_parent, link_agent_id).await;
        }

        self.link_repository.create(LinkRecord { parent_agent_id, link_agent_id }).await?;
        self.parent_links.write().await.insert(link_agent_id, parent_agent_id);
        self.child_links.write().await.entry(parent_agent_id).or_default().insert(link_agent_id);
        Ok(())
    }

    /// Remove a specific pivot relationship and mark the downstream subtree inactive.
    #[instrument(skip(self, reason), fields(parent_agent_id = format_args!("0x{:08X}", parent_agent_id), link_agent_id = format_args!("0x{:08X}", link_agent_id)))]
    pub async fn disconnect_link(
        &self,
        parent_agent_id: u32,
        link_agent_id: u32,
        reason: impl Into<String>,
    ) -> Result<Vec<u32>, TeamserverError> {
        let reason = reason.into();
        if self.parent_of(link_agent_id).await != Some(parent_agent_id) {
            return Ok(Vec::new());
        }

        let mut affected = vec![link_agent_id];
        affected.extend(self.child_subtree(link_agent_id).await);
        for agent_id in &affected {
            self.mark_subtree_member_dead(*agent_id, &reason).await?;
        }

        self.clear_links_for_agent(link_agent_id).await?;
        self.link_repository.delete(parent_agent_id, link_agent_id).await?;
        self.remove_link_from_memory(parent_agent_id, link_agent_id).await;
        Ok(affected)
    }

    async fn entry(&self, agent_id: u32) -> Option<Arc<AgentEntry>> {
        let entries = self.entries.read().await;
        entries.get(&agent_id).cloned()
    }

    async fn build_pivot_job(
        &self,
        direct_parent_agent_id: u32,
        target_agent_id: u32,
        job: Job,
    ) -> Result<(u32, Job), TeamserverError> {
        let mut wrapped_target = target_agent_id;
        let mut wrapped_payload =
            self.serialize_jobs_for_agent(target_agent_id, std::slice::from_ref(&job)).await?;
        let mut wrapped_job = Job {
            command: u32::from(DemonCommand::CommandPivot),
            request_id: job.request_id,
            payload: encode_pivot_job_payload(wrapped_target, &wrapped_payload)?,
            command_line: job.command_line.clone(),
            task_id: job.task_id.clone(),
            created_at: job.created_at.clone(),
            operator: job.operator.clone(),
        };
        let mut current_parent = direct_parent_agent_id;

        while let Some(next_parent) = self.parent_of(current_parent).await {
            wrapped_payload =
                self.serialize_jobs_for_agent(current_parent, &[wrapped_job.clone()]).await?;
            wrapped_target = current_parent;
            wrapped_job = Job {
                command: u32::from(DemonCommand::CommandPivot),
                request_id: job.request_id,
                payload: encode_pivot_job_payload(wrapped_target, &wrapped_payload)?,
                command_line: job.command_line.clone(),
                task_id: job.task_id.clone(),
                created_at: job.created_at.clone(),
                operator: job.operator.clone(),
            };
            current_parent = next_parent;
        }

        Ok((current_parent, wrapped_job))
    }

    async fn serialize_jobs_for_agent(
        &self,
        agent_id: u32,
        jobs: &[Job],
    ) -> Result<Vec<u8>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        let (key, iv) = decode_crypto_material(agent_id, &info.encryption)?;
        drop(info);

        let mut packages = Vec::with_capacity(jobs.len());
        let mut ctr_offset = entry.ctr_block_offset.lock().await;
        let starting_offset = *ctr_offset;
        let mut next_offset = starting_offset;

        for job in jobs {
            let payload = if job.payload.is_empty() {
                Vec::new()
            } else {
                let encrypted = encrypt_agent_data_at_offset(&key, &iv, next_offset, &job.payload)?;
                next_offset = next_ctr_offset(next_offset, job.payload.len())?;
                encrypted
            };
            packages.push(DemonPackage {
                command_id: job.command,
                request_id: job.request_id,
                payload,
            });
        }

        let bytes = DemonMessage::new(packages).to_bytes().map_err(TeamserverError::from)?;

        if next_offset != starting_offset {
            self.repository.set_ctr_block_offset(agent_id, next_offset).await?;
            *ctr_offset = next_offset;
        }
        drop(ctr_offset);

        Ok(bytes)
    }

    async fn encrypt_payload_with_ctr_offset(
        &self,
        agent_id: u32,
        entry: &Arc<AgentEntry>,
        key: &[u8; AGENT_KEY_LENGTH],
        iv: &[u8; AGENT_IV_LENGTH],
        plaintext: &[u8],
        advance: bool,
    ) -> Result<Vec<u8>, TeamserverError> {
        let mut ctr_offset = entry.ctr_block_offset.lock().await;
        let current_offset = *ctr_offset;
        let ciphertext = encrypt_agent_data_at_offset(key, iv, current_offset, plaintext)?;

        if advance {
            let next_offset = next_ctr_offset(current_offset, plaintext.len())?;
            if next_offset != current_offset {
                self.repository.set_ctr_block_offset(agent_id, next_offset).await?;
                *ctr_offset = next_offset;
            }
        }

        Ok(ciphertext)
    }

    async fn decrypt_payload_with_ctr_offset(
        &self,
        agent_id: u32,
        entry: &Arc<AgentEntry>,
        key: &[u8; AGENT_KEY_LENGTH],
        iv: &[u8; AGENT_IV_LENGTH],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TeamserverError> {
        let mut ctr_offset = entry.ctr_block_offset.lock().await;
        let current_offset = *ctr_offset;
        let plaintext = decrypt_agent_data_at_offset(key, iv, current_offset, ciphertext)?;
        let next_offset = next_ctr_offset(current_offset, ciphertext.len())?;

        if next_offset != current_offset {
            self.repository.set_ctr_block_offset(agent_id, next_offset).await?;
            *ctr_offset = next_offset;
        }

        Ok(plaintext)
    }

    async fn path_contains(&self, start_agent_id: u32, sought_agent_id: u32) -> bool {
        let mut current = Some(start_agent_id);
        while let Some(agent_id) = current {
            if agent_id == sought_agent_id {
                return true;
            }
            current = self.parent_of(agent_id).await;
        }
        false
    }

    async fn child_subtree(&self, agent_id: u32) -> Vec<u32> {
        let mut descendants = Vec::new();
        let mut stack = self.children_of(agent_id).await;

        while let Some(child_id) = stack.pop() {
            descendants.push(child_id);
            stack.extend(self.children_of(child_id).await);
        }

        descendants.sort_unstable();
        descendants
    }

    async fn clear_links_for_agent(&self, agent_id: u32) -> Result<(), TeamserverError> {
        if let Some(parent_agent_id) = self.parent_of(agent_id).await {
            self.link_repository.delete(parent_agent_id, agent_id).await?;
            self.remove_link_from_memory(parent_agent_id, agent_id).await;
        }

        let children = self.children_of(agent_id).await;
        for child_id in children {
            self.link_repository.delete(agent_id, child_id).await?;
            self.remove_link_from_memory(agent_id, child_id).await;
        }

        Ok(())
    }

    async fn remove_link_from_memory(&self, parent_agent_id: u32, link_agent_id: u32) {
        self.parent_links.write().await.remove(&link_agent_id);
        let mut child_links = self.child_links.write().await;
        if let Some(children) = child_links.get_mut(&parent_agent_id) {
            children.remove(&link_agent_id);
            if children.is_empty() {
                child_links.remove(&parent_agent_id);
            }
        }
    }

    async fn purge_request_contexts(&self, agent_id: u32) {
        self.request_contexts.write().await.retain(|&(aid, _), _| aid != agent_id);
    }

    async fn mark_subtree_member_dead(
        &self,
        agent_id: u32,
        reason: &str,
    ) -> Result<(), TeamserverError> {
        self.repository.set_status(agent_id, false, reason).await?;
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let mut info = entry.info.write().await;
        info.active = false;
        info.reason = reason.to_owned();
        Ok(())
    }
}

fn decode_crypto_material(
    agent_id: u32,
    encryption: &AgentEncryptionInfo,
) -> Result<([u8; AGENT_KEY_LENGTH], [u8; AGENT_IV_LENGTH]), TeamserverError> {
    let key = decode_fixed::<AGENT_KEY_LENGTH>(agent_id, "aes_key", encryption.aes_key.as_bytes())?;
    let iv = decode_fixed::<AGENT_IV_LENGTH>(agent_id, "aes_iv", encryption.aes_iv.as_bytes())?;
    if key.iter().all(|byte| *byte == 0) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting stored all-zero AES key for agent transport"
        );
        return Err(TeamserverError::InvalidAgentCrypto {
            agent_id,
            message: "all-zero AES keys are not allowed".to_owned(),
        });
    }
    Ok((key, iv))
}

fn decode_fixed<const N: usize>(
    agent_id: u32,
    field: &'static str,
    encoded: &[u8],
) -> Result<[u8; N], TeamserverError> {
    let decoded = BASE64_STANDARD.decode(encoded).map_err(|error| {
        TeamserverError::InvalidPersistedValue {
            field,
            message: format!("agent 0x{agent_id:08X}: {error}"),
        }
    })?;
    let actual = decoded.len();
    decoded.try_into().map_err(|_| TeamserverError::InvalidPersistedValue {
        field,
        message: format!("agent 0x{agent_id:08X}: expected {N} bytes, got {actual}"),
    })
}

fn next_ctr_offset(current_offset: u64, payload_len: usize) -> Result<u64, TeamserverError> {
    current_offset.checked_add(ctr_blocks_for_len(payload_len)).ok_or_else(|| {
        TeamserverError::InvalidPersistedValue {
            field: "ctr_block_offset",
            message: "AES-CTR block offset overflow".to_owned(),
        }
    })
}

/// Evict the oldest entries (by `created_at` timestamp) until the map has
/// at most `target_size` entries.  The `created_at` field is an RFC 3339
/// timestamp string and sorts lexicographically.
fn evict_oldest_contexts(contexts: &mut HashMap<(u32, u32), JobContext>, target_size: usize) {
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

fn encode_pivot_job_payload(
    target_agent_id: u32,
    payload: &[u8],
) -> Result<Vec<u8>, TeamserverError> {
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| TeamserverError::PayloadTooLarge { length: payload.len() })?;

    let mut inner = Vec::new();
    inner.extend_from_slice(&target_agent_id.to_le_bytes());
    inner.extend_from_slice(&payload_len.to_le_bytes());
    inner.extend_from_slice(payload);

    let inner_len = u32::try_from(inner.len())
        .map_err(|_| TeamserverError::PayloadTooLarge { length: inner.len() })?;

    let mut outer = Vec::new();
    outer.extend_from_slice(
        &u32::from(red_cell_common::demon::DemonPivotCommand::SmbCommand).to_le_bytes(),
    );
    outer.extend_from_slice(&target_agent_id.to_le_bytes());
    outer.extend_from_slice(&inner_len.to_le_bytes());
    outer.extend_from_slice(&inner);
    Ok(outer)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use red_cell_common::crypto::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, encrypt_agent_data_at_offset,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    use red_cell_common::AgentEncryptionInfo;
    use uuid::Uuid;

    use super::{AgentRegistry, Job};
    use crate::database::{Database, LinkRecord, TeamserverError};

    fn temp_db_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("red-cell-agent-registry-{}.sqlite", Uuid::new_v4()))
    }

    fn sample_agent(agent_id: u32) -> red_cell_common::AgentInfo {
        red_cell_common::AgentInfo {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: "YWVzLWtleQ==".to_owned(),
                aes_iv: "YWVzLWl2".to_owned(),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_arch: "x64".to_owned(),
            sleep_delay: 15,
            sleep_jitter: 20,
            kill_date: Some(1_893_456_000),
            working_hours: Some(0b101010),
            first_call_in: "2026-03-09T18:45:00Z".to_owned(),
            last_call_in: "2026-03-09T18:46:00Z".to_owned(),
        }
    }

    fn sample_agent_with_crypto(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> red_cell_common::AgentInfo {
        let mut agent = sample_agent(agent_id);
        agent.encryption = AgentEncryptionInfo {
            aes_key: BASE64_STANDARD.encode(key),
            aes_iv: BASE64_STANDARD.encode(iv),
        };
        agent
    }

    async fn test_database() -> Result<Database, TeamserverError> {
        Database::connect(temp_db_path()).await
    }

    fn sample_job(index: u32) -> Job {
        Job {
            command: 0x1000 + index,
            request_id: index,
            payload: vec![u8::try_from(index & 0xff).unwrap_or_default()],
            command_line: format!("job-{index}"),
            task_id: format!("task-{index}"),
            created_at: format!("2026-03-09T19:{index:02}:00Z"),
            operator: "operator".to_owned(),
        }
    }

    #[tokio::test]
    async fn new_starts_empty() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);

        assert!(registry.get(0x1234_5678).await.is_none());
        assert!(registry.list_active().await.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn load_restores_persisted_agents() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let agent = sample_agent(0x1000_0001);
        database.agents().create(&agent).await?;

        let registry = AgentRegistry::load(database).await?;

        assert_eq!(registry.get(agent.agent_id).await, Some(agent));
        Ok(())
    }

    #[tokio::test]
    async fn load_restores_persisted_listener_name() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let agent = sample_agent(0x1000_000A);
        database.agents().create_with_listener(&agent, "http-main").await?;

        let registry = AgentRegistry::load(database).await?;

        assert_eq!(registry.listener_name(agent.agent_id).await.as_deref(), Some("http-main"));
        Ok(())
    }

    #[tokio::test]
    async fn load_restores_persisted_ctr_offsets() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(
            0x1000_0ABC,
            [0x11; AGENT_KEY_LENGTH],
            [0x22; AGENT_IV_LENGTH],
        );

        registry.insert(agent.clone()).await?;
        registry.set_ctr_offset(agent.agent_id, 7).await?;
        let persisted_offset = registry.ctr_offset(agent.agent_id).await?;

        let reloaded = AgentRegistry::load(database.clone()).await?;
        assert_eq!(reloaded.ctr_offset(agent.agent_id).await?, persisted_offset);
        let stored = database
            .agents()
            .get_persisted(agent.agent_id)
            .await?
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert_eq!(stored.ctr_block_offset, persisted_offset);
        Ok(())
    }

    #[tokio::test]
    async fn load_restores_persisted_pivot_links() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let parent = sample_agent(0x1000_1010);
        let child = sample_agent(0x1000_2020);
        database.agents().create(&parent).await?;
        database.agents().create(&child).await?;
        database
            .links()
            .create(LinkRecord { parent_agent_id: parent.agent_id, link_agent_id: child.agent_id })
            .await?;

        let registry = AgentRegistry::load(database).await?;

        assert_eq!(registry.parent_of(child.agent_id).await, Some(parent.agent_id));
        assert_eq!(registry.children_of(parent.agent_id).await, vec![child.agent_id]);
        assert_eq!(
            registry.pivots(child.agent_id).await,
            super::PivotInfo { parent: Some(parent.agent_id), children: Vec::new() }
        );
        Ok(())
    }

    #[tokio::test]
    async fn insert_persists_and_rejects_duplicates() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_0002);

        registry.insert_with_listener(agent.clone(), "https-edge").await?;
        assert_eq!(registry.get(agent.agent_id).await, Some(agent.clone()));
        assert_eq!(database.agents().get(agent.agent_id).await?, Some(agent.clone()));
        assert_eq!(
            database
                .agents()
                .get_persisted(agent.agent_id)
                .await?
                .map(|persisted| persisted.listener_name),
            Some("https-edge".to_owned())
        );

        let duplicate = registry.insert(agent).await;
        assert!(matches!(
            duplicate,
            Err(TeamserverError::DuplicateAgent { agent_id: 0x1000_0002 })
        ));

        Ok(())
    }

    #[tokio::test]
    async fn insert_rejects_agents_after_registry_limit() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::with_max_registered_agents(database.clone(), 1);
        let first = sample_agent(0x1000_0100);
        let second = sample_agent(0x1000_0101);

        registry.insert(first).await?;
        let error = registry.insert(second.clone()).await.expect_err("second insert must fail");

        assert!(matches!(
            error,
            TeamserverError::MaxRegisteredAgentsExceeded {
                max_registered_agents: 1,
                registered: 1,
            }
        ));
        assert_eq!(registry.get(second.agent_id).await, None);
        assert_eq!(database.agents().get(second.agent_id).await?, None);

        Ok(())
    }

    #[tokio::test]
    async fn load_rejects_persisted_agents_when_registry_limit_is_exceeded()
    -> Result<(), TeamserverError> {
        let database = test_database().await?;
        database.agents().create(&sample_agent(0x1000_0200)).await?;
        database.agents().create(&sample_agent(0x1000_0201)).await?;

        let error = AgentRegistry::load_with_max_registered_agents(database, 1)
            .await
            .expect_err("load must fail when persisted agents exceed the configured limit");

        assert!(matches!(
            error,
            TeamserverError::MaxRegisteredAgentsExceeded {
                max_registered_agents: 1,
                registered: 2,
            }
        ));

        Ok(())
    }

    #[tokio::test]
    async fn list_active_filters_dead_agents() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let alive = sample_agent(0x1000_0003);
        let mut dead = sample_agent(0x1000_0004);
        dead.active = false;
        dead.reason = "lost".to_owned();

        registry.insert(alive.clone()).await?;
        registry.insert(dead).await?;

        assert_eq!(registry.list_active().await, vec![alive]);
        Ok(())
    }

    #[tokio::test]
    async fn list_returns_active_and_inactive_agents() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let alive = sample_agent(0x1000_0001);
        let mut dead = sample_agent(0x1000_0002);
        dead.active = false;
        dead.reason = "operator requested exit".to_owned();

        registry.insert(dead.clone()).await?;
        registry.insert(alive.clone()).await?;

        assert_eq!(registry.list().await, vec![alive, dead]);
        Ok(())
    }

    #[tokio::test]
    async fn update_agent_replaces_snapshot_and_persists() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let mut agent = sample_agent(0x1000_0005);
        registry.insert_with_listener(agent.clone(), "http-alpha").await?;

        agent.sleep_delay = 60;
        agent.reason = "updated".to_owned();
        agent.last_call_in = "2026-03-09T20:00:00Z".to_owned();
        registry.update_agent_with_listener(agent.clone(), "http-beta").await?;

        assert_eq!(registry.get(agent.agent_id).await, Some(agent.clone()));
        assert_eq!(database.agents().get(agent.agent_id).await?, Some(agent));
        assert_eq!(registry.listener_name(0x1000_0005).await.as_deref(), Some("http-beta"));
        Ok(())
    }

    #[tokio::test]
    async fn mark_dead_updates_memory_and_database() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_0006);
        registry.insert(agent.clone()).await?;

        registry.mark_dead(agent.agent_id, "lost contact").await?;

        let stored = registry
            .get(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert!(!stored.active);
        assert_eq!(stored.reason, "lost contact");

        let persisted = database
            .agents()
            .get(agent.agent_id)
            .await?
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert!(!persisted.active);
        assert_eq!(persisted.reason, "lost contact");

        Ok(())
    }

    #[tokio::test]
    async fn set_note_updates_memory_and_database() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_000C);
        registry.insert(agent.clone()).await?;

        let updated = registry.set_note(agent.agent_id, "tracked through VPN").await?;

        assert_eq!(updated.note, "tracked through VPN");
        assert_eq!(
            registry
                .get(agent.agent_id)
                .await
                .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?
                .note,
            "tracked through VPN"
        );
        assert_eq!(
            database
                .agents()
                .get(agent.agent_id)
                .await?
                .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?
                .note,
            "tracked through VPN"
        );

        Ok(())
    }

    #[tokio::test]
    async fn remove_deletes_agent_from_memory_and_database() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_000D);
        registry.insert(agent.clone()).await?;

        let removed = registry.remove(agent.agent_id).await?;

        assert_eq!(removed, agent);
        assert!(registry.get(agent.agent_id).await.is_none());
        assert_eq!(database.agents().get(agent.agent_id).await?, None);

        Ok(())
    }

    #[tokio::test]
    async fn mark_dead_tears_down_pivot_subtree() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let parent = sample_agent(0x1000_000D);
        let child = sample_agent(0x1000_000E);
        let grandchild = sample_agent(0x1000_000F);
        registry.insert(parent.clone()).await?;
        registry.insert(child.clone()).await?;
        registry.insert(grandchild.clone()).await?;
        registry.add_link(parent.agent_id, child.agent_id).await?;
        registry.add_link(child.agent_id, grandchild.agent_id).await?;

        registry.mark_dead(parent.agent_id, "lost contact").await?;

        assert_eq!(registry.parent_of(child.agent_id).await, None);
        assert_eq!(registry.parent_of(grandchild.agent_id).await, None);
        assert!(registry.children_of(parent.agent_id).await.is_empty());
        assert!(
            !registry
                .get(child.agent_id)
                .await
                .ok_or(TeamserverError::AgentNotFound { agent_id: child.agent_id })?
                .active
        );
        assert_eq!(
            registry
                .get(grandchild.agent_id)
                .await
                .ok_or(TeamserverError::AgentNotFound { agent_id: grandchild.agent_id })?
                .reason,
            "pivot parent disconnected"
        );
        assert!(database.links().list().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn encryption_round_trips() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_0007);
        let updated = AgentEncryptionInfo {
            aes_key: "bmV3LWtleQ==".to_owned(),
            aes_iv: "bmV3LWl2".to_owned(),
        };
        registry.insert(agent.clone()).await?;

        assert_eq!(registry.encryption(agent.agent_id).await?, agent.encryption);
        registry.set_encryption(agent.agent_id, updated.clone()).await?;
        assert_eq!(registry.encryption(agent.agent_id).await?, updated.clone());
        assert_eq!(
            database
                .agents()
                .get(agent.agent_id)
                .await?
                .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?
                .encryption,
            updated
        );

        Ok(())
    }

    #[tokio::test]
    async fn encrypt_for_agent_advances_ctr_offset_per_message() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let key = [0x31; AGENT_KEY_LENGTH];
        let iv = [0x41; AGENT_IV_LENGTH];
        let agent = sample_agent_with_crypto(0x1000_0701, key, iv);
        let plaintext = b"first encrypted payload";

        registry.insert(agent.clone()).await?;

        assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

        let first = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;
        let second = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;

        assert_eq!(first, encrypt_agent_data_at_offset(&key, &iv, 0, plaintext)?);
        assert_eq!(second, encrypt_agent_data_at_offset(&key, &iv, 2, plaintext)?);
        assert_ne!(first, second);
        assert_eq!(registry.ctr_offset(agent.agent_id).await?, 4);

        Ok(())
    }

    #[tokio::test]
    async fn encrypt_and_decrypt_for_agent_round_trip() -> Result<(), TeamserverError> {
        let sender = AgentRegistry::new(test_database().await?);
        let receiver = AgentRegistry::new(test_database().await?);
        let agent = sample_agent_with_crypto(
            0x1000_0702,
            [0x52; AGENT_KEY_LENGTH],
            [0x62; AGENT_IV_LENGTH],
        );
        let plaintext = b"callback payload requiring ctr synchronisation";

        sender.insert(agent.clone()).await?;
        receiver.insert(agent.clone()).await?;

        let ciphertext = sender.encrypt_for_agent(agent.agent_id, plaintext).await?;
        let decrypted = receiver.decrypt_from_agent(agent.agent_id, &ciphertext).await?;

        assert_eq!(decrypted, plaintext);
        assert_eq!(sender.ctr_offset(agent.agent_id).await?, ctr_blocks_for_len(plaintext.len()));
        assert_eq!(
            receiver.ctr_offset(agent.agent_id).await?,
            ctr_blocks_for_len(ciphertext.len())
        );

        Ok(())
    }

    #[tokio::test]
    async fn set_ctr_offset_changes_agent_transport_keystream() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let key = [0x73; AGENT_KEY_LENGTH];
        let iv = [0x83; AGENT_IV_LENGTH];
        let agent = sample_agent_with_crypto(0x1000_0703, key, iv);
        let starting_offset = 9;
        let plaintext = b"offset-aware encryption";

        registry.insert(agent.clone()).await?;
        registry.set_ctr_offset(agent.agent_id, starting_offset).await?;

        let ciphertext = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;
        let expected_ciphertext =
            encrypt_agent_data_at_offset(&key, &iv, starting_offset, plaintext)?;

        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(
            registry.ctr_offset(agent.agent_id).await?,
            starting_offset + ctr_blocks_for_len(plaintext.len())
        );

        Ok(())
    }

    #[tokio::test]
    async fn encrypt_for_agent_without_advancing_keeps_ctr_unchanged() -> Result<(), TeamserverError>
    {
        let registry = AgentRegistry::new(test_database().await?);
        let key = [0x74; AGENT_KEY_LENGTH];
        let iv = [0x84; AGENT_IV_LENGTH];
        let agent = sample_agent_with_crypto(0x1000_0705, key, iv);
        let starting_offset = 11;
        let plaintext = b"preview-only encryption";

        registry.insert(agent.clone()).await?;
        registry.set_ctr_offset(agent.agent_id, starting_offset).await?;

        let ciphertext =
            registry.encrypt_for_agent_without_advancing(agent.agent_id, plaintext).await?;
        let expected_ciphertext =
            encrypt_agent_data_at_offset(&key, &iv, starting_offset, plaintext)?;

        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(registry.ctr_offset(agent.agent_id).await?, starting_offset);

        Ok(())
    }

    #[tokio::test]
    async fn zero_key_agent_transport_is_rejected() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let agent = sample_agent_with_crypto(
            0x1000_0704,
            [0x00; AGENT_KEY_LENGTH],
            [0x00; AGENT_IV_LENGTH],
        );
        let plaintext = b"plaintext transport";

        registry.insert(agent.clone()).await?;

        assert!(matches!(
            registry.encrypt_for_agent(agent.agent_id, plaintext).await,
            Err(TeamserverError::InvalidAgentCrypto { agent_id, .. }) if agent_id == agent.agent_id
        ));
        assert!(matches!(
            registry.decrypt_from_agent(agent.agent_id, plaintext).await,
            Err(TeamserverError::InvalidAgentCrypto { agent_id, .. }) if agent_id == agent.agent_id
        ));
        assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

        Ok(())
    }

    #[tokio::test]
    async fn ctr_helpers_reject_unknown_agent_ids() {
        let registry = AgentRegistry::new(test_database().await.expect("db"));
        let missing_agent_id = 0x1000_07FF;

        assert!(matches!(
            registry.ctr_offset(missing_agent_id).await,
            Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == missing_agent_id
        ));
        assert!(matches!(
            registry.set_ctr_offset(missing_agent_id, 4).await,
            Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == missing_agent_id
        ));
        assert!(matches!(
            registry.encrypt_for_agent(missing_agent_id, b"abc").await,
            Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == missing_agent_id
        ));
        assert!(matches!(
            registry.decrypt_from_agent(missing_agent_id, b"abc").await,
            Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == missing_agent_id
        ));
    }

    #[tokio::test]
    async fn job_queue_supports_enqueue_dequeue_and_snapshot() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let agent = sample_agent(0x1000_0008);
        let first = sample_job(1);
        let second = sample_job(2);
        registry.insert(agent.clone()).await?;

        registry.enqueue_job(agent.agent_id, first.clone()).await?;
        registry.enqueue_job(agent.agent_id, second.clone()).await?;

        assert_eq!(
            registry.queued_jobs(agent.agent_id).await?,
            vec![first.clone(), second.clone()]
        );
        assert_eq!(registry.dequeue_job(agent.agent_id).await?, Some(first));
        assert_eq!(registry.dequeue_job(agent.agent_id).await?, Some(second));
        assert_eq!(registry.dequeue_job(agent.agent_id).await?, None);

        Ok(())
    }

    #[tokio::test]
    async fn dequeue_jobs_drains_queue_in_fifo_order() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let agent = sample_agent(0x1000_000A);
        let first = sample_job(3);
        let second = sample_job(4);
        registry.insert(agent.clone()).await?;

        registry.enqueue_job(agent.agent_id, first.clone()).await?;
        registry.enqueue_job(agent.agent_id, second.clone()).await?;

        assert_eq!(registry.dequeue_jobs(agent.agent_id).await?, vec![first, second]);
        assert!(registry.queued_jobs(agent.agent_id).await?.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn queued_jobs_all_returns_jobs_across_agents_in_stable_order()
    -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let first_agent = sample_agent(0x1000_000A);
        let second_agent = sample_agent(0x1000_000B);
        registry.insert(first_agent.clone()).await?;
        registry.insert(second_agent.clone()).await?;

        let second_job = sample_job(2);
        let first_job = sample_job(1);
        let third_job = sample_job(3);
        registry.enqueue_job(second_agent.agent_id, third_job.clone()).await?;
        registry.enqueue_job(first_agent.agent_id, second_job.clone()).await?;
        registry.enqueue_job(first_agent.agent_id, first_job.clone()).await?;

        assert_eq!(
            registry.queued_jobs_all().await,
            vec![
                super::QueuedJob { agent_id: first_agent.agent_id, job: first_job },
                super::QueuedJob { agent_id: first_agent.agent_id, job: second_job },
                super::QueuedJob { agent_id: second_agent.agent_id, job: third_job },
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn request_context_survives_multiple_reads() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let agent = sample_agent(0x1000_000B);
        let job = sample_job(5);
        registry.insert(agent.clone()).await?;

        registry.enqueue_job(agent.agent_id, job.clone()).await?;
        let queued = registry.dequeue_job(agent.agent_id).await?;
        assert_eq!(queued, Some(job.clone()));

        let context = registry
            .request_context(agent.agent_id, job.request_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert_eq!(context.request_id, job.request_id);
        assert_eq!(context.command_line, job.command_line);
        assert_eq!(context.task_id, job.task_id);
        assert_eq!(context.created_at, job.created_at);
        assert_eq!(context.operator, job.operator);

        assert!(
            registry.request_context(agent.agent_id, job.request_id).await.is_some(),
            "context must survive multiple reads for multi-phase callbacks"
        );

        Ok(())
    }

    #[tokio::test]
    async fn mark_dead_purges_request_contexts() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let agent = sample_agent(0x1000_00A0);
        registry.insert(agent.clone()).await?;
        registry.enqueue_job(agent.agent_id, sample_job(10)).await?;
        registry.enqueue_job(agent.agent_id, sample_job(11)).await?;

        registry.mark_dead(agent.agent_id, "lost contact").await?;

        assert!(registry.request_context(agent.agent_id, 10).await.is_none());
        assert!(registry.request_context(agent.agent_id, 11).await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn remove_purges_request_contexts() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let agent = sample_agent(0x1000_00B0);
        registry.insert(agent.clone()).await?;
        registry.enqueue_job(agent.agent_id, sample_job(20)).await?;

        registry.remove(agent.agent_id).await?;

        assert!(registry.request_context(agent.agent_id, 20).await.is_none());
        Ok(())
    }

    #[test]
    fn evict_oldest_contexts_prunes_to_target_size() {
        let mut map = HashMap::new();
        for i in 0..20_u32 {
            map.insert(
                (0xAAAA_0000, i),
                super::JobContext {
                    request_id: i,
                    command_line: String::new(),
                    task_id: String::new(),
                    created_at: format!("2026-03-10T10:{i:02}:00Z"),
                    operator: String::new(),
                },
            );
        }

        super::evict_oldest_contexts(&mut map, 10);

        assert_eq!(map.len(), 10);
        for i in 0..10_u32 {
            assert!(!map.contains_key(&(0xAAAA_0000, i)), "entry {i} should have been evicted");
        }
        for i in 10..20_u32 {
            assert!(map.contains_key(&(0xAAAA_0000, i)), "entry {i} should have been retained");
        }
    }

    #[test]
    fn evict_oldest_contexts_noop_when_under_target() {
        let mut map = HashMap::new();
        map.insert(
            (0xBBBB_0000, 1),
            super::JobContext {
                request_id: 1,
                command_line: String::new(),
                task_id: String::new(),
                created_at: "2026-03-10T10:00:00Z".to_owned(),
                operator: String::new(),
            },
        );

        super::evict_oldest_contexts(&mut map, 100);
        assert_eq!(map.len(), 1);
    }

    #[tokio::test]
    async fn enqueue_job_routes_linked_child_to_root_parent_queue() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let root = sample_agent_with_crypto(
            0x1000_0010,
            [0x11; AGENT_KEY_LENGTH],
            [0x22; AGENT_IV_LENGTH],
        );
        let pivot = sample_agent_with_crypto(
            0x1000_0011,
            [0x33; AGENT_KEY_LENGTH],
            [0x44; AGENT_IV_LENGTH],
        );
        let child = sample_agent_with_crypto(
            0x1000_0012,
            [0x55; AGENT_KEY_LENGTH],
            [0x66; AGENT_IV_LENGTH],
        );
        registry.insert(root.clone()).await?;
        registry.insert(pivot.clone()).await?;
        registry.insert(child.clone()).await?;
        registry.add_link(root.agent_id, pivot.agent_id).await?;
        registry.add_link(pivot.agent_id, child.agent_id).await?;

        registry.enqueue_job(child.agent_id, sample_job(7)).await?;

        assert!(registry.queued_jobs(child.agent_id).await?.is_empty());
        assert!(registry.queued_jobs(pivot.agent_id).await?.is_empty());
        let queued = registry.queued_jobs(root.agent_id).await?;
        assert_eq!(queued.len(), 1);
        assert_eq!(
            queued[0].command,
            u32::from(red_cell_common::demon::DemonCommand::CommandPivot)
        );
        Ok(())
    }

    #[tokio::test]
    async fn set_last_call_in_updates_memory_and_database() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_000B);
        registry.insert(agent.clone()).await?;

        let updated = registry.set_last_call_in(agent.agent_id, "2026-03-09T21:00:00Z").await?;

        assert_eq!(updated.last_call_in, "2026-03-09T21:00:00Z");
        assert_eq!(
            registry
                .get(agent.agent_id)
                .await
                .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?
                .last_call_in,
            "2026-03-09T21:00:00Z"
        );
        assert_eq!(
            database
                .agents()
                .get(agent.agent_id)
                .await?
                .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?
                .last_call_in,
            "2026-03-09T21:00:00Z"
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_insert_get_and_update_are_safe() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = Arc::new(AgentRegistry::new(database.clone()));

        let mut insert_tasks = Vec::new();
        for index in 0..16_u32 {
            let registry = Arc::clone(&registry);
            insert_tasks.push(tokio::spawn(async move {
                let agent_id = 0x2100_0000 + index;
                let agent = sample_agent(agent_id);
                registry.insert(agent.clone()).await?;

                let stored = registry
                    .get(agent_id)
                    .await
                    .ok_or(TeamserverError::AgentNotFound { agent_id })?;
                if stored != agent {
                    return Err(TeamserverError::InvalidPersistedValue {
                        field: "agent_snapshot",
                        message: format!("unexpected snapshot for agent 0x{agent_id:08X}"),
                    });
                }

                Ok::<(), TeamserverError>(())
            }));
        }

        for task in insert_tasks {
            task.await.map_err(|error| TeamserverError::InvalidPersistedValue {
                field: "task_join",
                message: error.to_string(),
            })??;
        }

        assert_eq!(registry.list().await.len(), 16);

        let mut update_tasks = Vec::new();
        for index in 0..16_u32 {
            let registry = Arc::clone(&registry);
            update_tasks.push(tokio::spawn(async move {
                let agent_id = 0x2100_0000 + index;
                let mut agent = registry
                    .get(agent_id)
                    .await
                    .ok_or(TeamserverError::AgentNotFound { agent_id })?;
                agent.sleep_delay = 60 + index;
                agent.last_call_in = format!("2026-03-10T12:{index:02}:00Z");
                registry.update_agent(agent.clone()).await?;

                let persisted = registry
                    .get(agent_id)
                    .await
                    .ok_or(TeamserverError::AgentNotFound { agent_id })?;
                if persisted.sleep_delay != 60 + index {
                    return Err(TeamserverError::InvalidPersistedValue {
                        field: "sleep_delay",
                        message: format!("agent 0x{agent_id:08X} did not persist its update"),
                    });
                }

                Ok::<(), TeamserverError>(())
            }));
        }

        for task in update_tasks {
            task.await.map_err(|error| TeamserverError::InvalidPersistedValue {
                field: "task_join",
                message: error.to_string(),
            })??;
        }

        for index in 0..16_u32 {
            let agent_id = 0x2100_0000 + index;
            let persisted = database
                .agents()
                .get(agent_id)
                .await?
                .ok_or(TeamserverError::AgentNotFound { agent_id })?;
            assert_eq!(persisted.sleep_delay, 60 + index);
            assert_eq!(persisted.last_call_in, format!("2026-03-10T12:{index:02}:00Z"));
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_updates_and_job_queue_access_are_safe() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = Arc::new(AgentRegistry::new(database.clone()));
        let agent = sample_agent(0x1000_0009);
        registry.insert(agent).await?;

        let mut tasks = Vec::new();
        for index in 0..16_u32 {
            let registry = Arc::clone(&registry);
            tasks.push(tokio::spawn(async move {
                let mut agent = registry
                    .get(0x1000_0009)
                    .await
                    .ok_or(TeamserverError::AgentNotFound { agent_id: 0x1000_0009 })?;
                agent.last_call_in = format!("2026-03-09T20:{index:02}:00Z");
                agent.sleep_delay = 30 + index;
                registry.update_agent(agent).await?;
                registry.enqueue_job(0x1000_0009, sample_job(index)).await?;
                Ok::<(), TeamserverError>(())
            }));
        }

        for task in tasks {
            task.await.map_err(|error| TeamserverError::InvalidPersistedValue {
                field: "task_join",
                message: error.to_string(),
            })??;
        }

        let queued = registry.queued_jobs(0x1000_0009).await?;
        assert_eq!(queued.len(), 16);
        let persisted = database
            .agents()
            .get(0x1000_0009)
            .await?
            .ok_or(TeamserverError::AgentNotFound { agent_id: 0x1000_0009 })?;
        assert!((30..=45).contains(&persisted.sleep_delay));

        Ok(())
    }

    #[test]
    fn encode_pivot_job_payload_normal_input() -> Result<(), TeamserverError> {
        let payload = b"hello";
        let outer = super::encode_pivot_job_payload(0xDEAD_BEEF, payload)?;
        assert!(outer.len() > payload.len());
        Ok(())
    }

    #[test]
    fn encode_pivot_job_payload_empty_input() {
        let result = super::encode_pivot_job_payload(0x1234, &[]);
        assert!(result.is_ok());
    }
}
