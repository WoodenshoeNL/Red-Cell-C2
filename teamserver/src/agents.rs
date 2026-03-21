//! In-memory agent registry with SQLite synchronization.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
    encrypt_agent_data_at_offset, is_weak_aes_key,
};
use red_cell_common::demon::{DemonCommand, DemonMessage, DemonPackage};
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use tokio::sync::{Mutex, RwLock};
use tracing::{instrument, warn};
use zeroize::Zeroizing;

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
    info: RwLock<AgentRecord>,
    listener_name: RwLock<String>,
    jobs: Mutex<VecDeque<Job>>,
    ctr_block_offset: Mutex<u64>,
}

impl AgentEntry {
    fn new(info: AgentRecord, listener_name: String, ctr_block_offset: u64) -> Self {
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
/// Maximum number of jobs that may be queued for a single agent at any time.
///
/// Attempts to enqueue beyond this limit are rejected with
/// [`TeamserverError::QueueFull`] so that a misbehaving or compromised operator
/// cannot cause unbounded heap growth on the teamserver.
pub const MAX_JOB_QUEUE_DEPTH: usize = 1_000;
/// Maximum allowed depth of a pivot chain (ancestor hops from a leaf to the root).
///
/// A compromised or misbehaving agent could register arbitrarily deep SMB pivot
/// chains. Every `enqueue_job` call for a pivoted agent calls `build_pivot_job`,
/// which acquires one read-lock per hop; without a cap this is O(depth) work
/// per dispatch. Limiting the chain to 16 hops bounds that cost while allowing
/// realistic multi-hop topologies.
pub const MAX_PIVOT_CHAIN_DEPTH: usize = 16;

type AgentCleanupFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type AgentCleanupHook = Arc<dyn Fn(u32) -> AgentCleanupFuture + Send + Sync + 'static>;

/// Thread-safe in-memory registry of active and historical agents.
#[derive(Clone)]
pub struct AgentRegistry {
    repository: crate::database::AgentRepository,
    link_repository: crate::database::LinkRepository,
    entries: Arc<RwLock<HashMap<u32, Arc<AgentEntry>>>>,
    parent_links: Arc<RwLock<HashMap<u32, u32>>>,
    child_links: Arc<RwLock<HashMap<u32, BTreeSet<u32>>>>,
    request_contexts: Arc<RwLock<HashMap<(u32, u32), JobContext>>>,
    cleanup_hooks: Arc<StdMutex<Vec<AgentCleanupHook>>>,
    max_registered_agents: usize,
}

impl std::fmt::Debug for AgentRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentRegistry")
            .field("repository", &self.repository)
            .field("link_repository", &self.link_repository)
            .field("entries", &self.entries)
            .field("parent_links", &self.parent_links)
            .field("child_links", &self.child_links)
            .field("request_contexts", &self.request_contexts)
            .field("max_registered_agents", &self.max_registered_agents)
            .finish_non_exhaustive()
    }
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
            cleanup_hooks: Arc::new(StdMutex::new(Vec::new())),
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
    pub async fn insert(&self, agent: AgentRecord) -> Result<(), TeamserverError> {
        self.insert_with_listener(agent, "null").await
    }

    /// Insert a newly registered agent and persist its accepting listener.
    #[instrument(skip(self, agent, listener_name), fields(agent_id = format_args!("0x{:08X}", agent.agent_id), listener_name = %listener_name))]
    pub async fn insert_with_listener(
        &self,
        agent: AgentRecord,
        listener_name: &str,
    ) -> Result<(), TeamserverError> {
        self.insert_with_listener_and_ctr_offset(agent, listener_name, 0).await
    }

    /// Insert a newly registered agent and atomically persist its initial CTR state.
    #[instrument(skip(self, agent, listener_name), fields(agent_id = format_args!("0x{:08X}", agent.agent_id), listener_name = %listener_name, ctr_block_offset))]
    pub async fn insert_with_listener_and_ctr_offset(
        &self,
        agent: AgentRecord,
        listener_name: &str,
        ctr_block_offset: u64,
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

        self.repository
            .create_with_listener_and_ctr_offset(&agent, listener_name, ctr_block_offset)
            .await?;
        entries.insert(
            agent.agent_id,
            Arc::new(AgentEntry::new(agent, listener_name.to_owned(), ctr_block_offset)),
        );
        Ok(())
    }

    /// Fetch a cloned snapshot of an agent by identifier.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn get(&self, agent_id: u32) -> Option<AgentRecord> {
        let entry = self.entry(agent_id).await?;
        let info = entry.info.read().await;
        Some(info.clone())
    }

    /// Return all agents that are still marked active.
    #[instrument(skip(self))]
    pub async fn list_active(&self) -> Vec<AgentRecord> {
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
    pub async fn list(&self) -> Vec<AgentRecord> {
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
    pub async fn update_agent(&self, agent: AgentRecord) -> Result<(), TeamserverError> {
        let listener_name =
            self.listener_name(agent.agent_id).await.unwrap_or_else(|| "null".to_owned());
        self.update_agent_with_listener(agent, &listener_name).await
    }

    /// Replace the stored metadata and listener provenance for an existing agent.
    #[instrument(skip(self, agent, listener_name), fields(agent_id = format_args!("0x{:08X}", agent.agent_id), listener_name = %listener_name))]
    pub async fn update_agent_with_listener(
        &self,
        agent: AgentRecord,
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
        let reason = reason.into();
        self.mark_subtree_member_dead(agent_id, &reason).await?;

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
    ) -> Result<AgentRecord, TeamserverError> {
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
    pub async fn remove(&self, agent_id: u32) -> Result<AgentRecord, TeamserverError> {
        self.clear_links_for_agent(agent_id).await?;
        self.purge_request_contexts(agent_id).await;
        let entry = {
            let mut entries = self.entries.write().await;
            entries.remove(&agent_id).ok_or(TeamserverError::AgentNotFound { agent_id })?
        };

        self.repository.delete(agent_id).await?;
        self.run_cleanup_hooks(agent_id).await;

        let info = entry.info.read().await;
        Ok(info.clone())
    }

    /// Register an async cleanup hook that runs whenever an agent is marked dead or removed.
    pub fn register_cleanup_hook<F, Fut>(&self, hook: F)
    where
        F: Fn(u32) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut cleanup_hooks = match self.cleanup_hooks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("agent cleanup hooks mutex poisoned — recovering");
                poisoned.into_inner()
            }
        };
        cleanup_hooks.push(Arc::new(move |agent_id| Box::pin(hook(agent_id))));
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
        // Persist first so that a DB failure leaves in-memory state untouched,
        // preventing memory/database drift on reconnect.
        self.repository.set_ctr_block_offset(agent_id, offset).await?;
        *entry.ctr_block_offset.lock().await = offset;
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
        self.decrypt_payload_with_ctr_offset(agent_id, &entry, &key, &iv, ciphertext, true).await
    }

    /// Decrypt a ciphertext payload without advancing the stored CTR offset.
    ///
    /// Use this when the plaintext must be validated before the offset is committed — for
    /// example when decrypting an agent callback before parsing the Demon protocol, so that a
    /// garbage payload from an attacker cannot permanently desync the keystream offset.
    /// Call [`AgentRegistry::advance_ctr_for_agent`] after successful validation.
    #[instrument(skip(self, ciphertext), fields(agent_id = format_args!("0x{:08X}", agent_id), len = ciphertext.len()))]
    pub(crate) async fn decrypt_from_agent_without_advancing(
        &self,
        agent_id: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        let (key, iv) = decode_crypto_material(agent_id, &info.encryption)?;
        drop(info);
        self.decrypt_payload_with_ctr_offset(agent_id, &entry, &key, &iv, ciphertext, false).await
    }

    /// Advance the CTR block offset for an agent by `byte_len` bytes.
    ///
    /// Called after [`AgentRegistry::decrypt_from_agent_without_advancing`] succeeds and the
    /// decrypted payload has been validated, so that a failed parse cannot desync the offset.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), byte_len))]
    pub(crate) async fn advance_ctr_for_agent(
        &self,
        agent_id: u32,
        byte_len: usize,
    ) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let mut ctr_offset = entry.ctr_block_offset.lock().await;
        let current_offset = *ctr_offset;
        let next_offset = next_ctr_offset(current_offset, byte_len)?;
        if next_offset != current_offset {
            self.repository.set_ctr_block_offset(agent_id, next_offset).await?;
            *ctr_offset = next_offset;
        }
        Ok(())
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

        // Build the updated record under a read lock so that a DB failure leaves
        // in-memory state completely untouched, preventing memory/database drift.
        let updated = {
            let info = entry.info.read().await;
            let mut cloned = info.clone();
            cloned.encryption = encryption.clone();
            cloned
        };

        let listener_name = entry.listener_name.read().await.clone();
        // Persist first; only mutate in-memory on success.
        self.repository.update_with_listener(&updated, &listener_name).await?;
        entry.info.write().await.encryption = encryption;
        Ok(())
    }

    /// Append a job to an agent's task queue.
    #[instrument(skip(self, job), fields(agent_id = format_args!("0x{:08X}", agent_id), command = job.command, request_id = job.request_id))]
    pub async fn enqueue_job(&self, agent_id: u32, job: Job) -> Result<(), TeamserverError> {
        self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;

        // Build the context before we move `job` into a queue.
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

        // Insert request context only after the job was successfully enqueued,
        // so that a QueueFull rejection leaves no stale context behind.
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

    /// Update an agent's last callback timestamp and persist the change.
    #[instrument(skip(self, last_call_in), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn set_last_call_in(
        &self,
        agent_id: u32,
        last_call_in: impl Into<String>,
    ) -> Result<AgentRecord, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let last_call_in = last_call_in.into();

        // Snapshot the fields we are about to mutate so we can roll back on
        // persistence failure and keep in-memory state consistent with SQLite.
        let (prev_last_call_in, prev_active, prev_reason) = {
            let info = entry.info.read().await;
            (info.last_call_in.clone(), info.active, info.reason.clone())
        };

        let updated = {
            let mut info = entry.info.write().await;
            info.last_call_in = last_call_in;
            if !info.active {
                info.active = true;
                info.reason.clear();
            }
            info.clone()
        };

        let listener_name = entry.listener_name.read().await.clone();
        if let Err(err) = self.repository.update_with_listener(&updated, &listener_name).await {
            // Roll back the in-memory mutation so callers never observe a
            // state that diverges from what is persisted.
            let mut info = entry.info.write().await;
            info.last_call_in = prev_last_call_in;
            info.active = prev_active;
            info.reason = prev_reason;
            return Err(err);
        }
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
        if self.path_contains(parent_agent_id, link_agent_id).await {
            return Err(TeamserverError::InvalidPivotLink {
                message: format!(
                    "linking 0x{parent_agent_id:08X} -> 0x{link_agent_id:08X} would create a cycle"
                ),
            });
        }

        let parent_depth = self.pivot_chain_depth(parent_agent_id).await;
        if parent_depth >= MAX_PIVOT_CHAIN_DEPTH {
            return Err(TeamserverError::InvalidPivotLink {
                message: format!(
                    "pivot chain depth would exceed MAX_PIVOT_CHAIN_DEPTH ({MAX_PIVOT_CHAIN_DEPTH})"
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
        let mut hops: usize = 0;

        while let Some(next_parent) = self.parent_of(current_parent).await {
            hops = hops.saturating_add(1);
            if hops > MAX_PIVOT_CHAIN_DEPTH {
                return Err(TeamserverError::InvalidPivotLink {
                    message: format!(
                        "pivot chain depth exceeds MAX_PIVOT_CHAIN_DEPTH ({MAX_PIVOT_CHAIN_DEPTH})"
                    ),
                });
            }
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
                let encrypted =
                    encrypt_agent_data_at_offset(&key[..], &iv[..], next_offset, &job.payload)?;
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
        advance: bool,
    ) -> Result<Vec<u8>, TeamserverError> {
        let mut ctr_offset = entry.ctr_block_offset.lock().await;
        let current_offset = *ctr_offset;
        let plaintext = decrypt_agent_data_at_offset(key, iv, current_offset, ciphertext)?;

        if advance {
            let next_offset = next_ctr_offset(current_offset, ciphertext.len())?;
            if next_offset != current_offset {
                self.repository.set_ctr_block_offset(agent_id, next_offset).await?;
                *ctr_offset = next_offset;
            }
        }

        Ok(plaintext)
    }

    /// Count the number of ancestor hops from `agent_id` to the root of its pivot chain.
    ///
    /// A root agent (no parent) has depth 0; its direct child has depth 1; and so on.
    async fn pivot_chain_depth(&self, agent_id: u32) -> usize {
        let mut depth = 0usize;
        let mut current = agent_id;
        while let Some(parent) = self.parent_of(current).await {
            depth = depth.saturating_add(1);
            current = parent;
        }
        depth
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
        drop(info);
        self.run_cleanup_hooks(agent_id).await;
        Ok(())
    }

    async fn run_cleanup_hooks(&self, agent_id: u32) {
        let cleanup_hooks = {
            let hooks = match self.cleanup_hooks.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("agent cleanup hooks mutex poisoned — recovering");
                    poisoned.into_inner()
                }
            };
            hooks.clone()
        };

        for hook in cleanup_hooks {
            hook(agent_id).await;
        }
    }
}

fn decode_crypto_material(
    agent_id: u32,
    encryption: &AgentEncryptionInfo,
) -> Result<(Zeroizing<[u8; AGENT_KEY_LENGTH]>, Zeroizing<[u8; AGENT_IV_LENGTH]>), TeamserverError>
{
    let key = copy_fixed::<AGENT_KEY_LENGTH>(agent_id, "aes_key", &encryption.aes_key)?;
    let iv = copy_fixed::<AGENT_IV_LENGTH>(agent_id, "aes_iv", &encryption.aes_iv)?;
    if is_weak_aes_key(key.as_ref()) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting stored degenerate AES key for agent transport"
        );
        return Err(TeamserverError::InvalidAgentCrypto {
            agent_id,
            message: "degenerate AES keys are not allowed".to_owned(),
        });
    }
    Ok((key, iv))
}

/// Copy raw bytes from a `Zeroizing<Vec<u8>>` into a fixed-size array.
///
/// Returns an error if the slice length does not match `N`.
fn copy_fixed<const N: usize>(
    agent_id: u32,
    field: &'static str,
    bytes: &Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<[u8; N]>, TeamserverError> {
    let actual = bytes.len();
    let array: [u8; N] =
        bytes.as_slice().try_into().map_err(|_| TeamserverError::InvalidPersistedValue {
            field,
            message: format!("agent 0x{agent_id:08X}: expected {N} bytes, got {actual}"),
        })?;
    Ok(Zeroizing::new(array))
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
    use red_cell_common::crypto::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, encrypt_agent_data_at_offset,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    use red_cell_common::AgentEncryptionInfo;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use super::{AgentRegistry, Job, MAX_JOB_QUEUE_DEPTH};
    use crate::database::{Database, LinkRecord, TeamserverError};

    /// Generate a non-degenerate test key from a seed byte.
    fn test_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
        core::array::from_fn(|i| seed.wrapping_add(i as u8))
    }

    /// Generate a non-degenerate test IV from a seed byte.
    fn test_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
        core::array::from_fn(|i| seed.wrapping_add(i as u8))
    }

    fn temp_db_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("red-cell-agent-registry-{}.sqlite", Uuid::new_v4()))
    }

    fn sample_agent(agent_id: u32) -> red_cell_common::AgentRecord {
        red_cell_common::AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(b"aes-key".to_vec()),
                aes_iv: Zeroizing::new(b"aes-iv".to_vec()),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 0,
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
    ) -> red_cell_common::AgentRecord {
        let mut agent = sample_agent(agent_id);
        agent.encryption = AgentEncryptionInfo {
            aes_key: Zeroizing::new(key.to_vec()),
            aes_iv: Zeroizing::new(iv.to_vec()),
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
            payload: vec![u8::try_from(index & 0xff).expect("test data fits in u8")],
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
        let agent = sample_agent_with_crypto(0x1000_0ABC, test_key(0x11), test_iv(0x22));

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
    async fn insert_with_listener_and_ctr_offset_persists_initial_transport_state()
    -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_0009);

        registry.insert_with_listener_and_ctr_offset(agent.clone(), "https-edge", 7).await?;

        assert_eq!(registry.get(agent.agent_id).await, Some(agent));
        assert_eq!(registry.ctr_offset(0x1000_0009).await?, 7);
        assert_eq!(
            database
                .agents()
                .get_persisted(0x1000_0009)
                .await?
                .ok_or(TeamserverError::AgentNotFound { agent_id: 0x1000_0009 })?
                .ctr_block_offset,
            7
        );

        Ok(())
    }

    #[tokio::test]
    async fn insert_with_listener_and_ctr_offset_rolls_back_when_ctr_persist_fails()
    -> Result<(), TeamserverError> {
        let database = test_database().await?;
        sqlx::query(
            r#"
            CREATE TRIGGER fail_ctr_offset_insert
            BEFORE INSERT ON ts_agents
            WHEN NEW.ctr_block_offset = 7
            BEGIN
                SELECT RAISE(FAIL, 'simulated ctr offset persistence failure');
            END;
            "#,
        )
        .execute(database.pool())
        .await?;

        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_000A);
        let error = registry
            .insert_with_listener_and_ctr_offset(agent.clone(), "https-edge", 7)
            .await
            .expect_err("registration should fail when ctr insert is rejected");

        assert!(matches!(error, TeamserverError::Database(_)));
        assert_eq!(registry.get(agent.agent_id).await, None);
        assert_eq!(database.agents().get(agent.agent_id).await?, None);
        assert_eq!(database.agents().get_persisted(agent.agent_id).await?, None);

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
        let cleaned = Arc::new(std::sync::Mutex::new(Vec::new()));
        let cleanup_observer = cleaned.clone();
        registry.register_cleanup_hook(move |agent_id| {
            let cleaned = cleanup_observer.clone();
            async move {
                let mut cleaned = cleaned.lock().expect("cleanup tracker lock should succeed");
                cleaned.push(agent_id);
            }
        });
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
        assert_eq!(
            cleaned.lock().expect("cleanup tracker lock should succeed").as_slice(),
            &[agent.agent_id]
        );

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
        let cleaned = Arc::new(std::sync::Mutex::new(Vec::new()));
        let cleanup_observer = cleaned.clone();
        registry.register_cleanup_hook(move |agent_id| {
            let cleaned = cleanup_observer.clone();
            async move {
                let mut cleaned = cleaned.lock().expect("cleanup tracker lock should succeed");
                cleaned.push(agent_id);
            }
        });
        registry.insert(agent.clone()).await?;

        let removed = registry.remove(agent.agent_id).await?;

        assert_eq!(removed, agent);
        assert!(registry.get(agent.agent_id).await.is_none());
        assert_eq!(database.agents().get(agent.agent_id).await?, None);
        assert_eq!(
            cleaned.lock().expect("cleanup tracker lock should succeed").as_slice(),
            &[agent.agent_id]
        );

        Ok(())
    }

    #[tokio::test]
    async fn mark_dead_tears_down_pivot_subtree() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let parent = sample_agent(0x1000_000D);
        let child = sample_agent(0x1000_000E);
        let grandchild = sample_agent(0x1000_000F);
        let cleaned = Arc::new(std::sync::Mutex::new(Vec::new()));
        let cleanup_observer = cleaned.clone();
        registry.register_cleanup_hook(move |agent_id| {
            let cleaned = cleanup_observer.clone();
            async move {
                let mut cleaned = cleaned.lock().expect("cleanup tracker lock should succeed");
                cleaned.push(agent_id);
            }
        });
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
        assert_eq!(
            cleaned.lock().expect("cleanup tracker lock should succeed").as_slice(),
            &[parent.agent_id, child.agent_id, grandchild.agent_id]
        );
        Ok(())
    }

    #[tokio::test]
    async fn disconnect_link_removes_existing_parent_child_relationship()
    -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let parent = sample_agent(0x1000_0010);
        let child = sample_agent(0x1000_0011);
        let grandchild = sample_agent(0x1000_0012);

        registry.insert(parent.clone()).await?;
        registry.insert(child.clone()).await?;
        registry.insert(grandchild.clone()).await?;
        registry.add_link(parent.agent_id, child.agent_id).await?;
        registry.add_link(child.agent_id, grandchild.agent_id).await?;

        let affected =
            registry.disconnect_link(parent.agent_id, child.agent_id, "pivot link removed").await?;

        assert_eq!(affected, vec![child.agent_id, grandchild.agent_id]);
        assert_eq!(registry.parent_of(child.agent_id).await, None);
        assert_eq!(registry.parent_of(grandchild.agent_id).await, None);
        assert!(registry.children_of(parent.agent_id).await.is_empty());
        assert!(registry.children_of(child.agent_id).await.is_empty());
        assert_eq!(
            registry.pivots(parent.agent_id).await,
            super::PivotInfo { parent: None, children: Vec::new() }
        );
        assert_eq!(
            registry.pivots(child.agent_id).await,
            super::PivotInfo { parent: None, children: Vec::new() }
        );
        assert_eq!(
            registry.pivots(grandchild.agent_id).await,
            super::PivotInfo { parent: None, children: Vec::new() }
        );
        assert_eq!(database.links().list().await?, Vec::<LinkRecord>::new());
        assert_eq!(
            registry
                .get(child.agent_id)
                .await
                .ok_or(TeamserverError::AgentNotFound { agent_id: child.agent_id })?
                .reason,
            "pivot link removed"
        );
        assert_eq!(
            registry
                .get(grandchild.agent_id)
                .await
                .ok_or(TeamserverError::AgentNotFound { agent_id: grandchild.agent_id })?
                .reason,
            "pivot link removed"
        );

        Ok(())
    }

    #[tokio::test]
    async fn disconnect_link_subtree_cascade_marks_all_descendants_inactive()
    -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let root = sample_agent(0x1000_0019);
        let mid = sample_agent(0x1000_001A);
        let leaf = sample_agent(0x1000_001B);

        registry.insert(root.clone()).await?;
        registry.insert(mid.clone()).await?;
        registry.insert(leaf.clone()).await?;
        registry.add_link(root.agent_id, mid.agent_id).await?;
        registry.add_link(mid.agent_id, leaf.agent_id).await?;

        let affected =
            registry.disconnect_link(root.agent_id, mid.agent_id, "cascade test").await?;

        // Both mid and leaf must appear in the affected set.
        assert_eq!(affected, vec![mid.agent_id, leaf.agent_id]);

        // mid must be marked inactive.
        let mid_state = registry
            .get(mid.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: mid.agent_id })?;
        assert!(!mid_state.active, "mid agent must be inactive after subtree cascade");
        assert_eq!(mid_state.reason, "cascade test");

        // leaf must also be marked inactive — the grandchild cascade path.
        let leaf_state = registry
            .get(leaf.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: leaf.agent_id })?;
        assert!(!leaf_state.active, "leaf agent must be inactive after subtree cascade");
        assert_eq!(leaf_state.reason, "cascade test");

        // root must remain active — it was not part of the disconnected subtree.
        let root_state = registry
            .get(root.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: root.agent_id })?;
        assert!(root_state.active, "root agent must remain active");

        Ok(())
    }

    #[tokio::test]
    async fn disconnect_link_leaf_no_children_returns_single_entry() -> Result<(), TeamserverError>
    {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let parent = sample_agent(0x1000_001C);
        let leaf = sample_agent(0x1000_001D);

        registry.insert(parent.clone()).await?;
        registry.insert(leaf.clone()).await?;
        registry.add_link(parent.agent_id, leaf.agent_id).await?;

        let affected =
            registry.disconnect_link(parent.agent_id, leaf.agent_id, "leaf removed").await?;

        assert_eq!(affected.len(), 1, "only the leaf itself should be affected");
        assert_eq!(affected[0], leaf.agent_id);

        let leaf_state = registry
            .get(leaf.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: leaf.agent_id })?;
        assert!(!leaf_state.active, "leaf must be marked inactive");
        assert_eq!(leaf_state.reason, "leaf removed");

        Ok(())
    }

    #[tokio::test]
    async fn disconnect_link_returns_empty_for_nonexistent_relationship()
    -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let parent = sample_agent(0x1000_0013);
        let child = sample_agent(0x1000_0014);
        let unrelated_parent = sample_agent(0x1000_0015);
        let unrelated_child = sample_agent(0x1000_0016);

        registry.insert(parent.clone()).await?;
        registry.insert(child.clone()).await?;
        registry.insert(unrelated_parent.clone()).await?;
        registry.insert(unrelated_child.clone()).await?;
        registry.add_link(unrelated_parent.agent_id, unrelated_child.agent_id).await?;

        let affected =
            registry.disconnect_link(parent.agent_id, child.agent_id, "missing link").await?;

        assert!(affected.is_empty());
        assert_eq!(registry.parent_of(child.agent_id).await, None);
        assert!(registry.children_of(parent.agent_id).await.is_empty());
        assert_eq!(
            registry.parent_of(unrelated_child.agent_id).await,
            Some(unrelated_parent.agent_id)
        );
        assert_eq!(
            registry.children_of(unrelated_parent.agent_id).await,
            vec![unrelated_child.agent_id]
        );
        assert_eq!(
            database.links().list().await?,
            vec![LinkRecord {
                parent_agent_id: unrelated_parent.agent_id,
                link_agent_id: unrelated_child.agent_id,
            }]
        );
        assert!(
            registry
                .get(unrelated_child.agent_id)
                .await
                .ok_or(TeamserverError::AgentNotFound { agent_id: unrelated_child.agent_id })?
                .active
        );

        Ok(())
    }

    #[tokio::test]
    async fn disconnect_link_cleans_up_final_child_and_runs_cleanup_hooks()
    -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let parent = sample_agent(0x1000_0017);
        let child = sample_agent(0x1000_0018);
        let cleaned = Arc::new(std::sync::Mutex::new(Vec::new()));
        let cleanup_observer = cleaned.clone();
        registry.register_cleanup_hook(move |agent_id| {
            let cleaned = cleanup_observer.clone();
            async move {
                let mut cleaned = cleaned.lock().expect("cleanup tracker lock should succeed");
                cleaned.push(agent_id);
            }
        });

        registry.insert(parent.clone()).await?;
        registry.insert(child.clone()).await?;
        registry.add_link(parent.agent_id, child.agent_id).await?;

        let affected = registry
            .disconnect_link(parent.agent_id, child.agent_id, "operator disconnected pivot")
            .await?;

        assert_eq!(affected, vec![child.agent_id]);
        assert_eq!(registry.parent_of(child.agent_id).await, None);
        assert!(registry.children_of(parent.agent_id).await.is_empty());
        assert_eq!(
            registry.pivots(parent.agent_id).await,
            super::PivotInfo { parent: None, children: Vec::new() }
        );
        assert_eq!(database.links().list().await?, Vec::<LinkRecord>::new());
        assert_eq!(
            cleaned.lock().expect("cleanup tracker lock should succeed").as_slice(),
            &[child.agent_id]
        );
        let child_state = registry
            .get(child.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: child.agent_id })?;
        assert!(!child_state.active);
        assert_eq!(child_state.reason, "operator disconnected pivot");

        Ok(())
    }

    #[tokio::test]
    async fn encryption_round_trips() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_0007);
        let updated = AgentEncryptionInfo {
            aes_key: Zeroizing::new(b"new-key".to_vec()),
            aes_iv: Zeroizing::new(b"new-iv".to_vec()),
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
        let key = test_key(0x31);
        let iv = test_iv(0x41);
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
        let agent = sample_agent_with_crypto(0x1000_0702, test_key(0x52), test_iv(0x62));
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
    async fn encrypt_for_agent_empty_plaintext_returns_empty_and_preserves_ctr()
    -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let key = test_key(0xA1);
        let iv = test_iv(0xB1);
        let agent = sample_agent_with_crypto(0x1000_0E01, key, iv);

        registry.insert(agent.clone()).await?;
        assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

        let ciphertext = registry.encrypt_for_agent(agent.agent_id, &[]).await?;

        assert!(ciphertext.is_empty(), "encrypting empty plaintext must produce empty ciphertext");
        assert_eq!(
            registry.ctr_offset(agent.agent_id).await?,
            0,
            "CTR offset must not advance for empty plaintext"
        );

        Ok(())
    }

    #[tokio::test]
    async fn decrypt_from_agent_empty_ciphertext_returns_empty_and_preserves_ctr()
    -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let key = test_key(0xA2);
        let iv = test_iv(0xB2);
        let agent = sample_agent_with_crypto(0x1000_0E02, key, iv);

        registry.insert(agent.clone()).await?;
        assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

        let plaintext = registry.decrypt_from_agent(agent.agent_id, &[]).await?;

        assert!(plaintext.is_empty(), "decrypting empty ciphertext must produce empty plaintext");
        assert_eq!(
            registry.ctr_offset(agent.agent_id).await?,
            0,
            "CTR offset must not advance for empty ciphertext"
        );

        Ok(())
    }

    #[tokio::test]
    async fn encrypt_empty_then_non_empty_preserves_keystream_continuity()
    -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let key = test_key(0xA3);
        let iv = test_iv(0xB3);
        let agent = sample_agent_with_crypto(0x1000_0E03, key, iv);
        let payload = b"payload after empty";

        registry.insert(agent.clone()).await?;

        // Encrypt empty — offset must stay at 0.
        let _ = registry.encrypt_for_agent(agent.agent_id, &[]).await?;
        assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

        // Encrypt a real payload — must use offset 0 keystream.
        let ciphertext = registry.encrypt_for_agent(agent.agent_id, payload).await?;
        let expected = encrypt_agent_data_at_offset(&key, &iv, 0, payload)?;
        assert_eq!(
            ciphertext, expected,
            "empty encrypt must not shift the keystream for subsequent messages"
        );

        Ok(())
    }

    #[tokio::test]
    async fn set_ctr_offset_changes_agent_transport_keystream() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let key = test_key(0x73);
        let iv = test_iv(0x83);
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
        let key = test_key(0x74);
        let iv = test_iv(0x84);
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
    async fn decrypt_from_agent_without_advancing_keeps_ctr_unchanged()
    -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let key = test_key(0x75);
        let iv = test_iv(0x85);
        let agent = sample_agent_with_crypto(0x1000_0706, key, iv);
        let starting_offset = 7;
        let plaintext = b"decrypt-without-advance payload";

        registry.insert(agent.clone()).await?;
        registry.set_ctr_offset(agent.agent_id, starting_offset).await?;

        let ciphertext = encrypt_agent_data_at_offset(&key, &iv, starting_offset, plaintext)?;
        let decrypted =
            registry.decrypt_from_agent_without_advancing(agent.agent_id, &ciphertext).await?;

        assert_eq!(decrypted, plaintext);
        // Offset must NOT have advanced.
        assert_eq!(registry.ctr_offset(agent.agent_id).await?, starting_offset);

        Ok(())
    }

    #[tokio::test]
    async fn advance_ctr_for_agent_commits_offset_correctly() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let key = test_key(0x76);
        let iv = test_iv(0x86);
        let agent = sample_agent_with_crypto(0x1000_0707, key, iv);
        let starting_offset = 3;
        let payload = b"advance-ctr test payload";

        registry.insert(agent.clone()).await?;
        registry.set_ctr_offset(agent.agent_id, starting_offset).await?;

        let ciphertext = encrypt_agent_data_at_offset(&key, &iv, starting_offset, payload)?;

        // Decrypt without advancing, then advance explicitly.
        let decrypted =
            registry.decrypt_from_agent_without_advancing(agent.agent_id, &ciphertext).await?;
        assert_eq!(decrypted, payload);
        assert_eq!(registry.ctr_offset(agent.agent_id).await?, starting_offset);

        registry.advance_ctr_for_agent(agent.agent_id, ciphertext.len()).await?;
        assert_eq!(
            registry.ctr_offset(agent.agent_id).await?,
            starting_offset + ctr_blocks_for_len(ciphertext.len())
        );

        Ok(())
    }

    #[tokio::test]
    async fn decrypt_without_advancing_then_advance_matches_single_step_decrypt()
    -> Result<(), TeamserverError> {
        // Verify that split decrypt+advance produces the same final offset as the normal
        // decrypt_from_agent (which advances atomically in one step).
        let registry_split = AgentRegistry::new(test_database().await?);
        let registry_atomic = AgentRegistry::new(test_database().await?);
        let key = test_key(0x77);
        let iv = test_iv(0x87);
        let agent = sample_agent_with_crypto(0x1000_0708, key, iv);
        let plaintext = b"split vs atomic ctr advance";

        registry_split.insert(agent.clone()).await?;
        registry_atomic.insert(agent.clone()).await?;

        let ciphertext = encrypt_agent_data_at_offset(&key, &iv, 0, plaintext)?;

        // Split path.
        let dec_split = registry_split
            .decrypt_from_agent_without_advancing(agent.agent_id, &ciphertext)
            .await?;
        registry_split.advance_ctr_for_agent(agent.agent_id, ciphertext.len()).await?;

        // Atomic path.
        let dec_atomic = registry_atomic.decrypt_from_agent(agent.agent_id, &ciphertext).await?;

        assert_eq!(dec_split, plaintext);
        assert_eq!(dec_atomic, plaintext);
        assert_eq!(
            registry_split.ctr_offset(agent.agent_id).await?,
            registry_atomic.ctr_offset(agent.agent_id).await?
        );

        Ok(())
    }

    #[tokio::test]
    async fn zero_key_agent_transport_is_rejected() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let agent =
            sample_agent_with_crypto(0x1000_0704, [0u8; AGENT_KEY_LENGTH], [0u8; AGENT_IV_LENGTH]);
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
        let root = sample_agent_with_crypto(0x1000_0010, test_key(0x11), test_iv(0x22));
        let pivot = sample_agent_with_crypto(0x1000_0011, test_key(0x33), test_iv(0x44));
        let child = sample_agent_with_crypto(0x1000_0012, test_key(0x55), test_iv(0x66));
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
    async fn enqueue_job_returns_queue_full_at_capacity() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let agent = sample_agent(0x1000_0200);
        registry.insert(agent.clone()).await?;

        // Fill the queue to exactly the limit.
        for i in 0..MAX_JOB_QUEUE_DEPTH as u32 {
            registry.enqueue_job(agent.agent_id, sample_job(i)).await?;
        }

        // One more should be rejected.
        let err = registry
            .enqueue_job(agent.agent_id, sample_job(MAX_JOB_QUEUE_DEPTH as u32))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                TeamserverError::QueueFull {
                    agent_id,
                    max_queue_depth,
                    queued
                } if agent_id == agent.agent_id
                    && max_queue_depth == MAX_JOB_QUEUE_DEPTH
                    && queued == MAX_JOB_QUEUE_DEPTH
            ),
            "unexpected error: {err}"
        );

        // The queue depth must not have grown beyond the limit.
        let queued = registry.queued_jobs(agent.agent_id).await?;
        assert_eq!(queued.len(), MAX_JOB_QUEUE_DEPTH);
        Ok(())
    }

    #[tokio::test]
    async fn enqueue_job_queue_full_does_not_retain_request_context() -> Result<(), TeamserverError>
    {
        let registry = AgentRegistry::new(test_database().await?);
        let agent = sample_agent(0x1000_0202);
        registry.insert(agent.clone()).await?;

        // Fill the queue to exactly the limit.
        for i in 0..MAX_JOB_QUEUE_DEPTH as u32 {
            registry.enqueue_job(agent.agent_id, sample_job(i)).await?;
        }

        let rejected_request_id = MAX_JOB_QUEUE_DEPTH as u32;
        let rejected_job = sample_job(rejected_request_id);

        // Attempt one more — must be rejected.
        let err = registry.enqueue_job(agent.agent_id, rejected_job).await.unwrap_err();
        assert!(matches!(err, TeamserverError::QueueFull { .. }), "expected QueueFull, got: {err}");

        // The rejected job must not leave a stale request context behind.
        assert!(
            registry.request_context(agent.agent_id, rejected_request_id).await.is_none(),
            "rejected enqueue must not retain request context"
        );

        // Queue depth must remain unchanged at the capacity limit.
        assert_eq!(registry.queued_jobs(agent.agent_id).await?.len(), MAX_JOB_QUEUE_DEPTH,);

        Ok(())
    }

    #[tokio::test]
    async fn enqueue_job_accepts_job_after_dequeue_frees_space() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let agent = sample_agent(0x1000_0201);
        registry.insert(agent.clone()).await?;

        for i in 0..MAX_JOB_QUEUE_DEPTH as u32 {
            registry.enqueue_job(agent.agent_id, sample_job(i)).await?;
        }

        // Drain one job to make room.
        registry.dequeue_job(agent.agent_id).await?;

        // Now the next enqueue must succeed.
        registry.enqueue_job(agent.agent_id, sample_job(MAX_JOB_QUEUE_DEPTH as u32)).await?;
        assert_eq!(registry.queued_jobs(agent.agent_id).await?.len(), MAX_JOB_QUEUE_DEPTH);
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

    #[tokio::test]
    async fn set_last_call_in_revives_inactive_agent_and_clears_reason()
    -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_00C0);
        registry.insert(agent.clone()).await?;
        registry.mark_dead(agent.agent_id, "agent timed out").await?;

        let updated = registry.set_last_call_in(agent.agent_id, "2026-03-09T21:05:00Z").await?;

        assert!(updated.active);
        assert!(updated.reason.is_empty());
        assert_eq!(updated.last_call_in, "2026-03-09T21:05:00Z");
        let persisted = database
            .agents()
            .get(agent.agent_id)
            .await?
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert!(persisted.active);
        assert!(persisted.reason.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn set_last_call_in_revival_persists_cleared_reason_across_load()
    -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_00C1);
        registry.insert(agent.clone()).await?;
        registry.mark_dead(agent.agent_id, "connection lost").await?;

        registry.set_last_call_in(agent.agent_id, "2026-03-09T22:00:00Z").await?;

        let reloaded = AgentRegistry::load(database).await?;
        let restored = reloaded
            .get(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert!(restored.active);
        assert!(restored.reason.is_empty());
        assert_eq!(restored.last_call_in, "2026-03-09T22:00:00Z");

        Ok(())
    }

    #[tokio::test]
    async fn set_last_call_in_returns_agent_not_found_for_unknown_id() -> Result<(), TeamserverError>
    {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);
        let unknown_id = 0x1000_00C2_u32;

        let error = registry
            .set_last_call_in(unknown_id, "2026-03-09T22:00:00Z")
            .await
            .expect_err("set_last_call_in must fail for an unknown agent_id");

        assert!(
            matches!(error, TeamserverError::AgentNotFound { agent_id } if agent_id == unknown_id)
        );

        Ok(())
    }

    #[tokio::test]
    async fn set_last_call_in_rolls_back_in_memory_state_on_persistence_failure()
    -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let mut agent = sample_agent(0x1000_00C3);
        // Start the agent as inactive with a reason so the revival branch is exercised.
        agent.active = false;
        agent.reason = "connection lost".to_owned();
        agent.last_call_in = "2026-03-09T18:00:00Z".to_owned();
        registry.insert(agent.clone()).await?;
        // Mark dead through the registry so persistence is consistent.
        registry.mark_dead(agent.agent_id, "connection lost").await?;

        let before = registry
            .get(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;

        // Close the pool to force any subsequent DB write to fail.
        database.close().await;

        let result = registry.set_last_call_in(agent.agent_id, "2026-03-10T12:00:00Z").await;
        assert!(result.is_err(), "set_last_call_in must fail when the database is closed");

        // The in-memory record must be unchanged — no partial mutation.
        let after = registry
            .get(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert_eq!(after.last_call_in, before.last_call_in);
        assert_eq!(after.active, before.active);
        assert_eq!(after.reason, before.reason);

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

    #[tokio::test]
    async fn add_link_rejects_self_link() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);
        let agent = sample_agent(0x1000_00D0);
        registry.insert(agent.clone()).await?;

        let result = registry.add_link(agent.agent_id, agent.agent_id).await;

        assert!(matches!(
            result,
            Err(TeamserverError::InvalidPivotLink { ref message }) if message.contains("itself")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn add_link_rejects_nonexistent_parent() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);
        let child = sample_agent(0x1000_00E0);
        registry.insert(child.clone()).await?;

        let unknown_parent = 0xDEAD_0001u32;
        let result = registry.add_link(unknown_parent, child.agent_id).await;

        assert!(
            matches!(
                result,
                Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == unknown_parent
            ),
            "expected AgentNotFound for unknown parent, got {result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn add_link_rejects_nonexistent_child() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);
        let parent = sample_agent(0x1000_00F0);
        registry.insert(parent.clone()).await?;

        let unknown_child = 0xDEAD_0002u32;
        let result = registry.add_link(parent.agent_id, unknown_child).await;

        assert!(
            matches!(
                result,
                Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == unknown_child
            ),
            "expected AgentNotFound for unknown child, got {result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn add_link_rejects_chain_too_deep() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);

        // Build a linear chain of MAX_PIVOT_CHAIN_DEPTH + 1 agents.
        // After MAX_PIVOT_CHAIN_DEPTH links the root is at depth 0 and the
        // last inserted agent is at depth MAX_PIVOT_CHAIN_DEPTH, which is the
        // limit. Trying to add one more level must be rejected.
        let base_id = 0x2000_0000u32;
        for i in 0..=(super::MAX_PIVOT_CHAIN_DEPTH as u32) {
            registry.insert(sample_agent(base_id + i)).await?;
        }
        for i in 0..(super::MAX_PIVOT_CHAIN_DEPTH as u32) {
            registry.add_link(base_id + i, base_id + i + 1).await?;
        }

        // The chain is now MAX_PIVOT_CHAIN_DEPTH deep. Adding one more level
        // must fail.
        let extra = sample_agent(base_id + super::MAX_PIVOT_CHAIN_DEPTH as u32 + 1);
        registry.insert(extra.clone()).await?;
        let result =
            registry.add_link(base_id + super::MAX_PIVOT_CHAIN_DEPTH as u32, extra.agent_id).await;

        assert!(
            matches!(result, Err(TeamserverError::InvalidPivotLink { ref message }) if message.contains("MAX_PIVOT_CHAIN_DEPTH")),
            "expected InvalidPivotLink depth error, got {result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn add_link_allows_chain_at_max_depth() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);

        // A chain exactly MAX_PIVOT_CHAIN_DEPTH nodes deep (0..MAX_PIVOT_CHAIN_DEPTH
        // links) must be accepted — depth equals the limit, not exceeds it.
        let base_id = 0x2100_0000u32;
        for i in 0..=(super::MAX_PIVOT_CHAIN_DEPTH as u32) {
            registry.insert(sample_agent(base_id + i)).await?;
        }
        for i in 0..(super::MAX_PIVOT_CHAIN_DEPTH as u32) {
            registry.add_link(base_id + i, base_id + i + 1).await?;
        }
        // The last link put the deepest agent at depth MAX_PIVOT_CHAIN_DEPTH,
        // which is exactly the boundary — it must have succeeded.
        let deepest_id = base_id + super::MAX_PIVOT_CHAIN_DEPTH as u32;
        assert_eq!(
            registry.parent_of(deepest_id).await,
            Some(deepest_id - 1),
            "deepest agent must still have a parent after successful add_link at boundary"
        );
        Ok(())
    }

    #[tokio::test]
    async fn add_link_rejects_cycle() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);
        let agent_a = sample_agent(0x1000_00D1);
        let agent_b = sample_agent(0x1000_00D2);
        let agent_c = sample_agent(0x1000_00D3);
        registry.insert(agent_a.clone()).await?;
        registry.insert(agent_b.clone()).await?;
        registry.insert(agent_c.clone()).await?;

        // Build A → B → C
        registry.add_link(agent_a.agent_id, agent_b.agent_id).await?;
        registry.add_link(agent_b.agent_id, agent_c.agent_id).await?;

        // Linking C → A would close the cycle
        let result = registry.add_link(agent_c.agent_id, agent_a.agent_id).await;

        assert!(matches!(
            result,
            Err(TeamserverError::InvalidPivotLink { ref message }) if message.contains("cycle")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn add_link_reparent_removes_previous_parent_child_relationship()
    -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent_a = sample_agent(0x1000_00E1);
        let agent_b = sample_agent(0x1000_00E2);
        let agent_c = sample_agent(0x1000_00E3);
        registry.insert(agent_a.clone()).await?;
        registry.insert(agent_b.clone()).await?;
        registry.insert(agent_c.clone()).await?;

        // Link A → C
        registry.add_link(agent_a.agent_id, agent_c.agent_id).await?;
        assert_eq!(registry.parent_of(agent_c.agent_id).await, Some(agent_a.agent_id));
        assert_eq!(registry.children_of(agent_a.agent_id).await, vec![agent_c.agent_id]);

        // Reparent: B → C (should remove A → C)
        registry.add_link(agent_b.agent_id, agent_c.agent_id).await?;

        // In-memory: parent_of(C) must now be B
        assert_eq!(
            registry.parent_of(agent_c.agent_id).await,
            Some(agent_b.agent_id),
            "parent_of(C) should be B after reparent"
        );
        // In-memory: A should have no children
        assert!(
            registry.children_of(agent_a.agent_id).await.is_empty(),
            "children_of(A) should be empty after reparent"
        );
        // In-memory: B should have exactly C
        assert_eq!(
            registry.children_of(agent_b.agent_id).await,
            vec![agent_c.agent_id],
            "children_of(B) should contain only C"
        );

        // Persisted: only B → C should exist in the link table
        let persisted = database.links().list().await?;
        assert_eq!(
            persisted.len(),
            1,
            "expected exactly one persisted link row after reparent, got {persisted:?}"
        );
        assert_eq!(persisted[0].parent_agent_id, agent_b.agent_id);
        assert_eq!(persisted[0].link_agent_id, agent_c.agent_id);

        // Persisted: A → C must not exist
        assert!(
            !database.links().exists(agent_a.agent_id, agent_c.agent_id).await?,
            "old A → C link must not exist in the database after reparent"
        );

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

    /// Closing the pool simulates a SQLite write failure for set_ctr_offset.
    /// The in-memory CTR offset must remain at its original value when the
    /// persistence step fails.
    #[tokio::test]
    async fn set_ctr_offset_no_partial_mutation_on_db_failure() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_F001);
        registry.insert(agent.clone()).await?;

        // Establish a known initial offset.
        registry.set_ctr_offset(agent.agent_id, 5).await?;
        assert_eq!(registry.ctr_offset(agent.agent_id).await?, 5);

        // Closing the pool causes any subsequent writes to fail.
        database.close().await;

        let result = registry.set_ctr_offset(agent.agent_id, 99).await;
        assert!(result.is_err(), "expected DB write to fail after pool close");

        // In-memory state must not have advanced.
        assert_eq!(
            registry.ctr_offset(agent.agent_id).await?,
            5,
            "in-memory ctr_block_offset must not mutate when persistence fails"
        );

        Ok(())
    }

    /// Closing the pool simulates a SQLite write failure for set_encryption.
    /// The in-memory AES key/IV must remain at their original values when the
    /// persistence step fails.
    #[tokio::test]
    async fn set_encryption_no_partial_mutation_on_db_failure() -> Result<(), TeamserverError> {
        use red_cell_common::AgentEncryptionInfo;

        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(0x1000_F002, test_key(0xAA), test_iv(0xBB));
        registry.insert(agent.clone()).await?;

        let original_enc = registry.encryption(agent.agent_id).await?;

        // Closing the pool causes any subsequent writes to fail.
        database.close().await;

        let new_enc = AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0xCC; AGENT_KEY_LENGTH]),
            aes_iv: Zeroizing::new(vec![0xDD; AGENT_IV_LENGTH]),
        };
        let result = registry.set_encryption(agent.agent_id, new_enc).await;
        assert!(result.is_err(), "expected DB write to fail after pool close");

        // In-memory encryption must not have changed.
        let current_enc = registry.encryption(agent.agent_id).await?;
        assert_eq!(
            current_enc, original_enc,
            "in-memory encryption must not mutate when persistence fails"
        );

        Ok(())
    }

    /// Fire N+1 concurrent registrations at a registry that is one slot away from its cap.
    ///
    /// The write lock inside `insert_with_listener_and_ctr_offset` serialises the cap check and
    /// the insertion atomically, so exactly one of the N+1 tasks must succeed and the remaining
    /// N must return `TooManyAgents` (i.e. `MaxRegisteredAgentsExceeded`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_registration_at_cap_allows_exactly_one() -> Result<(), TeamserverError> {
        const CAP: usize = 5;
        const EXTRA: usize = 4; // N+1 racers = CAP + EXTRA, where EXTRA > 0

        let database = test_database().await?;
        let registry = Arc::new(AgentRegistry::with_max_registered_agents(database, CAP));

        // Pre-fill the registry so it is one slot away from the limit.
        for index in 0..(CAP - 1) as u32 {
            let agent_id = 0x3300_0000 + index;
            registry.insert(sample_agent(agent_id)).await?;
        }
        assert_eq!(registry.list().await.len(), CAP - 1);

        // Spawn CAP - 1 + EXTRA + 1 = CAP + EXTRA tasks that all race to fill the last slot.
        let racer_count = CAP + EXTRA; // one more than the cap
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..racer_count as u32 {
            let registry = Arc::clone(&registry);
            tasks.spawn(async move {
                let agent_id = 0x3300_1000 + index;
                registry
                    .insert_with_listener_and_ctr_offset(sample_agent(agent_id), "http-race", 0)
                    .await
            });
        }

        let mut successes = 0u32;
        let mut too_many = 0u32;
        while let Some(outcome) = tasks.join_next().await {
            match outcome.expect("task must not panic") {
                Ok(()) => successes += 1,
                Err(TeamserverError::MaxRegisteredAgentsExceeded { .. }) => too_many += 1,
                Err(other) => {
                    return Err(other);
                }
            }
        }

        assert_eq!(
            successes, 1,
            "exactly one concurrent registration must succeed when the cap is one slot away"
        );
        assert_eq!(
            too_many,
            racer_count as u32 - 1,
            "all remaining racers must receive MaxRegisteredAgentsExceeded"
        );
        assert_eq!(
            registry.list().await.len(),
            CAP,
            "registry must be exactly at the cap after the race"
        );

        Ok(())
    }

    #[tokio::test]
    async fn encrypt_for_agent_returns_agent_not_found_for_unknown_id()
    -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let unknown_id: u32 = 0x1234;

        let result = registry.encrypt_for_agent(unknown_id, b"data").await;

        assert!(
            matches!(&result, Err(TeamserverError::AgentNotFound { agent_id }) if *agent_id == unknown_id),
            "expected AgentNotFound for 0x{unknown_id:08X}, got {result:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn decrypt_from_agent_returns_agent_not_found_for_unknown_id()
    -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let unknown_id: u32 = 0x1234;

        let result = registry.decrypt_from_agent(unknown_id, b"data").await;

        assert!(
            matches!(&result, Err(TeamserverError::AgentNotFound { agent_id }) if *agent_id == unknown_id),
            "expected AgentNotFound for 0x{unknown_id:08X}, got {result:?}"
        );

        Ok(())
    }

    #[test]
    fn next_ctr_offset_returns_error_on_u64_overflow() {
        // Place the offset near u64::MAX so adding even 1 block overflows.
        let near_max = u64::MAX;
        let result = super::next_ctr_offset(near_max, 16);
        assert!(result.is_err(), "adding 1 block at u64::MAX must overflow");
    }

    #[test]
    fn next_ctr_offset_succeeds_at_maximum_non_overflowing_value() {
        // u64::MAX - 1 + 1 block = u64::MAX, which is representable.
        let result = super::next_ctr_offset(u64::MAX - 1, 16);
        assert_eq!(result.unwrap(), u64::MAX);
    }

    #[test]
    fn next_ctr_offset_zero_payload_does_not_advance() {
        let result = super::next_ctr_offset(u64::MAX, 0);
        assert_eq!(result.unwrap(), u64::MAX, "zero-length payload must not advance");
    }

    #[tokio::test]
    async fn advance_ctr_for_agent_errors_on_overflow_near_i64_max() -> Result<(), TeamserverError>
    {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);
        let agent = sample_agent_with_crypto(0x1000_FFFE, test_key(0xCC), test_iv(0xDD));
        registry.insert(agent.clone()).await?;

        // i64::MAX as u64 is the largest offset storable in SQLite.
        let max_storable = i64::MAX as u64;
        registry.set_ctr_offset(agent.agent_id, max_storable).await?;
        assert_eq!(registry.ctr_offset(agent.agent_id).await?, max_storable);

        // Advancing by 16 bytes (1 block) would push past i64::MAX, which
        // next_ctr_offset allows (it works in u64 space), but persistence will
        // reject the resulting value.  Either way the operation must fail.
        let result = registry.advance_ctr_for_agent(agent.agent_id, 16).await;
        assert!(result.is_err(), "advance past i64::MAX must fail on persist");

        // In-memory offset must remain unchanged after the failed advance.
        assert_eq!(
            registry.ctr_offset(agent.agent_id).await?,
            max_storable,
            "in-memory ctr_block_offset must not change on overflow"
        );

        Ok(())
    }

    #[tokio::test]
    async fn advance_ctr_for_agent_succeeds_at_i64_max_boundary() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);
        let agent = sample_agent_with_crypto(0x1000_FFFD, test_key(0xCC), test_iv(0xDD));
        registry.insert(agent.clone()).await?;

        // Set to (i64::MAX - 1) as u64, then advance by 1 block → i64::MAX as u64.
        let near_max = (i64::MAX - 1) as u64;
        registry.set_ctr_offset(agent.agent_id, near_max).await?;
        registry.advance_ctr_for_agent(agent.agent_id, 16).await?;

        assert_eq!(
            registry.ctr_offset(agent.agent_id).await?,
            i64::MAX as u64,
            "advance to exactly i64::MAX must succeed"
        );

        Ok(())
    }

    #[tokio::test]
    async fn advance_ctr_for_agent_zero_len_at_max_does_not_advance() -> Result<(), TeamserverError>
    {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);
        let agent = sample_agent_with_crypto(0x1000_FFFC, test_key(0xCC), test_iv(0xDD));
        registry.insert(agent.clone()).await?;

        let max_storable = i64::MAX as u64;
        registry.set_ctr_offset(agent.agent_id, max_storable).await?;
        // Zero-length payload must not overflow even at the storage limit.
        registry.advance_ctr_for_agent(agent.agent_id, 0).await?;

        assert_eq!(registry.ctr_offset(agent.agent_id).await?, max_storable);

        Ok(())
    }

    /// Inserting an agent whose AES key is the wrong length (e.g. 16 bytes instead of 32)
    /// causes `encrypt_for_agent` and `decrypt_from_agent` to return
    /// `InvalidPersistedValue` from `decode_crypto_material` / `copy_fixed`.
    #[tokio::test]
    async fn encrypt_decrypt_reject_truncated_key_material() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let mut agent = sample_agent(0x1000_0D01);
        // 16-byte key instead of the required 32 (AGENT_KEY_LENGTH).
        agent.encryption = AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0xAA; 16]),
            aes_iv: Zeroizing::new(vec![0xBB; AGENT_IV_LENGTH]),
        };
        registry.insert(agent.clone()).await?;

        let enc_result = registry.encrypt_for_agent(agent.agent_id, b"hello").await;
        assert!(
            matches!(
                &enc_result,
                Err(TeamserverError::InvalidPersistedValue { field, .. }) if *field == "aes_key"
            ),
            "expected InvalidPersistedValue for aes_key, got {enc_result:?}"
        );

        let dec_result = registry.decrypt_from_agent(agent.agent_id, b"hello").await;
        assert!(
            matches!(
                &dec_result,
                Err(TeamserverError::InvalidPersistedValue { field, .. }) if *field == "aes_key"
            ),
            "expected InvalidPersistedValue for aes_key, got {dec_result:?}"
        );

        // CTR offset must remain untouched because we never reached encryption.
        assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

        Ok(())
    }

    /// Same as the above test but with a truncated IV instead of the key.
    #[tokio::test]
    async fn encrypt_decrypt_reject_truncated_iv_material() -> Result<(), TeamserverError> {
        let registry = AgentRegistry::new(test_database().await?);
        let mut agent = sample_agent(0x1000_0D02);
        agent.encryption = AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0xAA; AGENT_KEY_LENGTH]),
            aes_iv: Zeroizing::new(vec![0xBB; 8]), // 8 bytes instead of AGENT_IV_LENGTH (16)
        };
        registry.insert(agent.clone()).await?;

        let enc_result = registry.encrypt_for_agent(agent.agent_id, b"hello").await;
        assert!(
            matches!(
                &enc_result,
                Err(TeamserverError::InvalidPersistedValue { field, .. }) if *field == "aes_iv"
            ),
            "expected InvalidPersistedValue for aes_iv, got {enc_result:?}"
        );

        Ok(())
    }

    /// `advance_ctr_for_agent` must return `AgentNotFound` for a non-existent agent.
    #[tokio::test]
    async fn advance_ctr_for_agent_returns_agent_not_found_for_unknown_id() {
        let registry = AgentRegistry::new(test_database().await.expect("db"));
        let missing = 0x1000_0D03;

        assert!(matches!(
            registry.advance_ctr_for_agent(missing, 16).await,
            Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == missing
        ));
    }

    /// After a successful `set_encryption`, both the in-memory value and the persisted
    /// database row must reflect the new key material.
    #[tokio::test]
    async fn set_encryption_updates_both_memory_and_database() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(0x1000_0D04, test_key(0x11), test_iv(0x22));
        registry.insert(agent.clone()).await?;

        let new_enc = AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0xCC; AGENT_KEY_LENGTH]),
            aes_iv: Zeroizing::new(vec![0xDD; AGENT_IV_LENGTH]),
        };
        registry.set_encryption(agent.agent_id, new_enc.clone()).await?;

        // In-memory value must match.
        assert_eq!(registry.encryption(agent.agent_id).await?, new_enc);

        // Database value must also match.
        let persisted = database
            .agents()
            .get(agent.agent_id)
            .await?
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert_eq!(persisted.encryption, new_enc);

        Ok(())
    }

    #[tokio::test]
    async fn remove_returns_agent_not_found_for_unknown_id() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);
        let unknown_id = 0xFFFF_FFFF_u32;

        let error = registry
            .remove(unknown_id)
            .await
            .expect_err("remove must fail for an unknown agent_id");

        assert!(
            matches!(error, TeamserverError::AgentNotFound { agent_id } if agent_id == unknown_id)
        );

        Ok(())
    }

    #[tokio::test]
    async fn mark_dead_returns_agent_not_found_for_unknown_id() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);
        let unknown_id = 0xFFFF_FFFF_u32;

        let error = registry
            .mark_dead(unknown_id, "reason")
            .await
            .expect_err("mark_dead must fail for an unknown agent_id");

        assert!(
            matches!(error, TeamserverError::AgentNotFound { agent_id } if agent_id == unknown_id)
        );

        Ok(())
    }

    #[tokio::test]
    async fn mark_dead_on_already_dead_agent_is_idempotent() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent(0x1000_00DD);
        let cleaned = Arc::new(std::sync::Mutex::new(Vec::new()));
        let cleanup_observer = cleaned.clone();
        registry.register_cleanup_hook(move |agent_id| {
            let cleaned = cleanup_observer.clone();
            async move {
                let mut cleaned = cleaned.lock().expect("cleanup tracker lock should succeed");
                cleaned.push(agent_id);
            }
        });
        registry.insert(agent.clone()).await?;

        // First call: mark the agent dead.
        registry.mark_dead(agent.agent_id, "lost contact").await?;
        let after_first = registry
            .get(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert!(!after_first.active);
        assert_eq!(after_first.reason, "lost contact");

        // Second call: mark the already-dead agent dead again with a different reason.
        registry.mark_dead(agent.agent_id, "operator kill").await?;
        let after_second = registry
            .get(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert!(!after_second.active);
        assert_eq!(after_second.reason, "operator kill");

        // Verify the database also reflects the updated reason.
        let persisted = database
            .agents()
            .get(agent.agent_id)
            .await?
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
        assert!(!persisted.active);
        assert_eq!(persisted.reason, "operator kill");

        // Cleanup hooks fire on every mark_dead call (current behavior).
        assert_eq!(
            cleaned.lock().expect("cleanup tracker lock should succeed").as_slice(),
            &[agent.agent_id, agent.agent_id]
        );

        Ok(())
    }

    #[tokio::test]
    async fn set_note_returns_agent_not_found_for_unknown_id() -> Result<(), TeamserverError> {
        let database = test_database().await?;
        let registry = AgentRegistry::new(database);
        let unknown_id = 0xFFFF_FFFF_u32;

        let error = registry
            .set_note(unknown_id, "note")
            .await
            .expect_err("set_note must fail for an unknown agent_id");

        assert!(
            matches!(error, TeamserverError::AgentNotFound { agent_id } if agent_id == unknown_id)
        );

        Ok(())
    }
}
