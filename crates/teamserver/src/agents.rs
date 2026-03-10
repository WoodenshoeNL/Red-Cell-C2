//! In-memory agent registry with SQLite synchronization.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, encrypt_agent_data};
use red_cell_common::demon::{DemonCommand, DemonMessage, DemonPackage};
use red_cell_common::{AgentEncryptionInfo, AgentInfo};
use tokio::sync::{Mutex, RwLock};
use tracing::instrument;

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
}

#[derive(Debug)]
struct AgentEntry {
    info: RwLock<AgentInfo>,
    jobs: Mutex<VecDeque<Job>>,
}

impl AgentEntry {
    fn new(info: AgentInfo) -> Self {
        Self { info: RwLock::new(info), jobs: Mutex::new(VecDeque::new()) }
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

/// Thread-safe in-memory registry of active and historical agents.
#[derive(Clone, Debug)]
pub struct AgentRegistry {
    repository: crate::database::AgentRepository,
    link_repository: crate::database::LinkRepository,
    entries: Arc<RwLock<HashMap<u32, Arc<AgentEntry>>>>,
    parent_links: Arc<RwLock<HashMap<u32, u32>>>,
    child_links: Arc<RwLock<HashMap<u32, BTreeSet<u32>>>>,
}

impl AgentRegistry {
    /// Create an empty registry backed by the provided database.
    #[must_use]
    pub fn new(database: Database) -> Self {
        Self {
            repository: database.agents(),
            link_repository: database.links(),
            entries: Arc::new(RwLock::new(HashMap::new())),
            parent_links: Arc::new(RwLock::new(HashMap::new())),
            child_links: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load all persisted agents from SQLite into a new registry.
    #[instrument(skip(database))]
    pub async fn load(database: Database) -> Result<Self, TeamserverError> {
        let registry = Self::new(database.clone());
        let agents = database.agents().list().await?;
        let links = database.links().list().await?;
        let mut entries = registry.entries.write().await;
        let mut parent_links = registry.parent_links.write().await;
        let mut child_links = registry.child_links.write().await;

        for agent in agents {
            entries.insert(agent.agent_id, Arc::new(AgentEntry::new(agent)));
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
        let mut entries = self.entries.write().await;

        if entries.contains_key(&agent.agent_id) {
            return Err(TeamserverError::DuplicateAgent { agent_id: agent.agent_id });
        }

        self.repository.create(&agent).await?;
        entries.insert(agent.agent_id, Arc::new(AgentEntry::new(agent)));
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

    /// Replace the stored metadata for an existing agent and persist the change.
    #[instrument(skip(self, agent), fields(agent_id = format_args!("0x{:08X}", agent.agent_id)))]
    pub async fn update_agent(&self, agent: AgentInfo) -> Result<(), TeamserverError> {
        let entry = self
            .entry(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;

        self.repository.update(&agent).await?;
        let mut info = entry.info.write().await;
        *info = agent;
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
        }

        self.clear_links_for_agent(agent_id).await?;
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

        self.repository.update(&updated).await?;
        Ok(())
    }

    /// Append a job to an agent's task queue.
    #[instrument(skip(self, job), fields(agent_id = format_args!("0x{:08X}", agent_id), command = job.command, request_id = job.request_id))]
    pub async fn enqueue_job(&self, agent_id: u32, job: Job) -> Result<(), TeamserverError> {
        self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;

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

        self.repository.update(&updated).await?;
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
            payload: encode_pivot_job_payload(wrapped_target, &wrapped_payload),
            command_line: job.command_line.clone(),
            task_id: job.task_id.clone(),
            created_at: job.created_at.clone(),
        };
        let mut current_parent = direct_parent_agent_id;

        while let Some(next_parent) = self.parent_of(current_parent).await {
            wrapped_payload =
                self.serialize_jobs_for_agent(current_parent, &[wrapped_job.clone()]).await?;
            wrapped_target = current_parent;
            wrapped_job = Job {
                command: u32::from(DemonCommand::CommandPivot),
                request_id: job.request_id,
                payload: encode_pivot_job_payload(wrapped_target, &wrapped_payload),
                command_line: job.command_line.clone(),
                task_id: job.task_id.clone(),
                created_at: job.created_at.clone(),
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
        let encryption = self.encryption(agent_id).await?;
        let key =
            decode_fixed::<AGENT_KEY_LENGTH>(agent_id, "aes_key", encryption.aes_key.as_bytes())?;
        let iv = decode_fixed::<AGENT_IV_LENGTH>(agent_id, "aes_iv", encryption.aes_iv.as_bytes())?;
        let mut packages = Vec::with_capacity(jobs.len());

        for job in jobs {
            let payload = if job.payload.is_empty() {
                Vec::new()
            } else {
                encrypt_agent_data(&key, &iv, &job.payload)
            };
            packages.push(DemonPackage {
                command_id: job.command,
                request_id: job.request_id,
                payload,
            });
        }

        DemonMessage::new(packages).to_bytes().map_err(Into::into)
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

fn encode_pivot_job_payload(target_agent_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&target_agent_id.to_le_bytes());
    inner.extend_from_slice(&u32::try_from(payload.len()).unwrap_or_default().to_le_bytes());
    inner.extend_from_slice(payload);

    let mut outer = Vec::new();
    outer.extend_from_slice(
        &u32::from(red_cell_common::demon::DemonPivotCommand::SmbCommand).to_le_bytes(),
    );
    outer.extend_from_slice(&target_agent_id.to_le_bytes());
    outer.extend_from_slice(&u32::try_from(inner.len()).unwrap_or_default().to_le_bytes());
    outer.extend_from_slice(&inner);
    outer
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use red_cell_common::AgentEncryptionInfo;

    use super::{AgentRegistry, Job};
    use crate::database::{Database, LinkRecord, TeamserverError};

    fn temp_db_path() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();

        std::env::temp_dir().join(format!("red-cell-agent-registry-{unique}.sqlite"))
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

        registry.insert(agent.clone()).await?;
        assert_eq!(registry.get(agent.agent_id).await, Some(agent.clone()));
        assert_eq!(database.agents().get(agent.agent_id).await?, Some(agent.clone()));

        let duplicate = registry.insert(agent).await;
        assert!(matches!(
            duplicate,
            Err(TeamserverError::DuplicateAgent { agent_id: 0x1000_0002 })
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
        registry.insert(agent.clone()).await?;

        agent.sleep_delay = 60;
        agent.reason = "updated".to_owned();
        agent.last_call_in = "2026-03-09T20:00:00Z".to_owned();
        registry.update_agent(agent.clone()).await?;

        assert_eq!(registry.get(agent.agent_id).await, Some(agent.clone()));
        assert_eq!(database.agents().get(agent.agent_id).await?, Some(agent));
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
}
