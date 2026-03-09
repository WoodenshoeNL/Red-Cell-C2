//! In-memory agent registry with SQLite synchronization.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use red_cell_common::{AgentEncryptionInfo, AgentInfo};
use tokio::sync::{Mutex, RwLock};

use crate::database::{Database, TeamserverError};

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

/// Thread-safe in-memory registry of active and historical agents.
#[derive(Clone, Debug)]
pub struct AgentRegistry {
    repository: crate::database::AgentRepository,
    entries: Arc<RwLock<HashMap<u32, Arc<AgentEntry>>>>,
}

impl AgentRegistry {
    /// Create an empty registry backed by the provided database.
    #[must_use]
    pub fn new(database: Database) -> Self {
        Self { repository: database.agents(), entries: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Load all persisted agents from SQLite into a new registry.
    pub async fn load(database: Database) -> Result<Self, TeamserverError> {
        let registry = Self::new(database.clone());
        let agents = database.agents().list().await?;
        let mut entries = registry.entries.write().await;

        for agent in agents {
            entries.insert(agent.agent_id, Arc::new(AgentEntry::new(agent)));
        }

        drop(entries);
        Ok(registry)
    }

    /// Insert a newly registered agent and persist it to SQLite.
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
    pub async fn get(&self, agent_id: u32) -> Option<AgentInfo> {
        let entry = self.entry(agent_id).await?;
        let info = entry.info.read().await;
        Some(info.clone())
    }

    /// Return all agents that are still marked active.
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

    /// Replace the stored metadata for an existing agent and persist the change.
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
        Ok(())
    }

    /// Return the current AES key and IV for an agent.
    pub async fn encryption(&self, agent_id: u32) -> Result<AgentEncryptionInfo, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        Ok(info.encryption.clone())
    }

    /// Update the AES key and IV for an agent and persist the new values.
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
    pub async fn enqueue_job(&self, agent_id: u32, job: Job) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let mut jobs = entry.jobs.lock().await;
        jobs.push_back(job);
        Ok(())
    }

    /// Pop the next queued job for an agent, if one exists.
    pub async fn dequeue_job(&self, agent_id: u32) -> Result<Option<Job>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let mut jobs = entry.jobs.lock().await;
        Ok(jobs.pop_front())
    }

    /// Drain all queued jobs for an agent in FIFO order.
    pub async fn dequeue_jobs(&self, agent_id: u32) -> Result<Vec<Job>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let mut jobs = entry.jobs.lock().await;
        Ok(jobs.drain(..).collect())
    }

    /// Return a snapshot of the current queued jobs for an agent.
    pub async fn queued_jobs(&self, agent_id: u32) -> Result<Vec<Job>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let jobs = entry.jobs.lock().await;
        Ok(jobs.iter().cloned().collect())
    }

    /// Update an agent's last callback timestamp and persist the change.
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

    async fn entry(&self, agent_id: u32) -> Option<Arc<AgentEntry>> {
        let entries = self.entries.read().await;
        entries.get(&agent_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use red_cell_common::AgentEncryptionInfo;

    use super::{AgentRegistry, Job};
    use crate::database::{Database, TeamserverError};

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
