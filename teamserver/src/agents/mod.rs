//! In-memory agent registry with SQLite synchronization.

mod crypto;
mod jobs;
mod lifecycle;
mod pivot;
mod query;
mod seq;
mod state;

pub use jobs::{Job, JobContext, QueuedJob};
pub use pivot::PivotInfo;
use pivot::encode_pivot_job_payload;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use red_cell_common::AgentRecord;
use red_cell_common::demon::DemonCommand;
use tokio::sync::{Mutex, RwLock};
use tracing::error;
use tracing::{instrument, warn};

use crate::database::{Database, DatabaseHealthState, DeferredWrite, TeamserverError, WriteQueue};

#[derive(Debug)]
struct AgentEntry {
    info: RwLock<AgentRecord>,
    listener_name: RwLock<String>,
    jobs: Mutex<VecDeque<Job>>,
    ctr_block_offset: Mutex<u64>,
    /// When `true`, AES-CTR always uses block offset 0 (legacy Demon/Archon behaviour).
    legacy_ctr: AtomicBool,
    /// Last callback sequence number accepted from this agent.
    /// `0` means no seq-protected callback has been received yet.
    last_seen_seq: Mutex<u64>,
    /// When `true`, the teamserver enforces monotonic sequence numbers on incoming callbacks.
    /// Demon and Archon agents are exempt (`false`).
    seq_protected: AtomicBool,
    /// When `true`, the agent uses ECDH transport (Phantom/Specter new protocol).
    ///
    /// ECDH agents have no AES session key — job payloads must be returned unencrypted
    /// because the outer AES-256-GCM in the ECDH session provides confidentiality.
    ecdh_transport: AtomicBool,
    /// Number of consecutive replay rejections since the last accepted callback.
    /// Reset to 0 after any successful seq advance or agent re-registration.
    replay_attempt_count: Mutex<u32>,
    /// When `Some(instant)`, all callbacks are refused until that instant has passed.
    /// Lazily cleared on the first request after expiry.
    lockout_until: Mutex<Option<Instant>>,
}

/// Transport and session state passed to [`AgentEntry::new`].
///
/// Grouped into a struct to keep the constructor argument count within clippy's
/// `too_many_arguments` limit while remaining self-documenting at call sites.
struct AgentEntryState {
    ctr_block_offset: u64,
    legacy_ctr: bool,
    last_seen_seq: u64,
    seq_protected: bool,
    ecdh_transport: bool,
    replay_attempt_count: u32,
    lockout_until: Option<Instant>,
}

impl AgentEntry {
    fn new(
        info: AgentRecord,
        listener_name: String,
        state: AgentEntryState,
    ) -> Self {
        Self {
            info: RwLock::new(info),
            listener_name: RwLock::new(listener_name),
            jobs: Mutex::new(VecDeque::new()),
            ctr_block_offset: Mutex::new(state.ctr_block_offset),
            legacy_ctr: AtomicBool::new(state.legacy_ctr),
            last_seen_seq: Mutex::new(state.last_seen_seq),
            seq_protected: AtomicBool::new(state.seq_protected),
            ecdh_transport: AtomicBool::new(state.ecdh_transport),
            replay_attempt_count: Mutex::new(state.replay_attempt_count),
            lockout_until: Mutex::new(state.lockout_until),
        }
    }
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

/// Convert a persisted Unix timestamp (seconds) to an in-memory [`Instant`] deadline.
///
/// Returns `None` when the timestamp is `None`, zero/negative, or already in the past —
/// in all those cases there is no active lockout to restore.
fn unix_secs_to_lockout_instant(unix_secs: Option<i64>) -> Option<Instant> {
    let unix_secs = unix_secs?;
    if unix_secs <= 0 {
        return None;
    }
    let lockout_systime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix_secs as u64);
    let now_systime = std::time::SystemTime::now();
    let remaining = lockout_systime.duration_since(now_systime).ok()?;
    Some(Instant::now() + remaining)
}

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
    /// Shared health state for checking database degradation.
    health_state: Option<DatabaseHealthState>,
    /// Write queue for deferring DB writes during degraded mode.
    write_queue: Option<WriteQueue>,
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
            health_state: None,
            write_queue: None,
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

        // Reconstruct `ecdh_transport` from persisted ECDH sessions.  Phantom/
        // Specter agents created via `process_ecdh_registration` always have at
        // least one row in `ts_ecdh_sessions`, so their presence identifies an
        // ECDH transport agent across teamserver restarts.  Without this,
        // `handle_get_job` would fall back to legacy AES-CTR encryption of job
        // payloads and break the ECDH AES-256-GCM envelope the agent expects.
        let ecdh_agent_ids = database.ecdh().list_agent_ids_with_sessions().await?;

        let registry = Self::with_max_registered_agents(database.clone(), max_registered_agents);
        let links = database.links().list().await?;
        let mut entries = registry.entries.write().await;
        let mut parent_links = registry.parent_links.write().await;
        let mut child_links = registry.child_links.write().await;

        for agent in agents {
            let ecdh_transport = ecdh_agent_ids.contains(&agent.info.agent_id);
            let lockout_until = unix_secs_to_lockout_instant(agent.replay_lockout_until);
            entries.insert(
                agent.info.agent_id,
                Arc::new(AgentEntry::new(
                    agent.info,
                    agent.listener_name,
                    AgentEntryState {
                        ctr_block_offset: agent.ctr_block_offset,
                        legacy_ctr: agent.legacy_ctr,
                        last_seen_seq: agent.last_seen_seq,
                        seq_protected: agent.seq_protected,
                        ecdh_transport,
                        replay_attempt_count: agent.replay_attempt_count,
                        lockout_until,
                    },
                )),
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

    /// Returns `true` when the database circuit-breaker is open and writes
    /// should be deferred rather than attempted directly.
    fn is_degraded(&self) -> bool {
        self.health_state.as_ref().is_some_and(|hs| hs.is_degraded())
    }

    /// Attempt to persist a database write.  If the database is in degraded
    /// mode and a write queue is available, the write is buffered for later
    /// replay instead of failing the caller.
    async fn persist_or_queue<F, Fut>(
        &self,
        deferred: DeferredWrite,
        persist: F,
    ) -> Result<(), TeamserverError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), TeamserverError>>,
    {
        if self.is_degraded() {
            if let Some(ref wq) = self.write_queue {
                wq.enqueue(deferred).await;
                return Ok(());
            }
        }

        let result = persist().await;
        if let Err(ref err) = result {
            // If the write failed and we have a queue, try to buffer it.
            if let Some(ref wq) = self.write_queue {
                error!(%err, "DB write failed — queueing for later replay");
                wq.enqueue(deferred).await;
                return Ok(());
            }
        }

        result
    }

    /// Count active agents and update the Prometheus gauge.
    ///
    /// Accepts a read-locked reference to avoid re-acquiring the lock when the
    /// caller already holds it (e.g. after [`insert_full`]).
    async fn update_active_agent_gauge(
        &self,
        entries: &std::collections::HashMap<u32, Arc<AgentEntry>>,
    ) {
        let mut active = 0u64;
        for handle in entries.values() {
            if handle.info.read().await.active {
                active += 1;
            }
        }
        crate::metrics::set_agents_active(active);
    }

    /// Re-count active agents from scratch and update the gauge.
    ///
    /// Used when the caller does not hold the entries lock (e.g. after
    /// [`mark_dead`]).
    async fn refresh_active_agent_gauge(&self) {
        let entries = self.entries.read().await;
        self.update_active_agent_gauge(&entries).await;
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

#[cfg(test)]
mod tests;
