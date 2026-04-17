use std::collections::HashMap;
use std::sync::Arc;

use super::super::{
    AgentRegistry, Job, JobContext, MAX_JOB_QUEUE_DEPTH, MAX_REQUEST_CONTEXTS, QueuedJob,
};
use super::{sample_agent, sample_agent_with_crypto, sample_job, test_database, test_iv, test_key};
use crate::database::TeamserverError;

#[tokio::test]
async fn job_queue_supports_enqueue_dequeue_and_snapshot() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let agent = sample_agent(0x1000_0008);
    let first = sample_job(1);
    let second = sample_job(2);
    registry.insert(agent.clone()).await?;

    registry.enqueue_job(agent.agent_id, first.clone()).await?;
    registry.enqueue_job(agent.agent_id, second.clone()).await?;

    assert_eq!(registry.queued_jobs(agent.agent_id).await?, vec![first.clone(), second.clone()]);
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
async fn queued_jobs_all_returns_jobs_across_agents_in_stable_order() -> Result<(), TeamserverError>
{
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
            QueuedJob { agent_id: first_agent.agent_id, job: first_job },
            QueuedJob { agent_id: first_agent.agent_id, job: second_job },
            QueuedJob { agent_id: second_agent.agent_id, job: third_job },
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
            JobContext {
                request_id: i,
                command_line: String::new(),
                task_id: String::new(),
                created_at: format!("2026-03-10T10:{i:02}:00Z"),
                operator: String::new(),
            },
        );
    }

    super::super::jobs::evict_oldest_contexts(&mut map, 10);

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
        JobContext {
            request_id: 1,
            command_line: String::new(),
            task_id: String::new(),
            created_at: "2026-03-10T10:00:00Z".to_owned(),
            operator: String::new(),
        },
    );

    super::super::jobs::evict_oldest_contexts(&mut map, 100);
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
    assert_eq!(queued[0].command, u32::from(red_cell_common::demon::DemonCommand::CommandPivot));
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
        .expect_err("expected Err");
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
async fn enqueue_job_queue_full_does_not_retain_request_context() -> Result<(), TeamserverError> {
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
    let err = registry.enqueue_job(agent.agent_id, rejected_job).await.expect_err("expected Err");
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
async fn enqueue_job_evicts_oldest_request_contexts_at_capacity() -> Result<(), TeamserverError> {
    // To trigger the eviction branch inside `enqueue_job` we need to
    // accumulate more than MAX_REQUEST_CONTEXTS entries.  Since each agent
    // can hold at most MAX_JOB_QUEUE_DEPTH jobs, we cycle through
    // enqueue-then-dequeue rounds using multiple agents so that the request
    // contexts keep accumulating (they persist after dequeue) while the job
    // queues are drained to make room.
    let registry = AgentRegistry::new(test_database().await?);

    // We need ceil(MAX_REQUEST_CONTEXTS + 1, MAX_JOB_QUEUE_DEPTH) agents
    // to accumulate enough contexts.  Use a few extra rounds to be safe.
    let agents_needed = (MAX_REQUEST_CONTEXTS / MAX_JOB_QUEUE_DEPTH) + 2;

    // Register all the agents we'll need.
    let mut agent_ids = Vec::with_capacity(agents_needed);
    for i in 0..agents_needed as u32 {
        let agent_id = 0xCC00_0000 + i;
        registry.insert(sample_agent(agent_id)).await?;
        agent_ids.push(agent_id);
    }

    // Enqueue MAX_JOB_QUEUE_DEPTH jobs per agent — each creates a request
    // context keyed by (agent_id, request_id).  Use a global counter for
    // timestamps so the eviction order is deterministic.
    let mut global_seq: u32 = 0;
    for &agent_id in &agent_ids {
        for j in 0..MAX_JOB_QUEUE_DEPTH as u32 {
            let job = Job {
                command: 0x2000 + j,
                request_id: j,
                payload: vec![0],
                command_line: String::new(),
                task_id: String::new(),
                created_at: format!("2026-03-10T00:{:02}:{:02}Z", global_seq / 60, global_seq % 60),
                operator: String::new(),
            };
            global_seq += 1;
            registry.enqueue_job(agent_id, job).await?;
        }
    }

    // Total contexts created = agents_needed * MAX_JOB_QUEUE_DEPTH
    // which exceeds MAX_REQUEST_CONTEXTS, so eviction must have fired.
    let total_created = agents_needed * MAX_JOB_QUEUE_DEPTH;
    assert!(
        total_created > MAX_REQUEST_CONTEXTS,
        "test setup: expected {total_created} > {MAX_REQUEST_CONTEXTS}"
    );

    let remaining = registry.request_contexts_count().await;
    assert!(
        remaining <= MAX_REQUEST_CONTEXTS,
        "request contexts ({remaining}) must not exceed MAX_REQUEST_CONTEXTS ({MAX_REQUEST_CONTEXTS}) after eviction"
    );

    // After eviction the count is pruned to MAX_REQUEST_CONTEXTS / 2,
    // then the remaining enqueues from subsequent agents add more.  The
    // exact number depends on ordering, but it must be well below the
    // total we created.
    assert!(
        remaining < total_created,
        "eviction must have removed some contexts: {remaining} should be less than {total_created}"
    );

    Ok(())
}

#[tokio::test]
async fn enqueue_job_queue_full_for_pivoted_agent() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let root = sample_agent_with_crypto(0xDD00_0001, test_key(0xAA), test_iv(0xBB));
    let child = sample_agent_with_crypto(0xDD00_0002, test_key(0xCC), test_iv(0xDD));
    registry.insert(root.clone()).await?;
    registry.insert(child.clone()).await?;
    registry.add_link(root.agent_id, child.agent_id).await?;

    // Fill the root's queue (pivoted jobs land on root).
    for i in 0..MAX_JOB_QUEUE_DEPTH as u32 {
        registry.enqueue_job(child.agent_id, sample_job(i)).await?;
    }

    // One more for the child (routed to root) must be rejected.
    let err = registry
        .enqueue_job(child.agent_id, sample_job(MAX_JOB_QUEUE_DEPTH as u32))
        .await
        .expect_err("expected Err");

    assert!(
        matches!(
            err,
            TeamserverError::QueueFull {
                agent_id,
                max_queue_depth,
                queued
            } if agent_id == root.agent_id
                && max_queue_depth == MAX_JOB_QUEUE_DEPTH
                && queued == MAX_JOB_QUEUE_DEPTH
        ),
        "expected QueueFull for root, got: {err}"
    );

    Ok(())
}
