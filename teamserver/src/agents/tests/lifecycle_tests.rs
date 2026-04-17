use std::sync::Arc;

use super::super::{AgentRegistry, PivotInfo};
use super::{sample_agent, sample_agent_with_crypto, test_database, test_iv, test_key};
use crate::database::{LinkRecord, TeamserverError};

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
        PivotInfo { parent: Some(parent.agent_id), children: Vec::new() }
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
    assert!(matches!(duplicate, Err(TeamserverError::DuplicateAgent { agent_id: 0x1000_0002 })));

    Ok(())
}

#[tokio::test]
async fn reregister_full_updates_metadata_and_resets_ctr() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0xBEEF_0001);

    registry.insert_with_listener(agent.clone(), "http-primary").await?;
    registry.set_ctr_offset(agent.agent_id, 42).await?;

    let mut updated = sample_agent(0xBEEF_0001);
    updated.external_ip = "203.0.113.99".to_owned();
    updated.hostname = "new-wkstn".to_owned();
    updated.active = true;
    updated.reason = String::new();

    registry.reregister_full(updated.clone(), "smb-pivot", false).await?;

    let stored = registry.get(agent.agent_id).await.expect("agent should be present");
    assert_eq!(stored.external_ip, "203.0.113.99");
    assert_eq!(stored.hostname, "new-wkstn");
    assert!(stored.active);
    // CTR offset reset to 0.
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);
    // Listener updated.
    assert_eq!(registry.listener_name(agent.agent_id).await.as_deref(), Some("smb-pivot"));

    // DB also updated.
    let persisted = database
        .agents()
        .get_persisted(agent.agent_id)
        .await?
        .expect("persisted record should exist");
    assert_eq!(persisted.info.external_ip, "203.0.113.99");
    assert_eq!(persisted.ctr_block_offset, 0);
    assert!(!persisted.legacy_ctr);
    assert_eq!(persisted.listener_name, "smb-pivot");

    Ok(())
}

#[tokio::test]
async fn reregister_full_preserves_first_call_in_and_note() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0xBEEF_0002);

    registry.insert(agent.clone()).await?;
    registry.set_note(agent.agent_id, "do not lose this target").await?;
    let original_first_call_in =
        registry.get(agent.agent_id).await.expect("unwrap").first_call_in.clone();

    let mut updated = sample_agent(0xBEEF_0002);
    updated.first_call_in = "2099-01-01T00:00:00Z".to_owned(); // should be ignored
    updated.note = String::new(); // should be ignored

    registry.reregister_full(updated, "http-new", false).await?;

    let stored = registry.get(agent.agent_id).await.expect("agent should be present");
    assert_eq!(stored.first_call_in, original_first_call_in);
    assert_eq!(stored.note, "do not lose this target");

    // DB should also preserve these fields.
    let persisted = database
        .agents()
        .get_persisted(agent.agent_id)
        .await?
        .expect("persisted record should exist");
    assert_eq!(persisted.info.first_call_in, original_first_call_in);
    assert_eq!(persisted.info.note, "do not lose this target");

    Ok(())
}

#[tokio::test]
async fn reregister_full_returns_error_for_unknown_agent() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0xBEEF_0099);

    let result = registry.reregister_full(agent.clone(), "http-main", false).await;
    assert!(matches!(result, Err(TeamserverError::AgentNotFound { agent_id: 0xBEEF_0099 })));

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
        TeamserverError::MaxRegisteredAgentsExceeded { max_registered_agents: 1, registered: 1 }
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
        TeamserverError::MaxRegisteredAgentsExceeded { max_registered_agents: 1, registered: 2 }
    ));

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

            let stored =
                registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
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
            let mut agent =
                registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
            agent.sleep_delay = 60 + index;
            agent.last_call_in = format!("2026-03-10T12:{index:02}:00Z");
            registry.update_agent(agent.clone()).await?;

            let persisted =
                registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
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
async fn remove_returns_agent_not_found_for_unknown_id() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database);
    let unknown_id = 0xFFFF_FFFF_u32;

    let error =
        registry.remove(unknown_id).await.expect_err("remove must fail for an unknown agent_id");

    assert!(matches!(error, TeamserverError::AgentNotFound { agent_id } if agent_id == unknown_id));

    Ok(())
}

#[tokio::test]
async fn insert_allows_registration_after_removal_frees_slot() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::with_max_registered_agents(database, 2);
    let first = sample_agent(0xBB00_0001);
    let second = sample_agent(0xBB00_0002);
    let third = sample_agent(0xBB00_0003);

    registry.insert(first.clone()).await?;
    registry.insert(second.clone()).await?;

    // Cap is reached — third registration must fail.
    let err = registry.insert(third.clone()).await.expect_err("third insert must fail at cap");
    assert!(matches!(err, TeamserverError::MaxRegisteredAgentsExceeded { .. }));

    // Remove one agent to free a slot.
    registry.remove(first.agent_id).await?;

    // Now the third registration must succeed.
    registry.insert(third.clone()).await?;
    assert!(registry.get(third.agent_id).await.is_some());

    Ok(())
}
