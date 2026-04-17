use std::sync::Arc;

use super::super::{AgentRegistry, MAX_PIVOT_CHAIN_DEPTH, PivotInfo};
use super::{sample_agent, test_database};
use crate::database::{LinkRecord, TeamserverError};

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
async fn disconnect_link_removes_existing_parent_child_relationship() -> Result<(), TeamserverError>
{
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
        PivotInfo { parent: None, children: Vec::new() }
    );
    assert_eq!(
        registry.pivots(child.agent_id).await,
        PivotInfo { parent: None, children: Vec::new() }
    );
    assert_eq!(
        registry.pivots(grandchild.agent_id).await,
        PivotInfo { parent: None, children: Vec::new() }
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

    let affected = registry.disconnect_link(root.agent_id, mid.agent_id, "cascade test").await?;

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
async fn disconnect_link_leaf_no_children_returns_single_entry() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let parent = sample_agent(0x1000_001C);
    let leaf = sample_agent(0x1000_001D);

    registry.insert(parent.clone()).await?;
    registry.insert(leaf.clone()).await?;
    registry.add_link(parent.agent_id, leaf.agent_id).await?;

    let affected = registry.disconnect_link(parent.agent_id, leaf.agent_id, "leaf removed").await?;

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
async fn disconnect_link_returns_empty_for_nonexistent_relationship() -> Result<(), TeamserverError>
{
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
    assert_eq!(registry.parent_of(unrelated_child.agent_id).await, Some(unrelated_parent.agent_id));
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
        PivotInfo { parent: None, children: Vec::new() }
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
async fn parent_of_returns_none_for_unlinked_agent() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let agent = sample_agent(0x2000_0001);
    registry.insert(agent.clone()).await?;

    assert_eq!(registry.parent_of(agent.agent_id).await, None);
    Ok(())
}

#[tokio::test]
async fn parent_of_returns_none_for_unknown_agent() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);

    assert_eq!(registry.parent_of(0xDEAD_BEEF).await, None);
    Ok(())
}

#[tokio::test]
async fn parent_of_returns_direct_parent() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let parent = sample_agent(0x2000_0002);
    let child = sample_agent(0x2000_0003);
    registry.insert(parent.clone()).await?;
    registry.insert(child.clone()).await?;
    registry.add_link(parent.agent_id, child.agent_id).await?;

    assert_eq!(registry.parent_of(child.agent_id).await, Some(parent.agent_id));
    // The parent itself has no parent.
    assert_eq!(registry.parent_of(parent.agent_id).await, None);
    Ok(())
}

#[tokio::test]
async fn parent_of_reflects_reparent() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let old_parent = sample_agent(0x2000_0004);
    let new_parent = sample_agent(0x2000_0005);
    let child = sample_agent(0x2000_0006);
    registry.insert(old_parent.clone()).await?;
    registry.insert(new_parent.clone()).await?;
    registry.insert(child.clone()).await?;
    registry.add_link(old_parent.agent_id, child.agent_id).await?;

    assert_eq!(registry.parent_of(child.agent_id).await, Some(old_parent.agent_id));

    registry.add_link(new_parent.agent_id, child.agent_id).await?;
    assert_eq!(registry.parent_of(child.agent_id).await, Some(new_parent.agent_id));
    Ok(())
}

#[tokio::test]
async fn children_of_returns_empty_for_unlinked_agent() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let agent = sample_agent(0x2000_0010);
    registry.insert(agent.clone()).await?;

    assert!(registry.children_of(agent.agent_id).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn children_of_returns_empty_for_unknown_agent() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);

    assert!(registry.children_of(0xDEAD_BEEF).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn children_of_returns_single_child() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let parent = sample_agent(0x2000_0011);
    let child = sample_agent(0x2000_0012);
    registry.insert(parent.clone()).await?;
    registry.insert(child.clone()).await?;
    registry.add_link(parent.agent_id, child.agent_id).await?;

    let children = registry.children_of(parent.agent_id).await;
    assert_eq!(children, vec![child.agent_id]);
    Ok(())
}

#[tokio::test]
async fn children_of_returns_multiple_children() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let parent = sample_agent(0x2000_0020);
    let child_a = sample_agent(0x2000_0021);
    let child_b = sample_agent(0x2000_0022);
    let child_c = sample_agent(0x2000_0023);
    registry.insert(parent.clone()).await?;
    registry.insert(child_a.clone()).await?;
    registry.insert(child_b.clone()).await?;
    registry.insert(child_c.clone()).await?;
    registry.add_link(parent.agent_id, child_a.agent_id).await?;
    registry.add_link(parent.agent_id, child_b.agent_id).await?;
    registry.add_link(parent.agent_id, child_c.agent_id).await?;

    let mut children = registry.children_of(parent.agent_id).await;
    children.sort();
    let mut expected = vec![child_a.agent_id, child_b.agent_id, child_c.agent_id];
    expected.sort();
    assert_eq!(children, expected);
    Ok(())
}

#[tokio::test]
async fn children_of_does_not_include_grandchildren() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let root = sample_agent(0x2000_0030);
    let mid = sample_agent(0x2000_0031);
    let leaf = sample_agent(0x2000_0032);
    registry.insert(root.clone()).await?;
    registry.insert(mid.clone()).await?;
    registry.insert(leaf.clone()).await?;
    registry.add_link(root.agent_id, mid.agent_id).await?;
    registry.add_link(mid.agent_id, leaf.agent_id).await?;

    // root's direct children should only be mid.
    let children = registry.children_of(root.agent_id).await;
    assert_eq!(children, vec![mid.agent_id]);
    // mid's direct children should only be leaf.
    let children = registry.children_of(mid.agent_id).await;
    assert_eq!(children, vec![leaf.agent_id]);
    Ok(())
}

#[tokio::test]
async fn pivots_returns_default_for_unlinked_agent() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let agent = sample_agent(0x2000_0040);
    registry.insert(agent.clone()).await?;

    assert_eq!(
        registry.pivots(agent.agent_id).await,
        PivotInfo { parent: None, children: Vec::new() }
    );
    Ok(())
}

#[tokio::test]
async fn pivots_returns_parent_and_children() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let root = sample_agent(0x2000_0050);
    let mid = sample_agent(0x2000_0051);
    let leaf_a = sample_agent(0x2000_0052);
    let leaf_b = sample_agent(0x2000_0053);
    registry.insert(root.clone()).await?;
    registry.insert(mid.clone()).await?;
    registry.insert(leaf_a.clone()).await?;
    registry.insert(leaf_b.clone()).await?;
    registry.add_link(root.agent_id, mid.agent_id).await?;
    registry.add_link(mid.agent_id, leaf_a.agent_id).await?;
    registry.add_link(mid.agent_id, leaf_b.agent_id).await?;

    let pivot = registry.pivots(mid.agent_id).await;
    assert_eq!(pivot.parent, Some(root.agent_id));
    let mut children = pivot.children;
    children.sort();
    let mut expected = vec![leaf_a.agent_id, leaf_b.agent_id];
    expected.sort();
    assert_eq!(children, expected);

    // Root has children but no parent.
    let root_pivot = registry.pivots(root.agent_id).await;
    assert_eq!(root_pivot.parent, None);
    assert_eq!(root_pivot.children, vec![mid.agent_id]);

    // Leaves have a parent but no children.
    let leaf_pivot = registry.pivots(leaf_a.agent_id).await;
    assert_eq!(leaf_pivot.parent, Some(mid.agent_id));
    assert!(leaf_pivot.children.is_empty());
    Ok(())
}

#[tokio::test]
async fn disconnect_link_wide_fan_out_marks_all_children_inactive() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let root = sample_agent(0x2000_0060);
    let mid = sample_agent(0x2000_0061);
    let leaf_a = sample_agent(0x2000_0062);
    let leaf_b = sample_agent(0x2000_0063);
    let leaf_c = sample_agent(0x2000_0064);
    registry.insert(root.clone()).await?;
    registry.insert(mid.clone()).await?;
    registry.insert(leaf_a.clone()).await?;
    registry.insert(leaf_b.clone()).await?;
    registry.insert(leaf_c.clone()).await?;
    registry.add_link(root.agent_id, mid.agent_id).await?;
    registry.add_link(mid.agent_id, leaf_a.agent_id).await?;
    registry.add_link(mid.agent_id, leaf_b.agent_id).await?;
    registry.add_link(mid.agent_id, leaf_c.agent_id).await?;

    let mut affected =
        registry.disconnect_link(root.agent_id, mid.agent_id, "fan-out disconnect").await?;
    affected.sort();

    let mut expected = vec![mid.agent_id, leaf_a.agent_id, leaf_b.agent_id, leaf_c.agent_id];
    expected.sort();
    assert_eq!(affected, expected);

    // Every agent in the subtree must be inactive.
    for id in &affected {
        let state =
            registry.get(*id).await.ok_or(TeamserverError::AgentNotFound { agent_id: *id })?;
        assert!(!state.active, "agent 0x{id:08X} must be inactive");
        assert_eq!(state.reason, "fan-out disconnect");
    }

    // Root remains active and unlinked.
    let root_state = registry
        .get(root.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: root.agent_id })?;
    assert!(root_state.active);
    assert!(registry.children_of(root.agent_id).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn disconnect_link_preserves_sibling_subtrees() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let root = sample_agent(0x2000_0070);
    let left = sample_agent(0x2000_0071);
    let right = sample_agent(0x2000_0072);
    let left_leaf = sample_agent(0x2000_0073);
    registry.insert(root.clone()).await?;
    registry.insert(left.clone()).await?;
    registry.insert(right.clone()).await?;
    registry.insert(left_leaf.clone()).await?;
    registry.add_link(root.agent_id, left.agent_id).await?;
    registry.add_link(root.agent_id, right.agent_id).await?;
    registry.add_link(left.agent_id, left_leaf.agent_id).await?;

    // Disconnect left subtree; right should be untouched.
    let affected = registry.disconnect_link(root.agent_id, left.agent_id, "left removed").await?;

    assert!(affected.contains(&left.agent_id));
    assert!(affected.contains(&left_leaf.agent_id));
    assert!(!affected.contains(&right.agent_id));

    // Right branch fully intact.
    assert_eq!(registry.parent_of(right.agent_id).await, Some(root.agent_id));
    assert_eq!(registry.children_of(root.agent_id).await, vec![right.agent_id]);
    let right_state = registry
        .get(right.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: right.agent_id })?;
    assert!(right_state.active);
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
    for i in 0..=(MAX_PIVOT_CHAIN_DEPTH as u32) {
        registry.insert(sample_agent(base_id + i)).await?;
    }
    for i in 0..(MAX_PIVOT_CHAIN_DEPTH as u32) {
        registry.add_link(base_id + i, base_id + i + 1).await?;
    }

    // The chain is now MAX_PIVOT_CHAIN_DEPTH deep. Adding one more level
    // must fail.
    let extra = sample_agent(base_id + MAX_PIVOT_CHAIN_DEPTH as u32 + 1);
    registry.insert(extra.clone()).await?;
    let result = registry.add_link(base_id + MAX_PIVOT_CHAIN_DEPTH as u32, extra.agent_id).await;

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
    for i in 0..=(MAX_PIVOT_CHAIN_DEPTH as u32) {
        registry.insert(sample_agent(base_id + i)).await?;
    }
    for i in 0..(MAX_PIVOT_CHAIN_DEPTH as u32) {
        registry.add_link(base_id + i, base_id + i + 1).await?;
    }
    // The last link put the deepest agent at depth MAX_PIVOT_CHAIN_DEPTH,
    // which is exactly the boundary — it must have succeeded.
    let deepest_id = base_id + MAX_PIVOT_CHAIN_DEPTH as u32;
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

/// Verify that concurrent add_link calls for opposite directions cannot
/// both succeed and create a cycle (the TOCTOU race from red-cell-c2-g2i7a).
#[tokio::test]
async fn add_link_concurrent_opposite_links_no_cycle() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = Arc::new(AgentRegistry::new(database));
    let agent_a = sample_agent(0x1000_0F01);
    let agent_b = sample_agent(0x1000_0F02);
    registry.insert(agent_a.clone()).await?;
    registry.insert(agent_b.clone()).await?;

    // Attempt both directions concurrently many times. At least one must
    // always fail. If the TOCTOU race existed, both could succeed and create
    // A ↔ B, which would cause infinite loops in chain-walking functions.
    for _ in 0..50 {
        let reg1 = Arc::clone(&registry);
        let reg2 = Arc::clone(&registry);
        let a_id = agent_a.agent_id;
        let b_id = agent_b.agent_id;

        let (r1, r2) = tokio::join!(
            tokio::spawn(async move { reg1.add_link(a_id, b_id).await }),
            tokio::spawn(async move { reg2.add_link(b_id, a_id).await }),
        );
        let r1 = r1.expect("task panicked");
        let r2 = r2.expect("task panicked");

        // At most one direction may succeed.
        assert!(
            r1.is_err() || r2.is_err(),
            "both add_link(A,B) and add_link(B,A) succeeded — cycle created"
        );

        // Verify no cycle: walking from A must terminate, and walking from B
        // must terminate.
        assert!(
            registry.pivot_chain_depth(a_id).await <= MAX_PIVOT_CHAIN_DEPTH,
            "chain depth from A exceeded cap — possible cycle"
        );
        assert!(
            registry.pivot_chain_depth(b_id).await <= MAX_PIVOT_CHAIN_DEPTH,
            "chain depth from B exceeded cap — possible cycle"
        );

        // Clean up for next iteration: remove whichever link was created.
        if let Some(parent) = registry.parent_of(b_id).await {
            registry.disconnect_link(parent, b_id, "test cleanup").await?;
        }
        if let Some(parent) = registry.parent_of(a_id).await {
            registry.disconnect_link(parent, a_id, "test cleanup").await?;
        }
    }
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
    let outer = super::super::encode_pivot_job_payload(0xDEAD_BEEF, payload)?;
    assert!(outer.len() > payload.len());
    Ok(())
}

#[test]
fn encode_pivot_job_payload_empty_input() {
    let result = super::super::encode_pivot_job_payload(0x1234, &[]);
    assert!(result.is_ok());
}
