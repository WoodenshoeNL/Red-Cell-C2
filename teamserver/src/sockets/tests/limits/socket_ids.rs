use std::io;

use super::super::{register_pending_client, sample_agent, test_manager};

#[tokio::test]
async fn socket_id_allocation_wraps_around_u32_max() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    manager.next_socket_id.store(u32::MAX - 2, std::sync::atomic::Ordering::SeqCst);

    let id1 = manager.next_socket_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id2 = manager.next_socket_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id3 = manager.next_socket_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id4 = manager.next_socket_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id5 = manager.next_socket_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    assert_eq!(id1, u32::MAX - 2);
    assert_eq!(id2, u32::MAX - 1);
    assert_eq!(id3, u32::MAX);
    assert_eq!(id4, 0, "AtomicU32 must wrap around to 0 after u32::MAX");
    assert_eq!(id5, 1);

    Ok(())
}

#[tokio::test]
async fn wrapped_socket_ids_do_not_collide() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;

    let (_peer_read_0, _peer_write_0) = register_pending_client(&manager, agent_id, 0).await?;
    let (_peer_read_max, _peer_write_max) =
        register_pending_client(&manager, agent_id, u32::MAX).await?;

    {
        let state = manager.state.read().await;
        let agent_state = state.get(&agent_id).expect("agent state present");
        assert!(agent_state.clients.contains_key(&0));
        assert!(agent_state.clients.contains_key(&u32::MAX));
        assert_eq!(agent_state.clients.len(), 2);
    }

    manager.close_client(agent_id, 0).await.map_err(|e| io::Error::other(e.to_string()))?;
    {
        let state = manager.state.read().await;
        let agent_state = state.get(&agent_id).expect("agent state present");
        assert!(!agent_state.clients.contains_key(&0));
        assert!(agent_state.clients.contains_key(&u32::MAX));
    }

    Ok(())
}
