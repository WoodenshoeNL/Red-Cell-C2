//! Tests for the per-agent debug packet ring-buffer.

use super::{sample_agent, test_database};
use crate::AgentRegistry;
use crate::agents::packet_ring::{PacketRingBuffer, PacketRingDirection};
use crate::database::TeamserverError;

#[tokio::test]
async fn registry_exchange_round_trip() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let agent = sample_agent(0xACE0_0001);
    registry.insert(agent).await?;

    registry.record_packet_ring_exchange(0xACE0_0001, b"from-agent", b"to-agent", Some(7)).await;

    let snap = registry.packet_ring_snapshot(0xACE0_0001, 5).await;
    assert_eq!(snap.len(), 2);
    assert_eq!(snap[0].direction, PacketRingDirection::Rx);
    assert_eq!(snap[0].bytes, b"from-agent");
    assert_eq!(snap[0].seq, Some(7));
    assert_eq!(snap[1].direction, PacketRingDirection::Tx);
    assert_eq!(snap[1].bytes, b"to-agent");

    Ok(())
}

#[tokio::test]
async fn unknown_agent_record_is_silent_no_panic() {
    let registry = AgentRegistry::new(test_database().await.expect("db"));
    registry.record_packet_ring_exchange(0xFFFF_FFFF, b"rx", b"tx", None).await;
}

#[tokio::test]
async fn reregister_clears_ring() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let agent = sample_agent(0xACE0_0002);
    registry.insert(agent.clone()).await?;
    registry.record_packet_ring_exchange(agent.agent_id, b"a", b"b", None).await;
    assert_eq!(registry.packet_ring_snapshot(agent.agent_id, 5).await.len(), 2);

    registry.reregister_full(agent.clone(), "http", true, false).await?;

    assert!(registry.packet_ring_snapshot(agent.agent_id, 5).await.is_empty());

    Ok(())
}

#[test]
fn buffer_snapshot_n_zero_returns_empty() {
    let mut b = PacketRingBuffer::new();
    b.push(PacketRingDirection::Rx, None, b"x");
    assert!(b.snapshot_last_n_per_direction(0).is_empty());
}
