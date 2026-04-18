//! Multi-hop chain tests.

use super::*;

#[tokio::test]
async fn pivot_disconnect_success_cascades_to_grandchild() -> Result<(), Box<dyn std::error::Error>>
{
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let parent_id: u32 = 0xBBBB_0001;
    let child_id: u32 = 0xBBBB_0002;
    let grandchild_id: u32 = 0xBBBB_0003;

    registry.insert(sample_agent_info(parent_id, test_key(0x30), test_iv(0x31))).await?;
    registry.insert(sample_agent_info(child_id, test_key(0x40), test_iv(0x41))).await?;
    registry.insert(sample_agent_info(grandchild_id, test_key(0x50), test_iv(0x51))).await?;

    // parent -> child -> grandchild
    registry.add_link(parent_id, child_id).await?;
    registry.add_link(child_id, grandchild_id).await?;

    let payload = disconnect_payload(1, child_id);
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result =
        handle_pivot_disconnect_callback(&registry, &events, parent_id, REQUEST_ID, &mut parser)
            .await;
    assert!(result.is_ok(), "cascading disconnect must succeed: {result:?}");

    let mut marked_agents = Vec::new();
    for _ in 0..2 {
        let event = rx.recv().await.expect("should receive mark event");
        let OperatorMessage::AgentUpdate(update) = &event else {
            panic!("expected AgentUpdate, got {event:?}");
        };
        assert_eq!(update.info.marked, "Dead");
        marked_agents.push(update.info.agent_id.clone());
    }
    assert!(
        marked_agents.contains(&format!("{child_id:08X}")),
        "child must be in marked agents: {marked_agents:?}"
    );
    assert!(
        marked_agents.contains(&format!("{grandchild_id:08X}")),
        "grandchild must be in marked agents: {marked_agents:?}"
    );

    let child = registry.get(child_id).await.expect("child must exist");
    assert!(!child.active, "child must be dead after cascading disconnect");
    let grandchild = registry.get(grandchild_id).await.expect("grandchild must exist");
    assert!(!grandchild.active, "grandchild must be dead after cascading disconnect");

    let parent = registry.get(parent_id).await.expect("parent must exist");
    assert!(parent.active, "parent must remain alive after disconnecting a child");

    Ok(())
}

#[tokio::test]
async fn dispatch_builtin_packages_just_below_max_depth_succeeds()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH;

    let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;

    let child_id: u32 = 0xC0DE_CAFE;
    let child_key = test_key(0x33);
    let child_iv = test_iv(0x44);
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;

    let context = BuiltinDispatchContext {
        registry: &registry,
        events: &events,
        database: &database,
        sockets: &sockets,
        downloads: &downloads,
        plugins: None,
        pivot_dispatch_depth: DEFAULT_MAX_PIVOT_CHAIN_DEPTH - 1,
        max_pivot_chain_depth: DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        allow_legacy_ctr: true,
        init_secret_config: crate::DemonInitSecretConfig::None,
    };

    let packages = vec![DemonCallbackPackage {
        command_id: u32::from(DemonCommand::CommandOutput),
        request_id: 0x02,
        payload: command_output_payload("near limit"),
    }];

    let result = dispatch_builtin_packages(context, child_id, &packages).await;
    assert!(result.is_ok(), "dispatch just below max depth must succeed: {result:?}");
    Ok(())
}
