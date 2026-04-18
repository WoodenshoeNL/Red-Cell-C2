//! Builtin handler integration tests: job list/suspend/kill-remove/died and
//! package-dropped handlers.

use super::*;

#[tokio::test]
async fn builtin_job_and_package_dropped_handlers_broadcast_agent_responses()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    let mut job_payload = Vec::new();
    add_u32(&mut job_payload, u32::from(DemonJobCommand::Resume));
    add_u32(&mut job_payload, 7);
    add_u32(&mut job_payload, 1);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 30, &job_payload).await?;

    let event = receiver.recv().await.ok_or("job response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Successfully resumed job 7".to_owned()))
    );

    let mut dropped_payload = Vec::new();
    add_u32(&mut dropped_payload, 8192);
    add_u32(&mut dropped_payload, 4096);
    dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandPackageDropped), 31, &dropped_payload)
        .await?;

    let event = receiver.recv().await.ok_or("package dropped response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String(
            "A package was discarded by demon for being larger than PIPE_BUFFER_MAX (8192 > 4096)"
                .to_owned(),
        ))
    );
    Ok(())
}

#[tokio::test]
async fn handle_job_list_with_entries_broadcasts_formatted_table()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::List));
    // Entry 1: job_id=10, type=Thread(1), state=Running(1)
    add_u32(&mut payload, 10);
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    // Entry 2: job_id=42, type=Process(2), state=Suspended(2)
    add_u32(&mut payload, 42);
    add_u32(&mut payload, 2);
    add_u32(&mut payload, 2);
    // Entry 3: job_id=99, type=Track Process(3), state=Dead(3)
    add_u32(&mut payload, 99);
    add_u32(&mut payload, 3);
    add_u32(&mut payload, 3);

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 40, &payload).await?;

    let event = receiver.recv().await.ok_or("job list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Message"), Some(&Value::String("Job list:".to_owned())));
    let output = &message.info.output;
    assert!(output.contains("Job ID"), "table header should contain Job ID column");
    assert!(output.contains("Type"), "table header should contain Type column");
    assert!(output.contains("State"), "table header should contain State column");
    assert!(output.contains("10"), "output should contain job_id 10");
    assert!(output.contains("Thread"), "output should contain Thread type");
    assert!(output.contains("Running"), "output should contain Running state");
    assert!(output.contains("42"), "output should contain job_id 42");
    assert!(output.contains("Process"), "output should contain Process type");
    assert!(output.contains("Suspended"), "output should contain Suspended state");
    assert!(output.contains("99"), "output should contain job_id 99");
    assert!(output.contains("Track Process"), "output should contain Track Process type");
    assert!(output.contains("Dead"), "output should contain Dead state");
    Ok(())
}

#[tokio::test]
async fn handle_job_list_with_zero_rows_still_broadcasts_header()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::List));
    // No job entries follow

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 41, &payload).await?;

    let event = receiver.recv().await.ok_or("job list empty response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let output = &message.info.output;
    assert!(output.contains("Job ID"), "header should be present even with zero rows");
    assert!(output.contains("Type"), "header should contain Type column");
    assert!(output.contains("State"), "header should contain State column");
    Ok(())
}

#[tokio::test]
async fn handle_job_list_unknown_type_and_state_shows_unknown_label()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::List));
    // Entry with out-of-range type=99 and state=0 → both should render as "Unknown"
    add_u32(&mut payload, 7);
    add_u32(&mut payload, 99);
    add_u32(&mut payload, 0);

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 42, &payload).await?;

    let event = receiver.recv().await.ok_or("job list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let output = &message.info.output;
    assert!(output.contains("7"), "output should contain job_id 7");
    // "Unknown" must appear at least twice: once for type, once for state
    let unknown_count = output.matches("Unknown").count();
    assert!(
        unknown_count >= 2,
        "expected at least 2 occurrences of 'Unknown' (type and state), found {unknown_count} in: {output}"
    );
    Ok(())
}

#[tokio::test]
async fn handle_job_list_truncated_mid_row_returns_invalid_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::List));
    // One complete row: job_id=10, type=1, state=1
    add_u32(&mut payload, 10);
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    // Partial row: only job_id present, missing type and state
    add_u32(&mut payload, 20);

    let result =
        dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 42, &payload).await;

    assert!(result.is_err(), "truncated mid-row payload should be rejected");
    let err = result.expect_err("truncated mid-row payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn handle_job_suspend_success_and_failure_broadcasts_correct_messages()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    // Suspend success
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::Suspend));
    add_u32(&mut payload, 5);
    add_u32(&mut payload, 1); // success=true
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 42, &payload).await?;

    let event = receiver.recv().await.ok_or("suspend success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Successfully suspended job 5".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));

    // Suspend failure
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::Suspend));
    add_u32(&mut payload, 9);
    add_u32(&mut payload, 0); // success=false
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 43, &payload).await?;

    let event = receiver.recv().await.ok_or("suspend failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Failed to suspend job 9".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn handle_job_killremove_success_and_failure_broadcasts_correct_messages()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    // KillRemove success
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::KillRemove));
    add_u32(&mut payload, 3);
    add_u32(&mut payload, 1); // success=true
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 44, &payload).await?;

    let event = receiver.recv().await.ok_or("killremove success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Successfully killed and removed job 3".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));

    // KillRemove failure
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::KillRemove));
    add_u32(&mut payload, 11);
    add_u32(&mut payload, 0); // success=false
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 45, &payload).await?;

    let event = receiver.recv().await.ok_or("killremove failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Failed to kill job 11".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn handle_job_died_broadcasts_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::Died));
    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandJob), 46, &payload).await?;

    let result = timeout(Duration::from_millis(50), receiver.recv()).await;
    assert!(result.is_err(), "Died subcommand should not broadcast any event");
    Ok(())
}

#[tokio::test]
async fn handle_job_unknown_subcommand_returns_invalid_callback_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, 0xFF_u32); // invalid subcommand
    let result =
        dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandJob), 47, &payload).await;

    match result {
        Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
            assert_eq!(command_id, u32::from(DemonCommand::CommandJob));
        }
        other => panic!("expected InvalidCallbackPayload, got {other:?}"),
    }
    Ok(())
}
