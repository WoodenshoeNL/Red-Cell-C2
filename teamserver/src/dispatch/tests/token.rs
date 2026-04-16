//! Tests for token command family (steal, list, privs, make, getuid, revert,
//! remove, clear, find, impersonate) covering both the dispatcher callbacks
//! and their handler payload formatting.

use super::common::*;

use super::super::{CommandDispatchError, CommandDispatcher};
use crate::{AgentRegistry, Database, EventBus, SocketRelayManager};
use red_cell_common::demon::{DemonCommand, DemonTokenCommand};
use red_cell_common::operator::OperatorMessage;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn token_steal_callback_broadcasts_success_event() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Steal));
    add_utf16(&mut payload, "LAB\\admin");
    add_u32(&mut payload, 3);
    add_u32(&mut payload, 1234);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 10, &payload).await?;

    let event = receiver.recv().await.ok_or("token steal response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        msg,
        "Successfully stole and impersonated token from 1234 User:[LAB\\admin] TokenID:[3]"
    );
    assert!(msg.contains("LAB\\admin"));
    assert!(msg.contains("TokenID:[3]"));
    Ok(())
}

#[tokio::test]
async fn token_list_callback_formats_vault_table() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::List));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 0xAB);
    add_utf16(&mut payload, "LAB\\svc");
    add_u32(&mut payload, 4444);
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 11, &payload).await?;

    let event = receiver.recv().await.ok_or("token list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(message.info.output.contains("LAB\\svc"));
    assert!(message.info.output.contains("stolen"));
    assert!(message.info.output.contains("Yes"));
    Ok(())
}

#[tokio::test]
async fn token_list_callback_empty_vault() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::List));
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 12, &payload).await?;

    let event = receiver.recv().await.ok_or("token list empty response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(message.info.output.contains("token vault is empty"));
    Ok(())
}

#[tokio::test]
async fn token_privs_list_callback_formats_privilege_table()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 1);
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    add_u32(&mut payload, 3);
    add_bytes(&mut payload, b"SeShutdownPrivilege\0");
    add_u32(&mut payload, 0);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 13, &payload).await?;

    let event = receiver.recv().await.ok_or("token privs list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(message.info.output.contains("SeDebugPrivilege"));
    assert!(message.info.output.contains("Enabled"));
    assert!(message.info.output.contains("SeShutdownPrivilege"));
    assert!(message.info.output.contains("Disabled"));
    Ok(())
}

#[tokio::test]
async fn token_privs_get_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 1);
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 14, &payload).await?;

    let event = receiver.recv().await.ok_or("token privs get response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("successfully enabled"));
    assert!(msg.contains("SeDebugPrivilege"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 0);
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 15, &payload).await?;

    let event = receiver.recv().await.ok_or("token privs get failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to enable"));
    Ok(())
}

#[tokio::test]
async fn token_make_callback_success_and_empty() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    add_utf16(&mut payload, "LAB\\admin");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 16, &payload).await?;

    let event = receiver.recv().await.ok_or("token make response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Successfully created and impersonated token"));
    assert!(msg.contains("LAB\\admin"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 17, &payload).await?;

    let event = receiver.recv().await.ok_or("token make failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to create token"));
    Ok(())
}

#[tokio::test]
async fn token_getuid_callback_elevated_and_normal() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "LAB\\admin");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 18, &payload).await?;

    let event = receiver.recv().await.ok_or("token getuid response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("LAB\\admin"));
    assert!(msg.contains("(Admin)"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 0);
    add_utf16(&mut payload, "LAB\\user");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 19, &payload).await?;

    let event = receiver.recv().await.ok_or("token getuid normal response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("LAB\\user"));
    assert!(!msg.contains("(Admin)"));
    Ok(())
}

#[tokio::test]
async fn token_revert_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 1);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 20, &payload).await?;

    let event = receiver.recv().await.ok_or("token revert response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("reverted token to itself"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 0);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 21, &payload).await?;

    let event = receiver.recv().await.ok_or("token revert failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to revert"));
    Ok(())
}

#[tokio::test]
async fn token_remove_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 5);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 22, &payload).await?;

    let event = receiver.recv().await.ok_or("token remove response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("removed token [5]"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 5);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 23, &payload).await?;

    let event = receiver.recv().await.ok_or("token remove failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to remove token [5]"));
    Ok(())
}

#[tokio::test]
async fn token_clear_callback_broadcasts_success() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Clear));
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 24, &payload).await?;

    let event = receiver.recv().await.ok_or("token clear response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Token vault has been cleared"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_callback_formats_table() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "LAB\\admin");
    add_u32(&mut payload, 5678);
    add_u32(&mut payload, 0x10);
    add_u32(&mut payload, 0x3000);
    add_u32(&mut payload, 2);
    add_u32(&mut payload, 1);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 25, &payload).await?;

    let event = receiver.recv().await.ok_or("token find response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(message.info.output.contains("LAB\\admin"));
    assert!(message.info.output.contains("High"));
    assert!(message.info.output.contains("Primary"));
    assert!(message.info.output.contains("token steal"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_callback_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 0);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 26, &payload).await?;

    let event = receiver.recv().await.ok_or("token find failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to list existing tokens"));
    Ok(())
}

#[tokio::test]
async fn token_impersonate_success_emits_good_response() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Impersonate));
    add_u32(&mut payload, 1); // success
    add_bytes(&mut payload, b"CORP\\jdoe\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 40, &payload).await?;

    let event = receiver.recv().await.ok_or("impersonate success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Successfully impersonated CORP\\jdoe")
    );
    Ok(())
}

#[tokio::test]
async fn token_impersonate_failure_emits_error_response() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Impersonate));
    add_u32(&mut payload, 0); // failure
    add_bytes(&mut payload, b"CORP\\jdoe\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 41, &payload).await?;

    let event = receiver.recv().await.ok_or("impersonate failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to impersonate CORP\\jdoe")
    );
    Ok(())
}

#[tokio::test]
async fn token_make_success_emits_good_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    add_utf16(&mut payload, "CORP\\svcacct");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 42, &payload).await?;

    let event = receiver.recv().await.ok_or("make success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(msg, "Successfully created and impersonated token: CORP\\svcacct");
    Ok(())
}

#[tokio::test]
async fn token_make_empty_payload_emits_error_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    // No user_domain — triggers failure path
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 43, &payload).await?;

    let event = receiver.recv().await.ok_or("make failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to create token")
    );
    Ok(())
}

#[tokio::test]
async fn token_getuid_elevated_emits_admin_suffix() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Elevated user
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 1); // elevated
    add_utf16(&mut payload, "CORP\\admin");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 44, &payload).await?;

    let event = receiver.recv().await.ok_or("getuid elevated response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Token User: CORP\\admin (Admin)")
    );

    // Non-elevated user
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 0); // not elevated
    add_utf16(&mut payload, "CORP\\user");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 45, &payload).await?;

    let event = receiver.recv().await.ok_or("getuid normal response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Token User: CORP\\user")
    );
    Ok(())
}

#[tokio::test]
async fn token_privs_get_success_emits_good_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Enable privilege — success
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0); // get mode
    add_u32(&mut payload, 1); // success
    add_bytes(&mut payload, b"SeImpersonatePrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 46, &payload).await?;

    let event = receiver.recv().await.ok_or("privs get success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("The privilege SeImpersonatePrivilege was successfully enabled")
    );

    // Enable privilege — failure
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0); // get mode
    add_u32(&mut payload, 0); // failure
    add_bytes(&mut payload, b"SeImpersonatePrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 47, &payload).await?;

    let event = receiver.recv().await.ok_or("privs get failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to enable the SeImpersonatePrivilege privilege")
    );
    Ok(())
}

#[tokio::test]
async fn token_privs_list_emits_good_type_with_all_states() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 1); // list mode
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    add_u32(&mut payload, 3); // Enabled
    add_bytes(&mut payload, b"SeBackupPrivilege\0");
    add_u32(&mut payload, 2); // Adjusted
    add_bytes(&mut payload, b"SeRestorePrivilege\0");
    add_u32(&mut payload, 0); // Disabled
    add_bytes(&mut payload, b"SeCustomPrivilege\0");
    add_u32(&mut payload, 99); // Unknown
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 48, &payload).await?;

    let event = receiver.recv().await.ok_or("privs list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let output = &message.info.output;
    assert!(output.contains("SeDebugPrivilege :: Enabled"));
    assert!(output.contains("SeBackupPrivilege :: Adjusted"));
    assert!(output.contains("SeRestorePrivilege :: Disabled"));
    assert!(output.contains("SeCustomPrivilege :: Unknown"));
    Ok(())
}

#[tokio::test]
async fn token_revert_success_emits_good_failure_emits_error()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 1); // success
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 49, &payload).await?;

    let event = receiver.recv().await.ok_or("revert success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Successful reverted token to itself")
    );

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 0); // failure
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 50, &payload).await?;

    let event = receiver.recv().await.ok_or("revert failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to revert token to itself")
    );
    Ok(())
}

#[tokio::test]
async fn token_remove_success_emits_good_failure_emits_error()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 42); // token_id
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 51, &payload).await?;

    let event = receiver.recv().await.ok_or("remove success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Successful removed token [42] from vault")
    );

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 0); // failure
    add_u32(&mut payload, 42); // token_id
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 52, &payload).await?;

    let event = receiver.recv().await.ok_or("remove failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to remove token [42] from vault")
    );
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_zero_count_returns_no_tokens() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 0); // num_tokens = 0
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 53, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens zero count response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    assert!(message.info.output.contains("No tokens found"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_impersonation_type_with_delegation()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 1); // num_tokens
    add_utf16(&mut payload, "CORP\\delegator");
    add_u32(&mut payload, 9999); // pid
    add_u32(&mut payload, 0x20); // handle
    add_u32(&mut payload, 0x2000); // integrity = Medium
    add_u32(&mut payload, 3); // impersonation = Delegation
    add_u32(&mut payload, 2); // token_type = Impersonation
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 54, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens impersonation response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    let output = &message.info.output;
    assert!(output.contains("CORP\\delegator"));
    assert!(output.contains("Medium"));
    assert!(output.contains("Impersonation"));
    assert!(output.contains("Delegation"));
    // Delegation impersonation level means remote auth = Yes
    assert!(output.contains("Yes"));
    assert!(output.contains("token steal"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_failure_emits_error_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 0); // failure
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 55, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to list existing tokens")
    );
    Ok(())
}

#[tokio::test]
async fn token_list_multiple_types_formats_correctly() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::List));
    // Entry 0: stolen (type=1), impersonating
    add_u32(&mut payload, 0); // index
    add_u32(&mut payload, 0xAA); // handle
    add_utf16(&mut payload, "LAB\\stolen_user");
    add_u32(&mut payload, 1000); // pid
    add_u32(&mut payload, 1); // type = stolen
    add_u32(&mut payload, 1); // impersonating = Yes
    // Entry 1: make (local) (type=2), not impersonating
    add_u32(&mut payload, 1); // index
    add_u32(&mut payload, 0xBB); // handle
    add_utf16(&mut payload, "LAB\\local_user");
    add_u32(&mut payload, 2000); // pid
    add_u32(&mut payload, 2); // type = make (local)
    add_u32(&mut payload, 0); // impersonating = No
    // Entry 2: make (network) (type=3)
    add_u32(&mut payload, 2); // index
    add_u32(&mut payload, 0xCC); // handle
    add_utf16(&mut payload, "LAB\\net_user");
    add_u32(&mut payload, 3000); // pid
    add_u32(&mut payload, 3); // type = make (network)
    add_u32(&mut payload, 0); // impersonating = No
    // Entry 3: unknown type (type=99)
    add_u32(&mut payload, 3); // index
    add_u32(&mut payload, 0xDD); // handle
    add_utf16(&mut payload, "LAB\\unknown_user");
    add_u32(&mut payload, 4000); // pid
    add_u32(&mut payload, 99); // type = unknown
    add_u32(&mut payload, 0); // impersonating = No
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 56, &payload).await?;

    let event = receiver.recv().await.ok_or("token list multi response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    let output = &message.info.output;
    assert!(output.contains("stolen"));
    assert!(output.contains("make (local)"));
    assert!(output.contains("make (network)"));
    assert!(output.contains("unknown"));
    assert!(output.contains("LAB\\stolen_user"));
    assert!(output.contains("LAB\\local_user"));
    assert!(output.contains("LAB\\net_user"));
    assert!(output.contains("LAB\\unknown_user"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_integrity_levels_formatted_correctly()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 4); // num_tokens
    // Token 1: Low integrity (0x0800 < LOW_RID 0x1000)
    add_utf16(&mut payload, "LOW\\user");
    add_u32(&mut payload, 100); // pid
    add_u32(&mut payload, 0x01); // handle
    add_u32(&mut payload, 0x0800); // integrity = Low
    add_u32(&mut payload, 0); // impersonation
    add_u32(&mut payload, 2); // Impersonation token
    // Token 2: Medium integrity (0x2000)
    add_utf16(&mut payload, "MED\\user");
    add_u32(&mut payload, 200); // pid
    add_u32(&mut payload, 0x02); // handle
    add_u32(&mut payload, 0x2000); // integrity = Medium
    add_u32(&mut payload, 1); // impersonation = Identification
    add_u32(&mut payload, 2); // Impersonation token
    // Token 3: High integrity (0x3000)
    add_utf16(&mut payload, "HIGH\\user");
    add_u32(&mut payload, 300); // pid
    add_u32(&mut payload, 0x03); // handle
    add_u32(&mut payload, 0x3000); // integrity = High
    add_u32(&mut payload, 2); // impersonation = Impersonation
    add_u32(&mut payload, 2); // Impersonation token
    // Token 4: System integrity (0x4000)
    add_utf16(&mut payload, "SYS\\user");
    add_u32(&mut payload, 400); // pid
    add_u32(&mut payload, 0x04); // handle
    add_u32(&mut payload, 0x4000); // integrity = System
    add_u32(&mut payload, 0); // impersonation = Anonymous
    add_u32(&mut payload, 2); // Impersonation token
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 57, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens integrity response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let output = &message.info.output;
    // Verify each integrity level is correctly mapped
    assert!(output.contains("Low"));
    assert!(output.contains("Medium"));
    assert!(output.contains("High"));
    assert!(output.contains("System"));
    // Verify impersonation level labels
    assert!(output.contains("Anonymous"));
    assert!(output.contains("Identification"));
    // "Impersonation" appears as both token type and impersonation level
    assert!(output.contains("Impersonation"));
    Ok(())
}

#[tokio::test]
async fn token_list_callback_rejects_truncated_row() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Build a List payload with one complete row followed by a truncated second row.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::List));
    // First complete row
    add_u32(&mut payload, 0); // index
    add_u32(&mut payload, 0xAB); // handle
    add_utf16(&mut payload, "LAB\\svc"); // domain_user
    add_u32(&mut payload, 4444); // pid
    add_u32(&mut payload, 1); // type
    add_u32(&mut payload, 1); // impersonating
    // Second row: truncated — only index, missing the rest
    add_u32(&mut payload, 1); // index only

    let err = dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 30, &payload)
        .await
        .expect_err("truncated token list row must be rejected");
    assert!(
        matches!(
            err,
            CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandToken)
        ),
        "expected InvalidCallbackPayload, got {err:?}"
    );
    // Verify no event was broadcast by checking recv times out.
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "no event should be broadcast on parse failure"
    );
    Ok(())
}

#[tokio::test]
async fn token_privs_list_callback_rejects_truncated_row() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // PrivsGetOrList with priv_list=1 (list mode), one complete priv followed by truncation.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 1); // priv_list flag
    // First complete privilege entry
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    add_u32(&mut payload, 3); // state = Enabled
    // Second row: privilege name present but state truncated
    add_bytes(&mut payload, b"SeShutdownPrivilege\0");
    // Missing: state u32

    let err = dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 31, &payload)
        .await
        .expect_err("truncated privilege list row must be rejected");
    assert!(
        matches!(
            err,
            CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandToken)
        ),
        "expected InvalidCallbackPayload, got {err:?}"
    );
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "no event should be broadcast on parse failure"
    );
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_callback_rejects_truncated_row() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // FindTokens with success=1, num_tokens=2 but only one complete token row,
    // the second row truncated after domain_user.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 2); // num_tokens
    // First complete token entry
    add_utf16(&mut payload, "LAB\\admin"); // domain_user
    add_u32(&mut payload, 5678); // pid
    add_u32(&mut payload, 0x10); // handle
    add_u32(&mut payload, 0x3000); // integrity
    add_u32(&mut payload, 2); // impersonation level
    add_u32(&mut payload, 1); // token type
    // Second token: only domain_user, missing remaining fields
    add_utf16(&mut payload, "LAB\\guest");

    let err = dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 32, &payload)
        .await
        .expect_err("truncated found-token row must be rejected");
    assert!(
        matches!(
            err,
            CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandToken)
        ),
        "expected InvalidCallbackPayload, got {err:?}"
    );
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "no event should be broadcast on parse failure"
    );
    Ok(())
}
