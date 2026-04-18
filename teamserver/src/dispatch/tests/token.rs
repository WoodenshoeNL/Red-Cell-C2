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

// ── Formatter unit tests (split from dispatch/token.rs inline block) ──────────

use super::super::CallbackParser;
use super::super::token::{
    format_found_tokens, format_token_list, format_token_privs_list, handle_token_callback,
};
use serde_json::Value;

fn push_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn push_utf16(buf: &mut Vec<u8>, s: &str) {
    let words: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (words.len() * 2) as u32;
    push_u32(buf, byte_len);
    for w in &words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
}

fn push_string(buf: &mut Vec<u8>, s: &str) {
    push_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

// ── format_token_list tests ──────────────────────────────────────────────────

#[test]
fn format_token_list_empty() {
    let buf = Vec::new();
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\nThe token vault is empty");
}

#[test]
fn format_token_list_stolen_impersonating() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0x10);
    push_utf16(&mut buf, "CORP\\admin");
    push_u32(&mut buf, 1234);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 1);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");
    assert!(output.contains("stolen"), "expected 'stolen' in output: {output}");
    assert!(output.contains("Yes"), "expected 'Yes' for impersonating");
    assert!(output.contains("CORP\\admin"));
}

#[test]
fn format_token_list_make_local_not_impersonating() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0x20);
    push_utf16(&mut buf, "LOCAL\\user");
    push_u32(&mut buf, 5678);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 0);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");
    assert!(output.contains("make (local)"));
    assert!(output.contains("No"));
}

#[test]
fn format_token_list_make_network() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 0x30);
    push_utf16(&mut buf, "NET\\svc");
    push_u32(&mut buf, 9999);
    push_u32(&mut buf, 3);
    push_u32(&mut buf, 0);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");
    assert!(output.contains("make (network)"));
}

#[test]
fn format_token_list_unknown_type() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0x40);
    push_utf16(&mut buf, "X\\Y");
    push_u32(&mut buf, 42);
    push_u32(&mut buf, 99);
    push_u32(&mut buf, 0);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");
    assert!(output.contains("unknown"));
}

// ── format_token_privs_list tests ────────────────────────────────────────────

#[test]
fn format_token_privs_list_all_states() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeDebugPrivilege");
    push_u32(&mut buf, 3);
    push_string(&mut buf, "SeBackupPrivilege");
    push_u32(&mut buf, 2);
    push_string(&mut buf, "SeShutdownPrivilege");
    push_u32(&mut buf, 0);
    push_string(&mut buf, "SeRestorePrivilege");
    push_u32(&mut buf, 99);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert!(output.contains("SeDebugPrivilege :: Enabled"));
    assert!(output.contains("SeBackupPrivilege :: Adjusted"));
    assert!(output.contains("SeShutdownPrivilege :: Disabled"));
    assert!(output.contains("SeRestorePrivilege :: Unknown"));
}

#[test]
fn format_token_privs_list_empty() {
    let buf = Vec::new();
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n");
}

#[test]
fn format_token_privs_list_single_enabled() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeDebugPrivilege");
    push_u32(&mut buf, 3);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n SeDebugPrivilege :: Enabled\n");
}

#[test]
fn format_token_privs_list_single_adjusted() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeBackupPrivilege");
    push_u32(&mut buf, 2);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n SeBackupPrivilege :: Adjusted\n");
}

#[test]
fn format_token_privs_list_single_disabled() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeShutdownPrivilege");
    push_u32(&mut buf, 0);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n SeShutdownPrivilege :: Disabled\n");
}

#[test]
fn format_token_privs_list_state_1_is_unknown() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeImpersonatePrivilege");
    push_u32(&mut buf, 1);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n SeImpersonatePrivilege :: Unknown\n");
}

#[test]
fn format_token_privs_list_large_unknown_state() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeLoadDriverPrivilege");
    push_u32(&mut buf, 255);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n SeLoadDriverPrivilege :: Unknown\n");
}

#[test]
fn format_token_privs_list_multiple_preserves_order() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeDebugPrivilege");
    push_u32(&mut buf, 3);
    push_string(&mut buf, "SeShutdownPrivilege");
    push_u32(&mut buf, 0);
    push_string(&mut buf, "SeBackupPrivilege");
    push_u32(&mut buf, 2);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(
        output,
        "\n SeDebugPrivilege :: Enabled\n SeShutdownPrivilege :: Disabled\n SeBackupPrivilege :: Adjusted\n"
    );
}

// ── format_found_tokens tests — integrity level boundaries ───────────────────

fn build_found_token_payload(integrity_level: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, 1);
    push_utf16(&mut buf, "DOMAIN\\user");
    push_u32(&mut buf, 1000);
    push_u32(&mut buf, 0x100);
    push_u32(&mut buf, integrity_level);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 2);
    buf
}

fn get_integrity_from_output(output: &str) -> String {
    for line in output.lines().skip(3) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            return parts[1].to_string();
        }
    }
    panic!("Could not find integrity value in output:\n{output}");
}

#[test]
fn format_found_tokens_integrity_0x0000_is_low() {
    let buf = build_found_token_payload(0x0000);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Low");
}

#[test]
fn format_found_tokens_integrity_0x1000_is_low() {
    let buf = build_found_token_payload(0x1000);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Low");
}

#[test]
fn format_found_tokens_integrity_0x1001_falls_through_to_low() {
    let buf = build_found_token_payload(0x1001);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Low");
}

#[test]
fn format_found_tokens_integrity_0x1fff_falls_through_to_low() {
    let buf = build_found_token_payload(0x1FFF);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Low");
}

#[test]
fn format_found_tokens_integrity_0x2000_is_medium() {
    let buf = build_found_token_payload(0x2000);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Medium");
}

#[test]
fn format_found_tokens_integrity_0x2fff_is_medium() {
    let buf = build_found_token_payload(0x2FFF);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Medium");
}

#[test]
fn format_found_tokens_integrity_0x3000_is_high() {
    let buf = build_found_token_payload(0x3000);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "High");
}

#[test]
fn format_found_tokens_integrity_0x3fff_is_high() {
    let buf = build_found_token_payload(0x3FFF);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "High");
}

#[test]
fn format_found_tokens_integrity_0x4000_is_system() {
    let buf = build_found_token_payload(0x4000);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "System");
}

#[test]
fn format_found_tokens_zero_count() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 0);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(output, "\nNo tokens found");
}

#[test]
fn format_found_tokens_primary_token_type() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 1);
    push_utf16(&mut buf, "NT AUTHORITY\\SYSTEM");
    push_u32(&mut buf, 4);
    push_u32(&mut buf, 0x200);
    push_u32(&mut buf, 0x4000);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert!(output.contains("Primary"), "expected 'Primary' in output: {output}");
    assert!(output.contains("N/A"), "expected 'N/A' impersonation for Primary");
}

#[test]
fn format_found_tokens_impersonation_levels() {
    let levels = [
        (0u32, "Anonymous"),
        (1, "Identification"),
        (2, "Impersonation"),
        (3, "Delegation"),
        (99, "Unknown"),
    ];
    for (imp_level, expected_label) in &levels {
        let mut buf = Vec::new();
        push_u32(&mut buf, 1);
        push_utf16(&mut buf, "CORP\\user");
        push_u32(&mut buf, 100);
        push_u32(&mut buf, 0x50);
        push_u32(&mut buf, 0x2000);
        push_u32(&mut buf, *imp_level);
        push_u32(&mut buf, 2);

        let mut parser = CallbackParser::new(&buf, 0);
        let output = format_found_tokens(&mut parser).expect("unwrap");
        assert!(
            output.contains(expected_label),
            "imp_level={imp_level}: expected '{expected_label}' in output: {output}"
        );
    }
}

#[test]
fn format_token_list_column_expansion_with_long_domain_user() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0x10);
    push_utf16(&mut buf, "A\\B");
    push_u32(&mut buf, 100);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0x20);
    push_utf16(&mut buf, "VERYLONGDOMAIN\\administratoraccount");
    push_u32(&mut buf, 200);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 1);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");

    assert!(output.contains("VERYLONGDOMAIN\\administratoraccount"));
    assert!(output.contains("A\\B"));

    let data_lines: Vec<&str> = output.lines().filter(|l| !l.is_empty()).skip(2).collect();
    assert_eq!(data_lines.len(), 2, "expected 2 data rows");
    assert_eq!(
        data_lines[0].len(),
        data_lines[1].len(),
        "data rows should have same width:\n  row0: '{}'\n  row1: '{}'",
        data_lines[0],
        data_lines[1]
    );
}

#[test]
fn format_found_tokens_column_expansion_with_long_domain_user() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 2);
    push_utf16(&mut buf, "X\\Y");
    push_u32(&mut buf, 10);
    push_u32(&mut buf, 0x50);
    push_u32(&mut buf, 0x2000);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 2);
    push_utf16(&mut buf, "LONGCORP\\very_long_username_here");
    push_u32(&mut buf, 20);
    push_u32(&mut buf, 0x60);
    push_u32(&mut buf, 0x3000);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 2);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");

    assert!(output.contains("LONGCORP\\very_long_username_here"));
    assert!(output.contains("X\\Y"));

    let table_lines: Vec<&str> =
        output.lines().filter(|l| !l.is_empty() && !l.starts_with("To impersonate")).collect();
    assert!(table_lines.len() >= 3);
    let expected_len = table_lines[0].len();
    for line in &table_lines {
        assert_eq!(
            line.len(),
            expected_len,
            "column misalignment in found_tokens:\n  expected len {expected_len}\n  got len {} for: '{line}'",
            line.len()
        );
    }
}

#[test]
fn format_found_tokens_integrity_0x0fff_is_low() {
    let buf = build_found_token_payload(0x0FFF);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Low");
}

#[test]
fn format_found_tokens_unknown_token_type() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 1);
    push_utf16(&mut buf, "DOM\\user");
    push_u32(&mut buf, 42);
    push_u32(&mut buf, 0x10);
    push_u32(&mut buf, 0x2000);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 99);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert!(output.contains("?"), "expected '?' for unknown token type: {output}");
    assert!(output.contains("Unknown"), "expected 'Unknown' impersonation for unknown type");
}

#[test]
fn format_found_tokens_truncates_when_num_tokens_exceeds_payload() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 3);
    push_utf16(&mut buf, "CORP\\admin");
    push_u32(&mut buf, 1234);
    push_u32(&mut buf, 0x10);
    push_u32(&mut buf, 0x2000);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 2);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");

    assert!(output.contains("CORP\\admin"), "expected the single token in output: {output}");
    let data_rows: Vec<&str> = output.lines().filter(|l| l.contains("CORP\\admin")).collect();
    assert_eq!(
        data_rows.len(),
        1,
        "expected exactly 1 data row, got {}: {output}",
        data_rows.len()
    );
    assert!(!output.contains("No tokens found"));
}

#[test]
fn format_found_tokens_num_tokens_exceeds_payload_completely_empty() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 5);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(output, "\nNo tokens found");
}

#[test]
fn format_found_tokens_delegation_has_remote_auth_yes() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 1);
    push_utf16(&mut buf, "CORP\\admin");
    push_u32(&mut buf, 500);
    push_u32(&mut buf, 0x60);
    push_u32(&mut buf, 0x3000);
    push_u32(&mut buf, 3);
    push_u32(&mut buf, 2);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    let yes_count = output.matches("Yes").count();
    assert!(yes_count >= 2, "expected at least 2 'Yes' (Local+Remote) for delegation: {output}");
}

// ── handle_token_callback unit integration tests ──────────────────────────────

const UNIT_AGENT_ID: u32 = 0xDEAD_BEEF;
const UNIT_REQUEST_ID: u32 = 42;
const UNIT_TOKEN_CMD: u32 = 40;

fn unit_token_payload(subcmd: DemonTokenCommand, rest: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, subcmd as u32);
    buf.extend_from_slice(rest);
    buf
}

async fn unit_call_and_recv(
    payload: &[u8],
) -> (Result<Option<Vec<u8>>, super::super::CommandDispatchError>, Option<OperatorMessage>) {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, payload).await;
    drop(events);
    let msg = rx.recv().await;
    (result, msg)
}

fn assert_unit_response(
    msg: &OperatorMessage,
    expected_kind: &str,
    expected_message: &str,
) -> String {
    let OperatorMessage::AgentResponse(m) = msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    assert_eq!(m.info.demon_id, format!("{UNIT_AGENT_ID:08X}"));
    assert_eq!(m.info.command_id, UNIT_TOKEN_CMD.to_string());
    assert_eq!(
        m.info.extra.get("Type").and_then(Value::as_str),
        Some(expected_kind),
        "expected kind={expected_kind}, extra={:?}",
        m.info.extra
    );
    assert_eq!(
        m.info.extra.get("Message").and_then(Value::as_str),
        Some(expected_message),
        "expected message={expected_message}, extra={:?}",
        m.info.extra
    );
    m.info.output.clone()
}

#[tokio::test]
async fn unit_handle_impersonate_success() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    push_string(&mut rest, "CORP\\admin");
    let payload = unit_token_payload(DemonTokenCommand::Impersonate, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("ok"), None);
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Successfully impersonated CORP\\admin");
}

#[tokio::test]
async fn unit_handle_impersonate_failure() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_string(&mut rest, "CORP\\user");
    let payload = unit_token_payload(DemonTokenCommand::Impersonate, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Error", "Failed to impersonate CORP\\user");
}

#[tokio::test]
async fn unit_handle_steal() {
    let mut rest = Vec::new();
    push_utf16(&mut rest, "CORP\\admin");
    push_u32(&mut rest, 7);
    push_u32(&mut rest, 1234);
    let payload = unit_token_payload(DemonTokenCommand::Steal, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(
        &msg,
        "Good",
        "Successfully stole and impersonated token from 1234 User:[CORP\\admin] TokenID:[7]",
    );
}

#[tokio::test]
async fn unit_handle_revert_success() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    let payload = unit_token_payload(DemonTokenCommand::Revert, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Successful reverted token to itself");
}

#[tokio::test]
async fn unit_handle_revert_failure() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    let payload = unit_token_payload(DemonTokenCommand::Revert, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Error", "Failed to revert token to itself");
}

#[tokio::test]
async fn unit_handle_make_success() {
    let mut rest = Vec::new();
    push_utf16(&mut rest, "CORP\\newuser");
    let payload = unit_token_payload(DemonTokenCommand::Make, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(
        &msg,
        "Good",
        "Successfully created and impersonated token: CORP\\newuser",
    );
}

#[tokio::test]
async fn unit_handle_make_empty_payload_is_error() {
    let payload = unit_token_payload(DemonTokenCommand::Make, &[]);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Error", "Failed to create token");
}

#[tokio::test]
async fn unit_handle_getuid_elevated() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    push_utf16(&mut rest, "NT AUTHORITY\\SYSTEM");
    let payload = unit_token_payload(DemonTokenCommand::GetUid, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Token User: NT AUTHORITY\\SYSTEM (Admin)");
}

#[tokio::test]
async fn unit_handle_getuid_not_elevated() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_utf16(&mut rest, "CORP\\user");
    let payload = unit_token_payload(DemonTokenCommand::GetUid, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Token User: CORP\\user");
}

#[tokio::test]
async fn unit_handle_clear() {
    let payload = unit_token_payload(DemonTokenCommand::Clear, &[]);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Token vault has been cleared");
}

#[tokio::test]
async fn unit_handle_remove_success() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    push_u32(&mut rest, 5);
    let payload = unit_token_payload(DemonTokenCommand::Remove, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Successful removed token [5] from vault");
}

#[tokio::test]
async fn unit_handle_remove_failure() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_u32(&mut rest, 3);
    let payload = unit_token_payload(DemonTokenCommand::Remove, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Error", "Failed to remove token [3] from vault");
}

#[tokio::test]
async fn unit_handle_list_empty_vault() {
    let payload = unit_token_payload(DemonTokenCommand::List, &[]);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    let output = assert_unit_response(&msg, "Info", "Token Vault:");
    assert!(output.contains("token vault is empty"), "output={output}");
}

#[tokio::test]
async fn unit_handle_list_with_entries() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_u32(&mut rest, 0x10);
    push_utf16(&mut rest, "CORP\\admin");
    push_u32(&mut rest, 1234);
    push_u32(&mut rest, 1);
    push_u32(&mut rest, 1);
    let payload = unit_token_payload(DemonTokenCommand::List, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    let output = assert_unit_response(&msg, "Info", "Token Vault:");
    assert!(output.contains("CORP\\admin"));
    assert!(output.contains("stolen"));
}

#[tokio::test]
async fn unit_handle_privs_list() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    push_string(&mut rest, "SeDebugPrivilege");
    push_u32(&mut rest, 3);
    let payload = unit_token_payload(DemonTokenCommand::PrivsGetOrList, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    let output = assert_unit_response(&msg, "Good", "List Privileges for current Token:");
    assert!(output.contains("SeDebugPrivilege :: Enabled"));
}

#[tokio::test]
async fn unit_handle_privs_get_success() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_u32(&mut rest, 1);
    push_string(&mut rest, "SeDebugPrivilege");
    let payload = unit_token_payload(DemonTokenCommand::PrivsGetOrList, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "The privilege SeDebugPrivilege was successfully enabled");
}

#[tokio::test]
async fn unit_handle_privs_get_failure() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_u32(&mut rest, 0);
    push_string(&mut rest, "SeDebugPrivilege");
    let payload = unit_token_payload(DemonTokenCommand::PrivsGetOrList, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Error", "Failed to enable the SeDebugPrivilege privilege");
}

#[tokio::test]
async fn unit_handle_find_tokens_success() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    push_u32(&mut rest, 1);
    push_utf16(&mut rest, "CORP\\admin");
    push_u32(&mut rest, 500);
    push_u32(&mut rest, 0x60);
    push_u32(&mut rest, 0x3000);
    push_u32(&mut rest, 2);
    push_u32(&mut rest, 2);
    let payload = unit_token_payload(DemonTokenCommand::FindTokens, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    let output = assert_unit_response(&msg, "Info", "Tokens available:");
    assert!(output.contains("CORP\\admin"));
    assert!(output.contains("High"));
}

#[tokio::test]
async fn unit_handle_find_tokens_failure() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    let payload = unit_token_payload(DemonTokenCommand::FindTokens, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Error", "Failed to list existing tokens");
}

#[tokio::test]
async fn unit_handle_invalid_subcommand() {
    let mut payload = Vec::new();
    push_u32(&mut payload, 9999);

    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err());
    let err = result.expect_err("expected Err");
    let err_str = err.to_string();
    assert!(err_str.contains("0x00000028"), "error should reference token command id: {err_str}");
}

#[tokio::test]
async fn unit_handle_empty_payload() {
    let payload: &[u8] = &[];
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, payload).await;
    assert!(result.is_err(), "empty payload should fail to read subcommand");
}

#[tokio::test]
async fn unit_handle_truncated_impersonate_payload() {
    let payload = unit_token_payload(DemonTokenCommand::Impersonate, &[]);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated Impersonate should fail");
}

#[tokio::test]
async fn unit_handle_truncated_steal_payload() {
    let payload = unit_token_payload(DemonTokenCommand::Steal, &[]);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated Steal should fail");
}

#[tokio::test]
async fn unit_handle_truncated_revert_payload() {
    let payload = unit_token_payload(DemonTokenCommand::Revert, &[]);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated Revert should fail");
}

#[tokio::test]
async fn unit_handle_truncated_getuid_payload() {
    let payload = unit_token_payload(DemonTokenCommand::GetUid, &[]);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated GetUid should fail");
}

#[tokio::test]
async fn unit_handle_truncated_remove_payload() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    let payload = unit_token_payload(DemonTokenCommand::Remove, &rest);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated Remove should fail");
}

#[tokio::test]
async fn unit_handle_truncated_find_tokens_payload() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    let payload = unit_token_payload(DemonTokenCommand::FindTokens, &rest);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated FindTokens should fail");
}

#[tokio::test]
async fn unit_handle_truncated_privs_get_or_list_payload() {
    let payload = unit_token_payload(DemonTokenCommand::PrivsGetOrList, &[]);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated PrivsGetOrList should fail");
}

#[tokio::test]
async fn unit_handle_all_subcommands_return_none() {
    let test_cases: Vec<Vec<u8>> = {
        let mut cases = Vec::new();

        let mut r = Vec::new();
        push_u32(&mut r, 1);
        push_string(&mut r, "user");
        cases.push(unit_token_payload(DemonTokenCommand::Impersonate, &r));

        let mut r = Vec::new();
        push_utf16(&mut r, "user");
        push_u32(&mut r, 1);
        push_u32(&mut r, 2);
        cases.push(unit_token_payload(DemonTokenCommand::Steal, &r));

        cases.push(unit_token_payload(DemonTokenCommand::List, &[]));

        let mut r = Vec::new();
        push_u32(&mut r, 1);
        cases.push(unit_token_payload(DemonTokenCommand::PrivsGetOrList, &r));

        cases.push(unit_token_payload(DemonTokenCommand::Make, &[]));

        let mut r = Vec::new();
        push_u32(&mut r, 0);
        push_utf16(&mut r, "user");
        cases.push(unit_token_payload(DemonTokenCommand::GetUid, &r));

        let mut r = Vec::new();
        push_u32(&mut r, 1);
        cases.push(unit_token_payload(DemonTokenCommand::Revert, &r));

        let mut r = Vec::new();
        push_u32(&mut r, 1);
        push_u32(&mut r, 0);
        cases.push(unit_token_payload(DemonTokenCommand::Remove, &r));

        cases.push(unit_token_payload(DemonTokenCommand::Clear, &[]));

        let mut r = Vec::new();
        push_u32(&mut r, 0);
        cases.push(unit_token_payload(DemonTokenCommand::FindTokens, &r));

        cases
    };

    for (i, payload) in test_cases.iter().enumerate() {
        let events = EventBus::default();
        let _rx = events.subscribe();
        let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, payload).await;
        assert!(result.is_ok(), "case {i} should succeed");
        assert_eq!(result.expect("ok"), None, "case {i} should return None");
    }
}
