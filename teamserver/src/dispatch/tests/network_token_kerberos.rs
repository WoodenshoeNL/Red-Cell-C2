//! Tests for network and Kerberos command families.

use super::common::*;

use super::super::CommandDispatcher;
use crate::{AgentRegistry, Database, EventBus, SocketRelayManager};
use red_cell_common::demon::{
    DemonCommand, DemonFilesystemCommand, DemonKerberosCommand, DemonNetCommand,
    DemonTransferCommand,
};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn builtin_kerberos_klist_handler_formats_ticket_output()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonKerberosCommand::Klist));
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "alice");
    add_utf16(&mut payload, "LAB");
    add_u32(&mut payload, 0x1234);
    add_u32(&mut payload, 0x5678);
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "S-1-5-21");
    add_u32(&mut payload, 0xD53E_8000);
    add_u32(&mut payload, 0x019D_B1DE);
    add_u32(&mut payload, 2);
    add_utf16(&mut payload, "Kerberos");
    add_utf16(&mut payload, "DC01");
    add_utf16(&mut payload, "lab.local");
    add_utf16(&mut payload, "alice@lab.local");
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "alice");
    add_utf16(&mut payload, "LAB.LOCAL");
    add_utf16(&mut payload, "krbtgt");
    add_utf16(&mut payload, "LAB.LOCAL");
    add_u32(&mut payload, 0xD53E_8000);
    add_u32(&mut payload, 0x019D_B1DE);
    add_u32(&mut payload, 0xD53E_8000);
    add_u32(&mut payload, 0x019D_B1DE);
    add_u32(&mut payload, 0xD53E_8000);
    add_u32(&mut payload, 0x019D_B1DE);
    add_u32(&mut payload, 18);
    add_u32(&mut payload, 0x4081_0000);
    add_bytes(&mut payload, b"ticket");

    dispatcher.dispatch(0x0102_0304, u32::from(DemonCommand::CommandKerberos), 9, &payload).await?;

    let event = receiver.recv().await.ok_or_else(|| "kerberos response missing".to_owned())?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected kerberos agent response event");
    };
    assert!(message.info.output.contains("UserName                : alice"));
    assert!(message.info.output.contains("Encryption type : AES256_CTS_HMAC_SHA1"));
    assert!(message.info.output.contains("Ticket          : dGlja2V0"));
    Ok(())
}

#[tokio::test]
async fn builtin_net_and_transfer_handlers_format_operator_output()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, 0x44);
    add_u64(&mut open, 20);
    add_utf16(&mut open, "C:\\loot.bin");
    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandFs), 32, &open).await?;
    let _ = receiver.recv().await.ok_or("download progress event missing")?;

    let mut transfer_payload = Vec::new();
    add_u32(&mut transfer_payload, u32::from(DemonTransferCommand::List));
    add_u32(&mut transfer_payload, 0x44);
    add_u32(&mut transfer_payload, 10);
    add_u32(&mut transfer_payload, 1);
    dispatcher
        .dispatch(0x1122_3344, u32::from(DemonCommand::CommandTransfer), 33, &transfer_payload)
        .await?;

    let event = receiver.recv().await.ok_or("transfer response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("List downloads [1 current downloads]:".to_owned()))
    );
    assert!(message.info.output.contains("loot.bin"));
    assert!(message.info.output.contains("50.00%"));

    let mut net_payload = Vec::new();
    add_u32(&mut net_payload, u32::from(DemonNetCommand::Users));
    add_utf16(&mut net_payload, "WKSTN-01");
    add_utf16(&mut net_payload, "alice");
    add_u32(&mut net_payload, 1);
    add_utf16(&mut net_payload, "bob");
    add_u32(&mut net_payload, 0);
    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 34, &net_payload).await?;

    let event = receiver.recv().await.ok_or("net response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Users on WKSTN-01: ".to_owned()))
    );
    assert!(message.info.output.contains("alice (Admin)"));
    assert!(message.info.output.contains("bob"));
    Ok(())
}

#[tokio::test]
async fn net_sessions_two_rows_produces_formatted_table() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonNetCommand::Sessions));
    add_utf16(&mut payload, "SRV-01");
    // Row 1
    add_utf16(&mut payload, "10.0.0.1");
    add_utf16(&mut payload, "alice");
    add_u32(&mut payload, 120);
    add_u32(&mut payload, 5);
    // Row 2
    add_utf16(&mut payload, "10.0.0.2");
    add_utf16(&mut payload, "bob");
    add_u32(&mut payload, 300);
    add_u32(&mut payload, 0);

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 50, &payload).await?;

    let event = receiver.recv().await.ok_or("net sessions response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Sessions for SRV-01 [2]: ".to_owned()))
    );
    let output = &message.info.output;
    assert!(output.contains("10.0.0.1"), "output should contain first client");
    assert!(output.contains("alice"), "output should contain first user");
    assert!(output.contains("10.0.0.2"), "output should contain second client");
    assert!(output.contains("bob"), "output should contain second user");
    assert!(output.contains("Computer"), "output should contain header");
    Ok(())
}

#[tokio::test]
async fn net_share_one_row_contains_name_and_path() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonNetCommand::Share));
    add_utf16(&mut payload, "FILE-SRV");
    // One share row
    add_utf16(&mut payload, "ADMIN$");
    add_utf16(&mut payload, "C:\\Windows");
    add_utf16(&mut payload, "Remote Admin");
    add_u32(&mut payload, 0);

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 51, &payload).await?;

    let event = receiver.recv().await.ok_or("net share response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Shares for FILE-SRV [1]: ".to_owned()))
    );
    let output = &message.info.output;
    assert!(output.contains("ADMIN$"), "output should contain share name");
    assert!(output.contains("C:\\Windows"), "output should contain share path");
    assert!(output.contains("Remote Admin"), "output should contain remark");
    Ok(())
}

#[tokio::test]
async fn net_logons_lists_each_username() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonNetCommand::Logons));
    add_utf16(&mut payload, "DC-01");
    add_utf16(&mut payload, "administrator");
    add_utf16(&mut payload, "svc_backup");
    add_utf16(&mut payload, "jdoe");

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 52, &payload).await?;

    let event = receiver.recv().await.ok_or("net logons response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Logged on users at DC-01 [3]: ".to_owned()))
    );
    let output = &message.info.output;
    assert!(output.contains("administrator"), "output should list first user");
    assert!(output.contains("svc_backup"), "output should list second user");
    assert!(output.contains("jdoe"), "output should list third user");
    assert!(output.contains("Usernames"), "output should contain header");
    Ok(())
}

#[tokio::test]
async fn net_group_two_rows_contains_both_names() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonNetCommand::Group));
    add_utf16(&mut payload, "CORP-DC");
    add_utf16(&mut payload, "Domain Admins");
    add_utf16(&mut payload, "Designated administrators of the domain");
    add_utf16(&mut payload, "Domain Users");
    add_utf16(&mut payload, "All domain users");

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 53, &payload).await?;

    let event = receiver.recv().await.ok_or("net group response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("List groups on CORP-DC: ".to_owned()))
    );
    let output = &message.info.output;
    assert!(output.contains("Domain Admins"), "output should contain first group");
    assert!(output.contains("Domain Users"), "output should contain second group");
    Ok(())
}

#[tokio::test]
async fn net_localgroup_two_rows_contains_both_names() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonNetCommand::LocalGroup));
    add_utf16(&mut payload, "WKSTN-05");
    add_utf16(&mut payload, "Administrators");
    add_utf16(&mut payload, "Full system access");
    add_utf16(&mut payload, "Remote Desktop Users");
    add_utf16(&mut payload, "Can log on remotely");

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 54, &payload).await?;

    let event = receiver.recv().await.ok_or("net localgroup response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Local Groups for WKSTN-05: ".to_owned()))
    );
    let output = &message.info.output;
    assert!(output.contains("Administrators"), "output should contain first group");
    assert!(output.contains("Remote Desktop Users"), "output should contain second group");
    Ok(())
}

#[tokio::test]
async fn net_domain_nonempty_reports_domain_name() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonNetCommand::Domain));
    // read_string uses read_bytes (length-prefixed UTF-8)
    add_bytes(&mut payload, b"CORP.LOCAL\0");

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 55, &payload).await?;

    let event = receiver.recv().await.ok_or("net domain response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Domain for this Host: CORP.LOCAL".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn net_domain_empty_reports_not_joined() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonNetCommand::Domain));
    // Empty string: just a null terminator (read_string trims trailing \0)
    add_bytes(&mut payload, b"\0");

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 56, &payload).await?;

    let event = receiver.recv().await.ok_or("net domain empty response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("The machine does not seem to be joined to a domain".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn net_computer_broadcasts_computer_list() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonNetCommand::Computer));
    add_utf16(&mut payload, "CORP.LOCAL");
    add_utf16(&mut payload, "WS01");
    add_utf16(&mut payload, "WS02");

    let result =
        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 57, &payload).await?;
    assert!(result.is_none(), "Computer subcommand should return None");

    let msg = timeout(Duration::from_millis(200), receiver.recv())
        .await
        .expect("should receive event")
        .expect("should have message");
    let OperatorMessage::AgentResponse(resp) = msg else {
        panic!("expected AgentResponse");
    };
    assert!(
        resp.info
            .extra
            .get("Message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("Computers for CORP.LOCAL [2]"),
        "message should contain target and count"
    );
    assert!(resp.info.output.contains("WS01"));
    assert!(resp.info.output.contains("WS02"));
    Ok(())
}

#[tokio::test]
async fn net_dclist_broadcasts_dc_list() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonNetCommand::DcList));
    add_utf16(&mut payload, "CORP.LOCAL");
    add_utf16(&mut payload, "DC01.corp.local");

    let result =
        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 58, &payload).await?;
    assert!(result.is_none(), "DcList subcommand should return None");

    let msg = timeout(Duration::from_millis(200), receiver.recv())
        .await
        .expect("should receive event")
        .expect("should have message");
    let OperatorMessage::AgentResponse(resp) = msg else {
        panic!("expected AgentResponse");
    };
    assert!(
        resp.info
            .extra
            .get("Message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("Domain controllers for CORP.LOCAL [1]"),
        "message should contain target and count"
    );
    assert!(resp.info.output.contains("DC01.corp.local"));
    Ok(())
}
