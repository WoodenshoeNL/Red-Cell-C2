mod common;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

/// Sending command output containing a credential pattern (keyword-block style)
/// must create a loot record with kind="credential" in the database and broadcast
/// both a loot-new event and a CredentialsAdd event to the operator WebSocket.
#[tokio::test]
async fn command_output_credential_pattern_creates_loot_record()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cred-extract", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cred-extract").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00D0_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71,
        0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
        0x81, 0x82,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB2, 0xC5, 0xD8, 0xEB, 0xFE, 0x11, 0x24, 0x37, 0x4A, 0x5D, 0x70, 0x83, 0x96, 0xA9, 0xBC,
        0xCF,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Mimikatz-style credential output with keyword-block lines.
    let output_text = "Username : admin\nPassword : P@ssw0rd!";
    let payload = common::command_output_payload(output_text);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First event: AgentResponse with the output text.
    let event1 = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(resp_msg) = event1 else {
        panic!("expected AgentResponse for CommandOutput, got {event1:?}");
    };
    assert_eq!(resp_msg.info.demon_id, format!("{agent_id:08X}"));
    assert!(resp_msg.info.output.contains(output_text));

    // Second event: loot-new for the credential record.
    let event2 = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(loot_msg) = event2 else {
        panic!("expected AgentResponse (loot-new), got {event2:?}");
    };
    assert_eq!(
        loot_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("loot-new"),
        "loot event must have MiscType=loot-new"
    );

    // Third event: CredentialsAdd with the extracted credential details.
    let event3 = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::CredentialsAdd(cred_msg) = event3 else {
        panic!("expected CredentialsAdd event, got {event3:?}");
    };
    assert_eq!(
        cred_msg.info.fields.get("DemonID").and_then(|v| v.as_str()),
        Some(&format!("{agent_id:08X}") as &str),
    );
    let credential_content = cred_msg
        .info
        .fields
        .get("Credential")
        .and_then(|v| v.as_str())
        .expect("CredentialsAdd must contain a Credential field");
    assert!(
        credential_content.contains("Username") && credential_content.contains("Password"),
        "credential content should contain the keyword block: {credential_content:?}"
    );

    // Database must contain a loot record with kind="credential".
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert!(!loot_records.is_empty(), "at least one loot record must be persisted");
    assert!(
        loot_records.iter().any(|r| r.kind == "credential"),
        "expected a 'credential' loot record; got kinds: {:?}",
        loot_records.iter().map(|r| &r.kind).collect::<Vec<_>>()
    );
    let cred_record = loot_records.iter().find(|r| r.kind == "credential").expect("unwrap");
    assert_eq!(cred_record.agent_id, agent_id);
    let data_str = std::str::from_utf8(cred_record.data.as_deref().unwrap_or_default())
        .unwrap_or("<invalid utf8>");
    assert!(
        data_str.contains("Username") && data_str.contains("Password"),
        "loot data should contain the credential block: {data_str:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cred-extract").await?;
    Ok(())
}

/// Sending command output containing a pwdump-format hash must create a loot
/// record with pattern="pwdump-hash".
#[tokio::test]
async fn command_output_pwdump_hash_creates_loot_record() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cred-pwdump", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cred-pwdump").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00D1_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
        0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
        0xA6, 0xA7,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59, 0x6C, 0x7F, 0x92, 0xA5, 0xB8, 0xCB, 0xDE, 0xF1,
        0x04,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // pwdump-format NTLM hash line.
    let hash_line =
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::";
    let payload = common::command_output_payload(hash_line);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD1,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First event: AgentResponse with the output.
    let event1 = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(event1, OperatorMessage::AgentResponse(_)),
        "expected AgentResponse, got {event1:?}"
    );

    // Second event: loot-new.
    let event2 = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(loot_msg) = event2 else {
        panic!("expected AgentResponse (loot-new), got {event2:?}");
    };
    assert_eq!(loot_msg.info.extra.get("MiscType").and_then(|v| v.as_str()), Some("loot-new"),);

    // Third event: CredentialsAdd.
    let event3 = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(event3, OperatorMessage::CredentialsAdd(_)),
        "expected CredentialsAdd, got {event3:?}"
    );

    // Database loot record must exist with the hash data.
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert!(
        loot_records.iter().any(|r| r.kind == "credential"),
        "expected a 'credential' loot record; got: {loot_records:?}"
    );
    let cred_record = loot_records.iter().find(|r| r.kind == "credential").expect("unwrap");
    let data_str = std::str::from_utf8(cred_record.data.as_deref().unwrap_or_default())
        .unwrap_or("<invalid utf8>");
    assert!(
        data_str.contains("Administrator") && data_str.contains("aad3b435b51404ee"),
        "loot data should contain the pwdump hash: {data_str:?}"
    );
    // Verify metadata contains pattern=pwdump-hash.
    let metadata = cred_record.metadata.as_ref().expect("loot metadata must be present");
    assert_eq!(
        metadata.get("pattern").and_then(|v| v.as_str()),
        Some("pwdump-hash"),
        "loot metadata pattern should be 'pwdump-hash'"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cred-pwdump").await?;
    Ok(())
}

/// Non-credential command output (plain text with no credential patterns) must
/// NOT create any loot records — verifies no false-positive extraction.
#[tokio::test]
async fn command_output_no_credentials_creates_no_loot() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cred-none", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cred-none").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00D2_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
        0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
        0xCB, 0xCC,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1C, 0x2F, 0x42, 0x55, 0x68, 0x7B, 0x8E, 0xA1, 0xB4, 0xC7, 0xDA, 0xED, 0x00, 0x13, 0x26,
        0x39,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Plain text output with no credential patterns.
    let output_text = "Directory of C:\\Users\\operator\\Desktop\n\n2026-03-19  10:30    <DIR>          .\n2026-03-19  10:30    <DIR>          ..\n               0 File(s)              0 bytes";
    let payload = common::command_output_payload(output_text);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD2,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // Must receive the AgentResponse for the output text.
    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(resp_msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert!(resp_msg.info.output.contains("Directory of"));

    // No further events should arrive (no loot-new, no CredentialsAdd).
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(300)).await;

    // Database must have zero loot records for this agent.
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert!(
        loot_records.is_empty(),
        "non-credential output must not create loot records; got: {loot_records:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cred-none").await?;
    Ok(())
}
