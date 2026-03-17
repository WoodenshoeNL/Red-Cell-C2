use red_cell_common::crypto::{is_weak_aes_iv, is_weak_aes_key};
use red_cell_common::demon::DemonCommand;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;
use zeroize::Zeroizing;

use crate::agent_events::agent_mark_event;
use crate::{AgentRegistry, audit_details, parameter_object, record_operator_action};
use crate::{AuditResultStatus, Database, EventBus, PluginRuntime, TeamserverError};

use super::util::{basename, process_arch_label, windows_arch_label, windows_version_label};
use super::{CallbackParser, CommandDispatchError};

pub(super) async fn handle_checkin(
    registry: &AgentRegistry,
    events: &EventBus,
    database: &Database,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let existing =
        registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
    let agent = if let Some(mut updated) =
        parse_checkin_metadata(existing.clone(), agent_id, payload, &timestamp)?
    {
        let key_rotation = updated.encryption != existing.encryption;

        if key_rotation {
            // SECURITY: The Demon binary protocol includes no nonce, timestamp, or
            // challenge-response in the COMMAND_CHECKIN payload, so the teamserver cannot
            // distinguish a fresh rotation from a replayed packet carrying a known key.  An
            // adversary who captures a CHECKIN frame can replay it to push the session key to a
            // value they control and then decrypt subsequent traffic or inject spoofed commands.
            //
            // To close the replay window entirely, key rotation is refused for all agents
            // regardless of whether they are direct or pivot-relayed.  Agents that genuinely need
            // new key material must go through a full DEMON_INIT re-registration, which is
            // protected by the mutual-auth handshake.
            let pivot_parent = registry.parent_of(agent_id).await.map(|p| format!("{p:08X}"));
            warn!(
                agent_id = format_args!("{agent_id:08X}"),
                pivot_parent,
                "refused AES session key rotation from CHECKIN payload — \
                 no replay/freshness guarantee in the Demon protocol; \
                 re-init required for legitimate key rotation"
            );
            updated.encryption = existing.encryption.clone();
        }

        registry.update_agent(updated).await?;
        registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?
    } else {
        registry.set_last_call_in(agent_id, timestamp).await?
    };
    events.broadcast(agent_mark_event(&agent));
    // Spawn the audit write as a background task so the DB write does not
    // delay the checkin response back to the agent.  At scale (many agents
    // checking in concurrently) SQLite serialises writes; keeping this off
    // the hot path prevents the audit write from becoming a throughput
    // bottleneck.  Mirrors the same pattern used for agent.dead in
    // agent_liveness.rs.
    let db = database.clone();
    let external_ip = agent.external_ip.clone();
    tokio::spawn(async move {
        if let Err(error) = record_operator_action(
            &db,
            "teamserver",
            "agent.checkin",
            "agent",
            Some(format!("{agent_id:08X}")),
            audit_details(
                AuditResultStatus::Success,
                Some(agent_id),
                Some("checkin"),
                Some(parameter_object([("external_ip", serde_json::Value::String(external_ip))])),
            ),
        )
        .await
        {
            warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to persist agent.checkin audit entry");
        }
    });
    if let Some(plugins) = plugins
        && let Err(error) = plugins.emit_agent_checkin(agent_id).await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python agent_checkin event");
    }
    Ok(None)
}

fn parse_checkin_metadata(
    existing: red_cell_common::AgentRecord,
    agent_id: u32,
    payload: &[u8],
    timestamp: &str,
) -> Result<Option<red_cell_common::AgentRecord>, CommandDispatchError> {
    const CHECKIN_METADATA_PREFIX_LEN: usize = 32 + 16;

    if payload.is_empty() {
        return Ok(None);
    }
    if payload.len() < CHECKIN_METADATA_PREFIX_LEN {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandCheckin),
            message: format!(
                "truncated CHECKIN payload: {} byte(s) is too short for the \
                 {CHECKIN_METADATA_PREFIX_LEN}-byte metadata prefix",
                payload.len()
            ),
        });
    }

    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandCheckin));
    let aes_key = parser.read_fixed_bytes(32, "checkin AES key")?;
    let aes_iv = parser.read_fixed_bytes(16, "checkin AES IV")?;
    let parsed_agent_id = parser.read_u32("checkin agent id")?;

    validate_checkin_transport_material(agent_id, &aes_key, &aes_iv)?;

    if parsed_agent_id != agent_id {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandCheckin),
            message: format!(
                "checkin agent id mismatch: expected 0x{agent_id:08X}, got 0x{parsed_agent_id:08X}"
            ),
        });
    }

    let hostname = parser.read_string("checkin hostname")?;
    let username = parser.read_string("checkin username")?;
    let domain_name = parser.read_string("checkin domain name")?;
    let internal_ip = parser.read_string("checkin internal ip")?;
    let process_path = parser.read_utf16("checkin process path")?;
    let process_pid = parser.read_u32("checkin process pid")?;
    let process_tid = parser.read_u32("checkin process tid")?;
    let process_ppid = parser.read_u32("checkin process ppid")?;
    let process_arch = parser.read_u32("checkin process arch")?;
    let elevated = parser.read_bool("checkin elevated")?;
    let base_address = parser.read_u64("checkin base address")?;
    let os_major = parser.read_u32("checkin os major")?;
    let os_minor = parser.read_u32("checkin os minor")?;
    let os_product_type = parser.read_u32("checkin os product type")?;
    let os_service_pack = parser.read_u32("checkin os service pack")?;
    let os_build = parser.read_u32("checkin os build")?;
    let os_arch = parser.read_u32("checkin os arch")?;
    let sleep_delay = parser.read_u32("checkin sleep delay")?;
    let sleep_jitter = parser.read_u32("checkin sleep jitter")?;
    let kill_date = parser.read_u64("checkin kill date")?;
    let working_hours = parser.read_u32("checkin working hours")?;

    let mut updated = existing;
    updated.active = true;
    updated.reason.clear();
    updated.encryption.aes_key = Zeroizing::new(aes_key);
    updated.encryption.aes_iv = Zeroizing::new(aes_iv);
    updated.hostname = hostname;
    updated.username = username;
    updated.domain_name = domain_name;
    updated.internal_ip = internal_ip;
    updated.process_name = basename(&process_path);
    updated.process_path = process_path;
    updated.base_address = base_address;
    updated.process_pid = process_pid;
    updated.process_tid = process_tid;
    updated.process_ppid = process_ppid;
    updated.process_arch = process_arch_label(process_arch).to_owned();
    updated.elevated = elevated;
    updated.os_version =
        windows_version_label(os_major, os_minor, os_product_type, os_service_pack, os_build);
    updated.os_build = os_build;
    updated.os_arch = windows_arch_label(os_arch).to_owned();
    updated.sleep_delay = sleep_delay;
    updated.sleep_jitter = sleep_jitter;
    updated.kill_date = super::parse_optional_kill_date(
        kill_date,
        u32::from(DemonCommand::CommandCheckin),
        "checkin kill date",
    )?;
    updated.working_hours = decode_working_hours(working_hours);
    updated.last_call_in = timestamp.to_owned();

    Ok(Some(updated))
}

fn validate_checkin_transport_material(
    agent_id: u32,
    aes_key: &[u8],
    aes_iv: &[u8],
) -> Result<(), CommandDispatchError> {
    if is_weak_aes_key(aes_key) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting COMMAND_CHECKIN with all-zero AES key"
        );
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandCheckin),
            message: "all-zero AES key is not allowed".to_owned(),
        });
    }

    if is_weak_aes_iv(aes_iv) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting COMMAND_CHECKIN with all-zero AES IV"
        );
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandCheckin),
            message: "all-zero AES IV is not allowed".to_owned(),
        });
    }

    Ok(())
}

pub(super) fn decode_working_hours(raw: u32) -> Option<i32> {
    // Preserve the 32-bit protocol bitmask exactly, including the high bit.
    (raw != 0).then_some(i32::from_be_bytes(raw.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
    use zeroize::Zeroizing;

    use super::*;
    use crate::{AgentRegistry, Database, EventBus};

    #[test]
    fn decode_working_hours_zero_returns_none() {
        assert_eq!(decode_working_hours(0u32), None);
    }

    #[test]
    fn decode_working_hours_nonzero_returns_some() {
        assert_eq!(decode_working_hours(0b101010u32), Some(42i32));
    }

    #[test]
    fn decode_working_hours_high_bit_set_preserves_sign() {
        // 0x8000_0000 as u32 → i32::MIN when reinterpreted via big-endian bytes.
        assert_eq!(decode_working_hours(0x8000_0000u32), Some(i32::MIN));
    }

    // -- helpers for building checkin payloads --

    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_bytes(buf: &mut Vec<u8>, value: &[u8]) {
        push_u32(buf, u32::try_from(value.len()).unwrap_or_default());
        buf.extend_from_slice(value);
    }

    fn push_checkin_string(buf: &mut Vec<u8>, value: &str) {
        push_bytes(buf, value.as_bytes());
    }

    fn push_checkin_utf16(buf: &mut Vec<u8>, value: &str) {
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.extend_from_slice(&[0, 0]);
        push_bytes(buf, &encoded);
    }

    fn make_checkin_payload(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&key);
        buf.extend_from_slice(&iv);
        push_u32(&mut buf, agent_id);
        push_checkin_string(&mut buf, "wkstn-02");
        push_checkin_string(&mut buf, "svc-op");
        push_checkin_string(&mut buf, "research");
        push_checkin_string(&mut buf, "10.10.10.50");
        push_checkin_utf16(&mut buf, "C:\\Windows\\System32\\cmd.exe");
        push_u32(&mut buf, 4040); // pid
        push_u32(&mut buf, 5050); // tid
        push_u32(&mut buf, 3030); // ppid
        push_u32(&mut buf, 1); // arch
        push_u32(&mut buf, 0); // elevated
        push_u64(&mut buf, 0x401000); // base_address
        push_u32(&mut buf, 10); // os_major
        push_u32(&mut buf, 0); // os_minor
        push_u32(&mut buf, 1); // os_product_type
        push_u32(&mut buf, 0); // os_service_pack
        push_u32(&mut buf, 22_621); // os_build
        push_u32(&mut buf, 9); // os_arch
        push_u32(&mut buf, 45); // sleep_delay
        push_u32(&mut buf, 5); // sleep_jitter
        push_u64(&mut buf, 1_725_000_000); // kill_date
        push_u32(&mut buf, 0x00FF_00FF); // working_hours
        buf
    }

    fn sample_agent(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> red_cell_common::AgentRecord {
        red_cell_common::AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: Zeroizing::new(key.to_vec()),
                aes_iv: Zeroizing::new(iv.to_vec()),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "lab".to_owned(),
            external_ip: "127.0.0.1".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            base_address: 0x1000,
            process_pid: 1337,
            process_tid: 7331,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 10,
            sleep_jitter: 25,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-09T20:00:00Z".to_owned(),
            last_call_in: "2026-03-09T20:00:00Z".to_owned(),
        }
    }

    /// Verify that `handle_checkin` preserves the original AES session key when
    /// the CHECKIN payload carries different key/IV material (replay-attack
    /// defence).  This is the security property guarded by lines 29–51.
    #[tokio::test]
    async fn handle_checkin_rejects_key_rotation_and_preserves_original_session_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let original_key = [0xAA; AGENT_KEY_LENGTH];
        let original_iv = [0xBB; AGENT_IV_LENGTH];
        let attacker_key = [0xCC; AGENT_KEY_LENGTH];
        let attacker_iv = [0xDD; AGENT_IV_LENGTH];
        let agent_id = 0xDEAD_0001;

        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();

        registry.insert(sample_agent(agent_id, original_key, original_iv)).await?;

        // Build a CHECKIN payload with attacker-controlled key material.
        let payload = make_checkin_payload(agent_id, attacker_key, attacker_iv);

        handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

        // The agent's stored encryption must be the original, not the attacker's.
        let agent = registry.get(agent_id).await.ok_or("agent should still be registered")?;

        assert_eq!(
            agent.encryption.aes_key.as_slice(),
            original_key.as_slice(),
            "AES key must not be overwritten by CHECKIN payload"
        );
        assert_eq!(
            agent.encryption.aes_iv.as_slice(),
            original_iv.as_slice(),
            "AES IV must not be overwritten by CHECKIN payload"
        );

        Ok(())
    }

    /// When the CHECKIN payload carries the *same* key/IV as already registered,
    /// no rotation is detected and the metadata update proceeds normally.
    #[tokio::test]
    async fn handle_checkin_accepts_same_key_without_triggering_rotation_guard()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = [0xAA; AGENT_KEY_LENGTH];
        let iv = [0xBB; AGENT_IV_LENGTH];
        let agent_id = 0xDEAD_0002;

        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();

        registry.insert(sample_agent(agent_id, key, iv)).await?;

        // CHECKIN with the same key — should update metadata without warnings.
        let payload = make_checkin_payload(agent_id, key, iv);
        handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

        let agent = registry.get(agent_id).await.ok_or("agent should still be registered")?;

        assert_eq!(agent.encryption.aes_key.as_slice(), key.as_slice());
        assert_eq!(agent.encryption.aes_iv.as_slice(), iv.as_slice());
        // Metadata should have been updated from the payload.
        assert_eq!(agent.hostname, "wkstn-02");
        assert_eq!(agent.username, "svc-op");

        Ok(())
    }

    /// A payload shorter than the 48-byte metadata prefix must be rejected
    /// with `InvalidCallbackPayload`.  This guards against truncated or
    /// malformed CHECKIN frames reaching the parser.
    #[test]
    fn parse_checkin_metadata_rejects_truncated_payload() {
        let key = [0xAA; AGENT_KEY_LENGTH];
        let iv = [0xBB; AGENT_IV_LENGTH];
        let agent_id = 0xDEAD_0003;
        let existing = sample_agent(agent_id, key, iv);

        // 47 bytes — one byte short of the 48-byte minimum.
        let truncated = vec![0x42u8; 47];
        let result = parse_checkin_metadata(existing, agent_id, &truncated, "2026-03-17T00:00:00Z");

        let err = result.expect_err("truncated payload must be rejected");
        match &err {
            CommandDispatchError::InvalidCallbackPayload { command_id, message } => {
                assert_eq!(
                    *command_id,
                    u32::from(DemonCommand::CommandCheckin),
                    "error must reference CommandCheckin"
                );
                assert!(
                    message.contains("truncated"),
                    "error message should mention truncation, got: {message}"
                );
                assert!(
                    message.contains("47"),
                    "error message should include actual payload length, got: {message}"
                );
            }
            other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
        }
    }

    /// When the agent ID inside the payload differs from the outer envelope's
    /// agent ID, `parse_checkin_metadata` must return `InvalidCallbackPayload`.
    /// This prevents silent state corruption from misrouted or tampered frames.
    #[test]
    fn parse_checkin_metadata_rejects_agent_id_mismatch() {
        let key = [0xAA; AGENT_KEY_LENGTH];
        let iv = [0xBB; AGENT_IV_LENGTH];
        let envelope_agent_id = 0xDEAD_0004;
        let payload_agent_id = 0xDEAD_FFFF; // different from envelope
        let existing = sample_agent(envelope_agent_id, key, iv);

        let payload = make_checkin_payload(payload_agent_id, key, iv);
        let result =
            parse_checkin_metadata(existing, envelope_agent_id, &payload, "2026-03-17T00:00:00Z");

        let err = result.expect_err("agent ID mismatch must be rejected");
        match &err {
            CommandDispatchError::InvalidCallbackPayload { command_id, message } => {
                assert_eq!(
                    *command_id,
                    u32::from(DemonCommand::CommandCheckin),
                    "error must reference CommandCheckin"
                );
                assert!(
                    message.contains("mismatch"),
                    "error message should mention mismatch, got: {message}"
                );
                assert!(
                    message.contains(&format!("0x{envelope_agent_id:08X}")),
                    "error message should include expected agent ID, got: {message}"
                );
                assert!(
                    message.contains(&format!("0x{payload_agent_id:08X}")),
                    "error message should include actual agent ID, got: {message}"
                );
            }
            other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
        }
    }
}
