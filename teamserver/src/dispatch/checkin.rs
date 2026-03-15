use red_cell_common::crypto::{is_weak_aes_iv, is_weak_aes_key};
use red_cell_common::demon::DemonCommand;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;
use zeroize::Zeroizing;

use crate::agent_events::agent_mark_event;
use crate::{AgentRegistry, audit_details, parameter_object, record_operator_action};
use crate::{AuditResultStatus, Database, EventBus, PluginRuntime, TeamserverError};

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
    if let Err(error) = record_operator_action(
        database,
        "teamserver",
        "agent.checkin",
        "agent",
        Some(format!("{agent_id:08X}")),
        audit_details(
            AuditResultStatus::Success,
            Some(agent_id),
            Some("checkin"),
            Some(parameter_object([(
                "external_ip",
                serde_json::Value::String(agent.external_ip.clone()),
            )])),
        ),
    )
    .await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to persist agent.checkin audit entry");
    }
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
    updated.process_arch = checkin_process_arch_label(process_arch).to_owned();
    updated.elevated = elevated;
    updated.os_version = checkin_windows_version_label(
        os_major,
        os_minor,
        os_product_type,
        os_service_pack,
        os_build,
    );
    updated.os_build = os_build;
    updated.os_arch = checkin_windows_arch_label(os_arch).to_owned();
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

pub(super) fn checkin_process_arch_label(value: u32) -> &'static str {
    match value {
        2 => "x64",
        1 => "x86",
        3 => "IA64",
        _ => "Unknown",
    }
}

pub(super) fn checkin_windows_arch_label(value: u32) -> &'static str {
    match value {
        0 => "x86",
        9 => "x64/AMD64",
        5 => "ARM",
        12 => "ARM64",
        6 => "Itanium-based",
        _ => "Unknown",
    }
}

pub(super) fn checkin_windows_version_label(
    major: u32,
    minor: u32,
    product_type: u32,
    service_pack: u32,
    build: u32,
) -> String {
    const VER_NT_WORKSTATION: u32 = 1;

    let mut version =
        if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION && build == 20_348 {
            "Windows 2022 Server 22H2".to_owned()
        } else if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION && build == 17_763
        {
            "Windows 2019 Server".to_owned()
        } else if major == 10
            && minor == 0
            && product_type == VER_NT_WORKSTATION
            && (22_000..=22_621).contains(&build)
        {
            "Windows 11".to_owned()
        } else if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION {
            "Windows 2016 Server".to_owned()
        } else if major == 10 && minor == 0 && product_type == VER_NT_WORKSTATION {
            "Windows 10".to_owned()
        } else if major == 6 && minor == 3 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2012 R2".to_owned()
        } else if major == 6 && minor == 3 && product_type == VER_NT_WORKSTATION {
            "Windows 8.1".to_owned()
        } else if major == 6 && minor == 2 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2012".to_owned()
        } else if major == 6 && minor == 2 && product_type == VER_NT_WORKSTATION {
            "Windows 8".to_owned()
        } else if major == 6 && minor == 1 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2008 R2".to_owned()
        } else if major == 6 && minor == 1 && product_type == VER_NT_WORKSTATION {
            "Windows 7".to_owned()
        } else {
            "Unknown".to_owned()
        };

    if service_pack != 0 {
        version.push_str(" Service Pack ");
        version.push_str(&service_pack.to_string());
    }

    version
}

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_owned()
}
