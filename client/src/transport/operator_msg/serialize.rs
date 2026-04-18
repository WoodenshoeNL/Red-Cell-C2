use std::collections::BTreeMap;

use base64::Engine;
use red_cell_common::operator::{AgentResponseInfo, FlatInfo, ListenerInfo};
use tracing::warn;

use super::super::event_bus::{
    AgentSummary, DownloadProgress, FileBrowserEntry, ListenerSummary, LootItem, LootKind,
    MAX_LOOT_AGENT_ID_CHARS, MAX_LOOT_NAME_CHARS, MAX_LOOT_PATH_CHARS, MAX_LOOT_PREVIEW_CHARS,
    MAX_LOOT_SOURCE_CHARS, MAX_LOOT_TIMESTAMP_CHARS, ProcessEntry,
};
use super::types::{FileBrowserSnapshot, FileBrowserSnapshotPayload};

pub(super) fn listener_summary_from_info(info: &ListenerInfo) -> ListenerSummary {
    ListenerSummary {
        name: info.name.clone().unwrap_or_else(|| "unnamed".to_owned()),
        protocol: info.protocol.clone().unwrap_or_else(|| "unknown".to_owned()),
        host: info.host_bind.clone().unwrap_or_default(),
        port_bind: info.port_bind.clone().unwrap_or_default(),
        port_conn: info.port_conn.clone().unwrap_or_default(),
        status: info.status.clone().unwrap_or_else(|| "Unknown".to_owned()),
    }
}

pub(super) fn agent_summary_from_message(
    info: &red_cell_common::operator::AgentInfo,
) -> AgentSummary {
    let pivot_parent = info
        .pivots
        .parent
        .as_deref()
        .filter(|parent| !parent.trim().is_empty())
        .or_else(|| (!info.pivot_parent.trim().is_empty()).then_some(info.pivot_parent.as_str()))
        .map(normalize_agent_id);
    let pivot_links = info
        .pivots
        .links
        .iter()
        .filter(|link| !link.trim().is_empty())
        .map(|link| normalize_agent_id(link))
        .collect();

    AgentSummary {
        name_id: normalize_agent_id(&info.name_id),
        status: if info.active.eq_ignore_ascii_case("true") {
            "Alive".to_owned()
        } else {
            info.active.clone()
        },
        domain_name: info.domain_name.clone(),
        username: info.username.clone(),
        internal_ip: info.internal_ip.clone(),
        external_ip: info.external_ip.clone(),
        hostname: info.hostname.clone(),
        process_arch: info.process_arch.clone(),
        process_name: info.process_name.clone(),
        process_pid: info.process_pid.clone(),
        elevated: info.elevated,
        os_version: info.os_version.clone(),
        os_build: info.os_build.clone(),
        os_arch: info.os_arch.clone(),
        sleep_delay: info.sleep_delay.to_string(),
        sleep_jitter: info.sleep_jitter.to_string(),
        last_call_in: info.last_call_in.clone(),
        note: info.note.clone(),
        pivot_parent,
        pivot_links,
    }
}

pub(crate) fn normalize_agent_id(agent_id: &str) -> String {
    let trimmed = agent_id.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    if let Ok(value) = u32::from_str_radix(without_prefix, 16) {
        return format!("{value:08X}");
    }

    trimmed.to_ascii_uppercase()
}

pub(crate) fn flat_info_string(info: &FlatInfo, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        info.fields.get(*key).and_then(|value| match value {
            serde_json::Value::String(string) => Some(string.clone()),
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
    })
}

pub(crate) fn sanitize_text(message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.is_empty() { "Connected".to_owned() } else { trimmed.to_owned() }
}

pub(super) fn sanitize_output(output: &str) -> String {
    output.trim().to_owned()
}

pub(super) fn response_is_loot_notification(info: &AgentResponseInfo) -> bool {
    matches!(
        info.extra.get("MiscType"),
        Some(serde_json::Value::String(kind)) if kind == "loot-new"
    )
}

pub(super) fn extra_string(
    extra: &BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    extra.get(key).and_then(|value| match value {
        serde_json::Value::String(string) => Some(string.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    })
}

fn extra_u64(extra: &BTreeMap<String, serde_json::Value>, key: &str) -> Option<u64> {
    extra.get(key).and_then(|value| match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(string) => string.parse::<u64>().ok(),
        _ => None,
    })
}

fn extra_i64(extra: &BTreeMap<String, serde_json::Value>, key: &str) -> Option<i64> {
    extra.get(key).and_then(|value| match value {
        serde_json::Value::Number(number) => number.as_i64(),
        serde_json::Value::String(string) => string.parse::<i64>().ok(),
        _ => None,
    })
}

fn flat_info_u64(info: &FlatInfo, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        info.fields.get(*key).and_then(|value| match value {
            serde_json::Value::Number(number) => number.as_u64(),
            serde_json::Value::String(string) => string.parse::<u64>().ok(),
            _ => None,
        })
    })
}

fn flat_info_i64(info: &FlatInfo, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| {
        info.fields.get(*key).and_then(|value| match value {
            serde_json::Value::Number(number) => number.as_i64(),
            serde_json::Value::String(string) => string.parse::<i64>().ok(),
            _ => None,
        })
    })
}

pub(crate) fn loot_item_from_response(info: &AgentResponseInfo) -> Option<LootItem> {
    let normalized_agent_id = normalize_agent_id(&info.demon_id);
    let trusted_agent_id = sanitize_loot_required_field(
        normalized_agent_id.as_str(),
        "agent_id",
        normalized_agent_id.clone(),
        MAX_LOOT_AGENT_ID_CHARS,
    )?;
    let name = sanitize_loot_required_field(
        trusted_agent_id.as_str(),
        "name",
        extra_string(&info.extra, "LootName")?,
        MAX_LOOT_NAME_CHARS,
    )?;
    let source = extra_string(&info.extra, "LootKind")
        .or_else(|| extra_string(&info.extra, "Operator"))
        .and_then(|value| {
            sanitize_loot_optional_field(
                trusted_agent_id.as_str(),
                "source",
                value,
                MAX_LOOT_SOURCE_CHARS,
            )
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let collected_at = extra_string(&info.extra, "CapturedAt")
        .and_then(|value| {
            sanitize_loot_optional_field(
                trusted_agent_id.as_str(),
                "collected_at",
                value,
                MAX_LOOT_TIMESTAMP_CHARS,
            )
        })
        .unwrap_or_default();
    let file_path = extra_string(&info.extra, "FilePath").and_then(|value| {
        sanitize_loot_optional_field(
            trusted_agent_id.as_str(),
            "file_path",
            value,
            MAX_LOOT_PATH_CHARS,
        )
    });
    let preview = extra_string(&info.extra, "Preview")
        .or_else(|| extra_string(&info.extra, "Message"))
        .and_then(|value| {
            sanitize_loot_optional_field(
                trusted_agent_id.as_str(),
                "preview",
                value,
                MAX_LOOT_PREVIEW_CHARS,
            )
        });
    let kind = loot_kind_from_strings(
        extra_string(&info.extra, "LootKind").as_deref(),
        Some(name.as_str()),
        file_path.as_deref(),
    );

    Some(LootItem {
        id: extra_i64(&info.extra, "LootID"),
        kind,
        name,
        agent_id: trusted_agent_id,
        source,
        collected_at,
        file_path,
        size_bytes: extra_u64(&info.extra, "SizeBytes"),
        content_base64: extra_string(&info.extra, "ContentBase64")
            .or_else(|| extra_string(&info.extra, "Data")),
        preview,
    })
}

pub(crate) fn loot_item_from_flat_info(
    info: &FlatInfo,
    fallback_kind: LootKind,
) -> Option<LootItem> {
    let agent_id = flat_info_string(info, &["DemonID", "AgentID"])
        .as_deref()
        .map(normalize_agent_id)
        .and_then(|value| {
            sanitize_loot_optional_field("unknown", "agent_id", value, MAX_LOOT_AGENT_ID_CHARS)
        })
        .unwrap_or_default();
    let name = sanitize_loot_required_field(
        agent_id.as_str(),
        "name",
        flat_info_string(info, &["Name", "FileName", "LootName"])?,
        MAX_LOOT_NAME_CHARS,
    )?;
    let file_path = flat_info_string(info, &["FilePath", "Path"]).and_then(|value| {
        sanitize_loot_optional_field(agent_id.as_str(), "file_path", value, MAX_LOOT_PATH_CHARS)
    });
    let source = flat_info_string(info, &["Operator", "Pattern", "Kind", "Type"])
        .and_then(|value| {
            sanitize_loot_optional_field(agent_id.as_str(), "source", value, MAX_LOOT_SOURCE_CHARS)
        })
        .unwrap_or_else(|| fallback_kind.label().to_ascii_lowercase());
    let collected_at = flat_info_string(info, &["CapturedAt", "Time", "Timestamp"])
        .and_then(|value| {
            sanitize_loot_optional_field(
                agent_id.as_str(),
                "collected_at",
                value,
                MAX_LOOT_TIMESTAMP_CHARS,
            )
        })
        .unwrap_or_default();
    let preview = flat_info_string(info, &["Credential", "Preview", "Message"]).and_then(|value| {
        sanitize_loot_optional_field(agent_id.as_str(), "preview", value, MAX_LOOT_PREVIEW_CHARS)
    });
    let kind = loot_kind_from_strings(
        flat_info_string(info, &["Kind", "Type", "LootKind"]).as_deref(),
        Some(name.as_str()),
        file_path.as_deref(),
    );

    Some(LootItem {
        id: flat_info_i64(info, &["LootID", "ID"]),
        kind: if matches!(kind, LootKind::Other) { fallback_kind } else { kind },
        name,
        agent_id,
        source,
        collected_at,
        file_path,
        size_bytes: flat_info_u64(info, &["SizeBytes", "Size"]),
        content_base64: flat_info_string(info, &["ContentBase64", "Data", "Payload"]),
        preview,
    })
}

pub(super) fn loot_kind_from_strings(
    kind: Option<&str>,
    name: Option<&str>,
    file_path: Option<&str>,
) -> LootKind {
    let mut haystacks = Vec::new();
    if let Some(kind) = kind {
        haystacks.push(kind.to_ascii_lowercase());
    }
    if let Some(name) = name {
        haystacks.push(name.to_ascii_lowercase());
    }
    if let Some(path) = file_path {
        haystacks.push(path.to_ascii_lowercase());
    }

    if haystacks.iter().any(|value| value.contains("credential") || value.contains("password")) {
        LootKind::Credential
    } else if haystacks.iter().any(|value| {
        value.contains("screenshot")
            || value.ends_with(".png")
            || value.ends_with(".jpg")
            || value.ends_with(".jpeg")
    }) {
        LootKind::Screenshot
    } else if haystacks.iter().any(|value| {
        value.contains("file")
            || value.contains("download")
            || value.contains('\\')
            || value.contains('/')
    }) {
        LootKind::File
    } else {
        LootKind::Other
    }
}

pub(super) fn process_list_rows_from_response(
    info: &AgentResponseInfo,
) -> Option<Vec<ProcessEntry>> {
    let rows = info.extra.get("ProcessListRows")?.as_array()?;
    Some(
        rows.iter()
            .filter_map(|row| {
                let pid = row.get("PID")?.as_u64()?;
                let ppid = row.get("PPID")?.as_u64()?;
                let session = row.get("Session")?.as_u64()?;
                Some(ProcessEntry {
                    pid: u32::try_from(pid).ok()?,
                    ppid: u32::try_from(ppid).ok()?,
                    name: row.get("Name")?.as_str()?.to_owned(),
                    arch: row.get("Arch")?.as_str()?.to_owned(),
                    user: row.get("User")?.as_str()?.to_owned(),
                    session: u32::try_from(session).ok()?,
                })
            })
            .collect(),
    )
}

pub(super) fn file_browser_snapshot_from_response(
    info: &AgentResponseInfo,
) -> Option<FileBrowserSnapshot> {
    let encoded = extra_string(&info.extra, "MiscData")?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    let payload = serde_json::from_slice::<FileBrowserSnapshotPayload>(&bytes).ok()?;
    let path = payload.path.trim().to_owned();
    if path.is_empty() {
        return None;
    }

    let entries = payload
        .files
        .into_iter()
        .map(|row| {
            let name = row.name.trim().to_owned();
            let path = join_remote_path(&path, &name);
            let size_label = row.size.trim().to_owned();
            FileBrowserEntry {
                name,
                path,
                is_dir: row.entry_type.eq_ignore_ascii_case("dir"),
                size_bytes: parse_human_size(&size_label),
                size_label,
                modified_at: row.modified.trim().to_owned(),
                permissions: row.permissions.trim().to_owned(),
            }
        })
        .collect();

    Some(FileBrowserSnapshot { path, entries })
}

pub(super) fn download_progress_from_response(
    info: &AgentResponseInfo,
) -> Option<DownloadProgress> {
    Some(DownloadProgress {
        file_id: extra_string(&info.extra, "FileID")?,
        remote_path: extra_string(&info.extra, "FileName")?,
        current_size: extra_u64(&info.extra, "CurrentSize")?,
        expected_size: extra_u64(&info.extra, "ExpectedSize")?,
        state: extra_string(&info.extra, "State").unwrap_or_else(|| "InProgress".to_owned()),
    })
}

fn sanitize_loot_required_field(
    agent_id: &str,
    field_name: &'static str,
    value: String,
    max_chars: usize,
) -> Option<String> {
    let sanitized = sanitize_loot_field(agent_id, field_name, value, max_chars);
    if sanitized.is_empty() {
        warn!(
            agent_id = display_agent_id(agent_id),
            loot_field = field_name,
            "dropping loot item with empty required field after sanitization"
        );
        None
    } else {
        Some(sanitized)
    }
}

fn sanitize_loot_optional_field(
    agent_id: &str,
    field_name: &'static str,
    value: String,
    max_chars: usize,
) -> Option<String> {
    let sanitized = sanitize_loot_field(agent_id, field_name, value, max_chars);
    (!sanitized.is_empty()).then_some(sanitized)
}

fn sanitize_loot_field(
    agent_id: &str,
    field_name: &'static str,
    value: String,
    max_chars: usize,
) -> String {
    let original_char_count = value.chars().count();
    let had_control_chars = value.chars().any(char::is_control);
    let cleaned = value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_owned();
    let cleaned_char_count = cleaned.chars().count();
    let truncated = cleaned_char_count > max_chars;
    let sanitized =
        if truncated { cleaned.chars().take(max_chars).collect::<String>() } else { cleaned };

    if had_control_chars || original_char_count > max_chars {
        warn!(
            agent_id = display_agent_id(agent_id),
            loot_field = field_name,
            original_chars = original_char_count,
            sanitized_chars = sanitized.chars().count(),
            had_control_chars,
            truncated,
            "sanitized suspicious loot field"
        );
    }

    sanitized
}

fn display_agent_id(agent_id: &str) -> &str {
    if agent_id.is_empty() { "unknown" } else { agent_id }
}

fn join_remote_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        return name.to_owned();
    }
    if name.is_empty() {
        return base.to_owned();
    }

    let separator = if base.contains('\\') { '\\' } else { '/' };
    if base.ends_with(['\\', '/']) {
        format!("{base}{name}")
    } else {
        format!("{base}{separator}{name}")
    }
}

fn parse_human_size(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let number = parts.next()?.parse::<f64>().ok()?;
    let unit = parts.next().unwrap_or("B").to_ascii_uppercase();
    let multiplier = match unit.as_str() {
        "B" => 1_f64,
        "KB" => 1024_f64,
        "MB" => 1024_f64 * 1024_f64,
        "GB" => 1024_f64 * 1024_f64 * 1024_f64,
        _ => return None,
    };

    Some((number * multiplier).round() as u64)
}
