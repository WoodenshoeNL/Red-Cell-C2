//! Shared response types and event-builder helpers used across dispatch sub-modules.

use std::collections::BTreeMap;

use red_cell_common::operator::{
    AgentResponseInfo, EventCode, FlatInfo, Message, MessageHead, OperatorMessage,
};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use crate::{AgentRegistry, Database, EventBus, LootRecord, PluginRuntime};

use super::CommandDispatchError;

// ── Shared data types ─────────────────────────────────────────────────────────

/// Context captured from the task queue for enriching loot and response records.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::dispatch) struct LootContext {
    pub(in crate::dispatch) operator: String,
    pub(in crate::dispatch) command_line: String,
    pub(in crate::dispatch) task_id: String,
    pub(in crate::dispatch) queued_at: String,
}

/// A single credential extracted from command output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::dispatch) struct CredentialCapture {
    pub(in crate::dispatch) label: String,
    pub(in crate::dispatch) content: String,
    pub(in crate::dispatch) pattern: &'static str,
}

/// Collects all fields needed to persist and broadcast an agent response record.
#[derive(Clone, Debug)]
pub(in crate::dispatch) struct AgentResponseEntry {
    pub(in crate::dispatch) agent_id: u32,
    pub(in crate::dispatch) command_id: u32,
    pub(in crate::dispatch) request_id: u32,
    pub(in crate::dispatch) kind: String,
    pub(in crate::dispatch) message: String,
    pub(in crate::dispatch) extra: BTreeMap<String, Value>,
    pub(in crate::dispatch) output: String,
}

// ── Loot helpers ──────────────────────────────────────────────────────────────

/// When the in-memory job queue entry was evicted or the callback `request_id`
/// otherwise has no matching [`JobContext`], we still know the numeric request id
/// from the wire.  REST clients submit `TaskID` as the same hex string as this
/// id (`next_task_id`), so synthesizing `{:08X}` preserves `agent exec --wait`
/// and loot correlation.
pub(in crate::dispatch) fn enrich_loot_context_with_request_id(
    context: &LootContext,
    request_id: u32,
) -> LootContext {
    let mut out = context.clone();
    if out.task_id.is_empty() {
        out.task_id = format!("{request_id:08X}");
    }
    out
}

pub(in crate::dispatch) async fn loot_context(
    registry: &AgentRegistry,
    agent_id: u32,
    request_id: u32,
) -> LootContext {
    registry
        .request_context(agent_id, request_id)
        .await
        .map(|context| LootContext {
            operator: context.operator,
            command_line: context.command_line,
            task_id: context.task_id,
            queued_at: context.created_at,
        })
        .unwrap_or_default()
}

pub(in crate::dispatch) async fn insert_loot_record(
    database: &Database,
    loot: LootRecord,
) -> Result<LootRecord, CommandDispatchError> {
    let id = database.loot().create(&loot).await?;
    Ok(LootRecord { id: Some(id), ..loot })
}

pub(in crate::dispatch) async fn persist_agent_response_record(
    database: &Database,
    response: &AgentResponseEntry,
    context: &LootContext,
) -> Result<(), CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let final_extra = agent_response_extra(
        response.extra.clone(),
        response.request_id,
        &response.kind,
        &response.message,
        context,
    );
    database
        .agent_responses()
        .create(&crate::AgentResponseRecord {
            id: None,
            agent_id: response.agent_id,
            command_id: response.command_id,
            request_id: response.request_id,
            response_type: response.kind.clone(),
            message: response.message.clone(),
            output: response.output.clone(),
            command_line: non_empty_option(&context.command_line),
            task_id: non_empty_option(&context.task_id),
            operator: non_empty_option(&context.operator),
            received_at: timestamp,
            extra: Some(Value::Object(final_extra.into_iter().collect())),
        })
        .await?;
    Ok(())
}

pub(in crate::dispatch) async fn broadcast_and_persist_agent_response(
    database: &Database,
    events: &EventBus,
    response: AgentResponseEntry,
    context: &LootContext,
) -> Result<(), CommandDispatchError> {
    let context = enrich_loot_context_with_request_id(context, response.request_id);
    persist_agent_response_record(database, &response, &context).await?;
    events.broadcast(agent_response_event_with_extra_and_context(
        response.agent_id,
        response.command_id,
        response.request_id,
        &response.kind,
        &response.message,
        response.extra,
        response.output,
        Some(&context),
    )?);
    Ok(())
}

pub(in crate::dispatch) fn loot_new_event(
    loot: &LootRecord,
    command_id: u32,
    request_id: u32,
    context: &LootContext,
) -> Result<OperatorMessage, CommandDispatchError> {
    let context = enrich_loot_context_with_request_id(context, request_id);
    let mut extra = BTreeMap::from([
        ("MiscType".to_owned(), Value::String("loot-new".to_owned())),
        ("LootID".to_owned(), Value::String(loot.id.unwrap_or_default().to_string())),
        ("LootKind".to_owned(), Value::String(loot.kind.clone())),
        ("LootName".to_owned(), Value::String(loot.name.clone())),
        ("CapturedAt".to_owned(), Value::String(loot.captured_at.clone())),
    ]);

    if let Some(path) = &loot.file_path {
        extra.insert("FilePath".to_owned(), Value::String(path.clone()));
    }
    if let Some(size_bytes) = loot.size_bytes {
        extra.insert("SizeBytes".to_owned(), Value::String(size_bytes.to_string()));
    }
    if !context.operator.is_empty() {
        extra.insert("Operator".to_owned(), Value::String(context.operator.clone()));
    }
    if !context.command_line.is_empty() {
        extra.insert("CommandLine".to_owned(), Value::String(context.command_line.clone()));
    }
    if !context.task_id.is_empty() {
        extra.insert("TaskID".to_owned(), Value::String(context.task_id.clone()));
    }

    agent_response_event_with_extra(
        loot.agent_id,
        command_id,
        request_id,
        "Info",
        &format!("New loot captured: {} ({})", loot.name, loot.kind),
        extra,
        String::new(),
    )
}

pub(in crate::dispatch) fn metadata_with_context(
    entries: impl IntoIterator<Item = (String, Value)>,
    context: &LootContext,
    request_id: u32,
) -> Value {
    let mut metadata = serde_json::Map::new();
    for (key, value) in entries {
        metadata.insert(key, value);
    }
    if !context.operator.is_empty() {
        metadata.insert("operator".to_owned(), Value::String(context.operator.clone()));
    }
    if !context.command_line.is_empty() {
        metadata.insert("command_line".to_owned(), Value::String(context.command_line.clone()));
    }
    if !context.task_id.is_empty() {
        metadata.insert("task_id".to_owned(), Value::String(context.task_id.clone()));
    } else {
        metadata.insert("task_id".to_owned(), Value::String(format!("{request_id:08X}")));
    }
    if !context.queued_at.is_empty() {
        metadata.insert("queued_at".to_owned(), Value::String(context.queued_at.clone()));
    }
    Value::Object(metadata)
}

pub(in crate::dispatch) fn broadcast_credential_event(
    events: &EventBus,
    agent_id: u32,
    credential: &CredentialCapture,
    context: &LootContext,
    request_id: u32,
) -> Result<(), CommandDispatchError> {
    let context = enrich_loot_context_with_request_id(context, request_id);
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let mut fields = BTreeMap::from([
        ("DemonID".to_owned(), Value::String(format!("{agent_id:08X}"))),
        ("Name".to_owned(), Value::String(credential.label.clone())),
        ("Credential".to_owned(), Value::String(credential.content.clone())),
        ("Pattern".to_owned(), Value::String(credential.pattern.to_owned())),
    ]);

    if !context.operator.is_empty() {
        fields.insert("Operator".to_owned(), Value::String(context.operator.clone()));
    }
    if !context.command_line.is_empty() {
        fields.insert("CommandLine".to_owned(), Value::String(context.command_line.clone()));
    }
    if !context.task_id.is_empty() {
        fields.insert("TaskID".to_owned(), Value::String(context.task_id.clone()));
    }

    events.broadcast(OperatorMessage::CredentialsAdd(Message {
        head: MessageHead {
            event: EventCode::Credentials,
            user: "teamserver".to_owned(),
            timestamp,
            one_time: String::new(),
        },
        info: FlatInfo { fields },
    }));
    Ok(())
}

// ── Credential extraction ─────────────────────────────────────────────────────

pub(in crate::dispatch) fn extract_credentials(output: &str) -> Vec<CredentialCapture> {
    let mut captures = Vec::new();
    let mut current_block = Vec::new();

    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            if !current_block.is_empty() {
                captures.push(CredentialCapture {
                    label: "credential-block".to_owned(),
                    content: current_block.join("\n"),
                    pattern: "keyword-block",
                });
                current_block.clear();
            }
            continue;
        }

        if looks_like_pwdump_hash(line) {
            if !current_block.is_empty() {
                captures.push(CredentialCapture {
                    label: "credential-block".to_owned(),
                    content: current_block.join("\n"),
                    pattern: "keyword-block",
                });
                current_block.clear();
            }
            captures.push(CredentialCapture {
                label: "password-hash".to_owned(),
                content: line.to_owned(),
                pattern: "pwdump-hash",
            });
            continue;
        }

        if looks_like_inline_secret(line) {
            if !current_block.is_empty() {
                captures.push(CredentialCapture {
                    label: "credential-block".to_owned(),
                    content: current_block.join("\n"),
                    pattern: "keyword-block",
                });
                current_block.clear();
            }
            captures.push(CredentialCapture {
                label: "inline-credential".to_owned(),
                content: line.to_owned(),
                pattern: "inline-secret",
            });
            continue;
        }

        if looks_like_credential_line(line) {
            current_block.push(line.to_owned());
            continue;
        }

        if !current_block.is_empty() {
            captures.push(CredentialCapture {
                label: "credential-block".to_owned(),
                content: current_block.join("\n"),
                pattern: "keyword-block",
            });
            current_block.clear();
        }
    }

    if !current_block.is_empty() {
        captures.push(CredentialCapture {
            label: "credential-block".to_owned(),
            content: current_block.join("\n"),
            pattern: "keyword-block",
        });
    }

    let mut deduped = Vec::new();
    for capture in captures {
        if !deduped.iter().any(|existing: &CredentialCapture| existing.content == capture.content) {
            deduped.push(capture);
        }
    }
    deduped
}

pub(in crate::dispatch) fn looks_like_credential_line(line: &str) -> bool {
    let separators = [":", "="];
    separators.iter().any(|separator| {
        line.split_once(separator).is_some_and(|(key, value)| {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();
            !value.is_empty()
                && [
                    "user", "username", "login", "domain", "password", "pass", "secret", "hash",
                    "ntlm", "lm", "ticket", "cred",
                ]
                .iter()
                .any(|keyword| key.contains(keyword))
        })
    })
}

pub(in crate::dispatch) fn looks_like_inline_secret(line: &str) -> bool {
    let bytes = line.as_bytes();
    let looks_like_windows_drive_path = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');

    if line.contains("://")
        || looks_like_windows_drive_path
        || (line.contains('\\') && !line.contains(':'))
    {
        return false;
    }

    line.split_once(':').is_some_and(|(left, right)| {
        let left = left.trim();
        let right = right.trim();
        !left.is_empty()
            && !right.is_empty()
            && !left.contains(' ')
            && !right.contains(' ')
            && (left.contains('\\')
                || left.contains('@')
                || (right.len() >= 8 && !looks_like_credential_line(line)))
    })
}

pub(in crate::dispatch) fn looks_like_pwdump_hash(line: &str) -> bool {
    let parts = line.split(':').collect::<Vec<_>>();
    parts.len() >= 6
        && parts[0].chars().all(|char| char.is_ascii_graphic())
        && parts[2].len() == 32
        && parts[3].len() == 32
        && parts[2].chars().all(|char| char.is_ascii_hexdigit())
        && parts[3].chars().all(|char| char.is_ascii_hexdigit())
}

pub(in crate::dispatch) async fn persist_credentials_from_output(
    database: &Database,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    output: &str,
    context: &LootContext,
) -> Result<(), CommandDispatchError> {
    for (index, credential) in extract_credentials(output).into_iter().enumerate() {
        let captured_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let record = insert_loot_record(
            database,
            LootRecord {
                id: None,
                agent_id,
                kind: "credential".to_owned(),
                name: format!("credential-{request_id:X}-{}", index + 1),
                file_path: None,
                size_bytes: Some(i64::try_from(credential.content.len()).unwrap_or(i64::MAX)),
                captured_at,
                data: Some(credential.content.as_bytes().to_vec()),
                metadata: Some(metadata_with_context(
                    [
                        ("pattern".to_owned(), Value::String(credential.pattern.to_owned())),
                        ("request_id".to_owned(), Value::String(format!("{request_id:X}"))),
                    ],
                    context,
                    request_id,
                )),
            },
        )
        .await?;
        events.broadcast(loot_new_event(&record, command_id, request_id, context)?);
        broadcast_credential_event(events, agent_id, &credential, context, request_id)?;
        if let Some(plugins) = plugins
            && let Err(error) = plugins.emit_loot_captured(&record).await
        {
            warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python loot_captured event");
        }
    }

    Ok(())
}

// ── Agent response event builders ─────────────────────────────────────────────

pub(in crate::dispatch) fn agent_response_event(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    kind: &str,
    message: &str,
    output: Option<String>,
) -> Result<OperatorMessage, CommandDispatchError> {
    agent_response_event_with_extra_and_context(
        agent_id,
        command_id,
        request_id,
        kind,
        message,
        BTreeMap::new(),
        output.unwrap_or_default(),
        None,
    )
}

pub(in crate::dispatch) fn agent_response_event_with_extra(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    kind: &str,
    message: &str,
    mut extra: BTreeMap<String, Value>,
    output: String,
) -> Result<OperatorMessage, CommandDispatchError> {
    agent_response_event_with_extra_and_context(
        agent_id,
        command_id,
        request_id,
        kind,
        message,
        std::mem::take(&mut extra),
        output,
        None,
    )
}

pub(in crate::dispatch) fn agent_response_event_with_extra_and_context(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    kind: &str,
    message: &str,
    extra: BTreeMap<String, Value>,
    output: String,
    context: Option<&LootContext>,
) -> Result<OperatorMessage, CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let context = context.cloned().unwrap_or_default();
    let extra = agent_response_extra(extra, request_id, kind, message, &context);

    Ok(OperatorMessage::AgentResponse(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "teamserver".to_owned(),
            timestamp,
            one_time: String::new(),
        },
        info: AgentResponseInfo {
            demon_id: format!("{agent_id:08X}"),
            command_id: command_id.to_string(),
            output,
            command_line: non_empty_option(&context.command_line),
            extra,
        },
    }))
}

pub(in crate::dispatch) fn agent_response_extra(
    mut extra: BTreeMap<String, Value>,
    request_id: u32,
    kind: &str,
    message: &str,
    context: &LootContext,
) -> BTreeMap<String, Value> {
    extra.insert("Type".to_owned(), Value::String(kind.to_owned()));
    extra.insert("Message".to_owned(), Value::String(message.to_owned()));
    extra.insert("RequestID".to_owned(), Value::String(format!("{request_id:X}")));
    if !context.operator.is_empty() {
        extra.insert("Operator".to_owned(), Value::String(context.operator.clone()));
    }
    if !context.command_line.is_empty() {
        extra.insert("CommandLine".to_owned(), Value::String(context.command_line.clone()));
    }
    if !context.task_id.is_empty() {
        extra.insert("TaskID".to_owned(), Value::String(context.task_id.clone()));
    }
    extra
}

// ── Small helpers ─────────────────────────────────────────────────────────────

pub(in crate::dispatch) fn non_empty_option(value: &str) -> Option<String> {
    if value.is_empty() { None } else { Some(value.to_owned()) }
}

pub(in crate::dispatch) fn parse_optional_kill_date(
    raw: u64,
    command_id: u32,
    field: &'static str,
) -> Result<Option<i64>, CommandDispatchError> {
    if raw == 0 {
        return Ok(None);
    }

    let parsed = i64::try_from(raw).map_err(|_| CommandDispatchError::InvalidCallbackPayload {
        command_id,
        message: format!("{field} exceeds i64 range"),
    })?;
    Ok(Some(parsed))
}

pub(in crate::dispatch) fn bool_string(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

pub(in crate::dispatch) fn job_type_name(job_type: u32) -> &'static str {
    match job_type {
        1 => "Thread",
        2 => "Process",
        3 => "Track Process",
        _ => "Unknown",
    }
}

pub(in crate::dispatch) fn job_state_name(state: u32) -> &'static str {
    match state {
        1 => "Running",
        2 => "Suspended",
        3 => "Dead",
        _ => "Unknown",
    }
}
