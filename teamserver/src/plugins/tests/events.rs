use super::*;

fn make_tracker_and_callback(
    runtime: &PluginRuntime,
    py: Python<'_>,
    append_expr: &std::ffi::CStr,
) -> PyResult<(Py<PyList>, Py<PyAny>)> {
    runtime.install_api_module(py)?;
    let tracker = PyList::empty(py);
    let locals = pyo3::types::PyDict::new(py);
    locals.set_item("_tracker", tracker.clone())?;
    let cb = py.eval(append_expr, None, Some(&locals))?;
    Ok((tracker.unbind(), cb.unbind()))
}

fn tracker_len(tracker: Py<PyList>) -> usize {
    Python::with_gil(|py| tracker.bind(py).len())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_agent_checkin_invokes_registered_callbacks() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) = runtime_fixture("emit-checkin").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| {
                make_tracker_and_callback(
                    &runtime,
                    py,
                    pyo3::ffi::c_str!(
                        "(lambda t: lambda event: t.append(event.event_type))(_tracker)"
                    ),
                )
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::AgentCheckin, callback).await?;
    runtime.emit_agent_checkin(0x00AB_CDEF).await?;

    let (count, event_type) = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(usize, String)> {
            let list = tracker.bind(py);
            let count = list.len();
            let first = list.get_item(0)?.extract::<String>()?;
            Ok((count, first))
        })
    })
    .await??;
    assert_eq!(count, 1);
    assert_eq!(event_type, "agent_checkin");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_command_output_invokes_registered_callbacks() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) = runtime_fixture("emit-output").await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| {
                make_tracker_and_callback(
                    &runtime,
                    py,
                    pyo3::ffi::c_str!(
                        "(lambda t: lambda event: t.append(event.data['output']))(_tracker)"
                    ),
                )
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::CommandOutput, callback).await?;
    runtime.emit_command_output(0x00AB_CDEF, 42, 1, "hello world").await?;

    let (count, output) = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(usize, String)> {
            let list = tracker.bind(py);
            let count = list.len();
            let first = list.get_item(0)?.extract::<String>()?;
            Ok((count, first))
        })
    })
    .await??;
    assert_eq!(count, 1);
    assert_eq!(output, "hello world");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_agent_checkin_skips_unknown_agent() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("emit-checkin-unknown").await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| {
                make_tracker_and_callback(
                    &runtime,
                    py,
                    pyo3::ffi::c_str!("(lambda t: lambda event: t.append(1))(_tracker)"),
                )
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::AgentCheckin, callback).await?;
    runtime.emit_agent_checkin(0xDEAD).await?;

    let count = tokio::task::spawn_blocking(move || tracker_len(tracker)).await?;
    assert_eq!(count, 0, "callback must not fire when agent is unknown");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_callback_exception_does_not_propagate() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("emit-exception").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let (tracker, bad_cb, good_cb) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| -> PyResult<(Py<PyList>, Py<PyAny>, Py<PyAny>)> {
                runtime.install_api_module(py)?;
                let helper = PyModule::from_code(
                    py,
                    pyo3::ffi::c_str!("def raise_error(event):\n    raise Exception('boom')"),
                    pyo3::ffi::c_str!("test_raiser.py"),
                    pyo3::ffi::c_str!("test_raiser"),
                )?;
                let bad_cb = helper.getattr("raise_error")?.unbind();

                let tracker = PyList::empty(py);
                let locals = pyo3::types::PyDict::new(py);
                locals.set_item("_tracker", tracker.clone())?;
                let good_cb = py.eval(
                    pyo3::ffi::c_str!(
                        "(lambda t: lambda event: t.append(event.event_type))(_tracker)"
                    ),
                    None,
                    Some(&locals),
                )?;
                Ok((tracker.unbind(), bad_cb, good_cb.unbind()))
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::AgentCheckin, bad_cb).await?;
    runtime.register_callback(PluginEvent::AgentCheckin, good_cb).await?;

    runtime.emit_agent_checkin(0x00AB_CDEF).await?;

    let count = tokio::task::spawn_blocking(move || tracker_len(tracker)).await?;
    assert_eq!(count, 1, "good callback must still fire after bad callback raises");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_agent_registered_invokes_registered_callbacks()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("emit-registered").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| {
                make_tracker_and_callback(
                    &runtime,
                    py,
                    pyo3::ffi::c_str!(
                        "(lambda t: lambda event: t.append(event.event_type))(_tracker)"
                    ),
                )
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::AgentRegistered, callback).await?;
    runtime.emit_agent_registered(0x00AB_CDEF).await?;

    let (count, event_type) = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(usize, String)> {
            let list = tracker.bind(py);
            let count = list.len();
            let first = list.get_item(0)?.extract::<String>()?;
            Ok((count, first))
        })
    })
    .await??;
    assert_eq!(count, 1);
    assert_eq!(event_type, "agent_registered");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_agent_dead_invokes_registered_callbacks() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) = runtime_fixture("emit-dead").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| {
                make_tracker_and_callback(
                    &runtime,
                    py,
                    pyo3::ffi::c_str!(
                        "(lambda t: lambda event: t.append(event.event_type))(_tracker)"
                    ),
                )
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::AgentDead, callback).await?;
    runtime.emit_agent_dead(0x00AB_CDEF).await?;

    let (count, event_type) = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(usize, String)> {
            let list = tracker.bind(py);
            let count = list.len();
            let first = list.get_item(0)?.extract::<String>()?;
            Ok((count, first))
        })
    })
    .await??;
    assert_eq!(count, 1);
    assert_eq!(event_type, "agent_dead");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_loot_captured_invokes_registered_callbacks() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) = runtime_fixture("emit-loot").await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| {
                make_tracker_and_callback(
                    &runtime,
                    py,
                    pyo3::ffi::c_str!(
                        "(lambda t: lambda event: t.append(event.data['kind']))(_tracker)"
                    ),
                )
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::LootCaptured, callback).await?;
    let loot = LootRecord {
        id: Some(1),
        agent_id: 0x00AB_CDEF,
        kind: "screenshot".to_owned(),
        name: "Desktop_01.01.2026.png".to_owned(),
        file_path: None,
        size_bytes: Some(12345),
        captured_at: "2026-03-15T00:00:00Z".to_owned(),
        data: None,
        metadata: None,
    };
    runtime.emit_loot_captured(&loot).await?;

    let (count, kind) = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(usize, String)> {
            let list = tracker.bind(py);
            let count = list.len();
            let first = list.get_item(0)?.extract::<String>()?;
            Ok((count, first))
        })
    })
    .await??;
    assert_eq!(count, 1);
    assert_eq!(kind, "screenshot");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_task_created_invokes_registered_callbacks() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) = runtime_fixture("emit-task").await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| {
                make_tracker_and_callback(
                    &runtime,
                    py,
                    pyo3::ffi::c_str!(
                        "(lambda t: lambda event: t.append(event.data['command_line']))(_tracker)"
                    ),
                )
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::TaskCreated, callback).await?;
    let job = Job {
        command: 10,
        request_id: 42,
        payload: vec![],
        command_line: "shell whoami".to_owned(),
        task_id: "task-001".to_owned(),
        created_at: "2026-03-15T00:00:00Z".to_owned(),
        operator: "admin".to_owned(),
    };
    runtime.emit_task_created(0x00AB_CDEF, &job).await?;

    let (count, cmd_line) = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(usize, String)> {
            let list = tracker.bind(py);
            let count = list.len();
            let first = list.get_item(0)?.extract::<String>()?;
            Ok((count, first))
        })
    })
    .await??;
    assert_eq!(count, 1);
    assert_eq!(cmd_line, "shell whoami");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_agent_registered_skips_unknown_agent() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("emit-registered-unknown").await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| {
                make_tracker_and_callback(
                    &runtime,
                    py,
                    pyo3::ffi::c_str!("(lambda t: lambda event: t.append(1))(_tracker)"),
                )
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::AgentRegistered, callback).await?;
    runtime.emit_agent_registered(0xDEAD).await?;

    let count = tokio::task::spawn_blocking(move || tracker_len(tracker)).await?;
    assert_eq!(count, 0, "callback must not fire when agent is unknown");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_agent_dead_skips_unknown_agent() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("emit-dead-unknown").await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| {
                make_tracker_and_callback(
                    &runtime,
                    py,
                    pyo3::ffi::c_str!("(lambda t: lambda event: t.append(1))(_tracker)"),
                )
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::AgentDead, callback).await?;
    runtime.emit_agent_dead(0xDEAD).await?;

    let count = tokio::task::spawn_blocking(move || tracker_len(tracker)).await?;
    assert_eq!(count, 0, "callback must not fire when agent is unknown");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_events_succeed_silently_with_no_callbacks() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("emit-no-callbacks").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    // All emit_* methods must succeed when no callbacks are registered.
    runtime.emit_agent_checkin(0x00AB_CDEF).await?;
    runtime.emit_agent_registered(0x00AB_CDEF).await?;
    runtime.emit_agent_dead(0x00AB_CDEF).await?;
    runtime.emit_command_output(0x00AB_CDEF, 1, 1, "output").await?;
    runtime
        .emit_loot_captured(&LootRecord {
            id: Some(1),
            agent_id: 0x00AB_CDEF,
            kind: "screenshot".to_owned(),
            name: "test.png".to_owned(),
            file_path: None,
            size_bytes: Some(100),
            captured_at: "2026-03-15T00:00:00Z".to_owned(),
            data: None,
            metadata: None,
        })
        .await?;
    runtime
        .emit_task_created(
            0x00AB_CDEF,
            &Job {
                command: 1,
                request_id: 1,
                payload: vec![],
                command_line: "test".to_owned(),
                task_id: "001".to_owned(),
                created_at: "2026-03-15T00:00:00Z".to_owned(),
                operator: "admin".to_owned(),
            },
        )
        .await?;
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_agent_checkin_passes_full_agent_data() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("emit-checkin-full").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    // Capture event.data fields and event.agent.id (hex string) via Python.
    let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append((event.event_type, event.agent.id if event.agent else None, event.data.get('Hostname'), event.data.get('Username'), event.data.get('ExternalIP'), event.data.get('ProcessName'), event.data.get('Elevated'))))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

    runtime.register_callback(PluginEvent::AgentCheckin, callback).await?;
    runtime.emit_agent_checkin(0x00AB_CDEF).await?;

    let result = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(String, String, String, String, String, String, bool)> {
            let list = tracker.bind(py);
            let tuple = list.get_item(0)?;
            Ok((
                tuple.get_item(0)?.extract()?,
                tuple.get_item(1)?.extract()?,
                tuple.get_item(2)?.extract()?,
                tuple.get_item(3)?.extract()?,
                tuple.get_item(4)?.extract()?,
                tuple.get_item(5)?.extract()?,
                tuple.get_item(6)?.extract()?,
            ))
        })
    })
    .await??;
    assert_eq!(result.0, "agent_checkin");
    assert_eq!(result.1, "00ABCDEF");
    assert_eq!(result.2, "wkstn-01");
    assert_eq!(result.3, "operator");
    assert_eq!(result.4, "203.0.113.10");
    assert_eq!(result.5, "explorer.exe");
    assert!(result.6, "Elevated must be true");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_command_output_passes_all_fields() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("emit-output-full").await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append((event.event_type, event.data['agent_id'], event.data['command_id'], event.data['request_id'], event.data['output'])))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

    runtime.register_callback(PluginEvent::CommandOutput, callback).await?;
    runtime.emit_command_output(0x00AB_CDEF, 42, 7, "test output").await?;

    let result = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(String, u32, u32, u32, String)> {
            let list = tracker.bind(py);
            let tuple = list.get_item(0)?;
            Ok((
                tuple.get_item(0)?.extract()?,
                tuple.get_item(1)?.extract()?,
                tuple.get_item(2)?.extract()?,
                tuple.get_item(3)?.extract()?,
                tuple.get_item(4)?.extract()?,
            ))
        })
    })
    .await??;
    assert_eq!(result.0, "command_output");
    assert_eq!(result.1, 0x00AB_CDEF, "agent_id");
    assert_eq!(result.2, 42, "command_id");
    assert_eq!(result.3, 7, "request_id");
    assert_eq!(result.4, "test output");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_agent_dead_passes_full_agent_data() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("emit-dead-full").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append((event.event_type, event.agent.id if event.agent else None, event.data.get('Hostname'), event.data.get('DomainName'))))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

    runtime.register_callback(PluginEvent::AgentDead, callback).await?;
    runtime.emit_agent_dead(0x00AB_CDEF).await?;

    let result = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(String, String, String, String)> {
            let list = tracker.bind(py);
            let tuple = list.get_item(0)?;
            Ok((
                tuple.get_item(0)?.extract()?,
                tuple.get_item(1)?.extract()?,
                tuple.get_item(2)?.extract()?,
                tuple.get_item(3)?.extract()?,
            ))
        })
    })
    .await??;
    assert_eq!(result.0, "agent_dead");
    assert_eq!(result.1, "00ABCDEF");
    assert_eq!(result.2, "wkstn-01");
    assert_eq!(result.3, "REDCELL");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_loot_captured_passes_all_fields() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("emit-loot-full").await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append((event.event_type, event.data['agent_id'], event.data['id'], event.data['kind'], event.data['name'], event.data['size_bytes'], event.data['captured_at'], event.data.get('file_path'))))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

    runtime.register_callback(PluginEvent::LootCaptured, callback).await?;
    let loot = LootRecord {
        id: Some(99),
        agent_id: 0x00AB_CDEF,
        kind: "credential".to_owned(),
        name: "admin_creds.txt".to_owned(),
        file_path: Some("/loot/admin_creds.txt".to_owned()),
        size_bytes: Some(256),
        captured_at: "2026-03-15T12:00:00Z".to_owned(),
        data: None,
        metadata: None,
    };
    runtime.emit_loot_captured(&loot).await?;

    let result = tokio::task::spawn_blocking(move || {
        Python::with_gil(
            |py| -> PyResult<(String, u32, u64, String, String, u64, String, String)> {
                let list = tracker.bind(py);
                let tuple = list.get_item(0)?;
                Ok((
                    tuple.get_item(0)?.extract()?,
                    tuple.get_item(1)?.extract()?,
                    tuple.get_item(2)?.extract()?,
                    tuple.get_item(3)?.extract()?,
                    tuple.get_item(4)?.extract()?,
                    tuple.get_item(5)?.extract()?,
                    tuple.get_item(6)?.extract()?,
                    tuple.get_item(7)?.extract()?,
                ))
            },
        )
    })
    .await??;
    assert_eq!(result.0, "loot_captured");
    assert_eq!(result.1, 0x00AB_CDEF, "agent_id");
    assert_eq!(result.2, 99, "loot id");
    assert_eq!(result.3, "credential", "kind");
    assert_eq!(result.4, "admin_creds.txt", "name");
    assert_eq!(result.5, 256, "size_bytes");
    assert_eq!(result.6, "2026-03-15T12:00:00Z", "captured_at");
    assert_eq!(result.7, "/loot/admin_creds.txt", "file_path");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_task_created_passes_all_fields() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("emit-task-full").await?;

    let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    make_tracker_and_callback(
                        &runtime,
                        py,
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append((event.event_type, event.data['agent_id'], event.data['request_id'], event.data['command'], event.data['command_line'], event.data['task_id'], event.data['created_at'], event.data['operator'])))(_tracker)"
                        ),
                    )
                })
            }
        })
        .await??;

    runtime.register_callback(PluginEvent::TaskCreated, callback).await?;
    let job = Job {
        command: 15,
        request_id: 99,
        payload: vec![],
        command_line: "upload /tmp/payload.bin".to_owned(),
        task_id: "task-042".to_owned(),
        created_at: "2026-03-15T08:30:00Z".to_owned(),
        operator: "admin".to_owned(),
    };
    runtime.emit_task_created(0x00AB_CDEF, &job).await?;

    let result = tokio::task::spawn_blocking(move || {
        Python::with_gil(
            |py| -> PyResult<(String, u32, u32, u32, String, String, String, String)> {
                let list = tracker.bind(py);
                let tuple = list.get_item(0)?;
                Ok((
                    tuple.get_item(0)?.extract()?,
                    tuple.get_item(1)?.extract()?,
                    tuple.get_item(2)?.extract()?,
                    tuple.get_item(3)?.extract()?,
                    tuple.get_item(4)?.extract()?,
                    tuple.get_item(5)?.extract()?,
                    tuple.get_item(6)?.extract()?,
                    tuple.get_item(7)?.extract()?,
                ))
            },
        )
    })
    .await??;
    assert_eq!(result.0, "task_created");
    assert_eq!(result.1, 0x00AB_CDEF, "agent_id");
    assert_eq!(result.2, 99, "request_id");
    assert_eq!(result.3, 15, "command");
    assert_eq!(result.4, "upload /tmp/payload.bin", "command_line");
    assert_eq!(result.5, "task-042", "task_id");
    assert_eq!(result.6, "2026-03-15T08:30:00Z", "created_at");
    assert_eq!(result.7, "admin", "operator");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn emit_loot_captured_exception_does_not_block_subsequent_callbacks()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("emit-loot-exception").await?;

    let (tracker, bad_cb, good_cb) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| -> PyResult<(Py<PyList>, Py<PyAny>, Py<PyAny>)> {
                runtime.install_api_module(py)?;
                let helper = PyModule::from_code(
                    py,
                    pyo3::ffi::c_str!("def raise_error(event):\n    raise ValueError('loot boom')"),
                    pyo3::ffi::c_str!("test_loot_raiser.py"),
                    pyo3::ffi::c_str!("test_loot_raiser"),
                )?;
                let bad_cb = helper.getattr("raise_error")?.unbind();

                let tracker = PyList::empty(py);
                let locals = pyo3::types::PyDict::new(py);
                locals.set_item("_tracker", tracker.clone())?;
                let good_cb = py.eval(
                    pyo3::ffi::c_str!(
                        "(lambda t: lambda event: t.append(event.data['kind']))(_tracker)"
                    ),
                    None,
                    Some(&locals),
                )?;
                Ok((tracker.unbind(), bad_cb, good_cb.unbind()))
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::LootCaptured, bad_cb).await?;
    runtime.register_callback(PluginEvent::LootCaptured, good_cb).await?;

    let loot = LootRecord {
        id: Some(1),
        agent_id: 0x00AB_CDEF,
        kind: "download".to_owned(),
        name: "flag.txt".to_owned(),
        file_path: None,
        size_bytes: Some(42),
        captured_at: "2026-03-15T00:00:00Z".to_owned(),
        data: None,
        metadata: None,
    };
    runtime.emit_loot_captured(&loot).await?;

    let (count, kind) = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(usize, String)> {
            let list = tracker.bind(py);
            let count = list.len();
            let first = list.get_item(0)?.extract::<String>()?;
            Ok((count, first))
        })
    })
    .await??;
    assert_eq!(count, 1, "good callback must fire after bad callback raises");
    assert_eq!(kind, "download");
    Ok(())
}

// ---- stub_succeeding / stub_failing tests ----

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn stub_succeeding_emit_methods_return_ok() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let database = Database::connect(unique_test_dir("plugins-stub-ok")).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let runtime = PluginRuntime::stub_succeeding(database, registry, events, sockets);

    // All emit_* methods should succeed silently (no Python initialization).
    assert!(runtime.emit_agent_checkin(0x00AB_CDEF).await.is_ok());
    assert!(runtime.emit_agent_registered(0x00AB_CDEF).await.is_ok());
    assert!(runtime.emit_agent_dead(0x00AB_CDEF).await.is_ok());
    assert!(runtime.emit_command_output(0x00AB_CDEF, 1, 1, "out").await.is_ok());
    assert!(
        runtime
            .emit_task_created(
                0x00AB_CDEF,
                &Job {
                    command: 1,
                    request_id: 1,
                    payload: vec![],
                    command_line: "test".to_owned(),
                    task_id: "001".to_owned(),
                    created_at: "now".to_owned(),
                    operator: "op".to_owned(),
                },
            )
            .await
            .is_ok()
    );
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn stub_failing_emit_methods_return_err() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let database = Database::connect(unique_test_dir("plugins-stub-fail")).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let runtime = PluginRuntime::stub_failing(database, registry, events, sockets);

    assert!(runtime.emit_agent_checkin(0x00AB_CDEF).await.is_err());
    assert!(runtime.emit_agent_registered(0x00AB_CDEF).await.is_err());
    assert!(runtime.emit_agent_dead(0x00AB_CDEF).await.is_err());
    assert!(runtime.emit_command_output(0x00AB_CDEF, 1, 1, "out").await.is_err());
    assert!(
        runtime
            .emit_task_created(
                0x00AB_CDEF,
                &Job {
                    command: 1,
                    request_id: 1,
                    payload: vec![],
                    command_line: "test".to_owned(),
                    task_id: "001".to_owned(),
                    created_at: "now".to_owned(),
                    operator: "op".to_owned(),
                },
            )
            .await
            .is_err()
    );
    Ok(())
}

// ---- register_callback/register_command error cases via Python API ----

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn register_callback_rejects_invalid_event_type() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-register-cb-invalid-event").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| -> PyResult<String> {
                runtime.install_api_module(py)?;
                let module = py.import("havoc")?;
                let noop = py.eval(pyo3::ffi::c_str!("lambda event: None"), None, None)?;
                match module.call_method1("RegisterCallback", ("bogus_event_type", &noop)) {
                    Err(err) => Ok(err.to_string()),
                    Ok(_) => Ok("unexpected success".to_owned()),
                }
            })
        }
    });
    let error = handle.join().map_err(|_| "python test thread panicked")??;
    assert!(
        error.contains("unsupported event type"),
        "expected unsupported event type error, got: {error}",
    );
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn register_callback_rejects_non_callable() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-register-cb-non-callable").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| -> PyResult<String> {
                runtime.install_api_module(py)?;
                let module = py.import("havoc")?;
                let not_callable = py.eval(pyo3::ffi::c_str!("42"), None, None)?;
                match module.call_method1("RegisterCallback", ("agent_checkin", &not_callable)) {
                    Err(err) => Ok(err.to_string()),
                    Ok(_) => Ok("unexpected success".to_owned()),
                }
            })
        }
    });
    let error = handle.join().map_err(|_| "python test thread panicked")??;
    assert!(
        error.contains("callback must be callable"),
        "expected 'callback must be callable' error, got: {error}",
    );
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[allow(clippy::type_complexity)]
#[tokio::test(flavor = "multi_thread")]
async fn multiple_callbacks_same_event_all_fire() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-multi-cb").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let (tracker, cb1, cb2, cb3) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| -> PyResult<(Py<PyList>, Py<PyAny>, Py<PyAny>, Py<PyAny>)> {
                runtime.install_api_module(py)?;
                let tracker = PyList::empty(py);
                let locals = pyo3::types::PyDict::new(py);
                locals.set_item("_tracker", tracker.clone())?;

                let cb1 = py.eval(
                    pyo3::ffi::c_str!("(lambda t: lambda event: t.append('cb1'))(_tracker)"),
                    None,
                    Some(&locals),
                )?;
                let cb2 = py.eval(
                    pyo3::ffi::c_str!("(lambda t: lambda event: t.append('cb2'))(_tracker)"),
                    None,
                    Some(&locals),
                )?;
                let cb3 = py.eval(
                    pyo3::ffi::c_str!("(lambda t: lambda event: t.append('cb3'))(_tracker)"),
                    None,
                    Some(&locals),
                )?;
                Ok((tracker.unbind(), cb1.unbind(), cb2.unbind(), cb3.unbind()))
            })
        }
    })
    .await??;

    runtime.register_callback(PluginEvent::AgentCheckin, cb1).await?;
    runtime.register_callback(PluginEvent::AgentCheckin, cb2).await?;
    runtime.register_callback(PluginEvent::AgentCheckin, cb3).await?;
    runtime.emit_agent_checkin(0x00AB_CDEF).await?;

    let items = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<Vec<String>> {
            let list = tracker.bind(py);
            (0..list.len())
                .map(|i| list.get_item(i).and_then(|item| item.extract::<String>()))
                .collect()
        })
    })
    .await??;
    assert_eq!(items, vec!["cb1", "cb2", "cb3"], "all 3 callbacks should fire in order");
    Ok(())
}
