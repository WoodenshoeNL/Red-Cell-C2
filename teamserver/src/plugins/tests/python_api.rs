use super::*;

#[test]
fn plugin_event_round_trip_all_variants() {
    let variants = [
        PluginEvent::AgentCheckin,
        PluginEvent::AgentRegistered,
        PluginEvent::AgentDead,
        PluginEvent::CommandOutput,
        PluginEvent::LootCaptured,
        PluginEvent::TaskCreated,
    ];
    for event in variants {
        let s = event.as_str();
        let parsed = PluginEvent::parse(s);
        assert_eq!(parsed, Some(event), "round-trip failed for {s:?}");
    }
}

#[test]
fn plugin_event_parse_unknown_returns_none() {
    for input in ["nonexistent_event", "foo", "", "agent_checkin_extra", "UNKNOWN"] {
        assert_eq!(PluginEvent::parse(input), None, "expected None for unknown input {input:?}");
    }
}

#[test]
fn plugin_event_parse_case_insensitive() {
    assert_eq!(PluginEvent::parse("AGENT_CHECKIN"), Some(PluginEvent::AgentCheckin));
    assert_eq!(PluginEvent::parse("Agent_Registered"), Some(PluginEvent::AgentRegistered));
    assert_eq!(PluginEvent::parse("COMMAND_OUTPUT"), Some(PluginEvent::CommandOutput));
    assert_eq!(PluginEvent::parse("Loot_Captured"), Some(PluginEvent::LootCaptured));
    assert_eq!(PluginEvent::parse("TASK_CREATED"), Some(PluginEvent::TaskCreated));
    assert_eq!(PluginEvent::parse("AGENT_DEAD"), Some(PluginEvent::AgentDead));
}

#[test]
fn plugin_event_parse_trims_whitespace() {
    assert_eq!(PluginEvent::parse("  agent_checkin  "), Some(PluginEvent::AgentCheckin));
    assert_eq!(PluginEvent::parse("\tagent_dead\n"), Some(PluginEvent::AgentDead));
    assert_eq!(PluginEvent::parse("   "), None);
}

// ---- PyAgent construction tests via Python API ----

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn py_agent_new_parses_hex_formats() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-agent-parse").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| -> PyResult<Vec<String>> {
                runtime.install_api_module(py)?;
                let module = py.import("havoc")?;
                let mut ids = Vec::new();
                // Plain hex
                let agent = module.getattr("Agent")?.call1(("00ABCDEF",))?;
                ids.push(agent.getattr("id")?.extract::<String>()?);
                // 0x prefix
                let agent = module.getattr("Agent")?.call1(("0x00ABCDEF",))?;
                ids.push(agent.getattr("id")?.extract::<String>()?);
                // 0X prefix
                let agent = module.getattr("Agent")?.call1(("0X00ABCDEF",))?;
                ids.push(agent.getattr("id")?.extract::<String>()?);
                // Lowercase
                let agent = module.getattr("Agent")?.call1(("00abcdef",))?;
                ids.push(agent.getattr("id")?.extract::<String>()?);
                // With whitespace
                let agent = module.getattr("Agent")?.call1((" 00ABCDEF ",))?;
                ids.push(agent.getattr("id")?.extract::<String>()?);
                Ok(ids)
            })
        }
    });
    let ids = handle.join().map_err(|_| "python test thread panicked")??;
    for id in &ids {
        assert_eq!(id, "00ABCDEF", "all formats should parse to the same agent id");
    }
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn py_agent_new_rejects_invalid_hex() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-agent-invalid").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| -> PyResult<Vec<String>> {
                runtime.install_api_module(py)?;
                let module = py.import("havoc")?;
                let mut errors = Vec::new();
                for bad_input in ["not_hex", "ZZZZZZZZ", "", "0xGGGG"] {
                    match module.getattr("Agent")?.call1((bad_input,)) {
                        Err(err) => errors.push(err.to_string()),
                        Ok(_) => errors.push(format!("unexpected success for `{bad_input}`")),
                    }
                }
                Ok(errors)
            })
        }
    });
    let errors = handle.join().map_err(|_| "python test thread panicked")??;
    for error in &errors {
        assert!(
            error.contains("invalid agent id"),
            "expected 'invalid agent id' error, got: {error}",
        );
    }
    Ok(())
}

// ---- Python API module aliases ----

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn python_api_module_exposes_pascal_case_aliases() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-api-aliases").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| -> PyResult<Vec<String>> {
                runtime.install_api_module(py)?;
                let mut found = Vec::new();
                for module_name in ["red_cell", "havoc"] {
                    let module = py.import(module_name)?;
                    // Check PascalCase aliases exist and are callable.
                    for alias in [
                        "GetAgent",
                        "GetAgents",
                        "GetListener",
                        "GetListeners",
                        "RegisterCallback",
                        "RegisterCommand",
                    ] {
                        let attr = module.getattr(alias)?;
                        if attr.is_callable() {
                            found.push(format!("{module_name}.{alias}"));
                        }
                    }
                    // Check snake_case functions exist.
                    for func in [
                        "get_agent",
                        "list_agents",
                        "get_listener",
                        "list_listeners",
                        "register_callback",
                        "register_command",
                    ] {
                        let attr = module.getattr(func)?;
                        if attr.is_callable() {
                            found.push(format!("{module_name}.{func}"));
                        }
                    }
                    // Check classes exist.
                    for class in ["Agent", "Listener", "Event"] {
                        let _ = module.getattr(class)?;
                        found.push(format!("{module_name}.{class}"));
                    }
                }
                Ok(found)
            })
        }
    });
    let found = handle.join().map_err(|_| "python test thread panicked")??;
    // 6 aliases + 6 functions + 3 classes = 15 per module, 2 modules = 30
    assert_eq!(found.len(), 30, "expected 30 API entries across both modules, got: {found:?}");
    Ok(())
}

// ---- next_request_id monotonic increment ----

#[test]
fn next_request_id_is_monotonically_increasing() {
    let a = next_request_id();
    let b = next_request_id();
    let c = next_request_id();
    assert!(b > a, "second request_id ({b}) should be greater than first ({a})");
    assert!(c > b, "third request_id ({c}) should be greater than second ({b})");
}

// ---- PyAgent.task argument types ----

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn py_agent_task_accepts_none_and_string_and_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-task-arg-types").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let module = py.import("havoc")?;
                let agent = module.getattr("Agent")?.call1(("00ABCDEF",))?;

                // task with None args — should produce empty payload
                agent.call_method1("task", (1u32, py.None()))?;
                // task with no args at all
                agent.call_method1("task", (2u32,))?;
                // task with string args
                agent.call_method1("task", (3u32, "hello"))?;
                // task with bytes args
                agent.call_method1("task", (4u32, pyo3::types::PyBytes::new(py, b"binary")))?;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    let jobs = registry.dequeue_jobs(0x00AB_CDEF).await?;
    assert_eq!(jobs.len(), 4, "expected 4 queued jobs");
    assert!(jobs[0].payload.is_empty(), "None args → empty payload");
    assert!(jobs[1].payload.is_empty(), "no args → empty payload");
    assert_eq!(jobs[2].payload, b"hello", "string args → string bytes");
    assert_eq!(jobs[3].payload, b"binary", "bytes args → raw bytes");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn py_agent_task_rejects_invalid_arg_type() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-task-invalid-arg").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<String> {
                runtime.install_api_module(py)?;
                let module = py.import("havoc")?;
                let agent = module.getattr("Agent")?.call1(("00ABCDEF",))?;
                // Pass a dict as args — should be rejected.
                let dict = pyo3::types::PyDict::new(py);
                match agent.call_method1("task", (1u32, dict)) {
                    Err(err) => Ok(err.to_string()),
                    Ok(_) => Ok("unexpected success".to_owned()),
                }
            })
        }
    });
    let error = handle.join().map_err(|_| "python test thread panicked")??;
    assert!(
        error.contains("args must be bytes, bytearray, str, or None"),
        "expected type error, got: {error}",
    );
    Ok(())
}

// ---- PluginEvent Display / Debug coverage ----

#[test]
fn plugin_event_as_str_covers_all_variants() {
    // Ensure as_str does not return duplicates and covers every variant.
    let variants = [
        PluginEvent::AgentCheckin,
        PluginEvent::AgentRegistered,
        PluginEvent::AgentDead,
        PluginEvent::CommandOutput,
        PluginEvent::LootCaptured,
        PluginEvent::TaskCreated,
    ];
    let strings: Vec<&str> = variants.iter().map(|v| v.as_str()).collect();
    let unique: std::collections::HashSet<&str> = strings.iter().copied().collect();
    assert_eq!(
        strings.len(),
        unique.len(),
        "each variant must have a unique string representation"
    );
}

// ---- PluginError variants Display ----

#[test]
fn plugin_error_display_messages_are_meaningful() {
    let err = PluginError::InvalidPluginDirectory { path: PathBuf::from("/tmp/missing") };
    let msg = err.to_string();
    assert!(msg.contains("/tmp/missing"), "error should contain the path");

    let err = PluginError::InvalidCStringPath { path: "bad\0path".to_owned() };
    let msg = err.to_string();
    assert!(msg.contains("bad\0path"), "error should contain the path");

    let err = PluginError::ListenerManagerUnavailable;
    let msg = err.to_string();
    assert!(msg.contains("listener manager"), "error should mention listener manager");

    let err = PluginError::MutexPoisoned;
    let msg = err.to_string();
    assert!(msg.contains("mutex poisoned"), "error should mention mutex poisoned");

    let err = PluginError::AgentCommand { message: "task failed".to_owned() };
    assert_eq!(err.to_string(), "task failed");

    let err =
        PluginError::PermissionDenied { role: OperatorRole::Analyst, permission: "task_agents" };
    let msg = err.to_string();
    assert!(msg.contains("Analyst"), "error should contain the role");
    assert!(msg.contains("task_agents"), "error should contain the permission");
}
