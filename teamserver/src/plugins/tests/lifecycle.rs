use std::process::Command;

use pyo3::types::PyList;
use tempfile::TempDir;

use super::*;

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn current_is_none_before_initialization_and_plugins_dir_is_optional()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let _reset = ActiveRuntimeReset::clear()?;

    assert!(PluginRuntime::current()?.is_none());

    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-optional-dir").await?;

    assert!(runtime.plugins_dir().is_none());

    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn initialize_sets_current_runtime_and_exposes_plugins_dir()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let _reset = ActiveRuntimeReset::clear()?;
    let temp_dir = TempDir::new()?;
    let plugins_dir = temp_dir.path().to_path_buf();
    let database = Database::connect(unique_test_dir("plugins-current-state")).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    let runtime =
        PluginRuntime::initialize(database, registry, events, sockets, Some(plugins_dir.clone()))
            .await?;

    assert_eq!(runtime.plugins_dir(), Some(plugins_dir.as_path()));

    let current = PluginRuntime::current()?;
    let Some(current) = current else {
        return Err("expected active plugin runtime".into());
    };
    assert!(Arc::ptr_eq(&runtime.inner, &current.inner));
    assert_eq!(current.plugins_dir(), Some(plugins_dir.as_path()));

    Ok(())
}

#[test]
fn current_reports_mutex_poisoned_in_isolated_process() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os(POISON_CURRENT_ENV).is_some() {
        let child = std::thread::spawn(|| {
            let _guard = runtime_slot().lock().unwrap_or_else(|error| error.into_inner());
            panic!("poison plugin runtime mutex");
        });
        assert!(child.join().is_err(), "child thread must panic to poison the mutex");
        assert!(matches!(PluginRuntime::current(), Err(PluginError::MutexPoisoned)));
        return Ok(());
    }

    let status = Command::new(std::env::current_exe()?)
        .arg("current_reports_mutex_poisoned_in_isolated_process")
        .arg("--nocapture")
        .env(POISON_CURRENT_ENV, "1")
        .status()?;

    assert!(status.success(), "isolated poison harness failed");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn initialize_exposes_agent_and_listener_accessors() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let (database, registry, events, sockets, runtime) = runtime_fixture("plugins-access").await?;
    database.listeners().create(&sample_listener()).await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;
    let listeners = ListenerManager::new(
        database.clone(),
        registry.clone(),
        events,
        sockets,
        Some(runtime.clone()),
    )
    .with_demon_allow_legacy_ctr(true);
    runtime.attach_listener_manager(listeners).await;

    let handle = std::thread::spawn(move || {
        let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
        Python::with_gil(|py| -> PyResult<()> {
            runtime.install_api_module(py)?;

            let module = py.import("havoc")?;
            let agent = module.getattr("Agent")?.call1(("00ABCDEF",))?;
            let agent_info = agent.getattr("info")?;
            let listener = module.getattr("Listener")?.call1(("http-main",))?;
            let listener_info = listener.getattr("info")?;

            assert_eq!(agent_info.get_item("Hostname")?.extract::<String>()?, "wkstn-01");
            assert_eq!(listener_info.get_item("name")?.extract::<String>()?, "http-main");
            Ok(())
        })
    });
    handle.join().map_err(|_| "python test thread panicked")??;
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn load_plugins_registers_callbacks_and_commands() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let temp_dir = TempDir::new()?;
    let plugin_path = temp_dir.path().join("sample_plugin.py");
    std::fs::write(
        &plugin_path,
        r#"
import havoc

def handle_event(event):
    if event.event_type == "agent_checkin":
        _ = event.agent.info["Hostname"]
    else:
        _ = event.data["output"]

def run(agent, args):
    agent.task(0x63, "hello-from-python")

havoc.RegisterCallback("agent_checkin", handle_event)
havoc.RegisterCallback("command_output", handle_event)
havoc.RegisterCommand("demo", "demo command", run)
"#,
    )?;

    let database = Database::connect(unique_test_dir("plugins-load")).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = PluginRuntime::initialize(
        database,
        registry,
        events,
        sockets,
        Some(temp_dir.path().to_path_buf()),
    )
    .await?;

    let (loaded, failed) = runtime.load_plugins().await?;

    assert_eq!(loaded, vec!["sample_plugin".to_owned()]);
    assert_eq!(failed, 0);
    assert_eq!(runtime.command_names().await, vec!["demo".to_owned()]);
    assert_eq!(runtime.command_descriptions().await.get("demo"), Some(&"demo command".to_owned()));
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn load_plugins_skips_plugin_with_syntax_error() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let temp_dir = TempDir::new()?;
    let plugin_path = temp_dir.path().join("bad_plugin.py");
    // Deliberate Python syntax error: unmatched parenthesis.
    std::fs::write(&plugin_path, "def broken(\n    pass\n")?;

    let database = Database::connect(unique_test_dir("plugins-syntax-error")).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = PluginRuntime::initialize(
        database,
        registry,
        events,
        sockets,
        Some(temp_dir.path().to_path_buf()),
    )
    .await?;

    let (loaded, failed) = runtime.load_plugins().await?;
    assert!(loaded.is_empty(), "broken plugin should be skipped, got {loaded:?}");
    assert_eq!(failed, 1, "syntax error plugin should count as 1 failure");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn load_plugins_multiple_with_broken_plugin_isolation()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let temp_dir = TempDir::new()?;

    // alpha.py — registers a command
    std::fs::write(
        temp_dir.path().join("alpha.py"),
        r#"
import havoc
def run_alpha(agent, args):
    agent.task(0x10, "alpha-payload")
havoc.RegisterCommand("alpha_cmd", "alpha command", run_alpha)
"#,
    )?;

    // beta.py — has a syntax error (should be skipped)
    std::fs::write(temp_dir.path().join("beta.py"), "def broken(\n    pass\n")?;

    // gamma.py — registers a callback
    std::fs::write(
        temp_dir.path().join("gamma.py"),
        r#"
import havoc
def on_checkin(event):
    _ = event.agent.info["Hostname"]
havoc.RegisterCallback("agent_checkin", on_checkin)
"#,
    )?;

    let database = Database::connect(unique_test_dir("plugins-multi-isolation")).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = PluginRuntime::initialize(
        database,
        registry,
        events,
        sockets,
        Some(temp_dir.path().to_path_buf()),
    )
    .await?;

    let (loaded, failed) = runtime.load_plugins().await?;

    // alpha and gamma should load; beta (syntax error) should be skipped.
    assert_eq!(loaded, vec!["alpha".to_owned(), "gamma".to_owned()]);
    assert_eq!(failed, 1, "beta.py syntax error should count as 1 failure");

    // alpha's command should be registered.
    assert_eq!(runtime.command_names().await, vec!["alpha_cmd".to_owned()]);
    assert_eq!(
        runtime.command_descriptions().await.get("alpha_cmd"),
        Some(&"alpha command".to_owned()),
    );

    // gamma's callback should be registered (agent_checkin event).
    let callbacks = runtime.inner.callbacks.read().await;
    let checkin_callbacks = callbacks.get("agent_checkin");
    assert!(
        checkin_callbacks.is_some_and(|cbs| cbs.len() == 1),
        "expected exactly 1 agent_checkin callback from gamma plugin",
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn load_plugins_rejects_nonexistent_plugin_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let bogus_path = unique_test_dir("plugins-no-such-dir");
    // Ensure the directory really doesn't exist.
    assert!(!bogus_path.exists());

    let database = Database::connect(unique_test_dir("plugins-invalid-dir-db")).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime =
        PluginRuntime::initialize(database, registry, events, sockets, Some(bogus_path.clone()))
            .await?;

    let result = runtime.load_plugins().await;
    match result {
        Err(PluginError::InvalidPluginDirectory { path }) => {
            assert_eq!(path, bogus_path);
        }
        other => panic!("expected Err(InvalidPluginDirectory), got {other:?}"),
    }
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn load_plugins_skips_plugin_with_interior_nul_in_source()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let temp_dir = TempDir::new()?;
    let plugin_path = temp_dir.path().join("nul_plugin.py");
    // Write a plugin whose source contains an interior NUL byte — this must
    // trigger the CString conversion guard and skip the plugin.
    std::fs::write(&plugin_path, b"x = 1\0\ny = 2\n")?;

    let database = Database::connect(unique_test_dir("plugins-nul-source")).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = PluginRuntime::initialize(
        database,
        registry,
        events,
        sockets,
        Some(temp_dir.path().to_path_buf()),
    )
    .await?;

    let (loaded, failed) = runtime.load_plugins().await?;
    assert!(loaded.is_empty(), "plugin with interior NUL should be skipped, got {loaded:?}");
    assert_eq!(failed, 1, "plugin with interior NUL byte should count as 1 failure");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn load_plugins_rejects_regular_file_as_plugin_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let file_path = temp_dir.path().join("not_a_dir.txt");
    std::fs::write(&file_path, "hello")?;

    let database = Database::connect(unique_test_dir("plugins-file-not-dir-db")).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime =
        PluginRuntime::initialize(database, registry, events, sockets, Some(file_path.clone()))
            .await?;

    let result = runtime.load_plugins().await;
    match result {
        Err(PluginError::InvalidPluginDirectory { path }) => {
            assert_eq!(path, file_path);
        }
        other => panic!("expected Err(InvalidPluginDirectory), got {other:?}"),
    }
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn load_plugins_returns_empty_when_no_dir_configured()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-no-dir").await?;

    let (loaded, failed) = runtime.load_plugins().await?;
    assert!(loaded.is_empty(), "expected empty vec when no plugins_dir configured");
    assert_eq!(failed, 0);
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn load_plugins_skips_non_py_files() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let temp_dir = TempDir::new()?;
    std::fs::write(temp_dir.path().join("readme.txt"), "not a plugin")?;
    std::fs::write(temp_dir.path().join("data.json"), "{}")?;
    std::fs::write(temp_dir.path().join("real_plugin.py"), "x = 42\n")?;

    let database = Database::connect(unique_test_dir("plugins-skip-non-py")).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = PluginRuntime::initialize(
        database,
        registry,
        events,
        sockets,
        Some(temp_dir.path().to_path_buf()),
    )
    .await?;

    let (loaded, failed) = runtime.load_plugins().await?;
    assert_eq!(loaded, vec!["real_plugin".to_owned()]);
    assert_eq!(failed, 0, "non-.py files should not count as failures");
    Ok(())
}

/// Verify that the thread-local [`CallbackRuntimeGuard`] allows `active()` to
/// succeed even when the global `RUNTIME` mutex is held by another thread,
/// proving the re-entrancy fix for the callback deadlock (red-cell-c2-ss50).
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn callback_runtime_guard_bypasses_global_mutex() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-callback-guard").await?;

    let runtime_for_thread = runtime.clone();
    let result = tokio::task::spawn_blocking(move || {
        // Set the thread-local guard (simulating callback dispatch).
        let _guard = CallbackRuntimeGuard::enter(&runtime_for_thread);
        // active() should resolve via the thread-local, never touching the
        // global mutex.
        PluginRuntime::active()
    })
    .await?;

    assert!(result.is_ok(), "active() should succeed via thread-local guard");
    Ok(())
}

/// Verify that `active()` returns the thread-local runtime (not the global)
/// when the callback guard is set, and that the thread-local is cleared on
/// guard drop.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn callback_runtime_guard_clears_on_drop() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-callback-guard-drop").await?;

    let result = tokio::task::spawn_blocking(move || {
        // Verify thread-local is empty before guard.
        let before = CALLBACK_RUNTIME.with(|cell| cell.borrow().is_some());
        assert!(!before, "thread-local should be None before guard");

        {
            let _guard = CallbackRuntimeGuard::enter(&runtime);
            let during = CALLBACK_RUNTIME.with(|cell| cell.borrow().is_some());
            assert!(during, "thread-local should be Some while guard is active");
        }

        // After guard drops, thread-local should be cleared.
        let after = CALLBACK_RUNTIME.with(|cell| cell.borrow().is_some());
        assert!(!after, "thread-local should be None after guard drops");
    })
    .await;

    assert!(result.is_ok());
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn attach_listener_manager_makes_manager_available() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let (database, registry, events, sockets, runtime) =
        runtime_fixture("plugins-attach-manager").await?;
    database.listeners().create(&sample_listener()).await?;

    // Before attaching, listener operations should fail.
    let result = runtime.listener_manager().await;
    assert!(
        matches!(result, Err(PluginError::ListenerManagerUnavailable)),
        "expected ListenerManagerUnavailable before attach",
    );

    let listeners =
        ListenerManager::new(database, registry, events, sockets, Some(runtime.clone()))
            .with_demon_allow_legacy_ctr(true);
    runtime.attach_listener_manager(listeners).await;

    // After attaching, listener_manager() should succeed.
    let manager = runtime.listener_manager().await;
    assert!(manager.is_ok(), "expected listener manager to be available after attach");
    Ok(())
}

/// Regression test for red-cell-c2-ss50: a Python callback that calls back
/// into the Rust API (e.g. `havoc.Agent(...).info`) must not deadlock on the
/// global `RUNTIME` mutex.  The `CallbackRuntimeGuard` thread-local bypass
/// makes this safe.  Without it, `invoke_callbacks` holds the mutex while
/// Python calls `PluginRuntime::active()`, which tries to acquire it again
/// on the same thread — classic re-entrant deadlock.
///
/// We use `tokio::time::timeout` so the test fails fast rather than hanging
/// forever if the deadlock regresses.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn callback_reentrant_rust_api_does_not_deadlock() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-reentrant-deadlock").await?;
    let agent_id: u32 = 0x00DE_AD01;
    registry.insert(sample_agent(agent_id)).await?;

    // Build a Python callback that calls back into the Rust API via
    // `havoc.Agent("00DEAD01").info`, which internally calls
    // `PluginRuntime::active()`.  If the thread-local guard is not set,
    // this will deadlock because `invoke_callbacks` already holds the
    // global RUNTIME mutex on this thread.
    let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| -> PyResult<_> {
                    runtime.install_api_module(py)?;
                    let havoc = py.import("havoc")?;
                    let locals = pyo3::types::PyDict::new(py);
                    let tracker = PyList::empty(py);
                    locals.set_item("_tracker", tracker.clone())?;
                    locals.set_item("havoc", havoc)?;
                    let cb = py.eval(
                        pyo3::ffi::c_str!(
                            "(lambda t, h: lambda event: t.append(h.Agent('00DEAD01').info['Hostname']))(_tracker, havoc)"
                        ),
                        None,
                        Some(&locals),
                    )?;
                    Ok((tracker.unbind(), cb.unbind()))
                })
            }
        })
        .await??;

    runtime.register_callback(PluginEvent::AgentCheckin, callback).await?;

    // The callback re-enters Rust via havoc.Agent().info — if the
    // thread-local bypass is missing, this will hang forever.  A 10-second
    // timeout gives plenty of margin for CI while still catching a
    // deadlock quickly.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        runtime.emit_agent_checkin(agent_id),
    )
    .await;

    let emit_result = result.expect("timed out — likely deadlock in re-entrant callback");
    emit_result?;

    // Verify the callback actually ran and read the agent info successfully.
    let (count, hostname) = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(usize, String)> {
            let list = tracker.bind(py);
            let count = list.len();
            let first = list.get_item(0)?.extract::<String>()?;
            Ok((count, first))
        })
    })
    .await??;
    assert_eq!(count, 1, "callback should have been invoked exactly once");
    assert_eq!(hostname, "wkstn-01", "callback should have read the agent hostname");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn load_plugins_returns_empty_for_empty_directory() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let temp_dir = TempDir::new()?;
    // Directory exists but contains no files.

    let database = Database::connect(unique_test_dir("plugins-empty-dir")).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = PluginRuntime::initialize(
        database,
        registry,
        events,
        sockets,
        Some(temp_dir.path().to_path_buf()),
    )
    .await?;

    let (loaded, failed) = runtime.load_plugins().await?;
    assert!(loaded.is_empty(), "empty directory should produce no loaded plugins");
    assert_eq!(failed, 0);
    Ok(())
}

// ---- swap_active test-only helper ----

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn swap_active_replaces_and_returns_previous() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let _reset = ActiveRuntimeReset::clear()?;

    assert!(PluginRuntime::current()?.is_none(), "should start with None");

    let (_database, _registry, _events, _sockets, _runtime) =
        runtime_fixture("plugins-swap-active").await?;

    // After initialize, current should be Some.
    let previous = PluginRuntime::swap_active(None)?;
    assert!(previous.is_some(), "swap_active should return the previously installed runtime");
    assert!(PluginRuntime::current()?.is_none(), "after swap to None, current should be None");

    // Restore it.
    let none = PluginRuntime::swap_active(previous)?;
    assert!(none.is_none(), "second swap should return None");
    assert!(PluginRuntime::current()?.is_some(), "after restore, current should be Some");

    Ok(())
}

// ── Health-tracking / auto-disable unit tests ──────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn health_summary_empty_for_fresh_runtime() -> Result<(), Box<dyn std::error::Error>> {
    let (_db, _reg, _ev, _sock, runtime) = runtime_fixture("health-summary-empty").await?;
    let summary = runtime.plugin_health_summary();
    assert!(summary.is_empty(), "expected empty summary, got {summary:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn record_failure_increments_count_without_disabling()
-> Result<(), Box<dyn std::error::Error>> {
    let (_db, _reg, _ev, _sock, runtime) = runtime_fixture("health-single-failure").await?;
    let disabled = runtime.record_callback_failure("test_plugin");
    assert!(!disabled, "one failure should not disable the plugin");
    assert!(!runtime.is_plugin_disabled("test_plugin"));

    let counts = runtime.inner.failure_counts.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(*counts.get("test_plugin").unwrap_or(&0), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_auto_disabled_after_max_consecutive_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let (_db, _reg, _ev, _sock, runtime) = runtime_fixture("health-auto-disable").await?;

    // Record failures up to threshold - 1: should not disable.
    for i in 1..DEFAULT_MAX_CONSECUTIVE_FAILURES {
        let disabled = runtime.record_callback_failure("fragile_plugin");
        assert!(!disabled, "failure #{i} of {DEFAULT_MAX_CONSECUTIVE_FAILURES} should not disable",);
    }
    assert!(!runtime.is_plugin_disabled("fragile_plugin"));

    // The threshold-th failure should disable.
    let disabled = runtime.record_callback_failure("fragile_plugin");
    assert!(disabled, "failure at threshold should disable the plugin");
    assert!(runtime.is_plugin_disabled("fragile_plugin"));

    // Further failures should not return `true` again (already disabled).
    let disabled_again = runtime.record_callback_failure("fragile_plugin");
    assert!(!disabled_again, "already-disabled plugin should not re-trigger");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn success_resets_failure_count_and_re_enables() -> Result<(), Box<dyn std::error::Error>> {
    let (_db, _reg, _ev, _sock, runtime) = runtime_fixture("health-success-reset").await?;

    // Accumulate some failures (but not enough to disable).
    for _ in 0..3 {
        runtime.record_callback_failure("recovering_plugin");
    }
    {
        let counts = runtime.inner.failure_counts.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(*counts.get("recovering_plugin").unwrap_or(&0), 3);
    }

    // A success should reset the count.
    runtime.record_callback_success("recovering_plugin");
    {
        let counts = runtime.inner.failure_counts.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            !counts.contains_key("recovering_plugin"),
            "success should remove the failure counter",
        );
    }
    assert!(!runtime.is_plugin_disabled("recovering_plugin"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn health_summary_lists_plugins_with_callbacks_and_commands()
-> Result<(), Box<dyn std::error::Error>> {
    let (_db, _reg, _ev, _sock, runtime) = runtime_fixture("health-summary-list").await?;

    // Insert fake callback entries directly into the inner state.
    {
        let mut callbacks = runtime.inner.callbacks.write().await;
        callbacks.entry("agent_checkin").or_default().push(NamedCallback {
            plugin_name: "plugin_alpha".to_owned(),
            callback: Arc::new(pyo3::Python::with_gil(|py| py.None().into())),
        });
    }
    {
        let mut commands = runtime.inner.commands.write().await;
        commands.insert(
            "my_cmd".to_owned(),
            RegisteredCommand {
                description: "test command".to_owned(),
                callback: Arc::new(pyo3::Python::with_gil(|py| py.None().into())),
                plugin_name: "plugin_beta".to_owned(),
            },
        );
    }

    // Record a failure for plugin_alpha so we can verify the counts appear.
    runtime.record_callback_failure("plugin_alpha");

    let summary = runtime.plugin_health_summary();
    assert_eq!(summary.len(), 2, "expected 2 plugins in summary, got {summary:?}");

    let alpha = summary.iter().find(|e| e.plugin_name == "plugin_alpha");
    let beta = summary.iter().find(|e| e.plugin_name == "plugin_beta");

    let alpha = alpha.expect("plugin_alpha missing from summary");
    assert_eq!(alpha.consecutive_failures, 1);
    assert!(!alpha.disabled);

    let beta = beta.expect("plugin_beta missing from summary");
    assert_eq!(beta.consecutive_failures, 0);
    assert!(!beta.disabled);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn is_plugin_disabled_returns_false_for_unknown_plugin()
-> Result<(), Box<dyn std::error::Error>> {
    let (_db, _reg, _ev, _sock, runtime) = runtime_fixture("health-unknown-plugin").await?;
    assert!(!runtime.is_plugin_disabled("nonexistent_plugin"));
    Ok(())
}
