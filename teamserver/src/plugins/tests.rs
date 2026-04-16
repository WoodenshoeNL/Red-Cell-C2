
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use red_cell_common::{AgentEncryptionInfo, HttpListenerConfig, ListenerConfig};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::registry::{NamedCallback, RegisteredCommand};
use super::*;

// Tests that install a `PluginRuntime` as the active global must hold
// `super::PLUGIN_RUNTIME_TEST_MUTEX` so that wiring tests in other modules that
// call `PluginRuntime::swap_active` are serialised with us.
//
// We use `unwrap_or_else(|e| e.into_inner())` to tolerate a poisoned mutex — if a
// prior test panicked while holding the lock, the data inside is still valid (it is
// just `()`), so we recover and continue rather than cascading failures.
fn lock_test_guard() -> std::sync::MutexGuard<'static, ()> {
    super::PLUGIN_RUNTIME_TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
const POISON_CURRENT_ENV: &str = "RED_CELL_POISON_PLUGIN_RUNTIME_CURRENT";

fn unique_test_dir(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!("red-cell-{label}-{suffix}"))
}

fn sample_agent(agent_id: u32) -> AgentRecord {
    AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: "note".to_owned(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(b"aes-key".to_vec()),
            aes_iv: Zeroizing::new(b"aes-iv".to_vec()),
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "REDCELL".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        internal_ip: "10.0.0.25".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        base_address: 0x401000,
        process_pid: 1337,
        process_tid: 1338,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 15,
        sleep_jitter: 20,
        kill_date: Some(1_893_456_000),
        working_hours: Some(0b101010),
        first_call_in: "2026-03-09T18:45:00Z".to_owned(),
        last_call_in: "2026-03-09T18:46:00Z".to_owned(),
    }
}

fn sample_listener() -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: "http-main".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 8443,
        port_conn: Some(443),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: Some("Mozilla/5.0".to_owned()),
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
    })
}

async fn runtime_fixture(
    label: &str,
) -> Result<(Database, AgentRegistry, EventBus, SocketRelayManager, PluginRuntime), PluginError> {
    let database = Database::connect(unique_test_dir(label)).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = PluginRuntime::initialize(
        database.clone(),
        registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    )
    .await?;
    Ok((database, registry, events, sockets, runtime))
}

fn replace_active_runtime(
    runtime: Option<PluginRuntime>,
) -> Result<Option<PluginRuntime>, PluginError> {
    let mut guard = runtime_slot().lock().map_err(|_| PluginError::MutexPoisoned)?;
    Ok(std::mem::replace(&mut *guard, runtime))
}

struct ActiveRuntimeReset {
    previous: Option<PluginRuntime>,
}

impl ActiveRuntimeReset {
    fn clear() -> Result<Self, PluginError> {
        Ok(Self { previous: replace_active_runtime(None)? })
    }
}

impl Drop for ActiveRuntimeReset {
    fn drop(&mut self) {
        let _ = replace_active_runtime(self.previous.take());
    }
}

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

    let loaded = runtime.load_plugins().await?;

    assert_eq!(loaded, vec!["sample_plugin".to_owned()]);
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

    let loaded = runtime.load_plugins().await?;
    assert!(loaded.is_empty(), "broken plugin should be skipped, got {loaded:?}");
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

    let loaded = runtime.load_plugins().await?;

    // alpha and gamma should load; beta (syntax error) should be skipped.
    assert_eq!(loaded, vec!["alpha".to_owned(), "gamma".to_owned()]);

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

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn registered_command_callbacks_can_queue_agent_jobs()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-command-exec").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let module = py.import("red_cell")?;
                let callback = py.eval(
                    pyo3::ffi::c_str!("lambda agent, args: agent.task(99, ' '.join(args))"),
                    None,
                    None,
                )?;
                module.call_method1("register_command", ("demo", "demo command", callback))?;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    assert_eq!(
        runtime
            .match_registered_command(&AgentTaskInfo {
                command_line: "demo alpha beta".to_owned(),
                ..AgentTaskInfo::default()
            })
            .await,
        Some(("demo".to_owned(), vec!["alpha".to_owned(), "beta".to_owned()]))
    );

    assert!(
        runtime
            .invoke_registered_command(
                "demo",
                "operator",
                OperatorRole::Admin,
                0x00AB_CDEF,
                vec!["alpha".to_owned(), "beta".to_owned()],
            )
            .await?
    );

    let queued = registry.dequeue_jobs(0x00AB_CDEF).await?;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].command, 99);
    assert_eq!(queued[0].payload, b"alpha beta");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn register_command_accepts_havoc_keyword_signature() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-havoc-register-command").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let helper = PyModule::from_code(
                    py,
                    pyo3::ffi::c_str!(
                        "import havoc\n\
\n\
def run(agent, args):\n\
\tagent.task(100, ' '.join(args))\n\
\n\
havoc.RegisterCommand(\n\
\tfunction=run,\n\
\tmodule='situational_awareness',\n\
\tcommand='whoami',\n\
\tdescription='demo command',\n\
\tbehavior=0,\n\
\tusage='',\n\
\texample=''\n\
)\n"
                    ),
                    pyo3::ffi::c_str!("test_havoc_register_command.py"),
                    pyo3::ffi::c_str!("test_havoc_register_command"),
                )?;
                let _ = helper;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    assert_eq!(runtime.command_names().await, vec!["situational_awareness whoami".to_owned()]);
    assert_eq!(
        runtime
            .match_registered_command(&AgentTaskInfo {
                command_line: "situational_awareness whoami /all".to_owned(),
                ..AgentTaskInfo::default()
            })
            .await,
        Some(("situational_awareness whoami".to_owned(), vec!["/all".to_owned()],))
    );

    runtime
        .invoke_registered_command(
            "situational_awareness whoami",
            "operator",
            OperatorRole::Admin,
            0x00AB_CDEF,
            vec!["/all".to_owned()],
        )
        .await?;

    let queued = registry.dequeue_jobs(0x00AB_CDEF).await?;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].command, 100);
    assert_eq!(queued[0].payload, b"/all");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn invoke_registered_command_broadcast_task_id_matches_queued_job()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, registry, events, _sockets, runtime) =
        runtime_fixture("plugins-task-id-match").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let module = py.import("red_cell")?;
                let callback = py.eval(
                    pyo3::ffi::c_str!("lambda agent, args: agent.task(99, ' '.join(args))"),
                    None,
                    None,
                )?;
                module.call_method1("register_command", ("sync_cmd", "sync test", callback))?;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    let mut receiver = events.subscribe();

    runtime
        .invoke_registered_command(
            "sync_cmd",
            "operator",
            OperatorRole::Admin,
            0x00AB_CDEF,
            vec!["arg1".to_owned()],
        )
        .await?;

    let queued = registry.dequeue_jobs(0x00AB_CDEF).await?;
    assert_eq!(queued.len(), 1);
    let queued_task_id = &queued[0].task_id;

    let broadcast_msg = tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv())
        .await?
        .expect("expected a broadcast message");

    match broadcast_msg {
        OperatorMessage::AgentTask(msg) => {
            assert_eq!(
                &msg.info.task_id, queued_task_id,
                "broadcast task_id must match the queued job's task_id"
            );
        }
        other => panic!("expected AgentTask broadcast, got {other:?}"),
    }
    Ok(())
}

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
async fn listener_start_fails_before_manager_attached() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-listener-unavailable-start").await?;

    // Do NOT call attach_listener_manager — the manager stays None.
    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<String> {
                runtime.install_api_module(py)?;
                let module = py.import("havoc")?;
                let listener = module.getattr("Listener")?.call1(("nonexistent",))?;
                match listener.call_method0("start") {
                    Ok(_) => Ok("unexpected success".to_owned()),
                    Err(err) => Ok(err.to_string()),
                }
            })
        }
    });
    let error_message = handle.join().map_err(|_| "python test thread panicked")??;
    assert!(
        error_message.contains("listener manager is not available"),
        "expected ListenerManagerUnavailable error, got: {error_message}",
    );
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn listener_stop_fails_before_manager_attached() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-listener-unavailable-stop").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<String> {
                runtime.install_api_module(py)?;
                let module = py.import("havoc")?;
                let listener = module.getattr("Listener")?.call1(("nonexistent",))?;
                match listener.call_method0("stop") {
                    Ok(_) => Ok("unexpected success".to_owned()),
                    Err(err) => Ok(err.to_string()),
                }
            })
        }
    });
    let error_message = handle.join().map_err(|_| "python test thread panicked")??;
    assert!(
        error_message.contains("listener manager is not available"),
        "expected ListenerManagerUnavailable error, got: {error_message}",
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

    let loaded = runtime.load_plugins().await?;
    assert!(loaded.is_empty(), "plugin with interior NUL should be skipped, got {loaded:?}",);
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
async fn invoke_command_against_unknown_agent_returns_error_and_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    // Do NOT insert any agent into the registry — the agent ID will be unknown.
    let (_database, _registry, events, _sockets, runtime) =
        runtime_fixture("plugins-unknown-agent-task").await?;

    // Register a command that calls agent.task() inside its callback.
    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let module = py.import("red_cell")?;
                let callback = py.eval(
                    pyo3::ffi::c_str!("lambda agent, args: agent.task(99, 'payload')"),
                    None,
                    None,
                )?;
                module.call_method1(
                    "register_command",
                    ("fail_cmd", "command that will fail", callback),
                )?;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    let mut receiver = events.subscribe();

    // Invoke against a non-existent agent.
    let result = runtime
        .invoke_registered_command(
            "fail_cmd",
            "operator",
            OperatorRole::Admin,
            0xDEAD_BEEF,
            vec!["arg1".to_owned()],
        )
        .await;

    // The call must return an error (propagated from enqueue_job → AgentNotFound).
    assert!(result.is_err(), "expected error for unknown agent, got {result:?}");

    // No AgentTask broadcast should have been emitted.
    let recv_result =
        tokio::time::timeout(std::time::Duration::from_millis(100), receiver.recv()).await;
    assert!(recv_result.is_err(), "expected no broadcast, but received a message: {recv_result:?}",);
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn load_plugins_returns_empty_when_no_dir_configured()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-no-dir").await?;

    let loaded = runtime.load_plugins().await?;
    assert!(loaded.is_empty(), "expected empty vec when no plugins_dir configured");
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

    let loaded = runtime.load_plugins().await?;
    assert_eq!(loaded, vec!["real_plugin".to_owned()]);
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
async fn command_names_and_descriptions_empty_by_default() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-empty-commands").await?;

    assert!(runtime.command_names().await.is_empty());
    assert!(runtime.command_descriptions().await.is_empty());
    Ok(())
}

/// Multiple plugins registering different commands should produce a merged
/// result from `command_names()` and `command_descriptions()`.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn command_names_and_descriptions_merge_across_plugins()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let temp_dir = TempDir::new()?;

    // Plugin A registers "recon" command.
    std::fs::write(
        temp_dir.path().join("plugin_a.py"),
        r#"
import havoc

def run_recon(agent, args):
    agent.task(0x10, "recon")

havoc.RegisterCommand("recon", "run reconnaissance", run_recon)
"#,
    )?;

    // Plugin B registers "exfil" command.
    std::fs::write(
        temp_dir.path().join("plugin_b.py"),
        r#"
import havoc

def run_exfil(agent, args):
    agent.task(0x20, "exfil")

havoc.RegisterCommand("exfil", "exfiltrate data", run_exfil)
"#,
    )?;

    let database = Database::connect(unique_test_dir("plugins-merge-commands")).await?;
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

    let loaded = runtime.load_plugins().await?;
    assert_eq!(loaded.len(), 2);

    // command_names returns sorted keys from BTreeMap.
    let names = runtime.command_names().await;
    assert_eq!(names, vec!["exfil".to_owned(), "recon".to_owned()]);

    let descriptions = runtime.command_descriptions().await;
    assert_eq!(descriptions.len(), 2);
    assert_eq!(descriptions.get("recon"), Some(&"run reconnaissance".to_owned()),);
    assert_eq!(descriptions.get("exfil"), Some(&"exfiltrate data".to_owned()),);
    Ok(())
}

/// When two plugins register a command with the same name, the last one
/// loaded wins (alphabetical filename order). The description in
/// `command_descriptions()` should reflect the overwriting plugin.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn command_names_last_write_wins_on_duplicate_name() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_test_guard();
    let temp_dir = TempDir::new()?;

    // aaa_first.py registers "scan" with description "first scan".
    std::fs::write(
        temp_dir.path().join("aaa_first.py"),
        r#"
import havoc

def run_scan(agent, args):
    agent.task(0x30, "first")

havoc.RegisterCommand("scan", "first scan", run_scan)
"#,
    )?;

    // zzz_second.py registers "scan" with description "second scan".
    std::fs::write(
        temp_dir.path().join("zzz_second.py"),
        r#"
import havoc

def run_scan(agent, args):
    agent.task(0x30, "second")

havoc.RegisterCommand("scan", "second scan", run_scan)
"#,
    )?;

    let database = Database::connect(unique_test_dir("plugins-duplicate-command")).await?;
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

    let loaded = runtime.load_plugins().await?;
    assert_eq!(loaded.len(), 2);

    // Only one "scan" entry should exist (BTreeMap key deduplication).
    let names = runtime.command_names().await;
    assert_eq!(names, vec!["scan".to_owned()]);

    // zzz_second.py loads after aaa_first.py, so its description wins.
    let descriptions = runtime.command_descriptions().await;
    assert_eq!(descriptions.get("scan"), Some(&"second scan".to_owned()),);
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

// ---- RBAC enforcement tests ----

#[test]
fn caller_role_guard_sets_and_clears_thread_local() {
    // Initially no role is set.
    let role = CALLER_ROLE.with(|cell| *cell.borrow());
    assert!(role.is_none(), "caller role should be None before guard");

    {
        let _guard = CallerRoleGuard::enter(OperatorRole::Analyst);
        let role = CALLER_ROLE.with(|cell| *cell.borrow());
        assert_eq!(role, Some(OperatorRole::Analyst));
    }

    let role = CALLER_ROLE.with(|cell| *cell.borrow());
    assert!(role.is_none(), "caller role should be None after guard drops");
}

#[test]
fn check_plugin_permission_allows_all_in_system_context() {
    // Ensure no caller role is set (system context).
    CALLER_ROLE.with(|cell| *cell.borrow_mut() = None);

    for permission in [
        crate::rbac::Permission::Read,
        crate::rbac::Permission::TaskAgents,
        crate::rbac::Permission::ManageListeners,
        crate::rbac::Permission::Admin,
    ] {
        assert!(
            check_plugin_permission(permission).is_ok(),
            "system context should allow {}",
            permission.as_str(),
        );
    }
}

#[test]
fn check_plugin_permission_admin_allows_everything() {
    let _guard = CallerRoleGuard::enter(OperatorRole::Admin);
    for permission in [
        crate::rbac::Permission::Read,
        crate::rbac::Permission::TaskAgents,
        crate::rbac::Permission::ManageListeners,
        crate::rbac::Permission::Admin,
    ] {
        assert!(
            check_plugin_permission(permission).is_ok(),
            "Admin should have {} permission",
            permission.as_str(),
        );
    }
}

#[test]
fn check_plugin_permission_operator_denied_admin() {
    let _guard = CallerRoleGuard::enter(OperatorRole::Operator);

    assert!(check_plugin_permission(crate::rbac::Permission::Read).is_ok());
    assert!(check_plugin_permission(crate::rbac::Permission::TaskAgents).is_ok());
    assert!(check_plugin_permission(crate::rbac::Permission::ManageListeners).is_ok());
    assert!(
        check_plugin_permission(crate::rbac::Permission::Admin).is_err(),
        "Operator should be denied Admin permission",
    );
}

#[test]
fn check_plugin_permission_analyst_denied_write_operations() {
    let _guard = CallerRoleGuard::enter(OperatorRole::Analyst);

    assert!(check_plugin_permission(crate::rbac::Permission::Read).is_ok());
    assert!(
        check_plugin_permission(crate::rbac::Permission::TaskAgents).is_err(),
        "Analyst should be denied TaskAgents permission",
    );
    assert!(
        check_plugin_permission(crate::rbac::Permission::ManageListeners).is_err(),
        "Analyst should be denied ManageListeners permission",
    );
    assert!(
        check_plugin_permission(crate::rbac::Permission::Admin).is_err(),
        "Analyst should be denied Admin permission",
    );
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn invoke_registered_command_enforces_caller_role_in_python()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let _reset = ActiveRuntimeReset::clear()?;
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-rbac-invoke").await?;

    // Register an agent so the command can reference it.
    let agent = sample_agent(0xBEEF_0001);
    registry.insert(agent.clone()).await?;

    // Register a Python command that tries to call list_agents() (requires Read).
    let command_runtime = runtime.clone();
    let handle = std::thread::spawn(move || {
        let _cb_guard = CallbackRuntimeGuard::enter(&command_runtime);
        Python::with_gil(|py| -> PyResult<()> {
            command_runtime.install_api_module(py)?;
            let module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    "import red_cell\n\
                         \n\
                         def my_command(agent, args):\n\
                         \tagents = red_cell.list_agents()\n"
                ),
                pyo3::ffi::c_str!("test_rbac_read.py"),
                pyo3::ffi::c_str!("test_rbac_read"),
            )?;
            let callback = module.getattr("my_command")?.unbind();
            command_runtime
                .block_on(command_runtime.register_command(
                    "test_rbac_cmd".to_owned(),
                    "test command for RBAC".to_owned(),
                    callback,
                ))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            Ok(())
        })
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    // Admin should succeed.
    let result = runtime
        .invoke_registered_command(
            "test_rbac_cmd",
            "admin_user",
            OperatorRole::Admin,
            0xBEEF_0001,
            vec![],
        )
        .await;
    assert!(result.is_ok(), "Admin should be able to invoke the command");

    // Analyst should also succeed because list_agents requires Read.
    let result = runtime
        .invoke_registered_command(
            "test_rbac_cmd",
            "analyst_user",
            OperatorRole::Analyst,
            0xBEEF_0001,
            vec![],
        )
        .await;
    assert!(result.is_ok(), "Analyst should be able to invoke read-only command");

    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn invoke_registered_command_denies_analyst_task_agents()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let _reset = ActiveRuntimeReset::clear()?;
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-rbac-deny-task").await?;

    let agent = sample_agent(0xBEEF_0002);
    registry.insert(agent.clone()).await?;

    // Register a command that tries to task an agent (requires TaskAgents).
    let command_runtime = runtime.clone();
    let handle = std::thread::spawn(move || {
        let _cb_guard = CallbackRuntimeGuard::enter(&command_runtime);
        Python::with_gil(|py| -> PyResult<()> {
            command_runtime.install_api_module(py)?;
            let module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    "import red_cell\n\
                         \n\
                         def task_command(agent, args):\n\
                         \tagent.task(99)\n"
                ),
                pyo3::ffi::c_str!("test_rbac_task.py"),
                pyo3::ffi::c_str!("test_rbac_task"),
            )?;
            let callback = module.getattr("task_command")?.unbind();
            command_runtime
                .block_on(command_runtime.register_command(
                    "test_task_cmd".to_owned(),
                    "test task command".to_owned(),
                    callback,
                ))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            Ok(())
        })
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    // Analyst should be denied because task() requires TaskAgents.
    let result = runtime
        .invoke_registered_command(
            "test_task_cmd",
            "analyst_user",
            OperatorRole::Analyst,
            0xBEEF_0002,
            vec![],
        )
        .await;
    assert!(result.is_err(), "Analyst should be denied agent tasking via plugin");

    // Operator should succeed.
    let result = runtime
        .invoke_registered_command(
            "test_task_cmd",
            "operator_user",
            OperatorRole::Operator,
            0xBEEF_0002,
            vec![],
        )
        .await;
    assert!(result.is_ok(), "Operator should be able to task agents via plugin");

    Ok(())
}

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

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn match_registered_command_resolves_ambiguous_prefix_to_longest()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-ambiguous-prefix").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let module = py.import("red_cell")?;
                let noop = py.eval(pyo3::ffi::c_str!("lambda agent, args: None"), None, None)?;
                module.call_method1("register_command", ("scan", "short scan", &noop))?;
                module.call_method1("register_command", ("scan_deep", "deep scan", &noop))?;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    // "scan_deep target" must match "scan_deep", not "scan"
    assert_eq!(
        runtime
            .match_registered_command(&AgentTaskInfo {
                command_line: "scan_deep target".to_owned(),
                ..AgentTaskInfo::default()
            })
            .await,
        Some(("scan_deep".to_owned(), vec!["target".to_owned()]))
    );

    // "scan host1" must still match "scan"
    assert_eq!(
        runtime
            .match_registered_command(&AgentTaskInfo {
                command_line: "scan host1".to_owned(),
                ..AgentTaskInfo::default()
            })
            .await,
        Some(("scan".to_owned(), vec!["host1".to_owned()]))
    );

    // exact "scan_deep" with no args must match "scan_deep"
    assert_eq!(
        runtime
            .match_registered_command(&AgentTaskInfo {
                command_line: "scan_deep".to_owned(),
                ..AgentTaskInfo::default()
            })
            .await,
        Some(("scan_deep".to_owned(), vec![]))
    );

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

// ---- match_registered_command edge cases ----

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn match_registered_command_returns_none_when_no_commands_registered()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-match-no-commands").await?;

    let result = runtime
        .match_registered_command(&AgentTaskInfo {
            command_line: "anything here".to_owned(),
            ..AgentTaskInfo::default()
        })
        .await;
    assert_eq!(result, None, "should return None when no commands are registered");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn match_registered_command_returns_none_for_empty_command_line()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-match-empty-cmdline").await?;

    // Register a command so the map is non-empty.
    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let module = py.import("red_cell")?;
                let noop = py.eval(pyo3::ffi::c_str!("lambda agent, args: None"), None, None)?;
                module.call_method1("register_command", ("test_cmd", "desc", &noop))?;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    let result = runtime
        .match_registered_command(&AgentTaskInfo {
            command_line: String::new(),
            ..AgentTaskInfo::default()
        })
        .await;
    assert_eq!(result, None, "empty command_line should not match anything");

    let result = runtime
        .match_registered_command(&AgentTaskInfo {
            command_line: "   ".to_owned(),
            ..AgentTaskInfo::default()
        })
        .await;
    assert_eq!(result, None, "whitespace-only command_line should not match");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn match_registered_command_returns_none_for_unrecognized_command()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-match-unrecognized").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let module = py.import("red_cell")?;
                let noop = py.eval(pyo3::ffi::c_str!("lambda agent, args: None"), None, None)?;
                module.call_method1("register_command", ("known_cmd", "desc", &noop))?;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    let result = runtime
        .match_registered_command(&AgentTaskInfo {
            command_line: "unknown_cmd arg1".to_owned(),
            ..AgentTaskInfo::default()
        })
        .await;
    assert_eq!(result, None, "unrecognized command should not match");
    Ok(())
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn match_registered_command_prefers_explicit_command_field()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-match-explicit-field").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let module = py.import("red_cell")?;
                let noop = py.eval(pyo3::ffi::c_str!("lambda agent, args: None"), None, None)?;
                module.call_method1("register_command", ("cmd_a", "desc a", &noop))?;
                module.call_method1("register_command", ("cmd_b", "desc b", &noop))?;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    // When info.command is set and matches, it should be used regardless of command_line.
    let result = runtime
        .match_registered_command(&AgentTaskInfo {
            command: Some("cmd_a".to_owned()),
            arguments: Some("arg1 arg2".to_owned()),
            command_line: "cmd_b something_else".to_owned(),
            ..AgentTaskInfo::default()
        })
        .await;
    assert_eq!(
        result,
        Some(("cmd_a".to_owned(), vec!["arg1".to_owned(), "arg2".to_owned()])),
        "explicit command field should take priority over command_line",
    );
    Ok(())
}

// ---- invoke_registered_command edge cases ----

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn invoke_registered_command_returns_false_for_unknown_command()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-invoke-unknown-cmd").await?;
    registry.insert(sample_agent(0x00AB_CDEF)).await?;

    let result = runtime
        .invoke_registered_command(
            "nonexistent_command",
            "operator",
            OperatorRole::Admin,
            0x00AB_CDEF,
            vec![],
        )
        .await?;
    assert!(!result, "should return false for unregistered command name");
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
#[tokio::test(flavor = "multi_thread")]
async fn register_command_rejects_non_callable() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-register-cmd-non-callable").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| -> PyResult<String> {
                runtime.install_api_module(py)?;
                let module = py.import("red_cell")?;
                let not_callable = py.eval(pyo3::ffi::c_str!("42"), None, None)?;
                match module.call_method1("register_command", ("cmd", "desc", &not_callable)) {
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
#[tokio::test(flavor = "multi_thread")]
async fn register_command_rejects_missing_arguments() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-register-cmd-missing-args").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| -> PyResult<Vec<String>> {
                runtime.install_api_module(py)?;
                let module = py.import("red_cell")?;
                let mut errors = Vec::new();
                // No arguments at all
                match module.call_method0("register_command") {
                    Err(err) => errors.push(err.to_string()),
                    Ok(_) => errors.push("unexpected success with no args".to_owned()),
                }
                // Only name (missing description and callback)
                match module.call_method1("register_command", ("cmd",)) {
                    Err(err) => errors.push(err.to_string()),
                    Ok(_) => errors.push("unexpected success with one arg".to_owned()),
                }
                Ok(errors)
            })
        }
    });
    let errors = handle.join().map_err(|_| "python test thread panicked")??;
    assert!(errors.len() >= 2, "expected at least 2 errors");
    for error in &errors {
        assert!(
            error.contains("requires") || error.contains("argument"),
            "expected a missing argument error, got: {error}",
        );
    }
    Ok(())
}

// ---- Empty directory and multiple callbacks ----

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

    let loaded = runtime.load_plugins().await?;
    assert!(loaded.is_empty(), "empty directory should produce no loaded plugins");
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

// ---- Havoc-style RegisterCommand positional-argument format ----

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn register_command_havoc_positional_format() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-havoc-positional").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                // Havoc positional: RegisterCommand(function, module, command, description)
                let helper = PyModule::from_code(
                    py,
                    pyo3::ffi::c_str!(
                        "import havoc\n\
                             def my_func(agent, args): pass\n\
                             havoc.RegisterCommand(my_func, 'lateral_movement', 'psexec', 'run psexec')\n"
                    ),
                    pyo3::ffi::c_str!("test_havoc_pos.py"),
                    pyo3::ffi::c_str!("test_havoc_pos"),
                )?;
                let _ = helper;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    assert_eq!(runtime.command_names().await, vec!["lateral_movement psexec".to_owned()],);
    assert_eq!(
        runtime.command_descriptions().await.get("lateral_movement psexec"),
        Some(&"run psexec".to_owned()),
    );
    Ok(())
}

// ---- Havoc-style RegisterCommand with empty module name ----

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn register_command_havoc_empty_module_uses_command_only()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-havoc-empty-module").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let helper = PyModule::from_code(
                    py,
                    pyo3::ffi::c_str!(
                        "import havoc\n\
                             def my_func(agent, args): pass\n\
                             havoc.RegisterCommand(my_func, '', 'standalone', 'standalone cmd')\n"
                    ),
                    pyo3::ffi::c_str!("test_havoc_empty_mod.py"),
                    pyo3::ffi::c_str!("test_havoc_empty_mod"),
                )?;
                let _ = helper;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    assert_eq!(
        runtime.command_names().await,
        vec!["standalone".to_owned()],
        "empty module should result in command name without prefix",
    );
    Ok(())
}

// ---- on_* shorthand registration functions via Python ----

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn on_shorthand_functions_register_callbacks() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_test_guard();
    let (_database, _registry, _events, _sockets, runtime) =
        runtime_fixture("plugins-on-shorthands").await?;

    let handle = std::thread::spawn({
        let runtime = runtime.clone();
        move || {
            let _cb_guard = CallbackRuntimeGuard::enter(&runtime);
            Python::with_gil(|py| -> PyResult<()> {
                runtime.install_api_module(py)?;
                let module = py.import("havoc")?;
                let noop = py.eval(pyo3::ffi::c_str!("lambda event: None"), None, None)?;
                // Each on_* function should succeed.
                module.call_method1("on_agent_checkin", (&noop,))?;
                module.call_method1("on_agent_registered", (&noop,))?;
                module.call_method1("on_agent_dead", (&noop,))?;
                module.call_method1("on_command_output", (&noop,))?;
                module.call_method1("on_loot_captured", (&noop,))?;
                module.call_method1("on_task_created", (&noop,))?;
                Ok(())
            })
        }
    });
    handle.join().map_err(|_| "python test thread panicked")??;

    // Verify callbacks were registered for each event type.
    let callbacks = runtime.inner.callbacks.read().await;
    for event_str in [
        "agent_checkin",
        "agent_registered",
        "agent_dead",
        "command_output",
        "loot_captured",
        "task_created",
    ] {
        assert!(
            callbacks.get(event_str).is_some_and(|cbs| !cbs.is_empty()),
            "expected at least 1 callback for {event_str}",
        );
    }
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
