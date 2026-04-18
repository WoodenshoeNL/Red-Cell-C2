use tempfile::TempDir;

use super::*;

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

    let jobs = registry.dequeue_jobs(0x00AB_CDEF).await?;
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].command, 99);
    assert_eq!(jobs[0].payload, b"alpha beta");
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
